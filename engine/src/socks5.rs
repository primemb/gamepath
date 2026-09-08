use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::time::{Duration, Instant};

const VERSION: u8 = 5;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2).
pub const UDP_HEADER_LEN: usize = 10;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// A closed control stream is only diagnostic context, so it is sampled
/// rather than checked on every datagram.
const CONTROL_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5NodeConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Socks5NodeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err("SOCKS5 node is missing a host".into());
        }
        if self.port == 0 {
            return Err("SOCKS5 node port must be between 1 and 65535".into());
        }
        for (name, value) in [("username", &self.username), ("password", &self.password)] {
            if value.as_deref().is_some_and(|value| value.len() > 255) {
                return Err(format!("SOCKS5 {name} must be at most 255 bytes"));
            }
        }
        let username = self.username.as_deref().unwrap_or_default();
        let password = self.password.as_deref().unwrap_or_default();
        if username.is_empty() != password.is_empty() {
            return Err("SOCKS5 authentication needs both a username and a password".into());
        }
        Ok(())
    }

    fn credentials(&self) -> Option<(&str, &str)> {
        let username = self.username.as_deref().filter(|value| !value.is_empty())?;
        let password = self.password.as_deref().filter(|value| !value.is_empty())?;
        Some((username, password))
    }
}

/// One SOCKS5 UDP association carrying GamePath relay frames.
///
/// RFC 1928 ties the association's lifetime to the TCP control connection, so
/// the stream is held open for proxies that enforce that. Real proxies vary:
/// some close the control stream the moment they answer UDP ASSOCIATE and go
/// on relaying datagrams anyway. A closed control stream is therefore recorded
/// but never treated as a dead path — the session's own authenticated probes
/// decide that, and they measure what actually matters.
pub struct Socks5UdpPath {
    control: TcpStream,
    udp: UdpSocket,
    proxy: SocketAddr,
    relay: SocketAddrV4,
    request_header: [u8; UDP_HEADER_LEN],
    setup_latency_ms: f64,
    control_closed: bool,
    next_control_poll: Instant,
    send_buffer: Vec<u8>,
    receive_buffer: Vec<u8>,
    read_timeout: Option<Duration>,
}

impl Socks5UdpPath {
    pub fn open(config: &Socks5NodeConfig, relay: SocketAddrV4) -> Result<Self, String> {
        config.validate()?;
        let started = Instant::now();
        let proxy = resolve_proxy(&config.host, config.port)?;
        let mut control = TcpStream::connect_timeout(&proxy, CONNECT_TIMEOUT)
            .map_err(|error| format!("could not reach SOCKS5 proxy {proxy}: {error}"))?;
        control
            .set_nodelay(true)
            .map_err(|error| format!("could not configure SOCKS5 control socket: {error}"))?;
        control
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("could not configure SOCKS5 control socket: {error}"))?;
        control
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("could not configure SOCKS5 control socket: {error}"))?;

        negotiate_method(&mut control, config)?;
        let bound = request_udp_association(&mut control, proxy)?;

        let local = match bound {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let udp = UdpSocket::bind(local)
            .map_err(|error| format!("could not create SOCKS5 UDP socket: {error}"))?;
        socket2::SockRef::from(&udp)
            .set_recv_buffer_size(4 * 1024 * 1024)
            .map_err(|error| format!("could not size the SOCKS5 receive buffer: {error}"))?;
        socket2::SockRef::from(&udp)
            .set_send_buffer_size(4 * 1024 * 1024)
            .map_err(|error| format!("could not size the SOCKS5 send buffer: {error}"))?;
        udp.connect(bound)
            .map_err(|error| format!("could not bind SOCKS5 UDP association {bound}: {error}"))?;

        // Held open for proxies that tie the association to it, and parked in
        // non-blocking mode so polling it never stalls the datapath.
        control
            .set_nonblocking(true)
            .map_err(|error| format!("could not watch the SOCKS5 control socket: {error}"))?;

        Ok(Self {
            control,
            udp,
            proxy,
            relay,
            request_header: udp_request_header(relay),
            setup_latency_ms: started.elapsed().as_secs_f64() * 1000.0,
            control_closed: false,
            next_control_poll: Instant::now(),
            send_buffer: Vec::with_capacity(2048),
            receive_buffer: vec![0_u8; 65_535],
            read_timeout: None,
        })
    }

    pub fn proxy(&self) -> SocketAddr {
        self.proxy
    }

    pub fn relay(&self) -> SocketAddrV4 {
        self.relay
    }

    /// Milliseconds spent on TCP connect, authentication, and UDP ASSOCIATE.
    /// This is the SOCKS5 counterpart of the WireGuard handshake latency.
    pub fn setup_latency_ms(&self) -> f64 {
        self.setup_latency_ms
    }

    /// True once the proxy has closed the control stream. Datagrams may still
    /// flow; this is diagnostic context for a path that has gone quiet.
    pub fn control_closed(&mut self) -> bool {
        // Asked only when a path has already gone quiet, so sample it now.
        self.next_control_poll = Instant::now();
        self.poll_control();
        self.control_closed
    }

    /// Sends one sealed frame. Nothing here touches the control stream: this is
    /// the outbound latency path and it must cost exactly one system call.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.send_buffer.clear();
        self.send_buffer.extend_from_slice(&self.request_header);
        self.send_buffer.extend_from_slice(frame);
        self.udp
            .send(&self.send_buffer)
            .map_err(|error| format!("SOCKS5 UDP send failed: {error}"))?;
        Ok(())
    }

    /// Takes at most one datagram, waiting up to `timeout` for it.
    ///
    /// Reading further queued datagrams here would mean waiting out the timeout
    /// again on the common case of there being none, which would hold a packet
    /// already in hand for another millisecond. The caller loops instead: a
    /// queued datagram is returned by the next call without any wait, and the
    /// timeout is only ever paid when the socket is genuinely empty.
    pub fn receive_frames(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.poll_control();
        self.set_read_timeout(timeout)?;
        let received = {
            let Self {
                udp,
                receive_buffer,
                ..
            } = self;
            udp.recv(receive_buffer)
        };
        match received {
            Ok(length) => Ok(
                match udp_reply_payload(&self.receive_buffer[..length], self.relay) {
                    Some(payload) => vec![payload.to_vec()],
                    None => Vec::new(),
                },
            ),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(Vec::new())
            }
            // Windows reports a queued ICMP port-unreachable from an earlier
            // send as WSAECONNRESET. It concerns a packet already gone, not
            // the association, so it must not tear the path down.
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(Vec::new()),
            Err(error) => Err(format!("SOCKS5 UDP receive failed: {error}")),
        }
    }

    /// Drains anything the proxy writes on the control stream and notes a
    /// close. A SOCKS5 proxy sends nothing here after the reply, so the only
    /// interesting outcome is EOF, and that alone does not end the path.
    ///
    /// Purely diagnostic, so it is rate limited: the datapath calls its caller
    /// thousands of times a second and must not pay a system call for it.
    fn poll_control(&mut self) {
        if self.control_closed || Instant::now() < self.next_control_poll {
            return;
        }
        self.next_control_poll = Instant::now() + CONTROL_POLL_INTERVAL;
        let mut discard = [0_u8; 64];
        match self.control.read(&mut discard) {
            Ok(0) => self.control_closed = true,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => self.control_closed = true,
        }
    }

    fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        let timeout = crate::transport::socket_read_timeout(timeout);
        if self.read_timeout != Some(timeout) {
            self.udp
                .set_read_timeout(Some(timeout))
                .map_err(|error| format!("could not set the SOCKS5 read timeout: {error}"))?;
            self.read_timeout = Some(timeout);
        }
        Ok(())
    }
}

fn resolve_proxy(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host = host.trim();
    let addresses: Vec<SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve SOCKS5 proxy {host}: {error}"))?
        .collect();
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
        .ok_or_else(|| format!("SOCKS5 proxy {host} did not resolve"))
}

fn negotiate_method(control: &mut TcpStream, config: &Socks5NodeConfig) -> Result<(), String> {
    let offered: &[u8] = match config.credentials() {
        Some(_) => &[METHOD_NONE, METHOD_USERPASS],
        None => &[METHOD_NONE],
    };
    let mut greeting = vec![VERSION, offered.len() as u8];
    greeting.extend_from_slice(offered);
    write_all(control, &greeting)?;
    let reply = read_exact(control, 2)?;
    if reply[0] != VERSION {
        return Err(format!(
            "proxy is not SOCKS5 (it answered version {})",
            reply[0]
        ));
    }
    match reply[1] {
        METHOD_NONE => Ok(()),
        METHOD_USERPASS => authenticate(control, config),
        METHOD_UNACCEPTABLE => Err(
            "SOCKS5 proxy rejected the offered authentication methods; add a username and password"
                .into(),
        ),
        other => Err(format!(
            "SOCKS5 proxy asked for authentication method {other}, which GamePath does not support"
        )),
    }
}

fn authenticate(control: &mut TcpStream, config: &Socks5NodeConfig) -> Result<(), String> {
    let Some((username, password)) = config.credentials() else {
        return Err("SOCKS5 proxy requires a username and password".into());
    };
    let mut request = vec![AUTH_VERSION, username.len() as u8];
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password.as_bytes());
    write_all(control, &request)?;
    let reply = read_exact(control, 2)?;
    if reply[1] != 0 {
        return Err("SOCKS5 proxy rejected the username and password".into());
    }
    Ok(())
}

fn request_udp_association(
    control: &mut TcpStream,
    proxy: SocketAddr,
) -> Result<SocketAddr, String> {
    // The client UDP port is not known before the proxy names its relay port,
    // so the request carries the wildcard address RFC 1928 allows here.
    let request = [
        VERSION,
        CMD_UDP_ASSOCIATE,
        0x00,
        ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    write_all(control, &request)?;
    let head = read_exact(control, 4)?;
    if head[0] != VERSION {
        return Err(format!(
            "proxy is not SOCKS5 (it answered version {})",
            head[0]
        ));
    }
    if head[1] != 0 {
        return Err(reply_error(head[1]));
    }
    let (address, port) = match head[3] {
        ATYP_IPV4 => {
            let bytes = read_exact(control, 6)?;
            (
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                u16::from_be_bytes([bytes[4], bytes[5]]),
            )
        }
        ATYP_IPV6 => {
            let bytes = read_exact(control, 18)?;
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            (
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([bytes[16], bytes[17]]),
            )
        }
        ATYP_DOMAIN => {
            let length = usize::from(read_exact(control, 1)?[0]);
            let bytes = read_exact(control, length + 2)?;
            let host = String::from_utf8_lossy(&bytes[..length]).to_string();
            let port = u16::from_be_bytes([bytes[length], bytes[length + 1]]);
            (resolve_proxy(&host, port)?.ip(), port)
        }
        other => {
            return Err(format!(
                "SOCKS5 proxy replied with unknown address type {other}"
            ));
        }
    };
    // A wildcard bind address means "the host you are already talking to".
    let address = match address {
        IpAddr::V4(ip) if ip.is_unspecified() => proxy.ip(),
        IpAddr::V6(ip) if ip.is_unspecified() => proxy.ip(),
        other => other,
    };
    if port == 0 {
        return Err("SOCKS5 proxy replied with an unusable UDP port".into());
    }
    Ok(SocketAddr::new(address, port))
}

fn reply_error(code: u8) -> String {
    let detail = match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "the proxy does not support UDP ASSOCIATE",
        8 => "address type not supported",
        _ => "unknown failure",
    };
    format!("SOCKS5 proxy refused the UDP association: {detail}")
}

pub fn udp_request_header(relay: SocketAddrV4) -> [u8; UDP_HEADER_LEN] {
    let mut header = [0_u8; UDP_HEADER_LEN];
    header[3] = ATYP_IPV4;
    header[4..8].copy_from_slice(&relay.ip().octets());
    header[8..10].copy_from_slice(&relay.port().to_be_bytes());
    header
}

/// Strips the SOCKS5 UDP reply header and keeps only datagrams that came from
/// the relay. Fragmented datagrams are dropped: a GamePath frame is always one
/// datagram, so a non-zero FRAG can only be foreign traffic.
pub fn udp_reply_payload(datagram: &[u8], relay: SocketAddrV4) -> Option<&[u8]> {
    if datagram.len() < 4 || datagram[0] != 0 || datagram[1] != 0 || datagram[2] != 0 {
        return None;
    }
    match datagram[3] {
        ATYP_IPV4 => {
            if datagram.len() < UDP_HEADER_LEN {
                return None;
            }
            let source = Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]);
            let port = u16::from_be_bytes([datagram[8], datagram[9]]);
            if source != *relay.ip() || port != relay.port() {
                return None;
            }
            Some(&datagram[UDP_HEADER_LEN..])
        }
        // A proxy that names the source by domain cannot be matched against the
        // relay address here. The frame's own authentication is the real gate.
        ATYP_DOMAIN => {
            let length = usize::from(*datagram.get(4)?);
            let end = 5 + length + 2;
            if datagram.len() < end {
                return None;
            }
            Some(&datagram[end..])
        }
        // Relay paths are IPv4, so an IPv6 source is never our relay.
        _ => None,
    }
}

fn write_all(control: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    control
        .write_all(bytes)
        .map_err(|error| format!("SOCKS5 handshake write failed: {error}"))
}

fn read_exact(control: &mut TcpStream, length: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0_u8; length];
    control.read_exact(&mut buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            "SOCKS5 proxy closed the connection during the handshake".to_owned()
        } else {
            format!("SOCKS5 handshake read failed: {error}")
        }
    })?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A minimal SOCKS5 proxy that completes the handshake and echoes every
    /// relayed datagram back with a correct reply header. The listener is bound
    /// before the thread starts, so a client may connect immediately.
    fn spawn_proxy(require_auth: bool, support_udp: bool) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let relay_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0_u8; 2];
            stream.read_exact(&mut greeting).unwrap();
            let mut methods = vec![0_u8; usize::from(greeting[1])];
            stream.read_exact(&mut methods).unwrap();
            if require_auth {
                // RFC 1928: a server that needs an unoffered method answers 0xFF.
                if !methods.contains(&METHOD_USERPASS) {
                    stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).unwrap();
                    return;
                }
                stream.write_all(&[VERSION, METHOD_USERPASS]).unwrap();
                let mut head = [0_u8; 2];
                stream.read_exact(&mut head).unwrap();
                let mut username = vec![0_u8; usize::from(head[1])];
                stream.read_exact(&mut username).unwrap();
                let mut length = [0_u8; 1];
                stream.read_exact(&mut length).unwrap();
                let mut password = vec![0_u8; usize::from(length[0])];
                stream.read_exact(&mut password).unwrap();
                let accepted = username == b"player" && password == b"secret";
                stream
                    .write_all(&[AUTH_VERSION, u8::from(!accepted)])
                    .unwrap();
                if !accepted {
                    return;
                }
            } else {
                stream.write_all(&[VERSION, METHOD_NONE]).unwrap();
            }
            let mut request = [0_u8; 10];
            stream.read_exact(&mut request).unwrap();
            if !support_udp {
                stream
                    .write_all(&[VERSION, 7, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                thread::sleep(Duration::from_millis(200));
                return;
            }
            let mut reply = vec![VERSION, 0, 0, ATYP_IPV4];
            reply.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
            reply.extend_from_slice(&relay_socket.local_addr().unwrap().port().to_be_bytes());
            stream.write_all(&reply).unwrap();
            relay_socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buffer = [0_u8; 65_535];
            while let Ok((length, from)) = relay_socket.recv_from(&mut buffer) {
                if length >= UDP_HEADER_LEN {
                    let _ = relay_socket.send_to(&buffer[..length], from);
                }
            }
            // Hold the control stream for the association's whole lifetime.
            drop(stream);
        });
        address
    }

    fn config(address: SocketAddr, credentials: bool) -> Socks5NodeConfig {
        Socks5NodeConfig {
            host: address.ip().to_string(),
            port: address.port(),
            username: credentials.then(|| "player".to_owned()),
            password: credentials.then(|| "secret".to_owned()),
        }
    }

    const RELAY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 51_821);

    #[test]
    fn relay_frames_round_trip_through_a_socks5_association() {
        let proxy = spawn_proxy(false, true);
        let mut path = Socks5UdpPath::open(&config(proxy, false), RELAY).unwrap();
        path.send_frame(b"gamepath-frame").unwrap();
        assert_eq!(
            path.receive_frames(Duration::from_secs(2)).unwrap(),
            vec![b"gamepath-frame".to_vec()]
        );
        assert!(path.setup_latency_ms() >= 0.0);
        assert_eq!(path.relay(), RELAY);
        assert_eq!(path.proxy(), proxy);
    }

    /// Queued datagrams must come back without paying the timeout again: a
    /// receive that already holds a packet may not wait for a second one.
    #[test]
    fn queued_datagrams_are_returned_one_per_call_without_waiting() {
        let proxy = spawn_proxy(false, true);
        let mut path = Socks5UdpPath::open(&config(proxy, false), RELAY).unwrap();
        for index in 0..3_u8 {
            path.send_frame(&[b'f', index]).unwrap();
        }
        let mut collected = Vec::new();
        let started = Instant::now();
        // A generous per-call timeout that a correct implementation never pays
        // while datagrams are still queued.
        while collected.len() < 3 && started.elapsed() < Duration::from_secs(5) {
            let batch = path.receive_frames(Duration::from_secs(2)).unwrap();
            assert!(
                batch.len() <= 1,
                "a call returned {} frames, so it kept reading after it had one",
                batch.len()
            );
            collected.extend(batch);
        }
        assert_eq!(collected.len(), 3, "every queued datagram came back");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "draining took {:?}, so a call waited out its timeout with a packet in hand",
            started.elapsed()
        );
    }

    #[test]
    fn username_and_password_authentication_is_supported() {
        let proxy = spawn_proxy(true, true);
        let mut path = Socks5UdpPath::open(&config(proxy, true), RELAY).unwrap();
        path.send_frame(b"authenticated").unwrap();
        assert_eq!(
            path.receive_frames(Duration::from_secs(2)).unwrap(),
            vec![b"authenticated".to_vec()]
        );
    }

    #[test]
    fn a_proxy_without_udp_support_is_reported_clearly() {
        let proxy = spawn_proxy(false, false);
        let error = Socks5UdpPath::open(&config(proxy, false), RELAY)
            .err()
            .unwrap();
        assert!(error.contains("does not support UDP ASSOCIATE"), "{error}");
    }

    #[test]
    fn a_proxy_that_wants_credentials_reports_the_missing_ones() {
        let proxy = spawn_proxy(true, true);
        let error = Socks5UdpPath::open(&config(proxy, false), RELAY)
            .err()
            .unwrap();
        assert!(error.contains("add a username and password"), "{error}");
    }

    #[test]
    fn replies_from_other_sources_and_fragments_are_dropped() {
        let mut good = udp_request_header(RELAY).to_vec();
        good.extend_from_slice(b"payload");
        assert_eq!(udp_reply_payload(&good, RELAY), Some(b"payload".as_slice()));

        let mut header = udp_request_header(RELAY);
        header[2] = 1;
        let mut fragmented = header.to_vec();
        fragmented.extend_from_slice(b"payload");
        assert_eq!(udp_reply_payload(&fragmented, RELAY), None);

        let other = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 51_821);
        let mut foreign = udp_request_header(other).to_vec();
        foreign.extend_from_slice(b"payload");
        assert_eq!(udp_reply_payload(&foreign, RELAY), None);

        let mut wrong_port = udp_request_header(SocketAddrV4::new(*RELAY.ip(), 9)).to_vec();
        wrong_port.extend_from_slice(b"payload");
        assert_eq!(udp_reply_payload(&wrong_port, RELAY), None);

        assert_eq!(
            udp_reply_payload(&udp_request_header(RELAY)[..3], RELAY),
            None
        );
    }

    #[test]
    fn incomplete_configurations_are_rejected_before_dialling() {
        let base = Socks5NodeConfig {
            host: "127.0.0.1".into(),
            port: 2080,
            username: None,
            password: None,
        };
        assert!(base.validate().is_ok());
        assert!(
            Socks5NodeConfig {
                host: "  ".into(),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Socks5NodeConfig {
                port: 0,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Socks5NodeConfig {
                username: Some("player".into()),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Socks5NodeConfig {
                username: Some("player".into()),
                password: Some("secret".into()),
                ..base
            }
            .validate()
            .is_ok()
        );
    }
}
