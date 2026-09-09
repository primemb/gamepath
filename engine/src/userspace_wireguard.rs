use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub struct UserSpaceWireGuardPath {
    socket: UdpSocket,
    tunnel: Tunn,
    address: Ipv4Addr,
    endpoint: SocketAddr,
    identity_fingerprint: [u8; 32],
    handshake_started: Option<Instant>,
    handshake_latency_ms: Option<f64>,
    read_timeout: Option<Duration>,
    network_buffer: Vec<u8>,
    tunnel_buffer: Vec<u8>,
}

impl UserSpaceWireGuardPath {
    pub fn from_config(source: &str) -> Result<Self, String> {
        let private_key = decode_key(required_value(source, "interface", "privatekey")?)?;
        let public_key = decode_key(required_value(source, "peer", "publickey")?)?;
        let preshared_key = section_value(source, "peer", "presharedkey")
            .map(decode_key)
            .transpose()?;
        let address = required_value(source, "interface", "address")?
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .split('/')
            .next()
            .unwrap_or_default()
            .parse::<Ipv4Addr>()
            .map_err(|_| "user-space WireGuard currently requires an IPv4 Interface Address")?;
        let endpoint_text = required_value(source, "peer", "endpoint")?;
        let endpoint = endpoint_text
            .to_socket_addrs()
            .map_err(|error| format!("could not resolve WireGuard endpoint: {error}"))?
            .find(SocketAddr::is_ipv4)
            .ok_or("WireGuard endpoint did not resolve to IPv4")?;
        let persistent_keepalive = section_value(source, "peer", "persistentkeepalive")
            .map(|value| {
                value
                    .parse::<u16>()
                    .map_err(|_| "invalid PersistentKeepalive")
            })
            .transpose()?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .map_err(|error| format!("could not create WireGuard UDP socket: {error}"))?;
        socket2::SockRef::from(&socket)
            .set_recv_buffer_size(4 * 1024 * 1024)
            .map_err(|error| format!("could not enlarge WireGuard receive buffer: {error}"))?;
        socket2::SockRef::from(&socket)
            .set_send_buffer_size(4 * 1024 * 1024)
            .map_err(|error| format!("could not enlarge WireGuard send buffer: {error}"))?;
        socket
            .connect(endpoint)
            .map_err(|error| format!("could not connect WireGuard endpoint: {error}"))?;
        let tunnel = Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(public_key),
            preshared_key,
            persistent_keepalive,
            rand::rng().random(),
            None,
        );
        Ok(Self {
            socket,
            tunnel,
            address,
            endpoint,
            identity_fingerprint: Sha256::digest(private_key).into(),
            handshake_started: None,
            handshake_latency_ms: None,
            read_timeout: None,
            network_buffer: vec![0_u8; 65_535],
            tunnel_buffer: vec![0_u8; 65_535],
        })
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn identity_fingerprint(&self) -> [u8; 32] {
        self.identity_fingerprint
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint && self.identity_fingerprint == other.identity_fingerprint
    }

    pub fn handshake_latency_ms(&self) -> Option<f64> {
        self.handshake_latency_ms
    }

    pub fn transact(&mut self, inner_packet: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        self.set_read_timeout(Duration::from_millis(400))?;
        let first = action(
            self.tunnel
                .encapsulate(inner_packet, &mut self.tunnel_buffer),
        )?;
        self.apply(first)?;
        let deadline = Instant::now() + timeout;
        let started = Instant::now();
        while Instant::now() < deadline {
            match self.socket.recv(&mut self.network_buffer) {
                Ok(length) => {
                    if self.handshake_latency_ms.is_none() {
                        self.handshake_latency_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                    }
                    let next = decapsulation_action(self.tunnel.decapsulate(
                        None,
                        &self.network_buffer[..length],
                        &mut self.tunnel_buffer,
                    ));
                    if let Some(packet) = self.apply(next)? {
                        return Ok(packet);
                    }
                    loop {
                        let drained = decapsulation_action(self.tunnel.decapsulate(
                            None,
                            &[],
                            &mut self.tunnel_buffer,
                        ));
                        if matches!(drained, Action::Done) {
                            break;
                        }
                        if let Some(packet) = self.apply(drained)? {
                            return Ok(packet);
                        }
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    let timer = action(self.tunnel.update_timers(&mut self.tunnel_buffer))?;
                    if let Some(packet) = self.apply(timer)? {
                        return Ok(packet);
                    }
                }
                Err(error) => return Err(format!("WireGuard receive failed: {error}")),
            }
        }
        Err("WireGuard path did not return a packet before timeout".into())
    }

    pub fn send_inner(&mut self, inner_packet: &[u8]) -> Result<(), String> {
        // The first packet out is what makes BoringTun emit its handshake
        // initiation, so this is the moment the round trip to the peer starts.
        self.handshake_started.get_or_insert_with(Instant::now);
        let first = action(
            self.tunnel
                .encapsulate(inner_packet, &mut self.tunnel_buffer),
        )?;
        self.apply(first)?;
        loop {
            let drained =
                decapsulation_action(self.tunnel.decapsulate(None, &[], &mut self.tunnel_buffer));
            if matches!(drained, Action::Done) {
                return Ok(());
            }
            self.apply(drained)?;
        }
    }

    pub fn receive_inner(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.set_read_timeout(timeout)?;
        let mut packets = Vec::new();
        match self.socket.recv(&mut self.network_buffer) {
            Ok(length) => {
                // Anything at all coming back from the peer is the handshake
                // response, so this doubles as proof the tunnel is alive.
                if let (None, Some(started)) = (self.handshake_latency_ms, self.handshake_started) {
                    self.handshake_latency_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                }
                let mut next = decapsulation_action(self.tunnel.decapsulate(
                    None,
                    &self.network_buffer[..length],
                    &mut self.tunnel_buffer,
                ));
                loop {
                    match next {
                        Action::Done => break,
                        Action::Network(packet) => {
                            self.socket
                                .send(&packet)
                                .map_err(|error| format!("WireGuard send failed: {error}"))?;
                        }
                        Action::Tunnel(packet) => packets.push(packet),
                    }
                    next = decapsulation_action(self.tunnel.decapsulate(
                        None,
                        &[],
                        &mut self.tunnel_buffer,
                    ));
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) => return Err(format!("WireGuard receive failed: {error}")),
        }
        let timer = action(self.tunnel.update_timers(&mut self.tunnel_buffer))?;
        if let Some(packet) = self.apply(timer)? {
            packets.push(packet);
        }
        Ok(packets)
    }

    fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        let timeout = crate::transport::socket_read_timeout(timeout);
        if self.read_timeout != Some(timeout) {
            self.socket
                .set_read_timeout(Some(timeout))
                .map_err(|error| error.to_string())?;
            self.read_timeout = Some(timeout);
        }
        Ok(())
    }

    fn apply(&self, action: Action) -> Result<Option<Vec<u8>>, String> {
        match action {
            Action::Done => Ok(None),
            Action::Network(packet) => {
                self.socket
                    .send(&packet)
                    .map_err(|error| format!("WireGuard send failed: {error}"))?;
                Ok(None)
            }
            Action::Tunnel(packet) => Ok(Some(packet)),
        }
    }
}

enum Action {
    Done,
    Network(Vec<u8>),
    Tunnel(Vec<u8>),
}

fn action(result: TunnResult<'_>) -> Result<Action, String> {
    match result {
        TunnResult::Done => Ok(Action::Done),
        TunnResult::Err(error) => Err(format!("WireGuard protocol error: {error:?}")),
        TunnResult::WriteToNetwork(packet) => Ok(Action::Network(packet.to_vec())),
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            Ok(Action::Tunnel(packet.to_vec()))
        }
    }
}

fn decapsulation_action(result: TunnResult<'_>) -> Action {
    // A connected UDP socket can still receive delayed packets from an older
    // WireGuard session. They are untrusted input and must not tear down a path.
    match action(result) {
        Ok(action) => action,
        Err(_) => Action::Done,
    }
}

pub fn ipv4_udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let total_length = 20_usize + 8 + payload.len();
    if total_length > u16::MAX as usize {
        return Err("UDP packet is too large".into());
    }
    let mut packet = vec![0_u8; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&rand::rng().random::<u16>().to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    Ok(packet)
}

pub fn ipv4_udp_payload(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u16, u16, &[u8])> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || packet.len() < header_length + 8 {
        return None;
    }
    let udp_length = usize::from(u16::from_be_bytes([
        packet[header_length + 4],
        packet[header_length + 5],
    ]));
    if udp_length < 8 || packet.len() < header_length + udp_length {
        return None;
    }
    Some((
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        u16::from_be_bytes([packet[header_length], packet[header_length + 1]]),
        u16::from_be_bytes([packet[header_length + 2], packet[header_length + 3]]),
        &packet[header_length + 8..header_length + udp_length],
    ))
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn decode_key(value: &str) -> Result<[u8; 32], String> {
    let decoded = STANDARD
        .decode(value.trim())
        .map_err(|_| "WireGuard key is not valid base64")?;
    decoded
        .try_into()
        .map_err(|_| "WireGuard key must contain 32 bytes".into())
}

fn required_value<'a>(source: &'a str, section: &str, key: &str) -> Result<&'a str, String> {
    section_value(source, section, key)
        .ok_or_else(|| format!("WireGuard configuration is missing {section} {key}"))
}

fn section_value<'a>(source: &'a str, wanted_section: &str, wanted_key: &str) -> Option<&'a str> {
    let mut section = "";
    for line in source.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = if line[1..line.len() - 1].eq_ignore_ascii_case(wanted_section) {
                wanted_section
            } else {
                ""
            };
            continue;
        }
        if section != wanted_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(wanted_key) {
            return Some(value.trim());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::errors::WireGuardError;

    #[test]
    fn ipv4_udp_round_trips() {
        let packet = ipv4_udp_packet(
            "10.0.0.2".parse().unwrap(),
            "203.0.113.2".parse().unwrap(),
            40000,
            51821,
            b"hello",
        )
        .unwrap();
        let (source, destination, source_port, destination_port, payload) =
            ipv4_udp_payload(&packet).unwrap();
        assert_eq!(source, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(destination, "203.0.113.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            (source_port, destination_port, payload),
            (40000, 51821, b"hello".as_slice())
        );
        assert_eq!(ipv4_checksum(&packet[..20]), 0);
    }

    #[test]
    fn stale_wireguard_packets_are_ignored() {
        assert!(matches!(
            decapsulation_action(TunnResult::Err(WireGuardError::NoCurrentSession)),
            Action::Done
        ));
    }

    #[test]
    fn same_identity_and_endpoint_conflict() {
        let private = STANDARD.encode([3_u8; 32]);
        let other_private = STANDARD.encode([4_u8; 32]);
        let public = STANDARD.encode([5_u8; 32]);
        let config = |private: &str, endpoint: &str| {
            format!(
                "[Interface]\nPrivateKey = {private}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {public}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0"
            )
        };
        let first =
            UserSpaceWireGuardPath::from_config(&config(&private, "127.0.0.1:51820")).unwrap();
        let duplicate =
            UserSpaceWireGuardPath::from_config(&config(&private, "127.0.0.1:51820")).unwrap();
        let other_endpoint =
            UserSpaceWireGuardPath::from_config(&config(&private, "127.0.0.1:51821")).unwrap();
        let other_identity =
            UserSpaceWireGuardPath::from_config(&config(&other_private, "127.0.0.1:51820"))
                .unwrap();
        assert!(first.conflicts_with(&duplicate));
        assert!(!first.conflicts_with(&other_endpoint));
        assert!(!first.conflicts_with(&other_identity));
    }
}
