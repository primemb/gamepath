use crate::auth::SessionCrypto;
use crate::protocol::{FrameHeader, HEADER_LEN};
use crate::scheduler::Decision;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Shortest socket read timeout the platform accepts.
///
/// `SO_RCVTIMEO` reads zero as "block forever", so the standard library rejects
/// a zero duration outright. A path worker asking for the shortest possible
/// wait must not get an error back for it: the worker cannot tell that apart
/// from the node having gone away, and would take a perfectly healthy path out
/// of service. Sub-millisecond values round up to this anyway.
pub const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

/// Clamps a requested read timeout to something a socket will accept.
pub fn socket_read_timeout(requested: Duration) -> Duration {
    requested.max(MIN_READ_TIMEOUT)
}

pub struct UdpPath {
    id: String,
    socket: UdpSocket,
}

impl UdpPath {
    pub fn connect(
        id: impl Into<String>,
        local_address: IpAddr,
        interface_index: Option<u32>,
        relay: SocketAddr,
    ) -> io::Result<Self> {
        if local_address.is_ipv4() != relay.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "local and relay address families must match",
            ));
        }
        let socket = UdpSocket::bind(SocketAddr::new(local_address, 0))?;
        if let Some(index) = interface_index {
            bind_to_interface(&socket, local_address, index)?;
        }
        socket.connect(relay)?;
        Ok(Self {
            id: id.into(),
            socket,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    fn send_frame(&self, header: FrameHeader, payload: &[u8]) -> io::Result<usize> {
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(payload);
        self.socket.send(&frame)
    }

    fn send_datagram(&self, frame: &[u8]) -> io::Result<usize> {
        self.socket.send(frame)
    }
}

pub struct MultipathSender {
    paths: HashMap<String, UdpPath>,
}

impl MultipathSender {
    pub fn new(paths: impl IntoIterator<Item = UdpPath>) -> Self {
        Self {
            paths: paths
                .into_iter()
                .map(|path| (path.id.clone(), path))
                .collect(),
        }
    }

    pub fn send(
        &self,
        decision: &Decision,
        header: FrameHeader,
        payload: &[u8],
    ) -> io::Result<Vec<String>> {
        let selected: Vec<&str> = match decision {
            Decision::Drop => return Ok(Vec::new()),
            Decision::Single { path_id } => vec![path_id],
            Decision::Duplicate { path_ids } => path_ids.iter().map(String::as_str).collect(),
        };
        let mut sent = Vec::with_capacity(selected.len());
        for id in selected {
            let path = self.paths.get(id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("route socket not found: {id}"),
                )
            })?;
            path.send_frame(header, payload)?;
            sent.push(id.to_owned());
        }
        Ok(sent)
    }

    pub fn send_encrypted(
        &self,
        decision: &Decision,
        crypto: &SessionCrypto,
        header: FrameHeader,
        payload: &[u8],
    ) -> io::Result<Vec<String>> {
        let frame = crypto
            .seal_client(header, payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let selected: Vec<&str> = match decision {
            Decision::Drop => return Ok(Vec::new()),
            Decision::Single { path_id } => vec![path_id],
            Decision::Duplicate { path_ids } => path_ids.iter().map(String::as_str).collect(),
        };
        let mut sent = Vec::with_capacity(selected.len());
        for id in selected {
            let path = self.paths.get(id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("route socket not found: {id}"),
                )
            })?;
            path.send_datagram(&frame)?;
            sent.push(id.to_owned());
        }
        Ok(sent)
    }
}

#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

#[cfg(windows)]
pub fn bind_to_interface<S: AsRawSocket>(
    socket: &S,
    address: IpAddr,
    interface_index: u32,
) -> io::Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, setsockopt,
    };

    let raw_socket = socket.as_raw_socket() as usize;
    let (level, option, value) = match address {
        IpAddr::V4(_) => (IPPROTO_IP, IP_UNICAST_IF, interface_index.to_be()),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_UNICAST_IF, interface_index),
    };
    // SAFETY: setsockopt reads exactly one u32 from a valid pointer for the
    // lifetime of this call. The socket handle belongs to the live socket.
    let result = unsafe {
        setsockopt(
            raw_socket,
            level,
            option,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn bind_to_interface(
    _socket: &UdpSocket,
    _address: IpAddr,
    _interface_index: u32,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is currently implemented only on Windows",
    ))
}

/// Whether a send error means this socket can never carry anything again.
///
/// A socket bound to a VPN adapter's address and pinned to its interface with
/// `IP_UNICAST_IF` (the L2TP relay socket, an adapter node's sockets). When
/// Windows tears that adapter down - which happens on every L2TP redial, and
/// whenever another VPN app reconnects - the socket
/// outlives it and every send fails from then on. That is a different thing
/// from a datagram being dropped, and it needs a different answer: no probe
/// will succeed either, so waiting for three of them to time out only buys the
/// user three seconds of traffic pushed into a socket that cannot carry it.
///
/// Observed live as `WSAEINVAL` (10022), reported to the user as "L2TP relay
/// send failed: An invalid argument was supplied".
///
/// The list is deliberately short. `WSAECONNRESET` and `WSAEHOSTUNREACH` are
/// left out because Windows raises those from an ICMP message about an earlier
/// datagram - the socket is fine and the next send may well work, which is the
/// same reason [`crate::socks5`] swallows them on receive.
#[cfg(windows)]
pub fn is_interface_gone(error: &std::io::Error) -> bool {
    /// The bound local address no longer exists.
    const WSAEINVAL: i32 = 10022;
    /// The handle is no longer a socket.
    const WSAENOTSOCK: i32 = 10038;
    /// The interface underneath it was removed.
    const WSAEADDRNOTAVAIL: i32 = 10049;
    /// The network subsystem or that interface has gone down.
    const WSAENETDOWN: i32 = 10050;
    /// The connection was broken by the interface being reset.
    const WSAENETRESET: i32 = 10052;
    matches!(
        error.raw_os_error(),
        Some(WSAEINVAL | WSAENOTSOCK | WSAEADDRNOTAVAIL | WSAENETDOWN | WSAENETRESET)
    )
}

#[cfg(not(windows))]
pub fn is_interface_gone(_error: &std::io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_zero_read_timeout_is_clamped_rather_than_rejected() {
        use super::{MIN_READ_TIMEOUT, socket_read_timeout};
        use std::net::UdpSocket;
        use std::time::Duration;

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        // The reason the clamp exists: the platform refuses the raw value.
        assert!(socket.set_read_timeout(Some(Duration::ZERO)).is_err());
        assert!(
            socket
                .set_read_timeout(Some(socket_read_timeout(Duration::ZERO)))
                .is_ok()
        );
        assert_eq!(socket_read_timeout(Duration::ZERO), MIN_READ_TIMEOUT);
        // Anything longer is passed through untouched.
        assert_eq!(
            socket_read_timeout(Duration::from_millis(250)),
            Duration::from_millis(250)
        );
    }

    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;

    #[test]
    fn duplicate_decision_sends_identical_sequence_to_two_paths() {
        let receiver_one = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let receiver_two = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver_one
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        receiver_two
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let path_one = UdpPath::connect(
            "one",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            receiver_one.local_addr().unwrap(),
        )
        .unwrap();
        let path_two = UdpPath::connect(
            "two",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            receiver_two.local_addr().unwrap(),
        )
        .unwrap();
        let sender = MultipathSender::new([path_one, path_two]);
        let header = FrameHeader {
            flags: 0,
            client_id: [4; 16],
            session_id: 7,
            sequence: 99,
        };
        sender
            .send(
                &Decision::Duplicate {
                    path_ids: vec!["one".into(), "two".into()],
                },
                header,
                b"game-packet",
            )
            .unwrap();

        for receiver in [receiver_one, receiver_two] {
            let mut buffer = [0_u8; 256];
            let length = receiver.recv(&mut buffer).unwrap();
            assert_eq!(FrameHeader::decode(&buffer[..length]), Ok(header));
            assert_eq!(&buffer[HEADER_LEN..length], b"game-packet");
        }
    }

    #[test]
    fn secure_duplication_sends_one_authenticated_ciphertext_on_both_paths() {
        let receiver_one = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let receiver_two = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        for receiver in [&receiver_one, &receiver_two] {
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
        }
        let path_one = UdpPath::connect(
            "one",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            receiver_one.local_addr().unwrap(),
        )
        .unwrap();
        let path_two = UdpPath::connect(
            "two",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
            receiver_two.local_addr().unwrap(),
        )
        .unwrap();
        let sender = MultipathSender::new([path_one, path_two]);
        let header = FrameHeader {
            flags: 0,
            client_id: [8; 16],
            session_id: 55,
            sequence: 2,
        };
        let crypto = SessionCrypto::new(&[9; 32], header.session_id).unwrap();
        sender
            .send_encrypted(
                &Decision::Duplicate {
                    path_ids: vec!["one".into(), "two".into()],
                },
                &crypto,
                header,
                b"private-game-packet",
            )
            .unwrap();
        let mut frames = Vec::new();
        for receiver in [receiver_one, receiver_two] {
            let mut buffer = [0_u8; 256];
            let length = receiver.recv(&mut buffer).unwrap();
            frames.push(buffer[..length].to_vec());
        }
        assert_eq!(frames[0], frames[1]);
        assert!(
            !frames[0]
                .windows(b"private-game-packet".len())
                .any(|window| window == b"private-game-packet")
        );
        assert_eq!(
            crypto.open_client(&frames[0]).unwrap(),
            (header, b"private-game-packet".to_vec())
        );
    }

    /// The distinction the whole flag rests on: some send errors mean the
    /// socket is finished, and most do not.
    #[cfg(windows)]
    #[test]
    fn a_vanished_adapter_is_fatal_but_an_icmp_reply_is_not() {
        use super::is_interface_gone;
        use std::io::Error;

        // What a user actually saw, reported as "L2TP relay send failed: An
        // invalid argument was supplied": the RAS adapter went away underneath
        // a socket still bound to its address.
        assert!(is_interface_gone(&Error::from_raw_os_error(10022)));
        assert!(is_interface_gone(&Error::from_raw_os_error(10038)));
        assert!(is_interface_gone(&Error::from_raw_os_error(10049)));
        assert!(is_interface_gone(&Error::from_raw_os_error(10050)));
        assert!(is_interface_gone(&Error::from_raw_os_error(10052)));

        // Windows raises these from an ICMP message about a datagram already
        // sent. The socket is fine and the next send may well succeed, so
        // tearing the path down for one would be the more expensive mistake.
        assert!(!is_interface_gone(&Error::from_raw_os_error(10054)));
        assert!(!is_interface_gone(&Error::from_raw_os_error(10065)));
        assert!(!is_interface_gone(&Error::from_raw_os_error(10051)));

        // An error carrying no OS code cannot be classified, so it is not.
        assert!(!is_interface_gone(&Error::other("no code")));
    }
}
