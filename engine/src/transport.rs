use crate::auth::SessionCrypto;
use crate::protocol::{FrameHeader, HEADER_LEN};
use crate::scheduler::Decision;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

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
fn bind_to_interface(socket: &UdpSocket, address: IpAddr, interface_index: u32) -> io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET_ERROR, setsockopt,
    };

    let raw_socket = socket.as_raw_socket() as usize;
    let (level, option, value) = match address {
        IpAddr::V4(_) => (IPPROTO_IP, IP_UNICAST_IF, interface_index.to_be()),
        IpAddr::V6(_) => (IPPROTO_IPV6, IPV6_UNICAST_IF, interface_index),
    };
    // SAFETY: setsockopt reads exactly one u32 from a valid pointer for the
    // lifetime of this call. The socket handle belongs to the live UdpSocket.
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
fn bind_to_interface(
    _socket: &UdpSocket,
    _address: IpAddr,
    _interface_index: u32,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is currently implemented only on Windows",
    ))
}

#[cfg(test)]
mod tests {
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
}
