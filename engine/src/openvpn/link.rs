//! The socket underneath an OpenVPN session.
//!
//! OpenVPN is a datagram protocol whichever transport carries it. Over UDP each
//! packet is a datagram; over TCP each is preceded by its length, so the stream
//! can be cut back into the same packets. Everything above this module is
//! written once and works either way.

use super::config::Protocol;
use socket2::SockRef;
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// A socket buffer large enough that a burst of inbound traffic is not dropped
/// while the engine is between reads.
const SOCKET_BUFFER: usize = 4 * 1024 * 1024;

/// The largest packet either transport will accept, which bounds what a
/// malformed length prefix can make us allocate.
const MAX_PACKET: usize = 65_535;

pub enum Link {
    Udp(UdpSocket),
    Tcp {
        stream: TcpStream,
        /// Bytes read from the stream that do not yet form a whole packet.
        pending: Vec<u8>,
    },
}

impl Link {
    pub fn connect(
        protocol: Protocol,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, String> {
        match protocol {
            Protocol::Udp => {
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .map_err(|error| format!("could not create an OpenVPN UDP socket: {error}"))?;
                tune(SockRef::from(&socket))?;
                socket.connect(address).map_err(|error| {
                    format!("could not point a socket at OpenVPN server {address}: {error}")
                })?;
                Ok(Self::Udp(socket))
            }
            Protocol::Tcp => {
                let stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
                    format!("could not reach OpenVPN server {address}: {error}")
                })?;
                // Handshake packets are small and latency matters more than
                // packing them together, and once traffic flows every packet is
                // a game packet that must not wait for a fuller segment.
                stream.set_nodelay(true).map_err(|error| {
                    format!("could not disable Nagle on the OpenVPN link: {error}")
                })?;
                tune(SockRef::from(&stream))?;
                Ok(Self::Tcp {
                    stream,
                    pending: Vec::new(),
                })
            }
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Udp(socket) => socket.peer_addr().ok(),
            Self::Tcp { stream, .. } => stream.peer_addr().ok(),
        }
    }

    pub fn send(&mut self, packet: &[u8]) -> Result<(), String> {
        match self {
            Self::Udp(socket) => socket
                .send(packet)
                .map(|_| ())
                .map_err(|error| format!("could not send an OpenVPN packet: {error}")),
            Self::Tcp { stream, .. } => {
                let length = u16::try_from(packet.len())
                    .map_err(|_| "an OpenVPN packet was too large for a TCP link".to_owned())?;
                let mut framed = Vec::with_capacity(2 + packet.len());
                framed.extend_from_slice(&length.to_be_bytes());
                framed.extend_from_slice(packet);
                stream
                    .write_all(&framed)
                    .map_err(|error| format!("could not send an OpenVPN packet: {error}"))
            }
        }
    }

    /// Reads one packet, waiting at most `timeout`.
    ///
    /// `Ok(None)` means the wait expired with nothing to report, which is the
    /// normal state of an idle tunnel rather than a failure.
    pub fn receive(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::Udp(socket) => {
                socket
                    .set_read_timeout(Some(timeout))
                    .map_err(|error| format!("could not set an OpenVPN read timeout: {error}"))?;
                let mut buffer = vec![0_u8; MAX_PACKET];
                match socket.recv(&mut buffer) {
                    Ok(length) => {
                        buffer.truncate(length);
                        Ok(Some(buffer))
                    }
                    Err(error) if waited(&error) => Ok(None),
                    // A datagram socket reports an unreachable port from an
                    // earlier send as an error on the next read. That says
                    // nothing about the socket, so it is not fatal.
                    Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(None),
                    Err(error) => Err(format!("could not read from the OpenVPN link: {error}")),
                }
            }
            Self::Tcp { stream, pending } => {
                if let Some(packet) = take_framed(pending)? {
                    return Ok(Some(packet));
                }
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|error| format!("could not set an OpenVPN read timeout: {error}"))?;
                let mut chunk = [0_u8; 8192];
                match stream.read(&mut chunk) {
                    Ok(0) => Err("the OpenVPN server closed the connection".into()),
                    Ok(length) => {
                        pending.extend_from_slice(&chunk[..length]);
                        take_framed(pending)
                    }
                    Err(error) if waited(&error) => Ok(None),
                    Err(error) => Err(format!("could not read from the OpenVPN link: {error}")),
                }
            }
        }
    }
}

/// Cuts one length-prefixed packet off the front of a buffer.
fn take_framed(pending: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    if pending.len() < 2 {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes([pending[0], pending[1]]));
    if length == 0 {
        return Err("the OpenVPN server framed a zero-length packet".into());
    }
    if pending.len() < 2 + length {
        return Ok(None);
    }
    let packet = pending[2..2 + length].to_vec();
    pending.drain(..2 + length);
    Ok(Some(packet))
}

fn tune(socket: SockRef<'_>) -> Result<(), String> {
    socket
        .set_recv_buffer_size(SOCKET_BUFFER)
        .map_err(|error| format!("could not enlarge the OpenVPN receive buffer: {error}"))?;
    socket
        .set_send_buffer_size(SOCKET_BUFFER)
        .map_err(|error| format!("could not enlarge the OpenVPN send buffer: {error}"))
}

/// Whether an error only means the read timeout expired.
fn waited(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn a_framed_packet_is_taken_only_once_it_is_whole() {
        let mut pending = vec![0, 5, b'a', b'b'];
        assert!(take_framed(&mut pending).unwrap().is_none());
        pending.extend_from_slice(b"cde");
        assert_eq!(
            take_framed(&mut pending).unwrap().unwrap(),
            b"abcde".to_vec()
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn two_packets_arriving_together_are_read_one_at_a_time() {
        let mut pending = vec![0, 1, b'x', 0, 2, b'y', b'z'];
        assert_eq!(take_framed(&mut pending).unwrap().unwrap(), b"x".to_vec());
        assert_eq!(take_framed(&mut pending).unwrap().unwrap(), b"yz".to_vec());
        assert!(take_framed(&mut pending).unwrap().is_none());
    }

    #[test]
    fn a_zero_length_frame_is_refused_rather_than_looping() {
        let mut pending = vec![0, 0, 1, 2];
        assert!(take_framed(&mut pending).is_err());
    }

    #[test]
    fn a_tcp_link_round_trips_a_packet_with_its_length() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0_u8; 2];
            stream.read_exact(&mut header).unwrap();
            let mut body = vec![0_u8; usize::from(u16::from_be_bytes(header))];
            stream.read_exact(&mut body).unwrap();
            // Answer with a packet split across two writes, so the reader has
            // to reassemble it.
            stream.write_all(&[0, 4, b'p']).unwrap();
            stream.flush().unwrap();
            stream.write_all(b"ong").unwrap();
            body
        });
        let mut link = Link::connect(Protocol::Tcp, address, Duration::from_secs(2)).unwrap();
        link.send(b"ping").unwrap();
        let mut received = None;
        for _ in 0..20 {
            if let Some(packet) = link.receive(Duration::from_millis(200)).unwrap() {
                received = Some(packet);
                break;
            }
        }
        assert_eq!(received.unwrap(), b"pong".to_vec());
        assert_eq!(server.join().unwrap(), b"ping".to_vec());
    }

    #[test]
    fn a_udp_link_reports_an_idle_wait_rather_than_an_error() {
        // A port nothing is listening on: the read must simply expire.
        let mut link = Link::connect(
            Protocol::Udp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(link.receive(Duration::from_millis(50)).unwrap().is_none());
    }
}
