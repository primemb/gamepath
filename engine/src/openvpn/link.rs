//! The socket underneath an OpenVPN session.
//!
//! OpenVPN is a datagram protocol whichever transport carries it. Over UDP each
//! packet is a datagram; over TCP each is preceded by its length, so the stream
//! can be cut back into the same packets. Everything above this module is
//! written once and works either way.

use super::config::Protocol;
use socket2::SockRef;
use std::collections::VecDeque;
use std::io::{self, Read as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// A receive buffer large enough that a burst of inbound traffic is not dropped
/// while the engine is between reads.
///
/// This preserves bursts between reads; it does not bound receive-side latency.
const RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

/// How much unsent data the kernel is allowed to hold for a TCP link.
///
/// This is deliberately small, and the reasoning is the opposite of the receive
/// side. Whatever the kernel has accepted from us is beyond our reach: it goes
/// out at whatever rate congestion control allows, in order, and cannot be
/// reordered or discarded. Handing TCP four megabytes means that during a stall
/// the next game packet queues behind up to four megabytes of older bytes, and
/// no policy above this layer can do anything about it - which is what made the
/// dispatcher's staleness rule stop at the socket boundary.
///
/// So the kernel gets a smaller fixed budget and the rest of the
/// backlog stays in [`Link`], where it can still be shed. The cost is a ceiling
/// on bulk upload throughput of about this many bytes per round trip - some
/// 35 Mbit/s on a 60 ms path. This is an estimate, not a measured guarantee;
/// at lower rates even this buffer can hold more than 50 ms of traffic.
const SEND_BUFFER: usize = 256 * 1024;

/// The most unsent data [`Link`] will hold before it refuses more.
///
/// A backstop against unbounded growth rather than the working limit: with a
/// stalled socket the age rule below empties the queue long before this.
const MAX_OUTBOUND_BYTES: usize = 256 * 1024;

/// How long a real-time packet is worth sending.
///
/// The same judgement the dispatcher's own send queue makes, applied here
/// because a stream transport hides the backlog from it. A game packet that has
/// waited this long describes a world that has moved on, and delivering it late
/// is worse than not delivering it at all: it costs bandwidth that the packet
/// behind it needs.
const MAX_OUTBOUND_AGE: Duration = Duration::from_millis(50);

/// The largest packet either transport will accept, which bounds what a
/// malformed length prefix can make us allocate.
const MAX_PACKET: usize = 65_535;

/// Whether a packet may be dropped when the link is backed up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Urgency {
    /// Tunnelled traffic. The overlay already treats loss on a path as
    /// ordinary - it is what every datagram transport does under congestion -
    /// so shedding a stale packet here is better than delivering it late behind
    /// a stalled stream.
    Realtime,
    /// Control traffic: TLS, rekeys, keepalives and overlay health probes.
    /// Shedding these can stall a session or falsely report a path as dead.
    Reliable,
}

/// One length-prefixed packet waiting for the socket to accept it.
///
/// Public only because it appears in a field of the public [`Link`]; its
/// contents are this module's business.
pub struct Outbound {
    bytes: Vec<u8>,
    queued: Instant,
    urgency: Urgency,
}

pub enum Link {
    Udp(UdpSocket),
    Tcp {
        stream: TcpStream,
        /// Bytes read from the stream that do not yet form a whole packet.
        pending: Vec<u8>,
        /// Packets the socket has not accepted yet, oldest first.
        outbound: VecDeque<Outbound>,
        /// How much of the packet at the head is already on the wire. Non-zero
        /// means that packet is committed and can no longer be dropped.
        written: usize,
        /// Bytes in `outbound` still to be written, kept as a running total so
        /// the budget check is not a walk of the queue.
        queued_bytes: usize,
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
                // A datagram leaves as soon as it is sent, so there is no queue
                // to keep short and the buffer only has to be big enough not to
                // drop a burst.
                tune(SockRef::from(&socket), RECEIVE_BUFFER)?;
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
                tune(SockRef::from(&stream), SEND_BUFFER)?;
                Ok(Self::Tcp {
                    stream,
                    pending: Vec::new(),
                    outbound: VecDeque::new(),
                    written: 0,
                    queued_bytes: 0,
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

    /// Sends one packet, or queues it if the socket cannot take it yet.
    ///
    /// Over TCP this never blocks. A blocking `write_all` here would stall the
    /// worker thread that also runs this path's health probes and timers, so a
    /// congested link would present as a dead one - the failure this whole
    /// layer exists to avoid.
    pub fn send(&mut self, packet: &[u8], urgency: Urgency) -> Result<(), String> {
        if let Self::Udp(socket) = self {
            return socket
                .send(packet)
                .map(|_| ())
                .map_err(|error| format!("could not send an OpenVPN packet: {error}"));
        }
        self.enqueue(packet, urgency)?;
        self.flush_outbound()
    }

    /// Frames a packet and puts it at the back of the queue.
    fn enqueue(&mut self, packet: &[u8], urgency: Urgency) -> Result<(), String> {
        let Self::Tcp {
            outbound,
            written,
            queued_bytes,
            ..
        } = self
        else {
            return Ok(());
        };
        let length = u16::try_from(packet.len())
            .map_err(|_| "an OpenVPN packet was too large for a TCP link".to_owned())?;
        let mut bytes = Vec::with_capacity(2 + packet.len());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(packet);
        *queued_bytes += bytes.len();
        outbound.push_back(Outbound {
            bytes,
            queued: Instant::now(),
            urgency,
        });
        if *queued_bytes > MAX_OUTBOUND_BYTES {
            shed(outbound, *written, queued_bytes, Instant::now());
        }
        // Only control traffic, which is never shed, can still be over budget
        // here - and that much of it unsent means the stream is not moving.
        if *queued_bytes > MAX_OUTBOUND_BYTES {
            return Err("the OpenVPN link stopped accepting control traffic".to_owned());
        }
        Ok(())
    }

    /// Pushes as much of the queue into the socket as it will take, dropping
    /// real-time packets that are no longer worth sending.
    ///
    /// Called on every send and once per pass of the session loop, so a queue
    /// that built up during a stall drains as soon as the socket recovers.
    pub fn flush_outbound(&mut self) -> Result<(), String> {
        let Self::Tcp {
            stream,
            outbound,
            written,
            queued_bytes,
            ..
        } = self
        else {
            return Ok(());
        };
        if outbound.is_empty() {
            return Ok(());
        }
        shed(outbound, *written, queued_bytes, Instant::now());
        if outbound.is_empty() {
            return Ok(());
        }
        // Non-blocking for the write only. Reads use a blocking call with
        // SO_RCVTIMEO, so the socket is put back the way it was - including
        // when the write itself fails.
        stream
            .set_nonblocking(true)
            .map_err(|error| format!("could not prepare the OpenVPN link for writing: {error}"))?;
        let outcome = write_queued(stream, outbound, written, queued_bytes);
        let restored = stream
            .set_nonblocking(false)
            .map_err(|error| format!("could not restore the OpenVPN link after writing: {error}"));
        outcome.and(restored)
    }

    /// Reads one packet, waiting at most `timeout`.
    ///
    /// `Ok(None)` means the wait expired with nothing to report, which is the
    /// normal state of an idle tunnel rather than a failure.
    pub fn receive(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let timeout = crate::transport::socket_read_timeout(timeout);
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
            Self::Tcp {
                stream, pending, ..
            } => {
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

/// Writes queued packets until the socket will take no more.
///
/// The socket is non-blocking, so a short write is expected rather than
/// exceptional: the offset into the packet at the head is kept, and the next
/// call continues from there. That is what makes this safe on a length-prefixed
/// stream - a `write_all` interrupted part-way through would leave a truncated
/// frame behind it and desynchronise the reader for good.
fn write_queued(
    stream: &mut impl io::Write,
    outbound: &mut VecDeque<Outbound>,
    written: &mut usize,
    queued_bytes: &mut usize,
) -> Result<(), String> {
    loop {
        let Some(front) = outbound.front() else {
            return Ok(());
        };
        match stream.write(&front.bytes[*written..]) {
            // The socket will not take more right now. Not a failure: the queue
            // keeps the packet and the next pass tries again.
            Ok(0) => return Ok(()),
            Ok(count) => {
                let complete = *written + count == front.bytes.len();
                *written += count;
                *queued_bytes -= count;
                if complete {
                    outbound.pop_front();
                    *written = 0;
                }
            }
            Err(error) if waited(&error) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("could not send an OpenVPN packet: {error}")),
        }
    }
}

/// Drops real-time packets that are no longer worth sending, oldest first.
///
/// The packet at the head is spared whenever part of it is already on the wire.
/// The stream is length-prefixed, so removing a packet the reader has begun to
/// see would desynchronise it permanently - far worse than the delay being
/// avoided.
fn shed(outbound: &mut VecDeque<Outbound>, written: usize, queued_bytes: &mut usize, now: Instant) {
    let mut index = usize::from(written > 0);
    while index < outbound.len() {
        let frame = &outbound[index];
        let stale = now.saturating_duration_since(frame.queued) > MAX_OUTBOUND_AGE;
        if frame.urgency == Urgency::Realtime && (stale || *queued_bytes > MAX_OUTBOUND_BYTES) {
            *queued_bytes -= frame.bytes.len();
            outbound.remove(index);
        } else {
            index += 1;
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

fn tune(socket: SockRef<'_>, send_buffer: usize) -> Result<(), String> {
    socket
        .set_recv_buffer_size(RECEIVE_BUFFER)
        .map_err(|error| format!("could not enlarge the OpenVPN receive buffer: {error}"))?;
    socket
        .set_send_buffer_size(send_buffer)
        .map_err(|error| format!("could not size the OpenVPN send buffer: {error}"))
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
    use std::io::Write as _;
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
        link.send(b"ping", Urgency::Realtime).unwrap();
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

    fn queued(urgency: Urgency, age: Duration, size: usize) -> Outbound {
        Outbound {
            bytes: vec![0; size],
            queued: Instant::now() - age,
            urgency,
        }
    }

    fn total(outbound: &VecDeque<Outbound>) -> usize {
        outbound.iter().map(|frame| frame.bytes.len()).sum()
    }

    #[test]
    fn a_stale_game_packet_is_dropped_rather_than_sent_late() {
        let mut outbound = VecDeque::from(vec![
            queued(Urgency::Realtime, Duration::from_millis(400), 100),
            queued(Urgency::Realtime, Duration::ZERO, 100),
        ]);
        let mut queued_bytes = total(&outbound);
        shed(&mut outbound, 0, &mut queued_bytes, Instant::now());
        assert_eq!(outbound.len(), 1, "the stale packet should be gone");
        assert_eq!(queued_bytes, 100);
        assert_eq!(queued_bytes, total(&outbound), "the running total drifted");
    }

    /// Dropping a handshake or rekey packet stalls the session, so age is not
    /// a reason to drop one however backed up the link is.
    #[test]
    fn control_traffic_is_never_shed() {
        let mut outbound = VecDeque::from(vec![
            queued(Urgency::Reliable, Duration::from_secs(30), 100),
            queued(Urgency::Realtime, Duration::from_secs(30), 100),
        ]);
        let mut queued_bytes = total(&outbound);
        shed(&mut outbound, 0, &mut queued_bytes, Instant::now());
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].urgency, Urgency::Reliable);
        assert_eq!(queued_bytes, total(&outbound));
    }

    /// The one packet that must survive shedding whatever its age: the reader
    /// has already seen the front of it, and a length-prefixed stream cannot
    /// recover from half a frame going missing.
    #[test]
    fn a_partly_written_packet_is_never_dropped() {
        let mut outbound = VecDeque::from(vec![
            queued(Urgency::Realtime, Duration::from_secs(30), 100),
            queued(Urgency::Realtime, Duration::from_secs(30), 100),
        ]);
        let mut queued_bytes = total(&outbound) - 40;
        shed(&mut outbound, 40, &mut queued_bytes, Instant::now());
        assert_eq!(outbound.len(), 1, "the committed packet has to stay");
        assert_eq!(queued_bytes, 60);
    }

    #[test]
    fn short_writes_resume_without_corrupting_frames_or_shedding_probes() {
        struct Writer {
            bytes: Vec<u8>,
            allowance: usize,
        }
        impl io::Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.allowance == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let count = bytes.len().min(self.allowance);
                self.bytes.extend_from_slice(&bytes[..count]);
                self.allowance -= count;
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        // Stop inside the length prefix and inside the payload, respectively.
        for allowance in [1, 4] {
            let now = Instant::now();
            let mut outbound = VecDeque::new();
            for (packet, urgency) in [
                (b"committed".as_slice(), Urgency::Realtime),
                (b"stale".as_slice(), Urgency::Realtime),
                (b"probe".as_slice(), Urgency::Reliable),
            ] {
                let mut bytes = u16::try_from(packet.len()).unwrap().to_be_bytes().to_vec();
                bytes.extend_from_slice(packet);
                outbound.push_back(Outbound {
                    bytes,
                    queued: now,
                    urgency,
                });
            }
            let mut queued_bytes = total(&outbound);
            let mut written = 0;
            let mut writer = Writer {
                bytes: Vec::new(),
                allowance,
            };
            write_queued(&mut writer, &mut outbound, &mut written, &mut queued_bytes).unwrap();
            assert_eq!(written, allowance);
            assert_eq!(queued_bytes, total(&outbound) - written);

            shed(
                &mut outbound,
                written,
                &mut queued_bytes,
                now + Duration::from_millis(100),
            );
            assert_eq!(outbound.len(), 2);
            assert_eq!(queued_bytes, total(&outbound) - written);

            // A fresh game update can follow the surviving probe.
            outbound.push_back(Outbound {
                bytes: vec![0, 3, b'n', b'e', b'w'],
                queued: now + Duration::from_millis(100),
                urgency: Urgency::Realtime,
            });
            queued_bytes += 5;
            writer.allowance = usize::MAX;
            write_queued(&mut writer, &mut outbound, &mut written, &mut queued_bytes).unwrap();
            assert!(outbound.is_empty());
            assert_eq!((written, queued_bytes), (0, 0));
            for expected in [
                b"committed".as_slice(),
                b"probe".as_slice(),
                b"new".as_slice(),
            ] {
                assert_eq!(take_framed(&mut writer.bytes).unwrap().unwrap(), expected);
            }
            assert!(writer.bytes.is_empty());
        }
    }

    /// Shedding is oldest-first, because the newest game packet is the one
    /// still worth arriving.
    #[test]
    fn the_backlog_is_bounded_and_the_newest_packets_are_the_survivors() {
        let mut outbound = VecDeque::new();
        // Each one fresh, so only the byte budget can force a drop.
        for index in 0..400 {
            outbound.push_back(Outbound {
                bytes: vec![u8::try_from(index % 251).unwrap(); 1400],
                queued: Instant::now(),
                urgency: Urgency::Realtime,
            });
        }
        let mut queued_bytes = total(&outbound);
        assert!(queued_bytes > MAX_OUTBOUND_BYTES);
        shed(&mut outbound, 0, &mut queued_bytes, Instant::now());
        assert!(
            queued_bytes <= MAX_OUTBOUND_BYTES,
            "still holding {queued_bytes} bytes"
        );
        assert_eq!(queued_bytes, total(&outbound));
        let last = outbound.back().unwrap().bytes[0];
        assert_eq!(
            last,
            u8::try_from(399 % 251).unwrap(),
            "the newest packet should have survived"
        );
    }

    /// The reason the queue exists. A peer that stops reading used to block
    /// `write_all` on the worker thread, which also runs this path's health
    /// probes - so a congested link presented as a dead one.
    #[test]
    fn a_peer_that_stops_reading_does_not_block_the_sender() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        // Accepts and then never reads a byte, holding the connection open.
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = wait.recv();
            drop(stream);
        });

        let mut link = Link::connect(Protocol::Tcp, address, Duration::from_secs(2)).unwrap();
        let packet = vec![7_u8; 1400];
        let started = Instant::now();
        // Far more than the socket buffer, so the writer is certain to be
        // pushed back at some point.
        for _ in 0..4_000 {
            link.send(&packet, Urgency::Realtime).unwrap();
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "sending took {elapsed:?}, so it blocked"
        );

        let Link::Tcp {
            outbound,
            queued_bytes,
            written,
            ..
        } = &link
        else {
            panic!("expected a tcp link");
        };
        assert!(
            *queued_bytes <= MAX_OUTBOUND_BYTES,
            "the backlog grew to {queued_bytes} bytes"
        );
        assert_eq!(*queued_bytes, total(outbound) - written);

        drop(release);
        server.join().unwrap();
    }

    /// And the socket has to be blocking again afterwards, or the next read
    /// returns immediately and the session loop spins.
    #[test]
    fn the_socket_is_left_blocking_after_a_flush() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(300));
            drop(stream);
        });

        let mut link = Link::connect(Protocol::Tcp, address, Duration::from_secs(2)).unwrap();
        link.send(b"ping", Urgency::Realtime).unwrap();
        link.flush_outbound().unwrap();
        // A non-blocking socket would come back instantly; a blocking one with
        // SO_RCVTIMEO waits out the timeout it was given.
        let started = Instant::now();
        let _ = link.receive(Duration::from_millis(120));
        assert!(
            started.elapsed() >= Duration::from_millis(80),
            "the read returned after {:?}, so the socket was left non-blocking",
            started.elapsed()
        );
        server.join().unwrap();
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
