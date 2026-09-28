//! Hands inbound tunnel packets to the engine's own network stack when they
//! answer a flow that stack opened, before capture ever sees them.
//!
//! The LAN proxy terminates a console's connections in user space and opens
//! its own flows through the session from the session address. Their replies
//! arrive on the same inbound path as a captured game's, so they have to be
//! told apart here: capture would write them into Wintun, or reinject them
//! into WinDivert, where the machine has no socket for them and answers with
//! a reset.
//!
//! The decision is a port lookup. The stack claims every local port it uses,
//! and it takes those ports by binding a real socket first, so Windows can
//! never hand the same port to an application whose traffic capture carries.
//! The lookup is a bitmap of atomics, which keeps the per-packet cost of a
//! session without a proxy to one relaxed load.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const PORT_WORDS: usize = 65_536 / 64;

/// How long a fragmented datagram's later pieces keep following its first
/// one. Longer than any reassembly the stack would wait for.
const FRAGMENT_TRACK_TTL: Duration = Duration::from_secs(5);
const FRAGMENT_TRACK_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

/// The receiving end of diverted packets.
pub(crate) trait LocalStackSink: Send + Sync {
    /// Takes one packet, or gives it back when the stack cannot hold more.
    fn deliver(&self, packet: Vec<u8>) -> Result<(), Vec<u8>>;
}

pub(crate) enum Diversion {
    /// Not the stack's: capture carries it as before.
    NotLocal(Vec<u8>),
    Taken,
    /// The stack's, but its inbox is full. Dropped rather than handed to
    /// capture, which has no socket for it.
    Full,
}

pub(crate) struct LocalTap {
    armed: AtomicBool,
    tcp: Box<[AtomicU64]>,
    udp: Box<[AtomicU64]>,
    sink: RwLock<Option<Arc<dyn LocalStackSink>>>,
    /// `(source, IP identification)` of fragmented datagrams whose first piece
    /// was diverted. Later pieces carry no port, so they are matched on this.
    fragments: Mutex<VecDeque<(u32, u16, Instant)>>,
}

impl Default for LocalTap {
    fn default() -> Self {
        let bitmap = || (0..PORT_WORDS).map(|_| AtomicU64::new(0)).collect();
        Self {
            armed: AtomicBool::new(false),
            tcp: bitmap(),
            udp: bitmap(),
            sink: RwLock::new(None),
            fragments: Mutex::new(VecDeque::new()),
        }
    }
}

impl LocalTap {
    pub(crate) fn attach(&self, sink: Arc<dyn LocalStackSink>) {
        *self.sink.write().unwrap() = Some(sink);
        self.armed.store(true, Ordering::Release);
    }

    /// Stops diverting and forgets every claim, so a stack that stops cannot
    /// leave ports behind that swallow a later application's replies.
    pub(crate) fn detach(&self) {
        self.armed.store(false, Ordering::Release);
        *self.sink.write().unwrap() = None;
        for word in self.tcp.iter().chain(self.udp.iter()) {
            word.store(0, Ordering::Relaxed);
        }
        self.fragments.lock().unwrap().clear();
    }

    fn bitmap(&self, protocol: Protocol) -> &[AtomicU64] {
        match protocol {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
        }
    }

    pub(crate) fn claim(&self, protocol: Protocol, port: u16) {
        let (word, bit) = (usize::from(port) / 64, u64::from(port) % 64);
        self.bitmap(protocol)[word].fetch_or(1 << bit, Ordering::AcqRel);
    }

    pub(crate) fn release(&self, protocol: Protocol, port: u16) {
        let (word, bit) = (usize::from(port) / 64, u64::from(port) % 64);
        self.bitmap(protocol)[word].fetch_and(!(1 << bit), Ordering::AcqRel);
    }

    fn is_claimed(&self, protocol: Protocol, port: u16) -> bool {
        let (word, bit) = (usize::from(port) / 64, u64::from(port) % 64);
        self.bitmap(protocol)[word].load(Ordering::Acquire) & (1 << bit) != 0
    }

    pub(crate) fn divert(&self, packet: Vec<u8>) -> Diversion {
        if !self.armed.load(Ordering::Acquire) {
            return Diversion::NotLocal(packet);
        }
        let Some(header) = Ipv4Header::parse(&packet) else {
            return Diversion::NotLocal(packet);
        };
        let local = match header.destination_port {
            Some((protocol, port)) => {
                let claimed = self.is_claimed(protocol, port);
                if claimed && header.more_fragments {
                    self.track_fragment(header.source, header.identification);
                }
                claimed
            }
            // A later fragment: no ports, only the datagram it belongs to.
            None => self.is_tracked_fragment(header.source, header.identification),
        };
        if !local {
            return Diversion::NotLocal(packet);
        }
        let sink = self.sink.read().unwrap().clone();
        match sink.map(|sink| sink.deliver(packet)) {
            Some(Ok(())) => Diversion::Taken,
            Some(Err(_)) | None => Diversion::Full,
        }
    }

    fn track_fragment(&self, source: u32, identification: u16) {
        let mut fragments = self.fragments.lock().unwrap();
        let now = Instant::now();
        fragments.retain(|(_, _, seen)| now.duration_since(*seen) < FRAGMENT_TRACK_TTL);
        if fragments.len() >= FRAGMENT_TRACK_LIMIT {
            fragments.pop_front();
        }
        fragments.push_back((source, identification, now));
    }

    fn is_tracked_fragment(&self, source: u32, identification: u16) -> bool {
        let fragments = self.fragments.lock().unwrap();
        fragments.iter().any(|(from, id, seen)| {
            *from == source && *id == identification && seen.elapsed() < FRAGMENT_TRACK_TTL
        })
    }
}

struct Ipv4Header {
    source: u32,
    identification: u16,
    more_fragments: bool,
    /// Absent on every fragment but the first.
    destination_port: Option<(Protocol, u16)>,
}

impl Ipv4Header {
    fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return None;
        }
        let protocol = match packet[9] {
            IPPROTO_TCP => Protocol::Tcp,
            IPPROTO_UDP => Protocol::Udp,
            _ => return None,
        };
        let header_length = usize::from(packet[0] & 0x0f) * 4;
        let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
        let offset = flags_offset & 0x1fff;
        let destination_port = if offset == 0 {
            let port = packet.get(header_length + 2..header_length + 4)?;
            Some((protocol, u16::from_be_bytes([port[0], port[1]])))
        } else {
            None
        };
        Some(Self {
            source: u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]),
            identification: u16::from_be_bytes([packet[4], packet[5]]),
            more_fragments: flags_offset & 0x2000 != 0,
            destination_port,
        })
    }
}

/// Where a path worker puts an inbound packet: the local stack when it owns
/// the flow, otherwise the capture's queue.
pub(crate) trait InboundQueue {
    fn try_send(&self, packet: Vec<u8>) -> Result<(), mpsc::TrySendError<Vec<u8>>>;
}

impl InboundQueue for mpsc::SyncSender<Vec<u8>> {
    fn try_send(&self, packet: Vec<u8>) -> Result<(), mpsc::TrySendError<Vec<u8>>> {
        mpsc::SyncSender::try_send(self, packet)
    }
}

#[derive(Clone)]
pub(crate) struct InboundSink {
    queue: mpsc::SyncSender<Vec<u8>>,
    tap: Arc<LocalTap>,
}

impl InboundSink {
    pub(crate) fn new(queue: mpsc::SyncSender<Vec<u8>>, tap: Arc<LocalTap>) -> Self {
        Self { queue, tap }
    }
}

impl InboundQueue for InboundSink {
    fn try_send(&self, packet: Vec<u8>) -> Result<(), mpsc::TrySendError<Vec<u8>>> {
        match self.tap.divert(packet) {
            Diversion::NotLocal(packet) => self.queue.try_send(packet),
            Diversion::Taken => Ok(()),
            Diversion::Full => Err(mpsc::TrySendError::Full(Vec::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Collect(Mutex<Vec<Vec<u8>>>);

    impl LocalStackSink for Collect {
        fn deliver(&self, packet: Vec<u8>) -> Result<(), Vec<u8>> {
            self.0.lock().unwrap().push(packet);
            Ok(())
        }
    }

    fn packet(protocol: u8, port: u16, flags_offset: u16, identification: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[4..6].copy_from_slice(&identification.to_be_bytes());
        packet[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[8, 8, 8, 8]);
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet
    }

    fn tap_with_sink() -> (LocalTap, Arc<Collect>) {
        let tap = LocalTap::default();
        let sink = Arc::new(Collect(Mutex::new(Vec::new())));
        tap.attach(sink.clone());
        (tap, sink)
    }

    #[test]
    fn only_claimed_ports_of_the_same_protocol_are_diverted() {
        let (tap, sink) = tap_with_sink();
        tap.claim(Protocol::Tcp, 50_000);
        assert!(matches!(
            tap.divert(packet(6, 50_000, 0, 1)),
            Diversion::Taken
        ));
        // The same number on UDP is some application's socket.
        assert!(matches!(
            tap.divert(packet(17, 50_000, 0, 1)),
            Diversion::NotLocal(_)
        ));
        assert!(matches!(
            tap.divert(packet(6, 50_001, 0, 1)),
            Diversion::NotLocal(_)
        ));
        tap.release(Protocol::Tcp, 50_000);
        assert!(matches!(
            tap.divert(packet(6, 50_000, 0, 1)),
            Diversion::NotLocal(_)
        ));
        assert_eq!(sink.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn detaching_forgets_every_claim() {
        let (tap, _sink) = tap_with_sink();
        tap.claim(Protocol::Udp, 40_000);
        tap.detach();
        tap.attach(Arc::new(Collect(Mutex::new(Vec::new()))));
        assert!(matches!(
            tap.divert(packet(17, 40_000, 0, 1)),
            Diversion::NotLocal(_)
        ));
    }

    #[test]
    fn later_fragments_follow_a_diverted_first_fragment() {
        let (tap, sink) = tap_with_sink();
        tap.claim(Protocol::Udp, 51_000);
        assert!(matches!(
            tap.divert(packet(17, 51_000, 0x2000, 77)),
            Diversion::Taken
        ));
        // Offset 185 (1480 bytes), last fragment: no UDP header of its own.
        assert!(matches!(
            tap.divert(packet(17, 0, 185, 77)),
            Diversion::Taken
        ));
        assert!(matches!(
            tap.divert(packet(17, 0, 185, 78)),
            Diversion::NotLocal(_)
        ));
        assert_eq!(sink.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn an_idle_tap_passes_everything_through() {
        let tap = LocalTap::default();
        tap.claim(Protocol::Tcp, 1);
        assert!(matches!(
            tap.divert(packet(6, 1, 0, 1)),
            Diversion::NotLocal(_)
        ));
    }
}
