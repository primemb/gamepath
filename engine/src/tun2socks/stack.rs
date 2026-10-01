//! The event loop behind [`super::Socks5Stack`].
//!
//! Captured packets come in as raw IPv4. TCP goes into a smoltcp interface
//! that accepts any destination, so every connection an application opens is
//! answered here and replayed through the proxy with `CONNECT`. UDP is
//! forwarded datagram by datagram over one `UDP ASSOCIATE` per local socket.
//! Name lookups go over TCP through the proxy, which works whether or not the
//! proxy carries UDP. One thread and one `mio` poll drive all of it.
//!
//! A connection is only answered once the proxy has opened its far end: the
//! held SYN is fed to smoltcp then, or refused with a reset. Answering first
//! would make every connection look open while the proxy is down, and would
//! hand the session's health check packets the proxy never carried.

use super::handshake::{Command, Handshake, Step};
use super::packet::{
    PROTOCOL_TCP, PROTOCOL_UDP, build_echo_reply, build_tcp_reset, build_udp, is_echo_request,
    parse_ipv4, parse_tcp, parse_udp,
};
use crate::{log_info, log_warn};
use mio::net::{TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Registry, Token, Waker};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as StackDuration, Instant as StackInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

pub(crate) const WAKER: Token = Token(0);

/// Per-connection buffers. A connection only commits memory as it fills.
const TCP_RECEIVE_BUFFER: usize = 128 * 1024;
const TCP_SEND_BUFFER: usize = 128 * 1024;
/// Bytes held for one direction before that side is no longer read.
const PENDING_LIMIT: usize = 256 * 1024;
const TCP_KEEP_ALIVE: StackDuration = StackDuration::from_secs(30);
const TCP_TIMEOUT: StackDuration = StackDuration::from_secs(120);
/// Proxy dials still open past this are abandoned and their SYN refused.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent connections; a browser rarely holds more than a few hundred.
const MAX_TCP_FLOWS: usize = 2048;
const MAX_UDP_ASSOCIATIONS: usize = 512;
/// Datagrams held while an association is being set up.
const UDP_QUEUE_LIMIT: usize = 64;
/// QUIC and voice keep their sockets busy; one quiet for this long is done.
const UDP_IDLE: Duration = Duration::from_secs(60);
/// A refused association is not asked for again on that port this soon.
const UDP_RETRY_AFTER: Duration = Duration::from_secs(30);
/// Windows resends a lookup after one second and gives up after about ten,
/// so a lookup still unanswered by now is not coming back.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an unused stream to a resolver is kept for the next lookup.
const DNS_IDLE: Duration = Duration::from_secs(20);
/// Streams open at once to one resolver, each with one lookup waiting.
const DNS_STREAMS_PER_RESOLVER: usize = 8;
const DNS_PORT: u16 = 53;
/// The port the health probe opens on the benchmark target: a resolver
/// answers TCP there, and every proxy permits it.
const PROBE_PORT: u16 = 53;
const MAX_PROBES: usize = 4;
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) tcp_opened: AtomicU64,
    pub(crate) tcp_refused: AtomicU64,
    pub(crate) udp_sent: AtomicU64,
    pub(crate) udp_refused: AtomicU64,
    pub(crate) dns_answered: AtomicU64,
    pub(crate) dns_failed: AtomicU64,
    pub(crate) dropped: AtomicU64,
}

/// What the capture side and the loop share.
pub(crate) struct Shared {
    pub(crate) inbox: Mutex<VecDeque<Vec<u8>>>,
    pub(crate) waker: Waker,
    pub(crate) stop: AtomicBool,
    pub(crate) counters: Counters,
}

pub(crate) struct StackConfig {
    /// The address applications' packets are rewritten to come from.
    pub(crate) client: Ipv4Addr,
    /// The stack's own address on the same /24; it answers for every other.
    pub(crate) gateway: Ipv4Addr,
    pub(crate) proxy: SocketAddr,
    pub(crate) credentials: Option<(String, String)>,
    /// Where health probes and their echo replies are expected.
    pub(crate) probe_target: Ipv4Addr,
    pub(crate) mtu: usize,
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

struct Received(Vec<u8>);
struct Transmit<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Received {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push(packet);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = Received;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _now: StackInstant) -> Option<(Received, Transmit<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Received(packet), Transmit(&mut self.tx)))
    }

    fn transmit(&mut self, _now: StackInstant) -> Option<Transmit<'_>> {
        Some(Transmit(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

/// One stream to the proxy: its handshake, then the bytes it carries.
struct Upstream {
    stream: TcpStream,
    token: Token,
    handshake: Option<Handshake>,
    outgoing: Vec<u8>,
    connected: bool,
    /// Edge-triggered readiness that was not fully drained, because the far
    /// side's buffer was full. Retried every turn until it would block.
    read_pending: bool,
    closed: bool,
}

impl Upstream {
    fn dial(
        registry: &Registry,
        token: Token,
        proxy: SocketAddr,
        command: Command,
        target: SocketAddrV4,
        credentials: Option<(String, String)>,
    ) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect(proxy)?;
        let _ = stream.set_nodelay(true);
        registry.register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)?;
        let (handshake, greeting) = Handshake::start(command, target, credentials);
        Ok(Self {
            stream,
            token,
            handshake: Some(handshake),
            outgoing: greeting,
            connected: false,
            read_pending: true,
            closed: false,
        })
    }

    /// Writes what is queued. Errors close the stream.
    fn flush(&mut self) {
        while !self.outgoing.is_empty() && !self.closed {
            match self.stream.write(&self.outgoing) {
                Ok(0) => self.closed = true,
                Ok(written) => {
                    self.connected = true;
                    self.outgoing.drain(..written);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::NotConnected => break,
                Err(_) => self.closed = true,
            }
        }
    }

    /// Reads up to `room` bytes. Returns what was read and whether the far
    /// end has finished sending.
    fn read(&mut self, room: usize, buffer: &mut [u8]) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut finished = false;
        while data.len() < room {
            let want = buffer.len().min(room - data.len());
            match self.stream.read(&mut buffer[..want]) {
                Ok(0) => {
                    finished = true;
                    self.read_pending = false;
                    break;
                }
                Ok(read) => data.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.read_pending = false;
                    return (data, false);
                }
                Err(error) if error.kind() == ErrorKind::NotConnected => return (data, false),
                Err(_) => {
                    self.closed = true;
                    finished = true;
                    break;
                }
            }
        }
        if data.len() >= room {
            self.read_pending = true;
        }
        (data, finished)
    }

    /// Advances the handshake with what arrived. `Ok(Some(leftover))` once
    /// the proxy has agreed.
    fn advance(&mut self, data: &[u8]) -> Result<Option<(SocketAddr, Vec<u8>)>, String> {
        let Some(handshake) = self.handshake.as_mut() else {
            return Ok(None);
        };
        match handshake.receive(data)? {
            Step::Send(bytes) => {
                self.outgoing.extend_from_slice(&bytes);
                self.flush();
                Ok(None)
            }
            Step::Wait => Ok(None),
            Step::Done { bound, leftover } => {
                self.handshake = None;
                Ok(Some((bound, leftover)))
            }
        }
    }

    fn deregister(&mut self, registry: &Registry) {
        let _ = registry.deregister(&mut self.stream);
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    local_port: u16,
    remote: SocketAddrV4,
}

struct TcpFlow {
    upstream: Upstream,
    /// The application's SYN, held until the proxy has opened the far end.
    held_syn: Option<(Vec<u8>, u32)>,
    socket: Option<SocketHandle>,
    to_app: Vec<u8>,
    proxy_finished: bool,
    app_finished: bool,
    started: Instant,
}

enum UdpState {
    Dialing {
        control: Upstream,
        queue: Vec<(SocketAddrV4, Vec<u8>)>,
    },
    Ready {
        control: Upstream,
        socket: UdpSocket,
        token: Token,
    },
    Refused {
        until: Instant,
    },
}

struct UdpAssociation {
    state: UdpState,
    last_used: Instant,
}

/// One TCP stream to a resolver, carrying one lookup at a time.
///
/// Lookups sharing a stream are answered in order by some proxies, so one the
/// proxy is slow to answer held up every lookup behind it. Observed through
/// Throne: one unanswered lookup stalled eight more for ten seconds, which
/// froze every application's name resolution at once.
struct DnsUpstream {
    resolver: Ipv4Addr,
    upstream: Upstream,
    ready: bool,
    /// Since when nothing has been waiting on this stream.
    idle_since: Instant,
    queued: Vec<u8>,
    received: Vec<u8>,
    /// The id each lookup was sent under, mapped to who asked and as what.
    in_flight: HashMap<u16, DnsQuery>,
}

struct DnsQuery {
    local_port: u16,
    id: u16,
    sent: Instant,
    /// The query as the application sent it, to send again or to fail.
    message: Vec<u8>,
    retried: bool,
}

struct Probe {
    upstream: Upstream,
    request: Vec<u8>,
    started: Instant,
}

#[derive(Clone, Copy)]
enum Owner {
    Tcp(FlowKey),
    UdpControl(u16),
    UdpData(u16),
    Dns(u64),
    Probe(u64),
}

pub(crate) struct Stack {
    config: StackConfig,
    shared: Arc<Shared>,
    outbound: mpsc::SyncSender<Vec<u8>>,
    poll: Poll,
    iface: Interface,
    device: QueueDevice,
    sockets: SocketSet<'static>,
    owners: HashMap<Token, Owner>,
    next_token: usize,
    tcp: HashMap<FlowKey, TcpFlow>,
    udp: HashMap<u16, UdpAssociation>,
    dns: HashMap<u64, DnsUpstream>,
    next_dns_stream: u64,
    probes: HashMap<u64, Probe>,
    next_probe: u64,
    buffer: Vec<u8>,
    udp_refusal_logged: bool,
    dns_failure_logged: bool,
    dns_timeout_logged: bool,
    dns_close_logged: bool,
    last_summary: Instant,
}

impl Stack {
    pub(crate) fn new(
        config: StackConfig,
        shared: Arc<Shared>,
        poll: Poll,
        outbound: mpsc::SyncSender<Vec<u8>>,
    ) -> Self {
        let mut device = QueueDevice {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu: config.mtu,
        };
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, &mut device, StackInstant::now());
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(config.gateway), 24));
        });
        // A route through our own address is what makes smoltcp answer for
        // every destination when `any_ip` is on.
        let _ = iface.routes_mut().add_default_ipv4_route(config.gateway);
        iface.set_any_ip(true);
        Self {
            config,
            shared,
            outbound,
            poll,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            owners: HashMap::new(),
            next_token: 1,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            dns: HashMap::new(),
            next_dns_stream: 0,
            probes: HashMap::new(),
            next_probe: 0,
            buffer: vec![0; 64 * 1024],
            udp_refusal_logged: false,
            dns_failure_logged: false,
            dns_timeout_logged: false,
            dns_close_logged: false,
            last_summary: Instant::now(),
        }
    }

    pub(crate) fn run(mut self) {
        let mut events = Events::with_capacity(512);
        while !self.shared.stop.load(Ordering::Acquire) {
            let timeout = self.poll_timeout();
            if let Err(error) = self.poll.poll(&mut events, Some(timeout)) {
                if error.kind() != ErrorKind::Interrupted {
                    log_warn!("SOCKS5 stack poll failed: {error}");
                    std::thread::sleep(Duration::from_millis(10));
                }
                continue;
            }
            for event in events.iter() {
                if event.token() != WAKER {
                    self.ready(event.token());
                }
            }
            let packets = std::mem::take(&mut *self.shared.inbox.lock().unwrap());
            for packet in packets {
                self.on_app_packet(packet);
            }
            self.turn();
        }
        self.shutdown();
    }

    fn poll_timeout(&mut self) -> Duration {
        let busy = self
            .tcp
            .values()
            .any(|flow| !flow.upstream.outgoing.is_empty() || !flow.to_app.is_empty());
        let ceiling = if busy {
            Duration::from_millis(5)
        } else {
            Duration::from_millis(100)
        };
        self.iface
            .poll_delay(StackInstant::now(), &self.sockets)
            .map(|delay| Duration::from_micros(delay.total_micros()))
            .map_or(ceiling, |delay| delay.min(ceiling))
    }

    fn token(&mut self, owner: Owner) -> Token {
        let token = Token(self.next_token);
        self.next_token = self.next_token.wrapping_add(1).max(1);
        self.owners.insert(token, owner);
        token
    }

    fn emit(&self, packet: Vec<u8>) {
        if self.outbound.try_send(packet).is_err() {
            self.shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_app_packet(&mut self, packet: Vec<u8>) {
        let Some(ip) = parse_ipv4(&packet) else {
            return;
        };
        match ip.protocol {
            PROTOCOL_TCP => {
                let Some(head) = (!ip.fragmented).then(|| parse_tcp(ip.payload)).flatten() else {
                    // A fragment is reassembled by smoltcp itself.
                    self.device.rx.push_back(packet);
                    return;
                };
                let key = FlowKey {
                    local_port: head.source_port,
                    remote: SocketAddrV4::new(ip.destination, head.destination_port),
                };
                match self.tcp.get_mut(&key) {
                    Some(flow) if flow.socket.is_some() => self.device.rx.push_back(packet),
                    // A retransmitted SYN while the proxy is still dialling.
                    Some(flow) if head.syn => flow.held_syn = Some((packet, head.sequence)),
                    Some(_) => {}
                    None if head.syn && !head.ack => self.open_tcp(key, packet, head.sequence),
                    // Part of a connection this stack does not know, which
                    // can only be one it already ended. Say so.
                    None if !head.rst => self.emit(build_tcp_reset(
                        key.remote,
                        SocketAddrV4::new(self.config.client, key.local_port),
                        head.sequence.wrapping_add(1),
                    )),
                    None => {}
                }
            }
            PROTOCOL_UDP if !ip.fragmented => {
                let Some(udp) = parse_udp(ip.payload) else {
                    return;
                };
                let destination = SocketAddrV4::new(ip.destination, udp.destination_port);
                let payload = udp.payload.to_vec();
                if udp.destination_port == DNS_PORT {
                    self.lookup(udp.source_port, *destination.ip(), payload);
                } else {
                    self.send_udp(udp.source_port, destination, payload);
                }
            }
            _ if is_echo_request(&ip) && ip.destination == self.config.probe_target => {
                self.probe(packet);
            }
            _ => {
                self.shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn open_tcp(&mut self, key: FlowKey, syn: Vec<u8>, sequence: u32) {
        let refuse = |stack: &Self| {
            stack
                .shared
                .counters
                .tcp_refused
                .fetch_add(1, Ordering::Relaxed);
            stack.emit(build_tcp_reset(
                key.remote,
                SocketAddrV4::new(stack.config.client, key.local_port),
                sequence.wrapping_add(1),
            ));
        };
        if self.tcp.len() >= MAX_TCP_FLOWS {
            refuse(self);
            return;
        }
        let token = self.token(Owner::Tcp(key));
        match Upstream::dial(
            self.poll.registry(),
            token,
            self.config.proxy,
            Command::Connect,
            key.remote,
            self.config.credentials.clone(),
        ) {
            Ok(upstream) => {
                self.tcp.insert(
                    key,
                    TcpFlow {
                        upstream,
                        held_syn: Some((syn, sequence)),
                        socket: None,
                        to_app: Vec::new(),
                        proxy_finished: false,
                        app_finished: false,
                        started: Instant::now(),
                    },
                );
            }
            Err(error) => {
                self.owners.remove(&token);
                log_warn!("could not reach the SOCKS5 proxy: {error}");
                refuse(self);
            }
        }
    }

    /// The proxy opened the far end: hand the held SYN to smoltcp, listening
    /// on exactly that destination.
    fn accept_tcp(&mut self, key: FlowKey, leftover: Vec<u8>) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_TIMEOUT));
        let listening = socket.listen(IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(*key.remote.ip())),
            port: key.remote.port(),
        });
        let Some(flow) = self.tcp.get_mut(&key) else {
            return;
        };
        if listening.is_err() {
            flow.upstream.closed = true;
            return;
        }
        let handle = self.sockets.add(socket);
        flow.socket = Some(handle);
        flow.to_app = leftover;
        if let Some((syn, _)) = flow.held_syn.take() {
            self.device.rx.push_back(syn);
        }
        self.shared
            .counters
            .tcp_opened
            .fetch_add(1, Ordering::Relaxed);
    }

    fn send_udp(&mut self, local_port: u16, destination: SocketAddrV4, payload: Vec<u8>) {
        let now = Instant::now();
        if !self.udp.contains_key(&local_port) {
            // A browser opens a socket per QUIC connection, so the table fills
            // with ones already finished; the quietest makes room, rather than
            // a new connection being refused. Observed: all 512 in use within a
            // minute of browsing, and every new one dropped.
            if self.udp.len() >= MAX_UDP_ASSOCIATIONS {
                if let Some(quietest) = self
                    .udp
                    .iter()
                    .min_by_key(|(_, association)| association.last_used)
                    .map(|(port, _)| *port)
                {
                    self.remove_udp(quietest);
                }
            }
            let token = self.token(Owner::UdpControl(local_port));
            let state = match Upstream::dial(
                self.poll.registry(),
                token,
                self.config.proxy,
                Command::UdpAssociate,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                self.config.credentials.clone(),
            ) {
                Ok(control) => UdpState::Dialing {
                    control,
                    queue: Vec::new(),
                },
                Err(_) => UdpState::Refused {
                    until: now + UDP_RETRY_AFTER,
                },
            };
            self.udp.insert(
                local_port,
                UdpAssociation {
                    state,
                    last_used: now,
                },
            );
        }
        let association = self.udp.get_mut(&local_port).unwrap();
        association.last_used = now;
        match &mut association.state {
            UdpState::Dialing { queue, .. } => {
                if queue.len() < UDP_QUEUE_LIMIT {
                    queue.push((destination, payload));
                }
            }
            UdpState::Ready { socket, .. } => {
                if socket.send(&udp_request(destination, &payload)).is_ok() {
                    self.shared
                        .counters
                        .udp_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            UdpState::Refused { until } if now >= *until => {
                self.udp.remove(&local_port);
                self.send_udp(local_port, destination, payload);
            }
            UdpState::Refused { .. } => {
                self.shared.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn lookup(&mut self, local_port: u16, resolver: Ipv4Addr, query: Vec<u8>) {
        self.send_lookup(local_port, resolver, query, false);
    }

    fn send_lookup(&mut self, local_port: u16, resolver: Ipv4Addr, query: Vec<u8>, retried: bool) {
        if query.len() < 12 || query.len() > usize::from(u16::MAX) {
            return;
        }
        let Some(stream) = self.dns_stream_for(resolver) else {
            self.shared
                .counters
                .dns_failed
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let upstream = self.dns.get_mut(&stream).unwrap();
        // Lookups from different applications can share an id; each gets one
        // of its own on the stream and is given its own back.
        let original = u16::from_be_bytes([query[0], query[1]]);
        let mut id = rand::random::<u16>();
        while upstream.in_flight.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        upstream.in_flight.insert(
            id,
            DnsQuery {
                local_port,
                id: original,
                sent: Instant::now(),
                message: query.clone(),
                retried,
            },
        );
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&id.to_be_bytes());
        framed.extend_from_slice(&query[2..]);
        if upstream.ready {
            upstream.upstream.outgoing.extend_from_slice(&framed);
            upstream.upstream.flush();
        } else {
            upstream.queued.extend_from_slice(&framed);
        }
        self.keep_spare_dns_stream(resolver);
    }

    /// Keeps one stream to `resolver` connected and idle, so the next lookup
    /// is written at once instead of waiting for a proxy handshake.
    fn keep_spare_dns_stream(&mut self, resolver: Ipv4Addr) {
        let (open, idle) = self.dns_streams(resolver);
        if idle == 0 && open < DNS_STREAMS_PER_RESOLVER {
            let _ = self.dial_dns_stream(resolver);
        }
    }

    /// Streams to `resolver`: how many are open, and how many are idle.
    fn dns_streams(&self, resolver: Ipv4Addr) -> (usize, usize) {
        self.dns
            .values()
            .filter(|stream| stream.resolver == resolver)
            .fold((0, 0), |(open, idle), stream| {
                (open + 1, idle + usize::from(stream.in_flight.is_empty()))
            })
    }

    /// An idle stream to `resolver`, a new one while fewer than
    /// [`DNS_STREAMS_PER_RESOLVER`] are open, or else the least busy.
    fn dns_stream_for(&mut self, resolver: Ipv4Addr) -> Option<u64> {
        let mut least_busy: Option<(u64, usize)> = None;
        let mut open = 0;
        for (id, stream) in &self.dns {
            if stream.resolver != resolver {
                continue;
            }
            open += 1;
            if stream.in_flight.is_empty() {
                return Some(*id);
            }
            if least_busy.is_none_or(|(_, waiting)| stream.in_flight.len() < waiting) {
                least_busy = Some((*id, stream.in_flight.len()));
            }
        }
        if open >= DNS_STREAMS_PER_RESOLVER {
            return least_busy.map(|(id, _)| id);
        }
        self.dial_dns_stream(resolver)
    }

    fn dial_dns_stream(&mut self, resolver: Ipv4Addr) -> Option<u64> {
        self.next_dns_stream += 1;
        let stream = self.next_dns_stream;
        let token = self.token(Owner::Dns(stream));
        let upstream = Upstream::dial(
            self.poll.registry(),
            token,
            self.config.proxy,
            Command::Connect,
            SocketAddrV4::new(resolver, DNS_PORT),
            self.config.credentials.clone(),
        )
        .ok()?;
        self.dns.insert(
            stream,
            DnsUpstream {
                resolver,
                upstream,
                ready: false,
                idle_since: Instant::now(),
                queued: Vec::new(),
                received: Vec::new(),
                in_flight: HashMap::new(),
            },
        );
        Some(stream)
    }

    fn probe(&mut self, request: Vec<u8>) {
        if self.probes.len() >= MAX_PROBES {
            return;
        }
        self.next_probe += 1;
        let id = self.next_probe;
        let token = self.token(Owner::Probe(id));
        if let Ok(upstream) = Upstream::dial(
            self.poll.registry(),
            token,
            self.config.proxy,
            Command::Connect,
            SocketAddrV4::new(self.config.probe_target, PROBE_PORT),
            self.config.credentials.clone(),
        ) {
            self.probes.insert(
                id,
                Probe {
                    upstream,
                    request,
                    started: Instant::now(),
                },
            );
        } else {
            self.owners.remove(&token);
        }
    }

    /// Readiness on a proxy stream or association socket.
    fn ready(&mut self, token: Token) {
        let Some(owner) = self.owners.get(&token).copied() else {
            return;
        };
        match owner {
            Owner::Tcp(key) => {
                if let Some(flow) = self.tcp.get_mut(&key) {
                    flow.upstream.read_pending = true;
                    flow.upstream.flush();
                }
            }
            Owner::UdpControl(port) => self.udp_control_ready(port),
            Owner::UdpData(port) => self.udp_data_ready(port),
            Owner::Dns(stream) => self.dns_ready(stream),
            Owner::Probe(id) => self.probe_ready(id),
        }
    }

    fn udp_control_ready(&mut self, port: u16) {
        let proxy = self.config.proxy;
        let Some(association) = self.udp.get_mut(&port) else {
            return;
        };
        let control = match &mut association.state {
            UdpState::Dialing { control, .. } | UdpState::Ready { control, .. } => control,
            UdpState::Refused { .. } => return,
        };
        control.flush();
        let (data, finished) = control.read(4096, &mut self.buffer);
        if control.handshake.is_none() {
            // RFC 1928 ties an association to its control stream, but plenty
            // of proxies close it and keep relaying. The data socket decides.
            if finished {
                control.deregister(self.poll.registry());
            }
            return;
        }
        let outcome = control.advance(&data);
        let refused = match outcome {
            Ok(Some((bound, _))) => {
                let relay = match bound.ip() {
                    ip if ip.is_unspecified() => SocketAddr::new(proxy.ip(), bound.port()),
                    _ => bound,
                };
                self.open_association(port, relay).err()
            }
            Ok(None) if finished || control.closed => {
                Some("the proxy closed the connection".to_owned())
            }
            Ok(None) => None,
            Err(error) => Some(error),
        };
        if let Some(reason) = refused {
            self.refuse_association(port, &reason);
        }
    }

    fn open_association(&mut self, port: u16, relay: SocketAddr) -> Result<(), String> {
        let local = match relay {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
        };
        let mut socket = UdpSocket::bind(local).map_err(|error| error.to_string())?;
        socket.connect(relay).map_err(|error| error.to_string())?;
        let token = self.token(Owner::UdpData(port));
        self.poll
            .registry()
            .register(&mut socket, token, Interest::READABLE)
            .map_err(|error| error.to_string())?;
        let association = self.udp.get_mut(&port).ok_or("association vanished")?;
        let UdpState::Dialing { control, queue } = std::mem::replace(
            &mut association.state,
            UdpState::Refused {
                until: Instant::now(),
            },
        ) else {
            return Err("association was not being set up".into());
        };
        for (destination, payload) in &queue {
            if socket.send(&udp_request(*destination, payload)).is_ok() {
                self.shared
                    .counters
                    .udp_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        association.state = UdpState::Ready {
            control,
            socket,
            token,
        };
        Ok(())
    }

    fn refuse_association(&mut self, port: u16, reason: &str) {
        self.shared
            .counters
            .udp_refused
            .fetch_add(1, Ordering::Relaxed);
        if !self.udp_refusal_logged {
            self.udp_refusal_logged = true;
            log_warn!(
                "SOCKS5 proxy did not open a UDP association ({reason}); its UDP traffic is lost"
            );
        }
        if let Some(association) = self.udp.get_mut(&port) {
            if let UdpState::Dialing { control, .. } = &mut association.state {
                control.deregister(self.poll.registry());
                self.owners.remove(&control.token);
            }
            association.state = UdpState::Refused {
                until: Instant::now() + UDP_RETRY_AFTER,
            };
        }
    }

    fn udp_data_ready(&mut self, port: u16) {
        let client = SocketAddrV4::new(self.config.client, port);
        let mut replies = Vec::new();
        if let Some(UdpAssociation {
            state: UdpState::Ready { socket, .. },
            last_used,
        }) = self.udp.get_mut(&port)
        {
            loop {
                match socket.recv(&mut self.buffer) {
                    Ok(length) => {
                        *last_used = Instant::now();
                        if let Some((from, payload)) = udp_reply(&self.buffer[..length]) {
                            replies.push(build_udp(from, client, payload));
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        for reply in replies {
            self.emit(reply);
        }
    }

    fn dns_ready(&mut self, stream: u64) {
        let client = self.config.client;
        let Some(dns) = self.dns.get_mut(&stream) else {
            return;
        };
        let resolver = dns.resolver;
        dns.upstream.flush();
        // Drained to the end: readiness is edge-triggered, so whatever is
        // left unread now would wait for a next event that may never come.
        let mut data = Vec::new();
        let mut finished = false;
        loop {
            let (chunk, done) = dns.upstream.read(64 * 1024, &mut self.buffer);
            data.extend_from_slice(&chunk);
            finished |= done;
            if done || !dns.upstream.read_pending {
                break;
            }
        }
        let mut failure = None;
        if dns.upstream.handshake.is_some() {
            match dns.upstream.advance(&data) {
                Ok(Some((_, leftover))) => {
                    dns.ready = true;
                    let queued = std::mem::take(&mut dns.queued);
                    dns.upstream.outgoing.extend_from_slice(&queued);
                    dns.upstream.flush();
                    dns.received.extend_from_slice(&leftover);
                }
                Ok(None) => {}
                Err(error) => failure = Some(error),
            }
        } else {
            dns.received.extend_from_slice(&data);
        }
        let mut answers = Vec::new();
        while dns.received.len() >= 2 {
            let length = usize::from(u16::from_be_bytes([dns.received[0], dns.received[1]]));
            if dns.received.len() < 2 + length {
                break;
            }
            let mut message: Vec<u8> = dns.received.drain(..2 + length).skip(2).collect();
            if message.len() < 12 {
                continue;
            }
            let id = u16::from_be_bytes([message[0], message[1]]);
            if let Some(query) = dns.in_flight.remove(&id) {
                message[..2].copy_from_slice(&query.id.to_be_bytes());
                answers.push(build_udp(
                    SocketAddrV4::new(resolver, DNS_PORT),
                    SocketAddrV4::new(client, query.local_port),
                    &message,
                ));
            }
        }
        if !answers.is_empty() && dns.in_flight.is_empty() {
            dns.idle_since = Instant::now();
        }
        let gone = finished || dns.upstream.closed || failure.is_some();
        for answer in answers {
            self.shared
                .counters
                .dns_answered
                .fetch_add(1, Ordering::Relaxed);
            self.emit(answer);
        }
        if gone {
            if let Some(error) = failure.filter(|_| !self.dns_failure_logged) {
                self.dns_failure_logged = true;
                log_warn!("name lookups through the SOCKS5 proxy failed: {error}");
            }
            // sing-box closes a DNS stream when one lookup on it fails, taking
            // any other waiting lookup with it. Each is sent once more on a
            // fresh stream, then failed at once rather than left for the
            // application to time out.
            if let Some(mut dns) = self.dns.remove(&stream) {
                if !dns.in_flight.is_empty() && !self.dns_close_logged {
                    self.dns_close_logged = true;
                    log_warn!(
                        "the SOCKS5 proxy closed the DNS stream to {resolver} with {} lookup(s) waiting",
                        dns.in_flight.len()
                    );
                }
                dns.upstream.deregister(self.poll.registry());
                self.owners.remove(&dns.upstream.token);
                for query in dns.in_flight.into_values() {
                    if query.retried {
                        self.fail_lookup(resolver, &query);
                    } else {
                        self.send_lookup(query.local_port, resolver, query.message, true);
                    }
                }
            }
        }
    }

    /// Answers a lookup the proxy could not with SERVFAIL, so the
    /// application moves on instead of waiting for its own timeout.
    fn fail_lookup(&mut self, resolver: Ipv4Addr, query: &DnsQuery) {
        self.shared
            .counters
            .dns_failed
            .fetch_add(1, Ordering::Relaxed);
        if let Some(answer) = servfail(&query.message) {
            self.emit(build_udp(
                SocketAddrV4::new(resolver, DNS_PORT),
                SocketAddrV4::new(self.config.client, query.local_port),
                &answer,
            ));
        }
    }

    fn probe_ready(&mut self, id: u64) {
        let Some(probe) = self.probes.get_mut(&id) else {
            return;
        };
        probe.upstream.flush();
        let (data, finished) = probe.upstream.read(4096, &mut self.buffer);
        let reply = match probe.upstream.advance(&data) {
            Ok(Some(_)) => parse_ipv4(&probe.request).map(|request| build_echo_reply(&request)),
            Ok(None) if !finished && !probe.upstream.closed => return,
            _ => None,
        };
        if let Some(mut probe) = self.probes.remove(&id) {
            probe.upstream.deregister(self.poll.registry());
            self.owners.remove(&probe.upstream.token);
        }
        if let Some(reply) = reply {
            self.emit(reply);
        }
    }

    /// One turn of the stack: smoltcp, then every connection's two directions.
    fn turn(&mut self) {
        let now = StackInstant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.pump_tcp();
        // Data written into sockets above goes out in this same turn.
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        for packet in std::mem::take(&mut self.device.tx) {
            self.emit(packet);
        }
        self.expire();
        self.summarise();
    }

    fn pump_tcp(&mut self) {
        let keys: Vec<FlowKey> = self.tcp.keys().copied().collect();
        let mut finished = Vec::new();
        let mut accepted = Vec::new();
        let mut refused = Vec::new();
        for key in keys {
            let flow = self.tcp.get_mut(&key).unwrap();
            flow.upstream.flush();
            if flow.upstream.handshake.is_some() {
                let (data, closed) = flow.upstream.read(4096, &mut self.buffer);
                if data.is_empty() && !closed && !flow.upstream.closed {
                    if flow.started.elapsed() > DIAL_TIMEOUT {
                        refused.push((key, "the proxy did not answer in time".to_owned()));
                    }
                    continue;
                }
                match flow.upstream.advance(&data) {
                    Ok(Some((_, leftover))) => accepted.push((key, leftover)),
                    Ok(None) if closed || flow.upstream.closed => {
                        refused.push((key, "the proxy closed the connection".to_owned()))
                    }
                    Ok(None) => {}
                    Err(error) => refused.push((key, error)),
                }
                continue;
            }
            let Some(handle) = flow.socket else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            // Application to proxy.
            while socket.can_recv() && flow.upstream.outgoing.len() < PENDING_LIMIT {
                match socket.recv_slice(&mut self.buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => flow
                        .upstream
                        .outgoing
                        .extend_from_slice(&self.buffer[..read]),
                }
            }
            flow.upstream.flush();
            // Proxy to application.
            if flow.upstream.read_pending
                && flow.to_app.len() < PENDING_LIMIT
                && !flow.proxy_finished
            {
                let room = PENDING_LIMIT - flow.to_app.len();
                let (data, done) = flow.upstream.read(room, &mut self.buffer);
                flow.to_app.extend_from_slice(&data);
                flow.proxy_finished |= done;
            }
            if !flow.to_app.is_empty() && socket.can_send() {
                if let Ok(sent) = socket.send_slice(&flow.to_app) {
                    flow.to_app.drain(..sent);
                }
            }
            // Ends, in each direction, once everything before them is delivered.
            if flow.proxy_finished && flow.to_app.is_empty() && socket.may_send() {
                socket.close();
            }
            if !flow.app_finished
                && !socket.may_recv()
                && flow.upstream.outgoing.is_empty()
                && matches!(
                    socket.state(),
                    tcp::State::CloseWait | tcp::State::LastAck | tcp::State::Closed
                )
            {
                flow.app_finished = true;
                let _ = flow.upstream.stream.shutdown(Shutdown::Write);
            }
            if flow.upstream.closed && !flow.proxy_finished {
                socket.abort();
            }
            // Still listening long after the SYN was handed over means smoltcp
            // never took it; nothing will arrive for this flow now.
            let never_answered =
                socket.state() == tcp::State::Listen && flow.started.elapsed() > 2 * DIAL_TIMEOUT;
            if never_answered || matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
            {
                finished.push(key);
            }
        }
        for (key, leftover) in accepted {
            self.accept_tcp(key, leftover);
        }
        for (key, reason) in refused {
            if let Some(flow) = self.tcp.get(&key) {
                if let Some((_, sequence)) = &flow.held_syn {
                    self.shared
                        .counters
                        .tcp_refused
                        .fetch_add(1, Ordering::Relaxed);
                    self.emit(build_tcp_reset(
                        key.remote,
                        SocketAddrV4::new(self.config.client, key.local_port),
                        sequence.wrapping_add(1),
                    ));
                }
            }
            crate::log_debug!("connection to {} refused: {reason}", key.remote);
            finished.push(key);
        }
        for key in finished {
            self.remove_tcp(key);
        }
    }

    fn remove_tcp(&mut self, key: FlowKey) {
        if let Some(mut flow) = self.tcp.remove(&key) {
            flow.upstream.deregister(self.poll.registry());
            self.owners.remove(&flow.upstream.token);
            if let Some(handle) = flow.socket {
                self.sockets.remove(handle);
            }
        }
    }

    fn remove_udp(&mut self, port: u16) {
        let Some(association) = self.udp.remove(&port) else {
            return;
        };
        match association.state {
            UdpState::Dialing { mut control, .. } => {
                control.deregister(self.poll.registry());
                self.owners.remove(&control.token);
            }
            UdpState::Ready {
                mut control,
                mut socket,
                token,
            } => {
                control.deregister(self.poll.registry());
                self.owners.remove(&control.token);
                let _ = self.poll.registry().deregister(&mut socket);
                self.owners.remove(&token);
            }
            UdpState::Refused { .. } => {}
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        let idle: Vec<u16> = self
            .udp
            .iter()
            .filter(|(_, association)| match association.state {
                UdpState::Refused { until } => now >= until,
                _ => now.duration_since(association.last_used) > UDP_IDLE,
            })
            .map(|(port, _)| *port)
            .collect();
        for port in idle {
            self.remove_udp(port);
        }
        // A stream with a lookup this late is not trusted with another: the
        // proxy may be answering it in order behind the one it lost.
        // An idle stream is closed once unused for a while, except the last
        // one to each resolver, which is the spare the next lookup goes out on.
        let mut closing = Vec::new();
        let mut spare_kept = HashSet::new();
        for (id, dns) in &self.dns {
            let late = dns
                .in_flight
                .values()
                .any(|query| now.duration_since(query.sent) >= DNS_TIMEOUT);
            let idle = dns.in_flight.is_empty() && now.duration_since(dns.idle_since) >= DNS_IDLE;
            if late || (idle && !spare_kept.insert(dns.resolver)) {
                closing.push((*id, late));
            }
        }
        for (id, late) in closing {
            let Some(mut dns) = self.dns.remove(&id) else {
                continue;
            };
            dns.upstream.deregister(self.poll.registry());
            self.owners.remove(&dns.upstream.token);
            let lost = dns.in_flight.len();
            self.shared
                .counters
                .dns_failed
                .fetch_add(lost as u64, Ordering::Relaxed);
            if late && !self.dns_timeout_logged {
                self.dns_timeout_logged = true;
                log_warn!(
                    "a lookup through the SOCKS5 proxy went unanswered for {} s; its stream \
                     to {} is closed with {lost} lookup(s) on it",
                    DNS_TIMEOUT.as_secs(),
                    dns.resolver
                );
            }
        }
        let stale: Vec<u64> = self
            .probes
            .iter()
            .filter(|(_, probe)| probe.started.elapsed() > DIAL_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(mut probe) = self.probes.remove(&id) {
                probe.upstream.deregister(self.poll.registry());
                self.owners.remove(&probe.upstream.token);
            }
        }
    }

    fn summarise(&mut self) {
        if self.last_summary.elapsed() < SUMMARY_INTERVAL {
            return;
        }
        self.last_summary = Instant::now();
        let counters = &self.shared.counters;
        log_info!(
            "SOCKS5 stack: tcp open={} opened={} refused={} udp assoc={} sent={} refused={} \
             dns answered={} failed={} dropped={}",
            self.tcp.len(),
            counters.tcp_opened.load(Ordering::Relaxed),
            counters.tcp_refused.load(Ordering::Relaxed),
            self.udp.len(),
            counters.udp_sent.load(Ordering::Relaxed),
            counters.udp_refused.load(Ordering::Relaxed),
            counters.dns_answered.load(Ordering::Relaxed),
            counters.dns_failed.load(Ordering::Relaxed),
            counters.dropped.load(Ordering::Relaxed),
        );
    }

    fn shutdown(&mut self) {
        let keys: Vec<FlowKey> = self.tcp.keys().copied().collect();
        for key in keys {
            self.remove_tcp(key);
        }
        for (_, mut dns) in self.dns.drain() {
            dns.upstream.deregister(self.poll.registry());
        }
        for (_, mut probe) in self.probes.drain() {
            probe.upstream.deregister(self.poll.registry());
        }
        self.udp.clear();
    }
}

/// A SERVFAIL reply to `query`: its id and question, no records.
fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let questions = u16::from_be_bytes([*query.get(4)?, *query.get(5)?]);
    if questions != 1 {
        return None;
    }
    let mut answer = query.to_vec();
    // Response, same opcode and RD; recursion available; RCODE 2.
    answer[2] = 0x80 | (query[2] & 0x79);
    answer[3] = 0x80 | 2;
    answer[6..12].fill(0);
    Some(answer)
}

/// A datagram for the proxy's relay: RFC 1928's header, then the payload.
fn udp_request(destination: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(10 + payload.len());
    datagram.extend_from_slice(&[0, 0, 0, 1]);
    datagram.extend_from_slice(&destination.ip().octets());
    datagram.extend_from_slice(&destination.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

/// Where a relayed reply came from, and what it carried. Fragments and
/// non-IPv4 sources are dropped: nothing here can reassemble or address them.
fn udp_reply(datagram: &[u8]) -> Option<(SocketAddrV4, &[u8])> {
    if datagram.len() < 10 || datagram[2] != 0 || datagram[3] != 1 {
        return None;
    }
    let from = SocketAddrV4::new(
        Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]),
        u16::from_be_bytes([datagram[8], datagram[9]]),
    );
    Some((from, &datagram[10..]))
}

/// The proxy's address as an IPv4 bypass, unless it is this machine.
pub(crate) fn proxy_bypass(proxy: SocketAddr) -> Option<Ipv4Addr> {
    match proxy.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relayed_datagram_round_trips_through_the_socks_header() {
        let destination = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27_015);
        let request = udp_request(destination, b"query");
        assert_eq!(&request[..10], &[0, 0, 0, 1, 203, 0, 113, 9, 0x69, 0x87]);
        assert_eq!(udp_reply(&request), Some((destination, &b"query"[..])));
        // A fragment, or a reply from an IPv6 source, cannot be delivered.
        let mut fragment = request.clone();
        fragment[2] = 1;
        assert_eq!(udp_reply(&fragment), None);
        let mut ipv6 = request;
        ipv6[3] = 4;
        assert_eq!(udp_reply(&ipv6), None);
    }

    #[test]
    fn a_proxy_on_this_machine_needs_no_bypass() {
        assert_eq!(proxy_bypass("127.0.0.1:2080".parse().unwrap()), None);
        assert_eq!(
            proxy_bypass("198.51.100.7:1080".parse().unwrap()),
            Some(Ipv4Addr::new(198, 51, 100, 7))
        );
    }
}
