//! Opens the proxy's flows inside the session itself, through a user-space
//! TCP/IP stack.
//!
//! A session the engine runs has no socket Windows could connect through: in
//! split mode nothing routes to the tunnel at all, and in all-traffic mode the
//! routing that exists is exactly what a console must not depend on. So the
//! proxy speaks TCP itself, with smoltcp, from the session's own address, and
//! hands every packet it produces to the dispatcher like a captured one. That
//! is what makes a console's traffic independent of split rules: it never
//! reaches capture, so there is nothing for a rule to select or miss.
//!
//! Replies come back through [`crate::session::LocalTap`], which recognises
//! them by the local port. Every port is taken from Windows first by binding
//! a real socket to it, so no application's captured flow can share it.

use super::egress::{Egress, FlowId, TcpState};
use crate::session::{
    DataReceiver, LocalStackBinding, LocalStackSink, LocalTap, Protocol, WireGuardSessionManager,
};
use gamepath_engine::relay_path::SessionMode;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as StackDuration, Instant as StackInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use socket2::{Domain, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-connection receive window. Large enough to keep a console download
/// moving across a relay round trip; a buffer is only committed as it fills.
const TCP_RECEIVE_BUFFER: usize = 256 * 1024;
const TCP_SEND_BUFFER: usize = 128 * 1024;
const UDP_PACKETS: usize = 512;
const UDP_BUFFER: usize = 256 * 1024;
/// Finds a remote that vanished without a FIN, which a console would
/// otherwise hold open for ever.
const TCP_KEEP_ALIVE: StackDuration = StackDuration::from_secs(30);
const TCP_TIMEOUT: StackDuration = StackDuration::from_secs(120);
/// How long a released connection may take to finish closing before it is
/// torn down regardless.
const LINGER: Duration = Duration::from_secs(5);
/// Packets waiting for the stack. At a full-size MTU this is several
/// megabytes, a burst no console produces in one loop turn.
const INBOX_LIMIT: usize = 4096;

/// Where diverted packets wait for the event loop.
pub(crate) struct Inbox {
    queue: Mutex<VecDeque<Vec<u8>>>,
    waker: Arc<mio::Waker>,
    received: Arc<DataReceiver>,
    dropped: AtomicU64,
}

impl Inbox {
    pub(crate) fn new(waker: Arc<mio::Waker>, received: Arc<DataReceiver>) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            waker,
            received,
            dropped: AtomicU64::new(0),
        }
    }

    fn take(&self) -> VecDeque<Vec<u8>> {
        std::mem::take(&mut *self.queue.lock().unwrap())
    }
}

impl LocalStackSink for Inbox {
    fn deliver(&self, packet: Vec<u8>) -> Result<(), Vec<u8>> {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() >= INBOX_LIMIT {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
        self.received
            .user_bytes_received
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        let was_empty = queue.is_empty();
        queue.push_back(packet);
        drop(queue);
        // The loop drains everything once woken, so only the first packet of
        // a batch has to wake it.
        if was_empty {
            let _ = self.waker.wake();
        }
        Ok(())
    }
}

/// Where the stack's packets go: the session's dispatcher, or in tests a
/// simulated network.
pub(crate) trait PacketOutlet: Send {
    fn send_batch(&self, packets: Vec<Vec<u8>>);
}

impl PacketOutlet for Arc<Mutex<WireGuardSessionManager>> {
    fn send_batch(&self, packets: Vec<Vec<u8>>) {
        // Taken once per batch, and the lock released before sending.
        let Some(sender) = self.lock().unwrap().data_sender() else {
            return;
        };
        for packet in packets {
            // A packet no path took is lost like any other; TCP retransmits.
            let _ = sender.send(&packet);
        }
    }
}

struct TunnelDevice {
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

impl Device for TunnelDevice {
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

/// A local port held for the stack. Binding it is what keeps Windows from
/// giving it to anything else while the flow lives; dropping it gives it back.
struct Reservation {
    _socket: Socket,
    port: u16,
    protocol: Protocol,
    tap: Arc<LocalTap>,
}

impl Reservation {
    fn take(tap: &Arc<LocalTap>, protocol: Protocol) -> Result<Self, String> {
        let kind = match protocol {
            Protocol::Tcp => Type::STREAM,
            Protocol::Udp => Type::DGRAM,
        };
        let socket = Socket::new(Domain::IPV4, kind, None)
            .map_err(|error| format!("could not reserve a local port: {error}"))?;
        exclusive_address_use(&socket);
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .map_err(|error| format!("could not reserve a local port: {error}"))?;
        let port = socket
            .local_addr()
            .ok()
            .and_then(|address| address.as_socket_ipv4())
            .map(|address| address.port())
            .ok_or("Windows did not assign a local port")?;
        tap.claim(protocol, port);
        Ok(Self {
            _socket: socket,
            port,
            protocol,
            tap: Arc::clone(tap),
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.tap.release(self.protocol, self.port);
    }
}

/// Without this, a later bind to the specific session address on the same
/// port would succeed and steal the flow's replies.
fn exclusive_address_use(socket: &Socket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SO_REUSEADDR, SOL_SOCKET, setsockopt};
    const SO_EXCLUSIVEADDRUSE: i32 = !SO_REUSEADDR;
    let enabled: u32 = 1;
    // SAFETY: setsockopt reads one u32 from a live stack value; the handle is
    // owned by `socket` for the duration of the call.
    unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        );
    }
}

struct Flow {
    handle: SocketHandle,
    _reservation: Reservation,
    /// Seen established at least once, which separates a refused connection
    /// from one that has since closed.
    established: bool,
}

pub(crate) struct TunnelEgress {
    iface: Interface,
    device: TunnelDevice,
    sockets: SocketSet<'static>,
    flows: HashMap<FlowId, Flow>,
    lingering: Vec<(Flow, Instant)>,
    next_flow: FlowId,
    inbox: Arc<Inbox>,
    tap: Arc<LocalTap>,
    outlet: Box<dyn PacketOutlet>,
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    mode: SessionMode,
}

impl TunnelEgress {
    pub(crate) fn new(
        binding: LocalStackBinding,
        outlet: Box<dyn PacketOutlet>,
        waker: Arc<mio::Waker>,
    ) -> Self {
        let mut device = TunnelDevice {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu: usize::from(binding.mtu),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, StackInstant::now());
        let octets = binding.address.octets();
        let gateway = Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(binding.address), 24));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(gateway);
        let inbox = Arc::new(Inbox::new(waker, Arc::clone(&binding.data_receiver)));
        binding.tap.attach(inbox.clone());
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            lingering: Vec::new(),
            next_flow: 0,
            inbox,
            tap: binding.tap,
            outlet,
            address: binding.address,
            gateway,
            mode: binding.mode,
        }
    }

    fn insert(&mut self, handle: SocketHandle, reservation: Reservation) -> FlowId {
        self.next_flow += 1;
        self.flows.insert(
            self.next_flow,
            Flow {
                handle,
                _reservation: reservation,
                established: false,
            },
        );
        self.next_flow
    }

    fn tcp(&mut self, flow: FlowId) -> Option<&mut tcp::Socket<'static>> {
        let handle = self.flows.get(&flow)?.handle;
        Some(self.sockets.get_mut::<tcp::Socket>(handle))
    }

    fn udp(&mut self, flow: FlowId) -> Option<&mut udp::Socket<'static>> {
        let handle = self.flows.get(&flow)?.handle;
        Some(self.sockets.get_mut::<udp::Socket>(handle))
    }

    /// Hands what the stack produced to the session in one batch, so the
    /// session lock is taken once per turn rather than once per packet.
    fn flush(&mut self) {
        if !self.device.tx.is_empty() {
            self.outlet.send_batch(std::mem::take(&mut self.device.tx));
        }
    }

    fn reap(&mut self) {
        let now = Instant::now();
        let sockets = &mut self.sockets;
        self.lingering.retain(|(flow, since)| {
            let finished = match sockets.get_mut::<tcp::Socket>(flow.handle).state() {
                tcp::State::Closed | tcp::State::TimeWait => true,
                _ => now.duration_since(*since) > LINGER,
            };
            if finished {
                sockets.remove(flow.handle);
            }
            !finished
        });
    }
}

impl Drop for TunnelEgress {
    fn drop(&mut self) {
        self.tap.detach();
    }
}

impl Egress for TunnelEgress {
    fn tcp_connect(&mut self, remote: SocketAddrV4) -> Result<FlowId, String> {
        let reservation = Reservation::take(&self.tap, Protocol::Tcp)?;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER]),
        );
        // A game's small writes should leave now, not wait for an ACK.
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_TIMEOUT));
        socket
            .connect(
                self.iface.context(),
                IpEndpoint::new(IpAddress::Ipv4(*remote.ip()), remote.port()),
                reservation.port,
            )
            .map_err(|error| format!("could not open a connection to {remote}: {error}"))?;
        let handle = self.sockets.add(socket);
        Ok(self.insert(handle, reservation))
    }

    fn tcp_state(&mut self, flow: FlowId) -> TcpState {
        let Some(entry) = self.flows.get_mut(&flow) else {
            return TcpState::Closed;
        };
        let state = self.sockets.get_mut::<tcp::Socket>(entry.handle).state();
        match state {
            tcp::State::SynSent | tcp::State::SynReceived | tcp::State::Listen => {
                TcpState::Connecting
            }
            tcp::State::Established | tcp::State::FinWait1 | tcp::State::FinWait2 => {
                entry.established = true;
                TcpState::Open
            }
            tcp::State::CloseWait
            | tcp::State::LastAck
            | tcp::State::Closing
            | tcp::State::TimeWait => {
                entry.established = true;
                TcpState::RemoteClosed
            }
            tcp::State::Closed if entry.established => TcpState::Closed,
            tcp::State::Closed => TcpState::Refused,
        }
    }

    fn tcp_send(&mut self, flow: FlowId, data: &[u8]) -> usize {
        match self.tcp(flow) {
            Some(socket) if socket.may_send() => socket.send_slice(data).unwrap_or(0),
            _ => 0,
        }
    }

    fn tcp_recv(&mut self, flow: FlowId, buffer: &mut [u8]) -> usize {
        match self.tcp(flow) {
            Some(socket) if socket.can_recv() => socket.recv_slice(buffer).unwrap_or(0),
            _ => 0,
        }
    }

    fn tcp_send_idle(&mut self, flow: FlowId) -> bool {
        self.tcp(flow).is_none_or(|socket| socket.send_queue() == 0)
    }

    fn tcp_shutdown(&mut self, flow: FlowId) {
        if let Some(socket) = self.tcp(flow) {
            socket.close();
        }
    }

    fn tcp_release(&mut self, flow: FlowId) {
        let Some(entry) = self.flows.remove(&flow) else {
            return;
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
        // A clean end closes; anything else resets, so the remote does not
        // keep a half-open connection. Either way the socket stays long enough
        // for the stack to send it.
        match socket.state() {
            tcp::State::Established | tcp::State::CloseWait if socket.send_queue() == 0 => {
                socket.close()
            }
            tcp::State::FinWait1
            | tcp::State::FinWait2
            | tcp::State::LastAck
            | tcp::State::Closing
            | tcp::State::TimeWait
            | tcp::State::Closed => {}
            _ => socket.abort(),
        }
        self.lingering.push((entry, Instant::now()));
    }

    fn udp_open(&mut self) -> Result<FlowId, String> {
        let reservation = Reservation::take(&self.tap, Protocol::Udp)?;
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_BUFFER],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket
            .bind(reservation.port)
            .map_err(|error| format!("could not open a UDP flow: {error}"))?;
        let handle = self.sockets.add(socket);
        Ok(self.insert(handle, reservation))
    }

    fn udp_send(&mut self, flow: FlowId, to: SocketAddrV4, payload: &[u8]) -> bool {
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(*to.ip()), to.port());
        self.udp(flow)
            .is_some_and(|socket| socket.send_slice(payload, endpoint).is_ok())
    }

    fn udp_recv(&mut self, flow: FlowId) -> Option<(SocketAddrV4, Vec<u8>)> {
        let socket = self.udp(flow)?;
        let (payload, metadata) = socket.recv().ok()?;
        let IpAddress::Ipv4(from) = metadata.endpoint.addr;
        Some((
            SocketAddrV4::new(from, metadata.endpoint.port),
            payload.to_vec(),
        ))
    }

    fn udp_release(&mut self, flow: FlowId) {
        if let Some(entry) = self.flows.remove(&flow) {
            self.sockets.remove(entry.handle);
        }
    }

    fn drive(&mut self) -> Option<Duration> {
        self.device.rx.extend(self.inbox.take());
        let now = StackInstant::now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.flush();
        self.reap();
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_micros(delay.total_micros()))
    }

    fn resolvers(&self) -> Vec<Ipv4Addr> {
        let mut resolvers = gamepath_engine::dns::FALLBACK_RESOLVERS.to_vec();
        // The relay's own resolver, where one is installed, answers from
        // inside the tunnel. It is asked alongside the public ones rather than
        // first, because a relay without one would cost every lookup a timeout.
        if self.mode == SessionMode::Relay && self.gateway != self.address {
            resolvers.push(self.gateway);
        }
        resolvers
    }

    fn kind(&self) -> &'static str {
        "tunnel"
    }

    fn dropped_inbound(&self) -> u64 {
        self.inbox.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolver::{Lookup, Resolver};
    use super::*;
    use crate::session::{DataReceiver, Diversion};
    use smoltcp::iface::Route;
    use std::sync::mpsc;

    const SESSION_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 5);
    const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    #[derive(Clone, Default)]
    struct Wire(Arc<Mutex<Vec<Vec<u8>>>>);

    impl PacketOutlet for Wire {
        fn send_batch(&self, packets: Vec<Vec<u8>>) {
            self.0.lock().unwrap().extend(packets);
        }
    }

    /// The far side of the tunnel: a TCP and UDP echo service at `SERVER`,
    /// and a resolver at the public fallback address answering every A query
    /// with `SERVER`.
    struct Internet {
        iface: Interface,
        device: TunnelDevice,
        sockets: SocketSet<'static>,
        tcp: SocketHandle,
        echo: SocketHandle,
        dns: SocketHandle,
        stray: usize,
    }

    fn udp_socket(port: u16) -> udp::Socket<'static> {
        let buffer =
            || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 65_536]);
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket.bind(port).unwrap();
        socket
    }

    impl Internet {
        fn new() -> Self {
            let mut device = TunnelDevice {
                rx: VecDeque::new(),
                tx: Vec::new(),
                mtu: 1500,
            };
            let mut iface = Interface::new(
                Config::new(HardwareAddress::Ip),
                &mut device,
                StackInstant::now(),
            );
            iface.update_ip_addrs(|addresses| {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(SERVER), 24));
            });
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Addr::new(93, 184, 216, 1));
            // Answers for the resolver's address too, as if it were a host.
            iface.set_any_ip(true);
            iface.routes_mut().update(|routes| {
                let _ = routes.push(Route {
                    cidr: IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(8, 8, 0, 0)), 16),
                    via_router: IpAddress::Ipv4(SERVER),
                    preferred_until: None,
                    expires_at: None,
                });
            });
            let mut sockets = SocketSet::new(Vec::new());
            let mut tcp = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 256 * 1024]),
                tcp::SocketBuffer::new(vec![0; 256 * 1024]),
            );
            tcp.listen(7).unwrap();
            let tcp = sockets.add(tcp);
            let echo = sockets.add(udp_socket(7));
            let dns = sockets.add(udp_socket(53));
            Self {
                iface,
                device,
                sockets,
                tcp,
                echo,
                dns,
                stray: 0,
            }
        }

        fn step(&mut self, wire: &Wire, tap: &LocalTap) {
            self.device.rx.extend(wire.0.lock().unwrap().drain(..));
            let now = StackInstant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let mut buffer = [0_u8; 16 * 1024];
            let tcp = self.sockets.get_mut::<tcp::Socket>(self.tcp);
            if tcp.can_recv() && tcp.send_capacity() - tcp.send_queue() >= buffer.len() {
                let read = tcp.recv_slice(&mut buffer).unwrap();
                tcp.send_slice(&buffer[..read]).unwrap();
            }
            let echo = self.sockets.get_mut::<udp::Socket>(self.echo);
            while let Ok((length, metadata)) = echo.recv_slice(&mut buffer) {
                echo.send_slice(&buffer[..length], metadata.endpoint)
                    .unwrap();
            }
            let dns = self.sockets.get_mut::<udp::Socket>(self.dns);
            while let Ok((length, metadata)) = dns.recv_slice(&mut buffer) {
                let mut answer = buffer[..length].to_vec();
                answer[2] = 0x81;
                answer[3] = 0x80;
                answer[7] = 1;
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                answer.extend_from_slice(&SERVER.octets());
                let reply = udp::UdpMetadata {
                    endpoint: metadata.endpoint,
                    local_address: metadata.local_address,
                    meta: Default::default(),
                };
                dns.send_slice(&answer, reply).unwrap();
            }
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            for packet in self.device.tx.drain(..) {
                if let Diversion::NotLocal(_) = tap.divert(packet) {
                    self.stray += 1;
                }
            }
        }
    }

    struct Rig {
        _poll: mio::Poll,
        egress: TunnelEgress,
        internet: Internet,
        wire: Wire,
        tap: Arc<LocalTap>,
        received: Arc<DataReceiver>,
    }

    impl Rig {
        fn new() -> Self {
            let poll = mio::Poll::new().unwrap();
            let waker = Arc::new(mio::Waker::new(poll.registry(), mio::Token(0)).unwrap());
            let tap = Arc::new(LocalTap::default());
            let received = Arc::new(DataReceiver {
                inbound: Mutex::new(mpsc::sync_channel(1).1),
                user_bytes_received: AtomicU64::new(0),
            });
            let wire = Wire::default();
            let binding = LocalStackBinding {
                tap: Arc::clone(&tap),
                address: SESSION_ADDRESS,
                mtu: 1356,
                mode: SessionMode::Relay,
                data_receiver: Arc::clone(&received),
            };
            Self {
                _poll: poll,
                egress: TunnelEgress::new(binding, Box::new(wire.clone()), waker),
                internet: Internet::new(),
                wire,
                tap,
                received,
            }
        }

        /// Runs both stacks until `done` holds, for at most five seconds.
        fn run(&mut self, mut done: impl FnMut(&mut TunnelEgress) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !done(&mut self.egress) {
                assert!(Instant::now() < deadline, "timed out");
                self.egress.drive();
                self.internet.step(&self.wire, &self.tap);
            }
        }
    }

    #[test]
    fn a_connection_through_the_stack_carries_data_both_ways() {
        let mut rig = Rig::new();
        let flow = rig
            .egress
            .tcp_connect(SocketAddrV4::new(SERVER, 7))
            .unwrap();
        rig.run(|egress| egress.tcp_state(flow) == TcpState::Open);
        let payload = (0..300_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let (mut sent, mut echoed) = (0, Vec::new());
        let mut buffer = vec![0; 64 * 1024];
        rig.run(|egress| {
            sent += egress.tcp_send(flow, &payload[sent..]);
            let read = egress.tcp_recv(flow, &mut buffer);
            echoed.extend_from_slice(&buffer[..read]);
            echoed.len() == payload.len()
        });
        assert_eq!(echoed, payload);
        assert_eq!(rig.internet.stray, 0, "every reply reached the stack");
        assert!(rig.received.user_bytes_received.load(Ordering::Relaxed) > payload.len() as u64);
    }

    #[test]
    fn datagrams_and_lookups_go_through_the_stack() {
        let mut rig = Rig::new();
        let flow = rig.egress.udp_open().unwrap();
        assert!(
            rig.egress
                .udp_send(flow, SocketAddrV4::new(SERVER, 7), b"state")
        );
        let mut reply = None;
        rig.run(|egress| {
            reply = egress.udp_recv(flow);
            reply.is_some()
        });
        assert_eq!(
            reply,
            Some((SocketAddrV4::new(SERVER, 7), b"state".to_vec()))
        );

        let mut resolver = Resolver::new(rig.egress.resolvers());
        assert!(matches!(
            resolver.lookup(&mut rig.egress, "game.example", 1),
            Lookup::Pending
        ));
        let mut answers = Vec::new();
        rig.run(|egress| {
            answers.extend(resolver.poll(egress));
            !answers.is_empty()
        });
        assert_eq!(answers, vec![(1, Ok(SERVER))]);
        // The second lookup is answered from the cache, with no round trip.
        assert!(matches!(
            resolver.lookup(&mut rig.egress, "game.example", 2),
            Lookup::Ready(SERVER)
        ));
    }

    #[test]
    fn stopping_the_stack_gives_every_port_back() {
        let mut rig = Rig::new();
        let flow = rig.egress.udp_open().unwrap();
        rig.egress
            .udp_send(flow, SocketAddrV4::new(SERVER, 7), b"x");
        rig.egress.drive();
        let sent = rig.wire.0.lock().unwrap().pop().expect("a datagram left");
        let mut reply = sent.clone();
        // The same datagram turned around: from the server, to our port.
        reply[12..16].copy_from_slice(&sent[16..20]);
        reply[16..20].copy_from_slice(&sent[12..16]);
        reply[20..24].copy_from_slice(&[sent[22], sent[23], sent[20], sent[21]]);
        assert!(matches!(rig.tap.divert(reply.clone()), Diversion::Taken));
        let Rig { egress, tap, .. } = rig;
        drop(egress);
        assert!(matches!(tap.divert(reply), Diversion::NotLocal(_)));
    }
}
