//! The proxy's event loop: one thread, every client socket non-blocking.
//!
//! One thread rather than one per connection because a console opens dozens
//! of connections at once, and because the user-space stack behind the tunnel
//! egress is single-owner anyway. Every turn reads what clients sent, lets the
//! egress move packets, and writes back what arrived, so a packet from the
//! tunnel reaches its client in the same turn it woke the loop.

use super::clients::{ClientBook, ClientUsage};
use super::egress::{EGRESS_TOKEN_BASE, Egress, FlowId, TcpState, destination_allowed};
use super::resolver::{Lookup, Resolver};
use super::wire::{self, Parse, Reply, Target};
use gamepath_engine::{log_debug, log_info, log_warn};
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Interest, Poll, Token};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LISTENER: Token = Token(0);
const UDP_RELAY: Token = Token(1);
pub(crate) const WAKER: Token = Token(2);
const FIRST_CONNECTION: usize = 16;

/// Enough for a console's store and a game at once, bounded so a device on
/// the LAN cannot exhaust the engine.
const MAX_CONNECTIONS: usize = 1024;
const MAX_CONNECTIONS_PER_CLIENT: u32 = 512;
const MAX_ASSOCIATIONS_PER_CLIENT: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Data held for a client that is reading slower than the remote sends. Past
/// this the tunnel side stops being read, which closes its TCP window.
const CLIENT_BACKLOG: usize = 256 * 1024;
const READ_CHUNK: usize = 32 * 1024;
const PENDING_DATAGRAMS_PER_ASSOCIATION: usize = 64;
/// The loop wakes at least this often to publish status and check deadlines.
const MAX_WAIT: Duration = Duration::from_millis(250);
const STATUS_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Socks,
    Http,
}

enum ReplyKind {
    Socks,
    HttpTunnel,
    /// A plain HTTP request whose rewritten head goes upstream first.
    HttpForward(Vec<u8>),
}

enum Phase {
    Sniff,
    Greeting,
    UserPass,
    Request,
    HttpHead,
    Resolving {
        port: u16,
        reply: ReplyKind,
    },
    Connecting {
        flow: FlowId,
        reply: ReplyKind,
    },
    Relaying {
        flow: FlowId,
    },
    UdpControl {
        association: u64,
    },
    /// Flushing a final reply before the connection is dropped.
    Closing,
}

struct Connection {
    stream: TcpStream,
    client: SocketAddrV4,
    local: SocketAddrV4,
    phase: Phase,
    protocol: Protocol,
    input: Vec<u8>,
    output: Vec<u8>,
    written: usize,
    readable: bool,
    writable: bool,
    client_done: bool,
    upstream_shut: bool,
    client_shut: bool,
    deadline: Option<Instant>,
    counted: bool,
    finished: bool,
}

impl Connection {
    fn send(&mut self, bytes: &[u8]) {
        self.output.extend_from_slice(bytes);
    }

    fn backlog(&self) -> usize {
        self.output.len() - self.written
    }

    fn fail(&mut self, reply: Reply) {
        match self.protocol {
            Protocol::Socks => self.send(&wire::reply(reply, unspecified())),
            Protocol::Http => self.send(wire::http_failure(reply)),
        }
        self.phase = Phase::Closing;
        self.deadline = Some(Instant::now() + Duration::from_secs(2));
    }

    /// Reads whatever the client has sent, up to `limit` buffered bytes.
    fn read_client(&mut self, limit: usize) -> std::io::Result<()> {
        let mut chunk = [0_u8; READ_CHUNK];
        while self.readable && !self.client_done && self.input.len() < limit {
            let room = (limit - self.input.len()).min(READ_CHUNK);
            match self.stream.read(&mut chunk[..room]) {
                Ok(0) => self.client_done = true,
                Ok(read) => self.input.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => self.readable = false,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_client(&mut self) -> std::io::Result<()> {
        while self.writable && self.written < self.output.len() {
            match self.stream.write(&self.output[self.written..]) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(written) => self.written += written,
                Err(error) if error.kind() == ErrorKind::WouldBlock => self.writable = false,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if self.written == self.output.len() {
            self.output.clear();
            self.written = 0;
        }
        Ok(())
    }
}

struct Association {
    control: Token,
    client_ip: Ipv4Addr,
    client_port: Option<u16>,
    flow: FlowId,
    pending_lookups: usize,
}

/// A handshake step that needs more of the server than the one connection.
enum Next {
    Connect(Target, ReplyKind),
    Associate(Target),
}

enum Waiter {
    Connect(Token),
    Datagram {
        association: u64,
        port: u16,
        payload: Vec<u8>,
    },
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerStatus {
    pub(crate) active_connections: usize,
    pub(crate) udp_associations: usize,
    pub(crate) total_connections: u64,
    pub(crate) failed_connections: u64,
    pub(crate) rejected_connections: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) dropped_inbound: u64,
    pub(crate) clients: Vec<ClientUsage>,
}

pub(crate) struct Server {
    poll: Poll,
    listener: TcpListener,
    udp: UdpSocket,
    udp_readable: bool,
    port: u16,
    egress: Box<dyn Egress>,
    resolver: Resolver<Waiter>,
    connections: HashMap<Token, Connection>,
    associations: HashMap<u64, Association>,
    next_token: usize,
    next_association: u64,
    clients: ClientBook,
    credentials: Option<(String, String)>,
    stop: Arc<AtomicBool>,
    status: Arc<Mutex<ServerStatus>>,
    totals: ServerStatus,
    egress_wait: Option<Duration>,
    destination_allowed: fn(Ipv4Addr) -> bool,
}

fn unspecified() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
}

/// Devices on the same network as this PC. The proxy is for a console beside
/// it, never for the Internet, whatever the firewall happens to allow.
pub(crate) fn client_allowed(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || (first == 100 && (64..128).contains(&second))
}

fn same_secret(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

impl Server {
    pub(crate) fn new(
        poll: Poll,
        mut listener: TcpListener,
        mut udp: UdpSocket,
        egress: Box<dyn Egress>,
        credentials: Option<(String, String)>,
        stop: Arc<AtomicBool>,
        status: Arc<Mutex<ServerStatus>>,
    ) -> std::io::Result<Self> {
        let port = listener.local_addr()?.port();
        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        poll.registry()
            .register(&mut udp, UDP_RELAY, Interest::READABLE)?;
        let resolver = Resolver::new(egress.resolvers());
        Ok(Self {
            poll,
            listener,
            udp,
            udp_readable: false,
            port,
            egress,
            resolver,
            connections: HashMap::new(),
            associations: HashMap::new(),
            next_token: FIRST_CONNECTION,
            next_association: 0,
            clients: ClientBook::default(),
            credentials,
            stop,
            status,
            totals: ServerStatus::default(),
            egress_wait: None,
            destination_allowed,
        })
    }

    /// Lets tests reach echo servers on loopback, which clients never may.
    #[cfg(test)]
    fn allow_every_destination(mut self) -> Self {
        self.destination_allowed = |_| true;
        self
    }

    pub(crate) fn run(mut self) {
        let mut events = Events::with_capacity(1024);
        let mut next_status = Instant::now();
        while !self.stop.load(Ordering::Acquire) {
            let timeout = self.wait();
            if let Err(error) = self.poll.poll(&mut events, Some(timeout)) {
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                log_warn!("LAN proxy stopped: {error}");
                break;
            }
            for event in events.iter() {
                let token = event.token();
                let readable = event.is_readable() || event.is_read_closed() || event.is_error();
                let writable = event.is_writable() || event.is_write_closed() || event.is_error();
                match token {
                    LISTENER => self.accept(),
                    UDP_RELAY => self.udp_readable = true,
                    WAKER => {}
                    token if token.0 >= EGRESS_TOKEN_BASE => {
                        self.egress.on_event(token, readable, writable)
                    }
                    token => {
                        if let Some(connection) = self.connections.get_mut(&token) {
                            connection.readable |= readable;
                            connection.writable |= writable;
                        }
                    }
                }
            }
            self.turn();
            if Instant::now() >= next_status {
                self.publish();
                next_status = Instant::now() + STATUS_INTERVAL;
            }
        }
        self.shutdown();
    }

    fn wait(&self) -> Duration {
        let now = Instant::now();
        let mut wait = MAX_WAIT;
        if let Some(delay) = self.egress_wait {
            wait = wait.min(delay);
        }
        let deadlines = self
            .connections
            .values()
            .filter_map(|connection| connection.deadline)
            .chain(self.resolver.next_deadline());
        for deadline in deadlines {
            wait = wait.min(deadline.saturating_duration_since(now));
        }
        // Clients with data ready and nowhere to put it are retried as the
        // tunnel side drains; the egress's own timer says when that is.
        wait
    }

    fn accept(&mut self) {
        loop {
            let (mut stream, peer) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    log_warn!("LAN proxy could not accept a connection: {error}");
                    return;
                }
            };
            let (SocketAddr::V4(client), Ok(SocketAddr::V4(local))) = (peer, stream.local_addr())
            else {
                continue;
            };
            if !client_allowed(*client.ip())
                || self.connections.len() >= MAX_CONNECTIONS
                || self.clients.active_tcp(*client.ip()) >= MAX_CONNECTIONS_PER_CLIENT
            {
                self.totals.rejected_connections += 1;
                continue;
            }
            let _ = stream.set_nodelay(true);
            let token = Token(self.next_token);
            self.next_token += 1;
            if self
                .poll
                .registry()
                .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
                .is_err()
            {
                continue;
            }
            self.clients.entry(*client.ip()).total_connections += 1;
            self.totals.total_connections += 1;
            self.connections.insert(
                token,
                Connection {
                    stream,
                    client,
                    local,
                    phase: Phase::Sniff,
                    protocol: Protocol::Socks,
                    input: Vec::new(),
                    output: Vec::new(),
                    written: 0,
                    readable: true,
                    writable: true,
                    client_done: false,
                    upstream_shut: false,
                    client_shut: false,
                    deadline: Some(Instant::now() + HANDSHAKE_TIMEOUT),
                    counted: false,
                    finished: false,
                },
            );
        }
    }

    fn turn(&mut self) {
        let tokens = self.connections.keys().copied().collect::<Vec<_>>();
        for &token in &tokens {
            self.advance(token);
        }
        self.receive_client_datagrams();
        self.egress_wait = self.egress.drive();
        self.finish_lookups();
        for &token in &tokens {
            self.deliver(token);
        }
        self.deliver_datagrams();
        self.egress_wait = self.egress.drive();
        self.expire();
        self.reap();
    }

    /// Handshake progress and client-to-remote data for one connection.
    fn advance(&mut self, token: Token) {
        let Some(connection) = self.connections.get_mut(&token) else {
            return;
        };
        let limit = match connection.phase {
            Phase::Relaying { .. } => READ_CHUNK,
            _ => 64 * 1024,
        };
        // A connection waiting on the tunnel keeps what it has; reading on
        // would buffer without bound.
        let paused = matches!(
            connection.phase,
            Phase::Resolving { .. } | Phase::Connecting { .. }
        ) || (matches!(connection.phase, Phase::Relaying { .. })
            && !connection.input.is_empty());
        if !paused && connection.read_client(limit).is_err() {
            connection.finished = true;
            return;
        }
        loop {
            let progressed = self.step(token);
            if !progressed {
                break;
            }
        }
    }

    /// One handshake transition, if the buffered input allows it.
    fn step(&mut self, token: Token) -> bool {
        let (progressed, next) = self.step_connection(token);
        match next {
            Some(Next::Connect(target, reply)) => self.begin_connect(token, target, reply),
            Some(Next::Associate(target)) => self.associate(token, &target),
            None => {}
        }
        progressed
    }

    fn step_connection(&mut self, token: Token) -> (bool, Option<Next>) {
        let Some(connection) = self.connections.get_mut(&token) else {
            return (false, None);
        };
        let credentials = self.credentials.as_ref();
        let progressed = match &connection.phase {
            Phase::Sniff => {
                let Some(&first) = connection.input.first() else {
                    return (false, None);
                };
                match first {
                    wire::SOCKS_VERSION => connection.phase = Phase::Greeting,
                    byte if byte.is_ascii_alphabetic() => {
                        connection.protocol = Protocol::Http;
                        connection.phase = Phase::HttpHead;
                    }
                    // SOCKS4 and anything else: nothing to say in its language.
                    _ => connection.finished = true,
                }
                true
            }
            Phase::Greeting => match wire::parse_greeting(&connection.input) {
                Parse::Incomplete => false,
                Parse::Invalid(_) => {
                    connection.finished = true;
                    false
                }
                Parse::Done(methods, used) => {
                    connection.input.drain(..used);
                    // A client that insists on sending a login is let in with
                    // it when none is required, rather than turned away.
                    let method = if credentials.is_some() || !methods.contains(&wire::METHOD_NONE) {
                        methods
                            .contains(&wire::METHOD_USER_PASS)
                            .then_some(wire::METHOD_USER_PASS)
                    } else {
                        Some(wire::METHOD_NONE)
                    };
                    match method {
                        Some(wire::METHOD_USER_PASS) => {
                            connection.send(&[wire::SOCKS_VERSION, wire::METHOD_USER_PASS]);
                            connection.phase = Phase::UserPass;
                        }
                        Some(method) => {
                            connection.send(&[wire::SOCKS_VERSION, method]);
                            connection.phase = Phase::Request;
                        }
                        None => {
                            connection.send(&[wire::SOCKS_VERSION, wire::METHOD_UNACCEPTABLE]);
                            connection.phase = Phase::Closing;
                            self.totals.failed_connections += 1;
                        }
                    }
                    true
                }
            },
            Phase::UserPass => match wire::parse_user_pass(&connection.input) {
                Parse::Incomplete => false,
                Parse::Invalid(_) => {
                    connection.finished = true;
                    false
                }
                Parse::Done((user, password), used) => {
                    connection.input.drain(..used);
                    let accepted = credentials.is_none_or(|(expected_user, expected_password)| {
                        same_secret(&user, expected_user)
                            & same_secret(&password, expected_password)
                    });
                    connection.send(&wire::user_pass_reply(accepted));
                    if accepted {
                        connection.phase = Phase::Request;
                    } else {
                        connection.phase = Phase::Closing;
                        self.totals.failed_connections += 1;
                        self.clients
                            .entry(*connection.client.ip())
                            .failed_connections += 1;
                    }
                    true
                }
            },
            Phase::Request => match wire::parse_request(&connection.input) {
                Parse::Incomplete => false,
                Parse::Invalid(_) => {
                    connection.fail(Reply::GeneralFailure);
                    true
                }
                Parse::Done(request, used) => {
                    connection.input.drain(..used);
                    match request.command {
                        wire::COMMAND_CONNECT => {
                            return (true, Some(Next::Connect(request.target, ReplyKind::Socks)));
                        }
                        wire::COMMAND_UDP_ASSOCIATE => {
                            return (true, Some(Next::Associate(request.target)));
                        }
                        _ => connection.fail(Reply::CommandNotSupported),
                    }
                    true
                }
            },
            Phase::HttpHead => match wire::parse_http_request(&connection.input) {
                Parse::Incomplete => false,
                Parse::Invalid(_) => {
                    connection.fail(Reply::CommandNotSupported);
                    true
                }
                Parse::Done(request, used) => {
                    connection.input.drain(..used);
                    let authorised = credentials.is_none_or(|(user, password)| {
                        request
                            .credentials
                            .as_ref()
                            .is_some_and(|(given_user, given_password)| {
                                same_secret(given_user, user)
                                    & same_secret(given_password, password)
                            })
                    });
                    if !authorised {
                        connection.send(wire::HTTP_AUTH_REQUIRED);
                        connection.phase = Phase::Closing;
                        return (true, None);
                    }
                    let reply = if request.tunnel {
                        ReplyKind::HttpTunnel
                    } else {
                        ReplyKind::HttpForward(request.upstream_head)
                    };
                    return (true, Some(Next::Connect(request.target, reply)));
                }
            },
            Phase::Relaying { flow } => {
                let flow = *flow;
                if !connection.input.is_empty() {
                    let sent = self.egress.tcp_send(flow, &connection.input);
                    if sent > 0 {
                        connection.input.drain(..sent);
                        self.clients.entry(*connection.client.ip()).bytes_sent += sent as u64;
                        self.totals.bytes_sent += sent as u64;
                    }
                }
                if connection.input.is_empty()
                    && connection.client_done
                    && !connection.upstream_shut
                {
                    self.egress.tcp_shutdown(flow);
                    connection.upstream_shut = true;
                }
                // Room freed upstream lets the next read happen in this turn.
                let more =
                    connection.input.is_empty() && connection.readable && !connection.client_done;
                if more && connection.read_client(READ_CHUNK).is_err() {
                    connection.finished = true;
                    return (false, None);
                }
                more && !connection.input.is_empty()
            }
            Phase::UdpControl { .. } => {
                // Nothing is expected on the control stream; its closing is
                // what ends the association.
                connection.input.clear();
                if connection.client_done {
                    connection.finished = true;
                }
                false
            }
            Phase::Resolving { .. } | Phase::Connecting { .. } | Phase::Closing => false,
        };
        (progressed, None)
    }

    fn begin_connect(&mut self, token: Token, target: Target, reply: ReplyKind) {
        let Some(connection) = self.connections.get_mut(&token) else {
            return;
        };
        let address = match target {
            Target::Ipv6 => return connection.fail(Reply::AddressTypeNotSupported),
            Target::Ip(address) => address,
            Target::Domain(name, port) => {
                match self
                    .resolver
                    .lookup(self.egress.as_mut(), &name, Waiter::Connect(token))
                {
                    Lookup::Ready(ip) => SocketAddrV4::new(ip, port),
                    Lookup::Pending => {
                        connection.phase = Phase::Resolving { port, reply };
                        connection.deadline = Some(Instant::now() + CONNECT_TIMEOUT);
                        return;
                    }
                    Lookup::Failed(reason) => {
                        log_debug!("LAN proxy: {reason}");
                        return connection.fail(Reply::HostUnreachable);
                    }
                }
            }
        };
        self.open(token, address, reply);
    }

    fn open(&mut self, token: Token, address: SocketAddrV4, reply: ReplyKind) {
        let Some(connection) = self.connections.get_mut(&token) else {
            return;
        };
        if !(self.destination_allowed)(*address.ip()) {
            self.totals.failed_connections += 1;
            return connection.fail(Reply::NotAllowed);
        }
        match self.egress.tcp_connect(address) {
            Ok(flow) => {
                connection.phase = Phase::Connecting { flow, reply };
                connection.deadline = Some(Instant::now() + CONNECT_TIMEOUT);
            }
            Err(error) => {
                log_warn!("LAN proxy: {error}");
                self.totals.failed_connections += 1;
                connection.fail(Reply::GeneralFailure);
            }
        }
    }

    fn associate(&mut self, token: Token, target: &Target) {
        let Some(connection) = self.connections.get_mut(&token) else {
            return;
        };
        let client_ip = *connection.client.ip();
        let open = self
            .associations
            .values()
            .filter(|association| association.client_ip == client_ip)
            .count();
        if open >= MAX_ASSOCIATIONS_PER_CLIENT {
            return connection.fail(Reply::GeneralFailure);
        }
        let flow = match self.egress.udp_open() {
            Ok(flow) => flow,
            Err(error) => {
                log_warn!("LAN proxy: {error}");
                return connection.fail(Reply::GeneralFailure);
            }
        };
        // The client may say in advance which port it will send from; zero
        // means it does not know yet, and its first datagram decides.
        let client_port = match target {
            Target::Ip(address) if address.port() != 0 => Some(address.port()),
            _ => None,
        };
        self.next_association += 1;
        self.associations.insert(
            self.next_association,
            Association {
                control: token,
                client_ip,
                client_port,
                flow,
                pending_lookups: 0,
            },
        );
        let bound = SocketAddrV4::new(*connection.local.ip(), self.port);
        connection.send(&wire::reply(Reply::Succeeded, bound));
        connection.phase = Phase::UdpControl {
            association: self.next_association,
        };
        connection.deadline = None;
        self.clients.entry(client_ip).active_udp += 1;
    }

    fn finish_lookups(&mut self) {
        for (waiter, result) in self.resolver.poll(self.egress.as_mut()) {
            match waiter {
                Waiter::Connect(token) => {
                    let Some(connection) = self.connections.get_mut(&token) else {
                        continue;
                    };
                    let phase = std::mem::replace(&mut connection.phase, Phase::Closing);
                    let Phase::Resolving { port, reply } = phase else {
                        connection.phase = phase;
                        continue;
                    };
                    match result {
                        Ok(ip) => self.open(token, SocketAddrV4::new(ip, port), reply),
                        Err(_) => {
                            self.totals.failed_connections += 1;
                            connection.fail(Reply::HostUnreachable);
                        }
                    }
                }
                Waiter::Datagram {
                    association,
                    port,
                    payload,
                } => {
                    let Some(entry) = self.associations.get_mut(&association) else {
                        continue;
                    };
                    entry.pending_lookups = entry.pending_lookups.saturating_sub(1);
                    if let Ok(ip) = result {
                        let (flow, client_ip) = (entry.flow, entry.client_ip);
                        self.send_datagram(flow, client_ip, SocketAddrV4::new(ip, port), &payload);
                    }
                }
            }
        }
    }

    fn send_datagram(
        &mut self,
        flow: FlowId,
        client_ip: Ipv4Addr,
        to: SocketAddrV4,
        payload: &[u8],
    ) {
        if !(self.destination_allowed)(*to.ip()) {
            return;
        }
        if self.egress.udp_send(flow, to, payload) {
            self.clients.entry(client_ip).bytes_sent += payload.len() as u64;
            self.totals.bytes_sent += payload.len() as u64;
        }
    }

    fn receive_client_datagrams(&mut self) {
        let mut buffer = vec![0_u8; 65_536];
        while self.udp_readable {
            let (length, from) = match self.udp.recv_from(&mut buffer) {
                Ok((length, SocketAddr::V4(from))) => (length, from),
                Ok(_) => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    self.udp_readable = false;
                    break;
                }
                // A client that went away, reported on the next read.
                Err(error) if error.kind() == ErrorKind::ConnectionReset => continue,
                Err(_) => {
                    self.udp_readable = false;
                    break;
                }
            };
            let Some(id) = self.association_for(from) else {
                continue;
            };
            let Some((target, payload)) = wire::parse_udp_datagram(&buffer[..length]) else {
                continue;
            };
            let association = &self.associations[&id];
            let (flow, client_ip) = (association.flow, association.client_ip);
            match target {
                Target::Ip(to) => self.send_datagram(flow, client_ip, to, payload),
                Target::Domain(name, port) => {
                    if association.pending_lookups >= PENDING_DATAGRAMS_PER_ASSOCIATION {
                        continue;
                    }
                    let waiter = Waiter::Datagram {
                        association: id,
                        port,
                        payload: payload.to_vec(),
                    };
                    match self.resolver.lookup(self.egress.as_mut(), &name, waiter) {
                        Lookup::Ready(ip) => self.send_datagram(
                            flow,
                            client_ip,
                            SocketAddrV4::new(ip, port),
                            payload,
                        ),
                        Lookup::Pending => {
                            if let Some(entry) = self.associations.get_mut(&id) {
                                entry.pending_lookups += 1;
                            }
                        }
                        Lookup::Failed(_) => {}
                    }
                }
                Target::Ipv6 => {}
            }
        }
    }

    /// The association a datagram from `from` belongs to, adopting its port
    /// for one that did not know it in advance.
    fn association_for(&mut self, from: SocketAddrV4) -> Option<u64> {
        let exact = self.associations.iter().find_map(|(id, association)| {
            (association.client_ip == *from.ip() && association.client_port == Some(from.port()))
                .then_some(*id)
        });
        if exact.is_some() {
            return exact;
        }
        let (id, association) = self
            .associations
            .iter_mut()
            .filter(|(_, association)| {
                association.client_ip == *from.ip() && association.client_port.is_none()
            })
            .min_by_key(|(id, _)| **id)?;
        association.client_port = Some(from.port());
        Some(*id)
    }

    /// Remote-to-client data, connection results and closes for one connection.
    fn deliver(&mut self, token: Token) {
        let Some(connection) = self.connections.get_mut(&token) else {
            return;
        };
        match &mut connection.phase {
            Phase::Connecting { flow, reply } => {
                let flow = *flow;
                match self.egress.tcp_state(flow) {
                    TcpState::Connecting => {}
                    TcpState::Open | TcpState::RemoteClosed => {
                        let reply = std::mem::replace(reply, ReplyKind::Socks);
                        match reply {
                            ReplyKind::Socks => {
                                connection.send(&wire::reply(Reply::Succeeded, unspecified()))
                            }
                            ReplyKind::HttpTunnel => connection.send(wire::HTTP_ESTABLISHED),
                            ReplyKind::HttpForward(head) => {
                                let body = std::mem::take(&mut connection.input);
                                connection.input = head;
                                connection.input.extend_from_slice(&body);
                            }
                        }
                        connection.phase = Phase::Relaying { flow };
                        connection.deadline = None;
                        connection.counted = true;
                        self.clients.entry(*connection.client.ip()).active_tcp += 1;
                        // Anything the client sent ahead of the reply goes now.
                        self.step(token);
                        self.deliver(token);
                    }
                    state => {
                        self.egress.tcp_release(flow);
                        self.totals.failed_connections += 1;
                        self.clients
                            .entry(*connection.client.ip())
                            .failed_connections += 1;
                        connection.fail(if state == TcpState::Refused {
                            Reply::ConnectionRefused
                        } else {
                            Reply::GeneralFailure
                        });
                    }
                }
            }
            Phase::Relaying { flow } => {
                let flow = *flow;
                let mut chunk = [0_u8; READ_CHUNK];
                let mut received = 0;
                while connection.backlog() < CLIENT_BACKLOG {
                    let read = self.egress.tcp_recv(flow, &mut chunk);
                    if read == 0 {
                        break;
                    }
                    connection.output.extend_from_slice(&chunk[..read]);
                    received += read as u64;
                }
                if received > 0 {
                    self.clients.entry(*connection.client.ip()).bytes_received += received;
                    self.totals.bytes_received += received;
                }
                if connection.write_client().is_err() {
                    connection.finished = true;
                    return;
                }
                let state = self.egress.tcp_state(flow);
                let remote_done = matches!(
                    state,
                    TcpState::RemoteClosed | TcpState::Closed | TcpState::Refused
                );
                if remote_done && connection.backlog() == 0 && !connection.client_shut {
                    let _ = connection.stream.shutdown(Shutdown::Write);
                    connection.client_shut = true;
                }
                let upstream_idle = self.egress.tcp_send_idle(flow);
                let both_done = connection.client_shut
                    && (connection.client_done && upstream_idle
                        || matches!(state, TcpState::Closed | TcpState::Refused));
                if both_done {
                    connection.finished = true;
                }
            }
            _ => {
                if connection.write_client().is_err() {
                    connection.finished = true;
                    return;
                }
                if matches!(connection.phase, Phase::Closing) && connection.backlog() == 0 {
                    connection.finished = true;
                }
            }
        }
    }

    fn deliver_datagrams(&mut self) {
        for association in self.associations.values() {
            while let Some((from, payload)) = self.egress.udp_recv(association.flow) {
                let Some(port) = association.client_port else {
                    continue;
                };
                let client = SocketAddr::V4(SocketAddrV4::new(association.client_ip, port));
                // A full socket buffer drops the datagram, as the network would.
                if self
                    .udp
                    .send_to(&wire::udp_datagram(from, &payload), client)
                    .is_ok()
                {
                    self.clients.entry(association.client_ip).bytes_received +=
                        payload.len() as u64;
                    self.totals.bytes_received += payload.len() as u64;
                }
            }
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        for connection in self.connections.values_mut() {
            let Some(deadline) = connection.deadline else {
                continue;
            };
            if now < deadline {
                continue;
            }
            match std::mem::replace(&mut connection.phase, Phase::Closing) {
                Phase::Connecting { flow, .. } => {
                    self.egress.tcp_release(flow);
                    self.totals.failed_connections += 1;
                    connection.fail(Reply::TtlExpired);
                }
                Phase::Resolving { .. } => {
                    self.totals.failed_connections += 1;
                    connection.fail(Reply::HostUnreachable);
                }
                _ => connection.finished = true,
            }
        }
    }

    fn reap(&mut self) {
        let finished = self
            .connections
            .iter()
            .filter(|(_, connection)| connection.finished)
            .map(|(token, _)| *token)
            .collect::<Vec<_>>();
        for token in finished {
            let Some(mut connection) = self.connections.remove(&token) else {
                continue;
            };
            let _ = self.poll.registry().deregister(&mut connection.stream);
            let client_ip = *connection.client.ip();
            match connection.phase {
                Phase::Connecting { flow, .. } | Phase::Relaying { flow } => {
                    self.egress.tcp_release(flow)
                }
                Phase::UdpControl { association } => {
                    if let Some(entry) = self.associations.remove(&association) {
                        self.egress.udp_release(entry.flow);
                        let client = self.clients.entry(client_ip);
                        client.active_udp = client.active_udp.saturating_sub(1);
                    }
                }
                _ => {}
            }
            if connection.counted {
                let client = self.clients.entry(client_ip);
                client.active_tcp = client.active_tcp.saturating_sub(1);
            }
        }
        // An association whose control connection vanished some other way.
        let orphaned = self
            .associations
            .iter()
            .filter(|(_, association)| !self.connections.contains_key(&association.control))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in orphaned {
            if let Some(entry) = self.associations.remove(&id) {
                self.egress.udp_release(entry.flow);
            }
        }
    }

    fn publish(&mut self) {
        let status = ServerStatus {
            active_connections: self
                .connections
                .values()
                .filter(|connection| matches!(connection.phase, Phase::Relaying { .. }))
                .count(),
            udp_associations: self.associations.len(),
            dropped_inbound: self.egress.dropped_inbound(),
            clients: self.clients.snapshot(),
            ..self.totals.clone()
        };
        *self.status.lock().unwrap() = status;
    }

    fn shutdown(&mut self) {
        let tokens = self.connections.keys().copied().collect::<Vec<_>>();
        for token in tokens {
            if let Some(connection) = self.connections.get_mut(&token) {
                connection.finished = true;
            }
        }
        self.reap();
        self.resolver.release(self.egress.as_mut());
        // Lets the stack send the resets it just queued.
        self.egress.drive();
        self.publish();
        log_info!(
            "LAN proxy on port {} stopped after {} connection(s)",
            self.port,
            self.totals.total_connections
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_devices_on_the_local_network_may_connect() {
        for allowed in [
            "192.168.1.40",
            "10.0.0.5",
            "172.20.1.1",
            "100.100.1.1",
            "127.0.0.1",
        ] {
            assert!(client_allowed(allowed.parse().unwrap()), "{allowed}");
        }
        for refused in ["8.8.8.8", "100.128.0.1", "172.32.0.1"] {
            assert!(!client_allowed(refused.parse().unwrap()), "{refused}");
        }
    }

    use super::super::interface_egress::InterfaceEgress;
    use std::net::{TcpListener as StdListener, TcpStream as StdStream, UdpSocket as StdUdp};

    struct Harness {
        proxy: SocketAddr,
        stop: Arc<AtomicBool>,
        status: Arc<Mutex<ServerStatus>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// A proxy whose egress is plain loopback sockets, so the whole loop -
    /// handshakes, relaying, UDP associations - runs against real sockets.
    fn harness(credentials: Option<(&str, &str)>) -> Harness {
        let loopback = Ipv4Addr::LOCALHOST;
        let interface = gamepath_engine::netconfig::interface_index_for_address(loopback)
            .unwrap()
            .expect("loopback has an interface");
        let poll = Poll::new().unwrap();
        let egress =
            InterfaceEgress::new(poll.registry().try_clone().unwrap(), loopback, interface);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        udp.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(ServerStatus::default()));
        let server = Server::new(
            poll,
            TcpListener::from_std(listener),
            UdpSocket::from_std(udp),
            Box::new(egress),
            credentials.map(|(user, password)| (user.to_owned(), password.to_owned())),
            Arc::clone(&stop),
            Arc::clone(&status),
        )
        .unwrap()
        .allow_every_destination();
        Harness {
            proxy: SocketAddr::from((loopback, port)),
            stop,
            status,
            thread: Some(std::thread::spawn(move || server.run())),
        }
    }

    fn echo_tcp() -> SocketAddrV4 {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut reader = stream.try_clone().unwrap();
                    let mut writer = stream;
                    let _ = std::io::copy(&mut reader, &mut writer);
                });
            }
        });
        address
    }

    fn connect(proxy: SocketAddr) -> StdStream {
        let stream = StdStream::connect(proxy).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    fn read_exact(stream: &mut StdStream, length: usize) -> Vec<u8> {
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer).unwrap();
        buffer
    }

    fn socks_connect(stream: &mut StdStream, target: SocketAddrV4) {
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&target.ip().octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        stream.write_all(&request).unwrap();
    }

    #[test]
    fn a_socks5_connect_relays_both_ways() {
        let proxy = harness(None);
        let echo = echo_tcp();
        let mut client = connect(proxy.proxy);
        client.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_exact(&mut client, 2), [5, 0]);
        socks_connect(&mut client, echo);
        assert_eq!(read_exact(&mut client, 10)[..2], [5, 0]);
        let payload = (0..200_000).map(|index| index as u8).collect::<Vec<_>>();
        let mut writer = client.try_clone().unwrap();
        let sent = payload.clone();
        let sender = std::thread::spawn(move || writer.write_all(&sent).unwrap());
        assert_eq!(read_exact(&mut client, payload.len()), payload);
        sender.join().unwrap();
        std::thread::sleep(STATUS_INTERVAL * 2);
        let status = proxy.status.lock().unwrap().clone();
        assert_eq!(status.active_connections, 1);
        assert_eq!(status.clients.len(), 1);
        assert_eq!(status.clients[0].bytes_sent, payload.len() as u64);
        assert_eq!(status.clients[0].bytes_received, payload.len() as u64);
    }

    #[test]
    fn a_wrong_login_is_refused_and_the_right_one_admitted() {
        let proxy = harness(Some(("console", "secret")));
        let mut client = connect(proxy.proxy);
        client.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_exact(&mut client, 2), [5, 0xff]);

        let mut client = connect(proxy.proxy);
        client.write_all(&[5, 1, 2]).unwrap();
        assert_eq!(read_exact(&mut client, 2), [5, 2]);
        client.write_all(b"\x01\x07console\x05wrong").unwrap();
        assert_eq!(read_exact(&mut client, 2), [1, 1]);

        let echo = echo_tcp();
        let mut client = connect(proxy.proxy);
        client.write_all(&[5, 1, 2]).unwrap();
        assert_eq!(read_exact(&mut client, 2), [5, 2]);
        client.write_all(b"\x01\x07console\x06secret").unwrap();
        assert_eq!(read_exact(&mut client, 2), [1, 0]);
        socks_connect(&mut client, echo);
        assert_eq!(read_exact(&mut client, 10)[..2], [5, 0]);
        client.write_all(b"ping").unwrap();
        assert_eq!(read_exact(&mut client, 4), b"ping");
    }

    #[test]
    fn a_refused_connection_is_reported_as_refused() {
        let proxy = harness(None);
        // Bound and closed again: nothing listens there now.
        let closed = StdListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(target) = closed.local_addr().unwrap() else {
            unreachable!()
        };
        drop(closed);
        let mut client = connect(proxy.proxy);
        client.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_exact(&mut client, 2), [5, 0]);
        socks_connect(&mut client, target);
        assert_eq!(
            read_exact(&mut client, 10)[1],
            Reply::ConnectionRefused as u8
        );
    }

    #[test]
    fn http_connect_tunnels_to_the_target() {
        let proxy = harness(None);
        let echo = echo_tcp();
        let mut client = connect(proxy.proxy);
        write!(client, "CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").unwrap();
        assert_eq!(
            read_exact(&mut client, wire::HTTP_ESTABLISHED.len()),
            wire::HTTP_ESTABLISHED
        );
        client.write_all(b"through").unwrap();
        assert_eq!(read_exact(&mut client, 7), b"through");
    }

    #[test]
    fn a_udp_association_carries_datagrams_both_ways() {
        let proxy = harness(None);
        let echo = StdUdp::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(echo_address) = echo.local_addr().unwrap() else {
            unreachable!()
        };
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 2048];
            while let Ok((length, from)) = echo.recv_from(&mut buffer) {
                let _ = echo.send_to(&buffer[..length], from);
            }
        });
        let mut control = connect(proxy.proxy);
        control.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_exact(&mut control, 2), [5, 0]);
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let reply = read_exact(&mut control, 10);
        assert_eq!(reply[..2], [5, 0]);
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let game = StdUdp::bind("127.0.0.1:0").unwrap();
        game.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        game.send_to(&wire::udp_datagram(echo_address, b"state"), relay)
            .unwrap();
        let mut buffer = [0_u8; 2048];
        let (length, _) = game.recv_from(&mut buffer).unwrap();
        assert_eq!(
            wire::parse_udp_datagram(&buffer[..length]),
            Some((Target::Ip(echo_address), &b"state"[..]))
        );
    }

    #[test]
    fn secrets_compare_by_content_and_length() {
        assert!(same_secret("hunter2", "hunter2"));
        assert!(!same_secret("hunter2", "hunter3"));
        assert!(!same_secret("hunter2", "hunter22"));
    }
}
