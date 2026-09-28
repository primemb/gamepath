//! Opens the proxy's flows as ordinary Windows sockets pinned to one adapter.
//!
//! Native L2TP/IPsec is Windows' own VPN connection: the engine carries none of
//! its packets, so there is no session to put a user-space stack in front of.
//! What there is instead is an adapter with an address, and a socket bound to
//! that address and pinned to that interface with `IP_UNICAST_IF` leaves
//! through the VPN whatever the routing table says. That keeps a console's
//! traffic in the tunnel in split mode too, where Windows would otherwise send
//! it out of the physical adapter.

use super::egress::{EGRESS_TOKEN_BASE, Egress, FlowId, TcpState};
use gamepath_engine::transport::bind_to_interface;
use mio::net::{TcpStream, UdpSocket};
use mio::{Interest, Registry, Token};
use socket2::{Domain, Socket, Type};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4};
use std::time::Duration;

struct TcpFlow {
    stream: TcpStream,
    connected: bool,
    failed: bool,
    remote_closed: bool,
    writable: bool,
}

pub(crate) struct InterfaceEgress {
    registry: Registry,
    address: Ipv4Addr,
    interface_index: u32,
    tcp: HashMap<FlowId, TcpFlow>,
    udp: HashMap<FlowId, UdpSocket>,
    next_flow: FlowId,
}

impl InterfaceEgress {
    pub(crate) fn new(registry: Registry, address: Ipv4Addr, interface_index: u32) -> Self {
        Self {
            registry,
            address,
            interface_index,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            next_flow: 0,
        }
    }

    fn pinned(&self, kind: Type) -> Result<Socket, String> {
        let socket = Socket::new(Domain::IPV4, kind, None)
            .map_err(|error| format!("could not open a socket: {error}"))?;
        bind_to_interface(&socket, IpAddr::V4(self.address), self.interface_index)
            .map_err(|error| format!("could not pin a socket to the VPN adapter: {error}"))?;
        socket
            .bind(&SocketAddr::from((self.address, 0)).into())
            .map_err(|error| format!("could not bind to the VPN adapter: {error}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        Ok(socket)
    }

    fn next(&mut self) -> FlowId {
        self.next_flow += 1;
        self.next_flow
    }

    fn token(flow: FlowId) -> Token {
        Token(EGRESS_TOKEN_BASE + flow)
    }
}

impl Egress for InterfaceEgress {
    fn tcp_connect(&mut self, remote: SocketAddrV4) -> Result<FlowId, String> {
        let socket = self.pinned(Type::STREAM)?;
        let _ = socket.set_tcp_nodelay(true);
        match socket.connect(&SocketAddr::V4(remote).into()) {
            Ok(()) => {}
            Err(error)
                if error.kind() == ErrorKind::WouldBlock || error.raw_os_error() == Some(10036) => {
            }
            Err(error) => return Err(format!("could not connect to {remote}: {error}")),
        }
        let mut stream = TcpStream::from_std(socket.into());
        let flow = self.next();
        self.registry
            .register(
                &mut stream,
                Self::token(flow),
                Interest::READABLE | Interest::WRITABLE,
            )
            .map_err(|error| error.to_string())?;
        self.tcp.insert(
            flow,
            TcpFlow {
                stream,
                connected: false,
                failed: false,
                remote_closed: false,
                writable: false,
            },
        );
        Ok(flow)
    }

    fn tcp_state(&mut self, flow: FlowId) -> TcpState {
        let Some(entry) = self.tcp.get_mut(&flow) else {
            return TcpState::Closed;
        };
        if !entry.connected && !entry.failed && entry.writable {
            match entry.stream.take_error() {
                Ok(None) if entry.stream.peer_addr().is_ok() => entry.connected = true,
                _ => entry.failed = true,
            }
        }
        match (entry.connected, entry.failed, entry.remote_closed) {
            (false, true, _) => TcpState::Refused,
            (true, true, _) => TcpState::Closed,
            (false, false, _) => TcpState::Connecting,
            (true, false, true) => TcpState::RemoteClosed,
            (true, false, false) => TcpState::Open,
        }
    }

    fn tcp_send(&mut self, flow: FlowId, data: &[u8]) -> usize {
        let Some(entry) = self.tcp.get_mut(&flow) else {
            return 0;
        };
        if !entry.connected || entry.failed {
            return 0;
        }
        match entry.stream.write(data) {
            Ok(written) => written,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                entry.writable = false;
                0
            }
            Err(_) => {
                entry.failed = true;
                0
            }
        }
    }

    fn tcp_recv(&mut self, flow: FlowId, buffer: &mut [u8]) -> usize {
        let Some(entry) = self.tcp.get_mut(&flow) else {
            return 0;
        };
        if !entry.connected || entry.remote_closed {
            return 0;
        }
        match entry.stream.read(buffer) {
            Ok(0) => {
                entry.remote_closed = true;
                0
            }
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::WouldBlock => 0,
            Err(_) => {
                entry.failed = true;
                0
            }
        }
    }

    // The kernel owns anything already written.
    fn tcp_send_idle(&mut self, _flow: FlowId) -> bool {
        true
    }

    fn tcp_shutdown(&mut self, flow: FlowId) {
        if let Some(entry) = self.tcp.get(&flow) {
            let _ = entry.stream.shutdown(Shutdown::Write);
        }
    }

    fn tcp_release(&mut self, flow: FlowId) {
        if let Some(mut entry) = self.tcp.remove(&flow) {
            let _ = self.registry.deregister(&mut entry.stream);
        }
    }

    fn udp_open(&mut self) -> Result<FlowId, String> {
        let socket = self.pinned(Type::DGRAM)?;
        let mut socket = UdpSocket::from_std(socket.into());
        let flow = self.next();
        self.registry
            .register(&mut socket, Self::token(flow), Interest::READABLE)
            .map_err(|error| error.to_string())?;
        self.udp.insert(flow, socket);
        Ok(flow)
    }

    fn udp_send(&mut self, flow: FlowId, to: SocketAddrV4, payload: &[u8]) -> bool {
        self.udp
            .get(&flow)
            .is_some_and(|socket| socket.send_to(payload, SocketAddr::V4(to)).is_ok())
    }

    fn udp_recv(&mut self, flow: FlowId) -> Option<(SocketAddrV4, Vec<u8>)> {
        let socket = self.udp.get(&flow)?;
        let mut buffer = vec![0; 65_536];
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((length, SocketAddr::V4(from))) => {
                    buffer.truncate(length);
                    return Some((from, buffer));
                }
                Ok((_, SocketAddr::V6(_))) => continue,
                // An earlier datagram's ICMP error, reported on this read. The
                // socket is fine and the next datagram may already be waiting.
                Err(error) if error.kind() == ErrorKind::ConnectionReset => continue,
                Err(_) => return None,
            }
        }
    }

    fn udp_release(&mut self, flow: FlowId) {
        if let Some(mut socket) = self.udp.remove(&flow) {
            let _ = self.registry.deregister(&mut socket);
        }
    }

    fn on_event(&mut self, token: Token, _readable: bool, writable: bool) {
        let flow = token.0 - EGRESS_TOKEN_BASE;
        if let Some(entry) = self.tcp.get_mut(&flow) {
            entry.writable |= writable;
        }
    }

    fn drive(&mut self) -> Option<Duration> {
        None
    }

    fn resolvers(&self) -> Vec<Ipv4Addr> {
        gamepath_engine::dns::FALLBACK_RESOLVERS.to_vec()
    }

    fn kind(&self) -> &'static str {
        "interface"
    }
}
