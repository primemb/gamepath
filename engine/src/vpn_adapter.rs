//! Another VPN app's network adapter as a GamePath node.
//!
//! Apps such as Windscribe connect with their own transport, anti-censorship
//! included, and leave a Windows adapter behind. A socket bound to that
//! adapter's address and pinned to it with `IP_UNICAST_IF` leaves through that
//! VPN whatever the routing table says, UDP as well as TCP. Their proxy
//! gateways are no substitute: Windscribe's refuses `UDP ASSOCIATE` (reply 7)
//! while its adapter carried STUN in 84 ms.
//!
//! The adapter is found by name each time, never kept by index: an app that
//! reconnects is handed a new address, and one that switches protocol brings
//! up another adapter (`WindscribeOpenVPN`, `WindscribeWireguard`), so a node
//! named `Windscribe` follows whichever is up.

use crate::relay_path::{PathIdentity, RelayPath};
#[cfg(windows)]
use crate::transport::bind_to_interface;
use crate::transport::socket_read_timeout;
#[cfg(windows)]
use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// The adapter a node named, as it is right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    pub name: String,
    pub address: Ipv4Addr,
    pub interface_index: u32,
}

/// How well an adapter's name and description match what the user typed:
/// the exact name, then a name it starts, then a description containing it.
fn rank(name: &str, description: &str, wanted: &str) -> Option<u8> {
    let wanted = wanted.trim().to_lowercase();
    if wanted.is_empty() || is_own_adapter(name) {
        return None;
    }
    let name = name.to_lowercase();
    if name == wanted {
        Some(0)
    } else if name.starts_with(&wanted) {
        Some(1)
    } else if description.to_lowercase().contains(&wanted) {
        Some(2)
    } else {
        None
    }
}

/// GamePath's own Wintun adapters are its tunnels, never a way out of them.
fn is_own_adapter(name: &str) -> bool {
    name.to_lowercase().starts_with("gamepath")
}

/// The connected adapter `wanted` names.
#[cfg(windows)]
pub fn find(wanted: &str) -> Result<Adapter, String> {
    crate::netconfig::ipv4_interfaces()
        .into_iter()
        .filter_map(|interface| {
            rank(&interface.name, &interface.description, wanted).map(|rank| (rank, interface))
        })
        .min_by_key(|(rank, interface)| (*rank, interface.hardware))
        .map(|(_, interface)| Adapter {
            name: interface.name,
            address: interface.address,
            interface_index: interface.interface_index,
        })
        .ok_or_else(|| {
            format!(
                "no connected network adapter is named \"{}\"; connect that VPN app first",
                wanted.trim()
            )
        })
}

#[cfg(not(windows))]
pub fn find(_wanted: &str) -> Result<Adapter, String> {
    Err("network adapter nodes are only available on Windows".into())
}

/// Connected adapters a node could name, software adapters first.
#[cfg(windows)]
pub fn candidates() -> Vec<crate::netconfig::InterfaceAddress> {
    crate::netconfig::ipv4_interfaces()
        .into_iter()
        .filter(|interface| !is_own_adapter(&interface.name))
        .collect()
}

/// A socket of `kind` bound to the adapter's address and pinned to it, so it
/// leaves through that VPN whatever the routing table says.
#[cfg(windows)]
pub fn pinned_socket(adapter: &Adapter, kind: socket2::Type) -> std::io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, kind, None)?;
    bind_to_interface(
        &socket,
        IpAddr::V4(adapter.address),
        adapter.interface_index,
    )?;
    socket.bind(&std::net::SocketAddr::from((adapter.address, 0)).into())?;
    Ok(socket)
}

#[cfg(not(windows))]
pub fn pinned_socket(_adapter: &Adapter, _kind: socket2::Type) -> std::io::Result<socket2::Socket> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// What a test through an adapter found.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterCheck {
    pub adapter: String,
    pub address: Ipv4Addr,
    /// Opening a TCP connection to the benchmark target through it.
    pub latency_ms: f64,
    /// A STUN round trip, which only real UDP forwarding can answer.
    pub udp_latency_ms: Option<f64>,
    /// The address the far side saw: the other VPN's exit, not this PC's.
    pub public_address: Option<Ipv4Addr>,
}

/// STUN servers asked in turn. Neither is a DNS server, so no proxy or
/// resolver on the way can answer for it.
const STUN_SERVERS: [&str; 2] = ["stun.cloudflare.com:3478", "stun.l.google.com:19302"];
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Proves the adapter carries a connection, and whether it carries UDP.
#[cfg(windows)]
pub fn check(wanted: &str) -> Result<AdapterCheck, String> {
    use std::net::ToSocketAddrs;
    use std::time::Instant;

    let adapter = find(wanted)?;
    let stream = pinned_socket(&adapter, socket2::Type::STREAM)
        .map_err(|error| format!("could not open a socket on {}: {error}", adapter.name))?;
    let started = Instant::now();
    stream
        .connect_timeout(
            &std::net::SocketAddr::from((crate::BENCHMARK_TARGET, 443)).into(),
            CHECK_TIMEOUT,
        )
        .map_err(|error| {
            format!(
                "{} did not carry a test connection ({error}); is that VPN app connected?",
                adapter.name
            )
        })?;
    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
    drop(stream);
    // One address per server keeps a blocked UDP path to a few seconds.
    let stun = STUN_SERVERS
        .iter()
        .filter_map(|server| {
            server
                .to_socket_addrs()
                .ok()?
                .find_map(|address| match address {
                    std::net::SocketAddr::V4(address) => Some(address),
                    std::net::SocketAddr::V6(_) => None,
                })
        })
        .find_map(|server| stun_binding(&adapter, server));
    Ok(AdapterCheck {
        adapter: adapter.name,
        address: adapter.address,
        latency_ms,
        udp_latency_ms: stun.map(|(latency, _)| latency),
        public_address: stun.map(|(_, public)| public),
    })
}

/// One STUN binding request through the adapter: its round trip, and the
/// mapped address the server reports.
#[cfg(windows)]
fn stun_binding(adapter: &Adapter, server: SocketAddrV4) -> Option<(f64, Ipv4Addr)> {
    let socket: UdpSocket = pinned_socket(adapter, socket2::Type::DGRAM).ok()?.into();
    socket
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .ok()?;
    socket.connect(server).ok()?;
    let mut request = [0_u8; 20];
    request[1] = 1;
    request[4..8].copy_from_slice(&STUN_COOKIE.to_be_bytes());
    request[8..].copy_from_slice(&rand::random::<[u8; 12]>());
    let mut reply = [0_u8; 512];
    for _ in 0..2 {
        let started = std::time::Instant::now();
        socket.send(&request).ok()?;
        if let Ok(length) = socket.recv(&mut reply) {
            let latency = started.elapsed().as_secs_f64() * 1000.0;
            return mapped_address(&reply[..length], &request[8..20])
                .map(|public| (latency, public));
        }
    }
    None
}

const STUN_COOKIE: u32 = 0x2112_a442;

/// The XOR-MAPPED-ADDRESS of a binding success answering `transaction`
/// (RFC 8489).
fn mapped_address(reply: &[u8], transaction: &[u8]) -> Option<Ipv4Addr> {
    if reply.len() < 20
        || reply[..2] != [0x01, 0x01]
        || reply[4..8] != STUN_COOKIE.to_be_bytes()
        || &reply[8..20] != transaction
    {
        return None;
    }
    let mut at = 20;
    while at + 4 <= reply.len() {
        let kind = u16::from_be_bytes([reply[at], reply[at + 1]]);
        let length = usize::from(u16::from_be_bytes([reply[at + 2], reply[at + 3]]));
        let value = reply.get(at + 4..at + 4 + length)?;
        if kind == 0x0020 && length >= 8 && value[1] == 0x01 {
            let address =
                u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ STUN_COOKIE;
            return Some(Ipv4Addr::from(address));
        }
        at += 4 + length.div_ceil(4) * 4;
    }
    None
}

/// Carries relay frames over a UDP socket pinned to another VPN's adapter.
///
/// The other VPN wraps each datagram in its own transport, so to the relay
/// this path arrives from that VPN's exit address like any other.
pub struct AdapterRelayPath {
    adapter: Adapter,
    socket: UdpSocket,
    transport_failed: bool,
    receive_buffer: Vec<u8>,
}

impl AdapterRelayPath {
    pub fn open(wanted: &str, relay: SocketAddrV4) -> Result<Self, String> {
        let adapter = find(wanted)?;
        let socket: UdpSocket = pinned_socket(&adapter, socket2::Type::DGRAM)
            .map_err(|error| format!("could not open a socket on {}: {error}", adapter.name))?
            .into();
        socket.connect(relay).map_err(|error| {
            format!(
                "could not reach the relay through {}: {error}",
                adapter.name
            )
        })?;
        Ok(Self {
            adapter,
            socket,
            transport_failed: false,
            receive_buffer: vec![0; 65_535],
        })
    }
}

impl RelayPath for AdapterRelayPath {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.socket.send(frame).map(|_| ()).map_err(|error| {
            if crate::transport::is_interface_gone(&error) {
                self.transport_failed = true;
            }
            format!("{} send failed: {error}", self.adapter.name)
        })
    }

    fn receive_frames(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.socket
            .set_read_timeout(Some(socket_read_timeout(timeout)))
            .map_err(|error| format!("could not configure the adapter socket: {error}"))?;
        match self.socket.recv(&mut self.receive_buffer) {
            Ok(length) => Ok(vec![self.receive_buffer[..length].to_vec()]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(Vec::new())
            }
            // An ICMP error about an earlier datagram; the socket is fine.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(Vec::new()),
            Err(error) => Err(format!("{} receive failed: {error}", self.adapter.name)),
        }
    }

    fn kind(&self) -> &'static str {
        crate::relay_path::KIND_ADAPTER
    }

    fn endpoint(&self) -> String {
        format!("{} ({})", self.adapter.name, self.adapter.address)
    }

    fn setup_latency_ms(&self) -> Option<f64> {
        None
    }

    fn setup_round_trips(&self) -> Option<u8> {
        None
    }

    /// Two nodes on one adapter leave through the same VPN connection, however
    /// each named it.
    fn identity(&self) -> PathIdentity {
        PathIdentity::Adapter {
            name: self.adapter.name.to_lowercase(),
        }
    }

    /// The pinned socket ignores the routing table, so nothing has to be
    /// routed around the tunnel for it.
    fn bypass_ipv4(&self) -> Option<Ipv4Addr> {
        None
    }

    fn transport_failed(&self) -> bool {
        self.transport_failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_matches_exactly_then_by_prefix_then_by_description() {
        let description = "OpenVPN Data Channel Offload";
        assert_eq!(
            rank("WindscribeOpenVPN", description, "windscribeopenvpn"),
            Some(0)
        );
        assert_eq!(
            rank("WindscribeOpenVPN", description, " Windscribe "),
            Some(1)
        );
        assert_eq!(
            rank("Local Area Connection 3", description, "data channel"),
            Some(2)
        );
        assert_eq!(rank("Ethernet", "Intel(R) Ethernet", "windscribe"), None);
        assert_eq!(rank("WindscribeOpenVPN", description, "   "), None);
    }

    #[test]
    fn the_mapped_address_is_read_from_a_matching_binding_success() {
        let transaction = [7_u8; 12];
        let mut reply = vec![0x01, 0x01, 0, 12];
        reply.extend_from_slice(&STUN_COOKIE.to_be_bytes());
        reply.extend_from_slice(&transaction);
        // XOR-MAPPED-ADDRESS for 95.177.87.25:4000.
        let public = u32::from(Ipv4Addr::new(95, 177, 87, 25)) ^ STUN_COOKIE;
        reply.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 0x01]);
        reply.extend_from_slice(&(4000_u16 ^ 0x2112).to_be_bytes());
        reply.extend_from_slice(&public.to_be_bytes());
        assert_eq!(
            mapped_address(&reply, &transaction),
            Some(Ipv4Addr::new(95, 177, 87, 25))
        );
        // Another transaction's answer, or an error response, proves nothing.
        assert_eq!(mapped_address(&reply, &[8; 12]), None);
        reply[1] = 0x11;
        assert_eq!(mapped_address(&reply, &transaction), None);
    }

    #[test]
    fn gamepaths_own_tunnels_are_never_an_exit() {
        assert_eq!(rank("GamePath VPN", "GamePath Tunnel", "gamepath"), None);
        assert_eq!(rank("GamePath", "Wintun Userspace Tunnel", "wintun"), None);
    }

    #[cfg(windows)]
    #[test]
    fn a_missing_adapter_says_what_to_do() {
        let error = find("no-such-adapter-gp").unwrap_err();
        assert!(error.contains("connect that VPN app first"), "{error}");
    }
}
