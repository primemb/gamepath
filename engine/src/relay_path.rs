use crate::socks5::{Socks5NodeConfig, Socks5UdpPath};
use crate::userspace_wireguard::{UserSpaceWireGuardPath, ipv4_udp_packet, ipv4_udp_payload};
use rand::Rng;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

pub const KIND_WIREGUARD: &str = "wireguard";
pub const KIND_SOCKS5: &str = "socks5";

/// How a session reaches the Internet.
///
/// This decides what a node is asked to do, so the engine and the privileged
/// service both read it from the same definition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionMode {
    /// Every enabled node carries sealed frames to a relay the user runs, which
    /// is what lets the scheduler send one packet down several paths at once.
    #[default]
    Relay,
    /// One WireGuard node routes the captured traffic itself. Nothing to run on
    /// a server, and in exchange there is only ever one path.
    Direct,
}

impl SessionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Direct => "direct",
        }
    }
}

/// One node the user added, in the order that numbers the session's routes.
///
/// Both the engine and the privileged service read this shape, so a node is
/// described the same way wherever it is validated or opened.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum NodeSpec {
    #[serde(rename = "wireguard")]
    WireGuard {
        config: String,
        #[serde(default)]
        label: Option<String>,
    },
    #[serde(rename = "socks5")]
    Socks5 {
        host: String,
        port: u16,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        label: Option<String>,
    },
}

impl NodeSpec {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::WireGuard { .. } => KIND_WIREGUARD,
            Self::Socks5 { .. } => KIND_SOCKS5,
        }
    }

    /// Opens the node's transport. A SOCKS5 node dials its proxy here; a
    /// WireGuard node only prepares its socket and defers the handshake.
    pub fn open(&self, relay: SocketAddrV4) -> Result<Box<dyn RelayPath>, String> {
        match self {
            Self::WireGuard { config, .. } => {
                Ok(Box::new(WireGuardRelayPath::from_config(config, relay)?))
            }
            Self::Socks5 { .. } => Ok(Box::new(Socks5RelayPath::open(
                &self.socks5_config().ok_or("node is not a SOCKS5 node")?,
                relay,
            )?)),
        }
    }

    /// Checks the node's shape without touching the network.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::WireGuard { config, .. } => {
                if config.trim().is_empty() {
                    Err("WireGuard node is missing its configuration".into())
                } else {
                    Ok(())
                }
            }
            Self::Socks5 { .. } => self
                .socks5_config()
                .ok_or("node is not a SOCKS5 node")?
                .validate(),
        }
    }

    pub fn socks5_config(&self) -> Option<Socks5NodeConfig> {
        match self {
            Self::WireGuard { .. } => None,
            Self::Socks5 {
                host,
                port,
                username,
                password,
                ..
            } => Some(Socks5NodeConfig {
                host: host.clone(),
                port: *port,
                username: username.clone(),
                password: password.clone(),
            }),
        }
    }

    /// True for a proxy running on this machine. Such a proxy is reached over
    /// loopback and never enters the tunnel, but whatever it forwards to does.
    pub fn is_loopback_proxy(&self) -> bool {
        match self {
            Self::WireGuard { .. } => false,
            Self::Socks5 { host, .. } => {
                let host = host.trim();
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            }
        }
    }

    pub fn label(&self) -> Option<String> {
        let label = match self {
            Self::WireGuard { label, .. } | Self::Socks5 { label, .. } => label.as_deref()?,
        };
        Some(label.trim())
            .filter(|label| !label.is_empty())
            .map(str::to_owned)
    }

    pub fn default_label(&self, route: usize) -> String {
        match self {
            Self::WireGuard { .. } => format!("WireGuard route {route}"),
            Self::Socks5 { .. } => format!("SOCKS5 route {route}"),
        }
    }

    /// Opens the node as the only hop of a direct session.
    ///
    /// A direct session has no relay to frame traffic for, so the node itself
    /// has to route plain IPv4 packets onward. WireGuard servers do exactly
    /// that; a SOCKS5 proxy speaks in connections and datagrams instead and
    /// has nothing to route with, which is why it is turned away here rather
    /// than failing later with a confusing transport error.
    pub fn open_direct(&self) -> Result<DirectWireGuardPath, String> {
        match self {
            Self::WireGuard { config, .. } => DirectWireGuardPath::from_config(config),
            Self::Socks5 { .. } => Err(
                "a SOCKS5 proxy cannot carry a direct session on its own. Use a WireGuard node \
                 for direct mode, or set up a relay to reach this proxy through."
                    .into(),
            ),
        }
    }

    /// Whether this node can be the single hop of a direct session.
    pub fn supports_direct(&self) -> bool {
        matches!(self, Self::WireGuard { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::WireGuard { .. } => "WireGuard configuration".to_owned(),
            Self::Socks5 { host, port, .. } => format!("SOCKS5 proxy {host}:{port}"),
        }
    }
}

/// Two paths that share an identity cannot run at the same time, or gain
/// nothing from running at the same time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathIdentity {
    /// The same WireGuard endpoint reached with the same client key: the two
    /// handshakes would replace one another at the provider.
    WireGuard {
        endpoint: SocketAddr,
        fingerprint: [u8; 32],
    },
    /// A second association on one proxy works, but carries no path diversity.
    Socks5 { proxy: SocketAddr },
}

/// One outer transport carrying sealed GamePath frames to the relay.
///
/// Frames are already authenticated and encrypted by the session crypto before
/// they reach a path, so a path is only responsible for moving opaque bytes and
/// for reporting whether it can still do so.
pub trait RelayPath: Send {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String>;

    /// Collects the frames that have arrived from the relay, waiting at most
    /// `timeout` for the first one.
    fn receive_frames(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String>;

    fn kind(&self) -> &'static str;

    /// The outer endpoint shown in telemetry.
    fn endpoint(&self) -> String;

    /// Latency of the transport's own setup: the user-to-node hop.
    fn setup_latency_ms(&self) -> Option<f64>;

    fn identity(&self) -> PathIdentity;

    /// The outer address that has to keep reaching the Internet directly once
    /// the tunnel owns the default route.
    fn bypass_ipv4(&self) -> Option<Ipv4Addr>;

    /// Transport-specific context to add when a path stops answering. Most
    /// transports have nothing useful to say beyond the timeout itself.
    fn health_note(&mut self) -> Option<String> {
        None
    }
}

/// Carries relay frames inside an inner IPv4/UDP packet through a user-space
/// WireGuard tunnel.
pub struct WireGuardRelayPath {
    path: UserSpaceWireGuardPath,
    relay: SocketAddrV4,
    source_port: u16,
}

impl WireGuardRelayPath {
    pub fn from_config(source: &str, relay: SocketAddrV4) -> Result<Self, String> {
        Ok(Self {
            path: UserSpaceWireGuardPath::from_config(source)?,
            relay,
            source_port: rand::rng().random_range(49_152..=65_535),
        })
    }
}

impl RelayPath for WireGuardRelayPath {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        let inner = ipv4_udp_packet(
            self.path.address(),
            *self.relay.ip(),
            self.source_port,
            self.relay.port(),
            frame,
        )?;
        self.path.send_inner(&inner)
    }

    fn receive_frames(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        let packets = self.path.receive_inner(timeout)?;
        let mut frames = Vec::new();
        for packet in packets {
            let Some((source_ip, destination_ip, source_port, destination_port, payload)) =
                ipv4_udp_payload(&packet)
            else {
                continue;
            };
            if source_ip != *self.relay.ip()
                || destination_ip != self.path.address()
                || source_port != self.relay.port()
                || destination_port != self.source_port
            {
                continue;
            }
            frames.push(payload.to_vec());
        }
        Ok(frames)
    }

    fn kind(&self) -> &'static str {
        KIND_WIREGUARD
    }

    fn endpoint(&self) -> String {
        self.path.endpoint().to_string()
    }

    fn setup_latency_ms(&self) -> Option<f64> {
        self.path.handshake_latency_ms()
    }

    fn identity(&self) -> PathIdentity {
        PathIdentity::WireGuard {
            endpoint: self.path.endpoint(),
            fingerprint: self.path.identity_fingerprint(),
        }
    }

    fn bypass_ipv4(&self) -> Option<Ipv4Addr> {
        match self.path.endpoint().ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        }
    }
}

/// The single hop of a direct session: a WireGuard tunnel that carries the
/// captured packets themselves rather than frames addressed to a relay.
///
/// The node's own server is the router here, so nothing is wrapped, sealed or
/// scheduled. Packets go in as they were captured and come back the same way.
pub struct DirectWireGuardPath {
    path: UserSpaceWireGuardPath,
}

impl DirectWireGuardPath {
    pub fn from_config(source: &str) -> Result<Self, String> {
        Ok(Self {
            path: UserSpaceWireGuardPath::from_config(source)?,
        })
    }

    /// The tunnel's own address, which captured packets are rewritten to use
    /// and which replies come back addressed to.
    pub fn address(&self) -> Ipv4Addr {
        self.path.address()
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.path.endpoint()
    }

    /// The node's public address, which must keep reaching the Internet
    /// directly once the tunnel owns the default route.
    pub fn bypass_ipv4(&self) -> Option<Ipv4Addr> {
        match self.path.endpoint().ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }
    }

    /// Round trip of the WireGuard handshake, and the proof that it completed:
    /// a direct session has no relay to ping, so the handshake is what says the
    /// node is answering.
    pub fn handshake_latency_ms(&self) -> Option<f64> {
        self.path.handshake_latency_ms()
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        self.path.send_inner(packet)
    }

    /// Collects the packets the node routed back to us, waiting at most
    /// `timeout` for the first one.
    pub fn receive_packets(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        let address = self.path.address();
        let mut packets = self.path.receive_inner(timeout)?;
        // A peer configured with a wide AllowedIPs may send traffic for other
        // addresses in its subnet; only what is addressed to this tunnel can be
        // handed back to the capture layer.
        packets.retain(|packet| ipv4_destination(packet) == Some(address));
        Ok(packets)
    }
}

/// Carries relay frames as plain datagrams through a SOCKS5 UDP association.
pub struct Socks5RelayPath {
    path: Socks5UdpPath,
}

impl Socks5RelayPath {
    pub fn open(config: &Socks5NodeConfig, relay: SocketAddrV4) -> Result<Self, String> {
        Ok(Self {
            path: Socks5UdpPath::open(config, relay)?,
        })
    }
}

impl RelayPath for Socks5RelayPath {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.path.send_frame(frame)
    }

    fn receive_frames(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.path.receive_frames(timeout)
    }

    fn kind(&self) -> &'static str {
        KIND_SOCKS5
    }

    fn endpoint(&self) -> String {
        self.path.proxy().to_string()
    }

    fn setup_latency_ms(&self) -> Option<f64> {
        Some(self.path.setup_latency_ms())
    }

    fn identity(&self) -> PathIdentity {
        PathIdentity::Socks5 {
            proxy: self.path.proxy(),
        }
    }

    fn bypass_ipv4(&self) -> Option<Ipv4Addr> {
        match self.path.proxy().ip() {
            // A loopback proxy is never reached through the default route, so
            // it needs no bypass route of its own.
            std::net::IpAddr::V4(ip) if !ip.is_loopback() => Some(ip),
            _ => None,
        }
    }

    fn health_note(&mut self) -> Option<String> {
        // Stated without blame: proxies that tear the association down and
        // proxies that keep relaying both close this stream, so the reader is
        // told what happened rather than what it means.
        self.path.control_closed().then(|| {
            "the proxy closed its SOCKS5 control connection, which some proxies do while \
             still relaying"
                .to_owned()
        })
    }
}

fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    const RELAY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 51_821);

    fn wireguard_config(private: &str, endpoint: &str) -> String {
        let public = STANDARD.encode([5_u8; 32]);
        format!(
            "[Interface]\nPrivateKey = {private}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {public}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0"
        )
    }

    #[test]
    fn identical_wireguard_identities_collide_and_distinct_ones_do_not() {
        let private = STANDARD.encode([3_u8; 32]);
        let other = STANDARD.encode([4_u8; 32]);
        let first =
            WireGuardRelayPath::from_config(&wireguard_config(&private, "127.0.0.1:51820"), RELAY)
                .unwrap();
        let duplicate =
            WireGuardRelayPath::from_config(&wireguard_config(&private, "127.0.0.1:51820"), RELAY)
                .unwrap();
        let other_endpoint =
            WireGuardRelayPath::from_config(&wireguard_config(&private, "127.0.0.1:51821"), RELAY)
                .unwrap();
        let other_identity =
            WireGuardRelayPath::from_config(&wireguard_config(&other, "127.0.0.1:51820"), RELAY)
                .unwrap();
        assert_eq!(first.identity(), duplicate.identity());
        assert_ne!(first.identity(), other_endpoint.identity());
        assert_ne!(first.identity(), other_identity.identity());
        assert_eq!(first.kind(), KIND_WIREGUARD);
        assert_eq!(first.bypass_ipv4(), Some(Ipv4Addr::LOCALHOST));
    }

    fn socks5_node(host: &str) -> NodeSpec {
        NodeSpec::Socks5 {
            host: host.to_owned(),
            port: 2080,
            username: None,
            password: None,
            label: None,
        }
    }

    #[test]
    fn proxies_on_this_machine_are_recognised() {
        for host in ["127.0.0.1", "127.5.0.9", "localhost", "LOCALHOST", " ::1 "] {
            assert!(socks5_node(host).is_loopback_proxy(), "{host}");
        }
        for host in ["203.0.113.8", "proxy.example", "10.0.0.4"] {
            assert!(!socks5_node(host).is_loopback_proxy(), "{host}");
        }
        assert!(
            !NodeSpec::WireGuard {
                config: "[Interface]".into(),
                label: None,
            }
            .is_loopback_proxy()
        );
    }

    #[test]
    fn node_shapes_are_checked_before_any_network_use() {
        assert!(socks5_node("127.0.0.1").validate().is_ok());
        assert_eq!(socks5_node("127.0.0.1").kind(), KIND_SOCKS5);
        assert!(socks5_node("  ").validate().is_err());
        assert!(
            NodeSpec::WireGuard {
                config: "   ".into(),
                label: None,
            }
            .validate()
            .is_err()
        );
        // A username without a password would silently fall back to no auth.
        assert!(
            NodeSpec::Socks5 {
                host: "127.0.0.1".into(),
                port: 2080,
                username: Some("player".into()),
                password: None,
                label: None,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn only_wireguard_nodes_can_carry_a_direct_session() {
        let private = STANDARD.encode([3_u8; 32]);
        let wireguard = NodeSpec::WireGuard {
            config: wireguard_config(&private, "127.0.0.1:51820"),
            label: None,
        };
        assert!(wireguard.supports_direct());
        assert_eq!(
            wireguard.open_direct().unwrap().address(),
            Ipv4Addr::new(10, 0, 0, 2)
        );

        let proxy = socks5_node("203.0.113.8");
        assert!(!proxy.supports_direct());
        // The refusal has to name the way forward, since the node itself is
        // perfectly usable in the other mode.
        let error = proxy.open_direct().err().unwrap();
        assert!(error.contains("WireGuard node for direct mode"), "{error}");
        assert!(error.contains("relay"), "{error}");
    }

    #[test]
    fn replies_for_other_addresses_in_the_peer_subnet_are_dropped() {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        assert_eq!(ipv4_destination(&packet), Some(Ipv4Addr::new(10, 0, 0, 2)));
        // Too short to hold a header, and not IPv4 at all.
        assert_eq!(ipv4_destination(&packet[..19]), None);
        packet[0] = 0x60;
        assert_eq!(ipv4_destination(&packet), None);
    }

    /// A WireGuard peer that answers handshakes and echoes tunnel packets back
    /// to their sender, so a direct path can be exercised end to end.
    fn spawn_wireguard_peer(server_secret: [u8; 32], client_public: [u8; 32]) -> u16 {
        use boringtun::noise::{Tunn, TunnResult};
        use boringtun::x25519::{PublicKey, StaticSecret};
        use std::net::UdpSocket;

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut tunnel = Tunn::new(
                StaticSecret::from(server_secret),
                PublicKey::from(client_public),
                None,
                None,
                1,
                None,
            );
            let mut network = [0_u8; 65_535];
            let mut scratch = vec![0_u8; 65_535];
            socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while std::time::Instant::now() < deadline {
                let Ok((length, from)) = socket.recv_from(&mut network) else {
                    continue;
                };
                let mut input: &[u8] = &network[..length];
                loop {
                    match tunnel.decapsulate(None, input, &mut scratch) {
                        TunnResult::WriteToNetwork(packet) => {
                            let _ = socket.send_to(packet, from);
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            // Turn the packet around: swap source and
                            // destination so the client sees its own probe
                            // answered from the address it aimed at.
                            let mut echo = packet.to_vec();
                            let (source, destination) =
                                (echo[12..16].to_vec(), echo[16..20].to_vec());
                            echo[12..16].copy_from_slice(&destination);
                            echo[16..20].copy_from_slice(&source);
                            let mut out = vec![0_u8; echo.len() + 128];
                            if let TunnResult::WriteToNetwork(sealed) =
                                tunnel.encapsulate(&echo, &mut out)
                            {
                                let _ = socket.send_to(sealed, from);
                            }
                            break;
                        }
                        _ => break,
                    }
                    // Drain whatever the last call left queued.
                    input = &[];
                }
            }
        });
        port
    }

    #[test]
    fn a_direct_path_hands_a_captured_packet_to_its_node_and_gets_the_reply() {
        use boringtun::x25519::{PublicKey, StaticSecret};

        let client_secret = [7_u8; 32];
        let server_secret = [9_u8; 32];
        let client_public = *PublicKey::from(&StaticSecret::from(client_secret)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_secret)).as_bytes();
        let port = spawn_wireguard_peer(server_secret, client_public);

        let config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = {}\nEndpoint = 127.0.0.1:{port}\nAllowedIPs = 0.0.0.0/0",
            STANDARD.encode(client_secret),
            STANDARD.encode(server_public),
        );
        let node = NodeSpec::WireGuard {
            config,
            label: None,
        };
        let mut path = node.open_direct().unwrap();
        assert_eq!(path.address(), Ipv4Addr::new(10, 66, 66, 2));
        assert_eq!(path.handshake_latency_ms(), None);

        // A plain IPv4 packet, exactly as the capture layer would hand it over.
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(10, 66, 66, 2).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(1, 1, 1, 1).octets());

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut echoed = None;
        while std::time::Instant::now() < deadline && echoed.is_none() {
            path.send_packet(&packet).unwrap();
            for reply in path.receive_packets(Duration::from_millis(200)).unwrap() {
                echoed = Some(reply);
            }
        }
        let echoed = echoed.expect("the node never returned the packet");
        // Only traffic addressed to this tunnel comes back out of the path.
        assert_eq!(
            ipv4_destination(&echoed),
            Some(Ipv4Addr::new(10, 66, 66, 2))
        );
        assert_eq!(&echoed[16..20], &[10, 66, 66, 2]);
        // The handshake is what a direct session judges the node's health by.
        assert!(
            path.handshake_latency_ms()
                .is_some_and(|latency| latency >= 0.0)
        );
        assert_eq!(path.bypass_ipv4(), Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn socks5_and_wireguard_identities_never_collide() {
        let private = STANDARD.encode([3_u8; 32]);
        let wireguard =
            WireGuardRelayPath::from_config(&wireguard_config(&private, "127.0.0.1:51820"), RELAY)
                .unwrap();
        let proxy = PathIdentity::Socks5 {
            proxy: "127.0.0.1:51820".parse().unwrap(),
        };
        assert_ne!(wireguard.identity(), proxy);
    }
}
