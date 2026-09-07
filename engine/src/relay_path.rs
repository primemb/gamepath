use crate::socks5::{Socks5NodeConfig, Socks5UdpPath};
use crate::userspace_wireguard::{UserSpaceWireGuardPath, ipv4_udp_packet, ipv4_udp_payload};
use rand::Rng;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

pub const KIND_WIREGUARD: &str = "wireguard";
pub const KIND_SOCKS5: &str = "socks5";

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
