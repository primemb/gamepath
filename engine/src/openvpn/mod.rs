//! A user-space OpenVPN client.
//!
//! This exists so that an OpenVPN node behaves like a WireGuard one: several
//! can run at once inside the engine, each with its own socket, with no driver
//! to install, no adapter to create and no child process to supervise. The
//! reference implementation cannot be used that way -- it owns an operating
//! system adapter and takes the routing table with it -- which is why the
//! protocol is spoken here directly.
//!
//! The surface deliberately mirrors [`crate::userspace_wireguard`]: hand it
//! inner IPv4 packets, get inner IPv4 packets back. Everything above it --
//! scheduling, the split tunnel, direct sessions, telemetry -- then treats the
//! two kinds of node identically.

pub mod config;
mod control;
mod crypto;
mod link;
mod session;
mod verify;

pub use config::{OpenVpnConfig, Protocol};
pub use session::Credentials;

use sha2::{Digest as _, Sha256};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// One OpenVPN tunnel.
pub struct UserSpaceOpenVpnPath {
    session: session::Session,
    address: Ipv4Addr,
    endpoint: SocketAddr,
    identity_fingerprint: [u8; 32],
}

impl UserSpaceOpenVpnPath {
    /// Parses a configuration, dials the server and completes the handshake.
    ///
    /// Unlike WireGuard, which can defer its handshake until the first packet,
    /// OpenVPN has to finish a TLS exchange and be told its own address before
    /// anything can be sent. So this connects, and reports why if it cannot.
    pub fn from_config(source: &str, credentials: Credentials) -> Result<Self, String> {
        let config = OpenVpnConfig::parse(source)?;
        if config.wants_credentials && credentials.username.is_none() {
            return Err(
                "this OpenVPN configuration needs a username and password, which have not been                  entered for this node"
                    .into(),
            );
        }
        let identity_fingerprint = fingerprint(source, &credentials);
        let mut attempts = Vec::new();
        let mut failures = Vec::new();
        for remote in &config.remotes {
            attempts.push(remote.clone());
            // A provider that hands out a udp configuration almost always
            // listens for tcp on the same port, and on a connection that drops
            // large udp packets the tcp attempt is the one that works. Trying
            // it saves the user from having to understand why.
            if remote.protocol == Protocol::Udp {
                attempts.push(config::Remote {
                    protocol: Protocol::Tcp,
                    ..remote.clone()
                });
            }
        }
        for remote in attempts {
            let address = match config::resolve(&remote) {
                Ok(address) => address,
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            match session::Session::connect(config.clone(), &remote, address, credentials.clone()) {
                Ok(session) => {
                    let pushed = session.pushed().clone();
                    return Ok(Self {
                        address: pushed.address,
                        endpoint: address,
                        identity_fingerprint,
                        session,
                    });
                }
                Err(error) => failures.push(format!(
                    "{} over {}: {error}",
                    remote.endpoint(),
                    remote.protocol.as_str()
                )),
            }
        }
        Err(failures
            .first()
            .cloned()
            .unwrap_or_else(|| "this OpenVPN configuration has nothing to connect to".into()))
    }

    /// The tunnel's own address, which inner packets must come from.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// The far end of the tunnel, when the server pushed one.
    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.session.pushed().gateway
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Which transport the session settled on, which is worth showing because
    /// it may not be the one the configuration named.
    pub fn protocol(&self) -> Protocol {
        self.session.protocol()
    }

    /// The data-channel cipher the server chose.
    pub fn cipher(&self) -> &'static str {
        self.session.pushed().cipher.as_str()
    }

    /// The identifier the server assigned this client, when it assigned one.
    ///
    /// Its presence decides which of the two data-packet headers is used, so it
    /// is worth being able to see.
    pub fn peer_id(&self) -> Option<u32> {
        self.session.pushed().peer_id
    }

    pub fn identity_fingerprint(&self) -> [u8; 32] {
        self.identity_fingerprint
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint && self.identity_fingerprint == other.identity_fingerprint
    }

    /// How long the session took to come up, which is the user-to-node hop.
    pub fn handshake_latency_ms(&self) -> Option<f64> {
        self.session.handshake_latency_ms()
    }

    pub fn send_inner(&mut self, packet: &[u8]) -> Result<(), String> {
        self.session.send_inner(packet)
    }

    /// Protects an inner health probe from TCP queue shedding.
    pub fn send_probe(&mut self, packet: &[u8]) -> Result<(), String> {
        self.session
            .send_inner_with_urgency(packet, link::Urgency::Reliable)
    }

    pub fn receive_inner(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.session.receive_inner(timeout)
    }
}

/// Identifies a node so that two copies of the same one are not run at once.
///
/// Two OpenVPN sessions built from the same configuration and the same
/// credentials land on the same account at the provider, where the second
/// frequently displaces the first. The configuration text and the username are
/// enough to recognise that, and hashing them keeps the secrets out of
/// anything that logs an identity.
fn fingerprint(source: &str, credentials: &Credentials) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(source.trim().as_bytes());
    hasher.update([0]);
    hasher.update(
        credentials
            .username
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "client\ndev tun\nremote vpn.example 1194 udp\nauth-user-pass\n\
        <ca>\n-----BEGIN CERTIFICATE-----\n\
        MIIBIjCByaADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3QgQ0Ew\n\
        -----END CERTIFICATE-----\n</ca>\n";

    #[test]
    fn the_same_configuration_and_user_is_the_same_node() {
        let credentials = Credentials {
            username: Some("someone".into()),
            password: Some("secret".into()),
        };
        assert_eq!(
            fingerprint(CONFIG, &credentials),
            fingerprint(&format!("{CONFIG}\n"), &credentials),
            "trailing whitespace does not make it a different node"
        );
    }

    #[test]
    fn a_different_user_on_one_configuration_is_a_different_node() {
        let first = Credentials {
            username: Some("first".into()),
            password: Some("secret".into()),
        };
        let second = Credentials {
            username: Some("second".into()),
            password: Some("secret".into()),
        };
        assert_ne!(fingerprint(CONFIG, &first), fingerprint(CONFIG, &second));
    }

    /// Both types carry a secret and are printed by anything that reports a
    /// node, so their `Debug` is written by hand rather than derived.
    #[test]
    fn a_secret_does_not_appear_in_debug_output() {
        let credentials = Credentials {
            username: Some("someone".into()),
            password: Some("hunter2".into()),
        };
        let printed = format!("{credentials:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(printed.contains("someone"), "{printed}");

        let config = OpenVpnConfig::parse(CONFIG).unwrap();
        let printed = format!("{config:?}");
        assert!(printed.contains("vpn.example"), "{printed}");
        assert!(!printed.contains("BEGIN"), "{printed}");
    }

    #[test]
    fn a_configuration_needing_credentials_says_so_before_dialling() {
        let Err(error) = UserSpaceOpenVpnPath::from_config(CONFIG, Credentials::default()) else {
            panic!("a configuration with no credentials must not connect");
        };
        assert!(error.contains("username and password"), "{error}");
    }
}
