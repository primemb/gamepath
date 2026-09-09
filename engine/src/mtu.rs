//! Path MTU accounting.
//!
//! A captured packet is not what leaves the machine: every transport wraps it
//! again. Sizing the tunnel by the physical link instead of by the finished
//! wire format is how a 1380-byte packet turns into a 1524-byte datagram on a
//! 1500-byte link, which either fragments or is dropped outright. The numbers
//! here are the worst case for each layer, so the derived MTU is safe rather
//! than optimal.

use crate::protocol::HEADER_LEN;
use crate::relay_path::SessionMode;

/// Physical MTU assumed for the uplink. Ethernet and most consumer links use
/// this; PPPoE and some mobile carriers are lower, which is what
/// [`EffectiveMtu::probe_floor`] exists to cope with.
pub const LINK_MTU: u16 = 1500;

/// The smallest MTU IPv4 hosts are required to accept without fragmentation
/// help. Nothing derived here is allowed below it.
pub const MIN_TUNNEL_MTU: u16 = 1280;

/// IPv4 header plus UDP header for the datagram that leaves this machine.
const OUTER_IPV4_UDP: u16 = 20 + 8;

/// WireGuard's transport-data message: 16-byte header plus the Poly1305 tag.
const WIREGUARD_DATA: u16 = 16 + 16;

/// OpenVPN UDP worst case: opcode/key-id and peer-id, a 16-byte cipher IV, the
/// 8-byte packet id and a 32-byte SHA-256 auth tag.
const OPENVPN_DATA: u16 = 4 + 16 + 8 + 32;

/// SOCKS5 UDP request header in front of an IPv4 target.
const SOCKS5_UDP_REQUEST: u16 = 10;

/// A relay frame is an IPv4/UDP datagram carrying the GamePath header and the
/// AEAD tag that seals it.
const RELAY_OVERLAY: u16 = 20 + 8 + HEADER_LEN as u16 + 16;

/// AEAD tag length appended by [`crate::auth::SessionCrypto`].
pub const AEAD_TAG: u16 = 16;

/// Bytes each layer of `kind` adds to a captured packet under `mode`.
pub fn path_overhead_bytes(mode: SessionMode, kind: &str) -> u16 {
    // Matched as literals rather than the `KIND_*` constants: the relay links
    // this crate without the `openvpn` feature, which gates that constant.
    let transport = match kind {
        "wireguard" => WIREGUARD_DATA,
        "socks5" => SOCKS5_UDP_REQUEST,
        "openvpn" => OPENVPN_DATA,
        // An unrecognised transport is assumed to cost as much as the most
        // expensive one this build knows about.
        _ => OPENVPN_DATA,
    };
    let overlay = match mode {
        SessionMode::Relay => RELAY_OVERLAY,
        // The node is the last hop and forwards the captured packet as it
        // stands, so only its own transport wraps it.
        SessionMode::Direct => 0,
    };
    OUTER_IPV4_UDP + transport + overlay
}

/// MTU for the relay's own TUN interface.
///
/// Whatever the relay writes there is sealed and sent back to the client, so it
/// has to fit inside the smallest tunnel any client might be using. The relay
/// does not know which transports a given client opened, so this is the worst
/// case across all of them.
pub fn relay_tun_mtu(link_mtu: u16) -> u16 {
    EffectiveMtu::for_session(SessionMode::Relay, ["openvpn", "wireguard", "socks5"], link_mtu).mtu
}

/// The MTU a session can carry, and the TCP MSS that fits inside it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveMtu {
    pub mtu: u16,
    pub overhead: u16,
}

impl EffectiveMtu {
    /// Derived from the most expensive path in the set, because the scheduler
    /// may move a packet onto any of them without renegotiating anything.
    pub fn for_session<'a>(
        mode: SessionMode,
        kinds: impl IntoIterator<Item = &'a str>,
        link_mtu: u16,
    ) -> Self {
        let overhead = kinds
            .into_iter()
            .map(|kind| path_overhead_bytes(mode, kind))
            .max()
            .unwrap_or_else(|| path_overhead_bytes(mode, ""));
        let mtu = link_mtu.saturating_sub(overhead).max(MIN_TUNNEL_MTU);
        Self { mtu, overhead }
    }

    /// MSS for a clamped TCP handshake: the tunnel MTU less the IPv4 and TCP
    /// headers the peer will add back.
    pub fn tcp_mss(self) -> u16 {
        self.mtu.saturating_sub(20 + 20)
    }

    /// Lowest MTU worth trying before declaring a link unusable.
    pub fn probe_floor(self) -> u16 {
        MIN_TUNNEL_MTU.min(self.mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_over_wireguard_fits_a_1500_byte_link() {
        let mtu = EffectiveMtu::for_session(SessionMode::Relay, ["wireguard"], LINK_MTU);
        assert_eq!(mtu.overhead, 144);
        assert_eq!(mtu.mtu, 1356);
        assert!(u32::from(mtu.mtu) + u32::from(mtu.overhead) <= u32::from(LINK_MTU));
    }

    #[test]
    fn direct_wireguard_keeps_the_relay_overlay_out_of_the_budget() {
        let mtu = EffectiveMtu::for_session(SessionMode::Direct, ["wireguard"], LINK_MTU);
        assert_eq!(mtu.overhead, 60);
        assert_eq!(mtu.mtu, 1440);
    }

    #[test]
    fn the_most_expensive_path_sets_the_session_mtu() {
        let mixed =
            EffectiveMtu::for_session(SessionMode::Relay, ["wireguard", "openvpn"], LINK_MTU);
        let openvpn = EffectiveMtu::for_session(SessionMode::Relay, ["openvpn"], LINK_MTU);
        assert_eq!(mixed, openvpn);
        assert!(mixed.mtu < 1356);
    }

    #[test]
    fn mss_leaves_room_for_the_ipv4_and_tcp_headers() {
        let mtu = EffectiveMtu::for_session(SessionMode::Relay, ["wireguard"], LINK_MTU);
        assert_eq!(mtu.tcp_mss(), 1316);
        // The old fixed clamp cost 316 bytes of payload on every segment.
        assert!(mtu.tcp_mss() > 1000);
    }

    #[test]
    fn the_relay_tun_fits_inside_every_client_transport() {
        let relay = relay_tun_mtu(LINK_MTU);
        for kind in ["wireguard", "socks5", "openvpn"] {
            let client = EffectiveMtu::for_session(SessionMode::Relay, [kind], LINK_MTU);
            assert!(
                relay <= client.mtu,
                "a {kind} client cannot carry a {relay}-byte packet back"
            );
            assert!(u32::from(relay) + u32::from(client.overhead) <= u32::from(LINK_MTU));
        }
        // The old fixed 1380 did not, which is what this guards.
        assert!(relay < 1380);
    }

    #[test]
    fn a_small_link_never_produces_an_mtu_below_the_ipv4_minimum() {
        let mtu = EffectiveMtu::for_session(SessionMode::Relay, ["openvpn"], 1280);
        assert_eq!(mtu.mtu, MIN_TUNNEL_MTU);
    }

    #[test]
    fn the_kind_literals_match_the_transport_constants() {
        assert_eq!(crate::relay_path::KIND_WIREGUARD, "wireguard");
        assert_eq!(crate::relay_path::KIND_SOCKS5, "socks5");
        #[cfg(feature = "openvpn")]
        assert_eq!(crate::relay_path::KIND_OPENVPN, "openvpn");
    }

    #[test]
    fn an_unknown_transport_is_costed_as_the_most_expensive_one() {
        assert_eq!(
            path_overhead_bytes(SessionMode::Relay, "something-new"),
            path_overhead_bytes(SessionMode::Relay, "openvpn"),
        );
    }
}
