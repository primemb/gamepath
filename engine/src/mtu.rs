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

/// Conservative fallback and upper bound for an Internet uplink. Ethernet and
/// most consumer links use this. Session setup replaces it with the MTU of
/// the Windows route that actually reaches the selected tunnel endpoint.
pub const LINK_MTU: u16 = 1500;

/// Hard lower bound for a game tunnel. No session is configured below this,
/// whatever the link and encapsulation leave room for.
///
/// 1280 is the minimum every IPv6-capable link must carry, and the figure
/// games, engines and middleboxes assume they can send without discovering a
/// path MTU first. A tunnel advertised under it fits its own link but breaks
/// that assumption, which surfaces as connection failures rather than as the
/// slow path it ought to be. On a link too narrow to hold the floor plus its
/// encapsulation the remainder fragments, and
/// [`EffectiveMtu::below_link_budget`] records that so it can be logged.
pub const MIN_TUNNEL_MTU: u16 = 1280;

/// Makes an OS-reported link MTU safe to use as an Internet packet budget.
/// Jumbo frames do not help the Internet path, and a missing or implausibly
/// small report must never make connection startup fail.
pub fn normalize_link_mtu(reported: u16) -> u16 {
    reported.clamp(MIN_TUNNEL_MTU, LINK_MTU)
}

/// A provider-supplied tunnel MTU is an inner-packet limit, not an outer-link
/// budget. Ignore values outside the range GamePath can safely configure.
pub fn configured_tunnel_mtu(reported: u16) -> Option<u16> {
    (MIN_TUNNEL_MTU..=LINK_MTU)
        .contains(&reported)
        .then_some(reported)
}

/// IPv4 header plus UDP header for the datagram that leaves this machine.
const OUTER_IPV4_UDP: u16 = 20 + 8;

/// WireGuard's transport-data message: 16-byte header plus the Poly1305 tag.
const WIREGUARD_DATA: u16 = 16 + 16;

/// OpenVPN worst case: opcode/key-id and peer-id, a 16-byte cipher IV, the
/// 8-byte packet id, a 32-byte SHA-256 auth tag, and the 2-byte record length
/// that stream mode puts in front of every packet.
const OPENVPN_DATA: u16 = 4 + 16 + 8 + 32 + 2;

/// IPv4 plus a TCP header carrying the options a long-lived stream negotiates,
/// timestamps above all.
///
/// Charged to every OpenVPN path, including one configured for UDP.
/// `OpenVpnPath::connect` retries a UDP remote over TCP, because a provider
/// handing out a UDP profile almost always listens for TCP on the same port
/// and that is the attempt which survives a link that drops large datagrams.
/// So the protocol in use is decided while dialling, after this budget has
/// been derived, and `path_overhead_bytes` is given only the transport kind,
/// which says `openvpn` either way. Costing the cheaper of the two would mean
/// sizing the tunnel for UDP and then running it over TCP.
const OUTER_IPV4_TCP: u16 = 20 + 32;

/// SOCKS5 UDP request header in front of an IPv4 target.
const SOCKS5_UDP_REQUEST: u16 = 10;

/// Conservative L2TP/IPsec NAT-T allowance: outer IPv4/UDP, non-ESP marker,
/// ESP IV/auth/padding, the L2TP UDP header and PPP framing.
const L2TP_IPSEC_DATA: u16 = 116;

/// A relay frame is an IPv4/UDP datagram carrying the GamePath header and the
/// AEAD tag that seals it.
const RELAY_OVERLAY: u16 = 20 + 8 + HEADER_LEN as u16 + 16;

/// AEAD tag length appended by [`crate::auth::SessionCrypto`].
pub const AEAD_TAG: u16 = 16;

/// Bytes each layer of `kind` adds to a captured packet under `mode`.
pub fn path_overhead_bytes(mode: SessionMode, kind: &str) -> u16 {
    // Matched as literals rather than the `KIND_*` constants: the relay links
    // this crate without the `openvpn` feature, which gates that constant.
    let (transport, outer) = match kind {
        "wireguard" => (WIREGUARD_DATA, OUTER_IPV4_UDP),
        "socks5" => (SOCKS5_UDP_REQUEST, OUTER_IPV4_UDP),
        "openvpn" => (OPENVPN_DATA, OUTER_IPV4_TCP),
        "l2tp" => (L2TP_IPSEC_DATA, 0),
        // An unrecognised transport is assumed to cost as much as the most
        // expensive one this build knows about.
        _ => (L2TP_IPSEC_DATA, 0),
    };
    let overlay = match mode {
        SessionMode::Relay => RELAY_OVERLAY,
        // The node is the last hop and forwards the captured packet as it
        // stands, so only its own transport wraps it.
        SessionMode::Direct => 0,
    };
    // The L2TP/IPsec allowance already includes its outer IP/UDP headers.
    outer + transport + overlay
}

/// MTU for the relay's own TUN interface.
///
/// Whatever the relay writes there is sealed and sent back to the client, so it
/// has to fit inside the smallest tunnel any client might be using. The relay
/// does not know which transports a given client opened, so this is the worst
/// case across all of them.
pub fn relay_tun_mtu(link_mtu: u16) -> u16 {
    EffectiveMtu::for_session(
        SessionMode::Relay,
        ["openvpn", "wireguard", "socks5", "l2tp"],
        link_mtu,
    )
    .mtu
}

/// The MTU a session can carry, and the TCP MSS that fits inside it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveMtu {
    pub mtu: u16,
    pub overhead: u16,
    /// Set when [`MIN_TUNNEL_MTU`] had to be held above what the link and the
    /// encapsulation actually leave room for.
    ///
    /// The tunnel is still configured at the floor, because that is the
    /// contract, but on such a link a full-size packet has to fragment to get
    /// out. That is worth saying out loud in a log rather than discovering as
    /// unexplained loss, so the decision is recorded here instead of being
    /// silently absorbed by the clamp.
    pub below_link_budget: bool,
}

impl EffectiveMtu {
    /// Derived from the most expensive path in the set, because the scheduler
    /// may move a packet onto any of them without renegotiating anything.
    pub fn for_session<'a>(
        mode: SessionMode,
        kinds: impl IntoIterator<Item = &'a str>,
        link_mtu: u16,
    ) -> Self {
        let link_mtu = normalize_link_mtu(link_mtu);
        let overhead = kinds
            .into_iter()
            .map(|kind| path_overhead_bytes(mode, kind))
            .max()
            .unwrap_or_else(|| path_overhead_bytes(mode, ""));
        let budget = link_mtu.saturating_sub(overhead);
        // [`MIN_TUNNEL_MTU`] is a floor, not a preference: no session is ever
        // configured below it. Nested and mobile links can leave less than
        // that after encapsulation, and the alternative - advertising the
        // smaller real budget - hands games an MTU under the 1280 bytes IPv6
        // requires every link to carry, which breaks more than the
        // fragmentation this costs.
        let mtu = budget.max(MIN_TUNNEL_MTU);
        Self {
            mtu,
            overhead,
            below_link_budget: mtu > budget,
        }
    }

    /// Applies the lower inner-MTU requested by a provider configuration.
    /// The transport overhead is deliberately retained: it describes the
    /// selected transport, while this cap describes the provider's tunnel.
    pub fn with_tunnel_limit(self, configured: Option<u16>) -> Self {
        // `configured_tunnel_mtu` already rejects anything under the floor;
        // the clamp restates it so the invariant holds at the one place that
        // can otherwise lower `mtu` after construction.
        let mtu = configured_tunnel_mtu(configured.unwrap_or(LINK_MTU))
            .map_or(self.mtu, |limit| self.mtu.min(limit))
            .max(MIN_TUNNEL_MTU);
        Self { mtu, ..self }
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
    fn l2tp_counts_its_outer_headers_only_once() {
        let direct = EffectiveMtu::for_session(SessionMode::Direct, ["l2tp"], LINK_MTU);
        assert_eq!(direct.overhead, 116);
        assert_eq!(direct.mtu, 1384);

        let relay = EffectiveMtu::for_session(SessionMode::Relay, ["l2tp"], LINK_MTU);
        assert_eq!(relay.overhead, 200);
        assert_eq!(relay.mtu, 1300);
    }

    #[test]
    fn the_most_expensive_path_sets_the_session_mtu() {
        let mixed =
            EffectiveMtu::for_session(SessionMode::Relay, ["wireguard", "openvpn"], LINK_MTU);
        let openvpn = EffectiveMtu::for_session(SessionMode::Relay, ["openvpn"], LINK_MTU);
        assert_eq!(mixed, openvpn);
        assert!(mixed.mtu < 1356);
    }

    /// An OpenVPN path is sized for TCP whichever protocol its profile names,
    /// because `OpenVpnPath::connect` retries a UDP remote over TCP and the
    /// `kind` string says `openvpn` either way. A tunnel sized for UDP and then
    /// run over TCP puts the tail of every full-size packet past the end of the
    /// link.
    #[test]
    fn openvpn_is_costed_for_the_stream_framing_it_can_fall_back_to() {
        // Direct mode leaves only the transport's own cost in the figure.
        let overhead = path_overhead_bytes(SessionMode::Direct, "openvpn");
        // What UDP-only accounting charged: no record length, UDP outer.
        let as_if_udp = OUTER_IPV4_UDP + 4 + 16 + 8 + 32;
        assert!(
            // A TCP header in place of the UDP one, plus the record length.
            overhead >= as_if_udp + (20 - 8) + 2,
            "an openvpn path is charged {overhead} bytes, barely more than the \
             {as_if_udp} a udp-only path costs"
        );
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
        for kind in ["wireguard", "socks5", "openvpn", "l2tp"] {
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

    /// The floor wins on a link that cannot hold it, and says so rather than
    /// quietly handing back a tunnel under 1280.
    #[test]
    fn a_small_link_is_held_at_the_floor_and_flagged() {
        let mtu = EffectiveMtu::for_session(SessionMode::Relay, ["openvpn"], 1280);
        assert_eq!(mtu.mtu, MIN_TUNNEL_MTU);
        assert!(mtu.below_link_budget);
        // The cost of the floor, which is what the flag exists to let a caller
        // report: this much of every full-size packet has to fragment.
        assert!(u32::from(mtu.mtu) + u32::from(mtu.overhead) > 1280);
    }

    /// A link with room to spare is untouched by the floor, and is not
    /// flagged as if it were constrained.
    #[test]
    fn a_roomy_link_keeps_its_real_budget_and_is_not_flagged() {
        let mtu = EffectiveMtu::for_session(SessionMode::Relay, ["openvpn"], LINK_MTU);
        assert!(mtu.mtu > MIN_TUNNEL_MTU);
        assert!(!mtu.below_link_budget);
        assert_eq!(
            u32::from(mtu.mtu) + u32::from(mtu.overhead),
            u32::from(LINK_MTU)
        );
    }

    /// The invariant the whole change is for, across every transport, every
    /// mode, and every link MTU the normaliser can produce.
    #[test]
    fn no_session_is_ever_configured_below_the_floor() {
        for link in [0_u16, 576, 1000, 1280, 1400, 1492, 1500, 9000, u16::MAX] {
            for mode in [SessionMode::Relay, SessionMode::Direct] {
                for kind in ["wireguard", "openvpn", "socks5", "l2tp", "something-new"] {
                    let mtu = EffectiveMtu::for_session(mode, [kind], link);
                    assert!(
                        mtu.mtu >= MIN_TUNNEL_MTU,
                        "{kind} on a {link}-byte link produced {}",
                        mtu.mtu
                    );
                    // A provider cap must not be able to duck under it either.
                    for configured in [None, Some(0), Some(1279), Some(1280), Some(1400)] {
                        assert!(mtu.with_tunnel_limit(configured).mtu >= MIN_TUNNEL_MTU);
                    }
                }
            }
        }
        assert!(relay_tun_mtu(1280) >= MIN_TUNNEL_MTU);
    }

    #[test]
    fn a_provider_limit_can_only_reduce_the_safe_result() {
        let mtu = EffectiveMtu::for_session(SessionMode::Direct, ["wireguard"], LINK_MTU)
            .with_tunnel_limit(Some(1280));
        assert_eq!(mtu.mtu, 1280);
        assert_eq!(mtu.overhead, 60);
        assert_eq!(configured_tunnel_mtu(1279), None);
        assert_eq!(configured_tunnel_mtu(1501), None);
    }

    #[test]
    fn the_kind_literals_match_the_transport_constants() {
        assert_eq!(crate::relay_path::KIND_WIREGUARD, "wireguard");
        assert_eq!(crate::relay_path::KIND_SOCKS5, "socks5");
        assert_eq!(crate::relay_path::KIND_L2TP, "l2tp");
        #[cfg(feature = "openvpn")]
        assert_eq!(crate::relay_path::KIND_OPENVPN, "openvpn");
    }

    #[test]
    fn an_unknown_transport_is_costed_as_the_most_expensive_one() {
        assert_eq!(
            path_overhead_bytes(SessionMode::Relay, "something-new"),
            path_overhead_bytes(SessionMode::Relay, "l2tp"),
        );
    }
}

