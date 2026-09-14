//! Address resolution, per-route MTU discovery and the IPv6 exposure report.

use gamepath_engine::log_warn;
use gamepath_engine::mtu::{EffectiveMtu, LINK_MTU};
use serde_json::{Value, json};
use std::net::ToSocketAddrs;

pub(crate) fn resolve_ipv4(host: &str, port: u16) -> Result<std::net::Ipv4Addr, String> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve relay: {error}"))?
        .find_map(|address| match address.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or_else(|| "relay did not resolve to IPv4".into())
}

/// Returns the physical-interface MTU Windows selected for an already
/// resolved tunnel endpoint. This is deliberately route-specific: a laptop
/// can have Ethernet, Wi-Fi and a mobile interface active at the same time.
#[cfg(windows)]
fn route_link_mtu(destination: std::net::Ipv4Addr) -> Result<u16, String> {
    gamepath_engine::netconfig::route_link_mtu(destination)
        .map_err(|error| format!("could not inspect route MTU for {destination}: {error}"))
}

/// Says so when the 1280-byte tunnel floor had to be held above what the link
/// leaves after encapsulation.
///
/// The session still runs, because the floor is not negotiable, but on such a
/// link full-size packets fragment, and that would otherwise surface as
/// latency and loss with nothing in the log to explain it.
pub(crate) fn warn_if_below_link_budget(effective_mtu: EffectiveMtu, link_mtu: u16) {
    if effective_mtu.below_link_budget {
        log_warn!(
            "a {link_mtu}-byte uplink leaves {} bytes after {} bytes of encapsulation, under the {}-byte tunnel floor; holding the floor, so full-size packets fragment on this link",
            link_mtu.saturating_sub(effective_mtu.overhead),
            effective_mtu.overhead,
            effective_mtu.mtu,
        );
    }
}

/// Uses the tightest successfully inspected endpoint route. Discovery is an
/// optimisation, never a connection requirement: a filtered query falls back
/// to the proven 1500-byte budget for only that path.
pub(crate) fn link_mtu_for_endpoints(
    endpoints: impl IntoIterator<Item = std::net::Ipv4Addr>,
) -> u16 {
    #[cfg(windows)]
    {
        let mut smallest = None;
        for endpoint in endpoints {
            match route_link_mtu(endpoint) {
                Ok(mtu) => smallest = Some(smallest.map_or(mtu, |current: u16| current.min(mtu))),
                Err(error) => log_warn!("{error}; using the safe MTU fallback for this path"),
            }
        }
        smallest.unwrap_or(LINK_MTU)
    }
    #[cfg(not(windows))]
    {
        let _ = endpoints;
        LINK_MTU
    }
}

/// Whether an address means the same thing at the far end of the tunnel as it
/// does here.
///
/// A private, loopback or link-local destination is defined relative to the
/// machine holding it: `192.168.1.1` is the user's own router, and the relay
/// resolving that address would find its own LAN or nothing at all. Anything
/// aimed at one of these has to stay on the local network, because sending it
/// through the tunnel does not move it somewhere useful — it drops it.
///
/// Carrier-grade NAT space is excluded for the same reason: it is the ISP's
/// interior, unreachable from anywhere else.
pub(crate) fn is_globally_routable_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_unspecified()
        && !address.is_documentation()
        // 100.64.0.0/10, carrier-grade NAT.
        && !(first == 100 && (64..128).contains(&second))
}

/// Whether `address` is one this machine could reach the Internet from.
///
/// Loopback, link-local and unique-local addresses exist on machines with no
/// IPv6 connectivity at all, so treating them as an exposure would warn
/// everyone.
fn is_globally_routable_ipv6(address: std::net::Ipv6Addr) -> bool {
    let first = address.segments()[0];
    !address.is_loopback()
        && !address.is_unspecified()
        // fe80::/10 link-local
        && first & 0xffc0 != 0xfe80
        // fc00::/7 unique local
        && first & 0xfe00 != 0xfc00
}

/// What IPv6 traffic this session does and does not carry.
///
/// GamePath tunnels IPv4 only: the capture filter, the address rewriting and
/// the relay framing are all IPv4. On a dual-stack connection IPv6 therefore
/// keeps using the normal route, which is a leak if the user believed
/// all-traffic mode meant all traffic. Reporting it is the honest minimum
/// until IPv6 is carried end to end.
pub(crate) fn ipv6_exposure() -> Value {
    // Connecting a UDP socket sends nothing; it only makes the OS choose a
    // source address, which is exactly the question being asked.
    let source = std::net::UdpSocket::bind("[::]:0")
        .and_then(|socket| {
            socket.connect("[2606:4700:4700::1111]:53")?;
            socket.local_addr()
        })
        .ok()
        .and_then(|address| match address.ip() {
            std::net::IpAddr::V6(address) => Some(address),
            std::net::IpAddr::V4(_) => None,
        });
    json!({
        "carried": false,
        "systemHasRoute": source.is_some_and(is_globally_routable_ipv6),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every address family the relay cannot resolve to the same machine this
    /// one meant. Each of these has been seen selected by a split-mode rule:
    /// `192.168.1.1:53` from the DNS rule, `224.0.0.251:5353` from an
    /// application rule naming a game launcher.
    #[test]
    fn an_address_the_relay_cannot_reach_is_not_globally_routable() {
        use std::net::Ipv4Addr;
        for address in [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "255.255.255.255",
            "0.0.0.0",
            "192.0.2.1",
            // 100.64.0.0/10, the ISP's own interior.
            "100.64.0.1",
            "100.127.255.254",
        ] {
            assert!(
                !is_globally_routable_ipv4(address.parse::<Ipv4Addr>().unwrap()),
                "{address} was treated as reachable through the tunnel"
            );
        }
    }

    #[test]
    fn a_public_address_is_globally_routable() {
        use std::net::Ipv4Addr;
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "153.52.92.254",
            "100.63.255.255",
            "100.128.0.1",
        ] {
            assert!(
                is_globally_routable_ipv4(address.parse::<Ipv4Addr>().unwrap()),
                "{address} was withheld from the tunnel"
            );
        }
    }

    #[test]
    fn only_a_globally_routable_address_counts_as_ipv6_exposure() {
        use std::net::Ipv6Addr;
        assert!(is_globally_routable_ipv6(
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_globally_routable_ipv6(Ipv6Addr::LOCALHOST));
        assert!(!is_globally_routable_ipv6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_globally_routable_ipv6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_globally_routable_ipv6(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn ipv6_is_always_reported_as_uncarried() {
        let exposure = ipv6_exposure();
        assert_eq!(exposure["carried"], json!(false));
        assert!(exposure["systemHasRoute"].is_boolean());
    }
}
