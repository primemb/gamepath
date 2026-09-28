//! Where the proxy's outbound flows actually leave from.
//!
//! The proxy protocol is the same whichever way a session carries traffic; how
//! a connection to the Internet is opened is not. A session the engine runs
//! has no operating-system socket for the tunnel at all, so its flows live in
//! a user-space TCP/IP stack whose packets go straight into the session
//! ([`super::tunnel_egress`]). A native L2TP/IPsec session is Windows' own
//! VPN adapter, so there ordinary sockets pinned to that adapter do the job
//! ([`super::interface_egress`]). The event loop talks to either through this.

use mio::Token;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

pub(crate) type FlowId = usize;

/// Tokens at or above this belong to the egress's own sockets.
pub(crate) const EGRESS_TOKEN_BASE: usize = 1 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpState {
    Connecting,
    Open,
    /// The remote end finished sending; data it sent may still be buffered.
    RemoteClosed,
    /// Finished in both directions, or torn down.
    Closed,
    Refused,
}

pub(crate) trait Egress: Send {
    fn tcp_connect(&mut self, remote: SocketAddrV4) -> Result<FlowId, String>;
    fn tcp_state(&mut self, flow: FlowId) -> TcpState;
    /// Copies as much of `data` as the flow can take now.
    fn tcp_send(&mut self, flow: FlowId, data: &[u8]) -> usize;
    fn tcp_recv(&mut self, flow: FlowId, buffer: &mut [u8]) -> usize;
    /// Whether nothing written is still waiting to leave.
    fn tcp_send_idle(&mut self, flow: FlowId) -> bool;
    /// Sends FIN once queued data has gone.
    fn tcp_shutdown(&mut self, flow: FlowId);
    fn tcp_release(&mut self, flow: FlowId);

    fn udp_open(&mut self) -> Result<FlowId, String>;
    fn udp_send(&mut self, flow: FlowId, to: SocketAddrV4, payload: &[u8]) -> bool;
    fn udp_recv(&mut self, flow: FlowId) -> Option<(SocketAddrV4, Vec<u8>)>;
    fn udp_release(&mut self, flow: FlowId);

    /// Readiness on one of the egress's own registered sockets.
    fn on_event(&mut self, _token: Token, _readable: bool, _writable: bool) {}
    /// Moves packets between the flows and the network, and says how soon it
    /// needs to run again even if nothing happens.
    fn drive(&mut self) -> Option<Duration>;
    /// Resolvers reachable the same way the flows are.
    fn resolvers(&self) -> Vec<Ipv4Addr>;
    fn kind(&self) -> &'static str;
    /// Packets from the network the proxy had no room for.
    fn dropped_inbound(&self) -> u64 {
        0
    }
}

/// Destinations no LAN client has a reason to reach through the tunnel, and
/// some - loopback above all - that would reach this PC or the relay itself.
pub(crate) fn destination_allowed(address: Ipv4Addr) -> bool {
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_link_local()
        || address.octets()[0] == 0
        || address.octets()[0] >= 240)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_and_multicast_are_never_proxied() {
        for blocked in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
        ] {
            assert!(!destination_allowed(blocked.parse().unwrap()), "{blocked}");
        }
        for allowed in ["8.8.8.8", "10.8.0.1", "185.60.112.157"] {
            assert!(destination_allowed(allowed.parse().unwrap()), "{allowed}");
        }
    }
}
