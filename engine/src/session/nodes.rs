//! The nodes a session can pin a flow to.
//!
//! A relay session has one entry, the relay: every packet takes the
//! scheduler's pick across its routes. A direct session has one entry per
//! node, and capture picks the entry for each flow from the rule that
//! selected it, so one application can leave through a SOCKS5 proxy while
//! another uses a WireGuard node beside it.

use super::path_mtu::SessionMtu;
use gamepath_engine::mtu::EffectiveMtu;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Most nodes one direct session runs. Each is a tunnel with its own worker,
/// keepalives and probes, so this bounds what a session costs to hold open.
pub(crate) const MAX_DIRECT_NODES: usize = 8;

pub(crate) struct SessionNode {
    pub(crate) address: Ipv4Addr,
    pub(crate) mtu: Arc<SessionMtu>,
    pub(crate) socks_proxy: Option<SocketAddr>,
}

pub(crate) struct SessionNodes {
    /// Atomic because a node that redials can be handed a new address.
    addresses: Box<[AtomicU32]>,
    mtus: Vec<Arc<SessionMtu>>,
    socks_proxies: Vec<Option<SocketAddr>>,
}

impl SessionNodes {
    pub(crate) fn new(nodes: Vec<SessionNode>) -> Self {
        Self {
            addresses: nodes
                .iter()
                .map(|node| AtomicU32::new(u32::from(node.address)))
                .collect(),
            mtus: nodes.iter().map(|node| Arc::clone(&node.mtu)).collect(),
            socks_proxies: nodes.iter().map(|node| node.socks_proxy).collect(),
        }
    }

    /// The tunnel address `node` sends from. An index past the end is the
    /// default node's, so a stale index can never send from nowhere.
    pub(crate) fn address(&self, node: u8) -> Ipv4Addr {
        let slot = self
            .addresses
            .get(usize::from(node))
            .unwrap_or(&self.addresses[0]);
        Ipv4Addr::from(slot.load(Ordering::Relaxed))
    }

    pub(crate) fn set_address(&self, node: usize, address: Ipv4Addr) {
        if let Some(slot) = self.addresses.get(node) {
            slot.store(u32::from(address), Ordering::Relaxed);
        }
    }

    /// Whether a reply addressed to `address` came back through one of these
    /// nodes. Providers commonly give every client the same tunnel address,
    /// so two nodes can share one; the flow's own record says which it took.
    pub(crate) fn owns(&self, address: Ipv4Addr) -> bool {
        let address = u32::from(address);
        self.addresses
            .iter()
            .any(|slot| slot.load(Ordering::Relaxed) == address)
    }

    /// Each node's MTU once its path has been measured, in node order.
    pub(crate) fn mtus_for_capture(&self) -> Vec<EffectiveMtu> {
        self.mtus.iter().map(|mtu| mtu.for_capture()).collect()
    }

    pub(crate) fn socks_proxies(&self) -> impl Iterator<Item = (u8, SocketAddr)> + '_ {
        self.socks_proxies
            .iter()
            .enumerate()
            .filter_map(|(node, proxy)| Some((node as u8, (*proxy)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamepath_engine::relay_path::SessionMode;

    fn node(address: [u8; 4]) -> SessionNode {
        let derived = EffectiveMtu::for_session(SessionMode::Direct, ["wireguard"], 1500);
        SessionNode {
            address: Ipv4Addr::from(address),
            mtu: Arc::new(SessionMtu::measure(derived, 1500, [], |_| unreachable!())),
            socks_proxy: None,
        }
    }

    #[test]
    fn a_reply_to_any_node_address_belongs_to_the_session() {
        let nodes = SessionNodes::new(vec![node([10, 2, 0, 2]), node([10, 8, 0, 6])]);
        assert!(nodes.owns(Ipv4Addr::new(10, 8, 0, 6)));
        assert!(!nodes.owns(Ipv4Addr::new(10, 8, 0, 7)));
        nodes.set_address(1, Ipv4Addr::new(10, 8, 0, 7));
        assert!(nodes.owns(Ipv4Addr::new(10, 8, 0, 7)));
        assert_eq!(nodes.address(1), Ipv4Addr::new(10, 8, 0, 7));
    }

    #[test]
    fn an_unknown_node_sends_from_the_default_node() {
        let nodes = SessionNodes::new(vec![node([10, 2, 0, 2])]);
        assert_eq!(nodes.address(5), Ipv4Addr::new(10, 2, 0, 2));
    }
}
