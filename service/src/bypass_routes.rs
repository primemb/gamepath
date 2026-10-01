//! Host routes that keep one slot's tunnel endpoints on the physical uplink
//! while the other slot owns the default route.

use gamepath_engine::netconfig;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

pub(crate) struct BypassRoutes {
    gateway: Ipv4Addr,
    interface_index: u32,
    installed: BTreeSet<Ipv4Addr>,
}

impl BypassRoutes {
    /// Records the physical default route. Call it before anything takes the
    /// default route over, or the gateway found is the tunnel's own.
    pub(crate) fn on_physical_uplink() -> Result<Self, String> {
        let (gateway, interface_index) = netconfig::default_ipv4_route()?;
        Ok(Self {
            gateway,
            interface_index,
            installed: BTreeSet::new(),
        })
    }

    /// Makes the installed set exactly `wanted`, touching only the difference.
    pub(crate) fn apply(&mut self, wanted: &[Ipv4Addr]) -> Result<(), String> {
        let wanted: BTreeSet<Ipv4Addr> = wanted.iter().copied().collect();
        for stale in self
            .installed
            .difference(&wanted)
            .copied()
            .collect::<Vec<_>>()
        {
            netconfig::remove_route_via(stale, 32, self.gateway, self.interface_index);
            self.installed.remove(&stale);
        }
        for address in wanted.difference(&self.installed.clone()) {
            netconfig::add_route_via(*address, 32, self.gateway, self.interface_index, 1)?;
            self.installed.insert(*address);
        }
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.installed.len()
    }
}

impl Drop for BypassRoutes {
    fn drop(&mut self) {
        for address in &self.installed {
            netconfig::remove_route_via(*address, 32, self.gateway, self.interface_index);
        }
    }
}
