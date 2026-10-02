//! A session's tunnel MTU, refined by measuring the path to each endpoint.
//!
//! Measuring runs beside session setup, never in front of it. The session
//! starts on the MTU derived from the interface, and packet capture, which
//! opens after the relay handshake and benchmark, takes the measured one if it
//! has arrived by then. A path that measures narrower than its interface only
//! ever lowers the MTU.

use crate::netutil::{is_globally_routable_ipv4, warn_if_below_link_budget};
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::{log_info, log_warn, path_mtu};
use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

/// Well inside the time capture takes to follow session start on a healthy
/// link; a measurement still running past it is simply not used.
const MEASURE_BUDGET: Duration = Duration::from_secs(2);

pub(crate) struct SessionMtu {
    derived: EffectiveMtu,
    measured: Arc<OnceLock<EffectiveMtu>>,
}

impl SessionMtu {
    /// `derive` rebuilds the session's MTU from a link MTU, so a measured
    /// path gets exactly the overhead and provider limits the interface did.
    pub(crate) fn measure(
        derived: EffectiveMtu,
        link_mtu: u16,
        endpoints: impl IntoIterator<Item = Ipv4Addr>,
        derive: impl FnOnce(u16) -> EffectiveMtu + Send + 'static,
    ) -> Self {
        let measured = Arc::new(OnceLock::new());
        let endpoints = endpoints
            .into_iter()
            .filter(|endpoint| is_globally_routable_ipv4(*endpoint))
            .collect::<Vec<_>>();
        if !endpoints.is_empty() {
            let slot = Arc::clone(&measured);
            let spawned = thread::Builder::new()
                .name("gamepath-path-mtu".into())
                .spawn(move || {
                    let narrowest = narrowest_path(&endpoints, link_mtu);
                    let Some((endpoint, path)) = narrowest else {
                        log_info!(
                            "path MTU: endpoints do not answer echo requests; keeping the {link_mtu}-byte interface MTU"
                        );
                        return;
                    };
                    let refined = derive(path);
                    if refined.unfragmented() >= derived.unfragmented() {
                        log_info!("path MTU: {path} bytes to every endpoint, as the interface reports");
                        return;
                    }
                    log_warn!(
                        "path MTU to {endpoint} is {path} bytes though the interface reports {link_mtu}; tunnel MTU {} -> {}, unfragmented {} -> {}",
                        derived.mtu,
                        refined.mtu,
                        derived.unfragmented(),
                        refined.unfragmented()
                    );
                    warn_if_below_link_budget(refined, path);
                    let _ = slot.set(refined);
                });
            if let Err(error) = spawned {
                log_warn!("path MTU: could not start measuring: {error}");
            }
        }
        Self { derived, measured }
    }

    pub(crate) fn current(&self) -> EffectiveMtu {
        self.measured.get().copied().unwrap_or(self.derived)
    }
}

fn narrowest_path(endpoints: &[Ipv4Addr], link_mtu: u16) -> Option<(Ipv4Addr, u16)> {
    thread::scope(|scope| {
        let probes = endpoints
            .iter()
            .map(|&endpoint| {
                scope.spawn(move || {
                    path_mtu::measure(endpoint, link_mtu, MEASURE_BUDGET).map(|mtu| (endpoint, mtu))
                })
            })
            .collect::<Vec<_>>();
        probes
            .into_iter()
            .filter_map(|probe| probe.join().ok().flatten())
            .min_by_key(|(_, mtu)| *mtu)
    })
}
