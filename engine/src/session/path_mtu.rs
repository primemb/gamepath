//! A session's tunnel MTU, refined by measuring the path to each endpoint.
//!
//! Measuring overlaps handshakes and the benchmark. Capture waits for the
//! remaining measurement budget before fixing its adapter MTU and TCP MSS;
//! otherwise a fast handshake can leave it using a larger, stale link budget.

use crate::netutil::{is_globally_routable_ipv4, warn_if_below_link_budget};
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::{log_info, log_warn, path_mtu};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Total startup budget, including time already spent handshaking.
const MEASURE_BUDGET: Duration = Duration::from_secs(2);

pub(crate) struct SessionMtu {
    derived: EffectiveMtu,
    measured: Arc<OnceLock<EffectiveMtu>>,
    completion: Mutex<Option<mpsc::Receiver<()>>>,
    deadline: Instant,
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
        let deadline = Instant::now() + MEASURE_BUDGET;
        let mut completion = None;
        // Two routes through one node share its path; measure it once.
        let mut endpoints = endpoints
            .into_iter()
            .filter(|endpoint| is_globally_routable_ipv4(*endpoint))
            .collect::<Vec<_>>();
        endpoints.sort_unstable();
        endpoints.dedup();
        if !endpoints.is_empty() {
            let slot = Arc::clone(&measured);
            let (finished, receiver) = mpsc::channel();
            completion = Some(receiver);
            let spawned = thread::Builder::new()
                .name("gamepath-path-mtu".into())
                .spawn(move || {
                    // Every exit, including unknown MTU and a panic, wakes capture.
                    let _finished = finished;
                    let measured = measure_paths(&endpoints, link_mtu);
                    // Every endpoint's figure, so a reading that differs from
                    // the last session can be told apart from a changed path.
                    log_info!(
                        "path MTU measured: {}",
                        measured
                            .iter()
                            .map(|(endpoint, mtu)| match mtu {
                                Some(mtu) => format!("{endpoint}={mtu}"),
                                None => format!("{endpoint}=no answer"),
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    let narrowest = measured
                        .into_iter()
                        .filter_map(|(endpoint, mtu)| Some((endpoint, mtu?)))
                        .min_by_key(|(_, mtu)| *mtu);
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
        Self {
            derived,
            measured,
            completion: Mutex::new(completion),
            deadline,
        }
    }

    pub(crate) fn current(&self) -> EffectiveMtu {
        self.measured.get().copied().unwrap_or(self.derived)
    }

    pub(crate) fn for_capture(&self) -> EffectiveMtu {
        let completion = self.completion.lock().unwrap().take();
        if let Some(completion) = completion {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let _ = completion.recv_timeout(remaining);
        }
        self.current()
    }
}

fn measure_paths(endpoints: &[Ipv4Addr], link_mtu: u16) -> Vec<(Ipv4Addr, Option<u16>)> {
    thread::scope(|scope| {
        let probes = endpoints
            .iter()
            .map(|&endpoint| {
                (
                    endpoint,
                    scope.spawn(move || path_mtu::measure(endpoint, link_mtu, MEASURE_BUDGET)),
                )
            })
            .collect::<Vec<_>>();
        probes
            .into_iter()
            .map(|(endpoint, probe)| (endpoint, probe.join().ok().flatten()))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamepath_engine::relay_path::SessionMode;

    fn pending(deadline: Instant) -> (SessionMtu, mpsc::Sender<()>) {
        let (finished, completion) = mpsc::channel();
        (
            SessionMtu {
                derived: EffectiveMtu::for_session(SessionMode::Direct, ["wireguard"], 1500),
                measured: Arc::new(OnceLock::new()),
                completion: Mutex::new(Some(completion)),
                deadline,
            },
            finished,
        )
    }

    #[test]
    fn capture_uses_measurement_that_finishes_after_handshake() {
        let (mtu, finished) = pending(Instant::now() + Duration::from_secs(1));
        let measured = Arc::clone(&mtu.measured);
        let refined = EffectiveMtu::for_session(SessionMode::Direct, ["wireguard"], 1424);
        assert_eq!(mtu.current().mtu, 1440);
        thread::scope(|scope| {
            scope.spawn(move || {
                thread::sleep(Duration::from_millis(20));
                measured.set(refined).unwrap();
                drop(finished);
            });
            assert_eq!(mtu.for_capture(), refined);
            assert_eq!(mtu.for_capture(), refined);
        });
    }

    #[test]
    fn unknown_measurement_keeps_interface_budget() {
        let (mtu, finished) = pending(Instant::now() + Duration::from_secs(1));
        drop(finished);
        assert_eq!(mtu.for_capture(), mtu.derived);
    }

    #[test]
    fn capture_wait_ends_at_original_measurement_deadline() {
        let (mtu, _finished) = pending(Instant::now());
        assert_eq!(mtu.for_capture(), mtu.derived);
        assert!(mtu.completion.lock().unwrap().is_none());
    }

    #[test]
    fn no_measurable_endpoints_start_capture_immediately() {
        let derived = EffectiveMtu::for_session(SessionMode::Direct, ["wireguard"], 1500);
        let mtu = SessionMtu::measure(derived, 1500, [], |_| unreachable!());
        assert!(mtu.completion.lock().unwrap().is_none());
        assert_eq!(mtu.for_capture(), derived);
    }
}
