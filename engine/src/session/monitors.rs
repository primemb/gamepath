//! The two background threads a session runs beside its path workers: the
//! uplink monitor, which answers "can this machine reach the Internet at all"
//! without going through any node, and the periodic summary that gives a
//! transition in the log the context it would otherwise lack.

use super::health::selected_paths;
use super::state::PathSessionStatus;
use super::worker::PathTelemetry;
use gamepath_engine::scheduler::PathMetrics;
use gamepath_engine::uplink;
use gamepath_engine::{log_info, log_warn};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Starts the uplink monitor, which answers "can this machine reach the
/// Internet at all" without going through any node.
///
/// The probe is pinned to the adapter that currently carries the default route,
/// captured here while that is still the physical one - once capture starts,
/// the tunnel owns it.
pub(crate) fn spawn_uplink_monitor(
    stop: &Arc<AtomicBool>,
    telemetry: &PathTelemetry,
) -> Option<JoinHandle<()>> {
    let source = physical_source_address();
    let (stop, monitor) = (Arc::clone(stop), Arc::clone(&telemetry.uplink));
    thread::Builder::new()
        .name("gamepath-uplink".into())
        .spawn(move || {
            uplink::run(monitor, stop, source, |previous, next| {
                log_warn!("uplink {previous:?} -> {next:?}");
            })
        })
        .inspect_err(|error| log_warn!("uplink monitoring is unavailable: {error}"))
        .ok()
}

/// The local address the default route currently uses.
///
/// Connecting a UDP socket sends nothing; it only makes the OS pick a source,
/// which is exactly the question. `None` leaves the probe unpinned, which still
/// works whenever the tunnel does not own the default route.
fn physical_source_address() -> Option<std::net::Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((uplink::PROBE_TARGET, 53)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        _ => None,
    }
}

/// Queue shedding is logged promptly, but a burst is combined into one update
/// rather than producing a line for every discarded packet.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Starts the summary thread, or logs why it could not start and carries on:
/// a session that runs without its log line is better than one that refuses to
/// start because of it.
pub(crate) fn spawn_session_summary(
    session_id: u64,
    stop: &Arc<AtomicBool>,
    statuses: &Arc<Mutex<Vec<PathSessionStatus>>>,
    telemetry: &PathTelemetry,
    decision_mask: &Arc<AtomicU64>,
    scheduler_metrics: &Arc<Mutex<Vec<PathMetrics>>>,
) -> Option<JoinHandle<()>> {
    let (stop, statuses) = (Arc::clone(stop), Arc::clone(statuses));
    let (telemetry, decision_mask) = (telemetry.clone(), Arc::clone(decision_mask));
    let scheduler_metrics = Arc::clone(scheduler_metrics);
    thread::Builder::new()
        .name("gamepath-session-summary".into())
        .spawn(move || {
            run_session_summary(
                session_id,
                stop,
                statuses,
                telemetry,
                decision_mask,
                scheduler_metrics,
            )
        })
        .inspect_err(|error| log_warn!("session summary logging is unavailable: {error}"))
        .ok()
}

/// How often a running session writes its summary line.
const SESSION_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Writes one line a minute describing every path while a session runs.
///
/// This is the context a transition on its own does not give: what the other
/// routes were doing at the time, whether queues were backing up, and how much
/// had been shed. One line a minute remains small enough for the rotation cap,
/// while drop bursts are reported promptly and rate-limited above.
fn run_session_summary(
    session_id: u64,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    telemetry: PathTelemetry,
    decision_mask: Arc<AtomicU64>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
) {
    let route_count = statuses.lock().unwrap().len();
    let mut previous_lost = vec![0_u64; route_count];
    let mut previous_dropped = vec![0_u64; route_count];
    let mut previous_sent = vec![0_u64; route_count];
    let mut previous_received = vec![0_u64; route_count];
    let mut reported_dropped = vec![0_u64; route_count];
    let mut reported_full = vec![0_u64; route_count];
    let mut reported_stale = vec![0_u64; route_count];
    let mut reported_inbound = vec![0_u64; route_count];
    let mut last_drop_log: Option<Instant> = None;
    let mut next = Instant::now() + SESSION_SUMMARY_INTERVAL;
    while !stop.load(Ordering::Acquire) {
        let observed_at = Instant::now();
        let current_dropped = telemetry
            .dropped
            .iter()
            .map(|value| value.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        let has_new_drops = current_dropped
            .iter()
            .zip(&reported_dropped)
            .any(|(current, reported)| current > reported);
        if has_new_drops
            && last_drop_log
                .is_none_or(|logged| observed_at.duration_since(logged) >= DROP_LOG_INTERVAL)
        {
            let details = (0..route_count)
                .filter_map(|index| {
                    let total = current_dropped[index].saturating_sub(reported_dropped[index]);
                    (total > 0).then(|| {
                        let full = telemetry.queue_full_dropped[index].load(Ordering::Relaxed);
                        let stale = telemetry.stale_dropped[index].load(Ordering::Relaxed);
                        let inbound = telemetry.inbound_dropped[index].load(Ordering::Relaxed);
                        let detail = format!(
                            "{}:+{total} (full +{}, stale +{}, inbound +{}, q={}, peak={})",
                            index + 1,
                            full.saturating_sub(reported_full[index]),
                            stale.saturating_sub(reported_stale[index]),
                            inbound.saturating_sub(reported_inbound[index]),
                            telemetry.queue_depth[index].load(Ordering::Relaxed),
                            telemetry.queue_peak[index].load(Ordering::Relaxed),
                        );
                        reported_full[index] = full;
                        reported_stale[index] = stale;
                        reported_inbound[index] = inbound;
                        detail
                    })
                })
                .collect::<Vec<_>>()
                .join(" | ");
            log_warn!("session {session_id} packet shedding by route: {details}");
            reported_dropped.clone_from(&current_dropped);
            last_drop_log = Some(observed_at);
        }
        if observed_at < next {
            thread::sleep(Duration::from_millis(250));
            continue;
        }
        next = observed_at + SESSION_SUMMARY_INTERVAL;
        let selected = selected_paths(
            decision_mask.load(Ordering::Acquire),
            telemetry.healthy_mask.load(Ordering::Acquire),
        );
        let paths = statuses.lock().unwrap().clone();
        let metrics = scheduler_metrics.lock().unwrap().clone();
        let routes = paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let carrying = selected & 1_u64.checked_shl(index as u32).unwrap_or(0) != 0;
                let relay_rtt = path
                    .latency_ms
                    .map(|value| format!("{value:.0}ms"))
                    .unwrap_or_else(|| "-".into());
                let (ewma, jitter, loss) = metrics.get(index).map_or((0.0, 0.0, 0.0), |metric| {
                    (
                        metric.latency_ms,
                        metric.jitter_ms,
                        metric.loss_ratio * 100.0,
                    )
                });
                let dropped = telemetry.dropped[index].load(Ordering::Relaxed);
                let lost_delta = path.probes_lost.saturating_sub(previous_lost[index]);
                let dropped_delta = dropped.saturating_sub(previous_dropped[index]);
                let sent_delta = path.packets_sent.saturating_sub(previous_sent[index]);
                let received_delta = path
                    .packets_received
                    .saturating_sub(previous_received[index]);
                previous_lost[index] = path.probes_lost;
                previous_dropped[index] = dropped;
                previous_sent[index] = path.packets_sent;
                previous_received[index] = path.packets_received;
                format!(
                    "{}:{}{} relay-rtt={relay_rtt} ewma={ewma:.0}ms jitter={jitter:.0}ms \
                     loss-ewma={loss:.0}% probes-lost={} (+{lost_delta}) q={}/peak={} \
                     drop={dropped} (+{dropped_delta}; full={} stale={} inbound={}) \
                     packets=+{sent_delta}/+{received_delta} worker-gap-peak={}ms",
                    path.route,
                    if path.reachable { "up" } else { "down" },
                    if carrying { "/active" } else { "" },
                    path.probes_lost,
                    telemetry.queue_depth[index].load(Ordering::Relaxed),
                    telemetry.queue_peak[index].load(Ordering::Relaxed),
                    telemetry.queue_full_dropped[index].load(Ordering::Relaxed),
                    telemetry.stale_dropped[index].load(Ordering::Relaxed),
                    telemetry.inbound_dropped[index].load(Ordering::Relaxed),
                    telemetry.worker_gap_peak_ms[index].load(Ordering::Relaxed),
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        log_info!(
            "session {session_id}: uplink {:?} | {routes}",
            telemetry.uplink.state()
        );
    }
}
