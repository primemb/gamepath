//! One thread per relay path: it carries the dispatcher's packets, probes the
//! relay through its own transport, and decides when that transport has to be
//! dialled again.

use super::dialer::{
    PathDialer, RECONNECT_BACKOFF_MIN, ReconnectAttempt, ReconnectPoll, UPLINK_DOWN_BACKOFF,
    another_path_is_up, hold_redial_for_common_mode, next_backoff, schedule_redial,
};
use super::health::{
    HEALTH_FAILURE_THRESHOLD, PROBE_INTERVAL, PROBE_INTERVAL_DEGRADED, publish_path_health,
    record_path_receive, record_path_send, remember_expired_probe, take_late_probe_reply,
    update_path_status, update_scheduler_probe,
};
use super::latency::{LatencyEvent, LatencyWatch};
use super::state::{PathSessionStatus, RelayIngress};
use super::worker::{
    PathCommand, PathTelemetry, WORKER_GAP_LOG_INTERVAL, WORKER_GAP_WARN, WORKER_RECEIVE_TIMEOUT,
    drain_send_queue,
};
use gamepath_engine::relay_path::RelayPath;
use gamepath_engine::rtt::RttEstimator;
use gamepath_engine::scheduler::{PathMetrics, Strategy};
use gamepath_engine::{log_info, log_warn};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_path(
    mut path: Box<dyn RelayPath>,
    index: usize,
    sequences: Arc<AtomicU64>,
    client_id: [u8; 16],
    key: [u8; 32],
    session_id: u64,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
    inbound: mpsc::SyncSender<Vec<u8>>,
    ingress: Arc<RelayIngress>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    decision_mask: Arc<AtomicU64>,
    fallback_mask: u64,
    strategy: Strategy,
    telemetry: PathTelemetry,
    dialer: PathDialer,
    route_count: usize,
) {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};

    let Ok(crypto) = SessionCrypto::new(&key, session_id) else {
        return;
    };
    let mut next_probe = Instant::now();
    let mut pending_probe: Option<(u64, Instant)> = None;
    // Probes already written off, kept briefly so a reply that arrives after
    // the deadline can still tell the estimator how slow this path really is.
    let mut expired_probes: Vec<(u64, Instant)> = Vec::new();
    let mut correlated_probes = false;
    let mut warned_legacy_probes = false;
    let mut published_setup_latency = None;
    // The probe deadline tracks this path rather than being a constant that has
    // to suit both a 60 ms route and a congested one. Its floor comes from the
    // transport, because a stream-carried path stalls for its own retransmit
    // and answering later than that is not the same as not answering.
    let mut rtt = RttEstimator::with_floor(path.probe_deadline_floor());
    let mut latency_watch = LatencyWatch::default();
    let mut last_iteration = Instant::now();
    let mut last_worker_gap_log: Option<Instant> = None;
    // Consecutive failed health checks and the next redial deadline reset as
    // soon as the path answers. An already-running redial stays owned until
    // it finishes, then is discarded if that recovery made it obsolete.
    let mut failures = 0_u32;
    let mut backoff = RECONNECT_BACKOFF_MIN;
    let mut next_redial: Option<Instant> = None;
    // Set once this transport's own verdict has been acted on, so a socket that
    // stays broken is reported once rather than on every loop iteration.
    let mut reported_transport_failure = false;
    // When every path in this session was first seen down at the same moment.
    // Cleared as soon as any of them answers, so it measures one episode rather
    // than accumulating across unrelated ones.
    let mut common_mode_since: Option<Instant> = None;
    // Whether any path in this session has ever been healthy. Distinguishes a
    // session that collapsed from one that has not come up yet.
    let mut carried_traffic = false;
    // A dial can take seconds - a SOCKS5 connect allows eight, an OpenVPN
    // handshake its own - so it runs on its own thread and the result is
    // collected here. The worker keeps probing and keeps checking `stop` while
    // it is in flight, which is what stops a dead route delaying a session stop.
    let mut dialing: Option<ReconnectAttempt<Box<dyn RelayPath>>> = None;
    while !stop.load(Ordering::Acquire) {
        let iteration_started = Instant::now();
        let worker_gap = iteration_started.saturating_duration_since(last_iteration);
        last_iteration = iteration_started;
        let worker_gap_ms = worker_gap.as_millis().min(u128::from(u64::MAX)) as u64;
        telemetry.worker_gap_peak_ms[index].fetch_max(worker_gap_ms, Ordering::Relaxed);
        if worker_gap >= WORKER_GAP_WARN
            && last_worker_gap_log.is_none_or(|logged| logged.elapsed() >= WORKER_GAP_LOG_INTERVAL)
        {
            last_worker_gap_log = Some(iteration_started);
            log_warn!(
                "session {session_id} route {} worker gap {} ms; q={} drop={} uplink={:?}",
                index + 1,
                worker_gap_ms,
                telemetry.queue_depth[index].load(Ordering::Relaxed),
                telemetry.dropped[index].load(Ordering::Relaxed),
                telemetry.uplink.state()
            );
        }
        telemetry.iterations[index].fetch_add(1, Ordering::Relaxed);
        match dialing.as_mut().map(ReconnectAttempt::poll) {
            Some(ReconnectPoll::Finished(Ok(replacement))) => {
                dialing = None;
                path = replacement;
                reported_transport_failure = false;
                publish_path_health(&telemetry.healthy_mask, index, false);
                // A redial may fall back from UDP to TCP (or recover to UDP).
                // Neither the old samples nor its deadline floor apply.
                rtt = RttEstimator::with_floor(path.probe_deadline_floor());
                latency_watch.reset();
                failures = 0;
                // Opening a socket is not recovery. Repeated replacements
                // that never answer must back off until a real pong arrives.
                backoff = next_backoff(backoff);
                next_redial = None;
                pending_probe = None;
                published_setup_latency = None;
                // The new transport has to prove itself: only an answered probe
                // puts this path back into the dispatcher's selection.
                next_probe = Instant::now();
                log_info!(
                    "route {} transport opened via {}; awaiting relay probe",
                    index + 1,
                    path.endpoint()
                );
                let mut current = statuses.lock().unwrap();
                current[index].reachable = false;
                current[index].endpoint = path.endpoint();
                current[index].last_error = Some("reconnected; waiting for a probe".into());
            }
            Some(ReconnectPoll::Finished(Err(error))) => {
                dialing = None;
                backoff = next_backoff(backoff);
                next_redial = Some(Instant::now() + backoff);
                log_warn!(
                    "route {} reconnect failed, retrying in {} s: {error}",
                    index + 1,
                    backoff.as_secs()
                );
                statuses.lock().unwrap()[index].last_error =
                    Some(format!("reconnect failed, retrying: {error}"));
            }
            Some(ReconnectPoll::Discarded) => {
                dialing = None;
                log_info!(
                    "session {session_id} route {} discarded obsolete reconnect after recovery",
                    index + 1
                );
            }
            Some(ReconnectPoll::Pending) | None => {}
        }
        // A redial is only worth making when something proves the uplink is
        // there. The monitor answers that directly when it can, but it is slow
        // to change its mind, so every path being down at once is tracked here
        // as evidence in its own right - fresher than the monitor, and the only
        // thing that catches a stall too short for the monitor to see.
        //
        // Only a collapse counts, though. Until some path has carried traffic,
        // "nothing is up" is a session that has not finished starting, and
        // holding its redials would only slow it down.
        carried_traffic |= telemetry.healthy_mask.load(Ordering::Acquire) != 0;
        let common_mode_for = if route_count > 1
            && carried_traffic
            && !another_path_is_up(&telemetry.healthy_mask, index)
        {
            Some(common_mode_since.get_or_insert_with(Instant::now).elapsed())
        } else {
            // One path answering ends it: whatever happened was not shared.
            common_mode_since = None;
            None
        };
        let uplink_down = hold_redial_for_common_mode(telemetry.uplink.state(), common_mode_for);
        if dialing.is_none() && uplink_down && next_redial.is_some_and(|at| Instant::now() >= at) {
            next_redial = Some(Instant::now() + UPLINK_DOWN_BACKOFF);
            log_warn!(
                "route {} is not redialling: every route is down at once, so the uplink is the likely cause (monitor reports {:?})",
                index + 1,
                telemetry.uplink.state()
            );
        }
        if dialing.is_none() && !uplink_down && next_redial.is_some_and(|at| Instant::now() >= at) {
            next_redial = None;
            let (result_tx, result_rx) = mpsc::channel();
            let attempt = dialer.clone();
            match thread::Builder::new()
                .name(format!("gamepath-redial-{}", index + 1))
                .spawn(move || {
                    // The worker may already have stopped; nothing depends on
                    // this send arriving.
                    let _ = result_tx.send(attempt.open());
                }) {
                Ok(_) => {
                    dialing = Some(ReconnectAttempt::new(result_rx));
                    log_info!("route {} is reconnecting", index + 1);
                    statuses.lock().unwrap()[index].last_error = Some("reconnecting".to_owned());
                }
                Err(error) => {
                    backoff = next_backoff(backoff);
                    next_redial = Some(Instant::now() + backoff);
                    statuses.lock().unwrap()[index].last_error =
                        Some(format!("could not start a reconnect attempt: {error}"));
                }
            }
        }
        drain_send_queue(
            &commands,
            index,
            &telemetry.queue_depth,
            &telemetry.dropped,
            &telemetry.stale_dropped,
            |frame| (frame.len(), path.send_frame(frame)),
            |length, result| record_path_send(&statuses, index, length, result),
        );
        // A transport that has established it is gone will not answer a probe
        // either, so waiting three of them out only costs the user the traffic
        // handed to a socket that cannot carry it. The probe machinery still
        // runs; this only stops the dispatcher choosing this path meanwhile.
        if path.transport_failed() && !reported_transport_failure {
            reported_transport_failure = true;
            failures = failures.max(HEALTH_FAILURE_THRESHOLD);
            publish_path_health(&telemetry.healthy_mask, index, false);
            update_path_status(
                &statuses,
                index,
                Err("the transport underneath this route is gone".to_owned()),
            );
            schedule_redial(failures, backoff, &mut next_redial);
            log_warn!(
                "session {session_id} route {} reported its transport gone; redialling without waiting for probes to time out",
                index + 1
            );
        }
        if Instant::now() >= next_probe && pending_probe.is_none() {
            let sequence = sequences.fetch_add(1, Ordering::Relaxed);
            let result = (|| {
                let header = FrameHeader {
                    flags: FLAG_CONTROL,
                    client_id,
                    session_id,
                    sequence,
                };
                let overlay = crypto
                    .seal_client(header, &gamepath_engine::protocol::probe_request(sequence))?;
                {
                    let mut current = statuses.lock().unwrap();
                    current[index].packets_sent += 1;
                    current[index].probes_sent += 1;
                }
                path.send_probe(&overlay)
            })();
            match result {
                Ok(()) => pending_probe = Some((sequence, Instant::now())),
                Err(error) => {
                    statuses.lock().unwrap()[index].probes_lost += 1;
                    update_scheduler_probe(
                        &scheduler_metrics,
                        &decision_mask,
                        fallback_mask,
                        index,
                        None,
                        strategy,
                        session_id,
                    );
                    update_path_status(&statuses, index, Err(error));
                    failures += 1;
                    if failures == HEALTH_FAILURE_THRESHOLD - 1 {
                        log_warn!(
                            "session {session_id} route {} degraded after {failures} consecutive \
                             probe send failures; still carrying duplicated traffic",
                            index + 1
                        );
                    } else if failures == HEALTH_FAILURE_THRESHOLD {
                        log_warn!(
                            "session {session_id} route {} unavailable after {failures} consecutive \
                             probe send failures; dispatcher is using available alternatives",
                            index + 1
                        );
                    }
                    if failures >= HEALTH_FAILURE_THRESHOLD {
                        publish_path_health(&telemetry.healthy_mask, index, false);
                    }
                    schedule_redial(failures, backoff, &mut next_redial);
                    next_probe = Instant::now() + PROBE_INTERVAL_DEGRADED;
                }
            }
        }
        match path.receive_frames(WORKER_RECEIVE_TIMEOUT) {
            Ok(frames) => {
                for frame in frames {
                    if let Ok((header, plaintext)) = crypto.open_server(&frame) {
                        if header.client_id != client_id || header.session_id != session_id {
                            continue;
                        }
                        if header.flags & FLAG_CONTROL != 0 {
                            if let Some((sequence, started)) = pending_probe {
                                if header.flags & FLAG_SERVER_TO_CLIENT == 0
                                    || !gamepath_engine::protocol::probe_reply_matches(
                                        &plaintext,
                                        sequence,
                                        !correlated_probes,
                                    )
                                {
                                    // Not the outstanding probe's reply, but it
                                    // may answer one already written off, and
                                    // that measurement is the one the deadline
                                    // most needs.
                                    if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
                                        if let Some(elapsed) =
                                            take_late_probe_reply(&mut expired_probes, &plaintext)
                                        {
                                            rtt.record(elapsed);
                                        }
                                    }
                                    continue;
                                }
                                if plaintext.len() == 12 {
                                    correlated_probes = true;
                                } else if !warned_legacy_probes {
                                    log_warn!(
                                        "route {} relay uses legacy probe replies; update the relay \
                                         for accurate RTT matching after timeouts",
                                        index + 1
                                    );
                                    warned_legacy_probes = true;
                                }
                                pending_probe = None;
                                let elapsed = started.elapsed();
                                rtt.record(elapsed);
                                let latency = elapsed.as_secs_f64() * 1000.0;
                                statuses.lock().unwrap()[index].probes_received += 1;
                                update_path_status(&statuses, index, Ok(latency));
                                // An authenticated pong is the one unambiguous
                                // sign this path is carrying traffic, so this
                                // is where it rejoins the dispatcher, and where
                                // any pending reconnect is called off.
                                publish_path_health(&telemetry.healthy_mask, index, true);
                                if failures >= HEALTH_FAILURE_THRESHOLD - 1 {
                                    log_info!(
                                        "route {} is carrying traffic again after {failures} \
                                         failed check(s), {latency:.0} ms",
                                        index + 1
                                    );
                                }
                                failures = 0;
                                backoff = RECONNECT_BACKOFF_MIN;
                                next_redial = None;
                                // The path works, so the next outage gets a
                                // cheap first attempt again.
                                dialer.allow_cheap_reopen();
                                if let Some(attempt) = dialing.as_mut() {
                                    attempt.recovered();
                                }
                                update_scheduler_probe(
                                    &scheduler_metrics,
                                    &decision_mask,
                                    fallback_mask,
                                    index,
                                    Some(latency),
                                    strategy,
                                    session_id,
                                );
                                match latency_watch.observe(latency, Instant::now()) {
                                    Some(LatencyEvent::Degraded {
                                        baseline_ms,
                                        observed_ms,
                                    }) => log_warn!(
                                        "session {session_id} route {} relay RTT degraded: \
                                         {observed_ms:.0} ms vs {baseline_ms:.0} ms baseline; \
                                         q={} drop={} uplink={:?}",
                                        index + 1,
                                        telemetry.queue_depth[index].load(Ordering::Relaxed),
                                        telemetry.dropped[index].load(Ordering::Relaxed),
                                        telemetry.uplink.state()
                                    ),
                                    Some(LatencyEvent::Recovered {
                                        baseline_ms,
                                        peak_ms,
                                        duration,
                                    }) => log_info!(
                                        "session {session_id} route {} relay RTT recovered after \
                                         {:.1} s (baseline {baseline_ms:.0} ms, peak {peak_ms:.0} ms)",
                                        index + 1,
                                        duration.as_secs_f64()
                                    ),
                                    None => {}
                                }
                                next_probe = Instant::now() + PROBE_INTERVAL;
                            } else if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
                                // Nothing outstanding: a control frame now can
                                // only be answering a probe already given up
                                // on, in the gap before the next one goes out.
                                if let Some(elapsed) =
                                    take_late_probe_reply(&mut expired_probes, &plaintext)
                                {
                                    rtt.record(elapsed);
                                }
                            }
                        } else if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
                            record_path_receive(&statuses, index, frame.len());
                            // Blocking on a saturated inbound queue would stall
                            // this path's probes and timers, which is how a
                            // busy path ends up reported as a dead one.
                            if let Err(mpsc::TrySendError::Full(_)) =
                                ingress.enqueue_authenticated(&header, plaintext, &inbound)
                            {
                                telemetry.dropped[index].fetch_add(1, Ordering::Relaxed);
                                telemetry.inbound_dropped[index].fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            // Not a health verdict: Windows surfaces an earlier send's ICMP
            // unreachable on the next read, and a restarting node's next reply
            // disproves it. The probe timeout below is what takes a path out of
            // the dispatcher, so a transient like this cannot interrupt
            // duplication.
            Err(error) => update_path_status(&statuses, index, Err(error)),
        }
        // Setup latency is fixed once a path is up, and this lock is shared by
        // every path worker, so it is taken only when the value actually moves.
        let setup_latency = path.setup_latency_ms();
        if setup_latency != published_setup_latency {
            let mut current = statuses.lock().unwrap();
            current[index].handshake_ms = setup_latency;
            current[index].handshake_round_trips = path.setup_round_trips();
            published_setup_latency = setup_latency;
        }
        if let Some((sequence, started)) =
            pending_probe.filter(|(_, started)| started.elapsed() > rtt.timeout())
        {
            pending_probe = None;
            remember_expired_probe(&mut expired_probes, sequence, started);
            statuses.lock().unwrap()[index].probes_lost += 1;
            update_scheduler_probe(
                &scheduler_metrics,
                &decision_mask,
                fallback_mask,
                index,
                None,
                strategy,
                session_id,
            );
            let note = path.health_note();
            failures += 1;
            schedule_redial(failures, backoff, &mut next_redial);
            if failures == HEALTH_FAILURE_THRESHOLD - 1 {
                log_warn!(
                    "session {session_id} route {} degraded after {failures} consecutive health \
                     timeouts; still carrying duplicated traffic{}",
                    index + 1,
                    note.as_deref()
                        .map(|note| format!(": {note}"))
                        .unwrap_or_default()
                );
            } else if failures == HEALTH_FAILURE_THRESHOLD {
                log_warn!(
                    "session {session_id} route {} unavailable after {failures} consecutive health \
                     timeouts; dispatcher is using available alternatives{}",
                    index + 1,
                    note.as_deref()
                        .map(|note| format!(": {note}"))
                        .unwrap_or_default()
                );
            }
            // Only a run of unanswered probes takes the path out of service.
            // A single loss has already been recorded against the path's score
            // above, which is the proportionate response to it.
            if failures >= HEALTH_FAILURE_THRESHOLD {
                publish_path_health(&telemetry.healthy_mask, index, false);
                update_path_status(
                    &statuses,
                    index,
                    Err(match note {
                        Some(note) => format!("path health check timed out: {note}"),
                        None => "path health check timed out".to_owned(),
                    }),
                );
            }
            next_probe = Instant::now() + PROBE_INTERVAL_DEGRADED;
        }
    }
}
