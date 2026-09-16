//! Whether a path is carrying traffic, and what the dispatcher does about it.
//!
//! Health and scheduling are published separately - a lock-free mask the
//! dispatcher reads per packet, and the scheduler's own pick - so this is also
//! where the two are reconciled.

use super::state::PathSessionStatus;
use gamepath_engine::log_info;
use gamepath_engine::scheduler::{Decision, PathMetrics, Strategy, choose_paths_with_incumbent};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Gap between health probes on a path that is answering. One small request
/// and reply per second keeps a route's RTT current without turning an idle
/// game session into meaningful background data usage. A route in doubt uses
/// the shorter degraded interval below, so recovery is still noticed quickly.
pub(crate) const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Gap between probes on a path that has missed one.
///
/// This is a game client, so the time between a path coming back and GamePath
/// noticing is time the player spends on fewer routes than they have. At the
/// healthy cadence a recovered path waits up to half a second to be asked
/// again; probing hard while a path is in doubt cuts that to milliseconds, and
/// costs nothing the rest of the time because a healthy path never uses it.
pub(crate) const PROBE_INTERVAL_DEGRADED: Duration = Duration::from_millis(150);

/// Gap between probes on a healthy path the scheduler is not currently using.
///
/// A standby path is measured so it can be trusted in a failover, and at one
/// probe a second it was being measured cold. Observed on a live session: the
/// same WireGuard route reported 52 ms with 3 ms of jitter in the minutes it
/// carried traffic and 70 ms with 17 ms of jitter in the minutes it did not -
/// an 18 ms swing that had nothing to do with the path's quality and
/// everything to do with a provider exit that lets an idle session go cold.
/// The two other routes in the same session, on identical code, moved by 1 and
/// 2 ms, so this is the far end rather than anything measurable here.
///
/// That is self-reinforcing, which is what makes it worth spending packets on:
/// the score decides what carries traffic, so a route that measures badly
/// while idle stays idle and keeps measuring badly. The route above was the
/// joint-fastest in the set whenever it was actually used, and was passed over
/// as a 70 ms path.
///
/// Probes are the right thing to send. They are control frames the relay
/// answers rather than forwards, so nothing reaches the Internet, and the
/// extra samples sharpen the estimate they are keeping warm.
///
/// 250 ms is four probes a second where there was one, against the ~140
/// packets a second the same route sees while carrying traffic. It is a
/// starting point rather than a derived figure: what makes an idle session go
/// cold at the far end is the provider's business, so the useful number is
/// whichever closes the measured gap, and this is the smallest step likely to.
/// It stays no more aggressive than [`PROBE_INTERVAL_DEGRADED`], because a
/// path that has actually missed a reply is the one that deserves the hardest
/// probing.
pub(crate) const PROBE_INTERVAL_STANDBY: Duration = Duration::from_millis(250);

const _: () = assert!(
    PROBE_INTERVAL_STANDBY.as_millis() < PROBE_INTERVAL.as_millis(),
    "a standby path would be measured less often than one carrying traffic"
);
const _: () = assert!(
    PROBE_INTERVAL_STANDBY.as_millis() >= PROBE_INTERVAL_DEGRADED.as_millis(),
    "a standby path would out-probe one that has actually missed a reply"
);

/// The gap before the next probe on a healthy path, given whether the
/// scheduler currently has it carrying traffic.
///
/// A carrying path is already warm and already measured by its own traffic, so
/// it keeps the slow cadence; a standby path pays for its own accuracy.
pub(crate) fn healthy_probe_interval(carrying: bool) -> Duration {
    if carrying {
        PROBE_INTERVAL
    } else {
        PROBE_INTERVAL_STANDBY
    }
}

/// Consecutive unanswered probes before a path is declared down.
///
/// One lost probe is not a failure. The control probe is a bare UDP datagram on
/// a real network, and losing one occasionally is ordinary: over an 85-minute
/// session a healthy WireGuard route lost 57 of them, roughly one every ninety
/// seconds. Acting on the first loss took that route out of the dispatcher and
/// showed it offline every time, which reads as the tunnel dropping and
/// reconnecting when nothing of the sort happened.
///
/// The probe deadline follows the path's own round trip
/// ([`gamepath_engine::rtt`]), so on a healthy route a cycle costs a few
/// hundred milliseconds rather than two seconds. That is what lets this be a
/// real threshold instead of a trade against detection speed: three misses on a
/// 60 ms path resolve inside a second, where two misses used to take three and
/// a half.
///
/// The scheduler still sees the first loss immediately through `record_loss`,
/// so a path that starts dropping packets is de-prioritised by its score
/// straight away. This governs only the harder decision to stop using it.
pub(crate) const HEALTH_FAILURE_THRESHOLD: u32 = 3;

const _: () = assert!(
    HEALTH_FAILURE_THRESHOLD >= 2,
    "one lost probe is ordinary packet loss, not a path failure"
);

/// Records whether `index` is carrying traffic, so the dispatcher can leave a
/// dead path out of the pick without reading the status mutex per packet.
pub(crate) fn publish_path_health(healthy_mask: &AtomicU64, index: usize, healthy: bool) {
    let Some(bit) = 1_u64.checked_shl(index as u32) else {
        return;
    };
    if healthy {
        healthy_mask.fetch_or(bit, Ordering::Release);
    } else {
        healthy_mask.fetch_and(!bit, Ordering::Release);
    }
}

/// The paths a packet is actually dispatched to: the scheduler's pick,
/// narrowed to the ones known to be carrying traffic.
///
/// If the scheduler's pick has gone down, immediately use the healthy routes.
/// Health and scheduling are published separately, so their snapshots can
/// disagree during failure or recovery. Keep the original pick only when no
/// route has proved healthy, including startup before the first probe reply.
pub(crate) fn selected_paths(decision: u64, healthy: u64) -> u64 {
    if decision & healthy != 0 {
        decision & healthy
    } else if healthy != 0 {
        healthy
    } else {
        decision
    }
}

pub(crate) fn update_scheduler_probe(
    metrics: &Mutex<Vec<PathMetrics>>,
    decision_mask: &AtomicU64,
    fallback_mask: u64,
    index: usize,
    latency_ms: Option<f64>,
    strategy: Strategy,
    session_id: u64,
) {
    let mut metrics = metrics.lock().unwrap();
    let Some(path) = metrics.get_mut(index) else {
        return;
    };
    match latency_ms {
        Some(latency) => path.record_probe(latency),
        None => path.record_loss(),
    }
    // The routes already carrying traffic, so the scheduler can keep them
    // through a tie instead of re-deciding the whole set on every probe. This
    // is the only writer of `decision_mask`, and it holds `metrics`, so the
    // value read here is still the one the store below replaces.
    let previous = decision_mask.load(Ordering::Acquire);
    let incumbent: Vec<&str> = metrics
        .iter()
        .filter(|path| previous & bit_for_path(&path.id) != 0)
        .map(|path| path.id.as_str())
        .collect();
    let decision = choose_paths_with_incumbent(&metrics, strategy, &incumbent);
    let next = mask_for_decision(decision, fallback_mask);
    decision_mask.store(next, Ordering::Release);
    if previous != next {
        let reason = latency_ms
            .map(|latency| format!("route {} probe {latency:.0} ms", index + 1))
            .unwrap_or_else(|| format!("route {} probe lost", index + 1));
        let snapshot = metrics
            .iter()
            .enumerate()
            .map(|(route, path)| {
                format!(
                    "{}:rtt={:.0}ms jitter={:.0}ms loss-ewma={:.0}% score={:.0}",
                    route + 1,
                    path.latency_ms,
                    path.jitter_ms,
                    path.loss_ratio * 100.0,
                    path.score()
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        log_info!(
            "session {session_id} scheduler routes {} -> {} after {reason}; {snapshot}",
            route_mask(previous),
            route_mask(next)
        );
    }
}

fn route_mask(mask: u64) -> String {
    let routes = (0..64)
        .filter(|index| mask & (1_u64 << index) != 0)
        .map(|index| (index + 1).to_string())
        .collect::<Vec<_>>();
    if routes.is_empty() {
        "none".to_owned()
    } else {
        routes.join("+")
    }
}

/// A path id is its route index, which is also its bit in every mask the data
/// plane reads. One conversion so the masks and the incumbent set cannot drift.
fn bit_for_path(path_id: &str) -> u64 {
    path_id
        .parse::<u32>()
        .ok()
        .and_then(|index| 1_u64.checked_shl(index))
        .unwrap_or(0)
}

pub(crate) fn mask_for_decision(decision: Decision, fallback_mask: u64) -> u64 {
    let mask = match decision {
        Decision::Drop => 0,
        Decision::Single { path_id } => bit_for_path(&path_id),
        Decision::Duplicate { path_ids } => path_ids
            .into_iter()
            .fold(0, |mask, path_id| mask | bit_for_path(&path_id)),
    };
    if mask == 0 { fallback_mask } else { mask }
}

pub(crate) fn update_path_status(
    statuses: &Mutex<Vec<PathSessionStatus>>,
    index: usize,
    result: Result<f64, String>,
) {
    let mut current = statuses.lock().unwrap();
    let status = &mut current[index];
    match result {
        Ok(latency) => {
            status.reachable = true;
            status.latency_ms = Some(latency);
            status.packets_received += 1;
            status.last_error = None;
        }
        Err(error) => {
            status.reachable = false;
            status.last_error = Some(error);
        }
    }
}

pub(crate) fn record_path_send(
    statuses: &Mutex<Vec<PathSessionStatus>>,
    index: usize,
    sent_bytes: usize,
    result: Result<(), String>,
) {
    let mut current = statuses.lock().unwrap();
    let status = &mut current[index];
    status.packets_sent += 1;
    status.bytes_sent += sent_bytes as u64;
    if let Err(error) = result {
        status.last_error = Some(error);
    }
}

pub(crate) fn record_path_receive(
    statuses: &Mutex<Vec<PathSessionStatus>>,
    index: usize,
    received_bytes: usize,
) {
    let mut current = statuses.lock().unwrap();
    let status = &mut current[index];
    status.packets_received += 1;
    status.bytes_received += received_bytes as u64;
}

/// How long a timed-out probe is remembered so a reply arriving late can still
/// correct the deadline estimate.
///
/// Twice [`gamepath_engine::rtt::MAX_TIMEOUT`]. Past that the path has already
/// been taken out of service and a redial matters more than another sample, and
/// a reply that late produces the ceiling deadline either way.
const LATE_REPLY_WINDOW: Duration = Duration::from_secs(3);

/// Most written-off probes held at once. A degraded path probes every
/// [`PROBE_INTERVAL_DEGRADED`], which fits comfortably inside this, so
/// [`LATE_REPLY_WINDOW`] is what actually expires an entry and this only bounds
/// the memory.
const LATE_REPLY_CAPACITY: usize = 32;

/// Remembers a probe that missed its deadline, so its reply is still
/// recognisable if it turns up.
pub(crate) fn remember_expired_probe(
    expired: &mut Vec<(u64, Instant)>,
    sequence: u64,
    started: Instant,
) {
    expired.retain(|(_, sent)| sent.elapsed() < LATE_REPLY_WINDOW);
    if expired.len() >= LATE_REPLY_CAPACITY {
        expired.remove(0);
    }
    expired.push((sequence, started));
}

/// Matches a control frame against probes already written off, returning how
/// long that probe really took and forgetting it.
///
/// The probe stays lost. It missed its deadline, the scheduler has scored it
/// that way, and none of the health accounting is revisited. What this recovers
/// is the *measurement*.
///
/// Without it the estimator only ever sees replies that beat the current
/// deadline, which holds its smoothed round trip and variation below the truth
/// and keeps the deadline pinned near its floor - on exactly the paths whose
/// replies are slow enough to need it widened, so the next probe times out for
/// the same reason. Measured on a live L2TP/IPsec route whose round trip
/// doubled under congestion while two WireGuard routes on the same uplink did
/// not move at all.
///
/// A legacy untagged `pong` is deliberately not matched: it cannot say which
/// probe it answers, so crediting it to one would invent a round trip rather
/// than measure one.
pub(crate) fn take_late_probe_reply(
    expired: &mut Vec<(u64, Instant)>,
    reply: &[u8],
) -> Option<Duration> {
    let position = expired.iter().position(|(sequence, _)| {
        gamepath_engine::protocol::probe_reply_matches(reply, *sequence, false)
    })?;
    let (_, started) = expired.remove(position);
    Some(started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamepath_engine::scheduler::choose_paths;

    /// The measurement this exists for: a standby route was reported 18 ms
    /// slower and 14 ms jitterier than the same route carrying traffic, purely
    /// because it was idle. It has to be measured more often than a carrying
    /// route or the failover decision keeps being made on a cold path.
    #[test]
    fn a_standby_path_is_measured_more_often_than_a_carrying_one() {
        assert!(healthy_probe_interval(false) < healthy_probe_interval(true));
        assert_eq!(healthy_probe_interval(true), PROBE_INTERVAL);
        assert_eq!(healthy_probe_interval(false), PROBE_INTERVAL_STANDBY);
    }

    /// Warming a standby path must never outrank finding out whether a path
    /// that just missed a reply is coming back.
    #[test]
    fn a_path_in_doubt_is_still_probed_hardest() {
        assert!(PROBE_INTERVAL_DEGRADED <= healthy_probe_interval(false));
        assert!(PROBE_INTERVAL_DEGRADED < healthy_probe_interval(true));
    }

    /// Standby probing is an accuracy cost, not a bandwidth one: it has to stay
    /// a small multiple of the carrying cadence rather than approach the rate
    /// of real traffic.
    #[test]
    fn standby_probing_stays_a_background_cost() {
        let carrying = PROBE_INTERVAL.as_millis();
        let standby = healthy_probe_interval(false).as_millis();
        assert!(
            carrying / standby <= 8,
            "a standby path probes {}x as often as a carrying one",
            carrying / standby
        );
    }

    /// A redial is worth making only when something proves the uplink works.
    /// Two independent providers do not fail in the same second, so when no
    /// path is up the machine's own link is the cause and redialling each path
    /// separately just burns handshakes over a link that cannot carry them.
    /// A single lost probe is ordinary on a real network. Acting on it took a
    /// healthy WireGuard route out of service roughly once every ninety seconds
    /// and reported it as a disconnect.
    #[test]
    fn one_lost_probe_does_not_take_a_path_out_of_service() {
        let mask = AtomicU64::new(0);
        publish_path_health(&mask, 0, true);
        // What the worker does on each consecutive timeout: it stays up until
        // the threshold is reached, then goes down and stays down.
        let expected: Vec<bool> = (1..=HEALTH_FAILURE_THRESHOLD + 1)
            .map(|failures| failures < HEALTH_FAILURE_THRESHOLD)
            .collect();
        let mut failures = 0_u32;
        for expected_up in expected {
            failures += 1;
            if failures >= HEALTH_FAILURE_THRESHOLD {
                publish_path_health(&mask, 0, false);
            }
            assert_eq!(
                mask.load(Ordering::Acquire) & 1 != 0,
                expected_up,
                "after {failures} consecutive lost probe(s)"
            );
        }
    }

    /// Detection has to be quick enough to matter in a game. The deadline is
    /// the path's own, so this is what the threshold actually costs on a
    /// healthy route rather than on the old worst-case constant.
    #[test]
    fn a_dead_path_on_a_fast_route_is_noticed_within_a_second() {
        // A settled 60 ms route sits at the estimator's floor, and a missed
        // probe drops the gap to the degraded interval.
        let cycle = gamepath_engine::rtt::MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let detection = cycle * HEALTH_FAILURE_THRESHOLD;
        assert!(
            detection <= Duration::from_secs(2),
            "a dead path would take {detection:?} to notice"
        );
    }

    /// Even a path slow enough to sit at the ceiling has to resolve in seconds.
    #[test]
    fn a_dead_path_on_the_slowest_route_still_resolves_in_seconds() {
        let cycle = gamepath_engine::rtt::MAX_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let detection = cycle * HEALTH_FAILURE_THRESHOLD;
        assert!(
            detection <= Duration::from_secs(6),
            "the worst case is {detection:?}"
        );
    }

    /// A stream-carried path waits out one retransmission before calling a
    /// probe lost, so it is slower to declare dead. That is the point, but it
    /// still has to land inside a few seconds.
    #[test]
    fn a_dead_stream_path_costs_more_to_notice_but_still_resolves() {
        let cycle = gamepath_engine::rtt::STREAMED_MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let detection = cycle * HEALTH_FAILURE_THRESHOLD;
        assert!(
            detection > gamepath_engine::rtt::MIN_TIMEOUT * HEALTH_FAILURE_THRESHOLD,
            "the whole point is that it waits longer"
        );
        assert!(
            detection <= Duration::from_secs(4),
            "a dead stream path would take {detection:?} to notice"
        );
    }

    /// Raising the threshold only pays for itself because the deadline shrank.
    /// If someone puts the constant back, this says why that is not free.
    #[test]
    fn the_threshold_is_affordable_because_the_deadline_adapts() {
        let adaptive = (gamepath_engine::rtt::MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED)
            * HEALTH_FAILURE_THRESHOLD;
        let fixed = (Duration::from_millis(1500) + PROBE_INTERVAL) * HEALTH_FAILURE_THRESHOLD;
        assert!(
            adaptive * 4 < fixed,
            "the adaptive deadline should be far cheaper: {adaptive:?} vs {fixed:?}"
        );
    }

    #[test]
    fn the_health_mask_tracks_each_path_independently() {
        let mask = AtomicU64::new(0);
        publish_path_health(&mask, 0, true);
        publish_path_health(&mask, 2, true);
        assert_eq!(mask.load(Ordering::Acquire), 0b101);
        publish_path_health(&mask, 0, false);
        assert_eq!(mask.load(Ordering::Acquire), 0b100);
        // Out of range is ignored rather than corrupting the mask.
        publish_path_health(&mask, 64, true);
        assert_eq!(mask.load(Ordering::Acquire), 0b100);
    }

    #[test]
    fn a_dead_route_is_left_out_of_the_pick_but_never_leaves_it_empty() {
        // Two routes picked, only the second one up.
        assert_eq!(selected_paths(0b11, 0b10), 0b10);
        // Nothing reported healthy yet: the scheduler's pick still stands, so
        // the first packets of a session are not dropped while probes fly.
        assert_eq!(selected_paths(0b11, 0b00), 0b11);
        // A stale pick must not blackhole packets while another route is up.
        assert_eq!(selected_paths(0b01, 0b10), 0b10);
        assert_eq!(selected_paths(0b11, 0b11), 0b11);
    }

    #[test]
    fn openvpn_failure_and_recovery_keep_the_other_route_available() {
        let healthy = AtomicU64::new(0b11);
        let stale_openvpn_pick = 0b10;
        publish_path_health(&healthy, 1, false);
        // The scheduler has not republished yet. WireGuard must carry traffic
        // immediately, without waiting for another probe or reconnect.
        assert_eq!(
            selected_paths(stale_openvpn_pick, healthy.load(Ordering::Acquire)),
            0b01
        );
        publish_path_health(&healthy, 1, true);
        // Recovery allows both routes to carry copies again.
        assert_eq!(selected_paths(0b11, healthy.load(Ordering::Acquire)), 0b11);
        publish_path_health(&healthy, 0, false);
        assert_eq!(selected_paths(0b01, healthy.load(Ordering::Acquire)), 0b10);
    }

    #[test]
    fn dispatch_never_chooses_a_dead_route_when_a_healthy_route_exists() {
        // Cover every scheduler/health snapshot for four independent routes,
        // including an empty scheduler pick during initialization.
        for decision in 0_u64..16 {
            for healthy in 1_u64..16 {
                let selected = selected_paths(decision, healthy);
                assert_ne!(selected, 0);
                assert_eq!(selected & !healthy, 0);
            }
        }
    }

    fn probe_reply(sequence: u64) -> Vec<u8> {
        gamepath_engine::protocol::probe_response(&gamepath_engine::protocol::probe_request(
            sequence,
        ))
        .expect("a tagged request has a tagged response")
    }

    fn ago(duration: Duration) -> Instant {
        Instant::now()
            .checked_sub(duration)
            .expect("the test machine has been up longer than this")
    }

    /// What the whole mechanism is for. A path whose replies keep arriving
    /// just past the deadline has to be able to widen it; otherwise every
    /// probe times out for the same reason and the estimator never hears the
    /// sample that would fix it.
    #[test]
    fn late_replies_let_the_deadline_catch_up_with_a_slowing_path() {
        use gamepath_engine::rtt::{MAX_TIMEOUT, MIN_TIMEOUT, RttEstimator};
        let mut settled = RttEstimator::default();
        for _ in 0..40 {
            settled.record(Duration::from_millis(50));
        }
        assert_eq!(settled.timeout(), MIN_TIMEOUT);

        // Congestion doubles the path. These replies land past the deadline,
        // so they are exactly the ones that used to be discarded.
        let slow = Duration::from_millis(260);
        assert!(slow > settled.timeout());

        let mut learning = settled;
        for _ in 0..20 {
            learning.record(slow);
        }
        assert!(
            learning.timeout() > slow,
            "a path answering in {slow:?} still gets a {:?} deadline",
            learning.timeout()
        );
        assert!(learning.timeout() <= MAX_TIMEOUT);
    }

    #[test]
    fn a_late_reply_is_matched_to_the_probe_it_answers() {
        let mut expired = Vec::new();
        remember_expired_probe(&mut expired, 7, ago(Duration::from_millis(300)));
        remember_expired_probe(&mut expired, 8, Instant::now());
        let elapsed =
            take_late_probe_reply(&mut expired, &probe_reply(7)).expect("the reply names probe 7");
        assert!(elapsed >= Duration::from_millis(300), "got {elapsed:?}");
        // Taken rather than left to be counted twice.
        assert_eq!(take_late_probe_reply(&mut expired, &probe_reply(7)), None);
        // And the unrelated probe is untouched.
        assert!(take_late_probe_reply(&mut expired, &probe_reply(8)).is_some());
    }

    /// A legacy relay's bare `pong` cannot say which probe it answers, so
    /// crediting it to one would invent a round trip instead of measuring one.
    #[test]
    fn an_untagged_reply_is_never_credited_to_a_probe() {
        let mut expired = Vec::new();
        remember_expired_probe(&mut expired, 3, ago(Duration::from_millis(250)));
        assert_eq!(take_late_probe_reply(&mut expired, b"pong"), None);
        assert_eq!(take_late_probe_reply(&mut expired, &probe_reply(4)), None);
        assert!(take_late_probe_reply(&mut expired, &probe_reply(3)).is_some());
    }

    #[test]
    fn written_off_probes_cannot_grow_without_bound() {
        let mut expired = Vec::new();
        let last = LATE_REPLY_CAPACITY as u64 * 3;
        for sequence in 0..=last {
            remember_expired_probe(&mut expired, sequence, Instant::now());
        }
        assert!(expired.len() <= LATE_REPLY_CAPACITY, "{}", expired.len());
        // The newest are the ones still worth answering.
        assert!(take_late_probe_reply(&mut expired, &probe_reply(last)).is_some());
        assert_eq!(take_late_probe_reply(&mut expired, &probe_reply(0)), None);
    }

    #[test]
    fn a_probe_older_than_the_window_is_forgotten() {
        let mut expired = Vec::new();
        remember_expired_probe(
            &mut expired,
            1,
            ago(LATE_REPLY_WINDOW + Duration::from_millis(1)),
        );
        // Pruning happens as the next one is remembered.
        remember_expired_probe(&mut expired, 2, Instant::now());
        assert_eq!(take_late_probe_reply(&mut expired, &probe_reply(1)), None);
        assert!(take_late_probe_reply(&mut expired, &probe_reply(2)).is_some());
    }

    /// The window has to outlast the widest deadline a probe can be given, or
    /// the reply to the slowest probe would be forgotten before it arrived.
    #[test]
    fn the_late_reply_window_outlasts_the_widest_deadline() {
        assert!(LATE_REPLY_WINDOW >= gamepath_engine::rtt::MAX_TIMEOUT * 2);
        // And the window, not the capacity, is what expires an entry even when
        // a degraded path is probing as fast as it ever does.
        let in_flight = LATE_REPLY_WINDOW.as_millis() / PROBE_INTERVAL_DEGRADED.as_millis();
        assert!(
            (in_flight as usize) < LATE_REPLY_CAPACITY,
            "{in_flight} probes can be outstanding, capacity is {LATE_REPLY_CAPACITY}"
        );
    }

    #[test]
    fn scheduler_mask_keeps_single_route_armed_after_loss() {
        let mut route = PathMetrics::new("0");
        route.record_probe(40.0);
        route.record_loss();
        assert_eq!(
            mask_for_decision(choose_paths(&[route], Strategy::Adaptive), 0b1),
            0b1
        );
    }

    #[test]
    fn scheduler_mask_keeps_two_healthy_routes_ready() {
        let mut slower = PathMetrics::new("0");
        slower.record_probe(70.0);
        let mut faster = PathMetrics::new("1");
        faster.record_probe(35.0);
        assert_eq!(
            mask_for_decision(choose_paths(&[slower, faster], Strategy::Adaptive), 0b11),
            0b11
        );
    }

    #[test]
    fn scheduler_mask_duplicates_degraded_routes() {
        let mut degraded = PathMetrics::new("0");
        degraded.record_probe(35.0);
        degraded.record_loss();
        let mut backup = PathMetrics::new("1");
        backup.record_probe(50.0);
        assert_eq!(
            mask_for_decision(choose_paths(&[degraded, backup], Strategy::Adaptive), 0b11),
            0b11
        );
    }

    #[test]
    fn scheduler_mask_falls_back_when_all_routes_are_unrated() {
        let routes = [PathMetrics::new("0"), PathMetrics::new("1")];
        assert_eq!(
            mask_for_decision(choose_paths(&routes, Strategy::Adaptive), 0b11),
            0b11
        );
    }
}
