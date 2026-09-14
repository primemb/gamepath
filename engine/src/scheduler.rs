use serde::{Deserialize, Serialize};

const SMOOTHING: f64 = 0.2;

/// Smoothing for the loss estimate, deliberately much slower than
/// [`SMOOTHING`].
///
/// [`PathMetrics::loss_ratio`] is an EWMA over a per-probe 0/1 indicator, so
/// whatever this is set to, it still settles on the path's true loss rate.
/// What it controls is how far one probe can move it, and at 0.2 one probe
/// moved it all the way to 20% — a number that then decayed through 16, 13 and
/// 10% over the following seconds.
///
/// That was not a display problem. At 200 points per unit of loss, one lost
/// probe added 40 to [`PathMetrics::score`], while the whole spread between a
/// 47 ms route and an 86 ms one is 39 points — so a single lost packet
/// outranked every latency difference in the route set and the dispatcher
/// reshuffled. Measured on a live three-route session: 50 selection changes in
/// six minutes, and one summary line reporting `loss-ewma=16%` for a route
/// that had lost exactly one probe out of sixty that minute, on a path whose
/// real loss was around 3%.
///
/// A fifth of the old step averages over roughly twenty probes, which at the
/// healthy probe cadence is a real estimate of a real rate rather than a
/// readout of the last packet. Nothing is lost on the detection side, because
/// a path that is actually failing is taken out by `consecutive_losses`
/// reaching [`LOSSES_BEFORE_INACTIVE`] — a separate, immediate signal that
/// this does not touch.
const LOSS_SMOOTHING: f64 = 0.05;

/// Consecutive lost probes before a path stops being offered to the scheduler
/// at all. This is what makes a slow loss estimate affordable: it, not
/// [`PathMetrics::loss_ratio`], is what reacts to a path that has just died.
const LOSSES_BEFORE_INACTIVE: u32 = 3;

/// Policy budget for a backup's extra RTT plus jitter, not a one-way latency
/// measurement or guarantee. Keep useful dissimilar providers in the race,
/// while avoiding extra outbound load on a severely stalled tunnel.
const ADAPTIVE_DUPLICATE_DELAY_BUDGET_MS: f64 = 100.0;

/// How much better than the route already carrying traffic a challenger has to
/// score before it takes the slot.
///
/// Ranking is otherwise memoryless: every probe reply re-sorts the whole route
/// set, so two routes within measurement noise of each other trade places on
/// whichever was measured last. Live three-route session, three consecutive
/// selections inside 2.1 seconds — `1+3`, then `1+2`, then `2+3` — decided by a
/// single point between routes all sitting at ~52 ms with no loss.
///
/// Sized from the gap the decision actually turns on, the second-best route
/// against the third: over 261 recorded selection changes its median was 1
/// point and its 90th percentile 6. Those are ties. The smallest gap that ever
/// separated genuinely different routes in the same log was 39 points, two
/// 47 ms WireGuard paths against an 86 ms L2TP one, so a margin of 8 sits well
/// inside the noise and nowhere near real signal. Replaying the recorded score
/// sequences, it suppresses about 88% of the selection changes.
///
/// It cannot delay a failover. A path that stops answering scores
/// [`f64::INFINITY`] through [`LOSSES_BEFORE_INACTIVE`], and infinity is not
/// reachable from eight; a path that genuinely degrades moves its score by far
/// more than this. The margin only ever decides ties.
const INCUMBENCY_MARGIN: f64 = 8.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    pub id: String,
    pub active: bool,
    pub samples: u64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_ratio: f64,
    #[serde(default)]
    last_latency_ms: Option<f64>,
    #[serde(default)]
    consecutive_losses: u32,
}

impl PathMetrics {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            samples: 0,
            latency_ms: 0.0,
            jitter_ms: 0.0,
            loss_ratio: 0.0,
            last_latency_ms: None,
            consecutive_losses: 0,
        }
    }

    pub fn record_probe(&mut self, latency_ms: f64) {
        let latency_ms = latency_ms.max(0.0);
        if self.last_latency_ms.is_none() {
            self.latency_ms = latency_ms;
        } else {
            let deviation = (latency_ms - self.latency_ms).abs();
            self.jitter_ms = ewma(self.jitter_ms, deviation);
            self.latency_ms = ewma(self.latency_ms, latency_ms);
        }
        // A probe that arrived is a zero in the same series a lost one
        // contributes a one to, which is what makes the ratio settle on
        // the path's real loss rate rather than drift.
        self.loss_ratio = ewma_with(self.loss_ratio, 0.0, LOSS_SMOOTHING).clamp(0.0, 1.0);
        self.samples += 1;
        self.active = true;
        self.last_latency_ms = Some(latency_ms);
        self.consecutive_losses = 0;
    }

    pub fn record_loss(&mut self) {
        self.loss_ratio = ewma_with(self.loss_ratio, 1.0, LOSS_SMOOTHING).clamp(0.0, 1.0);
        self.samples += 1;
        self.consecutive_losses = self.consecutive_losses.saturating_add(1);
        if self.consecutive_losses >= LOSSES_BEFORE_INACTIVE {
            self.active = false;
        }
    }

    pub fn score(&self) -> f64 {
        if !self.active || self.last_latency_ms.is_none() {
            return f64::INFINITY;
        }
        self.latency_ms + (self.jitter_ms * 2.0) + (self.loss_ratio * 200.0)
    }
}

fn ewma(previous: f64, sample: f64) -> f64 {
    ewma_with(previous, sample, SMOOTHING)
}

fn ewma_with(previous: f64, sample: f64, smoothing: f64) -> f64 {
    previous + smoothing * (sample - previous)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    FastestPath,
    Duplicate,
    Adaptive,
    /// Send every packet on every healthy enabled route. This is intentionally
    /// opt-in: it trades proportional bandwidth for maximum redundancy.
    AllPaths,
}

impl Strategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FastestPath => "fastest-path",
            Self::Duplicate => "duplicate",
            Self::Adaptive => "adaptive",
            Self::AllPaths => "all-paths",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Decision {
    Drop,
    Single { path_id: String },
    Duplicate { path_ids: Vec<String> },
}

/// Ranks with no incumbent, so the best-scoring routes win outright.
pub fn choose_paths(paths: &[PathMetrics], strategy: Strategy) -> Decision {
    choose_paths_with_incumbent(paths, strategy, &[])
}

/// As [`choose_paths`], but the routes in `incumbent` — the ones already
/// carrying traffic — keep their slots unless a challenger beats them by
/// [`INCUMBENCY_MARGIN`].
///
/// The discount applies to ranking only. Whether to duplicate at all still
/// reads the paths' true latency, jitter and loss, because that is a question
/// about the routes rather than about which of them was picked last time.
pub fn choose_paths_with_incumbent(
    paths: &[PathMetrics],
    strategy: Strategy,
    incumbent: &[&str],
) -> Decision {
    let holding = |path: &PathMetrics| incumbent.iter().any(|id| *id == path.id);
    // Infinity is unreachable from any finite margin, so a path taken out by
    // `LOSSES_BEFORE_INACTIVE` cannot be held by having been chosen before.
    let ranked = |path: &PathMetrics| {
        if holding(path) {
            path.score() - INCUMBENCY_MARGIN
        } else {
            path.score()
        }
    };
    let mut healthy: Vec<_> = paths
        .iter()
        .filter(|path| path.active && path.last_latency_ms.is_some())
        .collect();
    healthy.sort_by(|left, right| ranked(left).total_cmp(&ranked(right)));
    let Some(best) = healthy.first() else {
        // Keep one previously proven route armed through a total outage. A
        // Drop here becomes the dispatcher's all-path startup fallback, which
        // would multiply traffic precisely when every route is struggling.
        let last_resort = paths
            .iter()
            .filter(|path| path.last_latency_ms.is_some())
            .min_by(|left, right| {
                let cost = |path: &PathMetrics| {
                    // During a total outage, alternating failed probes only
                    // change loss estimates. Including those estimates makes
                    // the fallback bounce on every timeout without evidence
                    // that either route recovered. Hold the best last known
                    // latency/jitter route until a successful probe arrives,
                    // and prefer the one already armed when two are close.
                    let cost = path.latency_ms + path.jitter_ms * 2.0;
                    if holding(path) {
                        cost - INCUMBENCY_MARGIN
                    } else {
                        cost
                    }
                };
                cost(left).total_cmp(&cost(right))
            });
        if let Some(path) = last_resort {
            return Decision::Single {
                path_id: path.id.clone(),
            };
        }
        return Decision::Drop;
    };
    if strategy == Strategy::AllPaths {
        return if healthy.len() == 1 {
            Decision::Single {
                path_id: best.id.clone(),
            }
        } else {
            Decision::Duplicate {
                path_ids: healthy.iter().map(|path| path.id.clone()).collect(),
            }
        };
    }
    if healthy.len() == 1 || strategy == Strategy::FastestPath {
        return Decision::Single {
            path_id: best.id.clone(),
        };
    }

    // Keep two suitable paths in use BEFORE a failure. Waiting for a lost
    // health probe leaves game packets unprotected during failure detection.
    // Mild loss on both providers is not evidence of a shared uplink outage.
    // Only substantial degradation on both reduces the extra outbound load.
    let degraded = |path: &PathMetrics| path.loss_ratio >= 0.5 || path.jitter_ms >= 50.0;
    let candidates = healthy.iter().take(2).collect::<Vec<_>>();
    let all_degraded = candidates.iter().all(|path| degraded(path));
    // Latency alone is not enough here.  A path whose EWMA still looks close
    // can already have enough variation to deliver a duplicate hundreds of
    // milliseconds late, so compare the same latency-plus-jitter delivery
    // estimate used by the score (without its loss penalty).
    let delivery_delay = |path: &PathMetrics| {
        (path.latency_ms + path.jitter_ms * 2.0).max(path.last_latency_ms.unwrap_or(0.0))
    };
    let quickest_delivery = candidates
        .iter()
        .map(|path| delivery_delay(path))
        .fold(f64::INFINITY, f64::min);
    let latency_comparable = candidates
        .iter()
        .all(|path| delivery_delay(path) <= quickest_delivery + ADAPTIVE_DUPLICATE_DELAY_BUDGET_MS);
    let should_duplicate = strategy == Strategy::Duplicate || (!all_degraded && latency_comparable);
    if should_duplicate {
        Decision::Duplicate {
            path_ids: healthy.iter().take(2).map(|path| path.id.clone()).collect(),
        }
    } else {
        Decision::Single {
            path_id: best.id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(id: &str, latency: f64) -> PathMetrics {
        let mut path = PathMetrics::new(id);
        path.record_probe(latency);
        path
    }

    /// A path whose score is exactly `score`, for replaying figures recorded in
    /// a log rather than re-deriving them through the smoothing.
    fn scored(id: &str, score: f64) -> PathMetrics {
        let mut path = measured(id, score);
        path.latency_ms = score;
        path.jitter_ms = 0.0;
        path
    }

    /// Runs a recorded sequence of per-route scores through the ranking and
    /// returns how many times the set of carried routes changed.
    fn selection_changes(snapshots: &[[f64; 3]], margin_applies: bool) -> usize {
        let mut carried: Vec<String> = Vec::new();
        let mut changes = 0;
        for scores in snapshots {
            let paths: Vec<_> = scores
                .iter()
                .enumerate()
                .map(|(route, score)| scored(&route.to_string(), *score))
                .collect();
            let incumbent: Vec<&str> = if margin_applies {
                carried.iter().map(String::as_str).collect()
            } else {
                Vec::new()
            };
            let Decision::Duplicate { path_ids } =
                choose_paths_with_incumbent(&paths, Strategy::Adaptive, &incumbent)
            else {
                panic!("three healthy routes should duplicate");
            };
            let mut next = path_ids;
            next.sort();
            if !carried.is_empty() && next != carried {
                changes += 1;
            }
            carried = next;
        }
        changes
    }

    /// The recorded incident. Three consecutive selections inside 2.1 seconds on
    /// a live three-route session, every route at ~52 ms with no loss, the pick
    /// turning on one point. Replaying those scores must now settle.
    #[test]
    fn recorded_near_identical_routes_stop_trading_places() {
        // 22:31:23.679, 22:31:24.319 and 22:31:25.795.
        let recorded = [[52.0, 57.0, 58.0], [58.0, 57.0, 58.0], [58.0, 64.0, 57.0]];
        assert!(
            selection_changes(&recorded, false) > 0,
            "the recorded scores did not reproduce the flapping this guards"
        );
        assert_eq!(
            selection_changes(&recorded, true),
            0,
            "a one-point difference still moved the session between routes"
        );
    }

    #[test]
    fn a_marginally_better_challenger_does_not_take_the_slot() {
        let paths = [scored("0", 50.0), scored("1", 58.0), scored("2", 57.0)];
        let Decision::Duplicate { path_ids } =
            choose_paths_with_incumbent(&paths, Strategy::Adaptive, &["0", "1"])
        else {
            panic!("three healthy routes should duplicate");
        };
        assert!(
            path_ids.contains(&"1".to_owned()),
            "a route carrying traffic lost its slot to one point: {path_ids:?}"
        );
    }

    /// And the margin must not become a lock. A route that is genuinely better
    /// still takes the slot, or hysteresis would cost exactly the latency the
    /// scheduler exists to find.
    #[test]
    fn a_clearly_better_challenger_still_takes_the_slot() {
        let paths = [scored("0", 50.0), scored("1", 58.0), scored("2", 40.0)];
        let Decision::Duplicate { path_ids } =
            choose_paths_with_incumbent(&paths, Strategy::Adaptive, &["0", "1"])
        else {
            panic!("three healthy routes should duplicate");
        };
        assert_eq!(path_ids.len(), 2);
        assert!(
            path_ids.contains(&"2".to_owned()),
            "a route 18 points better was kept out by incumbency: {path_ids:?}"
        );
    }

    /// The live spread this was sized against: two 47 ms WireGuard routes and an
    /// 86 ms L2TP one. Incumbency must be nowhere near wide enough to hold the
    /// slow route in the pick.
    #[test]
    fn incumbency_is_narrower_than_a_real_route_difference() {
        let paths = [scored("0", 47.0), scored("1", 47.0), scored("2", 86.0)];
        let Decision::Duplicate { path_ids } =
            choose_paths_with_incumbent(&paths, Strategy::Adaptive, &["2"])
        else {
            panic!("three healthy routes should duplicate");
        };
        assert!(
            !path_ids.contains(&"2".to_owned()),
            "incumbency held an 86 ms route against two 47 ms ones: {path_ids:?}"
        );
    }

    /// The property that makes the margin affordable: it ranks, and a path taken
    /// out by consecutive losses is not ranked at all.
    #[test]
    fn incumbency_cannot_hold_a_path_that_stopped_answering() {
        let mut failing = measured("0", 40.0);
        for _ in 0..LOSSES_BEFORE_INACTIVE {
            failing.record_loss();
        }
        let paths = [failing, measured("1", 70.0), measured("2", 75.0)];
        let decision = choose_paths_with_incumbent(&paths, Strategy::Adaptive, &["0"]);
        let Decision::Duplicate { path_ids } = decision else {
            panic!("two healthy routes remain, so they should duplicate");
        };
        assert!(
            !path_ids.contains(&"0".to_owned()),
            "a dead route kept its slot because it used to hold one: {path_ids:?}"
        );
    }

    /// A path that degrades without ever missing three probes in a row is the
    /// case only the score can catch, so the margin must not swallow it either.
    #[test]
    fn incumbency_does_not_outlast_a_real_degradation() {
        let mut degrading = measured("0", 45.0);
        for _ in 0..40 {
            degrading.record_probe(140.0);
        }
        let paths = [degrading, measured("1", 60.0), measured("2", 65.0)];
        let Decision::Duplicate { path_ids } =
            choose_paths_with_incumbent(&paths, Strategy::Adaptive, &["0", "1"])
        else {
            panic!("three healthy routes should duplicate");
        };
        assert!(
            !path_ids.contains(&"0".to_owned()),
            "a route that drifted to 140 ms kept its slot: {path_ids:?}"
        );
    }

    /// Nothing carries traffic yet at startup, so the first pick is decided on
    /// the scores alone.
    #[test]
    fn with_nothing_carrying_traffic_the_best_routes_win_outright() {
        let paths = [scored("0", 90.0), scored("1", 50.0), scored("2", 55.0)];
        assert_eq!(
            choose_paths_with_incumbent(&paths, Strategy::Adaptive, &[]),
            choose_paths(&paths, Strategy::Adaptive),
        );
    }

    /// Two routes both down and close together used to alternate as the armed
    /// fallback on every timeout, which is the same flapping one layer down.
    #[test]
    fn a_total_outage_holds_the_route_it_already_armed() {
        let mut first = measured("0", 52.0);
        let mut second = measured("1", 50.0);
        for _ in 0..LOSSES_BEFORE_INACTIVE {
            first.record_loss();
            second.record_loss();
        }
        assert_eq!(
            choose_paths_with_incumbent(&[first, second], Strategy::Adaptive, &["0"]),
            Decision::Single {
                path_id: "0".into()
            }
        );
    }

    #[test]
    fn fastest_path_uses_lowest_score() {
        let paths = [measured("slow", 80.0), measured("fast", 41.0)];
        assert_eq!(
            choose_paths(&paths, Strategy::FastestPath),
            Decision::Single {
                path_id: "fast".into()
            }
        );
    }

    /// Substantial degradation on both candidates suppresses extra load. This
    /// is a conservative policy, not proof of where congestion occurred.
    #[test]
    fn adaptive_mode_stops_duplicating_when_every_path_is_degraded() {
        let mut first = measured("first", 60.0);
        let mut second = measured("second", 65.0);
        for _ in 0..20 {
            first.record_probe(250.0);
            second.record_probe(255.0);
            first.record_probe(60.0);
            second.record_probe(65.0);
        }
        assert!(matches!(
            choose_paths(&[first, second], Strategy::Adaptive),
            Decision::Single { .. }
        ));
    }

    #[test]
    fn an_explicit_duplicate_strategy_still_duplicates_when_all_are_degraded() {
        let mut first = measured("first", 60.0);
        let mut second = measured("second", 65.0);
        first.record_loss();
        second.record_loss();
        assert!(matches!(
            choose_paths(&[first, second], Strategy::Duplicate),
            Decision::Duplicate { .. }
        ));
    }

    #[test]
    fn adaptive_mode_duplicates_on_loss() {
        let mut unstable = measured("unstable", 35.0);
        unstable.record_loss();
        let paths = [unstable, measured("backup", 52.0)];
        assert!(matches!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Duplicate { .. }
        ));
    }

    #[test]
    fn adaptive_mode_does_not_duplicate_onto_a_slow_backup() {
        let mut unstable = measured("fast", 50.0);
        unstable.record_loss();
        let paths = [unstable, measured("slow", 180.0)];
        assert_eq!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Single {
                path_id: "fast".into()
            }
        );
    }

    #[test]
    fn adaptive_mode_does_not_duplicate_onto_a_jittering_backup() {
        let stable = measured("stable", 50.0);
        let mut jittering = measured("jittering", 50.0);
        jittering.record_probe(500.0);
        assert_eq!(
            choose_paths(&[stable, jittering], Strategy::Adaptive),
            Decision::Single {
                path_id: "stable".into()
            }
        );
    }

    #[test]
    fn healthy_paths_are_already_duplicating_before_a_failure() {
        assert!(matches!(
            choose_paths(
                &[measured("wg", 50.0), measured("tcp", 88.0)],
                Strategy::Adaptive
            ),
            Decision::Duplicate { .. }
        ));
    }

    #[test]
    fn all_paths_mode_keeps_every_healthy_enabled_route_active() {
        assert_eq!(
            choose_paths(
                &[
                    measured("wg", 50.0),
                    measured("tcp", 65.0),
                    measured("socks", 95.0)
                ],
                Strategy::AllPaths,
            ),
            Decision::Duplicate {
                path_ids: vec!["wg".into(), "tcp".into(), "socks".into()],
            }
        );
    }

    #[test]
    fn intermittent_loss_on_both_paths_keeps_redundancy() {
        let mut paths = [measured("wg", 50.0), measured("udp", 60.0)];
        for path in &mut paths {
            path.record_loss();
        }
        assert!(matches!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Duplicate { .. }
        ));
    }

    #[test]
    fn a_path_that_only_lost_probes_is_never_rated_as_zero_ms() {
        let mut unproven = PathMetrics::new("unproven");
        unproven.record_loss();
        assert_eq!(
            choose_paths(
                &[unproven.clone(), measured("working", 90.0)],
                Strategy::Adaptive
            ),
            Decision::Single {
                path_id: "working".into()
            }
        );
        unproven.record_probe(90.0);
        assert_eq!(unproven.latency_ms, 90.0);
    }

    #[test]
    fn failed_primary_is_replaced_by_two_working_backups_and_can_recover() {
        let mut paths = [
            measured("wg", 40.0),
            measured("tcp", 60.0),
            measured("socks", 70.0),
        ];
        for _ in 0..3 {
            paths[0].record_loss();
        }
        assert_eq!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Duplicate {
                path_ids: vec!["tcp".into(), "socks".into()]
            }
        );
        for _ in 0..20 {
            paths[0].record_probe(40.0);
        }
        assert_eq!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Duplicate {
                path_ids: vec!["wg".into(), "tcp".into()]
            }
        );
    }

    #[test]
    fn total_outage_does_not_expand_outbound_traffic_to_all_paths() {
        let mut paths = [
            measured("wg", 40.0),
            measured("tcp", 60.0),
            measured("socks", 70.0),
        ];
        for path in &mut paths {
            for _ in 0..3 {
                path.record_loss();
            }
        }
        assert_eq!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Single {
                path_id: "wg".into()
            }
        );
        paths[2].record_probe(70.0);
        assert_eq!(
            choose_paths(&paths, Strategy::Adaptive),
            Decision::Single {
                path_id: "socks".into()
            }
        );
    }

    #[test]
    fn a_total_outage_holds_one_last_known_route_instead_of_flipping_on_loss() {
        let mut first = measured("first", 45.0);
        let mut second = measured("second", 60.0);
        for _ in 0..3 {
            first.record_loss();
            second.record_loss();
        }
        for _ in 0..10 {
            first.record_loss();
            assert_eq!(
                choose_paths(&[first.clone(), second.clone()], Strategy::Adaptive),
                Decision::Single {
                    path_id: "first".into()
                }
            );
            second.record_loss();
            assert_eq!(
                choose_paths(&[first.clone(), second.clone()], Strategy::Adaptive),
                Decision::Single {
                    path_id: "first".into()
                }
            );
        }
    }

    /// A lost probe is one packet, and must read as one packet. The old
    /// smoothing turned it into a 20% loss rate that decayed through the teens
    /// for several seconds, which is what users saw and reported as a loss
    /// spike on a link whose real loss was a few percent.
    #[test]
    fn one_lost_probe_reads_as_one_probe_not_a_loss_spike() {
        let mut path = measured("route", 47.0);
        path.record_loss();
        assert!(
            path.loss_ratio <= 0.05 + f64::EPSILON,
            "one probe reported {:.0}% loss",
            path.loss_ratio * 100.0
        );
    }

    /// The property that makes the number worth showing anyone: the reading at
    /// an arbitrary moment is close to the path's real loss rate.
    ///
    /// Any smoothing gets this right *on average* — it is an EWMA over a 0/1
    /// indicator, so its expectation is the loss rate either way. What the old
    /// constant got wrong was the spread around that average: at 0.2 a
    /// one-in-twenty path swung between 20% just after a loss and 0.6% just
    /// before the next one, so whenever anyone actually looked, the figure was
    /// wrong. This samples mid-stream rather than averaging, which is why it
    /// fails against the old constant.
    #[test]
    fn the_loss_estimate_settles_on_the_real_loss_rate() {
        for (lose_one_in, expected) in [(20, 0.05), (10, 0.10), (4, 0.25)] {
            let mut path = measured("route", 50.0);
            for probe in 0..4_000 {
                if probe % lose_one_in == 0 {
                    path.record_loss();
                } else {
                    path.record_probe(50.0);
                }
            }
            assert!(
                (path.loss_ratio - expected).abs() < 0.03,
                "1-in-{lose_one_in} loss settled at {:.1}%, expected about {:.0}%",
                path.loss_ratio * 100.0,
                expected * 100.0
            );
        }
    }

    /// The live regression. Two WireGuard routes at 47 ms and an L2TP route at
    /// 86 ms: losing a single probe on a fast route must not hand the session
    /// to one 39 ms slower. This is the flapping that produced 50 selection
    /// changes in six minutes.
    #[test]
    fn a_single_loss_does_not_promote_a_route_that_is_far_slower() {
        let mut fast = measured("fast", 47.0);
        let steady = measured("steady", 47.0);
        let slow = measured("slow", 86.0);
        fast.record_loss();
        let Decision::Duplicate { path_ids } =
            choose_paths(&[fast, steady, slow], Strategy::Adaptive)
        else {
            panic!("three healthy routes should still duplicate");
        };
        assert!(
            !path_ids.contains(&"slow".to_owned()),
            "one lost probe promoted the slow route: {path_ids:?}"
        );
    }

    /// And the estimate still has to be able to condemn a path. A route losing
    /// most of its probes without ever losing three in a row is exactly the
    /// case `consecutive_losses` cannot catch, so the ratio has to carry it.
    #[test]
    fn sustained_heavy_loss_still_reaches_the_degraded_threshold() {
        let mut path = measured("lossy", 50.0);
        for probe in 0..400 {
            // Two lost, one delivered: never three in a row, so the path stays
            // `active` and only the loss estimate can speak against it.
            if probe % 3 == 2 {
                path.record_probe(50.0);
            } else {
                path.record_loss();
            }
        }
        assert!(path.active, "this path never lost three probes in a row");
        assert!(
            path.loss_ratio >= 0.5,
            "two-in-three loss only reached {:.0}%",
            path.loss_ratio * 100.0
        );
    }

    /// Slowing the estimate must not slow down the thing that actually reacts
    /// to a dead path, which is a run of consecutive losses.
    #[test]
    fn a_dead_path_is_still_dropped_after_three_consecutive_losses() {
        let mut path = measured("dead", 40.0);
        for _ in 0..LOSSES_BEFORE_INACTIVE - 1 {
            path.record_loss();
            assert!(path.active);
        }
        path.record_loss();
        assert!(!path.active);
        assert_eq!(path.score(), f64::INFINITY);
        // And one good probe brings it straight back.
        path.record_probe(40.0);
        assert!(path.active);
    }
}
