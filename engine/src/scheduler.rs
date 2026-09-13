use serde::{Deserialize, Serialize};

const SMOOTHING: f64 = 0.2;

/// Policy budget for a backup's extra RTT plus jitter, not a one-way latency
/// measurement or guarantee. Keep useful dissimilar providers in the race,
/// while avoiding extra outbound load on a severely stalled tunnel.
const ADAPTIVE_DUPLICATE_DELAY_BUDGET_MS: f64 = 100.0;

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
        self.loss_ratio = (self.loss_ratio * (1.0 - SMOOTHING)).clamp(0.0, 1.0);
        self.samples += 1;
        self.active = true;
        self.last_latency_ms = Some(latency_ms);
        self.consecutive_losses = 0;
    }

    pub fn record_loss(&mut self) {
        self.loss_ratio = ewma(self.loss_ratio, 1.0).clamp(0.0, 1.0);
        self.samples += 1;
        self.consecutive_losses = self.consecutive_losses.saturating_add(1);
        if self.consecutive_losses >= 3 {
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
    previous + SMOOTHING * (sample - previous)
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

pub fn choose_paths(paths: &[PathMetrics], strategy: Strategy) -> Decision {
    let mut healthy: Vec<_> = paths
        .iter()
        .filter(|path| path.active && path.last_latency_ms.is_some())
        .collect();
    healthy.sort_by(|left, right| left.score().total_cmp(&right.score()));
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
                    // latency/jitter route until a successful probe arrives.
                    path.latency_ms + path.jitter_ms * 2.0
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
}
