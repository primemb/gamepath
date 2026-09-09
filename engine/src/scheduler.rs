use serde::{Deserialize, Serialize};

const SMOOTHING: f64 = 0.2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    pub id: String,
    pub active: bool,
    pub samples: u64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_ratio: f64,
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
        }
    }

    pub fn record_probe(&mut self, latency_ms: f64) {
        let latency_ms = latency_ms.max(0.0);
        if self.samples == 0 {
            self.latency_ms = latency_ms;
        } else {
            let deviation = (latency_ms - self.latency_ms).abs();
            self.jitter_ms = ewma(self.jitter_ms, deviation);
            self.latency_ms = ewma(self.latency_ms, latency_ms);
        }
        self.loss_ratio = (self.loss_ratio * (1.0 - SMOOTHING)).clamp(0.0, 1.0);
        self.samples += 1;
        self.active = true;
    }

    pub fn record_loss(&mut self) {
        self.loss_ratio = ewma(self.loss_ratio, 1.0).clamp(0.0, 1.0);
        self.samples += 1;
    }

    pub fn score(&self) -> f64 {
        if !self.active || self.samples == 0 {
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
        .filter(|path| path.active && path.samples > 0)
        .collect();
    healthy.sort_by(|left, right| left.score().total_cmp(&right.score()));
    let Some(best) = healthy.first() else {
        return Decision::Drop;
    };
    if healthy.len() == 1 || strategy == Strategy::FastestPath {
        return Decision::Single {
            path_id: best.id.clone(),
        };
    }

    // Duplication buys redundancy only when the paths fail independently. If
    // every path is struggling at once the cause is almost always the one thing
    // they share - this machine's uplink - and sending each packet twice over a
    // congested link doubles the load that is already the problem. That is a
    // feedback loop: congestion raises loss, loss turns duplication on, and the
    // extra copies deepen the congestion.
    //
    // So a degraded path is covered by a healthy one, and when nothing is
    // healthy the best single path carries the traffic alone.
    let degraded = |path: &PathMetrics| path.loss_ratio >= 0.01 || path.jitter_ms >= 7.0;
    let candidates = healthy.iter().take(2).collect::<Vec<_>>();
    let any_degraded = candidates.iter().any(|path| degraded(path));
    let all_degraded = candidates.iter().all(|path| degraded(path));
    let should_duplicate = strategy == Strategy::Duplicate || (any_degraded && !all_degraded);
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

    /// The uplink is shared, so when every path degrades together duplication
    /// cannot route around anything and only adds to the congestion.
    #[test]
    fn adaptive_mode_stops_duplicating_when_every_path_is_degraded() {
        let mut first = measured("first", 60.0);
        let mut second = measured("second", 65.0);
        for _ in 0..5 {
            first.record_loss();
            second.record_loss();
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
}
