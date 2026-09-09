//! Round-trip time estimation for health probes.
//!
//! A probe needs a deadline, and a constant one cannot be right for both cases
//! it has to cover. Fixed at 1500 ms it was twenty-five times the round trip of
//! a healthy 60 ms path, so a dead path took seconds to notice; fixed low it
//! would call a path dead every time congestion pushed the real round trip up,
//! which is exactly when the measurement is least trustworthy.
//!
//! So the deadline follows the path. This is the estimator TCP uses for its
//! retransmission timeout (Jacobson/Karels, RFC 6298): a smoothed round trip
//! plus four times its variation, which widens on its own when a path becomes
//! erratic and tightens again when it settles.
//!
//! The payoff is that the *threshold* — how many probes must go unanswered
//! before a path is declared down — stops being a trade against detection
//! speed. Each probe cycle costs a few hundred milliseconds on a healthy path
//! instead of two seconds, so several can be required and still resolve
//! quickly.

use std::time::Duration;

/// Shortest probe deadline.
///
/// Well above any plausible round trip on a working path, so ordinary jitter
/// never expires a probe, while still an order of magnitude under the old
/// constant.
pub const MIN_TIMEOUT: Duration = Duration::from_millis(200);

/// Longest probe deadline. A path slower than this is unusable for a game
/// whether or not the probe is still outstanding.
pub const MAX_TIMEOUT: Duration = Duration::from_millis(1500);

/// Weight of each new sample in the smoothed round trip (RFC 6298 uses 1/8).
const ALPHA_RECIPROCAL: u32 = 8;

/// Weight of each new deviation in the variation estimate (RFC 6298 uses 1/4).
const BETA_RECIPROCAL: u32 = 4;

/// Multiplier on the variation when forming the deadline.
const VARIATION_MULTIPLIER: u32 = 4;

/// Tracks a path's round trip and derives a probe deadline from it.
#[derive(Clone, Copy, Debug, Default)]
pub struct RttEstimator {
    smoothed: Option<Duration>,
    variation: Duration,
}

impl RttEstimator {
    /// Folds in one measured round trip.
    pub fn record(&mut self, sample: Duration) {
        match self.smoothed {
            // RFC 6298: the first measurement seeds both terms directly.
            None => {
                self.smoothed = Some(sample);
                self.variation = sample / 2;
            }
            Some(smoothed) => {
                let deviation = sample.abs_diff(smoothed);
                self.variation = (self.variation * (BETA_RECIPROCAL - 1) + deviation)
                    / BETA_RECIPROCAL;
                self.smoothed = Some(
                    (smoothed * (ALPHA_RECIPROCAL - 1) + sample) / ALPHA_RECIPROCAL,
                );
            }
        }
    }

    /// How long the next probe may go unanswered before it counts as lost.
    ///
    /// Before any sample has arrived this is the ceiling, because nothing is
    /// known about the path yet and a new path deserves the benefit of doubt.
    pub fn timeout(&self) -> Duration {
        let Some(smoothed) = self.smoothed else {
            return MAX_TIMEOUT;
        };
        (smoothed + self.variation * VARIATION_MULTIPLIER).clamp(MIN_TIMEOUT, MAX_TIMEOUT)
    }

    /// The smoothed round trip, once there is one.
    pub fn smoothed(&self) -> Option<Duration> {
        self.smoothed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(rtt_ms: u64, jitter_ms: u64) -> RttEstimator {
        let mut estimator = RttEstimator::default();
        for index in 0..40 {
            let wobble = if index % 2 == 0 { jitter_ms } else { 0 };
            estimator.record(Duration::from_millis(rtt_ms + wobble));
        }
        estimator
    }

    #[test]
    fn an_unmeasured_path_gets_the_benefit_of_the_doubt() {
        assert_eq!(RttEstimator::default().timeout(), MAX_TIMEOUT);
    }

    /// The case that mattered: a healthy 60 ms route was being given 1500 ms.
    #[test]
    fn a_fast_steady_path_gets_a_deadline_far_under_the_old_constant() {
        let estimator = settled(61, 3);
        let timeout = estimator.timeout();
        assert_eq!(timeout, MIN_TIMEOUT, "got {timeout:?}");
        assert!(timeout < MAX_TIMEOUT / 5);
    }

    /// And the case that stopped it being lowered by hand: real congestion.
    #[test]
    fn a_path_whose_round_trip_really_rises_gets_a_wider_deadline() {
        let mut estimator = settled(61, 3);
        let quiet = estimator.timeout();
        // The 1.2 s round trips seen during a live congestion event.
        for _ in 0..10 {
            estimator.record(Duration::from_millis(1200));
        }
        let congested = estimator.timeout();
        assert!(
            congested > quiet,
            "the deadline has to follow the path: {quiet:?} -> {congested:?}"
        );
        assert_eq!(congested, MAX_TIMEOUT);
    }

    #[test]
    fn an_erratic_path_is_given_more_room_than_a_steady_one_at_the_same_speed() {
        let steady = settled(300, 0);
        let erratic = settled(300, 200);
        assert!(
            erratic.timeout() > steady.timeout(),
            "steady {:?} vs erratic {:?}",
            steady.timeout(),
            erratic.timeout()
        );
    }

    #[test]
    fn the_deadline_never_leaves_its_bounds() {
        for rtt in [0_u64, 1, 50, 500, 5_000, 60_000] {
            for jitter in [0_u64, 10, 1_000] {
                let timeout = settled(rtt, jitter).timeout();
                assert!(
                    (MIN_TIMEOUT..=MAX_TIMEOUT).contains(&timeout),
                    "rtt {rtt} jitter {jitter} produced {timeout:?}"
                );
            }
        }
    }

    #[test]
    fn a_single_outlier_does_not_move_the_deadline_much() {
        let mut estimator = settled(60, 2);
        let before = estimator.timeout();
        estimator.record(Duration::from_millis(900));
        let after = estimator.timeout();
        // It reacts, but one bad sample cannot swing the deadline to the cap.
        assert!(after >= before);
        assert!(after < MAX_TIMEOUT, "one outlier pinned it at the ceiling");
    }

    #[test]
    fn the_estimate_converges_on_a_changed_path() {
        let mut estimator = settled(60, 0);
        for _ in 0..60 {
            estimator.record(Duration::from_millis(200));
        }
        let smoothed = estimator.smoothed().unwrap();
        assert!(
            smoothed >= Duration::from_millis(190) && smoothed <= Duration::from_millis(210),
            "converged to {smoothed:?}"
        );
    }
}
