//! Edge-triggered latency diagnostics.
//!
//! A route that slows down mid-match is worth one log line, not one per probe,
//! so a rise has to be confirmed before it is reported and the baseline only
//! moves while the route is not already in an incident.

use std::time::{Duration, Instant};

/// A 10-15 ms step is visible in a competitive game but ordinary sub-frame
/// jitter is not. Two consecutive samples confirm a modest rise; a severe
/// spike is reported immediately. Recovery also needs several samples so the
/// log contains one incident and one recovery instead of a line per probe.
const LATENCY_RISE_MIN_MS: f64 = 12.0;

const LATENCY_RISE_RATIO: f64 = 0.10;

const LATENCY_SEVERE_MIN_MS: f64 = 50.0;

const LATENCY_SEVERE_RATIO: f64 = 0.75;

const LATENCY_BASELINE_SAMPLES: u64 = 4;

const LATENCY_RISE_SAMPLES: u8 = 2;

const LATENCY_RECOVERY_SAMPLES: u8 = 3;

#[derive(Debug, PartialEq)]
pub(crate) enum LatencyEvent {
    Degraded {
        baseline_ms: f64,
        observed_ms: f64,
    },
    Recovered {
        baseline_ms: f64,
        peak_ms: f64,
        duration: Duration,
    },
}

/// Per-worker state for edge-triggered latency diagnostics. The baseline only
/// moves while the route is not in an incident; otherwise a sustained rise
/// would teach the detector that the degraded value is normal before recovery.
#[derive(Default)]
pub(crate) struct LatencyWatch {
    baseline_ms: Option<f64>,
    samples: u64,
    elevated_samples: u8,
    recovery_samples: u8,
    incident_started: Option<Instant>,
    peak_ms: f64,
}

impl LatencyWatch {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn observe(&mut self, sample_ms: f64, now: Instant) -> Option<LatencyEvent> {
        let sample_ms = sample_ms.max(0.0);
        let Some(baseline_ms) = self.baseline_ms else {
            self.baseline_ms = Some(sample_ms);
            self.samples = 1;
            return None;
        };

        if let Some(started) = self.incident_started {
            self.peak_ms = self.peak_ms.max(sample_ms);
            let recovered_below = baseline_ms + (LATENCY_RISE_MIN_MS / 2.0);
            if sample_ms <= recovered_below {
                self.recovery_samples = self.recovery_samples.saturating_add(1);
            } else {
                self.recovery_samples = 0;
            }
            if self.recovery_samples >= LATENCY_RECOVERY_SAMPLES {
                let event = LatencyEvent::Recovered {
                    baseline_ms,
                    peak_ms: self.peak_ms,
                    duration: now.saturating_duration_since(started),
                };
                self.baseline_ms = Some(sample_ms);
                self.samples = 1;
                self.elevated_samples = 0;
                self.recovery_samples = 0;
                self.incident_started = None;
                self.peak_ms = 0.0;
                return Some(event);
            }
            return None;
        }

        let rise = sample_ms - baseline_ms;
        let threshold = LATENCY_RISE_MIN_MS.max(baseline_ms * LATENCY_RISE_RATIO);
        let severe = rise >= LATENCY_SEVERE_MIN_MS.max(baseline_ms * LATENCY_SEVERE_RATIO);
        let elevated = self.samples >= LATENCY_BASELINE_SAMPLES && rise >= threshold;
        if elevated {
            self.elevated_samples = self.elevated_samples.saturating_add(1);
            self.peak_ms = self.peak_ms.max(sample_ms);
            if severe || self.elevated_samples >= LATENCY_RISE_SAMPLES {
                self.incident_started = Some(now);
                return Some(LatencyEvent::Degraded {
                    baseline_ms,
                    observed_ms: self.peak_ms,
                });
            }
            return None;
        }

        self.elevated_samples = 0;
        self.peak_ms = 0.0;
        self.samples = self.samples.saturating_add(1);
        // A slow EWMA follows normal route drift but preserves enough history
        // to spot a persistent 105 -> 120 ms step.
        self.baseline_ms = Some(baseline_ms + 0.05 * (sample_ms - baseline_ms));
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_watch_reports_a_sustained_small_step_once_then_recovers_once() {
        let mut watch = LatencyWatch::default();
        let started = Instant::now();
        for offset in 0..LATENCY_BASELINE_SAMPLES {
            assert_eq!(
                watch.observe(105.0, started + Duration::from_millis(offset)),
                None
            );
        }
        assert_eq!(
            watch.observe(120.0, started + Duration::from_secs(1)),
            None,
            "one modest sample is not an incident"
        );
        assert!(matches!(
            watch.observe(121.0, started + Duration::from_secs(2)),
            Some(LatencyEvent::Degraded { .. })
        ));
        assert_eq!(
            watch.observe(123.0, started + Duration::from_secs(3)),
            None,
            "an active incident must not log every sample"
        );
        for second in 4..4 + u64::from(LATENCY_RECOVERY_SAMPLES) - 1 {
            assert_eq!(
                watch.observe(106.0, started + Duration::from_secs(second)),
                None
            );
        }
        assert!(matches!(
            watch.observe(106.0, started + Duration::from_secs(6)),
            Some(LatencyEvent::Recovered { peak_ms, .. }) if peak_ms == 123.0
        ));
    }

    #[test]
    fn latency_watch_reports_one_severe_spike_immediately() {
        let mut watch = LatencyWatch::default();
        let now = Instant::now();
        for offset in 0..LATENCY_BASELINE_SAMPLES {
            assert_eq!(
                watch.observe(50.0, now + Duration::from_millis(offset)),
                None
            );
        }
        assert!(matches!(
            watch.observe(120.0, now + Duration::from_secs(1)),
            Some(LatencyEvent::Degraded { .. })
        ));
    }
}
