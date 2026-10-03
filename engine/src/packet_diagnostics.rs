//! Bounded packet-failure counters; reporting runs outside the packet loops.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Reason {
    OutboundNoQueue,
    OutboundNoWorker,
    TransportSend,
    WintunInject,
    WintunInvalidSource,
    OversizedReply,
    BypassInject,
    Checksum,
    ReturnInject,
    RepairQueue,
    RelayAuthentication,
    ReplayTooOld,
}

const LABELS: [&str; 12] = [
    "outbound-no-queue",
    "outbound-no-worker",
    "transport-copy-send-failed",
    "wintun-return-injection-failed",
    "wintun-invalid-source",
    "oversized-return",
    "bypass-injection-failed",
    "outbound-checksum-failed",
    "return-injection-failed",
    "repair-inbound-queue-rejected",
    "relay-authentication-rejected",
    "relay-return-too-old",
];

#[derive(Default)]
struct Counter {
    protocols: [AtomicU64; 3],
    sample: Mutex<Option<String>>,
    sample_pending: AtomicBool,
}

#[derive(Default)]
pub struct PacketDiagnostics {
    counters: [Counter; LABELS.len()],
}

impl PacketDiagnostics {
    /// Counts inner IPv4 packets, including later fragments. Empty bytes mean
    /// encrypted/control traffic whose inner protocol cannot be identified.
    pub fn record(&self, reason: Reason, packet: &[u8]) {
        let protocol = if packet.len() >= 20 && packet[0] >> 4 == 4 {
            match packet[9] {
                17 => 0,
                6 => 1,
                _ => 2,
            }
        } else {
            2
        };
        self.counters[reason as usize].protocols[protocol].fetch_add(1, Ordering::Relaxed);
    }

    /// Only pass non-secret API errors. At most one sample per reporting interval.
    pub fn record_error(&self, reason: Reason, packet: &[u8], error: &str) {
        self.record(reason, packet);
        let counter = &self.counters[reason as usize];
        if counter.sample_pending.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Ok(mut sample) = counter.sample.try_lock() {
            if sample.is_none() {
                *sample = Some(
                    error
                        .chars()
                        .take(256)
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .collect(),
                );
            }
        } else {
            counter.sample_pending.store(false, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> [[u64; 3]; LABELS.len()] {
        std::array::from_fn(|index| {
            std::array::from_fn(|protocol| {
                self.counters[index].protocols[protocol].load(Ordering::Relaxed)
            })
        })
    }

    pub fn status(&self) -> serde_json::Value {
        let values = self.snapshot();
        LABELS
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let [udp, tcp, other] = values[index];
                (
                    (*label).to_owned(),
                    serde_json::json!({ "udp": udp, "tcp": tcp, "other": other }),
                )
            })
            .collect::<serde_json::Map<_, _>>()
            .into()
    }
}

#[derive(Default)]
pub struct Reporter {
    reported: [[u64; 3]; LABELS.len()],
    last_log: Option<Instant>,
}

impl Reporter {
    /// `force` drains pending failures at shutdown, including short sessions.
    pub fn poll(&mut self, diagnostics: &PacketDiagnostics, context: &str, force: bool) {
        if !force
            && self
                .last_log
                .is_some_and(|logged| logged.elapsed() < Duration::from_secs(10))
        {
            return;
        }
        if let Some(details) = self.take_report(diagnostics) {
            crate::log_warn!("{context} packet failures: {details}");
            self.last_log = Some(Instant::now());
        }
    }

    fn take_report(&mut self, diagnostics: &PacketDiagnostics) -> Option<String> {
        let current = diagnostics.snapshot();
        let mut details = Vec::new();
        for (index, label) in LABELS.iter().enumerate() {
            let delta: [u64; 3] = std::array::from_fn(|protocol| {
                current[index][protocol].saturating_sub(self.reported[index][protocol])
            });
            if delta == [0; 3] {
                continue;
            }
            let [udp, tcp, other] = delta;
            let sample = diagnostics.counters[index].sample.lock().unwrap().take();
            diagnostics.counters[index]
                .sample_pending
                .store(false, Ordering::Relaxed);
            details.push(format!(
                "{label}=+{} (udp +{udp}, tcp +{tcp}, other +{other}){}",
                udp + tcp + other,
                sample
                    .map(|error| format!(" error={error}"))
                    .unwrap_or_default()
            ));
        }
        self.reported = current;
        (!details.is_empty()).then(|| details.join(" | "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_keep_protocols_reasons_and_interval_deltas_separate() {
        let diagnostics = PacketDiagnostics::default();
        let mut reporter = Reporter::default();
        let mut packet = [0_u8; 20];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[6..8].copy_from_slice(&185_u16.to_be_bytes());
        diagnostics.record(Reason::OutboundNoQueue, &packet);
        packet[9] = 6;
        diagnostics.record(Reason::OutboundNoQueue, &packet);
        diagnostics.record_error(Reason::WintunInject, &[], "OS error 111\nnext line");
        let report = reporter.take_report(&diagnostics).unwrap();
        assert!(report.contains("outbound-no-queue=+2 (udp +1, tcp +1, other +0)"));
        assert!(report.contains("error=OS error 111 next line"));
        assert!(reporter.take_report(&diagnostics).is_none());
        packet[9] = 17;
        diagnostics.record(Reason::OutboundNoQueue, &packet);
        assert_eq!(
            reporter.take_report(&diagnostics).unwrap(),
            "outbound-no-queue=+1 (udp +1, tcp +0, other +0)"
        );
        assert_eq!(diagnostics.status()["outbound-no-queue"]["udp"], 2);
    }

    #[test]
    fn shutdown_drains_failures_inside_the_rate_limit() {
        let diagnostics = PacketDiagnostics::default();
        let mut reporter = Reporter::default();
        diagnostics.record(Reason::OutboundNoWorker, &[]);
        reporter.poll(&diagnostics, "test", false);
        diagnostics.record(Reason::OutboundNoWorker, &[]);
        reporter.poll(&diagnostics, "test", false);
        assert_eq!(reporter.reported[Reason::OutboundNoWorker as usize][2], 1);
        reporter.poll(&diagnostics, "test", true);
        assert_eq!(reporter.reported[Reason::OutboundNoWorker as usize][2], 2);
    }
}
