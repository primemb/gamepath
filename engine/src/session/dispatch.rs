//! Handing one sealed frame to the path workers that should carry it.
//!
//! Shared by the dispatcher, which sends every captured packet, and by loss
//! repair, which sends repairs from its own thread, so both count queue depth
//! and drops the same way.

use super::worker::{PathCommand, PathTelemetry};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Instant;

pub(crate) struct Dispatch {
    pub(crate) commands: Vec<mpsc::SyncSender<PathCommand>>,
    pub(crate) telemetry: PathTelemetry,
}

/// How many paths `mask` named, and how many of them took the frame.
pub(crate) struct Dispatched {
    pub(crate) selected: usize,
    pub(crate) accepted: usize,
    pub(crate) disconnected: usize,
}

impl Dispatch {
    pub(crate) fn send(&self, frame: Vec<u8>, mask: u64) -> Dispatched {
        let mut outcome = Dispatched {
            selected: 0,
            accepted: 0,
            disconnected: 0,
        };
        let queued_at = Instant::now();
        for (index, sender) in self.commands.iter().enumerate() {
            let bit = 1_u64.checked_shl(index as u32).unwrap_or(0);
            if mask & bit == 0 {
                continue;
            }
            outcome.selected += 1;
            // Reserve before publication: a worker can receive immediately and
            // decrement the depth before try_send returns to this thread.
            let reserved = self
                .telemetry
                .queue_depth
                .get(index)
                .map(|depth| depth.fetch_add(1, Ordering::Relaxed) + 1);
            match sender.try_send(PathCommand {
                frame: frame.clone(),
                queued_at,
            }) {
                Ok(()) => {
                    outcome.accepted += 1;
                    if let Some(current) = reserved {
                        if let Some(peak) = self.telemetry.queue_peak.get(index) {
                            peak.fetch_max(current, Ordering::Relaxed);
                        }
                    }
                }
                // A full queue means the path is already behind. Shedding the
                // newest packet keeps the backlog bounded: game traffic is
                // stale by the time it would drain, and TCP retransmits.
                Err(mpsc::TrySendError::Full(_)) => {
                    if let Some(depth) = self.telemetry.queue_depth.get(index) {
                        depth.fetch_sub(1, Ordering::Relaxed);
                    }
                    if let Some(dropped) = self.telemetry.dropped.get(index) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(dropped) = self.telemetry.queue_full_dropped.get(index) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    if let Some(depth) = self.telemetry.queue_depth.get(index) {
                        depth.fetch_sub(1, Ordering::Relaxed);
                    }
                    outcome.disconnected += 1;
                }
            }
        }
        outcome
    }
}
