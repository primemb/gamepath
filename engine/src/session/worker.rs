//! Plumbing shared by both path workers: what the dispatcher hands them, the
//! counters they publish, and the bounded send that keeps a burst from
//! starving the probes and timers that decide whether a path is still alive.

use gamepath_engine::uplink::UplinkMonitor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

pub(crate) struct PathCommand {
    pub(crate) frame: Vec<u8>,
    /// When the scheduler handed this packet over. A packet that waited longer
    /// than [`PATH_QUEUE_MAX_AGE`] is worth less than the latency it would add
    /// to everything behind it, so the worker drops it instead of sending it.
    pub(crate) queued_at: Instant,
}

/// Per-path counters a worker publishes and [`WireGuardSessionManager::status`]
/// reads back. Grouped so the workers take one parameter for all of it.
#[derive(Clone)]
pub(crate) struct PathTelemetry {
    pub(crate) iterations: Arc<Vec<AtomicU64>>,
    pub(crate) queue_depth: Arc<Vec<AtomicU64>>,
    /// Highest dispatcher queue depth observed during this session. The
    /// current depth is commonly back at zero by the time a periodic summary
    /// runs, so without a peak a short burst is invisible in the log.
    pub(crate) queue_peak: Arc<Vec<AtomicU64>>,
    pub(crate) dropped: Arc<Vec<AtomicU64>>,
    /// Why `dropped` moved. Kept separately so the next incident distinguishes
    /// dispatcher saturation, packets that became stale in a worker, and a
    /// saturated receive queue.
    pub(crate) queue_full_dropped: Arc<Vec<AtomicU64>>,
    pub(crate) stale_dropped: Arc<Vec<AtomicU64>>,
    pub(crate) inbound_dropped: Arc<Vec<AtomicU64>>,
    /// Longest interval between two worker iterations. A one-second CPU stall
    /// or a transport call that blocks past its deadline otherwise leaves no
    /// trace once the worker resumes.
    pub(crate) worker_gap_peak_ms: Arc<Vec<AtomicU64>>,
    pub(crate) healthy_mask: Arc<AtomicU64>,
    /// Whether this machine can reach the Internet at all, measured outside
    /// every node. Session-wide rather than per-path, but it rides here so the
    /// workers get it with the rest of what they read.
    pub(crate) uplink: Arc<UplinkMonitor>,
}

/// How long a worker waits on its socket per iteration. Short, because an
/// outbound packet handed over during the wait is only sent once it ends.
pub(crate) const WORKER_RECEIVE_TIMEOUT: Duration = Duration::from_millis(1);

/// Outbound packets a path worker sends before it goes back to servicing
/// inbound frames, probes and timers. Draining the whole queue first is what
/// lets a burst delay the replies that decide whether the path is still alive.
///
/// Sized so the cap bounds starvation without bounding throughput. A worker
/// iterates at least once per [`WORKER_RECEIVE_TIMEOUT`], so this is a floor of
/// ~128k packets per second per path - well past any line rate this runs on -
/// while the batch itself is a few hundred microseconds of `send` calls, an
/// order of magnitude under the wait it sits next to.
const PATH_SEND_BATCH: usize = 128;

/// Outbound queue depth per path. At [`PATH_SEND_BATCH`] this drains in about
/// 8 ms, which is the most latency the queue itself can add before
/// [`PATH_QUEUE_MAX_AGE`] starts shedding. Past that, holding a packet costs
/// more latency than dropping it saves.
pub(crate) const PATH_QUEUE_DEPTH: usize = 1024;

/// Inbound queue depth shared by every path worker.
pub(crate) const INBOUND_QUEUE_DEPTH: usize = 2048;

// A frame is numbered when it is queued but a probe is numbered later and sent
// immediately, so a probe overtakes everything still in the queue. The relay
// has to still remember the oldest of those when it arrives.
const _: () = assert!(
    PATH_QUEUE_DEPTH as u64 <= gamepath_engine::replay::MAX_REORDERING,
    "a full outbound queue can reorder further than the replay window covers"
);

/// How long a queued packet stays worth sending.
const PATH_QUEUE_MAX_AGE: Duration = Duration::from_millis(50);

/// A worker normally returns to its loop every millisecond. Only log gaps big
/// enough to be felt in a game, and rate-limit the warning locally because a
/// persistently blocked transport would otherwise produce a new value (and
/// defeat identical-message collapsing) on every iteration.
pub(crate) const WORKER_GAP_WARN: Duration = Duration::from_millis(100);

pub(crate) const WORKER_GAP_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Sends at most [`PATH_SEND_BATCH`] queued packets, shedding any that waited
/// past [`PATH_QUEUE_MAX_AGE`], and returns without draining the rest so the
/// caller can service inbound frames, probes and timers.
pub(crate) fn drain_send_queue(
    commands: &mpsc::Receiver<PathCommand>,
    index: usize,
    queue_depth: &[AtomicU64],
    dropped: &[AtomicU64],
    stale_dropped: &[AtomicU64],
    mut send: impl FnMut(&[u8]) -> (usize, Result<(), String>),
    mut record: impl FnMut(usize, Result<(), String>),
) {
    for _ in 0..PATH_SEND_BATCH {
        let Ok(command) = commands.try_recv() else {
            return;
        };
        if let Some(depth) = queue_depth.get(index) {
            depth.fetch_sub(1, Ordering::Relaxed);
        }
        if command.queued_at.elapsed() > PATH_QUEUE_MAX_AGE {
            if let Some(dropped) = dropped.get(index) {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(dropped) = stale_dropped.get(index) {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }
        let (length, result) = send(&command.frame);
        record(length, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(frame: Vec<u8>, age: Duration) -> PathCommand {
        PathCommand {
            frame,
            queued_at: Instant::now() - age,
        }
    }

    #[test]
    fn a_worker_sends_a_bounded_batch_and_leaves_the_rest_queued() {
        let (sender, receiver) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let depth = vec![AtomicU64::new(0)];
        let dropped = vec![AtomicU64::new(0)];
        let stale = vec![AtomicU64::new(0)];
        for _ in 0..PATH_SEND_BATCH * 2 {
            sender
                .try_send(queued(vec![0; 64], Duration::ZERO))
                .unwrap();
            depth[0].fetch_add(1, Ordering::Relaxed);
        }
        let mut sent = 0;
        drain_send_queue(
            &receiver,
            0,
            &depth,
            &dropped,
            &stale,
            |frame| (frame.len(), Ok(())),
            |_, _| sent += 1,
        );
        // The point is that the loop gets back to inbound frames and probes
        // rather than emptying a burst first.
        assert_eq!(sent, PATH_SEND_BATCH);
        assert_eq!(depth[0].load(Ordering::Relaxed) as usize, PATH_SEND_BATCH);
        assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_packet_that_waited_too_long_is_dropped_rather_than_sent_late() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let depth = vec![AtomicU64::new(2)];
        let dropped = vec![AtomicU64::new(0)];
        let stale = vec![AtomicU64::new(0)];
        sender
            .try_send(queued(vec![1; 64], PATH_QUEUE_MAX_AGE * 2))
            .unwrap();
        sender
            .try_send(queued(vec![2; 64], Duration::ZERO))
            .unwrap();
        let mut sent = Vec::new();
        drain_send_queue(
            &receiver,
            0,
            &depth,
            &dropped,
            &stale,
            |frame| (frame.len(), Ok(())),
            |length, _| sent.push(length),
        );
        assert_eq!(sent, [64]);
        assert_eq!(dropped[0].load(Ordering::Relaxed), 1);
        assert_eq!(stale[0].load(Ordering::Relaxed), 1);
        assert_eq!(depth[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_saturated_queue_sheds_packets_instead_of_growing() {
        let (sender, _receiver) = mpsc::sync_channel::<PathCommand>(2);
        assert!(sender.try_send(queued(vec![0; 8], Duration::ZERO)).is_ok());
        assert!(sender.try_send(queued(vec![0; 8], Duration::ZERO)).is_ok());
        assert!(matches!(
            sender.try_send(queued(vec![0; 8], Duration::ZERO)),
            Err(mpsc::TrySendError::Full(_))
        ));
    }
}
