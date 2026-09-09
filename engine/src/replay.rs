//! Replay protection for sealed frames.
//!
//! A GamePath session numbers every frame from one counter so the relay can
//! recognise the same packet arriving down two paths and forward only the first
//! copy. The receiver therefore needs a window: accept a sequence once, reject
//! it if it comes back, and reject anything so old it has fallen out of memory.
//!
//! The window has to be wide, because in this system a frame's sequence says
//! very little about when it will arrive:
//!
//! - A data frame is numbered when the capture layer hands it over, then waits
//!   in its path's send queue. A control probe is numbered later but sent
//!   straight away, so it overtakes every frame still queued ahead of it.
//! - Paths have different latencies, so a frame sent earlier on a slow path can
//!   land well after frames sent later on a fast one.
//!
//! With a 64-entry window either of those silently drops real traffic as soon
//! as a queue is more than 64 deep, which shows up as unexplained packet loss
//! and unanswered health probes rather than as anything to do with replay.

/// Sequences the window remembers.
///
/// Sized for the worst reordering the transport can produce: a full outbound
/// queue on one path overtaken by a probe from another. It is a power of two so
/// the index is a mask, and costs 1 KiB per window.
pub const WINDOW: u64 = 8192;

const WORDS: usize = (WINDOW / 64) as usize;

/// Most out-of-order sequences the sending side can produce.
///
/// The sender's deepest outbound queue sets this: a probe numbered after every
/// frame in that queue is transmitted before them, so the window has to still
/// remember the oldest of them when it arrives. The engine asserts its own
/// queue depth against this at compile time.
pub const MAX_REORDERING: u64 = 2048;

const _: () = assert!(
    WINDOW >= MAX_REORDERING * 2,
    "the replay window must leave headroom above the worst reordering the \
     sender can produce, or real frames are rejected as replays"
);

/// Sliding replay window over a monotonically allocated sequence space.
///
/// The bitmap is circular and indexed by the sequence itself, so advancing does
/// not shift anything: only the range being skipped over is cleared, which is a
/// single bit in the common case.
#[derive(Clone)]
pub struct ReplayWindow {
    highest: u64,
    seen: [u64; WORDS],
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: 0,
            seen: [0; WORDS],
            initialized: false,
        }
    }
}

impl std::fmt::Debug for ReplayWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .field("initialized", &self.initialized)
            .finish_non_exhaustive()
    }
}

impl ReplayWindow {
    fn slot(sequence: u64) -> (usize, u64) {
        let position = sequence % WINDOW;
        ((position / 64) as usize, 1_u64 << (position % 64))
    }

    fn is_set(&self, sequence: u64) -> bool {
        let (word, bit) = Self::slot(sequence);
        self.seen[word] & bit != 0
    }

    fn set(&mut self, sequence: u64) {
        let (word, bit) = Self::slot(sequence);
        self.seen[word] |= bit;
    }

    fn clear(&mut self, sequence: u64) {
        let (word, bit) = Self::slot(sequence);
        self.seen[word] &= !bit;
    }

    /// Records `sequence` and reports whether it is the first time it has been
    /// seen. A repeat, or anything more than [`WINDOW`] behind the newest
    /// sequence so far, is rejected.
    pub fn accept(&mut self, sequence: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = sequence;
            self.set(sequence);
            return true;
        }
        if sequence > self.highest {
            let advance = sequence - self.highest;
            if advance >= WINDOW {
                // Nothing recorded is still inside the window.
                self.seen = [0; WORDS];
            } else {
                // Only the skipped sequences need forgetting; every other slot
                // still refers to a sequence inside the new window.
                for skipped in (self.highest + 1)..sequence {
                    self.clear(skipped);
                }
            }
            self.highest = sequence;
            self.set(sequence);
            return true;
        }
        if self.highest - sequence >= WINDOW || self.is_set(sequence) {
            return false;
        }
        self.set(sequence);
        true
    }

    /// The newest sequence accepted so far.
    pub fn highest(&self) -> u64 {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sequence_is_accepted_once_and_never_again() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(1));
        assert!(!window.accept(1));
        assert!(window.accept(2));
        assert!(!window.accept(2));
    }

    #[test]
    fn reordering_inside_the_window_is_accepted() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(100));
        for sequence in (1..100).rev() {
            assert!(
                window.accept(sequence),
                "{sequence} was rejected out of order"
            );
        }
        for sequence in 1..=100 {
            assert!(!window.accept(sequence), "{sequence} was accepted twice");
        }
    }

    /// The reason this window is not 64 wide.
    ///
    /// A data frame is numbered when it is queued; a probe is numbered later but
    /// sent immediately, so the probe lands first and the queued frames arrive
    /// behind it. Everything still in the queue has to be accepted.
    #[test]
    fn queued_data_overtaken_by_a_probe_is_still_accepted() {
        let mut window = ReplayWindow::default();
        // A full outbound queue, matching PATH_QUEUE_DEPTH.
        let queued: Vec<u64> = (1..=1024).collect();
        let probe = 1025;
        assert!(window.accept(probe));
        for sequence in queued {
            assert!(
                window.accept(sequence),
                "queued frame {sequence} was rejected as a replay behind the probe"
            );
        }
    }

    /// Two paths with different latencies share one sequence space, so frames
    /// sent earlier on the slow path land after later frames on the fast one.
    #[test]
    fn a_slow_path_lagging_a_fast_one_is_still_accepted() {
        let mut window = ReplayWindow::default();
        let mut fast = Vec::new();
        let mut slow = Vec::new();
        for sequence in 1..=4000_u64 {
            if sequence % 8 == 0 {
                slow.push(sequence);
            } else {
                fast.push(sequence);
            }
        }
        for sequence in fast {
            assert!(window.accept(sequence));
        }
        for sequence in slow {
            assert!(
                window.accept(sequence),
                "slow-path frame {sequence} was rejected"
            );
        }
    }

    #[test]
    fn anything_older_than_the_window_is_rejected() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(WINDOW * 2));
        assert!(!window.accept(WINDOW));
        assert!(!window.accept(1));
        // The oldest sequence still inside the window is accepted.
        assert!(window.accept(WINDOW + 1));
    }

    #[test]
    fn a_large_jump_forward_forgets_everything_behind_it() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(5));
        assert!(window.accept(5 + WINDOW * 3));
        assert!(!window.accept(5));
        assert_eq!(window.highest(), 5 + WINDOW * 3);
    }

    #[test]
    fn a_gap_left_by_a_lost_frame_can_still_be_filled_later() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(1));
        assert!(window.accept(500));
        assert!(window.accept(250));
        assert!(!window.accept(250));
    }

    #[test]
    fn wrapping_the_circular_bitmap_does_not_confuse_two_sequences() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(1));
        // Exactly one window later maps to the same bit as sequence 1.
        assert!(window.accept(1 + WINDOW));
        assert!(!window.accept(1 + WINDOW));
        // The original is outside the window now, not reported as unseen.
        assert!(!window.accept(1));
    }
}
