//! Names the step a teardown is stuck on.
//!
//! A stop that never returns leaves nothing in the log: the step that hung
//! cannot report itself. Observed live, a game session's stop logged the LAN
//! proxy closing and then nothing, while its routes kept running. Each step
//! records its name here, and a watchdog reports it if the stop runs long.

use gamepath_engine::log_warn;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const REPORT_AFTER: Duration = Duration::from_secs(5);

static STEP: Mutex<String> = Mutex::new(String::new());
/// Which teardown is running; a watchdog outliving its own stays quiet.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Records the step the running teardown has reached.
pub(crate) fn step(name: impl Into<String>) {
    *STEP.lock().unwrap() = name.into();
}

/// Ends the watch when dropped.
pub(crate) struct Watch {
    generation: u64,
}

/// Starts watching `what`, reporting its current step every few seconds
/// until the returned guard is dropped.
pub(crate) fn watch(what: &'static str) -> Watch {
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    step("starting");
    let started = Instant::now();
    let _ = thread::Builder::new()
        .name("gamepath-teardown-watch".into())
        .spawn(move || {
            loop {
                thread::sleep(REPORT_AFTER);
                if GENERATION.load(Ordering::Acquire) != generation {
                    return;
                }
                log_warn!(
                    "{what} still running after {} s, at: {}",
                    started.elapsed().as_secs(),
                    STEP.lock().unwrap()
                );
            }
        });
    Watch { generation }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let _ = GENERATION.compare_exchange(
            self.generation,
            self.generation + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finished_watch_silences_its_watchdog() {
        let watch = watch("test teardown");
        let generation = watch.generation;
        step("joining a worker");
        assert_eq!(*STEP.lock().unwrap(), "joining a worker");
        drop(watch);
        assert_ne!(GENERATION.load(Ordering::Acquire), generation);
    }
}
