//! Scheduling priority for the threads that touch every game packet.
//!
//! A game running flat out keeps every core busy with threads at normal
//! priority, and Windows round-robins threads of equal priority. A capture or
//! path worker woken by an arriving packet then waits for a game thread's
//! quantum to expire before it can forward that packet, which shows up as
//! jitter that no network measurement explains.
//!
//! `THREAD_PRIORITY_HIGHEST` puts these threads at base priority 10 in a
//! normal-class process, above normal game threads (8) and still inside the
//! range Microsoft documents as safe: base priorities above 11 interfere with
//! the operating system. That is also why this is not MMCSS, whose categories
//! run threads at 16 to 26. Every thread raised here blocks on a socket, a
//! driver or a queue between packets, so it runs briefly and often rather than
//! long, which is the pattern a raised priority is meant for.
//!
//! A VPN engine running beside the game raises its threads one step less, to
//! `THREAD_PRIORITY_ABOVE_NORMAL`: still ahead of the game's own threads, but
//! behind the game engine's whenever both have a packet ready.

/// Raises the calling thread. Failure only costs the raise, so it is logged
/// and the thread carries on at normal priority.
#[cfg(windows)]
pub fn raise_current_for_data_plane() {
    use windows_sys::Win32::System::Threading::{
        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST,
    };
    let priority = if crate::role::Role::current().data_plane_highest() {
        THREAD_PRIORITY_HIGHEST
    } else {
        THREAD_PRIORITY_ABOVE_NORMAL
    };
    // GetCurrentThread returns a pseudo-handle with full access to the calling
    // thread, so there is nothing to open or close.
    if unsafe { SetThreadPriority(GetCurrentThread(), priority) } == 0 {
        crate::log_warn!(
            "could not raise {} to high priority: {}",
            std::thread::current()
                .name()
                .unwrap_or("a data-plane thread"),
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(windows))]
pub fn raise_current_for_data_plane() {}

#[cfg(test)]
mod tests {
    #[test]
    fn raising_the_current_thread_is_harmless_to_repeat() {
        let worker = std::thread::spawn(|| {
            super::raise_current_for_data_plane();
            super::raise_current_for_data_plane();
        });
        worker.join().unwrap();
    }
}
