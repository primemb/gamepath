/// Raises the Windows timer resolution for as long as a session is running.
///
/// Windows schedules waits on a ~15.6 ms timer by default, so a socket read
/// that asks for a 1 ms timeout actually returns after about 15 ms. That is
/// harmless for arriving packets, which wake a blocked read immediately, but
/// each path worker drains its queue of outbound packets between reads: at the
/// default resolution a game packet handed to a worker can wait most of a frame
/// before it is sent. Raising the resolution for the session's lifetime brings
/// that wait down to roughly a millisecond.
///
/// The raise is released when the guard drops, so it lasts only while a session
/// is actually carrying traffic.
pub struct HighResolutionTimer {
    #[cfg(windows)]
    period: Option<u32>,
}

#[cfg(windows)]
mod bindings {
    #[link(name = "winmm")]
    unsafe extern "system" {
        pub fn timeBeginPeriod(period: u32) -> u32;
        pub fn timeEndPeriod(period: u32) -> u32;
    }
}

/// `TIMERR_NOERROR`, the only success value these two calls return.
#[cfg(windows)]
const TIMER_OK: u32 = 0;

impl HighResolutionTimer {
    #[cfg(windows)]
    pub fn raise() -> Self {
        // 1 ms is the resolution games and media players ask for. If the system
        // refuses it the session still runs, only with coarser wakeups.
        let granted = unsafe { bindings::timeBeginPeriod(1) } == TIMER_OK;
        Self {
            period: granted.then_some(1),
        }
    }

    #[cfg(not(windows))]
    pub fn raise() -> Self {
        Self {}
    }

    /// Whether the raise was granted. Reported in session telemetry so a
    /// machine that refused it can be told apart from one that never asked.
    #[cfg(windows)]
    pub fn active(&self) -> bool {
        self.period.is_some()
    }

    #[cfg(not(windows))]
    pub fn active(&self) -> bool {
        false
    }
}

impl Drop for HighResolutionTimer {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(period) = self.period.take() {
            unsafe { bindings::timeEndPeriod(period) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_raise_is_balanced_by_its_drop() {
        // Each raise must be released exactly once, so nesting and dropping in
        // any order has to stay sound.
        let outer = HighResolutionTimer::raise();
        {
            let inner = HighResolutionTimer::raise();
            assert_eq!(inner.active(), cfg!(windows));
        }
        assert_eq!(outer.active(), cfg!(windows));
    }
}
