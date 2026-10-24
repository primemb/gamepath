//! Bounded, cancellable Windows RAS negotiation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::Rras::{
    HRASCONN, RASCONNSTATE, RASCONNSTATUSW, RASCS_Connected, RASCS_Disconnected, RASDIALPARAMSW,
    RasDialW, RasGetConnectStatusW,
};

const DIAL_TIMEOUT: Duration = Duration::from_secs(45);

// A notifier makes RasDial asynchronous. Polling owns all state, so the
// callback needs no borrowed context that could outlive a cancelled dial.
unsafe extern "system" fn notified(_: u32, _: RASCONNSTATE, _: u32) {}

pub(crate) fn dial(
    phonebook: &[u16],
    params: &RASDIALPARAMSW,
    connection: &mut HRASCONN,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    wait(
        cancelled,
        DIAL_TIMEOUT,
        || unsafe {
            let result = RasDialW(
                std::ptr::null(),
                phonebook.as_ptr(),
                params,
                0,
                notified as *const () as *const std::ffi::c_void,
                connection,
            );
            if result == 0 {
                Ok(*connection)
            } else {
                Err(super::l2tp::ras_error(result))
            }
        },
        |connection| {
            let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
            status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
            let result = unsafe { RasGetConnectStatusW(*connection, &mut status) };
            if result != 0 || status.dwError != 0 {
                return Err(super::l2tp::ras_error(if result != 0 {
                    result
                } else {
                    status.dwError
                }));
            }
            if status.rasconnstate == RASCS_Disconnected {
                return Err("Windows disconnected the L2TP/IPsec negotiation".into());
            }
            Ok(status.rasconnstate == RASCS_Connected)
        },
    )
}

fn wait<T>(
    cancelled: &AtomicBool,
    timeout: Duration,
    start: impl FnOnce() -> Result<T, String>,
    mut connected: impl FnMut(&T) -> Result<bool, String>,
) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        return Err("L2TP/IPsec connection cancelled".into());
    }
    let deadline = Instant::now() + timeout;
    let connection = start()?;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("L2TP/IPsec connection cancelled".into());
        }
        if connected(&connection)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("L2TP/IPsec negotiation timed out after 45 seconds".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_prevents_a_dial_and_interrupts_one_in_progress() {
        let cancelled = AtomicBool::new(true);
        assert!(
            wait(
                &cancelled,
                DIAL_TIMEOUT,
                || panic!("cancelled dial started"),
                |_: &()| Ok(false)
            )
            .is_err()
        );
        cancelled.store(false, Ordering::Release);
        let started = Instant::now();
        let result = wait(
            &cancelled,
            DIAL_TIMEOUT,
            || Ok(()),
            |_| {
                cancelled.store(true, Ordering::Release);
                Ok(false)
            },
        );
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn negotiation_reports_success_errors_and_a_deadline() {
        let cancelled = AtomicBool::new(false);
        assert!(wait(&cancelled, DIAL_TIMEOUT, || Ok(()), |_| Ok(true)).is_ok());
        assert_eq!(
            wait(
                &cancelled,
                DIAL_TIMEOUT,
                || Ok(()),
                |_| Err("RAS error 809".into())
            )
            .unwrap_err(),
            "RAS error 809"
        );
        assert!(
            wait(&cancelled, Duration::ZERO, || Ok(()), |_| Ok(false))
                .unwrap_err()
                .contains("timed out")
        );
    }
}
