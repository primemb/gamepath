//! Bounded, cancellable Windows RAS negotiation.
//!
//! `RasDialW` with a notifier returns at once and reports progress, and the
//! error that ends a failed dial, to the notifier. Polling
//! `RasGetConnectStatusW` alone is not enough: measured live, the first poll
//! after the call returned ERROR_INVALID_HANDLE (6) before Windows had
//! registered the dial, so every attempt was hung up within a second and
//! logged by RasClient as failed with error 0.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::Rras::{
    HRASCONN, RASCONNSTATE, RASCONNSTATUSW, RASCS_Connected, RASCS_Disconnected, RASDIALPARAMSW,
    RasDialW, RasGetConnectStatusW,
};
use windows_sys::Win32::System::Threading::SleepEx;

const DIAL_TIMEOUT: Duration = Duration::from_secs(45);

/// `dwNotifierType` for a `RasDialFunc2` notifier.
const RAS_DIAL_FUNC2: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Progress {
    Dialing,
    Connected,
    Failed(u32),
    Disconnected,
}

/// Progress of each dial in flight, keyed by the `dwCallbackId` it was given.
/// Global rather than borrowed, so a notification arriving after a cancelled
/// dial returned finds nothing and is ignored.
static DIALS: Mutex<BTreeMap<usize, Progress>> = Mutex::new(BTreeMap::new());
static NEXT_DIAL: AtomicUsize = AtomicUsize::new(1);

/// `RasDialFunc2`. Called by RAS on each state change; the first error or
/// final state a dial reaches is kept.
unsafe extern "system" fn notified(
    dial: usize,
    _subentry: u32,
    _connection: HRASCONN,
    _message: u32,
    state: RASCONNSTATE,
    error: u32,
    _extended_error: u32,
) -> u32 {
    let mut dials = DIALS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(progress) = dials.get_mut(&dial) {
        if *progress == Progress::Dialing {
            *progress = advance(state, error);
        }
    }
    1
}

fn advance(state: RASCONNSTATE, error: u32) -> Progress {
    if error != 0 {
        Progress::Failed(error)
    } else if state == RASCS_Connected {
        Progress::Connected
    } else if state == RASCS_Disconnected {
        Progress::Disconnected
    } else {
        Progress::Dialing
    }
}

pub(crate) fn dial(
    phonebook: &[u16],
    params: &RASDIALPARAMSW,
    connection: &mut HRASCONN,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    let id = NEXT_DIAL.fetch_add(1, Ordering::Relaxed);
    DIALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(id, Progress::Dialing);
    let mut params = *params;
    params.dwCallbackId = id;
    let result = wait(
        cancelled,
        DIAL_TIMEOUT,
        || unsafe {
            let result = RasDialW(
                std::ptr::null(),
                phonebook.as_ptr(),
                &params,
                RAS_DIAL_FUNC2,
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
            let progress = DIALS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&id)
                .copied()
                .unwrap_or(Progress::Dialing);
            match progress {
                Progress::Connected => Ok(true),
                Progress::Failed(error) => Err(super::l2tp::ras_error(error)),
                Progress::Disconnected => {
                    Err("Windows disconnected the L2TP/IPsec negotiation".into())
                }
                // A missed notification must not cost a working connection;
                // a status error here only means Windows has not caught up.
                Progress::Dialing => Ok(connected_by_status(*connection)),
            }
        },
    );
    DIALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&id);
    params.szUserName.fill(0);
    params.szPassword.fill(0);
    result
}

fn connected_by_status(connection: HRASCONN) -> bool {
    let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
    status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
    let result = unsafe { RasGetConnectStatusW(connection, &mut status) };
    result == 0 && status.dwError == 0 && status.rasconnstate == RASCS_Connected
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
        // Alertable: RAS notifies "in the context of a thread captured during
        // the initial call to RasDial", which may be this one.
        unsafe { SleepEx(100, 1) };
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
    fn the_notifier_keeps_the_first_error_or_final_state() {
        let id = NEXT_DIAL.fetch_add(1, Ordering::Relaxed);
        DIALS.lock().unwrap().insert(id, Progress::Dialing);
        let notify = |state, error| unsafe { notified(id, 0, 0, 0, state, error, 0) };
        assert_eq!(notify(0, 0), 1, "notifications keep coming");
        assert_eq!(DIALS.lock().unwrap()[&id], Progress::Dialing);
        notify(0, 809);
        notify(RASCS_Connected, 0);
        assert_eq!(DIALS.lock().unwrap()[&id], Progress::Failed(809));
        DIALS.lock().unwrap().remove(&id);
        notify(RASCS_Connected, 0);
        assert!(!DIALS.lock().unwrap().contains_key(&id), "a finished dial");
        assert_eq!(advance(RASCS_Connected, 0), Progress::Connected);
        assert_eq!(advance(RASCS_Disconnected, 0), Progress::Disconnected);
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
