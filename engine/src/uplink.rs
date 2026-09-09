//! Direct evidence that this machine can reach the Internet at all.
//!
//! When every path stops answering at once the cause is almost always the one
//! thing they share — the local uplink — and the two reflexes that serve a
//! single failing path (redial it, duplicate onto it) both make a local outage
//! worse. Deciding that from the paths themselves is guesswork: it infers a
//! shared cause from correlated symptoms, and it cannot work at all for a
//! single-path session, where there is nothing to correlate against.
//!
//! So this asks the question directly, with an ICMP echo to a public address
//! that does not go through any node. A reply is positive proof the uplink is
//! up; silence for several probes in a row is good evidence it is not.
//!
//! **The probe is pinned to the physical adapter by source address, not by a
//! route.** In all-traffic mode the tunnel owns the default route, so reaching a
//! public address would otherwise need a bypass host route for it — and that
//! route is a hole, because every packet the user sends to that address would
//! then leave untunnelled. Putting one on a public resolver address is not an
//! acceptable trade in a VPN client. Binding the echo to the physical adapter's
//! own address gets the probe out of the same interface without any route, so
//! nothing else changes path.
//!
//! The answer is deliberately three-valued. Plenty of networks drop ICMP, and a
//! monitor that cannot get a reply must say [`UplinkState::Unknown`] rather than
//! claim the uplink is down — otherwise a filtered probe would stop every path
//! from ever redialling.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

/// Where the uplink probe is aimed: a public resolver on anycast, so it is
/// close to every user and reliably answers echo requests.
pub const PROBE_TARGET: std::net::Ipv4Addr = std::net::Ipv4Addr::new(8, 8, 8, 8);

/// Gap between uplink probes. This is a background sanity check, not a latency
/// measurement, so it is far slower than a path's own probe.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// How long one probe waits for its reply.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Consecutive unanswered probes before the uplink is called down.
///
/// The uplink is the thing every path depends on, so being wrong about it is
/// expensive in both directions: too eager and paths stop redialling when they
/// should, too slow and they hammer a link that cannot carry them.
pub const FAILURES_BEFORE_DOWN: u32 = 3;

/// Answered probes needed before a recovered uplink is trusted again.
///
/// One is enough. Recovery should be immediate — this is a game client, and
/// every path is waiting on this answer to start reconnecting.
pub const SUCCESSES_BEFORE_UP: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UplinkState {
    /// No usable answer yet, or ICMP appears to be filtered. Callers must treat
    /// this as "carry on as before", never as a failure.
    Unknown = 0,
    Up = 1,
    Down = 2,
}

impl UplinkState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Up,
            2 => Self::Down,
            _ => Self::Unknown,
        }
    }
}

/// Shared, lock-free view of the uplink for the path workers.
#[derive(Debug, Default)]
pub struct UplinkMonitor {
    state: AtomicU8,
    transitions: AtomicU64,
}

impl UplinkMonitor {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(UplinkState::Unknown as u8),
            transitions: AtomicU64::new(0),
        }
    }

    pub fn state(&self) -> UplinkState {
        UplinkState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// True only when the uplink is known to be down. `Unknown` is not down.
    pub fn is_known_down(&self) -> bool {
        self.state() == UplinkState::Down
    }

    /// How many times the verdict has changed, for diagnostics.
    pub fn transitions(&self) -> u64 {
        self.transitions.load(Ordering::Relaxed)
    }

    /// Records a verdict, returning the previous one when it changed.
    pub fn publish(&self, next: UplinkState) -> Option<UplinkState> {
        let previous = UplinkState::from_u8(self.state.swap(next as u8, Ordering::AcqRel));
        if previous == next {
            return None;
        }
        self.transitions.fetch_add(1, Ordering::Relaxed);
        Some(previous)
    }
}

/// Turns a run of probe outcomes into a verdict.
///
/// Kept separate from the probing so the policy is testable without a network:
/// the counting rules are the part that decides whether paths reconnect.
#[derive(Debug, Default)]
pub struct UplinkVerdict {
    failures: u32,
    successes: u32,
    /// Set once any probe has ever been answered. Until then, silence means
    /// "ICMP is probably filtered here", not "the uplink is down" - a machine
    /// whose network blocks ICMP must not have every path frozen.
    ever_answered: bool,
}

impl UplinkVerdict {
    pub fn record(&mut self, answered: bool) -> UplinkState {
        if answered {
            self.ever_answered = true;
            self.failures = 0;
            self.successes += 1;
            if self.successes >= SUCCESSES_BEFORE_UP {
                return UplinkState::Up;
            }
            return UplinkState::Unknown;
        }
        self.successes = 0;
        self.failures += 1;
        if !self.ever_answered {
            // Never had an answer, so silence proves nothing about the uplink.
            return UplinkState::Unknown;
        }
        if self.failures >= FAILURES_BEFORE_DOWN {
            return UplinkState::Down;
        }
        UplinkState::Unknown
    }
}

/// Sends one ICMP echo to `target`, returning whether a reply came back.
///
/// Uses the IP Helper echo API rather than a raw socket: it needs no special
/// privilege beyond what the engine already has, and it does not require
/// parsing the reply, because the return value is the number of replies.
#[cfg(windows)]
pub fn probe_once(
    target: std::net::Ipv4Addr,
    source: Option<std::net::Ipv4Addr>,
    timeout: Duration,
) -> bool {
    use std::ffi::c_void;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> isize;
        fn IcmpCloseHandle(handle: isize) -> i32;
        fn IcmpSendEcho(
            handle: isize,
            destination: u32,
            request: *const c_void,
            request_size: u16,
            options: *const c_void,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn IcmpSendEcho2Ex(
            handle: isize,
            event: isize,
            apc_routine: *const c_void,
            apc_context: *const c_void,
            source: u32,
            destination: u32,
            request: *const c_void,
            request_size: u16,
            options: *const c_void,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
    }

    // Addresses go on the wire in network byte order, which on a little-endian
    // host means the octets in the order they are written.
    let destination = u32::from_le_bytes(target.octets());
    let request = [0x61_u8; 32];
    // Must hold one ICMP_ECHO_REPLY plus the echoed request. Generous, so the
    // exact struct layout never has to be reproduced here.
    let mut reply = [0_u8; 256];
    let timeout = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    unsafe {
        let handle = IcmpCreateFile();
        if handle == -1 {
            return false;
        }
        let replies = match source {
            // Pinned to the physical adapter, so the probe leaves by it without
            // a route of its own.
            Some(source) => IcmpSendEcho2Ex(
                handle,
                0,
                std::ptr::null(),
                std::ptr::null(),
                u32::from_le_bytes(source.octets()),
                destination,
                request.as_ptr().cast(),
                request.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout,
            ),
            None => IcmpSendEcho(
                handle,
                destination,
                request.as_ptr().cast(),
                request.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout,
            ),
        };
        IcmpCloseHandle(handle);
        replies > 0
    }
}

#[cfg(not(windows))]
pub fn probe_once(
    _target: std::net::Ipv4Addr,
    _source: Option<std::net::Ipv4Addr>,
    _timeout: Duration,
) -> bool {
    false
}

/// Runs the probe loop until `stop` is set.
pub fn run(
    monitor: Arc<UplinkMonitor>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    source: Option<std::net::Ipv4Addr>,
    mut on_change: impl FnMut(UplinkState, UplinkState),
) {
    let mut verdict = UplinkVerdict::default();
    let mut next = std::time::Instant::now();
    while !stop.load(Ordering::Acquire) {
        if std::time::Instant::now() < next {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        next = std::time::Instant::now() + PROBE_INTERVAL;
        let answered = probe_once(PROBE_TARGET, source, PROBE_TIMEOUT);
        let state = verdict.record(answered);
        if let Some(previous) = monitor.publish(state) {
            on_change(previous, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unproven_uplink_is_unknown_not_down() {
        let mut verdict = UplinkVerdict::default();
        // A network that filters ICMP must never freeze every path.
        for _ in 0..50 {
            assert_eq!(verdict.record(false), UplinkState::Unknown);
        }
    }

    #[test]
    fn a_uplink_that_answered_once_can_then_be_called_down() {
        let mut verdict = UplinkVerdict::default();
        assert_eq!(verdict.record(true), UplinkState::Up);
        for _ in 1..FAILURES_BEFORE_DOWN {
            assert_eq!(verdict.record(false), UplinkState::Unknown);
        }
        assert_eq!(verdict.record(false), UplinkState::Down);
    }

    #[test]
    fn recovery_is_immediate_because_every_path_is_waiting_on_it() {
        let mut verdict = UplinkVerdict::default();
        verdict.record(true);
        for _ in 0..FAILURES_BEFORE_DOWN {
            verdict.record(false);
        }
        assert_eq!(verdict.record(true), UplinkState::Up);
    }

    #[test]
    fn a_single_lost_probe_does_not_condemn_the_uplink() {
        let mut verdict = UplinkVerdict::default();
        verdict.record(true);
        assert_eq!(verdict.record(false), UplinkState::Unknown);
        assert_eq!(verdict.record(true), UplinkState::Up);
    }

    #[test]
    fn the_monitor_reports_only_real_changes() {
        let monitor = UplinkMonitor::new();
        assert_eq!(monitor.state(), UplinkState::Unknown);
        assert!(!monitor.is_known_down());
        assert_eq!(monitor.publish(UplinkState::Up), Some(UplinkState::Unknown));
        assert_eq!(monitor.publish(UplinkState::Up), None);
        assert_eq!(monitor.publish(UplinkState::Down), Some(UplinkState::Up));
        assert!(monitor.is_known_down());
        assert_eq!(monitor.transitions(), 2);
    }

    /// Exercises the real ICMP call. Ignored by default because it needs the
    /// network, but it is the only way to know the FFI signature is right.
    /// Exercises the real ICMP call with no source pinning.
    #[test]
    #[ignore = "requires a working uplink"]
    fn the_probe_reaches_the_public_target() {
        assert!(
            probe_once(PROBE_TARGET, None, PROBE_TIMEOUT),
            "no echo reply from {PROBE_TARGET}"
        );
    }

    /// And with it, which is the form the session actually uses: the same
    /// target has to answer when the echo is pinned to this machine's own
    /// adapter address.
    #[test]
    #[ignore = "requires a working uplink"]
    fn the_probe_reaches_the_target_when_pinned_to_the_local_adapter() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect("8.8.8.8:53").unwrap();
        let std::net::IpAddr::V4(source) = socket.local_addr().unwrap().ip() else {
            panic!("expected an IPv4 source address");
        };
        assert!(
            probe_once(PROBE_TARGET, Some(source), PROBE_TIMEOUT),
            "no echo reply from {PROBE_TARGET} sourced at {source}"
        );
    }

    #[test]
    #[ignore = "requires a working uplink"]
    fn an_unroutable_address_does_not_answer() {
        // Reserved for documentation, so nothing should reply.
        let blackhole = std::net::Ipv4Addr::new(192, 0, 2, 1);
        assert!(!probe_once(blackhole, None, Duration::from_millis(300)));
    }

    #[test]
    fn unknown_is_never_treated_as_down() {
        let monitor = UplinkMonitor::new();
        monitor.publish(UplinkState::Unknown);
        assert!(!monitor.is_known_down());
    }
}
