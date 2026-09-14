//! Reopening a path that stopped answering, and deciding when that is even
//! worth attempting.
//!
//! Redialling a path costs a handshake and, for L2TP/IPsec, up to twenty
//! seconds of play. The rules for escalating from a cheap reopen to a full
//! rebuild, for backing off, and for standing down when the evidence points at
//! this machine's uplink rather than the path all live here so they can be
//! tested without a node or a network.

use gamepath_engine::relay_path::{NodeSpec, RelayPath, ReopenEffort};
use gamepath_engine::uplink::{self, UplinkState};
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// What a path worker needs to open its transport again.
///
/// The transport is opened once when the session starts, and for WireGuard that
/// is enough: BoringTun re-initiates a handshake from its own timers, so a
/// rekey or a peer restart recovers on its own. A SOCKS5 association and an
/// OpenVPN link have no such mechanism - once the proxy drops the control
/// connection or the tunnel dies, that path stays dead for the whole session
/// unless something dials it again. This is what does that.
#[derive(Clone)]
pub(crate) struct PathDialer {
    pub(crate) node: NodeSpec,
    pub(crate) relay: SocketAddrV4,
    /// Whether the next reopen may take the cheap route.
    ///
    /// Shared with the worker rather than owned by it, because the dial runs on
    /// its own thread. Set again every time the path answers a probe, so the
    /// cheap attempt is offered once per outage: if it does not hold, the next
    /// attempt is the full rebuild, and a path can never sit in a loop of cheap
    /// reopens that do not fix it.
    pub(crate) cheap_reopen: Arc<AtomicBool>,
}

/// Takes the cheap attempt if one is on offer, and withdraws the offer.
///
/// Separated from the dial so the escalation can be tested without a node or a
/// network: it is the part that has to be right, because getting it wrong in
/// one direction costs twenty seconds of play and in the other loops for ever
/// on a rebuild that never helps.
fn choose_reopen_effort(cheap_allowed: &AtomicBool) -> ReopenEffort {
    if cheap_allowed.swap(false, Ordering::AcqRel) {
        ReopenEffort::Cheap
    } else {
        ReopenEffort::Full
    }
}

impl PathDialer {
    pub(crate) fn open(&self) -> Result<Box<dyn RelayPath>, String> {
        self.node
            .reopen(self.relay, choose_reopen_effort(&self.cheap_reopen))
    }

    /// Lets the next recovery try the cheap route again. Called when the path
    /// has proved itself, which is what makes the offer safe to renew.
    pub(crate) fn allow_cheap_reopen(&self) {
        self.cheap_reopen.store(true, Ordering::Release);
    }
}

/// Keep an obsolete dial in its slot until it finishes, so recovery followed
/// by another outage cannot spawn overlapping connections to the same node.
pub(crate) struct ReconnectAttempt<T> {
    receiver: mpsc::Receiver<Result<T, String>>,
    superseded: bool,
}

pub(crate) enum ReconnectPoll<T> {
    Pending,
    Discarded,
    Finished(Result<T, String>),
}

impl<T> ReconnectAttempt<T> {
    pub(crate) fn new(receiver: mpsc::Receiver<Result<T, String>>) -> Self {
        Self {
            receiver,
            superseded: false,
        }
    }

    pub(crate) fn recovered(&mut self) {
        self.superseded = true;
    }

    pub(crate) fn poll(&mut self) -> ReconnectPoll<T> {
        let result = match self.receiver.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return ReconnectPoll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("reconnect worker stopped without a result".to_owned())
            }
        };
        if self.superseded {
            ReconnectPoll::Discarded
        } else {
            ReconnectPoll::Finished(result)
        }
    }
}

/// Consecutive failed health checks before a path's transport is redialled.
/// Three of them is a little over a second of silence, long enough that a
/// single lost probe or a brief stall does not tear down a working socket.
const RECONNECT_AFTER_FAILURES: u32 = 3;

/// Wait before the *first* redial once a path is judged dead.
///
/// Zero: by this point the path has missed several probes in a row and another
/// path is up, so the uplink is known good and there is nothing to gain by
/// waiting. Later attempts back off from [`RECONNECT_BACKOFF_STEP`].
pub(crate) const RECONNECT_BACKOFF_MIN: Duration = Duration::ZERO;

/// The wait the backoff grows from after the immediate first attempt.
const RECONNECT_BACKOFF_STEP: Duration = Duration::from_secs(1);

/// Longest wait between redial attempts. A provider that is down for an hour
/// is retried every half minute rather than hammered.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The wait after a failed redial. The first attempt is immediate, so the
/// sequence grows from [`RECONNECT_BACKOFF_STEP`] rather than doubling zero.
pub(crate) fn next_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        RECONNECT_BACKOFF_STEP
    } else {
        (current * 2).min(RECONNECT_BACKOFF_MAX)
    }
}

/// Arms the next redial once a path has failed [`RECONNECT_AFTER_FAILURES`]
/// health checks in a row, leaving an already-armed one alone so the backoff
/// is not restarted by every further failure.
pub(crate) fn schedule_redial(failures: u32, backoff: Duration, next_redial: &mut Option<Instant>) {
    if failures >= RECONNECT_AFTER_FAILURES && next_redial.is_none() {
        *next_redial = Some(Instant::now() + backoff);
    }
}

/// How long a path waits before reconsidering a redial while no other path is
/// up.
///
/// Independent providers do not fail in the same second. When every path stops
/// answering at once, the cause is the one thing they share - this machine's
/// uplink - and redialling cannot fix that: the dial has nowhere to go, and a
/// WireGuard redial throws away a working tunnel to negotiate a new handshake
/// over a link that is already struggling.
///
/// This only defers the *transport* redial. Probing continues throughout at its
/// normal cadence, so a path whose transport is still intact recovers the
/// instant the uplink does, without waiting for this at all. What it does bound
/// is recovery for a transport that genuinely cannot come back without a new
/// dial - a dropped OpenVPN connection, where WireGuard would rehandshake on
/// its own - so it is kept to three probe cycles, the same rhythm as
/// [`RECONNECT_AFTER_FAILURES`], rather than anything longer.
pub(crate) const UPLINK_DOWN_BACKOFF: Duration = Duration::from_secs(6);

/// Whether any path other than `index` is currently carrying traffic.
///
/// One healthy path proves the uplink works, which is what makes a redial of a
/// different path worth attempting.
pub(crate) fn another_path_is_up(healthy_mask: &AtomicU64, index: usize) -> bool {
    let own = 1_u64.checked_shl(index as u32).unwrap_or(0);
    healthy_mask.load(Ordering::Acquire) & !own != 0
}

/// How long every path being down at once is treated as evidence of a shared
/// cause while the uplink monitor still reports `Up`.
///
/// Sized from how long the monitor needs to change its mind: up to one
/// `uplink::PROBE_INTERVAL` before it probes again, then
/// `uplink::FAILURES_BEFORE_DOWN` probes that have to fail. A path declares
/// itself dead after three probes of its own, inside a second.
///
/// That gap was the bug. A real uplink stall shorter than the monitor's window
/// - a Wi-Fi hiccup, a router pause, a congestion burst, which is the common
/// case - killed every path at once while the monitor still said `Up`, so the
/// guard below never engaged and all of them redialled simultaneously into a
/// link that could not carry the dials. Observed live: three routes across two
/// unrelated providers went unavailable inside 1.2 s and all three redialled,
/// one of them an L2TP/IPsec RAS redial, with the monitor reporting `Up`
/// throughout.
const COMMON_MODE_CONFIRM_WINDOW: Duration = Duration::from_secs(
    uplink::PROBE_INTERVAL.as_secs() * (uplink::FAILURES_BEFORE_DOWN as u64 + 1),
);

/// Whether a failed path should hold its redial because the evidence points at
/// something shared rather than at the path itself.
///
/// `common_mode_for` is how long every path in the session has been down at
/// once, having previously carried traffic. It is `None` when at least one path
/// is up, when none has ever been up - a session still starting has not
/// collapsed, it has simply not arrived - and when the session has a single
/// path, which has nothing to compare itself against and so always redials.
pub(crate) fn hold_redial_for_common_mode(
    uplink: UplinkState,
    common_mode_for: Option<Duration>,
) -> bool {
    match uplink {
        // Measured down. Nothing a dial could accomplish.
        UplinkState::Down => true,
        // Measured up - but that measurement can be a probe interval old, and
        // promoting it to `Down` takes several more probes. Inside that window
        // the health mask is the fresher evidence, because it moves the moment
        // a path fails, so simultaneous failure outranks a stale `Up`. Past the
        // window the monitor has had every chance to agree and has not, so
        // these paths are down for their own reasons and must be allowed to
        // redial rather than wait for a verdict that is not coming.
        UplinkState::Up => {
            common_mode_for.is_some_and(|elapsed| elapsed < COMMON_MODE_CONFIRM_WINDOW)
        }
        // No measurement to weigh against, which is where a router filtering
        // ICMP leaves us, so the inference is all there is and gets no
        // deadline: an uplink that is genuinely down would look exactly like
        // this for as long as it stayed down.
        UplinkState::Unknown => common_mode_for.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::health::{PROBE_INTERVAL_DEGRADED, publish_path_health};
    use super::*;

    #[test]
    fn a_recovery_discards_an_already_running_reconnect() {
        let (sender, receiver) = mpsc::channel();
        let mut attempt = ReconnectAttempt::new(receiver);
        attempt.recovered();
        sender.send(Ok::<_, String>(42_u8)).unwrap();
        assert!(matches!(attempt.poll(), ReconnectPoll::Discarded));
    }

    #[test]
    fn a_reconnect_result_is_used_when_the_old_path_never_recovers() {
        let (sender, receiver) = mpsc::channel();
        let mut attempt = ReconnectAttempt::new(receiver);
        sender.send(Ok::<_, String>(42_u8)).unwrap();
        assert!(matches!(attempt.poll(), ReconnectPoll::Finished(Ok(42))));
    }

    /// One cheap attempt per outage, then the real thing. Getting this wrong
    /// either way is expensive: never escalating leaves a path rebuilding a
    /// socket that cannot help, and never offering the cheap attempt pays a
    /// twenty-second RAS redial for a relay that merely went quiet.
    #[test]
    fn a_reopen_escalates_after_the_cheap_attempt_is_spent() {
        let allowed = AtomicBool::new(true);
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Cheap);
        // Spent: every further attempt in this outage rebuilds properly.
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Full);
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Full);
    }

    #[test]
    fn a_recovered_path_is_offered_the_cheap_attempt_again() {
        let allowed = AtomicBool::new(true);
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Cheap);
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Full);
        // What the worker does once a probe is answered.
        allowed.store(true, Ordering::Release);
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Cheap);
    }

    /// A path that has never come up must not get the cheap attempt, or a
    /// session whose adapter was never usable would keep reusing it.
    #[test]
    fn a_dialer_that_is_not_offered_the_cheap_route_rebuilds() {
        let allowed = AtomicBool::new(false);
        assert_eq!(choose_reopen_effort(&allowed), ReopenEffort::Full);
    }

    #[test]
    fn the_uplink_backoff_is_longer_than_the_ordinary_one() {
        // Otherwise the guard would not actually slow anything down.
        assert!(UPLINK_DOWN_BACKOFF > RECONNECT_BACKOFF_STEP);
    }

    #[test]
    fn a_path_is_not_redialled_until_it_has_failed_repeatedly() {
        let mut next_redial = None;
        for failures in 1..RECONNECT_AFTER_FAILURES {
            schedule_redial(failures, RECONNECT_BACKOFF_MIN, &mut next_redial);
            assert!(
                next_redial.is_none(),
                "a working socket was torn down after {failures} lost probes"
            );
        }
        schedule_redial(
            RECONNECT_AFTER_FAILURES,
            RECONNECT_BACKOFF_MIN,
            &mut next_redial,
        );
        assert!(next_redial.is_some());
    }

    #[test]
    fn further_failures_do_not_restart_an_armed_backoff() {
        let armed = Instant::now() + Duration::from_secs(9);
        let mut next_redial = Some(armed);
        schedule_redial(
            RECONNECT_AFTER_FAILURES + 5,
            RECONNECT_BACKOFF_MIN,
            &mut next_redial,
        );
        assert_eq!(next_redial, Some(armed));
    }

    #[test]
    fn the_first_redial_is_immediate_and_later_ones_back_off() {
        let mut backoff = RECONNECT_BACKOFF_MIN;
        let mut waits = vec![backoff];
        for _ in 0..12 {
            backoff = next_backoff(backoff);
            waits.push(backoff);
        }
        // The path has already missed several probes and another path is up, so
        // the uplink is known good: the first attempt waits for nothing.
        assert_eq!(waits[0], Duration::ZERO);
        assert_eq!(waits[1], RECONNECT_BACKOFF_STEP);
        assert_eq!(waits[2], RECONNECT_BACKOFF_STEP * 2);
        assert!(
            waits
                .windows(2)
                .skip(1)
                .all(|pair| pair[1] > pair[0] || pair[1] == RECONNECT_BACKOFF_MAX),
            "the backoff has to keep growing until it reaches the ceiling"
        );
        // A provider that stays down is retried forever, never faster than the
        // ceiling and never so slowly that recovery is missed.
        assert_eq!(*waits.last().unwrap(), RECONNECT_BACKOFF_MAX);
        assert!(waits.iter().all(|wait| *wait <= RECONNECT_BACKOFF_MAX));
    }

    /// The whole point of this path is speed: a route that dies while another
    /// is up has to be back in service quickly enough to matter in a match.
    #[test]
    fn a_dead_route_is_redialled_within_a_few_seconds() {
        // On a settled fast route every cycle is the estimator's floor plus the
        // degraded gap, and the first dial itself waits for nothing.
        let cycle = gamepath_engine::rtt::MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let total = cycle * RECONNECT_AFTER_FAILURES + RECONNECT_BACKOFF_MIN;
        assert!(
            total <= Duration::from_secs(3),
            "a dead route would take {total:?} to redial"
        );
    }

    /// The monitor answers directly where it can, and the inference covers
    /// where it cannot.
    #[test]
    fn a_measured_uplink_overrides_the_inference_in_both_directions() {
        let recent = Some(Duration::ZERO);
        let none = None;
        // Measured down: no redial, even though another path looks up.
        assert!(hold_redial_for_common_mode(UplinkState::Down, none));
        // Something else is carrying traffic, so this path is on its own and
        // redials whatever the monitor thinks.
        assert!(!hold_redial_for_common_mode(UplinkState::Up, none));
        assert!(!hold_redial_for_common_mode(UplinkState::Unknown, none));
        // No measurement and nothing up: the inference is all there is.
        assert!(hold_redial_for_common_mode(UplinkState::Unknown, recent));
    }

    /// The bug this guard was missing. The monitor needs several seconds to
    /// turn `Up` into `Down`, and a path gives up in about one, so a short
    /// uplink stall used to leave every path redialling at once while the
    /// monitor still said `Up`.
    #[test]
    fn a_stale_up_does_not_override_every_path_failing_at_once() {
        assert!(hold_redial_for_common_mode(
            UplinkState::Up,
            Some(Duration::ZERO)
        ));
        assert!(hold_redial_for_common_mode(
            UplinkState::Up,
            Some(COMMON_MODE_CONFIRM_WINDOW - Duration::from_millis(1))
        ));
    }

    /// But it is a window, not a veto: once the monitor has had time to agree
    /// and has not, the paths are down for their own reasons and have to be
    /// allowed to recover. Without this the session could hold every redial
    /// indefinitely on transports that cannot come back without one.
    #[test]
    fn a_monitor_that_keeps_reporting_up_eventually_wins() {
        assert!(!hold_redial_for_common_mode(
            UplinkState::Up,
            Some(COMMON_MODE_CONFIRM_WINDOW)
        ));
        assert!(!hold_redial_for_common_mode(
            UplinkState::Up,
            Some(COMMON_MODE_CONFIRM_WINDOW * 10)
        ));
    }

    /// The window has to outlast the monitor's own verdict, or it would expire
    /// while a real outage was still being confirmed - which is exactly the
    /// case it exists to cover.
    #[test]
    fn the_confirmation_window_outlasts_the_monitors_decision() {
        let worst_case_to_declare_down =
            uplink::PROBE_INTERVAL * (uplink::FAILURES_BEFORE_DOWN + 1) - uplink::PROBE_INTERVAL;
        assert!(
            COMMON_MODE_CONFIRM_WINDOW >= worst_case_to_declare_down,
            "{COMMON_MODE_CONFIRM_WINDOW:?} is shorter than the {worst_case_to_declare_down:?} the monitor needs"
        );
        // And it is not so long that a path is stranded: the guard re-arms in
        // UPLINK_DOWN_BACKOFF steps, so this bounds one episode, not recovery.
        assert!(COMMON_MODE_CONFIRM_WINDOW <= Duration::from_secs(15));
    }

    /// A single-path session has nothing to compare against, so it is never
    /// held back - the caller passes `None` for it. The same goes for a session
    /// still starting up, where no path has carried traffic yet: that is not a
    /// collapse and its retries must not be slowed down.
    #[test]
    fn a_single_path_session_or_one_still_starting_always_redials() {
        for state in [UplinkState::Up, UplinkState::Unknown] {
            assert!(!hold_redial_for_common_mode(state, None));
        }
    }

    #[test]
    fn a_path_only_redials_while_another_path_proves_the_uplink_is_up() {
        let mask = AtomicU64::new(0);
        // Nothing is up: from route 0's view the uplink is the suspect.
        assert!(!another_path_is_up(&mask, 0));
        assert!(!another_path_is_up(&mask, 1));
        // Route 0 alone being up says nothing to route 0 itself, but proves the
        // uplink to route 1.
        publish_path_health(&mask, 0, true);
        assert!(!another_path_is_up(&mask, 0));
        assert!(another_path_is_up(&mask, 1));
        // Both up: each can see the other.
        publish_path_health(&mask, 1, true);
        assert!(another_path_is_up(&mask, 0));
        assert!(another_path_is_up(&mask, 1));
    }
}
