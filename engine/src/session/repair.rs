//! Loss repair on the client side of a relay session.
//!
//! Uplink: every data frame the dispatcher sends joins the encoder's open
//! group, and the group's repair is sealed and sent like any other frame. A
//! repair goes to one healthy path, preferring one not carrying data, so a
//! burst on the carrying paths cannot take a packet and its repair together.
//! It used to go to every healthy path: on a live four-route session that made
//! repairs over half of all upload packets, each with ~145-200 bytes of tunnel
//! overhead, on a link whose stalls looked upload-only. A loss that reaches every
//! copy of a packet is shared by the uplink, which takes extra repair copies
//! down with it, so they bought nothing and added to the congestion.
//!
//! Downlink: the relay encodes its replies the same way once this client has
//! offered, with the same group size this side uses and this session's tunnel
//! MTU. Path workers send the offer and read the relay's acceptance. A
//! relay that never accepts predates loss repair; the session then runs
//! exactly as it did before, and nothing is spent on repairs it would discard.

use super::dispatch::Dispatch;
use super::worker::PATH_QUEUE_DEPTH;
use gamepath_engine::auth::SessionCrypto;
use gamepath_engine::fec::{self, Encoder, MultipathPolicy, Offer, ProbeHistory};
use gamepath_engine::protocol::{FLAG_REPAIR, FrameHeader};
use gamepath_engine::thread_priority;
use gamepath_engine::{log_info, log_warn};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const UNKNOWN: u8 = 0;
const SUPPORTED: u8 = 1;
const LEGACY: u8 = 2;

/// How often an unanswered or outdated offer is sent again. Short, because the
/// relay's group size should follow a path failing within a few probes.
const OFFER_RETRY: Duration = Duration::from_millis(250);

/// Offers a relay may leave unanswered before it is reported as predating
/// loss repair: three seconds of silence while paths are answering probes.
const OFFER_LIMIT: u32 = 12;

/// Even in step, the offer is repeated this often. A relay that restarted has
/// forgotten it, and the client would otherwise keep sending repairs the relay
/// discards while its replies go unprotected.
const OFFER_REFRESH: Duration = Duration::from_secs(5);

/// A relay reported as predating loss repair is still asked now and then, so a
/// dropped run of offers on a bad network does not disable repair for the
/// rest of the session.
const LEGACY_OFFER_RETRY: Duration = Duration::from_secs(10);

/// Longest the flusher sleeps with no group open. It is woken whenever a group
/// opens or the session stops, so this only bounds a missed wakeup.
const IDLE_WAIT: Duration = Duration::from_millis(250);

/// Queue depth past which a path stops taking repairs. A quarter of the queue
/// is already milliseconds of backlog: the path is saturated, and more traffic
/// there only turns into the loss repairs exist to undo.
const REPAIR_QUEUE_LIMIT: u64 = (PATH_QUEUE_DEPTH / 4) as u64;

const NEVER: u64 = u64::MAX;

pub(crate) struct LossRepair {
    crypto: Arc<SessionCrypto>,
    client_id: [u8; 16],
    session_id: u64,
    sequences: Arc<AtomicU64>,
    dispatch: Arc<Dispatch>,
    decision_mask: Arc<AtomicU64>,
    encoder: Mutex<Encoder>,
    wake: Condvar,
    tunnel_mtu: u16,
    policy: Mutex<MultipathPolicy>,
    histories: Mutex<Vec<ProbeHistory>>,
    /// What `policy` last decided, read per packet without its lock.
    multipath_group: AtomicU8,
    support: AtomicU8,
    /// Group size the relay last confirmed for its replies; 0 before any.
    downlink_group: AtomicU8,
    offers_unanswered: AtomicU32,
    clock: Instant,
    last_offer_ms: AtomicU64,
    repairs_sent: AtomicU64,
}

/// One probe result, as [`LossRepair::record_probe`] needs it.
pub(crate) enum Probe {
    Lost,
    /// `after_outage` when the path had been declared down until this answer.
    Answered {
        after_outage: bool,
    },
}

pub(crate) struct RepairStatus {
    pub(crate) state: &'static str,
    pub(crate) uplink_group: u8,
    pub(crate) downlink_group: Option<u8>,
    pub(crate) repairs_sent: u64,
}

impl LossRepair {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        crypto: Arc<SessionCrypto>,
        client_id: [u8; 16],
        session_id: u64,
        sequences: Arc<AtomicU64>,
        dispatch: Arc<Dispatch>,
        decision_mask: Arc<AtomicU64>,
        tunnel_mtu: u16,
    ) -> Self {
        let routes = dispatch.commands.len();
        Self {
            crypto,
            client_id,
            session_id,
            sequences,
            dispatch,
            decision_mask,
            encoder: Mutex::new(Encoder::new(
                fec::SINGLE_PATH_GROUP,
                usize::from(tunnel_mtu),
            )),
            wake: Condvar::new(),
            tunnel_mtu,
            policy: Mutex::new(MultipathPolicy::default()),
            histories: Mutex::new(vec![ProbeHistory::default(); routes]),
            multipath_group: AtomicU8::new(fec::MULTIPATH_GROUP),
            support: AtomicU8::new(UNKNOWN),
            downlink_group: AtomicU8::new(0),
            offers_unanswered: AtomicU32::new(0),
            clock: Instant::now(),
            last_offer_ms: AtomicU64::new(NEVER),
            repairs_sent: AtomicU64::new(0),
        }
    }

    fn healthy(&self) -> u64 {
        self.dispatch.telemetry.healthy_mask.load(Ordering::Acquire)
    }

    /// Read per packet from the health mask, so the moment a second path comes
    /// back the next group is already sized for multipath.
    fn desired_group(&self) -> u8 {
        fec::group_size_for(
            self.healthy().count_ones(),
            self.multipath_group.load(Ordering::Acquire),
        )
    }

    /// Feeds the policy one probe result from path `index`, after its worker
    /// has recorded it. Only the paths carrying data count: a packet is lost
    /// for good when every copy of it is, and a clean standby the scheduler is
    /// not sending on rescues none of them.
    pub(crate) fn record_probe(&self, index: usize, probe: Probe) {
        let healthy = self.healthy();
        let bit = 1_u64.checked_shl(index as u32).unwrap_or(0);
        let mut histories = self.histories.lock().unwrap();
        if let Some(history) = histories.get_mut(index) {
            match probe {
                // The path is already out of service, so this loss belongs to
                // the outage that took it out, as did the run before it.
                Probe::Lost if healthy & bit == 0 => history.forget_outage(),
                Probe::Lost => history.record(true),
                Probe::Answered { after_outage } => {
                    if after_outage {
                        history.forget_outage();
                    }
                    history.record(false);
                }
            }
        }
        // What the dispatcher is sending on, as `selected_paths` has it, except
        // that nothing healthy means nothing carrying rather than a fallback.
        let decision = self.decision_mask.load(Ordering::Acquire);
        let carrying = if decision & healthy != 0 {
            decision & healthy
        } else {
            healthy
        };
        let mut policy = self.policy.lock().unwrap();
        if carrying == 0 {
            // Nothing is carrying, so nothing observed now says anything about
            // how the paths carry. Whatever was building up starts over.
            policy.interrupt();
            return;
        }
        let best_loss = histories
            .iter()
            .enumerate()
            .filter(|(path, _)| carrying & 1_u64.checked_shl(*path as u32).unwrap_or(0) != 0)
            .map(|(_, history)| history.loss().unwrap_or(0.0))
            .fold(f64::INFINITY, f64::min);
        drop(histories);
        let group = policy.observe(best_loss, Instant::now());
        drop(policy);
        let previous = self.multipath_group.swap(group, Ordering::AcqRel);
        if previous != group {
            log_info!(
                "session {} loss repair now 1 per {group} packets on multipath: the best \
                 carrying path lost {:.0}% of its recent probes",
                self.session_id,
                best_loss * 100.0
            );
        }
    }

    /// Adds a data frame the dispatcher has just sent as `sequence`.
    pub(crate) fn protect(&self, sequence: u64, packet: &[u8]) {
        if self.support.load(Ordering::Acquire) != SUPPORTED {
            return;
        }
        let group = self.desired_group();
        let (resized, closed, opened) = {
            let mut encoder = self.encoder.lock().unwrap();
            let resized = encoder.set_group_size(group);
            let idle = encoder.deadline().is_none();
            let closed = encoder.push(sequence, packet, Instant::now());
            (resized, closed, idle && encoder.deadline().is_some())
        };
        // A flusher already waiting on a deadline wakes for it and rereads the
        // encoder, so only one sleeping with nothing open needs telling.
        if opened {
            self.wake.notify_one();
        }
        for repair in resized.into_iter().chain(closed) {
            self.send(repair);
        }
    }

    fn send(&self, repair: Vec<u8>) {
        let healthy = self.healthy();
        let candidates = if healthy != 0 {
            healthy
        } else {
            self.decision_mask.load(Ordering::Acquire)
        };
        let mask = self.with_room(candidates);
        if mask == 0 {
            return;
        }
        let carrying = self.decision_mask.load(Ordering::Acquire);
        let mask = repair_target(mask, carrying, self.repairs_sent.load(Ordering::Relaxed));
        let header = FrameHeader {
            flags: FLAG_REPAIR,
            client_id: self.client_id,
            session_id: self.session_id,
            sequence: self.sequences.fetch_add(1, Ordering::Relaxed),
        };
        let Ok(frame) = self.crypto.seal_client(header, &repair) else {
            return;
        };
        if self.dispatch.send(frame, mask).accepted > 0 {
            self.repairs_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drops from `mask` every path whose queue is already backing up. A repair
    /// is worth less than the packets it protects, so on a saturated path it
    /// gives way rather than taking queue space a game packet then cannot get.
    fn with_room(&self, mask: u64) -> u64 {
        self.dispatch
            .telemetry
            .queue_depth
            .iter()
            .enumerate()
            .filter(|(_, depth)| depth.load(Ordering::Relaxed) >= REPAIR_QUEUE_LIMIT)
            .fold(mask, |mask, (index, _)| {
                mask & !1_u64.checked_shl(index as u32).unwrap_or(0)
            })
    }

    /// Asked by each path worker once per iteration. Returns the offer to send
    /// when it is this worker's turn: its own path has to be healthy, or the
    /// offer would only be lost with it.
    pub(crate) fn offer_due(&self, path_healthy: bool) -> Option<Offer> {
        if !path_healthy {
            return None;
        }
        let support = self.support.load(Ordering::Acquire);
        let desired = self.desired_group();
        let in_step =
            support == SUPPORTED && self.downlink_group.load(Ordering::Acquire) == desired;
        let retry = match support {
            _ if in_step => OFFER_REFRESH,
            LEGACY => LEGACY_OFFER_RETRY,
            _ => OFFER_RETRY,
        };
        let now = self.clock.elapsed().as_millis() as u64;
        let last = self.last_offer_ms.load(Ordering::Acquire);
        if last != NEVER && now < last.saturating_add(retry.as_millis() as u64) {
            return None;
        }
        // Several workers can see the offer due at once; one of them sends it.
        self.last_offer_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        if support == UNKNOWN
            && self.offers_unanswered.fetch_add(1, Ordering::AcqRel) + 1 >= OFFER_LIMIT
            && self
                .support
                .compare_exchange(UNKNOWN, LEGACY, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            log_warn!(
                "session {} relay did not answer loss-repair offers; it predates loss repair, \
                 so traffic is carried without repairs. Update the relay to enable it.",
                self.session_id
            );
        }
        Some(Offer {
            group_size: desired,
            mtu: self.tunnel_mtu,
        })
    }

    /// The relay confirmed it protects its replies with `group`-sized groups.
    pub(crate) fn accepted(&self, group: u8) {
        self.offers_unanswered.store(0, Ordering::Release);
        self.downlink_group.store(group, Ordering::Release);
        if self.support.swap(SUPPORTED, Ordering::AcqRel) != SUPPORTED {
            log_info!(
                "session {} loss repair active: relay protects replies in groups of {group}",
                self.session_id
            );
        }
    }

    /// Called after the session's stop flag is set. Taking the lock first means
    /// the flusher is either about to read the flag or already waiting, so the
    /// wakeup cannot fall between the two.
    pub(crate) fn wake_flusher(&self) {
        drop(self.encoder.lock().unwrap());
        self.wake.notify_all();
    }

    pub(crate) fn status(&self) -> RepairStatus {
        RepairStatus {
            state: match self.support.load(Ordering::Acquire) {
                SUPPORTED => "active",
                LEGACY => "unsupported",
                _ => "negotiating",
            },
            // What the next packet will use; the encoder only catches up when
            // traffic flows.
            uplink_group: self.desired_group(),
            downlink_group: match self.downlink_group.load(Ordering::Acquire) {
                0 => None,
                group => Some(group),
            },
            repairs_sent: self.repairs_sent.load(Ordering::Relaxed),
        }
    }
}

/// The single path a repair takes out of `mask`: a spare one when any is free
/// of data, otherwise one of the carrying ones, rotated by `turn` so no one
/// path carries every repair.
fn repair_target(mask: u64, carrying: u64, turn: u64) -> u64 {
    let spare = mask & !carrying;
    let mut pool = if spare != 0 { spare } else { mask };
    for _ in 0..turn % u64::from(pool.count_ones()) {
        pool &= pool - 1;
    }
    pool & pool.wrapping_neg()
}

/// Closes groups that stopped growing, so a game's last packet before a pause
/// is covered within [`fec::GROUP_MAX_AGE`] rather than whenever the next one
/// comes along.
pub(crate) fn spawn_flusher(
    repair: &Arc<LossRepair>,
    stop: &Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    let repair = Arc::clone(repair);
    let stop = Arc::clone(stop);
    thread::Builder::new()
        .name("gamepath-loss-repair".into())
        .spawn(move || {
            thread_priority::raise_current_for_data_plane();
            let mut encoder = repair.encoder.lock().unwrap();
            while !stop.load(Ordering::Acquire) {
                let now = Instant::now();
                let wait = match encoder.deadline() {
                    None => IDLE_WAIT,
                    Some(deadline) if deadline > now => deadline - now,
                    Some(_) => {
                        let due = encoder.flush_due(now);
                        drop(encoder);
                        if let Some(repair_frame) = due {
                            repair.send(repair_frame);
                        }
                        encoder = repair.encoder.lock().unwrap();
                        continue;
                    }
                };
                encoder = repair.wake.wait_timeout(encoder, wait).unwrap().0;
            }
        })
}

#[cfg(test)]
mod tests {
    use super::repair_target;

    #[test]
    fn a_repair_takes_exactly_one_path() {
        for turn in 0..8 {
            assert_eq!(repair_target(0b1111, 0b0011, turn).count_ones(), 1);
        }
    }

    #[test]
    fn a_repair_prefers_a_path_not_carrying_data_and_rotates_among_them() {
        assert_eq!(repair_target(0b1111, 0b0011, 0), 0b0100);
        assert_eq!(repair_target(0b1111, 0b0011, 1), 0b1000);
        assert_eq!(repair_target(0b1111, 0b0011, 2), 0b0100);
    }

    #[test]
    fn with_every_path_carrying_a_repair_rotates_over_them() {
        assert_eq!(repair_target(0b0011, 0b0011, 0), 0b0001);
        assert_eq!(repair_target(0b0011, 0b0011, 1), 0b0010);
    }
}
