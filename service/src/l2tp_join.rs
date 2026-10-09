//! L2TP/IPsec routes dialled alongside a relay session instead of before it.
//!
//! A Windows RAS dial negotiates IKE, IPsec, L2TP and PPP. It takes seconds
//! when it works and can take forty when it does not: observed live, RAS error
//! 628 after 40 s while three WireGuard routes had been ready the whole time
//! and the player waited on all of it. The session now starts on whatever is
//! ready, and each L2TP route is handed to the running engine once Windows has
//! connected it.
//!
//! A failed dial is retried before the route is given up for the session: the
//! same provider that refused a negotiation often accepts the next one.

use crate::l2tp::{L2tpSession, connect_l2tp_node};
use crate::registry::Registry;
use crate::slot::SlotId;
use gamepath_engine::relay_path::NodeSpec;
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// RAS dials a route gets before it is given up for the session.
const DIAL_ATTEMPTS: u32 = 5;

/// The wait after the first failed dial, doubling after each one after it:
/// 2, 4, 8 and 16 seconds. Longer than the engine's own retries because each
/// RAS negotiation is itself seconds of IKE and PPP.
const DIAL_RETRY_STEP: Duration = Duration::from_secs(2);

/// How long a start with nothing else to run on waits for an L2TP route. The
/// client gives an L2TP session 60 s to start; this leaves it room to report
/// why rather than time out.
const START_WAIT: Duration = Duration::from_secs(40);

/// A refused login fails the same way every time, and repeating it can lock
/// the account at the provider.
const RAS_AUTHENTICATION_FAILURE: &str = "RAS error 691";

/// Tells one session apart from the next in the same slot, so a dial that
/// finishes after its session ended is hung up rather than attached to the
/// session that replaced it.
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Ordering::Relaxed)
}

fn retry_delay(failed: u32) -> Duration {
    DIAL_RETRY_STEP * 2_u32.pow(failed.saturating_sub(1).min(4))
}

fn worth_retrying(error: &str) -> bool {
    !error.contains(RAS_AUTHENTICATION_FAILURE)
}

/// Sleeps `delay`, or less if the dials are cancelled first. True if not.
fn wait_unless_cancelled(delay: Duration, cancelled: &AtomicBool) -> bool {
    let deadline = Instant::now() + delay;
    while Instant::now() < deadline {
        if cancelled.load(Ordering::Acquire) {
            return false;
        }
        thread::sleep(
            Duration::from_millis(100).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    !cancelled.load(Ordering::Acquire)
}

struct Dialled {
    index: usize,
    node: NodeSpec,
    session: Option<L2tpSession>,
}

/// Dials `node` until it connects, its attempts run out or the dials are
/// cancelled. `None` when cancelled: there is no session left to tell.
fn dial_with_retries(
    node: &NodeSpec,
    index: usize,
    relay: Ipv4Addr,
    tag: &str,
    cancelled: &AtomicBool,
) -> Option<Dialled> {
    let route = index + 1;
    for attempt in 1..=DIAL_ATTEMPTS {
        if cancelled.load(Ordering::Acquire) {
            return None;
        }
        // A fresh copy every time: a failed dial clears the key it used.
        let mut dialled = node.clone();
        let session = connect_l2tp_node(&mut dialled, index, Some(relay), true, tag)
            .unwrap_or_else(|error| {
                mark_failed(&mut dialled, error);
                None
            });
        if session.is_some() {
            return Some(Dialled {
                index,
                node: dialled,
                session,
            });
        }
        let error = match &dialled {
            NodeSpec::L2tp {
                dial_error: Some(error),
                ..
            } => error.clone(),
            _ => "the L2TP dial ended without a result".to_owned(),
        };
        if attempt == DIAL_ATTEMPTS || !worth_retrying(&error) {
            let tried = if attempt > 1 {
                format!(" (gave up after {attempt} attempts)")
            } else {
                String::new()
            };
            gamepath_engine::log_warn!(
                "{tag} route {route}: L2TP/IPsec did not connect{tried}; the session continues without it"
            );
            mark_failed(&mut dialled, format!("{error}{tried}"));
            return Some(Dialled {
                index,
                node: dialled,
                session: None,
            });
        }
        let delay = retry_delay(attempt);
        gamepath_engine::log_info!(
            "{tag} route {route}: L2TP/IPsec attempt {attempt} of {DIAL_ATTEMPTS} failed; retrying in {} s",
            delay.as_secs()
        );
        if !wait_unless_cancelled(delay, cancelled) {
            return None;
        }
    }
    None
}

/// The L2TP nodes of one relay session, dialling in the background.
///
/// Dropping it cancels whatever is still retrying: the session it was for has
/// failed to start, stopped or been replaced.
pub(crate) struct L2tpDials {
    results: mpsc::Receiver<Dialled>,
    outstanding: usize,
    cancelled: Arc<AtomicBool>,
    started: Instant,
}

impl Drop for L2tpDials {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl L2tpDials {
    /// Starts dialling every L2TP node in `nodes` and marks each one pending,
    /// so the engine starts without it. The pre-shared key stays with the dial
    /// and never reaches the engine child.
    pub(crate) fn begin(nodes: &mut [NodeSpec], relay: Ipv4Addr, tag: &str) -> Self {
        let (sender, results) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut outstanding = 0;
        for (index, node) in nodes.iter_mut().enumerate() {
            if !matches!(node, NodeSpec::L2tp { .. }) {
                continue;
            }
            let pristine = node.clone();
            let sender = sender.clone();
            let tag = tag.to_owned();
            let cancelled = Arc::clone(&cancelled);
            let spawned = thread::Builder::new()
                .name(format!("gamepath-l2tp-dial-{}", index + 1))
                .spawn(move || {
                    if let Some(dialled) =
                        dial_with_retries(&pristine, index, relay, &tag, &cancelled)
                    {
                        // Dropped with its connection when the session is gone.
                        let _ = sender.send(dialled);
                    }
                });
            let NodeSpec::L2tp {
                pre_shared_key,
                pending,
                ..
            } = node
            else {
                continue;
            };
            pre_shared_key.clear();
            match spawned {
                Ok(_) => {
                    *pending = true;
                    outstanding += 1;
                }
                Err(error) => mark_failed(node, format!("could not start the L2TP dial: {error}")),
            }
        }
        Self {
            results,
            outstanding,
            cancelled,
            started: Instant::now(),
        }
    }

    pub(crate) fn outstanding(&self) -> bool {
        self.outstanding > 0
    }

    /// Applies every dial that has already finished. Returns whether one of
    /// them connected.
    pub(crate) fn collect(
        &mut self,
        nodes: &mut [NodeSpec],
        sessions: &mut Vec<L2tpSession>,
    ) -> bool {
        let mut connected = false;
        while self.outstanding() {
            let Ok(dialled) = self.results.try_recv() else {
                break;
            };
            connected |= self.apply(dialled, nodes, sessions);
        }
        connected
    }

    /// Blocks until an L2TP route connects. False once none is left dialling,
    /// or once `START_WAIT` has passed since the dials began, so a start never
    /// outlasts the client waiting for it.
    pub(crate) fn wait_for_connected(
        &mut self,
        nodes: &mut [NodeSpec],
        sessions: &mut Vec<L2tpSession>,
    ) -> bool {
        let deadline = self.started + START_WAIT;
        while self.outstanding() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let dialled = match self.results.recv_timeout(remaining) {
                Ok(dialled) => dialled,
                Err(mpsc::RecvTimeoutError::Timeout) => return false,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.outstanding = 0;
                    break;
                }
            };
            if self.apply(dialled, nodes, sessions) {
                return true;
            }
        }
        false
    }

    fn apply(
        &mut self,
        dialled: Dialled,
        nodes: &mut [NodeSpec],
        sessions: &mut Vec<L2tpSession>,
    ) -> bool {
        self.outstanding -= 1;
        nodes[dialled.index] = dialled.node;
        let connected = dialled.session.is_some();
        sessions.extend(dialled.session);
        connected
    }

    /// Hands every dial still running to the session's engine as it finishes.
    ///
    /// `generation` is the session the dials belong to. Anything that finishes
    /// after it stopped, or after another session replaced it, is hung up, and
    /// the retries still waiting are cancelled as soon as that is noticed.
    pub(crate) fn join_in_background(
        mut self,
        id: SlotId,
        generation: u64,
        registry: Arc<Registry>,
    ) {
        if !self.outstanding() {
            return;
        }
        let spawned = thread::Builder::new()
            .name("gamepath-l2tp-join".into())
            .spawn(move || {
                while self.outstanding() {
                    match self.results.recv_timeout(Duration::from_secs(1)) {
                        Ok(dialled) => {
                            self.outstanding -= 1;
                            attach(dialled, id, generation, &registry);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // Busy means a start or stop holds it; asked again
                            // next second.
                            let ended = registry
                                .slot(id)
                                .try_lock()
                                .is_ok_and(|slot| slot.generation != generation);
                            if ended {
                                return;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            });
        if let Err(error) = spawned {
            // Dropping the dials cancels their retries, and each hangs up its
            // own connection once nobody receives it.
            gamepath_engine::log_warn!("L2TP routes cannot join the session: {error}");
        }
    }
}

fn mark_failed(node: &mut NodeSpec, error: String) {
    if let NodeSpec::L2tp {
        pre_shared_key,
        dial_error,
        pending,
        ..
    } = node
    {
        pre_shared_key.clear();
        *pending = false;
        *dial_error = Some(error);
    }
}

/// What the engine is told about a finished dial.
fn attach_payload(route: usize, node: &NodeSpec) -> Value {
    match node {
        NodeSpec::L2tp {
            runtime: Some(runtime),
            ..
        } => json!({ "route": route, "runtime": runtime }),
        NodeSpec::L2tp {
            dial_error: Some(error),
            ..
        } => json!({ "route": route, "dialError": error }),
        _ => json!({ "route": route, "dialError": "the L2TP dial ended without a result" }),
    }
}

fn attach(dialled: Dialled, id: SlotId, generation: u64, registry: &Registry) {
    let route = dialled.index + 1;
    let mut slot = registry.slot(id).lock().unwrap();
    let current = slot.generation == generation;
    let Some(engine) = slot.engine.as_mut().filter(|_| current) else {
        drop(slot);
        if dialled.session.is_some() {
            gamepath_engine::log_info!(
                "[{}] route {route} connected L2TP/IPsec after its session ended; hanging it up",
                id.as_str()
            );
        }
        return;
    };
    match engine.request("attach-l2tp-route", attach_payload(route, &dialled.node)) {
        Ok(_) => {
            if let Some(session) = dialled.session {
                slot.l2tp_sessions.push(session);
                slot.log(&format!(
                    "route {route} L2TP/IPsec connected and joined the session"
                ));
            }
        }
        Err(error) => {
            slot.warn(&format!(
                "route {route} could not join the session: {error}"
            ));
            // Hung up after the slot is free: RAS can take its time.
            drop(slot);
            drop(dialled.session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamepath_engine::l2tp::L2tpRuntime;

    fn l2tp(runtime: Option<L2tpRuntime>, dial_error: Option<&str>) -> NodeSpec {
        NodeSpec::L2tp {
            server: "203.0.113.20".into(),
            username: "player".into(),
            password: "secret".into(),
            pre_shared_key: String::new(),
            label: None,
            runtime,
            dial_error: dial_error.map(str::to_owned),
            pending: false,
        }
    }

    #[test]
    fn the_engine_hears_a_finished_dial_either_way() {
        let runtime = L2tpRuntime {
            local_address: "10.0.0.2".parse().unwrap(),
            virtual_address: "10.203.201.2".parse().unwrap(),
            server_address: "203.0.113.20".parse().unwrap(),
            interface_index: 42,
            mtu: 1384,
            setup_latency_ms: 125.0,
            profile_name: "GamePath-L2TP-test".into(),
            phonebook_path: r"C:\ProgramData\rasphone.pbk".into(),
        };
        let connected = attach_payload(3, &l2tp(Some(runtime), None));
        assert_eq!(connected["route"], 3);
        assert_eq!(connected["runtime"]["interfaceIndex"], 42);
        assert!(connected.get("dialError").is_none());

        let failed = attach_payload(4, &l2tp(None, Some("RAS error 628")));
        assert_eq!(failed["route"], 4);
        assert_eq!(failed["dialError"], "RAS error 628");
        assert!(failed.get("runtime").is_none());
    }

    #[test]
    fn a_failed_dial_never_carries_its_key_or_stays_pending() {
        let mut node = l2tp(None, None);
        if let NodeSpec::L2tp {
            pre_shared_key,
            pending,
            ..
        } = &mut node
        {
            *pre_shared_key = "shared-secret".into();
            *pending = true;
        }
        mark_failed(&mut node, "could not start".into());
        let NodeSpec::L2tp {
            pre_shared_key,
            pending,
            dial_error,
            ..
        } = &node
        else {
            unreachable!();
        };
        assert!(pre_shared_key.is_empty());
        assert!(!pending);
        assert_eq!(dial_error.as_deref(), Some("could not start"));
    }

    #[test]
    fn a_failed_dial_is_retried_with_a_growing_wait() {
        let waits = (1..DIAL_ATTEMPTS).map(retry_delay).collect::<Vec<_>>();
        assert_eq!(waits, [2, 4, 8, 16].map(Duration::from_secs).to_vec());
        // Even all five, each a long RAS negotiation, run in the background
        // once the session is up; only a start with nothing else waits, and
        // that for at most `START_WAIT`.
        assert!(START_WAIT < Duration::from_secs(60));
    }

    #[test]
    fn a_refused_login_is_not_repeated() {
        assert!(!worth_retrying(
            "Access was denied because the username and/or password was invalid on the domain. (RAS error 691)"
        ));
        assert!(worth_retrying(
            "The connection was terminated by the remote computer before it could be completed. (RAS error 628)"
        ));
    }

    #[test]
    fn a_cancelled_retry_stops_waiting() {
        let cancelled = AtomicBool::new(true);
        let started = Instant::now();
        assert!(!wait_unless_cancelled(Duration::from_secs(16), &cancelled));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(wait_unless_cancelled(
            Duration::from_millis(10),
            &AtomicBool::new(false)
        ));
    }

    #[test]
    fn generations_never_repeat() {
        let first = next_generation();
        assert!(next_generation() > first);
        // An idle slot is generation zero, which no session ever has.
        assert_ne!(first, 0);
    }
}
