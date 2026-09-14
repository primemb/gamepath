//! Owns the multipath session: every enabled node, a worker per path, and the
//! answers the rest of the engine needs about it while it runs.
//!
//! The pieces are split by what they are responsible for: [`start`] brings a
//! session up, [`dataplane`] carries packets through one, [`status`] reports on
//! it, and this file holds the manager itself - the struct that owns the active
//! session, admits it only once it can carry traffic, and tears it down.

mod dataplane;
mod dialer;
mod direct_worker;
mod health;
mod latency;
mod monitors;
mod relay_worker;
mod start;
mod state;
mod status;
mod worker;

#[cfg(test)]
mod failover_tests;

pub(crate) use state::DataReceiver;

use crate::ipc::SessionRequest;
use gamepath_engine::log_info;
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::relay_path::SessionMode;
use serde_json::{Value, json};
use state::ActiveWireGuardSession;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub(crate) struct WireGuardSessionManager {
    active: Option<ActiveWireGuardSession>,
}

/// How long a session waits for a path to become usable before giving up.
const SESSION_READY_TIMEOUT: Duration = Duration::from_secs(12);

/// How long a relay session waits for every path before starting on the ones
/// that answered.
///
/// Only a slow route set pays this: a session whose paths are all up returns as
/// soon as the last one answers. A route that answers after capture has started
/// is not shut out either - its first pong puts it back in the dispatcher - so
/// this trades a little completeness at startup for a session that connects
/// promptly instead of failing on one bad route.
const DEGRADED_START_SETTLE: Duration = Duration::from_millis(1500);

fn unix_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

impl WireGuardSessionManager {
    pub(crate) fn start(&mut self, payload: Value) -> Result<Value, String> {
        let input: SessionRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid session request: {error}"))?;
        let nodes = input.resolved_nodes();
        if nodes.is_empty() {
            return Err(
                "at least one WireGuard, OpenVPN, L2TP/IPsec, or SOCKS5 node is required".into(),
            );
        }
        match input.mode {
            SessionMode::Relay => self.start_relay(&input, &nodes)?,
            SessionMode::Direct => self.start_direct(&nodes)?,
        }
        self.wait_until_ready()
    }

    /// Holds until the session can carry traffic, so nothing is captured into
    /// a session with nowhere to send it.
    ///
    /// A relay session needs one working path, not all of them: the point of
    /// multipath is that an expired, blocked or offline route costs a route
    /// rather than the session. Paths that are still down stay out of the
    /// scheduler's pick and keep probing, and join in when they answer. A
    /// direct session has exactly one path, so for it this is unchanged.
    fn wait_until_ready(&mut self) -> Result<Value, String> {
        let deadline = Instant::now() + SESSION_READY_TIMEOUT;
        let settle = Instant::now() + DEGRADED_START_SETTLE;
        while Instant::now() < deadline {
            if self.all_paths_reachable() {
                return Ok(self.status());
            }
            if Instant::now() >= settle && self.any_path_reachable() {
                return Ok(self.status());
            }
            thread::sleep(Duration::from_millis(100));
        }
        let (subject, detail) = self
            .active
            .as_ref()
            .map(|session| {
                let subject = match session.mode {
                    SessionMode::Relay => "relay paths",
                    SessionMode::Direct => "the node",
                };
                let detail = session
                    .paths
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|path| path.last_error.as_deref())
                    .collect::<Vec<_>>()
                    .join("; ");
                (subject, detail)
            })
            .unwrap_or(("relay paths", String::new()));
        self.stop();
        if detail.is_empty() {
            Err(format!("{subject} did not become ready before timeout"))
        } else {
            Err(format!("{subject} did not become ready: {detail}"))
        }
    }
    pub(crate) fn data_receiver(&self) -> Option<Arc<DataReceiver>> {
        self.active
            .as_ref()
            .map(|session| Arc::clone(&session.data_receiver))
    }

    pub(crate) fn virtual_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.active.as_ref().map(|session| session.virtual_ipv4)
    }

    pub(crate) fn effective_mtu(&self) -> Option<EffectiveMtu> {
        self.active.as_ref().map(|session| session.effective_mtu)
    }

    pub(crate) fn bypass_ips(&self) -> Vec<std::net::Ipv4Addr> {
        self.active
            .as_ref()
            .map(|session| session.bypass_ips.clone())
            .unwrap_or_default()
    }

    fn all_paths_reachable(&self) -> bool {
        self.active
            .as_ref()
            .map(|session| {
                let paths = session.paths.lock().unwrap();
                !paths.is_empty() && paths.iter().all(|path| path.reachable)
            })
            .unwrap_or(false)
    }

    fn any_path_reachable(&self) -> bool {
        self.active
            .as_ref()
            .map(|session| {
                session
                    .paths
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|path| path.reachable)
            })
            .unwrap_or(false)
    }

    pub(crate) fn stop(&mut self) -> Value {
        let Some(mut session) = self.active.take() else {
            return json!({ "state": "idle", "paths": [] });
        };
        log_info!(
            "session {} stopping after {} s",
            session.session_id,
            unix_time_millis().saturating_sub(session.started_at) / 1000
        );
        session.stop.store(true, Ordering::Release);
        session.commands.clear();
        for worker in session.workers.drain(..) {
            let _ = worker.join();
        }
        json!({ "state": "idle", "paths": [] })
    }
}

impl Drop for WireGuardSessionManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamepath_engine::relay_path::NodeSpec;

    #[test]
    fn a_direct_session_refuses_to_pick_one_node_out_of_several() {
        let mut manager = WireGuardSessionManager::default();
        let node = || NodeSpec::WireGuard {
            config: "[Interface]".into(),
            label: None,
        };
        let error = manager.start_direct(&[node(), node()]).err().unwrap();
        assert!(error.contains("exactly one node"), "{error}");
        // The message has to name both ways out, since either is reasonable.
        assert!(
            error.contains("single WireGuard, OpenVPN or L2TP/IPsec node"),
            "{error}"
        );
        assert!(error.contains("relay mode"), "{error}");
        assert!(manager.active.is_none());
    }
}
