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
mod dispatch;
mod health;
mod join;
mod latency;
mod local_tap;
mod monitors;
mod path_mtu;
mod relay_worker;
mod repair;
mod sender;
mod start;
mod state;
mod status;
mod worker;

#[cfg(test)]
mod failover_tests;

#[cfg(test)]
pub(crate) use local_tap::Diversion;
pub(crate) use local_tap::{LocalStackSink, LocalTap, Protocol};
pub(crate) use state::DataReceiver;

use crate::ipc::SessionRequest;
use gamepath_engine::log_info;
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::relay_path::SessionMode;
pub(crate) use sender::{DataSender, SenderCache};
use serde_json::{Value, json};
use state::ActiveWireGuardSession;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2tpAttachRequest {
    route: usize,
    #[serde(default)]
    runtime: Option<gamepath_engine::l2tp::L2tpRuntime>,
    #[serde(default)]
    dial_error: Option<String>,
}

pub(crate) struct LocalStackBinding {
    pub(crate) tap: Arc<LocalTap>,
    pub(crate) address: std::net::Ipv4Addr,
    pub(crate) mtu: u16,
    pub(crate) mode: SessionMode,
    /// Diverted replies never pass through the receiver, so the stack counts
    /// them into its total itself.
    pub(crate) data_receiver: Arc<DataReceiver>,
}

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
    pub(crate) fn packet_diagnostics(
        &self,
    ) -> Option<Arc<gamepath_engine::packet_diagnostics::PacketDiagnostics>> {
        self.active
            .as_ref()
            .map(|session| Arc::clone(&session.telemetry.packet_diagnostics))
    }

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

    /// What a packet path needs to hand packets to this session without
    /// holding the manager's lock; see [`sender`].
    pub(crate) fn data_sender(&self) -> Option<DataSender> {
        self.active.as_ref().map(DataSender::of)
    }

    pub(crate) fn effective_mtu(&self) -> Option<EffectiveMtu> {
        self.active
            .as_ref()
            .map(|session| session.mtu.for_capture())
    }

    /// What the LAN proxy needs to open flows of its own through this session.
    pub(crate) fn local_stack_binding(&self) -> Option<LocalStackBinding> {
        self.active.as_ref().map(|session| LocalStackBinding {
            tap: Arc::clone(&session.local_tap),
            address: session.virtual_ipv4,
            mtu: session.mtu.current().mtu,
            mode: session.mode,
            data_receiver: Arc::clone(&session.data_receiver),
        })
    }

    pub(crate) fn bypass_ips(&self) -> Vec<std::net::Ipv4Addr> {
        self.active
            .as_ref()
            .map(|session| session.bypass_ips.clone())
            .unwrap_or_default()
    }

    pub(crate) fn socks_proxy(&self) -> Option<std::net::SocketAddr> {
        self.active.as_ref().and_then(|session| session.socks_proxy)
    }

    /// Whether every route that has joined answers. Routes still dialling are
    /// not waited for: they join the running session when they open.
    fn all_paths_reachable(&self) -> bool {
        self.active
            .as_ref()
            .map(|session| {
                let skipped = session.skipped_route_numbers();
                let paths = session.paths.lock().unwrap();
                let mut joined = paths
                    .iter()
                    .filter(|path| !path.joining && !skipped.contains(&path.route))
                    .peekable();
                joined.peek().is_some() && joined.all(|path| path.reachable)
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

    /// Hands an L2TP route the service has finished dialling to the session,
    /// which opens it on the route's own worker and lets it join.
    pub(crate) fn attach_l2tp_route(&mut self, payload: Value) -> Result<Value, String> {
        let request: L2tpAttachRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid L2TP attach request: {error}"))?;
        let session = self.active.as_mut().ok_or("no active network session")?;
        let dial = session
            .service_dials
            .remove(&request.route)
            .ok_or_else(|| format!("route {} is not waiting for an L2TP dial", request.route))?;
        let result = match (request.runtime, request.dial_error) {
            (Some(runtime), _) => Ok(runtime),
            (None, Some(error)) => Err(error),
            (None, None) => Err("the service finished dialling without a result".into()),
        };
        // The route's dial thread only goes once the session is gone.
        let _ = dial.send(result);
        Ok(json!({ "route": request.route }))
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
        if let Some(repair) = &session.loss_repair {
            repair.wake_flusher();
        }
        for worker in session.workers.drain(..) {
            crate::teardown::step(format!(
                "session thread {}",
                worker.thread().name().unwrap_or("unnamed")
            ));
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

    #[test]
    fn packets_flow_while_a_control_request_holds_the_session_lock() {
        use base64::Engine as _;
        use std::sync::Mutex;

        // A peer that never answers: WireGuard opens without a handshake, and
        // a packet is accepted once its path worker queues it.
        let peer = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let key = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        let config = format!(
            "[Interface]\nPrivateKey = {key}\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = {key}\n\
             Endpoint = 127.0.0.1:{}\nAllowedIPs = 0.0.0.0/0",
            peer.local_addr().unwrap().port()
        );
        let sessions = Arc::new(Mutex::new(WireGuardSessionManager::default()));
        sessions
            .lock()
            .unwrap()
            .start_direct(&[NodeSpec::WireGuard {
                config,
                label: None,
            }])
            .unwrap();
        let packet = crate::icmp::icmp_echo_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 2),
            gamepath_engine::BENCHMARK_TARGET,
            1,
            1,
            false,
        );
        let mut cache = SenderCache::new(Arc::clone(&sessions));
        cache.send(&packet).unwrap();

        // A status poll holding the lock for as long as it likes.
        let held = sessions.lock().unwrap();
        let sender = thread::spawn(move || {
            (0..100)
                .all(|_| cache.send(&packet).is_ok())
                .then_some(cache)
        });
        let mut cache = sender.join().unwrap().expect("sent without the lock");
        drop(held);

        // A stopped session is noticed, and its replacement picked up.
        sessions.lock().unwrap().stop();
        let probe = crate::icmp::icmp_echo_packet(
            std::net::Ipv4Addr::new(10, 66, 66, 2),
            gamepath_engine::BENCHMARK_TARGET,
            1,
            2,
            false,
        );
        assert!(cache.send(&probe).is_err());
    }
}
