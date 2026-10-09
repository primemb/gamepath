//! One session slot: everything a running session owns in the service.
//!
//! The service runs two slots side by side. The game slot is the session the
//! client always had; the VPN slot is a second, lower-priority session for
//! everyday traffic. Each slot has its own engine child, lease and rules, and
//! its own lock, so one slot starting, dialling or hanging never stalls the
//! other's status requests.

use crate::bypass_routes::BypassRoutes;
use crate::engine_process::EngineProcess;
use crate::l2tp::{L2tpSession, NativeL2tpUsage};
use serde_json::Value;
use std::time::{Duration, Instant};

/// How long the service keeps a session alive without hearing from the
/// client. The client renews this every few seconds from its main process;
/// the window is wide enough that a stalled request or a busy engine cannot
/// tear down a working session, and still short enough that routes do not
/// outlive a client that has actually died. Observed live: the service went
/// unanswered for about 35 s mid-match while every path kept carrying the
/// game, which a 30 s lease would have ended. The client waits out exactly
/// this window (`SERVICE_LEASE_MS` in electron/session-lease.cjs).
pub(crate) const SESSION_LEASE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotId {
    Game,
    Vpn,
}

impl SlotId {
    pub(crate) const ALL: [SlotId; 2] = [SlotId::Game, SlotId::Vpn];

    /// The slot a request is for. Absent means the game slot, which is what
    /// every caller written before slots existed meant.
    pub(crate) fn from_payload(payload: &Value) -> Result<Self, String> {
        match payload.get("slot").and_then(Value::as_str) {
            None | Some("game") => Ok(Self::Game),
            Some("vpn") => Ok(Self::Vpn),
            Some(other) => Err(format!("unknown session slot: {other}")),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Game => "game",
            Self::Vpn => "vpn",
        }
    }

    pub(crate) fn other(self) -> Self {
        match self {
            Self::Game => Self::Vpn,
            Self::Vpn => Self::Game,
        }
    }
}

pub(crate) struct SessionSlot {
    pub(crate) id: SlotId,
    /// `[game]` or `[vpn vpn-3f9a1c]`: the prefix on every log line about
    /// this slot, carrying the client's session id once one is running.
    pub(crate) tag: String,
    /// Which session this is, from `l2tp_join::next_generation`; zero while
    /// idle. A late L2TP dial joins only the session it was dialled for.
    pub(crate) generation: u64,
    pub(crate) session_status: String,
    pub(crate) route_count: usize,
    pub(crate) traffic_mode: String,
    /// Remembered so a live rule edit reapplies the session's DNS choice
    /// rather than silently reverting it to the default.
    pub(crate) remote_dns: bool,
    pub(crate) kill_switch: bool,
    /// Names of GamePath's own nodes and relays, whose lookups this slot's
    /// capture leaves alone.
    pub(crate) own_hostnames: Vec<String>,
    pub(crate) session_rules: Value,
    pub(crate) engine: Option<EngineProcess>,
    pub(crate) l2tp_sessions: Vec<L2tpSession>,
    pub(crate) native_l2tp_direct: bool,
    pub(crate) native_l2tp_status: Value,
    pub(crate) native_l2tp_capture: Value,
    pub(crate) native_l2tp_probe_supported: bool,
    pub(crate) native_l2tp_probe_failures: u32,
    pub(crate) native_l2tp_usage: NativeL2tpUsage,
    /// Routes that keep the other slot's tunnel off a native L2TP default
    /// route. Only a VPN slot in L2TP all-traffic mode has any.
    pub(crate) bypass_routes: Option<BypassRoutes>,
    /// The LAN proxy's last status, for when there is no engine to ask:
    /// it failed to start, or it was never asked for.
    pub(crate) lan_proxy: Value,
    pub(crate) lease_deadline: Option<Instant>,
    /// Why the slot last stopped when it was not the client's own request,
    /// so the client can tell a paused VPN from a failed one.
    pub(crate) stop_reason: Option<String>,
}

impl SessionSlot {
    pub(crate) fn new(id: SlotId) -> Self {
        Self {
            id,
            tag: format!("[{}]", id.as_str()),
            generation: 0,
            session_status: "idle".into(),
            route_count: 0,
            traffic_mode: String::new(),
            remote_dns: false,
            kill_switch: false,
            own_hostnames: Vec::new(),
            session_rules: Value::Null,
            engine: None,
            l2tp_sessions: Vec::new(),
            native_l2tp_direct: false,
            native_l2tp_status: Value::Null,
            native_l2tp_capture: Value::Null,
            native_l2tp_probe_supported: false,
            native_l2tp_probe_failures: 0,
            native_l2tp_usage: NativeL2tpUsage::default(),
            bypass_routes: None,
            lan_proxy: Value::Null,
            lease_deadline: None,
            stop_reason: None,
        }
    }

    pub(crate) fn log(&self, message: &str) {
        gamepath_engine::log_info!("{} {message}", self.tag);
    }

    pub(crate) fn warn(&self, message: &str) {
        gamepath_engine::log_warn!("{} {message}", self.tag);
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.session_status == "connected"
    }

    pub(crate) fn renew_lease(&mut self) {
        self.lease_deadline = Some(Instant::now() + SESSION_LEASE);
    }

    pub(crate) fn lease_expired(&self, now: Instant) -> bool {
        self.lease_deadline.is_some_and(|deadline| now >= deadline)
    }

    /// Resets the slot to idle and hands back what still has to be torn
    /// down. The caller does the slow part after releasing the slot's lock.
    pub(crate) fn take_for_teardown(&mut self, reason: Option<&str>) -> Teardown {
        let teardown = Teardown {
            engine: self.engine.take(),
            l2tp_sessions: std::mem::take(&mut self.l2tp_sessions),
            bypass_routes: self.bypass_routes.take(),
        };
        let id = self.id;
        *self = Self::new(id);
        self.stop_reason = reason.map(str::to_owned);
        teardown
    }
}

/// What a stopped slot still owns. Dropping it in order removes the engine's
/// capture and routes first, then the RAS connections the engine sent through.
pub(crate) struct Teardown {
    engine: Option<EngineProcess>,
    l2tp_sessions: Vec<L2tpSession>,
    bypass_routes: Option<BypassRoutes>,
}

impl Teardown {
    pub(crate) fn run(self) {
        if let Some(engine) = self.engine {
            engine.shut_down();
        }
        drop(self.l2tp_sessions);
        drop(self.bypass_routes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_request_without_a_slot_is_for_the_game() {
        assert_eq!(SlotId::from_payload(&json!({})).unwrap(), SlotId::Game);
        assert_eq!(SlotId::from_payload(&Value::Null).unwrap(), SlotId::Game);
        assert_eq!(
            SlotId::from_payload(&json!({ "slot": "vpn" })).unwrap(),
            SlotId::Vpn
        );
        assert!(SlotId::from_payload(&json!({ "slot": "other" })).is_err());
    }

    #[test]
    fn teardown_leaves_an_idle_slot_that_says_why_it_stopped() {
        let mut slot = SessionSlot::new(SlotId::Vpn);
        slot.session_status = "connected".into();
        slot.traffic_mode = "split".into();
        slot.route_count = 1;
        slot.renew_lease();
        slot.take_for_teardown(Some("game-all-traffic")).run();
        assert_eq!(slot.session_status, "idle");
        assert_eq!(slot.route_count, 0);
        assert!(slot.lease_deadline.is_none());
        assert_eq!(slot.stop_reason.as_deref(), Some("game-all-traffic"));
        assert_eq!(slot.id, SlotId::Vpn);
    }

    #[test]
    fn a_lease_expires_only_once_its_deadline_passes() {
        let mut slot = SessionSlot::new(SlotId::Game);
        assert!(!slot.lease_expired(Instant::now()));
        slot.renew_lease();
        assert!(!slot.lease_expired(Instant::now()));
        assert!(slot.lease_expired(Instant::now() + SESSION_LEASE));
    }
}
