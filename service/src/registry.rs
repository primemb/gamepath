//! Both session slots, and the little each needs to know about the other.
//!
//! A slot's lock can be held for tens of seconds while it starts (an L2TP
//! dial is the long pole), so nothing here ever waits on the other slot's
//! lock to make a decision. Each slot publishes a small summary instead, under
//! a lock that is only ever held for a copy.

use crate::slot::{SessionSlot, SlotId};
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const STOPPED_FOR_GAME_ALL_TRAFFIC: &str = "game-all-traffic";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SlotSummary {
    pub(crate) status: String,
    pub(crate) traffic_mode: String,
    pub(crate) route_count: usize,
    /// Where this slot's own tunnel traffic goes. The other slot keeps these
    /// out of its capture and, when it owns the default route, routes them
    /// around itself.
    pub(crate) bypass: Vec<Ipv4Addr>,
    pub(crate) stop_reason: Option<String>,
}

impl SlotSummary {
    pub(crate) fn idle(stop_reason: Option<String>) -> Self {
        Self {
            status: "idle".into(),
            stop_reason,
            ..Self::default()
        }
    }

    pub(crate) fn owns_all_traffic(&self) -> bool {
        matches!(self.status.as_str(), "starting" | "connected") && self.traffic_mode == "all"
    }

    fn to_json(&self) -> Value {
        json!({
            "sessionStatus": self.status,
            "routeCount": self.route_count,
            "trafficMode": self.traffic_mode,
            "stopReason": self.stop_reason,
        })
    }
}

pub(crate) struct Registry {
    game: Mutex<SessionSlot>,
    vpn: Mutex<SessionSlot>,
    summaries: Mutex<[SlotSummary; 2]>,
}

fn index(id: SlotId) -> usize {
    match id {
        SlotId::Game => 0,
        SlotId::Vpn => 1,
    }
}

impl Registry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            game: Mutex::new(SessionSlot::new(SlotId::Game)),
            vpn: Mutex::new(SessionSlot::new(SlotId::Vpn)),
            summaries: Mutex::new([SlotSummary::idle(None), SlotSummary::idle(None)]),
        })
    }

    pub(crate) fn slot(&self, id: SlotId) -> &Mutex<SessionSlot> {
        match id {
            SlotId::Game => &self.game,
            SlotId::Vpn => &self.vpn,
        }
    }

    pub(crate) fn summary(&self, id: SlotId) -> SlotSummary {
        self.summaries.lock().unwrap()[index(id)].clone()
    }

    /// Records `id`'s new summary and does what that means for the other
    /// slot. Only the game's changes reach across: the VPN yields to the game,
    /// never the other way round.
    pub(crate) fn publish(self: &Arc<Self>, id: SlotId, summary: SlotSummary) {
        let previous = {
            let mut summaries = self.summaries.lock().unwrap();
            std::mem::replace(&mut summaries[index(id)], summary.clone())
        };
        if id != SlotId::Game || previous == summary {
            return;
        }
        if summary.owns_all_traffic() {
            if !previous.owns_all_traffic() {
                self.in_background(|registry| {
                    crate::session::stop_session(
                        SlotId::Vpn,
                        &registry,
                        Some(STOPPED_FOR_GAME_ALL_TRAFFIC),
                    );
                });
            }
        } else if previous.bypass != summary.bypass {
            let addresses = summary.bypass;
            self.in_background(move |registry| {
                crate::session::set_foreign_bypass(SlotId::Vpn, &registry, &addresses);
            });
        }
    }

    /// Runs `work` without holding up the caller, which is usually the game
    /// slot in the middle of starting: the VPN's lock may be held for as long
    /// as its own start takes, and the game must not wait for that.
    fn in_background<F>(self: &Arc<Self>, work: F)
    where
        F: FnOnce(Arc<Registry>) + Send + 'static,
    {
        let registry = Arc::clone(self);
        thread::spawn(move || work(registry));
    }

    /// The `status` command's answer. The top-level fields are the game
    /// slot's, which is what every client written before slots existed reads.
    pub(crate) fn status(&self) -> Value {
        let summaries = self.summaries.lock().unwrap().clone();
        let game = &summaries[index(SlotId::Game)];
        json!({
            "service": "gamepath",
            "version": env!("CARGO_PKG_VERSION"),
            "elevated": true,
            "sessionStatus": game.status,
            "routeCount": game.route_count,
            "trafficMode": game.traffic_mode,
            "slots": {
                "game": game.to_json(),
                "vpn": summaries[index(SlotId::Vpn)].to_json(),
            },
        })
    }
}

/// Tears a slot down when its client stops renewing the lease. One watchdog
/// per slot, so a slot whose lock is held through a long start can never
/// delay the other's expiry check.
pub(crate) fn watch_lease(registry: Arc<Registry>, id: SlotId, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Acquire) {
        let expired = registry
            .slot(id)
            .try_lock()
            .map(|slot| slot.lease_expired(Instant::now()))
            .unwrap_or(false);
        if expired {
            crate::session::expire_lease(id, &registry);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected(traffic_mode: &str, bypass: &[Ipv4Addr]) -> SlotSummary {
        SlotSummary {
            status: "connected".into(),
            traffic_mode: traffic_mode.into(),
            route_count: 1,
            bypass: bypass.to_vec(),
            stop_reason: None,
        }
    }

    #[test]
    fn only_a_live_all_traffic_session_owns_all_traffic() {
        assert!(connected("all", &[]).owns_all_traffic());
        assert!(!connected("split", &[]).owns_all_traffic());
        assert!(!SlotSummary::idle(None).owns_all_traffic());
        let starting = SlotSummary {
            status: "starting".into(),
            ..connected("all", &[])
        };
        assert!(starting.owns_all_traffic());
    }

    #[test]
    fn status_keeps_the_game_fields_where_older_clients_read_them() {
        let registry = Registry::new();
        registry.publish(SlotId::Vpn, connected("split", &[]));
        let status = registry.status();
        assert_eq!(status["sessionStatus"], "idle");
        assert_eq!(status["slots"]["game"]["sessionStatus"], "idle");
        assert_eq!(status["slots"]["vpn"]["sessionStatus"], "connected");
        assert_eq!(status["slots"]["vpn"]["trafficMode"], "split");
    }

    #[test]
    fn a_vpn_change_never_reaches_the_game() {
        let registry = Registry::new();
        registry.publish(
            SlotId::Vpn,
            connected("all", &[Ipv4Addr::new(198, 51, 100, 7)]),
        );
        assert_eq!(registry.summary(SlotId::Game), SlotSummary::idle(None));
    }
}
