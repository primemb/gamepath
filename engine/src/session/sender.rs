//! Handing captured packets to a session without the session manager's lock.
//!
//! The manager's mutex also serves every control request: status polls, rule
//! updates, stop. Taking it once per packet made it the busiest lock in the
//! engine, and Windows' SRW locks are not fair: a capture thread releasing and
//! re-taking it back to back can keep a waiting request out indefinitely.
//! Observed live: a 70 Mbit/s download through the VPN left its engine
//! unable to answer three status polls in a row, and the client tore the VPN
//! down as lost. Everything a packet needs is already shared through atomics
//! and `Arc`s, so the packet paths hold a [`DataSender`] instead.

use super::WireGuardSessionManager;
use super::dispatch::Dispatch;
use super::health::selected_paths;
use super::repair::LossRepair;
use super::state::{ActiveWireGuardSession, SessionOverlay};
use gamepath_engine::protocol::FrameHeader;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct DataSender {
    overlay: SessionOverlay,
    session_id: u64,
    sequences: Arc<AtomicU64>,
    decision_mask: Arc<AtomicU64>,
    healthy_mask: Arc<AtomicU64>,
    dispatch: Arc<Dispatch>,
    loss_repair: Option<Arc<LossRepair>>,
    user_bytes_sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl DataSender {
    pub(crate) fn of(session: &ActiveWireGuardSession) -> Self {
        Self {
            overlay: session.overlay.clone(),
            session_id: session.session_id,
            sequences: Arc::clone(&session.sequences),
            decision_mask: Arc::clone(&session.decision_mask),
            healthy_mask: Arc::clone(&session.telemetry.healthy_mask),
            dispatch: Arc::clone(&session.dispatch),
            loss_repair: session.loss_repair.clone(),
            user_bytes_sent: Arc::clone(&session.user_bytes_sent),
            stop: Arc::clone(&session.stop),
        }
    }

    /// False once the session it was taken from has stopped.
    pub(crate) fn is_live(&self) -> bool {
        !self.stop.load(Ordering::Acquire)
    }

    /// Ok(true) when at least one path accepted the packet. An error means no
    /// path was even chosen, which split mode reads as the relay being
    /// unavailable and answers by letting the packet take the normal route.
    pub(crate) fn send(&self, packet: &[u8]) -> Result<bool, String> {
        if !self.is_live() {
            return Err("the session has stopped".into());
        }
        let (frame, sequence) = match &self.overlay {
            SessionOverlay::Relay { client_id, crypto } => {
                let sequence = self.sequences.fetch_add(1, Ordering::Relaxed);
                let header = FrameHeader {
                    flags: 0,
                    client_id: *client_id,
                    session_id: self.session_id,
                    sequence,
                };
                (crypto.seal_client(header, packet)?, Some(sequence))
            }
            // The node routes the packet as it stands, so there is nothing to
            // wrap it in and no sequence for anyone to compare copies by.
            SessionOverlay::Direct => (packet.to_vec(), None),
        };
        // The scheduler's pick, narrowed to the paths that are actually
        // carrying traffic. A path that never came up would otherwise take a
        // copy of every packet and throw it away.
        let decision = self.decision_mask.load(Ordering::Acquire);
        let healthy = self.healthy_mask.load(Ordering::Acquire);
        let dispatched = self.dispatch.send(frame, selected_paths(decision, healthy));
        // Nothing to send down: only then is failing open correct. A packet
        // dropped because every chosen path is saturated must not bypass:
        // half a flow arriving from a different source address breaks it at
        // the server.
        if dispatched.selected == 0 {
            return Err("no active path workers accepted the packet".into());
        }
        // Covered even when every chosen queue was full: the relay can still
        // rebuild it from the repair, and it was never going to bypass.
        if let (Some(repair), Some(sequence)) = (&self.loss_repair, sequence) {
            repair.protect(sequence, packet);
        }
        if dispatched.accepted > 0 {
            self.user_bytes_sent
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
        }
        Ok(dispatched.accepted > 0)
    }
}

/// One packet path's sender, renewed from the manager only when the session
/// it came from has stopped. Each thread owns its own.
pub(crate) struct SenderCache {
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    sender: Option<DataSender>,
}

impl SenderCache {
    pub(crate) fn new(sessions: Arc<Mutex<WireGuardSessionManager>>) -> Self {
        Self {
            sessions,
            sender: None,
        }
    }

    pub(crate) fn send(&mut self, packet: &[u8]) -> Result<bool, String> {
        if !self.sender.as_ref().is_some_and(DataSender::is_live) {
            self.sender = self.sessions.lock().unwrap().data_sender();
        }
        self.sender
            .as_ref()
            .ok_or("start the WireGuard session before sending packets")?
            .send(packet)
    }
}
