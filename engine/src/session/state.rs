//! What a running session is made of: the per-path status the UI reads, the
//! overlay captured packets are wrapped in, and the ingress that admits the
//! first authenticated copy of an inbound packet.

use super::dispatch::Dispatch;
use super::local_tap::{InboundQueue, LocalTap};
use super::path_mtu::SessionMtu;
use super::repair::LossRepair;
use super::worker::PathTelemetry;
use gamepath_engine::auth::SessionCrypto;
use gamepath_engine::fec::Decoder;
use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_REPAIR, FLAG_SERVER_TO_CLIENT, FrameHeader};
use gamepath_engine::relay_path::SessionMode;
use gamepath_engine::replay::ReplayWindow;
use gamepath_engine::scheduler::{PathMetrics, Strategy};
use gamepath_engine::timer::HighResolutionTimer;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathSessionStatus {
    pub(crate) route: usize,
    pub(crate) path_kind: String,
    pub(crate) label: String,
    pub(crate) endpoint: String,
    pub(crate) reachable: bool,
    pub(crate) latency_ms: Option<f64>,
    /// One-time cost of establishing this path's transport. Not a hop
    /// latency: see `handshake_round_trips`.
    pub(crate) handshake_ms: Option<f64>,
    /// Round trips inside `handshake_ms`, when the protocol has a fixed
    /// number. `None` means no hop estimate can be derived from it.
    pub(crate) handshake_round_trips: Option<u8>,
    pub(crate) packets_sent: u64,
    pub(crate) packets_received: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) probes_sent: u64,
    pub(crate) probes_received: u64,
    pub(crate) probes_lost: u64,
    /// Current probe loss, as the smoothed ratio the scheduler actually acts
    /// on, in percent.
    ///
    /// The lifetime `probes_lost`/`probes_received` counters above cannot
    /// answer "is this path lossy *now*": they never forget, so a single bad
    /// minute at startup keeps showing as steady-state loss for as long as the
    /// session runs, decaying only as the session ages. This is the same EWMA
    /// that feeds [`PathMetrics::score`], so what the user sees and what the
    /// scheduler believes cannot drift apart.
    pub(crate) loss_percent: f64,
    pub(crate) last_error: Option<String>,
}

/// A route that is configured and enabled but is not part of the session.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SkippedRoute {
    pub(crate) route: usize,
    pub(crate) label: String,
    pub(crate) reason: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn initial_status(
    route: usize,
    path_kind: &str,
    label: String,
    endpoint: String,
) -> PathSessionStatus {
    PathSessionStatus {
        route,
        path_kind: path_kind.into(),
        label,
        endpoint,
        reachable: false,
        latency_ms: None,
        handshake_ms: None,
        handshake_round_trips: None,
        packets_sent: 0,
        packets_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
        probes_sent: 0,
        probes_received: 0,
        probes_lost: 0,
        loss_percent: 0.0,
        last_error: None,
    }
}

/// What a session wraps captured packets in before a path carries them.
#[derive(Clone)]
pub(crate) enum SessionOverlay {
    /// Relay sessions seal every packet under the enrollment key, so the relay
    /// can authenticate it and so a duplicate arriving by another path can be
    /// recognised as the same packet.
    Relay {
        client_id: [u8; 16],
        crypto: Arc<SessionCrypto>,
    },
    /// A direct session's node is the last hop and speaks plain IPv4. There is
    /// no relay to authenticate to and no duplicate to recognise, so packets
    /// travel exactly as they were captured — inside WireGuard's own crypto.
    Direct,
}

pub(crate) struct ActiveWireGuardSession {
    pub(crate) mode: SessionMode,
    pub(crate) strategy: Strategy,
    pub(crate) overlay: SessionOverlay,
    pub(crate) session_id: u64,
    pub(crate) started_at: u128,
    pub(crate) user_bytes_sent: Arc<AtomicU64>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) paths: Arc<Mutex<Vec<PathSessionStatus>>>,
    pub(crate) workers: Vec<JoinHandle<()>>,
    pub(crate) skipped_routes: Vec<SkippedRoute>,
    pub(crate) dispatch: Arc<Dispatch>,
    /// Relay sessions only: a direct node cannot decode repairs.
    pub(crate) loss_repair: Option<Arc<LossRepair>>,
    pub(crate) ingress: Option<Arc<RelayIngress>>,
    pub(crate) data_receiver: Arc<DataReceiver>,
    pub(crate) virtual_ipv4: std::net::Ipv4Addr,
    pub(crate) sequences: Arc<AtomicU64>,
    pub(crate) decision_mask: Arc<AtomicU64>,
    pub(crate) telemetry: PathTelemetry,
    pub(crate) scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    pub(crate) mtu: SessionMtu,
    pub(crate) bypass_ips: Vec<std::net::Ipv4Addr>,
    /// The SOCKS5 proxy a direct VPN session runs through. Such a proxy may
    /// answer name lookups with fake-IP addresses only it can reach.
    pub(crate) socks_proxy: Option<std::net::SocketAddr>,
    /// Diverts replies for the LAN proxy's own flows away from capture.
    pub(crate) local_tap: Arc<LocalTap>,
    // Held for the session so the path workers wake on a millisecond timer
    // instead of Windows' default ~15.6 ms one.
    pub(crate) timer: HighResolutionTimer,
}

/// Shared by the path workers: admit the first authenticated copy before it
/// enters the bounded receive queue. No waiting for slower paths or ordering
/// barrier, and no dependency on the outbound scheduler's current choice.
///
/// Loss repair lives under the same lock as the replay window because the two
/// answer one question between them: whether a sequence has reached the game
/// yet, by a path or by being rebuilt.
pub(crate) struct RelayIngress {
    client_id: [u8; 16],
    session_id: u64,
    state: Mutex<IngressState>,
    pub(crate) recovered: AtomicU64,
    pub(crate) repair_queue_rejected: AtomicU64,
    diagnostics: Arc<gamepath_engine::packet_diagnostics::PacketDiagnostics>,
}

struct IngressState {
    replay: ReplayWindow,
    repair: Decoder,
}

/// What the ingress has seen of the relay's repairs, for session status.
pub(crate) struct RepairCounters {
    pub(crate) received: u64,
    pub(crate) recovered: u64,
    pub(crate) unrecoverable: u64,
}

impl RelayIngress {
    pub(crate) fn new(
        client_id: [u8; 16],
        session_id: u64,
        diagnostics: Arc<gamepath_engine::packet_diagnostics::PacketDiagnostics>,
    ) -> Self {
        Self {
            client_id,
            session_id,
            diagnostics,
            state: Mutex::new(IngressState {
                replay: ReplayWindow::default(),
                repair: Decoder::default(),
            }),
            recovered: AtomicU64::new(0),
            repair_queue_rejected: AtomicU64::new(0),
        }
    }

    fn is_ours(&self, header: &FrameHeader) -> bool {
        header.client_id == self.client_id
            && header.session_id == self.session_id
            && header.flags & FLAG_SERVER_TO_CLIENT != 0
            && header.flags & FLAG_CONTROL == 0
    }

    /// `header` and `plaintext` must come from successful `open_server`.
    pub(crate) fn enqueue_authenticated(
        &self,
        header: &FrameHeader,
        plaintext: Vec<u8>,
        inbound: &impl InboundQueue,
    ) -> Result<bool, mpsc::TrySendError<Vec<u8>>> {
        if !self.is_ours(header) || header.flags & FLAG_REPAIR != 0 {
            return Ok(false);
        }
        let mut state = self.state.lock().unwrap();
        if !state.replay.would_accept(header.sequence) {
            if state.replay.is_too_old(header.sequence) {
                self.diagnostics.record(
                    gamepath_engine::packet_diagnostics::Reason::ReplayTooOld,
                    &plaintext,
                );
            }
            return Ok(false);
        }
        // Kept even if the queue turns it away: its bytes still let a repair
        // rebuild one of its neighbours.
        state.repair.remember(header.sequence, &plaintext);
        inbound.try_send(plaintext)?;
        // A full queue must not consume the sequence: a backup arriving after
        // space is available can still rescue this packet.
        state.replay.accept(header.sequence);
        self.retry_pending(&mut state, inbound);
        Ok(true)
    }

    /// Takes a repair frame from the relay. Returns whether it rebuilt a packet.
    pub(crate) fn enqueue_repair(
        &self,
        header: &FrameHeader,
        payload: &[u8],
        inbound: &impl InboundQueue,
    ) -> bool {
        if !self.is_ours(header) || header.flags & FLAG_REPAIR == 0 {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        // Repairs travel every path too; only the first copy is worth decoding.
        if !state.replay.accept(header.sequence) {
            return false;
        }
        let IngressState { replay, repair } = &mut *state;
        let rebuilt = repair.accept_repair(payload, Instant::now(), |sequence| {
            !replay.would_accept(sequence)
        });
        let admitted = rebuilt.is_some_and(|(sequence, packet)| {
            self.admit_rebuilt(&mut state, sequence, packet, inbound)
        });
        self.retry_pending(&mut state, inbound);
        admitted
    }

    fn admit_rebuilt(
        &self,
        state: &mut IngressState,
        sequence: u64,
        packet: Vec<u8>,
        inbound: &impl InboundQueue,
    ) -> bool {
        if !state.replay.would_accept(sequence) {
            return false;
        }
        state.repair.remember(sequence, &packet);
        let mut protocol_header = [0_u8; 20];
        if let Some(header) = packet.get(..20) {
            protocol_header.copy_from_slice(header);
        }
        if inbound.try_send(packet).is_err() {
            self.diagnostics.record(
                gamepath_engine::packet_diagnostics::Reason::RepairQueue,
                &protocol_header,
            );
            self.repair_queue_rejected.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        state.replay.accept(sequence);
        self.recovered.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// A delivery can complete a repair that was waiting on more than one member.
    fn retry_pending(&self, state: &mut IngressState, inbound: &impl InboundQueue) {
        while state.repair.has_pending() {
            let IngressState { replay, repair } = &mut *state;
            let Some((sequence, packet)) =
                repair.retry_pending(Instant::now(), |sequence| !replay.would_accept(sequence))
            else {
                return;
            };
            self.admit_rebuilt(state, sequence, packet, inbound);
        }
    }

    pub(crate) fn repair_counters(&self) -> RepairCounters {
        let state = self.state.lock().unwrap();
        RepairCounters {
            received: state.repair.repairs_received,
            recovered: self.recovered.load(Ordering::Relaxed),
            unrecoverable: state.repair.unrecoverable,
        }
    }
}

pub(crate) struct DataReceiver {
    /// Workers authenticate and deduplicate relay traffic before admission;
    /// direct workers likewise provide validated inner packets.
    pub(crate) inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    pub(crate) user_bytes_received: AtomicU64,
}

impl DataReceiver {
    pub(crate) fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let response = match self.inbound.lock().unwrap().recv_timeout(timeout) {
            Ok(response) => response,
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("all path receivers stopped".into());
            }
        };
        self.user_bytes_received
            .fetch_add(response.len() as u64, Ordering::Relaxed);
        Ok(Some(response))
    }
}
