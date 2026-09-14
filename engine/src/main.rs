use base64::Engine as _;
use gamepath_engine::adapter::inspect_library;
use gamepath_engine::auth::{EnrollmentToken, SessionCrypto};
use gamepath_engine::mtu::{EffectiveMtu, LINK_MTU};
use gamepath_engine::policy::{RuleSpec, compile as compile_policy};
use gamepath_engine::relay_path::{
    DirectPath, KIND_WIREGUARD, NodeSpec, RelayPath, SessionMode, Socks5RelayPath,
};
use gamepath_engine::replay::ReplayWindow;
use gamepath_engine::rtt::RttEstimator;
use gamepath_engine::scheduler::{Decision, PathMetrics, Strategy, choose_paths};
use gamepath_engine::socks5::{Socks5NodeConfig, Socks5UdpPath};
use gamepath_engine::timer::HighResolutionTimer;
use gamepath_engine::uplink::{self, UplinkMonitor, UplinkState};
use gamepath_engine::wfp::inspect_backend;
use gamepath_engine::{log_error, log_info, log_warn};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
mod split_capture;

#[derive(Debug, Deserialize)]
struct Request {
    id: u64,
    command: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    id: u64,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrepareRequest {
    route_ids: Vec<String>,
    traffic_mode: String,
    rules: Vec<RuleSpec>,
    /// Absent for callers written before direct sessions existed.
    #[serde(default)]
    mode: SessionMode,
    /// A direct session has no relay, so these three carry nothing there.
    #[serde(default)]
    relay_host: String,
    #[serde(default)]
    relay_port: u16,
    #[serde(default)]
    enrollment_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeRequest {
    relay_host: String,
    relay_port: u16,
    enrollment_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireGuardProbeRequest {
    relay_host: String,
    relay_port: u16,
    enrollment_token: String,
    wireguard_configs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionRequest {
    /// Absent for callers written before direct sessions existed, all of which
    /// meant a relay session.
    #[serde(default)]
    mode: SessionMode,
    /// A direct session has no relay, so these three carry nothing there.
    #[serde(default)]
    relay_host: String,
    #[serde(default)]
    relay_port: u16,
    #[serde(default)]
    enrollment_token: String,
    #[serde(default)]
    nodes: Vec<NodeSpec>,
    #[serde(default)]
    wireguard_configs: Vec<String>,
    #[serde(default)]
    route_labels: Vec<String>,
    /// Smart is the safe default; all-paths is an explicit user choice for
    /// sending each packet on every healthy enabled route.
    #[serde(default = "default_relay_strategy")]
    strategy: Strategy,
}

fn default_relay_strategy() -> Strategy {
    Strategy::Adaptive
}

impl SessionRequest {
    /// Callers may send the tagged node list or, for WireGuard-only sessions,
    /// the original flat configuration list.
    fn resolved_nodes(&self) -> Vec<NodeSpec> {
        if !self.nodes.is_empty() {
            return self.nodes.clone();
        }
        self.wireguard_configs
            .iter()
            .enumerate()
            .map(|(index, config)| NodeSpec::WireGuard {
                config: config.clone(),
                label: self.route_labels.get(index).cloned(),
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Socks5ProbeRequest {
    relay_host: String,
    relay_port: u16,
    enrollment_token: String,
    host: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PathSessionStatus {
    route: usize,
    path_kind: String,
    label: String,
    endpoint: String,
    reachable: bool,
    latency_ms: Option<f64>,
    /// One-time cost of establishing this path's transport. Not a hop
    /// latency: see `handshake_round_trips`.
    handshake_ms: Option<f64>,
    /// Round trips inside `handshake_ms`, when the protocol has a fixed
    /// number. `None` means no hop estimate can be derived from it.
    handshake_round_trips: Option<u8>,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    probes_sent: u64,
    probes_received: u64,
    probes_lost: u64,
    /// Current probe loss, as the smoothed ratio the scheduler actually acts
    /// on, in percent.
    ///
    /// The lifetime `probes_lost`/`probes_received` counters above cannot
    /// answer "is this path lossy *now*": they never forget, so a single bad
    /// minute at startup keeps showing as steady-state loss for as long as the
    /// session runs, decaying only as the session ages. This is the same EWMA
    /// that feeds [`PathMetrics::score`], so what the user sees and what the
    /// scheduler believes cannot drift apart.
    loss_percent: f64,
    last_error: Option<String>,
}

/// What a session wraps captured packets in before a path carries them.
enum SessionOverlay {
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

struct ActiveWireGuardSession {
    mode: SessionMode,
    strategy: Strategy,
    overlay: SessionOverlay,
    session_id: u64,
    started_at: u128,
    stop: Arc<AtomicBool>,
    paths: Arc<Mutex<Vec<PathSessionStatus>>>,
    workers: Vec<JoinHandle<()>>,
    skipped_routes: Vec<SkippedRoute>,
    commands: Vec<mpsc::SyncSender<PathCommand>>,
    data_receiver: Arc<DataReceiver>,
    virtual_ipv4: std::net::Ipv4Addr,
    sequences: Arc<AtomicU64>,
    decision_mask: Arc<AtomicU64>,
    telemetry: PathTelemetry,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    effective_mtu: EffectiveMtu,
    bypass_ips: Vec<std::net::Ipv4Addr>,
    // Held for the session so the path workers wake on a millisecond timer
    // instead of Windows' default ~15.6 ms one.
    timer: HighResolutionTimer,
}

/// Shared by the path workers: admit the first authenticated copy before it
/// enters the bounded receive queue. No waiting for slower paths or ordering
/// barrier, and no dependency on the outbound scheduler's current choice.
struct RelayIngress {
    client_id: [u8; 16],
    session_id: u64,
    server_replay: Mutex<ReplayWindow>,
}

impl RelayIngress {
    /// `header` and `plaintext` must come from successful `open_server`.
    fn enqueue_authenticated(
        &self,
        header: &gamepath_engine::protocol::FrameHeader,
        plaintext: Vec<u8>,
        inbound: &mpsc::SyncSender<Vec<u8>>,
    ) -> Result<bool, mpsc::TrySendError<Vec<u8>>> {
        use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT};
        if header.client_id != self.client_id
            || header.session_id != self.session_id
            || header.flags & FLAG_SERVER_TO_CLIENT == 0
            || header.flags & FLAG_CONTROL != 0
        {
            return Ok(false);
        }
        let mut replay = self.server_replay.lock().unwrap();
        if !replay.would_accept(header.sequence) {
            return Ok(false);
        }
        inbound.try_send(plaintext)?;
        // A full queue must not consume the sequence: a backup arriving after
        // space is available can still rescue this packet.
        replay.accept(header.sequence);
        Ok(true)
    }
}

pub(crate) struct DataReceiver {
    /// Workers authenticate and deduplicate relay traffic before admission;
    /// direct workers likewise provide validated inner packets.
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
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
        Ok(Some(response))
    }
}

#[cfg(test)]
#[path = "failover_tests.rs"]
mod failover_tests;

/// A route that is configured and enabled but is not part of the session.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SkippedRoute {
    route: usize,
    label: String,
    reason: String,
}

/// What a path worker needs to open its transport again.
///
/// The transport is opened once when the session starts, and for WireGuard that
/// is enough: BoringTun re-initiates a handshake from its own timers, so a
/// rekey or a peer restart recovers on its own. A SOCKS5 association and an
/// OpenVPN link have no such mechanism - once the proxy drops the control
/// connection or the tunnel dies, that path stays dead for the whole session
/// unless something dials it again. This is what does that.
#[derive(Clone)]
struct PathDialer {
    node: NodeSpec,
    relay: SocketAddrV4,
}

impl PathDialer {
    fn open(&self) -> Result<Box<dyn RelayPath>, String> {
        self.node.reopen(self.relay)
    }
}

/// Keep an obsolete dial in its slot until it finishes, so recovery followed
/// by another outage cannot spawn overlapping connections to the same node.
struct ReconnectAttempt<T> {
    receiver: mpsc::Receiver<Result<T, String>>,
    superseded: bool,
}

enum ReconnectPoll<T> {
    Pending,
    Discarded,
    Finished(Result<T, String>),
}

impl<T> ReconnectAttempt<T> {
    fn new(receiver: mpsc::Receiver<Result<T, String>>) -> Self {
        Self {
            receiver,
            superseded: false,
        }
    }

    fn recovered(&mut self) {
        self.superseded = true;
    }

    fn poll(&mut self) -> ReconnectPoll<T> {
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

/// Gap between health probes on a path that is answering. One small request
/// and reply per second keeps a route's RTT current without turning an idle
/// game session into meaningful background data usage. A route in doubt uses
/// the shorter degraded interval below, so recovery is still noticed quickly.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Gap between probes on a path that has missed one.
///
/// This is a game client, so the time between a path coming back and GamePath
/// noticing is time the player spends on fewer routes than they have. At the
/// healthy cadence a recovered path waits up to half a second to be asked
/// again; probing hard while a path is in doubt cuts that to milliseconds, and
/// costs nothing the rest of the time because a healthy path never uses it.
const PROBE_INTERVAL_DEGRADED: Duration = Duration::from_millis(150);

/// Consecutive unanswered probes before a path is declared down.
///
/// One lost probe is not a failure. The control probe is a bare UDP datagram on
/// a real network, and losing one occasionally is ordinary: over an 85-minute
/// session a healthy WireGuard route lost 57 of them, roughly one every ninety
/// seconds. Acting on the first loss took that route out of the dispatcher and
/// showed it offline every time, which reads as the tunnel dropping and
/// reconnecting when nothing of the sort happened.
///
/// The probe deadline follows the path's own round trip
/// ([`gamepath_engine::rtt`]), so on a healthy route a cycle costs a few
/// hundred milliseconds rather than two seconds. That is what lets this be a
/// real threshold instead of a trade against detection speed: three misses on a
/// 60 ms path resolve inside a second, where two misses used to take three and
/// a half.
///
/// The scheduler still sees the first loss immediately through `record_loss`,
/// so a path that starts dropping packets is de-prioritised by its score
/// straight away. This governs only the harder decision to stop using it.
const HEALTH_FAILURE_THRESHOLD: u32 = 3;

const _: () = assert!(
    HEALTH_FAILURE_THRESHOLD >= 2,
    "one lost probe is ordinary packet loss, not a path failure"
);

/// Consecutive failed health checks before a path's transport is redialled.
/// Three of them is a little over a second of silence, long enough that a
/// single lost probe or a brief stall does not tear down a working socket.
const RECONNECT_AFTER_FAILURES: u32 = 3;

/// Wait before the *first* redial once a path is judged dead.
///
/// Zero: by this point the path has missed several probes in a row and another
/// path is up, so the uplink is known good and there is nothing to gain by
/// waiting. Later attempts back off from [`RECONNECT_BACKOFF_STEP`].
const RECONNECT_BACKOFF_MIN: Duration = Duration::ZERO;

/// The wait the backoff grows from after the immediate first attempt.
const RECONNECT_BACKOFF_STEP: Duration = Duration::from_secs(1);

/// Longest wait between redial attempts. A provider that is down for an hour
/// is retried every half minute rather than hammered.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

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
const UPLINK_DOWN_BACKOFF: Duration = Duration::from_secs(6);

/// Whether any path other than `index` is currently carrying traffic.
///
/// One healthy path proves the uplink works, which is what makes a redial of a
/// different path worth attempting.
fn another_path_is_up(healthy_mask: &AtomicU64, index: usize) -> bool {
    let own = 1_u64.checked_shl(index as u32).unwrap_or(0);
    healthy_mask.load(Ordering::Acquire) & !own != 0
}

struct PathCommand {
    frame: Vec<u8>,
    /// When the scheduler handed this packet over. A packet that waited longer
    /// than [`PATH_QUEUE_MAX_AGE`] is worth less than the latency it would add
    /// to everything behind it, so the worker drops it instead of sending it.
    queued_at: Instant,
}

/// Per-path counters a worker publishes and [`WireGuardSessionManager::status`]
/// reads back. Grouped so the workers take one parameter for all of it.
#[derive(Clone)]
struct PathTelemetry {
    iterations: Arc<Vec<AtomicU64>>,
    queue_depth: Arc<Vec<AtomicU64>>,
    /// Highest dispatcher queue depth observed during this session. The
    /// current depth is commonly back at zero by the time a periodic summary
    /// runs, so without a peak a short burst is invisible in the log.
    queue_peak: Arc<Vec<AtomicU64>>,
    dropped: Arc<Vec<AtomicU64>>,
    /// Why `dropped` moved. Kept separately so the next incident distinguishes
    /// dispatcher saturation, packets that became stale in a worker, and a
    /// saturated receive queue.
    queue_full_dropped: Arc<Vec<AtomicU64>>,
    stale_dropped: Arc<Vec<AtomicU64>>,
    inbound_dropped: Arc<Vec<AtomicU64>>,
    /// Longest interval between two worker iterations. A one-second CPU stall
    /// or a transport call that blocks past its deadline otherwise leaves no
    /// trace once the worker resumes.
    worker_gap_peak_ms: Arc<Vec<AtomicU64>>,
    healthy_mask: Arc<AtomicU64>,
    /// Whether this machine can reach the Internet at all, measured outside
    /// every node. Session-wide rather than per-path, but it rides here so the
    /// workers get it with the rest of what they read.
    uplink: Arc<UplinkMonitor>,
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

/// How long a worker waits on its socket per iteration. Short, because an
/// outbound packet handed over during the wait is only sent once it ends.
const WORKER_RECEIVE_TIMEOUT: Duration = Duration::from_millis(1);

/// Outbound packets a path worker sends before it goes back to servicing
/// inbound frames, probes and timers. Draining the whole queue first is what
/// lets a burst delay the replies that decide whether the path is still alive.
///
/// Sized so the cap bounds starvation without bounding throughput. A worker
/// iterates at least once per [`WORKER_RECEIVE_TIMEOUT`], so this is a floor of
/// ~128k packets per second per path - well past any line rate this runs on -
/// while the batch itself is a few hundred microseconds of `send` calls, an
/// order of magnitude under the wait it sits next to.
const PATH_SEND_BATCH: usize = 128;

/// Outbound queue depth per path. At [`PATH_SEND_BATCH`] this drains in about
/// 8 ms, which is the most latency the queue itself can add before
/// [`PATH_QUEUE_MAX_AGE`] starts shedding. Past that, holding a packet costs
/// more latency than dropping it saves.
const PATH_QUEUE_DEPTH: usize = 1024;

/// Inbound queue depth shared by every path worker.
const INBOUND_QUEUE_DEPTH: usize = 2048;

// A frame is numbered when it is queued but a probe is numbered later and sent
// immediately, so a probe overtakes everything still in the queue. The relay
// has to still remember the oldest of those when it arrives.
const _: () = assert!(
    PATH_QUEUE_DEPTH as u64 <= gamepath_engine::replay::MAX_REORDERING,
    "a full outbound queue can reorder further than the replay window covers"
);

/// How long a queued packet stays worth sending.
const PATH_QUEUE_MAX_AGE: Duration = Duration::from_millis(50);

/// A worker normally returns to its loop every millisecond. Only log gaps big
/// enough to be felt in a game, and rate-limit the warning locally because a
/// persistently blocked transport would otherwise produce a new value (and
/// defeat identical-message collapsing) on every iteration.
const WORKER_GAP_WARN: Duration = Duration::from_millis(100);
const WORKER_GAP_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Queue shedding is logged promptly, but a burst is combined into one update
/// rather than producing a line for every discarded packet.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// A 10-15 ms step is visible in a competitive game but ordinary sub-frame
/// jitter is not. Two consecutive samples confirm a modest rise; a severe
/// spike is reported immediately. Recovery also needs several samples so the
/// log contains one incident and one recovery instead of a line per probe.
const LATENCY_RISE_MIN_MS: f64 = 12.0;
const LATENCY_RISE_RATIO: f64 = 0.10;
const LATENCY_SEVERE_MIN_MS: f64 = 50.0;
const LATENCY_SEVERE_RATIO: f64 = 0.75;
const LATENCY_BASELINE_SAMPLES: u64 = 4;
const LATENCY_RISE_SAMPLES: u8 = 2;
const LATENCY_RECOVERY_SAMPLES: u8 = 3;

#[derive(Debug, PartialEq)]
enum LatencyEvent {
    Degraded {
        baseline_ms: f64,
        observed_ms: f64,
    },
    Recovered {
        baseline_ms: f64,
        peak_ms: f64,
        duration: Duration,
    },
}

/// Per-worker state for edge-triggered latency diagnostics. The baseline only
/// moves while the route is not in an incident; otherwise a sustained rise
/// would teach the detector that the degraded value is normal before recovery.
#[derive(Default)]
struct LatencyWatch {
    baseline_ms: Option<f64>,
    samples: u64,
    elevated_samples: u8,
    recovery_samples: u8,
    incident_started: Option<Instant>,
    peak_ms: f64,
}

impl LatencyWatch {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn observe(&mut self, sample_ms: f64, now: Instant) -> Option<LatencyEvent> {
        let sample_ms = sample_ms.max(0.0);
        let Some(baseline_ms) = self.baseline_ms else {
            self.baseline_ms = Some(sample_ms);
            self.samples = 1;
            return None;
        };

        if let Some(started) = self.incident_started {
            self.peak_ms = self.peak_ms.max(sample_ms);
            let recovered_below = baseline_ms + (LATENCY_RISE_MIN_MS / 2.0);
            if sample_ms <= recovered_below {
                self.recovery_samples = self.recovery_samples.saturating_add(1);
            } else {
                self.recovery_samples = 0;
            }
            if self.recovery_samples >= LATENCY_RECOVERY_SAMPLES {
                let event = LatencyEvent::Recovered {
                    baseline_ms,
                    peak_ms: self.peak_ms,
                    duration: now.saturating_duration_since(started),
                };
                self.baseline_ms = Some(sample_ms);
                self.samples = 1;
                self.elevated_samples = 0;
                self.recovery_samples = 0;
                self.incident_started = None;
                self.peak_ms = 0.0;
                return Some(event);
            }
            return None;
        }

        let rise = sample_ms - baseline_ms;
        let threshold = LATENCY_RISE_MIN_MS.max(baseline_ms * LATENCY_RISE_RATIO);
        let severe = rise >= LATENCY_SEVERE_MIN_MS.max(baseline_ms * LATENCY_SEVERE_RATIO);
        let elevated = self.samples >= LATENCY_BASELINE_SAMPLES && rise >= threshold;
        if elevated {
            self.elevated_samples = self.elevated_samples.saturating_add(1);
            self.peak_ms = self.peak_ms.max(sample_ms);
            if severe || self.elevated_samples >= LATENCY_RISE_SAMPLES {
                self.incident_started = Some(now);
                return Some(LatencyEvent::Degraded {
                    baseline_ms,
                    observed_ms: self.peak_ms,
                });
            }
            return None;
        }

        self.elevated_samples = 0;
        self.peak_ms = 0.0;
        self.samples = self.samples.saturating_add(1);
        // A slow EWMA follows normal route drift but preserves enough history
        // to spot a persistent 105 -> 120 ms step.
        self.baseline_ms = Some(baseline_ms + 0.05 * (sample_ms - baseline_ms));
        None
    }
}

#[derive(Default)]
struct WireGuardSessionManager {
    active: Option<ActiveWireGuardSession>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PacketCaptureRequest {
    traffic_mode: String,
    #[serde(default)]
    rules: Vec<RuleSpec>,
}

#[derive(Default)]
struct PacketCaptureManager {
    #[cfg(windows)]
    active: Option<WindowsPacketCapture>,
    #[cfg(windows)]
    active_split: Option<split_capture::SplitPacketCapture>,
}

fn main() {
    // stdout carries the JSON-RPC the service reads, so the log must not go
    // there. The file is shared with the other components; stderr is off
    // because the service captures it and would record every line twice.
    gamepath_engine::log::init(
        "engine",
        Some(gamepath_engine::log::log_path("engine")),
        false,
    );
    log_info!("gamepath-engine {} started", env!("CARGO_PKG_VERSION"));
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let sessions = Arc::new(Mutex::new(WireGuardSessionManager::default()));
    let mut capture = PacketCaptureManager::default();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, &sessions, &mut capture),
            Err(error) => Response {
                id: 0,
                ok: false,
                result: None,
                error: Some(format!("invalid request: {error}")),
            },
        };
        if !response.ok {
            // The service turns this into one user-facing message; the log
            // keeps the request that actually failed, in order.
            log_error!(
                "request failed: {}",
                response.error.as_deref().unwrap_or("unknown error")
            );
        }
        if serde_json::to_writer(&mut stdout, &response).is_err() {
            break;
        }
        if writeln!(stdout).and_then(|_| stdout.flush()).is_err() {
            break;
        }
    }
}

fn handle_request(
    request: Request,
    sessions: &Arc<Mutex<WireGuardSessionManager>>,
    capture: &mut PacketCaptureManager,
) -> Response {
    let result = match request.command.as_str() {
        "hello" => Ok(json!({
            "engine": "gamepath",
            "version": env!("CARGO_PKG_VERSION"),
            "protocolVersion": 1,
        })),
        "inspect-system" => Ok(inspect_system()),
        "prepare-session" => prepare_session(request.payload),
        "probe-relay" => probe_relay(request.payload),
        "probe-wireguard-routes" => probe_wireguard_routes(request.payload),
        "probe-socks5-node" => probe_socks5_node(request.payload),
        "start-wireguard-session" => sessions.lock().unwrap().start(request.payload),
        "wireguard-session-status" => Ok(sessions.lock().unwrap().status()),
        "probe-data-plane" => sessions.lock().unwrap().probe_data_plane(),
        "start-packet-capture" => capture.start(request.payload, Arc::clone(sessions)),
        "update-packet-capture" => capture.update(request.payload, Arc::clone(sessions)),
        "packet-capture-status" => Ok(capture.status()),
        "stop-packet-capture" => Ok(capture.stop()),
        "stop-wireguard-session" => {
            capture.stop();
            Ok(sessions.lock().unwrap().stop())
        }
        "scheduler-demo" => Ok(scheduler_demo()),
        _ => Err(format!("unknown command: {}", request.command)),
    };
    match result {
        Ok(value) => Response {
            id: request.id,
            ok: true,
            result: Some(value),
            error: None,
        },
        Err(error) => Response {
            id: request.id,
            ok: false,
            result: None,
            error: Some(error),
        },
    }
}

impl WireGuardSessionManager {
    fn start(&mut self, payload: Value) -> Result<Value, String> {
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

    /// Brings up a relay session: every node carries sealed frames to the
    /// relay, and the scheduler decides how many of them each packet takes.
    fn start_relay(&mut self, input: &SessionRequest, nodes: &[NodeSpec]) -> Result<(), String> {
        let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
        let (client_id, key) = enrollment.material()?;
        let relay_ip = resolve_ipv4(&input.relay_host, input.relay_port)?;
        let relay = SocketAddrV4::new(relay_ip, input.relay_port);
        let strategy = input.strategy;
        let mut paths: Vec<(usize, String, NodeSpec, Box<dyn RelayPath>)> = Vec::new();
        let mut skipped_routes = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let route = index + 1;
            // A SOCKS5 node dials its proxy here and an OpenVPN node completes
            // a handshake, so this is where a dead provider shows up. One node
            // failing costs its own route: the session runs on the rest, and
            // the worker set does not include a path that was never opened.
            let path = match node.open(relay) {
                Ok(path) => path,
                Err(error) => {
                    skipped_routes.push(SkippedRoute {
                        route,
                        label: node.describe(),
                        reason: error,
                    });
                    continue;
                }
            };
            if paths
                .iter()
                .any(|(_, _, _, current)| current.identity() == path.identity())
            {
                skipped_routes.push(SkippedRoute {
                    route,
                    label: node.describe(),
                    reason: "another enabled route already uses this endpoint and key".into(),
                });
                continue;
            }
            let label = node
                .label()
                .or_else(|| {
                    input
                        .route_labels
                        .get(index)
                        .map(|label| label.trim().to_owned())
                        .filter(|label| !label.is_empty())
                })
                .unwrap_or_else(|| node.default_label(route));
            paths.push((route, label, node.clone(), path));
        }
        for skipped in &skipped_routes {
            // A route silently missing from the session is the thing nobody can
            // explain later, so each one says why on its own line.
            log_warn!(
                "route {} ({}) did not join: {}",
                skipped.route,
                skipped.label,
                skipped.reason
            );
        }
        // Every node failed to dial. There is no session to degrade into, so
        // this reports each one rather than a bare timeout.
        if paths.is_empty() {
            return Err(format!(
                "no route could be opened: {}",
                skipped_routes
                    .iter()
                    .map(|skipped| format!(
                        "route {} ({}): {}",
                        skipped.route, skipped.label, skipped.reason
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        // One capture adapter serves every selected path. Its MTU must fit the
        // smallest actual outer route and the strictest provider tunnel cap.
        let link_mtu = link_mtu_for_endpoints(
            paths
                .iter()
                .filter_map(|(_, _, _, path)| path.bypass_ipv4()),
        );
        let provider_mtu = paths
            .iter()
            .filter_map(|(_, _, node, _)| node.configured_tunnel_mtu())
            .min();
        let effective_mtu = EffectiveMtu::for_session(
            SessionMode::Relay,
            paths.iter().map(|(_, _, _, path)| path.kind()),
            link_mtu,
        )
        .with_tunnel_limit(provider_mtu);
        let route_summary = paths
            .iter()
            .map(|(route, label, _, path)| format!("{route}:{label}/{}", path.kind()))
            .collect::<Vec<_>>()
            .join(", ");
        let mut bypass_ips = vec![relay_ip];
        bypass_ips.extend(
            paths
                .iter()
                .filter_map(|(_, _, _, path)| path.bypass_ipv4()),
        );
        bypass_ips.sort_unstable();
        bypass_ips.dedup();

        self.stop();
        let timer = HighResolutionTimer::raise();
        let session_id = rand::random::<u64>();
        let crypto = Arc::new(SessionCrypto::new(&key, session_id)?);
        let stop = Arc::new(AtomicBool::new(false));
        let sequences = Arc::new(AtomicU64::new(1));
        let initial_statuses = paths
            .iter()
            .map(|(route, label, _, path)| {
                initial_status(*route, path.kind(), label.clone(), path.endpoint())
            })
            .collect::<Vec<_>>();
        let statuses = Arc::new(Mutex::new(initial_statuses));
        let route_count = paths.len();
        let scheduler_metrics = Arc::new(Mutex::new(
            (0..route_count)
                .map(|index| PathMetrics::new(index.to_string()))
                .collect::<Vec<_>>(),
        ));
        let initial_mask = if route_count >= 64 {
            u64::MAX
        } else {
            (1_u64 << route_count) - 1
        };
        let decision_mask = Arc::new(AtomicU64::new(initial_mask));
        let counters = || {
            Arc::new(
                (0..route_count)
                    .map(|_| AtomicU64::new(0))
                    .collect::<Vec<_>>(),
            )
        };
        let telemetry = PathTelemetry {
            iterations: counters(),
            queue_depth: counters(),
            queue_peak: counters(),
            dropped: counters(),
            queue_full_dropped: counters(),
            stale_dropped: counters(),
            inbound_dropped: counters(),
            worker_gap_peak_ms: counters(),
            healthy_mask: Arc::new(AtomicU64::new(0)),
            uplink: Arc::new(UplinkMonitor::new()),
        };
        let mut workers = Vec::with_capacity(route_count);
        let mut commands = Vec::with_capacity(route_count);
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let ingress = Arc::new(RelayIngress {
            client_id,
            session_id,
            server_replay: Mutex::new(ReplayWindow::default()),
        });
        for (index, (_, _, node, path)) in paths.into_iter().enumerate() {
            let status_index = index;
            let (command_tx, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
            commands.push(command_tx);
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
            let worker_inbound = inbound_tx.clone();
            let worker_ingress = Arc::clone(&ingress);
            let worker_metrics = Arc::clone(&scheduler_metrics);
            let worker_decision = Arc::clone(&decision_mask);
            let worker_telemetry = telemetry.clone();
            let worker_dialer = PathDialer { node, relay };
            let worker_kind = path.kind();
            workers.push(
                thread::Builder::new()
                    .name(format!("gamepath-{worker_kind}-{}", index + 1))
                    .spawn(move || {
                        run_path(
                            path,
                            status_index,
                            worker_sequences,
                            client_id,
                            key,
                            session_id,
                            worker_stop,
                            worker_statuses,
                            command_rx,
                            worker_inbound,
                            worker_ingress,
                            worker_metrics,
                            worker_decision,
                            initial_mask,
                            strategy,
                            worker_telemetry,
                            worker_dialer,
                            route_count,
                        )
                    })
                    .map_err(|error| format!("could not start path worker: {error}"))?,
            );
        }
        let data_receiver = Arc::new(DataReceiver {
            inbound: Mutex::new(inbound_rx),
        });
        workers.extend(spawn_uplink_monitor(&stop, &telemetry));
        let summary = spawn_session_summary(
            session_id,
            &stop,
            &statuses,
            &telemetry,
            &decision_mask,
            &scheduler_metrics,
        );
        workers.extend(summary);
        log_info!(
            "relay session {session_id} up: {route_count} route(s) [{route_summary}], \
             uplink mtu {link_mtu}, tunnel mtu {} overhead {}, {} skipped",
            effective_mtu.mtu,
            effective_mtu.overhead,
            skipped_routes.len()
        );
        warn_if_below_link_budget(effective_mtu, link_mtu);
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Relay,
            strategy,
            overlay: SessionOverlay::Relay { client_id, crypto },
            session_id,
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers,
            skipped_routes,
            commands,
            data_receiver,
            virtual_ipv4: enrollment.virtual_ipv4,
            sequences,
            decision_mask,
            telemetry,
            scheduler_metrics,
            effective_mtu,
            bypass_ips,
            timer,
        });
        Ok(())
    }

    /// Brings up a direct session: no relay, and one tunnelling node doing the
    /// routing that a relay would otherwise do.
    fn start_direct(&mut self, nodes: &[NodeSpec]) -> Result<(), String> {
        // Duplication is the only reason to run several paths, and duplication
        // needs a relay to recognise the copies. Say so rather than silently
        // using the first node and leaving the rest looking active.
        let [node] = nodes else {
            return Err(format!(
                "direct mode sends traffic through exactly one node, but {} are enabled. \
                 Enable a single WireGuard, OpenVPN or L2TP/IPsec node, or switch to relay mode to combine them.",
                nodes.len()
            ));
        };
        let path = node
            .open_direct()
            .map_err(|error| format!("{}: {error}", node.describe()))?;
        let virtual_ipv4 = path.address();
        let bypass_ips = path.bypass_ipv4().into_iter().collect::<Vec<_>>();
        let label = node.label().unwrap_or_else(|| node.default_label(1));
        let endpoint = path.endpoint().to_string();

        self.stop();
        let timer = HighResolutionTimer::raise();
        let stop = Arc::new(AtomicBool::new(false));
        let kind = path.kind();
        let label_for_log = label.clone();
        let link_mtu = link_mtu_for_endpoints(path.bypass_ipv4());
        let effective_mtu = EffectiveMtu::for_session(SessionMode::Direct, [kind], link_mtu)
            .with_tunnel_limit(node.configured_tunnel_mtu());
        let statuses = Arc::new(Mutex::new(vec![initial_status(1, kind, label, endpoint)]));
        let scheduler_metrics = Arc::new(Mutex::new(vec![PathMetrics::new("0".to_owned())]));
        let (command_tx, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let telemetry = PathTelemetry {
            iterations: Arc::new(vec![AtomicU64::new(0)]),
            queue_depth: Arc::new(vec![AtomicU64::new(0)]),
            queue_peak: Arc::new(vec![AtomicU64::new(0)]),
            dropped: Arc::new(vec![AtomicU64::new(0)]),
            queue_full_dropped: Arc::new(vec![AtomicU64::new(0)]),
            stale_dropped: Arc::new(vec![AtomicU64::new(0)]),
            inbound_dropped: Arc::new(vec![AtomicU64::new(0)]),
            worker_gap_peak_ms: Arc::new(vec![AtomicU64::new(0)]),
            healthy_mask: Arc::new(AtomicU64::new(0)),
            uplink: Arc::new(UplinkMonitor::new()),
        };
        let worker_telemetry = telemetry.clone();
        let worker_stop = Arc::clone(&stop);
        let worker_statuses = Arc::clone(&statuses);
        let worker_metrics = Arc::clone(&scheduler_metrics);
        let session_id = rand::random::<u64>();
        let worker = thread::Builder::new()
            .name("gamepath-direct-1".into())
            .spawn(move || {
                run_direct_path(
                    path,
                    virtual_ipv4,
                    worker_stop,
                    worker_statuses,
                    command_rx,
                    inbound_tx,
                    worker_metrics,
                    worker_telemetry,
                    session_id,
                )
            })
            .map_err(|error| format!("could not start path worker: {error}"))?;
        let mut workers = vec![worker];
        warn_if_below_link_budget(effective_mtu, link_mtu);
        workers.extend(spawn_uplink_monitor(&stop, &telemetry));
        workers.extend(spawn_session_summary(
            session_id,
            &stop,
            &statuses,
            &telemetry,
            &Arc::new(AtomicU64::new(1)),
            &scheduler_metrics,
        ));
        log_info!(
            "direct session up: {label_for_log} ({kind}), uplink mtu {link_mtu}, tunnel mtu {} overhead {}",
            effective_mtu.mtu,
            effective_mtu.overhead
        );
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Direct,
            strategy: Strategy::FastestPath,
            overlay: SessionOverlay::Direct,
            session_id,
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers,
            skipped_routes: Vec::new(),
            commands: vec![command_tx],
            data_receiver: Arc::new(DataReceiver {
                inbound: Mutex::new(inbound_rx),
            }),
            virtual_ipv4,
            sequences: Arc::new(AtomicU64::new(1)),
            // One path, always selected: there is nothing to schedule between.
            decision_mask: Arc::new(AtomicU64::new(1)),
            telemetry,
            scheduler_metrics,
            effective_mtu,
            bypass_ips,
            timer,
        });
        Ok(())
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

    fn probe_data_plane(&mut self) -> Result<Value, String> {
        let session = self
            .active
            .as_ref()
            .ok_or("start the WireGuard session before probing its data plane")?;
        let (virtual_ipv4, mode) = (session.virtual_ipv4, session.mode);
        let benchmark_server = gamepath_engine::BENCHMARK_TARGET;
        let identifier = rand::random::<u16>();
        let request = icmp_echo_packet(virtual_ipv4, benchmark_server, identifier, 1, false);
        let started = Instant::now();
        // A relay session has to answer: the relay is the user's own, and this
        // round trip is what proves the whole chain carries traffic. A direct
        // session's node belongs to a provider who may simply filter ICMP,
        // which says nothing about the game traffic it will carry — so there
        // the probe is telemetry, and a silent node is not a failed session.
        let timeout = match mode {
            SessionMode::Relay => Duration::from_secs(8),
            SessionMode::Direct => Duration::from_secs(2),
        };
        let reply = match self.send_data_packet(&request, timeout) {
            Ok(reply)
                if is_matching_icmp_reply(&reply, benchmark_server, virtual_ipv4, identifier) =>
            {
                reply
            }
            outcome => {
                if mode == SessionMode::Relay {
                    return Err(match outcome {
                        Ok(_) => "relay data plane returned an unexpected packet".to_owned(),
                        Err(error) => error,
                    });
                }
                return Ok(json!({
                    "reachable": false,
                    "latencyMs": Value::Null,
                    "userToRelayMs": Value::Null,
                    "relayToServerMs": Value::Null,
                    "benchmarkServer": benchmark_server.to_string(),
                    "note": "the node did not answer a test ping, which many providers filter",
                }));
            }
        };
        let end_to_end = started.elapsed().as_secs_f64() * 1000.0;
        let user_to_relay = self
            .active
            .as_ref()
            .and_then(|session| {
                session
                    .paths
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|path| path.latency_ms)
                    .reduce(f64::min)
            })
            .unwrap_or(end_to_end);
        // These timings come from independent samples. If the fresh end-to-end
        // probe happens to beat the route EWMA, subtraction produces zero or a
        // negative number; reporting 0 ms invents a physically impossible hop.
        let relay_to_server = (end_to_end > user_to_relay).then_some(end_to_end - user_to_relay);
        Ok(json!({
            "reachable": true,
            "latencyMs": end_to_end,
            "userToRelayMs": user_to_relay,
            "relayToServerMs": relay_to_server,
            "benchmarkServer": benchmark_server.to_string(),
            "bytes": reply.len(),
        }))
    }

    fn send_data_packet(&mut self, packet: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        self.enqueue_data_packet(packet)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(packet) = self.receive_data_packet(remaining)? {
                return Ok(packet);
            }
        }
        Err("no path returned the relayed packet before timeout".into())
    }

    fn enqueue_data_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        use gamepath_engine::protocol::FrameHeader;

        let session = self
            .active
            .as_mut()
            .ok_or("start the WireGuard session before sending packets")?;
        let frame = match &session.overlay {
            SessionOverlay::Relay { client_id, crypto } => {
                let sequence = session.sequences.fetch_add(1, Ordering::Relaxed);
                let header = FrameHeader {
                    flags: 0,
                    client_id: *client_id,
                    session_id: session.session_id,
                    sequence,
                };
                crypto.seal_client(header, packet)?
            }
            // The node routes the packet as it stands, so there is nothing to
            // wrap it in and no sequence for anyone to compare copies by.
            SessionOverlay::Direct => packet.to_vec(),
        };
        // The scheduler's pick, narrowed to the paths that are actually
        // carrying traffic. A path that never came up would otherwise take a
        // copy of every packet and throw it away.
        let decision = session.decision_mask.load(Ordering::Acquire);
        let healthy = session.telemetry.healthy_mask.load(Ordering::Acquire);
        let selected = selected_paths(decision, healthy);
        let mut selected_paths = 0;
        let queued_at = Instant::now();
        for (index, sender) in session.commands.iter().enumerate() {
            let bit = 1_u64.checked_shl(index as u32).unwrap_or(0);
            if selected & bit == 0 {
                continue;
            }
            selected_paths += 1;
            match sender.try_send(PathCommand {
                frame: frame.clone(),
                queued_at,
            }) {
                Ok(()) => {
                    if let Some(depth) = session.telemetry.queue_depth.get(index) {
                        let current = depth.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(peak) = session.telemetry.queue_peak.get(index) {
                            peak.fetch_max(current, Ordering::Relaxed);
                        }
                    }
                }
                // A full queue means the path is already behind. Shedding the
                // newest packet keeps the backlog bounded: game traffic is
                // stale by the time it would drain, and TCP retransmits.
                Err(mpsc::TrySendError::Full(_)) => {
                    if let Some(dropped) = session.telemetry.dropped.get(index) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(dropped) = session.telemetry.queue_full_dropped.get(index) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {}
            }
        }
        // Nothing to send down. Split mode reads this as the relay being
        // unavailable and lets the packet take the normal route; that fail-open
        // is only correct here, when no path was ever chosen. A packet dropped
        // because every chosen path is saturated must not bypass: half a flow
        // arriving from a different source address breaks it at the server.
        if selected_paths == 0 {
            return Err("no active path workers accepted the packet".into());
        }
        Ok(())
    }

    fn receive_data_packet(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let session = self
            .active
            .as_mut()
            .ok_or("start the WireGuard session before receiving packets")?;
        session.data_receiver.receive(timeout)
    }

    fn data_receiver(&self) -> Option<Arc<DataReceiver>> {
        self.active
            .as_ref()
            .map(|session| Arc::clone(&session.data_receiver))
    }

    fn virtual_ipv4(&self) -> Option<std::net::Ipv4Addr> {
        self.active.as_ref().map(|session| session.virtual_ipv4)
    }

    fn effective_mtu(&self) -> Option<EffectiveMtu> {
        self.active.as_ref().map(|session| session.effective_mtu)
    }

    fn bypass_ips(&self) -> Vec<std::net::Ipv4Addr> {
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

    fn status(&self) -> Value {
        let Some(session) = &self.active else {
            return json!({ "state": "idle", "paths": [] });
        };
        let mut paths = session.paths.lock().unwrap().clone();
        let scheduler_metrics = session.scheduler_metrics.lock().unwrap().clone();
        // The workers own these two structures separately, so the live loss
        // estimate is joined onto the path status here rather than written on
        // the hot path under a second lock.
        for (path, metric) in paths.iter_mut().zip(scheduler_metrics.iter()) {
            path.loss_percent = metric.loss_ratio * 100.0;
        }
        let decision = session.decision_mask.load(Ordering::Acquire);
        let healthy = session.telemetry.healthy_mask.load(Ordering::Acquire);
        // What the dispatcher will actually use. Reporting the raw pick would
        // show a route as carrying traffic while it is being skipped.
        let effective = selected_paths(decision, healthy);
        let selected_routes = paths
            .iter()
            .enumerate()
            .filter(|(index, _)| effective & 1_u64.checked_shl(*index as u32).unwrap_or(0) != 0)
            .map(|(_, path)| path.route)
            .collect::<Vec<_>>();
        let degraded_routes = paths
            .iter()
            .filter(|path| !path.reachable)
            .map(|path| path.route)
            .collect::<Vec<_>>();
        let path_worker_iterations = session
            .telemetry
            .iterations
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        let state = if paths.iter().any(|path| path.reachable) {
            "connected"
        } else {
            "connecting"
        };
        json!({
            "state": state,
            "mode": session.mode.as_str(),
            "sessionId": session.session_id.to_string(),
            "startedAt": session.started_at,
            "paths": paths,
            "skippedRoutes": session.skipped_routes,
            "strategy": match session.mode {
                SessionMode::Relay => session.strategy.as_str(),
                // One path cannot be scheduled between, so nothing is chosen.
                SessionMode::Direct => "single-path",
            },
            "selectedRoutes": selected_routes,
            // Routes the session started or carried on without. Present so the
            // UI can say a path is down without implying the session is.
            "degradedRoutes": degraded_routes,
            "schedulerMetrics": scheduler_metrics,
            "pathWorkerIterations": path_worker_iterations,
            "queueDepth": session
                .telemetry
                .queue_depth
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            "droppedPackets": session
                .telemetry
                .dropped
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            "queuePeak": session
                .telemetry
                .queue_peak
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .collect::<Vec<_>>(),
            "dropReasons": {
                "queueFull": session.telemetry.queue_full_dropped.iter()
                    .map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>(),
                "stale": session.telemetry.stale_dropped.iter()
                    .map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>(),
                "inboundFull": session.telemetry.inbound_dropped.iter()
                    .map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>(),
            },
            "workerGapPeakMs": session.telemetry.worker_gap_peak_ms.iter()
                .map(|value| value.load(Ordering::Relaxed)).collect::<Vec<_>>(),
            "queueCapacity": PATH_QUEUE_DEPTH,
            "effectiveMtu": session.effective_mtu.mtu,
            "transportOverhead": session.effective_mtu.overhead,
            "uplink": match session.telemetry.uplink.state() {
                UplinkState::Up => "up",
                UplinkState::Down => "down",
                UplinkState::Unknown => "unknown",
            },
            "highResolutionTimer": session.timer.active(),
        })
    }

    fn stop(&mut self) -> Value {
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

#[cfg(windows)]
struct WindowsPacketCapture {
    stop: Arc<AtomicBool>,
    session: Arc<wintun::Session>,
    workers: Vec<JoinHandle<()>>,
    routes: Vec<InstalledRoute>,
    adapter_index: u32,
}

#[cfg(windows)]
struct InstalledRoute {
    destination: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
    interface_index: u32,
}

impl PacketCaptureManager {
    #[cfg(windows)]
    fn start(
        &mut self,
        payload: Value,
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        let input: PacketCaptureRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid packet capture request: {error}"))?;
        match input.traffic_mode.as_str() {
            // Validate before dropping a live capture. This makes a rejected
            // live rule edit leave the previous policy fully operational.
            "split" => {
                compile_policy("split", &input.rules)?;
            }
            "all" => {}
            _ => return Err("traffic mode must be all or split".into()),
        }
        self.stop();
        let (virtual_ipv4, bypass_ips, data_receiver, effective_mtu) = {
            let manager = sessions.lock().unwrap();
            (
                manager
                    .virtual_ipv4()
                    .ok_or("start the multipath session before packet capture")?,
                manager.bypass_ips(),
                manager
                    .data_receiver()
                    .ok_or("start the multipath session before packet capture")?,
                manager
                    .effective_mtu()
                    .ok_or("start the multipath session before packet capture")?,
            )
        };
        if input.traffic_mode == "split" {
            let split = split_capture::SplitPacketCapture::start(
                &input.rules,
                virtual_ipv4,
                &bypass_ips,
                sessions,
                data_receiver,
                effective_mtu,
            )?;
            let target_count = split.target_count();
            self.active_split = Some(split);
            return Ok(json!({
                "state": "capturing",
                "backend": "windivert",
                "trafficMode": "split",
                "targetCount": target_count,
                "effectiveMtu": effective_mtu.mtu,
                "tcpMss": effective_mtu.tcp_mss(),
                // Selected targets are matched as IPv4. A game reaching the
                // same server over IPv6 is not captured at all, so the
                // exposure is worth reporting in split mode too.
                "ipv6": ipv6_exposure(),
            }));
        }
        let (default_gateway, default_interface) = default_ipv4_route()?;
        let executable_dir = std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .ok_or("engine executable has no parent directory")?
            .to_path_buf();
        let installed_dll = executable_dir.join("wintun.dll");
        let project_dll = std::env::current_dir()
            .unwrap_or_default()
            .join("vendor")
            .join("wintun")
            .join("wintun.dll");
        let dll = if installed_dll.is_file() {
            installed_dll
        } else {
            project_dll
        };
        // SAFETY: only the repository's verified Wintun DLL or the installed
        // copy beside the privileged engine is loaded.
        let wintun = unsafe { wintun::load_from_path(&dll) }
            .map_err(|error| format!("could not load Wintun: {error}"))?;
        let adapter = wintun::Adapter::open(&wintun, "GamePath")
            .or_else(|_| {
                wintun::Adapter::create(
                    &wintun,
                    "GamePath",
                    "GamePath",
                    Some(0x7f0a_9828_52ef_4ddd_913d_c11f_f0d4_a58a_u128),
                )
            })
            .map_err(|error| format!("could not create GamePath adapter: {error}"))?;
        let adapter_index = adapter
            .get_adapter_index()
            .map_err(|error| format!("could not read GamePath adapter index: {error}"))?;
        configure_tunnel_interface(adapter_index, effective_mtu.mtu)?;
        adapter
            .set_network_addresses_tuple(
                virtual_ipv4.into(),
                std::net::Ipv4Addr::new(255, 255, 255, 0).into(),
                None,
            )
            .map_err(|error| format!("could not configure GamePath adapter: {error}"))?;
        // Sized from what the selected transports actually add to a packet, so
        // a full-size packet still fits the physical link once it is wrapped.
        adapter
            .set_mtu(usize::from(effective_mtu.mtu))
            .map_err(|error| format!("could not set GamePath MTU: {error}"))?;
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|error| format!("could not start Wintun packet ring: {error}"))?,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let uplink_stop = Arc::clone(&stop);
        let uplink_session = Arc::clone(&session);
        let uplink = thread::Builder::new()
            .name("gamepath-wintun-uplink".into())
            .spawn(move || run_wintun_uplink(uplink_session, sessions, virtual_ipv4, uplink_stop))
            .map_err(|error| format!("could not start Wintun uplink: {error}"))?;
        let downlink_stop = Arc::clone(&stop);
        let downlink_session = Arc::clone(&session);
        let downlink = thread::Builder::new()
            .name("gamepath-wintun-downlink".into())
            .spawn(move || run_wintun_downlink(downlink_session, data_receiver, downlink_stop))
            .map_err(|error| format!("could not start Wintun downlink: {error}"))?;

        let mut capture = WindowsPacketCapture {
            stop,
            session,
            workers: vec![uplink, downlink],
            routes: Vec::new(),
            adapter_index,
        };
        for address in bypass_ips {
            capture.routes.push(add_ipv4_route(
                address,
                std::net::Ipv4Addr::new(255, 255, 255, 255),
                default_gateway,
                default_interface,
                1,
            )?);
        }
        // The next hop has to sit inside the adapter's own /24 for Windows to
        // accept the route. A relay hands out 10.203.0.x, so this is the same
        // 10.203.0.1 as before; a direct session's address comes from the
        // node's provider and gets the matching first host of its subnet.
        let octets = virtual_ipv4.octets();
        let tunnel_gateway = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
        capture.routes.push(add_ipv4_route(
            std::net::Ipv4Addr::UNSPECIFIED,
            std::net::Ipv4Addr::new(128, 0, 0, 0),
            tunnel_gateway,
            adapter_index,
            5,
        )?);
        capture.routes.push(add_ipv4_route(
            std::net::Ipv4Addr::new(128, 0, 0, 0),
            std::net::Ipv4Addr::new(128, 0, 0, 0),
            tunnel_gateway,
            adapter_index,
            5,
        )?);
        self.active = Some(capture);
        Ok(json!({
            "state": "capturing",
            "backend": "wintun",
            "adapterIndex": adapter_index,
            "virtualIpv4": virtual_ipv4,
            "trafficMode": input.traffic_mode,
            "effectiveMtu": effective_mtu.mtu,
            "transportOverhead": effective_mtu.overhead,
            "ipv6": ipv6_exposure(),
        }))
    }

    #[cfg(not(windows))]
    fn start(
        &mut self,
        _payload: Value,
        _sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        Err("packet capture is available only on Windows".into())
    }

    /// Applies a new split policy without touching the multipath session.
    /// WinDivert's kernel expression is immutable, so this intentionally
    /// replaces the capture handles while retaining every relay path.
    #[cfg(windows)]
    fn update(
        &mut self,
        payload: Value,
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        if self.active_split.is_none() {
            return Err("live target updates require an active split capture".into());
        }
        if payload["trafficMode"].as_str() != Some("split") {
            return Err("live target updates require split traffic mode".into());
        }
        self.start(payload, sessions)
    }

    #[cfg(not(windows))]
    fn update(
        &mut self,
        _payload: Value,
        _sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        Err("packet capture is available only on Windows".into())
    }

    fn status(&self) -> Value {
        #[cfg(windows)]
        if let Some(capture) = &self.active {
            return json!({
                "state": "capturing",
                "backend": "wintun",
                "adapterIndex": capture.adapter_index,
            });
        }
        #[cfg(windows)]
        if let Some(capture) = &self.active_split {
            let diagnostics = capture.diagnostics();
            return json!({
                "state": "capturing",
                "backend": "windivert",
                "trafficMode": "split",
                "targetCount": capture.target_count(),
                "diagnostics": diagnostics,
            });
        }
        json!({ "state": "idle" })
    }

    fn stop(&mut self) -> Value {
        #[cfg(windows)]
        {
            drop(self.active.take());
            drop(self.active_split.take());
        }
        json!({ "state": "idle" })
    }
}

impl Drop for PacketCaptureManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(windows)]
impl Drop for WindowsPacketCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.session.shutdown();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        for route in self.routes.iter().rev() {
            let _ = remove_ipv4_route(route);
        }
    }
}

#[cfg(windows)]
fn run_wintun_uplink(
    session: Arc<wintun::Session>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    virtual_ipv4: std::net::Ipv4Addr,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        let packet = match session.receive_blocking() {
            Ok(packet) => packet,
            Err(_) => return,
        };
        let bytes = packet.bytes().to_vec();
        drop(packet);
        if ipv4_source_address(&bytes) == Some(virtual_ipv4) {
            let _ = sessions.lock().unwrap().enqueue_data_packet(&bytes);
        }
    }
}

#[cfg(windows)]
fn run_wintun_downlink(
    session: Arc<wintun::Session>,
    data_receiver: Arc<DataReceiver>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        let reply = match data_receiver.receive(Duration::from_millis(250)) {
            Ok(Some(packet)) => packet,
            Ok(None) => continue,
            Err(_) => return,
        };
        if reply.len() > u16::MAX as usize {
            continue;
        }
        if let Ok(mut packet) = session.allocate_send_packet(reply.len() as u16) {
            packet.bytes_mut().copy_from_slice(&reply);
            session.send_packet(packet);
        }
    }
}

#[cfg(windows)]
fn configure_tunnel_interface(interface_index: u32, mtu: u16) -> Result<(), String> {
    gamepath_engine::netconfig::configure_tunnel_interface(interface_index, mtu)
}

/// Returns the physical-interface MTU Windows selected for an already
/// resolved tunnel endpoint. This is deliberately route-specific: a laptop
/// can have Ethernet, Wi-Fi and a mobile interface active at the same time.
#[cfg(windows)]
fn route_link_mtu(destination: std::net::Ipv4Addr) -> Result<u16, String> {
    gamepath_engine::netconfig::route_link_mtu(destination)
        .map_err(|error| format!("could not inspect route MTU for {destination}: {error}"))
}

/// Says so when the 1280-byte tunnel floor had to be held above what the link
/// leaves after encapsulation.
///
/// The session still runs, because the floor is not negotiable, but on such a
/// link full-size packets fragment, and that would otherwise surface as
/// latency and loss with nothing in the log to explain it.
fn warn_if_below_link_budget(effective_mtu: EffectiveMtu, link_mtu: u16) {
    if effective_mtu.below_link_budget {
        log_warn!(
            "a {link_mtu}-byte uplink leaves {} bytes after {} bytes of encapsulation, under the {}-byte tunnel floor; holding the floor, so full-size packets fragment on this link",
            link_mtu.saturating_sub(effective_mtu.overhead),
            effective_mtu.overhead,
            effective_mtu.mtu,
        );
    }
}

/// Uses the tightest successfully inspected endpoint route. Discovery is an
/// optimisation, never a connection requirement: a filtered query falls back
/// to the proven 1500-byte budget for only that path.
fn link_mtu_for_endpoints(endpoints: impl IntoIterator<Item = std::net::Ipv4Addr>) -> u16 {
    #[cfg(windows)]
    {
        let mut smallest = None;
        for endpoint in endpoints {
            match route_link_mtu(endpoint) {
                Ok(mtu) => smallest = Some(smallest.map_or(mtu, |current: u16| current.min(mtu))),
                Err(error) => log_warn!("{error}; using the safe MTU fallback for this path"),
            }
        }
        smallest.unwrap_or(LINK_MTU)
    }
    #[cfg(not(windows))]
    {
        let _ = endpoints;
        LINK_MTU
    }
}

#[cfg(windows)]
fn default_ipv4_route() -> Result<(std::net::Ipv4Addr, u32), String> {
    let script = "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric | Select-Object -First 1; if($r){Write-Output ($r.NextHop+'|'+$r.InterfaceIndex)}";
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|error| format!("could not inspect the default route: {error}"))?;
    if !output.status.success() {
        return Err("could not inspect the default IPv4 route".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let (gateway, interface) = text
        .trim()
        .split_once('|')
        .ok_or("no usable default IPv4 route was found")?;
    Ok((
        gateway.parse().map_err(|_| "default gateway is invalid")?,
        interface
            .parse()
            .map_err(|_| "default interface index is invalid")?,
    ))
}

#[cfg(windows)]
fn add_ipv4_route(
    destination: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> Result<InstalledRoute, String> {
    let status = Command::new("route.exe")
        .args([
            "ADD".to_owned(),
            destination.to_string(),
            "MASK".to_owned(),
            mask.to_string(),
            gateway.to_string(),
            "METRIC".to_owned(),
            metric.to_string(),
            "IF".to_owned(),
            interface_index.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not add route for {destination}: {error}"))?;
    if !status.success() {
        return Err(format!("Windows rejected route for {destination}/{mask}"));
    }
    Ok(InstalledRoute {
        destination,
        mask,
        gateway,
        interface_index,
    })
}

#[cfg(windows)]
fn remove_ipv4_route(route: &InstalledRoute) -> Result<(), String> {
    let status = Command::new("route.exe")
        .args([
            "DELETE".to_owned(),
            route.destination.to_string(),
            "MASK".to_owned(),
            route.mask.to_string(),
            route.gateway.to_string(),
            "IF".to_owned(),
            route.interface_index.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("could not remove route: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("Windows rejected route cleanup".into())
    }
}

fn ipv4_source_address(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

#[allow(clippy::too_many_arguments)]
fn initial_status(
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

/// How many unanswered probes it takes to conclude the node filters ICMP.
const DIRECT_PROBE_ATTEMPTS: u64 = 3;
/// How many probes a node that *had* been answering may miss in a row before
/// it is reported as down. There is no second path to fail over to here, so
/// this only decides when the user is told, and a twitchier number would
/// report a hiccup as an outage.
const DIRECT_LOSS_LIMIT: u64 = 3;

/// How recently the node must have sent something authenticated for the path to
/// count as carrying traffic regardless of what the ICMP probes say.
const DIRECT_LIVENESS_WINDOW: Duration = Duration::from_secs(5);

/// Probe interval once a node has shown it will not answer ICMP. Slow enough
/// to be free, frequent enough that a node which starts answering is noticed.
const DIRECT_QUIET_PROBE_INTERVAL: Duration = Duration::from_secs(15);
/// Whether `address` is one this machine could reach the Internet from.
///
/// Loopback, link-local and unique-local addresses exist on machines with no
/// IPv6 connectivity at all, so treating them as an exposure would warn
/// everyone.
fn is_globally_routable_ipv6(address: std::net::Ipv6Addr) -> bool {
    let first = address.segments()[0];
    !address.is_loopback()
        && !address.is_unspecified()
        // fe80::/10 link-local
        && first & 0xffc0 != 0xfe80
        // fc00::/7 unique local
        && first & 0xfe00 != 0xfc00
}

/// What IPv6 traffic this session does and does not carry.
///
/// GamePath tunnels IPv4 only: the capture filter, the address rewriting and
/// the relay framing are all IPv4. On a dual-stack connection IPv6 therefore
/// keeps using the normal route, which is a leak if the user believed
/// all-traffic mode meant all traffic. Reporting it is the honest minimum
/// until IPv6 is carried end to end.
fn ipv6_exposure() -> Value {
    // Connecting a UDP socket sends nothing; it only makes the OS choose a
    // source address, which is exactly the question being asked.
    let source = std::net::UdpSocket::bind("[::]:0")
        .and_then(|socket| {
            socket.connect("[2606:4700:4700::1111]:53")?;
            socket.local_addr()
        })
        .ok()
        .and_then(|address| match address.ip() {
            std::net::IpAddr::V6(address) => Some(address),
            std::net::IpAddr::V4(_) => None,
        });
    json!({
        "carried": false,
        "systemHasRoute": source.is_some_and(is_globally_routable_ipv6),
    })
}

/// Where a direct session's latency probe is aimed. A public resolver that
/// answers echo requests, reached through the node like any game server.
const DIRECT_PROBE_TARGET: std::net::Ipv4Addr = gamepath_engine::BENCHMARK_TARGET;

/// Carries a direct session's traffic through its single node.
///
/// There is no relay here to exchange control frames with, so health and
/// latency come from two different places. The WireGuard handshake decides
/// whether the node is up: it either answered or it did not, and nothing about
/// the user's traffic can make that ambiguous. An ICMP echo through the tunnel
/// then measures the whole trip out to the Internet — but only as telemetry.
/// Plenty of providers filter ICMP while routing everything else perfectly, so
/// after a few unanswered probes this stops asking and stops counting them as
/// loss, rather than reporting a healthy node as totally lossy.
#[allow(clippy::too_many_arguments)]
fn run_direct_path(
    mut path: DirectPath,
    address: std::net::Ipv4Addr,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
    inbound: mpsc::SyncSender<Vec<u8>>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    telemetry: PathTelemetry,
    session_id: u64,
) {
    let identifier = rand::random::<u16>();
    let mut probe_sequence = 0_u16;
    let mut next_probe = Instant::now();
    let mut pending_probe: Option<Instant> = None;
    // The probe deadline follows this node's own round trip, so a provider that
    // is simply distant is not mistaken for one that is losing packets.
    let mut rtt = RttEstimator::default();
    let mut latency_watch = LatencyWatch::default();
    let mut last_iteration = Instant::now();
    let mut last_worker_gap_log: Option<Instant> = None;
    let mut probes_attempted = 0_u64;
    let mut consecutive_losses = 0_u64;
    let mut icmp_answered = false;
    let mut published_health = (None, false);
    let mut published_error = false;
    // Set once this worker has a specific answer for why the node is not
    // usable. Transport errors are noisier and less useful than that answer,
    // so they stop overwriting it.
    let mut verdict = false;
    let started = Instant::now();
    let mut reported_silence = false;
    // Any packet the node sends back has already passed WireGuard's or
    // OpenVPN's authentication, so it proves the tunnel is alive whether or not
    // ICMP is carried. Handshake age alone does not: a node can complete one
    // and then stop forwarding.
    let mut last_authenticated_receive: Option<Instant> = None;
    let mut published_healthy = false;
    let endpoint = path.endpoint();

    while !stop.load(Ordering::Acquire) {
        let iteration_started = Instant::now();
        let worker_gap = iteration_started.saturating_duration_since(last_iteration);
        last_iteration = iteration_started;
        let worker_gap_ms = worker_gap.as_millis().min(u128::from(u64::MAX)) as u64;
        telemetry.worker_gap_peak_ms[0].fetch_max(worker_gap_ms, Ordering::Relaxed);
        if worker_gap >= WORKER_GAP_WARN
            && last_worker_gap_log.is_none_or(|logged| logged.elapsed() >= WORKER_GAP_LOG_INTERVAL)
        {
            last_worker_gap_log = Some(iteration_started);
            log_warn!(
                "session {session_id} route 1 worker gap {worker_gap_ms} ms; q={} drop={} uplink={:?}",
                telemetry.queue_depth[0].load(Ordering::Relaxed),
                telemetry.dropped[0].load(Ordering::Relaxed),
                telemetry.uplink.state()
            );
        }
        telemetry.iterations[0].fetch_add(1, Ordering::Relaxed);
        // Health is decided first so the rest of the iteration can see it, and
        // published only when it moves: this lock is on the hot path.
        let handshake = path.handshake_latency_ms();
        // Authenticated return traffic outranks the probe verdict: a node that
        // is demonstrably carrying packets is not down because ICMP to
        // 1.1.1.1 is being filtered somewhere past it.
        let carrying =
            last_authenticated_receive.is_some_and(|seen| seen.elapsed() <= DIRECT_LIVENESS_WINDOW);
        let losing = icmp_answered && consecutive_losses >= DIRECT_LOSS_LIMIT && !carrying;
        let reachable = handshake.is_some() && !losing;
        if reachable != published_healthy {
            publish_path_health(&telemetry.healthy_mask, 0, reachable);
            published_healthy = reachable;
        }
        if (handshake, reachable) != published_health {
            let mut current = statuses.lock().unwrap();
            current[0].reachable = reachable;
            current[0].handshake_ms = handshake;
            // WireGuard's handshake is one round trip, so it doubles as a hop
            // estimate. OpenVPN's spans a TLS negotiation whose round-trip
            // count depends on the server, so none is offered.
            current[0].handshake_round_trips = (path.kind() == KIND_WIREGUARD).then_some(1);
            if let Some(latency) = handshake {
                // Stand in for the end-to-end number until a probe answers, so
                // a node that filters ICMP still reports a real measurement.
                current[0].latency_ms.get_or_insert(latency);
            }
            current[0].last_error = losing
                .then(|| format!("{endpoint} stopped answering probes sent through the tunnel"));
            published_error = losing;
            verdict = losing;
            published_health = (handshake, reachable);
        }
        drain_send_queue(
            &commands,
            0,
            &telemetry.queue_depth,
            &telemetry.dropped,
            &telemetry.stale_dropped,
            |frame| (frame.len(), path.send_packet(frame)),
            |length, result| record_path_send(&statuses, 0, length, result),
        );
        if pending_probe.is_none() && Instant::now() >= next_probe {
            probe_sequence = probe_sequence.wrapping_add(1);
            let probe = icmp_echo_packet(
                address,
                DIRECT_PROBE_TARGET,
                identifier,
                probe_sequence,
                false,
            );
            match path.send_packet(&probe) {
                Ok(()) => {
                    probes_attempted += 1;
                    // Until one probe is answered nothing is published, so a
                    // node that filters ICMP never reports probes it did send
                    // and never looks totally lossy because of it.
                    if icmp_answered {
                        statuses.lock().unwrap()[0].probes_sent += 1;
                    }
                    pending_probe = Some(Instant::now());
                }
                // The handshake, not this probe, decides whether the node is
                // up, so a failed send is recorded and the loop carries on.
                Err(error) => {
                    if !verdict {
                        statuses.lock().unwrap()[0].last_error = Some(error);
                        published_error = true;
                    }
                }
            }
            next_probe = Instant::now() + PROBE_INTERVAL;
        }
        match path.receive_packets(WORKER_RECEIVE_TIMEOUT) {
            Ok(packets) => {
                for packet in packets {
                    if is_matching_icmp_reply(&packet, DIRECT_PROBE_TARGET, address, identifier) {
                        let Some(started) = pending_probe.take() else {
                            continue;
                        };
                        let elapsed = started.elapsed();
                        rtt.record(elapsed);
                        let latency = elapsed.as_secs_f64() * 1000.0;
                        let first = !icmp_answered;
                        icmp_answered = true;
                        consecutive_losses = 0;
                        {
                            let mut current = statuses.lock().unwrap();
                            // The probe this answers was sent before ICMP was
                            // known to work, so it was not counted then.
                            current[0].probes_sent += u64::from(first);
                            current[0].probes_received += 1;
                            current[0].latency_ms = Some(latency);
                        }
                        scheduler_metrics.lock().unwrap()[0].record_probe(latency);
                        match latency_watch.observe(latency, Instant::now()) {
                            Some(LatencyEvent::Degraded {
                                baseline_ms,
                                observed_ms,
                            }) => log_warn!(
                                "session {session_id} route 1 data-plane RTT degraded: \
                                 {observed_ms:.0} ms vs {baseline_ms:.0} ms baseline; \
                                 q={} drop={} uplink={:?}",
                                telemetry.queue_depth[0].load(Ordering::Relaxed),
                                telemetry.dropped[0].load(Ordering::Relaxed),
                                telemetry.uplink.state()
                            ),
                            Some(LatencyEvent::Recovered {
                                baseline_ms,
                                peak_ms,
                                duration,
                            }) => log_info!(
                                "session {session_id} route 1 data-plane RTT recovered after \
                                 {:.1} s (baseline {baseline_ms:.0} ms, peak {peak_ms:.0} ms)",
                                duration.as_secs_f64()
                            ),
                            None => {}
                        }
                        last_authenticated_receive = Some(Instant::now());
                        continue;
                    }
                    record_path_receive(&statuses, 0, packet.len());
                    last_authenticated_receive = Some(Instant::now());
                    // Blocking here would stall the probe and timer work that
                    // decides whether this path is still usable.
                    if let Err(mpsc::TrySendError::Full(_)) = inbound.try_send(packet) {
                        telemetry.dropped[0].fetch_add(1, Ordering::Relaxed);
                        telemetry.inbound_dropped[0].fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Windows reports an unreachable endpoint on the next read of a
                // connected UDP socket, so a restarting node leaves an error
                // behind that its next reply disproves. Clearing it costs a
                // lock, so it is taken only when the state actually changes.
                if published_error && reachable {
                    statuses.lock().unwrap()[0].last_error = None;
                    published_error = false;
                }
            }
            Err(error) => {
                if !verdict {
                    statuses.lock().unwrap()[0].last_error = Some(error);
                    published_error = true;
                }
            }
        }
        // A silent peer is the usual way a direct session fails to start, and
        // the timeout alone would not say which part of the file to look at.
        if !reported_silence
            && path.kind() == KIND_WIREGUARD
            && path.handshake_latency_ms().is_none()
            && started.elapsed() > Duration::from_secs(3)
        {
            reported_silence = true;
            published_error = true;
            verdict = true;
            statuses.lock().unwrap()[0].last_error = Some(format!(
                "no WireGuard handshake reply from {endpoint}; check the configuration's Endpoint, \
                 PrivateKey and Peer PublicKey"
            ));
        }
        if pending_probe.is_some_and(|started| started.elapsed() > rtt.timeout()) {
            pending_probe = None;
            if icmp_answered {
                consecutive_losses += 1;
                statuses.lock().unwrap()[0].probes_lost += 1;
                scheduler_metrics.lock().unwrap()[0].record_loss();
            } else if probes_attempted >= DIRECT_PROBE_ATTEMPTS {
                // Never answered once: this node does not carry ICMP, which
                // says nothing about the traffic it does carry. Back off to a
                // slow retry rather than stopping for the session, so a node
                // that starts answering later is measured again.
                next_probe = Instant::now() + DIRECT_QUIET_PROBE_INTERVAL;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_path(
    mut path: Box<dyn RelayPath>,
    index: usize,
    sequences: Arc<AtomicU64>,
    client_id: [u8; 16],
    key: [u8; 32],
    session_id: u64,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
    inbound: mpsc::SyncSender<Vec<u8>>,
    ingress: Arc<RelayIngress>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    decision_mask: Arc<AtomicU64>,
    fallback_mask: u64,
    strategy: Strategy,
    telemetry: PathTelemetry,
    dialer: PathDialer,
    route_count: usize,
) {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};

    let Ok(crypto) = SessionCrypto::new(&key, session_id) else {
        return;
    };
    let mut next_probe = Instant::now();
    let mut pending_probe: Option<(u64, Instant)> = None;
    let mut correlated_probes = false;
    let mut warned_legacy_probes = false;
    let mut published_setup_latency = None;
    // The probe deadline tracks this path rather than being a constant that has
    // to suit both a 60 ms route and a congested one. Its floor comes from the
    // transport, because a stream-carried path stalls for its own retransmit
    // and answering later than that is not the same as not answering.
    let mut rtt = RttEstimator::with_floor(path.probe_deadline_floor());
    let mut latency_watch = LatencyWatch::default();
    let mut last_iteration = Instant::now();
    let mut last_worker_gap_log: Option<Instant> = None;
    // Consecutive failed health checks and the next redial deadline reset as
    // soon as the path answers. An already-running redial stays owned until
    // it finishes, then is discarded if that recovery made it obsolete.
    let mut failures = 0_u32;
    let mut backoff = RECONNECT_BACKOFF_MIN;
    let mut next_redial: Option<Instant> = None;
    // A dial can take seconds - a SOCKS5 connect allows eight, an OpenVPN
    // handshake its own - so it runs on its own thread and the result is
    // collected here. The worker keeps probing and keeps checking `stop` while
    // it is in flight, which is what stops a dead route delaying a session stop.
    let mut dialing: Option<ReconnectAttempt<Box<dyn RelayPath>>> = None;
    while !stop.load(Ordering::Acquire) {
        let iteration_started = Instant::now();
        let worker_gap = iteration_started.saturating_duration_since(last_iteration);
        last_iteration = iteration_started;
        let worker_gap_ms = worker_gap.as_millis().min(u128::from(u64::MAX)) as u64;
        telemetry.worker_gap_peak_ms[index].fetch_max(worker_gap_ms, Ordering::Relaxed);
        if worker_gap >= WORKER_GAP_WARN
            && last_worker_gap_log.is_none_or(|logged| logged.elapsed() >= WORKER_GAP_LOG_INTERVAL)
        {
            last_worker_gap_log = Some(iteration_started);
            log_warn!(
                "session {session_id} route {} worker gap {} ms; q={} drop={} uplink={:?}",
                index + 1,
                worker_gap_ms,
                telemetry.queue_depth[index].load(Ordering::Relaxed),
                telemetry.dropped[index].load(Ordering::Relaxed),
                telemetry.uplink.state()
            );
        }
        telemetry.iterations[index].fetch_add(1, Ordering::Relaxed);
        match dialing.as_mut().map(ReconnectAttempt::poll) {
            Some(ReconnectPoll::Finished(Ok(replacement))) => {
                dialing = None;
                path = replacement;
                publish_path_health(&telemetry.healthy_mask, index, false);
                // A redial may fall back from UDP to TCP (or recover to UDP).
                // Neither the old samples nor its deadline floor apply.
                rtt = RttEstimator::with_floor(path.probe_deadline_floor());
                latency_watch.reset();
                failures = 0;
                // Opening a socket is not recovery. Repeated replacements
                // that never answer must back off until a real pong arrives.
                backoff = next_backoff(backoff);
                next_redial = None;
                pending_probe = None;
                published_setup_latency = None;
                // The new transport has to prove itself: only an answered probe
                // puts this path back into the dispatcher's selection.
                next_probe = Instant::now();
                log_info!(
                    "route {} transport opened via {}; awaiting relay probe",
                    index + 1,
                    path.endpoint()
                );
                let mut current = statuses.lock().unwrap();
                current[index].reachable = false;
                current[index].endpoint = path.endpoint();
                current[index].last_error = Some("reconnected; waiting for a probe".into());
            }
            Some(ReconnectPoll::Finished(Err(error))) => {
                dialing = None;
                backoff = next_backoff(backoff);
                next_redial = Some(Instant::now() + backoff);
                log_warn!(
                    "route {} reconnect failed, retrying in {} s: {error}",
                    index + 1,
                    backoff.as_secs()
                );
                statuses.lock().unwrap()[index].last_error =
                    Some(format!("reconnect failed, retrying: {error}"));
            }
            Some(ReconnectPoll::Discarded) => {
                dialing = None;
                log_info!(
                    "session {session_id} route {} discarded obsolete reconnect after recovery",
                    index + 1
                );
            }
            Some(ReconnectPoll::Pending) | None => {}
        }
        // A redial is only worth making when something proves the uplink is
        // there. The monitor answers that directly when it can; when it cannot
        // - a router that filters ICMP - fall back to inferring it from whether
        // any other path is up, which is all that was available before.
        let uplink_down = match telemetry.uplink.state() {
            UplinkState::Down => true,
            UplinkState::Up => false,
            UplinkState::Unknown => {
                route_count > 1 && !another_path_is_up(&telemetry.healthy_mask, index)
            }
        };
        if dialing.is_none() && uplink_down && next_redial.is_some_and(|at| Instant::now() >= at) {
            next_redial = Some(Instant::now() + UPLINK_DOWN_BACKOFF);
            log_warn!(
                "route {} is not redialling: no path is up, so the uplink is the likely cause",
                index + 1
            );
        }
        if dialing.is_none() && !uplink_down && next_redial.is_some_and(|at| Instant::now() >= at) {
            next_redial = None;
            let (result_tx, result_rx) = mpsc::channel();
            let attempt = dialer.clone();
            match thread::Builder::new()
                .name(format!("gamepath-redial-{}", index + 1))
                .spawn(move || {
                    // The worker may already have stopped; nothing depends on
                    // this send arriving.
                    let _ = result_tx.send(attempt.open());
                }) {
                Ok(_) => {
                    dialing = Some(ReconnectAttempt::new(result_rx));
                    log_info!("route {} is reconnecting", index + 1);
                    statuses.lock().unwrap()[index].last_error = Some("reconnecting".to_owned());
                }
                Err(error) => {
                    backoff = next_backoff(backoff);
                    next_redial = Some(Instant::now() + backoff);
                    statuses.lock().unwrap()[index].last_error =
                        Some(format!("could not start a reconnect attempt: {error}"));
                }
            }
        }
        drain_send_queue(
            &commands,
            index,
            &telemetry.queue_depth,
            &telemetry.dropped,
            &telemetry.stale_dropped,
            |frame| (frame.len(), path.send_frame(frame)),
            |length, result| record_path_send(&statuses, index, length, result),
        );
        if Instant::now() >= next_probe && pending_probe.is_none() {
            let sequence = sequences.fetch_add(1, Ordering::Relaxed);
            let result = (|| {
                let header = FrameHeader {
                    flags: FLAG_CONTROL,
                    client_id,
                    session_id,
                    sequence,
                };
                let overlay = crypto
                    .seal_client(header, &gamepath_engine::protocol::probe_request(sequence))?;
                {
                    let mut current = statuses.lock().unwrap();
                    current[index].packets_sent += 1;
                    current[index].probes_sent += 1;
                }
                path.send_probe(&overlay)
            })();
            match result {
                Ok(()) => pending_probe = Some((sequence, Instant::now())),
                Err(error) => {
                    statuses.lock().unwrap()[index].probes_lost += 1;
                    update_scheduler_probe(
                        &scheduler_metrics,
                        &decision_mask,
                        fallback_mask,
                        index,
                        None,
                        strategy,
                        session_id,
                    );
                    update_path_status(&statuses, index, Err(error));
                    failures += 1;
                    if failures == HEALTH_FAILURE_THRESHOLD - 1 {
                        log_warn!(
                            "session {session_id} route {} degraded after {failures} consecutive \
                             probe send failures; still carrying duplicated traffic",
                            index + 1
                        );
                    } else if failures == HEALTH_FAILURE_THRESHOLD {
                        log_warn!(
                            "session {session_id} route {} unavailable after {failures} consecutive \
                             probe send failures; dispatcher is using available alternatives",
                            index + 1
                        );
                    }
                    if failures >= HEALTH_FAILURE_THRESHOLD {
                        publish_path_health(&telemetry.healthy_mask, index, false);
                    }
                    schedule_redial(failures, backoff, &mut next_redial);
                    next_probe = Instant::now() + PROBE_INTERVAL_DEGRADED;
                }
            }
        }
        match path.receive_frames(WORKER_RECEIVE_TIMEOUT) {
            Ok(frames) => {
                for frame in frames {
                    if let Ok((header, plaintext)) = crypto.open_server(&frame) {
                        if header.client_id != client_id || header.session_id != session_id {
                            continue;
                        }
                        if header.flags & FLAG_CONTROL != 0 {
                            if let Some((sequence, started)) = pending_probe {
                                if header.flags & FLAG_SERVER_TO_CLIENT == 0
                                    || !gamepath_engine::protocol::probe_reply_matches(
                                        &plaintext,
                                        sequence,
                                        !correlated_probes,
                                    )
                                {
                                    continue;
                                }
                                if plaintext.len() == 12 {
                                    correlated_probes = true;
                                } else if !warned_legacy_probes {
                                    log_warn!(
                                        "route {} relay uses legacy probe replies; update the relay \
                                         for accurate RTT matching after timeouts",
                                        index + 1
                                    );
                                    warned_legacy_probes = true;
                                }
                                pending_probe = None;
                                let elapsed = started.elapsed();
                                rtt.record(elapsed);
                                let latency = elapsed.as_secs_f64() * 1000.0;
                                statuses.lock().unwrap()[index].probes_received += 1;
                                update_path_status(&statuses, index, Ok(latency));
                                // An authenticated pong is the one unambiguous
                                // sign this path is carrying traffic, so this
                                // is where it rejoins the dispatcher, and where
                                // any pending reconnect is called off.
                                publish_path_health(&telemetry.healthy_mask, index, true);
                                if failures >= HEALTH_FAILURE_THRESHOLD - 1 {
                                    log_info!(
                                        "route {} is carrying traffic again after {failures} \
                                         failed check(s), {latency:.0} ms",
                                        index + 1
                                    );
                                }
                                failures = 0;
                                backoff = RECONNECT_BACKOFF_MIN;
                                next_redial = None;
                                if let Some(attempt) = dialing.as_mut() {
                                    attempt.recovered();
                                }
                                update_scheduler_probe(
                                    &scheduler_metrics,
                                    &decision_mask,
                                    fallback_mask,
                                    index,
                                    Some(latency),
                                    strategy,
                                    session_id,
                                );
                                match latency_watch.observe(latency, Instant::now()) {
                                    Some(LatencyEvent::Degraded {
                                        baseline_ms,
                                        observed_ms,
                                    }) => log_warn!(
                                        "session {session_id} route {} relay RTT degraded: \
                                         {observed_ms:.0} ms vs {baseline_ms:.0} ms baseline; \
                                         q={} drop={} uplink={:?}",
                                        index + 1,
                                        telemetry.queue_depth[index].load(Ordering::Relaxed),
                                        telemetry.dropped[index].load(Ordering::Relaxed),
                                        telemetry.uplink.state()
                                    ),
                                    Some(LatencyEvent::Recovered {
                                        baseline_ms,
                                        peak_ms,
                                        duration,
                                    }) => log_info!(
                                        "session {session_id} route {} relay RTT recovered after \
                                         {:.1} s (baseline {baseline_ms:.0} ms, peak {peak_ms:.0} ms)",
                                        index + 1,
                                        duration.as_secs_f64()
                                    ),
                                    None => {}
                                }
                                next_probe = Instant::now() + PROBE_INTERVAL;
                            }
                        } else if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
                            record_path_receive(&statuses, index, frame.len());
                            // Blocking on a saturated inbound queue would stall
                            // this path's probes and timers, which is how a
                            // busy path ends up reported as a dead one.
                            if let Err(mpsc::TrySendError::Full(_)) =
                                ingress.enqueue_authenticated(&header, plaintext, &inbound)
                            {
                                telemetry.dropped[index].fetch_add(1, Ordering::Relaxed);
                                telemetry.inbound_dropped[index].fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            // Not a health verdict: Windows surfaces an earlier send's ICMP
            // unreachable on the next read, and a restarting node's next reply
            // disproves it. The probe timeout below is what takes a path out of
            // the dispatcher, so a transient like this cannot interrupt
            // duplication.
            Err(error) => update_path_status(&statuses, index, Err(error)),
        }
        // Setup latency is fixed once a path is up, and this lock is shared by
        // every path worker, so it is taken only when the value actually moves.
        let setup_latency = path.setup_latency_ms();
        if setup_latency != published_setup_latency {
            let mut current = statuses.lock().unwrap();
            current[index].handshake_ms = setup_latency;
            current[index].handshake_round_trips = path.setup_round_trips();
            published_setup_latency = setup_latency;
        }
        if pending_probe.is_some_and(|(_, started)| started.elapsed() > rtt.timeout()) {
            pending_probe = None;
            statuses.lock().unwrap()[index].probes_lost += 1;
            update_scheduler_probe(
                &scheduler_metrics,
                &decision_mask,
                fallback_mask,
                index,
                None,
                strategy,
                session_id,
            );
            let note = path.health_note();
            failures += 1;
            schedule_redial(failures, backoff, &mut next_redial);
            if failures == HEALTH_FAILURE_THRESHOLD - 1 {
                log_warn!(
                    "session {session_id} route {} degraded after {failures} consecutive health \
                     timeouts; still carrying duplicated traffic{}",
                    index + 1,
                    note.as_deref()
                        .map(|note| format!(": {note}"))
                        .unwrap_or_default()
                );
            } else if failures == HEALTH_FAILURE_THRESHOLD {
                log_warn!(
                    "session {session_id} route {} unavailable after {failures} consecutive health \
                     timeouts; dispatcher is using available alternatives{}",
                    index + 1,
                    note.as_deref()
                        .map(|note| format!(": {note}"))
                        .unwrap_or_default()
                );
            }
            // Only a run of unanswered probes takes the path out of service.
            // A single loss has already been recorded against the path's score
            // above, which is the proportionate response to it.
            if failures >= HEALTH_FAILURE_THRESHOLD {
                publish_path_health(&telemetry.healthy_mask, index, false);
                update_path_status(
                    &statuses,
                    index,
                    Err(match note {
                        Some(note) => format!("path health check timed out: {note}"),
                        None => "path health check timed out".to_owned(),
                    }),
                );
            }
            next_probe = Instant::now() + PROBE_INTERVAL_DEGRADED;
        }
    }
}

/// The paths a packet is actually dispatched to: the scheduler's pick,
/// narrowed to the ones known to be carrying traffic.
///
/// If the scheduler's pick has gone down, immediately use the healthy routes.
/// Health and scheduling are published separately, so their snapshots can
/// disagree during failure or recovery. Keep the original pick only when no
/// route has proved healthy, including startup before the first probe reply.
fn selected_paths(decision: u64, healthy: u64) -> u64 {
    if decision & healthy != 0 {
        decision & healthy
    } else if healthy != 0 {
        healthy
    } else {
        decision
    }
}

/// Sends at most [`PATH_SEND_BATCH`] queued packets, shedding any that waited
/// past [`PATH_QUEUE_MAX_AGE`], and returns without draining the rest so the
/// caller can service inbound frames, probes and timers.
fn drain_send_queue(
    commands: &mpsc::Receiver<PathCommand>,
    index: usize,
    queue_depth: &[AtomicU64],
    dropped: &[AtomicU64],
    stale_dropped: &[AtomicU64],
    mut send: impl FnMut(&[u8]) -> (usize, Result<(), String>),
    mut record: impl FnMut(usize, Result<(), String>),
) {
    for _ in 0..PATH_SEND_BATCH {
        let Ok(command) = commands.try_recv() else {
            return;
        };
        if let Some(depth) = queue_depth.get(index) {
            depth.fetch_sub(1, Ordering::Relaxed);
        }
        if command.queued_at.elapsed() > PATH_QUEUE_MAX_AGE {
            if let Some(dropped) = dropped.get(index) {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(dropped) = stale_dropped.get(index) {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }
        let (length, result) = send(&command.frame);
        record(length, result);
    }
}

/// Starts the uplink monitor, which answers "can this machine reach the
/// Internet at all" without going through any node.
///
/// The probe is pinned to the adapter that currently carries the default route,
/// captured here while that is still the physical one - once capture starts,
/// the tunnel owns it.
fn spawn_uplink_monitor(
    stop: &Arc<AtomicBool>,
    telemetry: &PathTelemetry,
) -> Option<JoinHandle<()>> {
    let source = physical_source_address();
    let (stop, monitor) = (Arc::clone(stop), Arc::clone(&telemetry.uplink));
    thread::Builder::new()
        .name("gamepath-uplink".into())
        .spawn(move || {
            uplink::run(monitor, stop, source, |previous, next| {
                log_warn!("uplink {previous:?} -> {next:?}");
            })
        })
        .inspect_err(|error| log_warn!("uplink monitoring is unavailable: {error}"))
        .ok()
}

/// The local address the default route currently uses.
///
/// Connecting a UDP socket sends nothing; it only makes the OS pick a source,
/// which is exactly the question. `None` leaves the probe unpinned, which still
/// works whenever the tunnel does not own the default route.
fn physical_source_address() -> Option<std::net::Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((uplink::PROBE_TARGET, 53)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        _ => None,
    }
}

/// Starts the summary thread, or logs why it could not start and carries on:
/// a session that runs without its log line is better than one that refuses to
/// start because of it.
fn spawn_session_summary(
    session_id: u64,
    stop: &Arc<AtomicBool>,
    statuses: &Arc<Mutex<Vec<PathSessionStatus>>>,
    telemetry: &PathTelemetry,
    decision_mask: &Arc<AtomicU64>,
    scheduler_metrics: &Arc<Mutex<Vec<PathMetrics>>>,
) -> Option<JoinHandle<()>> {
    let (stop, statuses) = (Arc::clone(stop), Arc::clone(statuses));
    let (telemetry, decision_mask) = (telemetry.clone(), Arc::clone(decision_mask));
    let scheduler_metrics = Arc::clone(scheduler_metrics);
    thread::Builder::new()
        .name("gamepath-session-summary".into())
        .spawn(move || {
            run_session_summary(
                session_id,
                stop,
                statuses,
                telemetry,
                decision_mask,
                scheduler_metrics,
            )
        })
        .inspect_err(|error| log_warn!("session summary logging is unavailable: {error}"))
        .ok()
}

/// How often a running session writes its summary line.
const SESSION_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Writes one line a minute describing every path while a session runs.
///
/// This is the context a transition on its own does not give: what the other
/// routes were doing at the time, whether queues were backing up, and how much
/// had been shed. One line a minute remains small enough for the rotation cap,
/// while drop bursts are reported promptly and rate-limited above.
fn run_session_summary(
    session_id: u64,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    telemetry: PathTelemetry,
    decision_mask: Arc<AtomicU64>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
) {
    let route_count = statuses.lock().unwrap().len();
    let mut previous_lost = vec![0_u64; route_count];
    let mut previous_dropped = vec![0_u64; route_count];
    let mut previous_sent = vec![0_u64; route_count];
    let mut previous_received = vec![0_u64; route_count];
    let mut reported_dropped = vec![0_u64; route_count];
    let mut reported_full = vec![0_u64; route_count];
    let mut reported_stale = vec![0_u64; route_count];
    let mut reported_inbound = vec![0_u64; route_count];
    let mut last_drop_log: Option<Instant> = None;
    let mut next = Instant::now() + SESSION_SUMMARY_INTERVAL;
    while !stop.load(Ordering::Acquire) {
        let observed_at = Instant::now();
        let current_dropped = telemetry
            .dropped
            .iter()
            .map(|value| value.load(Ordering::Relaxed))
            .collect::<Vec<_>>();
        let has_new_drops = current_dropped
            .iter()
            .zip(&reported_dropped)
            .any(|(current, reported)| current > reported);
        if has_new_drops
            && last_drop_log
                .is_none_or(|logged| observed_at.duration_since(logged) >= DROP_LOG_INTERVAL)
        {
            let details = (0..route_count)
                .filter_map(|index| {
                    let total = current_dropped[index].saturating_sub(reported_dropped[index]);
                    (total > 0).then(|| {
                        let full = telemetry.queue_full_dropped[index].load(Ordering::Relaxed);
                        let stale = telemetry.stale_dropped[index].load(Ordering::Relaxed);
                        let inbound = telemetry.inbound_dropped[index].load(Ordering::Relaxed);
                        let detail = format!(
                            "{}:+{total} (full +{}, stale +{}, inbound +{}, q={}, peak={})",
                            index + 1,
                            full.saturating_sub(reported_full[index]),
                            stale.saturating_sub(reported_stale[index]),
                            inbound.saturating_sub(reported_inbound[index]),
                            telemetry.queue_depth[index].load(Ordering::Relaxed),
                            telemetry.queue_peak[index].load(Ordering::Relaxed),
                        );
                        reported_full[index] = full;
                        reported_stale[index] = stale;
                        reported_inbound[index] = inbound;
                        detail
                    })
                })
                .collect::<Vec<_>>()
                .join(" | ");
            log_warn!("session {session_id} packet shedding by route: {details}");
            reported_dropped.clone_from(&current_dropped);
            last_drop_log = Some(observed_at);
        }
        if observed_at < next {
            thread::sleep(Duration::from_millis(250));
            continue;
        }
        next = observed_at + SESSION_SUMMARY_INTERVAL;
        let selected = selected_paths(
            decision_mask.load(Ordering::Acquire),
            telemetry.healthy_mask.load(Ordering::Acquire),
        );
        let paths = statuses.lock().unwrap().clone();
        let metrics = scheduler_metrics.lock().unwrap().clone();
        let routes = paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let carrying = selected & 1_u64.checked_shl(index as u32).unwrap_or(0) != 0;
                let relay_rtt = path
                    .latency_ms
                    .map(|value| format!("{value:.0}ms"))
                    .unwrap_or_else(|| "-".into());
                let (ewma, jitter, loss) = metrics.get(index).map_or((0.0, 0.0, 0.0), |metric| {
                    (
                        metric.latency_ms,
                        metric.jitter_ms,
                        metric.loss_ratio * 100.0,
                    )
                });
                let dropped = telemetry.dropped[index].load(Ordering::Relaxed);
                let lost_delta = path.probes_lost.saturating_sub(previous_lost[index]);
                let dropped_delta = dropped.saturating_sub(previous_dropped[index]);
                let sent_delta = path.packets_sent.saturating_sub(previous_sent[index]);
                let received_delta = path
                    .packets_received
                    .saturating_sub(previous_received[index]);
                previous_lost[index] = path.probes_lost;
                previous_dropped[index] = dropped;
                previous_sent[index] = path.packets_sent;
                previous_received[index] = path.packets_received;
                format!(
                    "{}:{}{} relay-rtt={relay_rtt} ewma={ewma:.0}ms jitter={jitter:.0}ms \
                     loss-ewma={loss:.0}% probes-lost={} (+{lost_delta}) q={}/peak={} \
                     drop={dropped} (+{dropped_delta}; full={} stale={} inbound={}) \
                     packets=+{sent_delta}/+{received_delta} worker-gap-peak={}ms",
                    path.route,
                    if path.reachable { "up" } else { "down" },
                    if carrying { "/active" } else { "" },
                    path.probes_lost,
                    telemetry.queue_depth[index].load(Ordering::Relaxed),
                    telemetry.queue_peak[index].load(Ordering::Relaxed),
                    telemetry.queue_full_dropped[index].load(Ordering::Relaxed),
                    telemetry.stale_dropped[index].load(Ordering::Relaxed),
                    telemetry.inbound_dropped[index].load(Ordering::Relaxed),
                    telemetry.worker_gap_peak_ms[index].load(Ordering::Relaxed),
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        log_info!(
            "session {session_id}: uplink {:?} | {routes}",
            telemetry.uplink.state()
        );
    }
}

/// The wait after a failed redial. The first attempt is immediate, so the
/// sequence grows from [`RECONNECT_BACKOFF_STEP`] rather than doubling zero.
fn next_backoff(current: Duration) -> Duration {
    if current.is_zero() {
        RECONNECT_BACKOFF_STEP
    } else {
        (current * 2).min(RECONNECT_BACKOFF_MAX)
    }
}

/// Arms the next redial once a path has failed [`RECONNECT_AFTER_FAILURES`]
/// health checks in a row, leaving an already-armed one alone so the backoff
/// is not restarted by every further failure.
fn schedule_redial(failures: u32, backoff: Duration, next_redial: &mut Option<Instant>) {
    if failures >= RECONNECT_AFTER_FAILURES && next_redial.is_none() {
        *next_redial = Some(Instant::now() + backoff);
    }
}

/// Records whether `index` is carrying traffic, so the dispatcher can leave a
/// dead path out of the pick without reading the status mutex per packet.
fn publish_path_health(healthy_mask: &AtomicU64, index: usize, healthy: bool) {
    let Some(bit) = 1_u64.checked_shl(index as u32) else {
        return;
    };
    if healthy {
        healthy_mask.fetch_or(bit, Ordering::Release);
    } else {
        healthy_mask.fetch_and(!bit, Ordering::Release);
    }
}

fn update_scheduler_probe(
    metrics: &Mutex<Vec<PathMetrics>>,
    decision_mask: &AtomicU64,
    fallback_mask: u64,
    index: usize,
    latency_ms: Option<f64>,
    strategy: Strategy,
    session_id: u64,
) {
    let mut metrics = metrics.lock().unwrap();
    let Some(path) = metrics.get_mut(index) else {
        return;
    };
    match latency_ms {
        Some(latency) => path.record_probe(latency),
        None => path.record_loss(),
    }
    let decision = choose_paths(&metrics, strategy);
    let next = mask_for_decision(decision, fallback_mask);
    let previous = decision_mask.swap(next, Ordering::AcqRel);
    if previous != next {
        let reason = latency_ms
            .map(|latency| format!("route {} probe {latency:.0} ms", index + 1))
            .unwrap_or_else(|| format!("route {} probe lost", index + 1));
        let snapshot = metrics
            .iter()
            .enumerate()
            .map(|(route, path)| {
                format!(
                    "{}:rtt={:.0}ms jitter={:.0}ms loss-ewma={:.0}% score={:.0}",
                    route + 1,
                    path.latency_ms,
                    path.jitter_ms,
                    path.loss_ratio * 100.0,
                    path.score()
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        log_info!(
            "session {session_id} scheduler routes {} -> {} after {reason}; {snapshot}",
            route_mask(previous),
            route_mask(next)
        );
    }
}

fn route_mask(mask: u64) -> String {
    let routes = (0..64)
        .filter(|index| mask & (1_u64 << index) != 0)
        .map(|index| (index + 1).to_string())
        .collect::<Vec<_>>();
    if routes.is_empty() {
        "none".to_owned()
    } else {
        routes.join("+")
    }
}

fn mask_for_decision(decision: Decision, fallback_mask: u64) -> u64 {
    let mask = match decision {
        Decision::Drop => 0,
        Decision::Single { path_id } => path_id
            .parse::<u32>()
            .ok()
            .and_then(|index| 1_u64.checked_shl(index))
            .unwrap_or(0),
        Decision::Duplicate { path_ids } => path_ids.into_iter().fold(0, |mask, path_id| {
            mask | path_id
                .parse::<u32>()
                .ok()
                .and_then(|index| 1_u64.checked_shl(index))
                .unwrap_or(0)
        }),
    };
    if mask == 0 { fallback_mask } else { mask }
}

fn update_path_status(
    statuses: &Mutex<Vec<PathSessionStatus>>,
    index: usize,
    result: Result<f64, String>,
) {
    let mut current = statuses.lock().unwrap();
    let status = &mut current[index];
    match result {
        Ok(latency) => {
            status.reachable = true;
            status.latency_ms = Some(latency);
            status.packets_received += 1;
            status.last_error = None;
        }
        Err(error) => {
            status.reachable = false;
            status.last_error = Some(error);
        }
    }
}

fn record_path_send(
    statuses: &Mutex<Vec<PathSessionStatus>>,
    index: usize,
    sent_bytes: usize,
    result: Result<(), String>,
) {
    let mut current = statuses.lock().unwrap();
    let status = &mut current[index];
    status.packets_sent += 1;
    status.bytes_sent += sent_bytes as u64;
    if let Err(error) = result {
        status.last_error = Some(error);
    }
}

fn record_path_receive(
    statuses: &Mutex<Vec<PathSessionStatus>>,
    index: usize,
    received_bytes: usize,
) {
    let mut current = statuses.lock().unwrap();
    let status = &mut current[index];
    status.packets_received += 1;
    status.bytes_received += received_bytes as u64;
}

fn icmp_echo_packet(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    identifier: u16,
    sequence: u16,
    reply: bool,
) -> Vec<u8> {
    let payload = b"gamepath-data-plane";
    let total_length = 20 + 8 + payload.len();
    let mut packet = vec![0_u8; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[20] = if reply { 0 } else { 8 };
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    packet[26..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

fn is_matching_icmp_reply(
    packet: &[u8],
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    identifier: u16,
) -> bool {
    packet.len() >= 28
        && packet[0] >> 4 == 4
        && packet[9] == 1
        && packet[12..16] == source.octets()
        && packet[16..20] == destination.octets()
        && packet[20] == 0
        && u16::from_be_bytes([packet[24], packet[25]]) == identifier
        && internet_checksum(&packet[20..]) == 0
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn resolve_ipv4(host: &str, port: u16) -> Result<std::net::Ipv4Addr, String> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve relay: {error}"))?
        .find_map(|address| match address.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or_else(|| "relay did not resolve to IPv4".into())
}

fn unix_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn probe_wireguard_routes(payload: Value) -> Result<Value, String> {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};
    use gamepath_engine::userspace_wireguard::{
        UserSpaceWireGuardPath, ipv4_udp_packet, ipv4_udp_payload,
    };
    use rand::Rng;
    use std::time::{Duration, Instant};

    let input: WireGuardProbeRequest = serde_json::from_value(payload)
        .map_err(|error| format!("invalid WireGuard probe: {error}"))?;
    if input.wireguard_configs.len() < 2 {
        return Err("at least two WireGuard configurations are required".into());
    }
    let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
    let (client_id, key) = enrollment.material()?;
    let relay_ip = format!("{}:{}", input.relay_host, input.relay_port)
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve relay: {error}"))?
        .find_map(|address| match address.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            std::net::IpAddr::V6(_) => None,
        })
        .ok_or("relay did not resolve to IPv4")?;
    let session_id = rand::random::<u64>();
    let crypto = SessionCrypto::new(&key, session_id)?;
    let mut results = Vec::new();
    for (index, source) in input.wireguard_configs.iter().enumerate() {
        let mut path = UserSpaceWireGuardPath::from_config(source)?;
        let sequence = index as u64 + 1;
        let header = FrameHeader {
            flags: FLAG_CONTROL,
            client_id,
            session_id,
            sequence,
        };
        let overlay = crypto.seal_client(header, b"ping")?;
        let source_port = rand::rng().random_range(49_152..=65_535);
        let inner = ipv4_udp_packet(
            path.address(),
            relay_ip,
            source_port,
            input.relay_port,
            &overlay,
        )?;
        let started = Instant::now();
        let reply = path.transact(&inner, Duration::from_secs(8))?;
        let (source_ip, destination_ip, reply_source_port, reply_destination_port, response_frame) =
            ipv4_udp_payload(&reply).ok_or("WireGuard path returned a non-UDP packet")?;
        if source_ip != relay_ip
            || destination_ip != path.address()
            || reply_source_port != input.relay_port
            || reply_destination_port != source_port
        {
            return Err("WireGuard path returned an unexpected UDP flow".into());
        }
        let (response_header, plaintext) = crypto.open_server(response_frame)?;
        if response_header.client_id != client_id
            || response_header.session_id != session_id
            || response_header.flags & (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
                != (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
            || plaintext != b"pong"
        {
            return Err("WireGuard path returned an invalid authenticated relay response".into());
        }
        results.push(json!({
            "route": index + 1,
            "endpoint": path.endpoint().to_string(),
            "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
            "reachable": true,
        }));
    }
    Ok(json!({ "reachable": true, "routes": results }))
}

fn probe_relay(payload: Value) -> Result<Value, String> {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};
    use std::time::{Duration, Instant};

    let input: ProbeRequest =
        serde_json::from_value(payload).map_err(|error| format!("invalid relay probe: {error}"))?;
    let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
    let (client_id, key) = enrollment.material()?;
    let relay: SocketAddr = format!("{}:{}", input.relay_host, input.relay_port)
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve relay: {error}"))?
        .next()
        .ok_or("relay address did not resolve")?;
    let bind = if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind).map_err(|error| format!("could not open probe socket: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let session_id = rand::random::<u64>();
    let header = FrameHeader {
        flags: FLAG_CONTROL,
        client_id,
        session_id,
        sequence: 1,
    };
    let crypto = SessionCrypto::new(&key, session_id)?;
    let frame = crypto.seal_client(header, b"ping")?;
    let started = Instant::now();
    socket
        .send_to(&frame, relay)
        .map_err(|error| format!("relay probe send failed: {error}"))?;
    let mut response = [0_u8; 2048];
    let (length, source) = socket
        .recv_from(&mut response)
        .map_err(|error| format!("relay did not answer: {error}"))?;
    if source.ip() != relay.ip() {
        return Err("relay probe came from an unexpected address".into());
    }
    let (response_header, plaintext) = crypto.open_server(&response[..length])?;
    if response_header.client_id != client_id
        || response_header.session_id != session_id
        || response_header.flags & (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
            != (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
        || plaintext != b"pong"
    {
        return Err("relay returned an invalid authenticated probe".into());
    }
    Ok(json!({
        "reachable": true,
        "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
        "virtualIpv4": enrollment.virtual_ipv4,
    }))
}

/// Proves a SOCKS5 proxy can carry GamePath traffic before it is saved as a
/// node. Accepting UDP ASSOCIATE is not enough on its own: some proxies accept
/// the association and then never forward a datagram, so this waits for an
/// authenticated reply that only the relay can produce.
fn probe_socks5_node(payload: Value) -> Result<Value, String> {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};

    let input: Socks5ProbeRequest = serde_json::from_value(payload)
        .map_err(|error| format!("invalid SOCKS5 probe: {error}"))?;
    let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
    let (client_id, key) = enrollment.material()?;
    let relay_ip = resolve_ipv4(&input.relay_host, input.relay_port)?;
    let relay = SocketAddrV4::new(relay_ip, input.relay_port);
    let config = Socks5NodeConfig {
        host: input.host,
        port: input.port,
        username: input.username,
        password: input.password,
    };
    let mut path = Socks5RelayPath::open(&config, relay)?;
    let session_id = rand::random::<u64>();
    let crypto = SessionCrypto::new(&key, session_id)?;
    let header = FrameHeader {
        flags: FLAG_CONTROL,
        client_id,
        session_id,
        sequence: 1,
    };
    let frame = crypto.seal_client(header, b"ping")?;
    let started = Instant::now();
    path.send_frame(&frame)?;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        let frames = path.receive_frames(Duration::from_millis(200))?;
        for response in frames {
            let Ok((reply, plaintext)) = crypto.open_server(&response) else {
                continue;
            };
            if reply.client_id != client_id
                || reply.session_id != session_id
                || reply.flags & (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
                    != (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
                || plaintext != b"pong"
            {
                continue;
            }
            return Ok(json!({
                "reachable": true,
                "udpAssociate": true,
                "proxy": path.endpoint(),
                "setupLatencyMs": path.setup_latency_ms(),
                "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
            }));
        }
    }
    // Before blaming the relay, find out whether this proxy forwards UDP at
    // all. Many do not, and answer DNS themselves in a way that makes the
    // association look functional.
    if answers_dns_without_forwarding(&config) {
        return Err(
            "this proxy answers DNS from its own resolver and does not forward UDP anywhere \
             else, so it cannot carry GamePath traffic. Testing it with a DNS query always \
             succeeds and proves nothing. If it chains to another proxy, that one has to \
             support UDP ASSOCIATE too: a TCP-only upstream refuses with code 7 while this \
             proxy still grants the association here, so the failure is invisible from \
             outside. Check the client's own log for that refusal. When the provider's \
             proxy is TCP-only, use a WireGuard configuration from them instead."
                .into(),
        );
    }
    Err(format!(
        "the proxy opened a UDP association and forwards UDP, but the relay never answered \
         through it. Check that UDP {} is open on the relay, and that the proxy has no \
         routing rule sending {} somewhere else.",
        input.relay_port, input.relay_host
    ))
}

/// Whether the proxy resolves DNS itself rather than relaying the datagram.
///
/// The query is aimed at 192.0.2.1, which is reserved for documentation and
/// routes nowhere. Nothing on the Internet can answer it, so a reply can only
/// have been produced by the proxy intercepting the query. Clients built on
/// sing-box and Xray commonly do exactly that, which is why a DNS round trip
/// through them is not evidence that they relay UDP.
fn answers_dns_without_forwarding(config: &Socks5NodeConfig) -> bool {
    const UNROUTABLE_RESOLVER: SocketAddrV4 =
        SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, 1), 53);
    // An A query for a name reserved by RFC 2606 to never exist.
    // Header, then the labels "gamepath" (8) and "invalid" (7), then A/IN.
    let query = [
        0x9e, 0x7a, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 8, b'g', b'a', b'm', b'e', b'p', b'a',
        b't', b'h', 7, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0, 0, 1, 0, 1,
    ];
    let Ok(mut path) = Socks5UdpPath::open(config, UNROUTABLE_RESOLVER) else {
        return false;
    };
    if path.send_frame(&query).is_err() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        match path.receive_frames(Duration::from_millis(200)) {
            // Any datagram at all settles it: the destination cannot reply.
            Ok(frames) if !frames.is_empty() => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    false
}

fn inspect_system() -> Value {
    let wireguard_exe = r"C:\Program Files\WireGuard\wireguard.exe";
    let wg_exe = r"C:\Program Files\WireGuard\wg.exe";
    let adapter = inspect_library(Path::new(r"vendor\wintun\wintun.dll"));
    let interception = inspect_backend(
        Path::new(r"vendor\windivert\WinDivert.dll"),
        Path::new(r"vendor\windivert\WinDivert64.sys"),
    );
    let interfaces = if Path::new(wg_exe).exists() {
        Command::new(wg_exe)
            .args(["show", "interfaces"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    json!({
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "wireGuardInstalled": Path::new(wireguard_exe).exists() && Path::new(wg_exe).exists(),
        "wireGuardExecutable": Path::new(wireguard_exe).exists().then_some(wireguard_exe),
        "activeWireGuardInterfaces": interfaces,
        "packetAdapter": adapter,
        "packetAdapterInstalled": adapter.driver_version.is_some(),
        "interception": interception,
    })
}

fn prepare_session(payload: Value) -> Result<Value, String> {
    let input: PrepareRequest = serde_json::from_value(payload)
        .map_err(|error| format!("invalid session plan: {error}"))?;
    if input.route_ids.is_empty() {
        return Err("at least one active WireGuard route is required".into());
    }
    let interception = compile_policy(&input.traffic_mode, &input.rules)?;
    // A direct session has no relay to address and no enrollment to prove, so
    // only the capture policy above is planned for it.
    let enrollment = match input.mode {
        SessionMode::Relay => {
            if input.relay_host.trim().is_empty() || input.relay_port == 0 {
                return Err("a relay host and port are required".into());
            }
            Some(EnrollmentToken::decode(&input.enrollment_token)?)
        }
        SessionMode::Direct => None,
    };
    let client_id = enrollment
        .as_ref()
        .map(EnrollmentToken::material)
        .transpose()?
        .map(|(client_id, _)| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_id));
    let plan_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    Ok(json!({
        "planId": plan_id,
        "mode": input.mode.as_str(),
        "routeCount": input.route_ids.len(),
        "trafficMode": input.traffic_mode,
        "interception": interception,
        "relay": enrollment.as_ref().map(|_| json!({
            "host": input.relay_host,
            "port": input.relay_port,
        })),
        "clientId": client_id,
        "virtualIpv4": enrollment.map(|enrollment| enrollment.virtual_ipv4),
        "state": "prepared",
    }))
}

fn scheduler_demo() -> Value {
    let mut first = PathMetrics::new("route-1");
    let mut second = PathMetrics::new("route-2");
    first.record_probe(42.0);
    second.record_probe(56.0);
    let decision: Decision = choose_paths(&[first, second], Strategy::Adaptive);
    json!({ "decision": decision })
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn latency_watch_reports_a_sustained_small_step_once_then_recovers_once() {
        let mut watch = LatencyWatch::default();
        let started = Instant::now();
        for offset in 0..LATENCY_BASELINE_SAMPLES {
            assert_eq!(
                watch.observe(105.0, started + Duration::from_millis(offset)),
                None
            );
        }
        assert_eq!(
            watch.observe(120.0, started + Duration::from_secs(1)),
            None,
            "one modest sample is not an incident"
        );
        assert!(matches!(
            watch.observe(121.0, started + Duration::from_secs(2)),
            Some(LatencyEvent::Degraded { .. })
        ));
        assert_eq!(
            watch.observe(123.0, started + Duration::from_secs(3)),
            None,
            "an active incident must not log every sample"
        );
        for second in 4..4 + u64::from(LATENCY_RECOVERY_SAMPLES) - 1 {
            assert_eq!(
                watch.observe(106.0, started + Duration::from_secs(second)),
                None
            );
        }
        assert!(matches!(
            watch.observe(106.0, started + Duration::from_secs(6)),
            Some(LatencyEvent::Recovered { peak_ms, .. }) if peak_ms == 123.0
        ));
    }

    #[test]
    fn latency_watch_reports_one_severe_spike_immediately() {
        let mut watch = LatencyWatch::default();
        let now = Instant::now();
        for offset in 0..LATENCY_BASELINE_SAMPLES {
            assert_eq!(
                watch.observe(50.0, now + Duration::from_millis(offset)),
                None
            );
        }
        assert!(matches!(
            watch.observe(120.0, now + Duration::from_secs(1)),
            Some(LatencyEvent::Degraded { .. })
        ));
    }

    fn queued(frame: Vec<u8>, age: Duration) -> PathCommand {
        PathCommand {
            frame,
            queued_at: Instant::now() - age,
        }
    }

    #[test]
    fn a_worker_sends_a_bounded_batch_and_leaves_the_rest_queued() {
        let (sender, receiver) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let depth = vec![AtomicU64::new(0)];
        let dropped = vec![AtomicU64::new(0)];
        let stale = vec![AtomicU64::new(0)];
        for _ in 0..PATH_SEND_BATCH * 2 {
            sender
                .try_send(queued(vec![0; 64], Duration::ZERO))
                .unwrap();
            depth[0].fetch_add(1, Ordering::Relaxed);
        }
        let mut sent = 0;
        drain_send_queue(
            &receiver,
            0,
            &depth,
            &dropped,
            &stale,
            |frame| (frame.len(), Ok(())),
            |_, _| sent += 1,
        );
        // The point is that the loop gets back to inbound frames and probes
        // rather than emptying a burst first.
        assert_eq!(sent, PATH_SEND_BATCH);
        assert_eq!(depth[0].load(Ordering::Relaxed) as usize, PATH_SEND_BATCH);
        assert_eq!(dropped[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_packet_that_waited_too_long_is_dropped_rather_than_sent_late() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let depth = vec![AtomicU64::new(2)];
        let dropped = vec![AtomicU64::new(0)];
        let stale = vec![AtomicU64::new(0)];
        sender
            .try_send(queued(vec![1; 64], PATH_QUEUE_MAX_AGE * 2))
            .unwrap();
        sender
            .try_send(queued(vec![2; 64], Duration::ZERO))
            .unwrap();
        let mut sent = Vec::new();
        drain_send_queue(
            &receiver,
            0,
            &depth,
            &dropped,
            &stale,
            |frame| (frame.len(), Ok(())),
            |length, _| sent.push(length),
        );
        assert_eq!(sent, [64]);
        assert_eq!(dropped[0].load(Ordering::Relaxed), 1);
        assert_eq!(stale[0].load(Ordering::Relaxed), 1);
        assert_eq!(depth[0].load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_saturated_queue_sheds_packets_instead_of_growing() {
        let (sender, _receiver) = mpsc::sync_channel::<PathCommand>(2);
        assert!(sender.try_send(queued(vec![0; 8], Duration::ZERO)).is_ok());
        assert!(sender.try_send(queued(vec![0; 8], Duration::ZERO)).is_ok());
        assert!(matches!(
            sender.try_send(queued(vec![0; 8], Duration::ZERO)),
            Err(mpsc::TrySendError::Full(_))
        ));
    }

    /// A redial is worth making only when something proves the uplink works.
    /// Two independent providers do not fail in the same second, so when no
    /// path is up the machine's own link is the cause and redialling each path
    /// separately just burns handshakes over a link that cannot carry them.
    /// A single lost probe is ordinary on a real network. Acting on it took a
    /// healthy WireGuard route out of service roughly once every ninety seconds
    /// and reported it as a disconnect.
    #[test]
    fn one_lost_probe_does_not_take_a_path_out_of_service() {
        let mask = AtomicU64::new(0);
        publish_path_health(&mask, 0, true);
        // What the worker does on each consecutive timeout: it stays up until
        // the threshold is reached, then goes down and stays down.
        let expected: Vec<bool> = (1..=HEALTH_FAILURE_THRESHOLD + 1)
            .map(|failures| failures < HEALTH_FAILURE_THRESHOLD)
            .collect();
        let mut failures = 0_u32;
        for expected_up in expected {
            failures += 1;
            if failures >= HEALTH_FAILURE_THRESHOLD {
                publish_path_health(&mask, 0, false);
            }
            assert_eq!(
                mask.load(Ordering::Acquire) & 1 != 0,
                expected_up,
                "after {failures} consecutive lost probe(s)"
            );
        }
    }

    /// Detection has to be quick enough to matter in a game. The deadline is
    /// the path's own, so this is what the threshold actually costs on a
    /// healthy route rather than on the old worst-case constant.
    #[test]
    fn a_dead_path_on_a_fast_route_is_noticed_within_a_second() {
        // A settled 60 ms route sits at the estimator's floor, and a missed
        // probe drops the gap to the degraded interval.
        let cycle = gamepath_engine::rtt::MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let detection = cycle * HEALTH_FAILURE_THRESHOLD;
        assert!(
            detection <= Duration::from_secs(2),
            "a dead path would take {detection:?} to notice"
        );
    }

    /// Even a path slow enough to sit at the ceiling has to resolve in seconds.
    #[test]
    fn a_dead_path_on_the_slowest_route_still_resolves_in_seconds() {
        let cycle = gamepath_engine::rtt::MAX_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let detection = cycle * HEALTH_FAILURE_THRESHOLD;
        assert!(
            detection <= Duration::from_secs(6),
            "the worst case is {detection:?}"
        );
    }

    /// A stream-carried path waits out one retransmission before calling a
    /// probe lost, so it is slower to declare dead. That is the point, but it
    /// still has to land inside a few seconds.
    #[test]
    fn a_dead_stream_path_costs_more_to_notice_but_still_resolves() {
        let cycle = gamepath_engine::rtt::STREAMED_MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED;
        let detection = cycle * HEALTH_FAILURE_THRESHOLD;
        assert!(
            detection > gamepath_engine::rtt::MIN_TIMEOUT * HEALTH_FAILURE_THRESHOLD,
            "the whole point is that it waits longer"
        );
        assert!(
            detection <= Duration::from_secs(4),
            "a dead stream path would take {detection:?} to notice"
        );
    }

    /// Raising the threshold only pays for itself because the deadline shrank.
    /// If someone puts the constant back, this says why that is not free.
    #[test]
    fn the_threshold_is_affordable_because_the_deadline_adapts() {
        let adaptive = (gamepath_engine::rtt::MIN_TIMEOUT + PROBE_INTERVAL_DEGRADED)
            * HEALTH_FAILURE_THRESHOLD;
        let fixed = (Duration::from_millis(1500) + PROBE_INTERVAL) * HEALTH_FAILURE_THRESHOLD;
        assert!(
            adaptive * 4 < fixed,
            "the adaptive deadline should be far cheaper: {adaptive:?} vs {fixed:?}"
        );
    }

    /// The monitor answers directly where it can, and the old inference is
    /// kept only for where it cannot.
    #[test]
    fn a_measured_uplink_overrides_the_inference_in_both_directions() {
        let decide = |state: UplinkState, route_count: usize, others_up: bool| match state {
            UplinkState::Down => true,
            UplinkState::Up => false,
            UplinkState::Unknown => route_count > 1 && !others_up,
        };
        // Measured down: no redial, even though another path looks up.
        assert!(decide(UplinkState::Down, 2, true));
        // Measured up: redial, even though nothing else is up. This is the case
        // the inference could never get right, and the only case for a
        // single-path session.
        assert!(!decide(UplinkState::Up, 1, false));
        assert!(!decide(UplinkState::Up, 2, false));
        // No opinion: exactly the previous behaviour.
        assert!(decide(UplinkState::Unknown, 2, false));
        assert!(!decide(UplinkState::Unknown, 2, true));
        assert!(!decide(UplinkState::Unknown, 1, false));
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

    #[test]
    fn the_health_mask_tracks_each_path_independently() {
        let mask = AtomicU64::new(0);
        publish_path_health(&mask, 0, true);
        publish_path_health(&mask, 2, true);
        assert_eq!(mask.load(Ordering::Acquire), 0b101);
        publish_path_health(&mask, 0, false);
        assert_eq!(mask.load(Ordering::Acquire), 0b100);
        // Out of range is ignored rather than corrupting the mask.
        publish_path_health(&mask, 64, true);
        assert_eq!(mask.load(Ordering::Acquire), 0b100);
    }

    #[test]
    fn a_dead_route_is_left_out_of_the_pick_but_never_leaves_it_empty() {
        // Two routes picked, only the second one up.
        assert_eq!(selected_paths(0b11, 0b10), 0b10);
        // Nothing reported healthy yet: the scheduler's pick still stands, so
        // the first packets of a session are not dropped while probes fly.
        assert_eq!(selected_paths(0b11, 0b00), 0b11);
        // A stale pick must not blackhole packets while another route is up.
        assert_eq!(selected_paths(0b01, 0b10), 0b10);
        assert_eq!(selected_paths(0b11, 0b11), 0b11);
    }

    #[test]
    fn openvpn_failure_and_recovery_keep_the_other_route_available() {
        let healthy = AtomicU64::new(0b11);
        let stale_openvpn_pick = 0b10;
        publish_path_health(&healthy, 1, false);
        // The scheduler has not republished yet. WireGuard must carry traffic
        // immediately, without waiting for another probe or reconnect.
        assert_eq!(
            selected_paths(stale_openvpn_pick, healthy.load(Ordering::Acquire)),
            0b01
        );
        publish_path_health(&healthy, 1, true);
        // Recovery allows both routes to carry copies again.
        assert_eq!(selected_paths(0b11, healthy.load(Ordering::Acquire)), 0b11);
        publish_path_health(&healthy, 0, false);
        assert_eq!(selected_paths(0b01, healthy.load(Ordering::Acquire)), 0b10);
    }

    #[test]
    fn dispatch_never_chooses_a_dead_route_when_a_healthy_route_exists() {
        // Cover every scheduler/health snapshot for four independent routes,
        // including an empty scheduler pick during initialization.
        for decision in 0_u64..16 {
            for healthy in 1_u64..16 {
                let selected = selected_paths(decision, healthy);
                assert_ne!(selected, 0);
                assert_eq!(selected & !healthy, 0);
            }
        }
    }

    #[test]
    fn only_a_globally_routable_address_counts_as_ipv6_exposure() {
        use std::net::Ipv6Addr;
        assert!(is_globally_routable_ipv6(
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_globally_routable_ipv6(Ipv6Addr::LOCALHOST));
        assert!(!is_globally_routable_ipv6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_globally_routable_ipv6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_globally_routable_ipv6(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        ));
    }

    #[test]
    fn ipv6_is_always_reported_as_uncarried() {
        let exposure = ipv6_exposure();
        assert_eq!(exposure["carried"], json!(false));
        assert!(exposure["systemHasRoute"].is_boolean());
    }

    fn session_request(payload: Value) -> SessionRequest {
        serde_json::from_value(payload).unwrap()
    }

    #[test]
    fn a_tagged_node_list_keeps_its_order_and_kinds() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "nodes": [
                { "kind": "wireguard", "config": "[Interface]", "label": "Provider A" },
                { "kind": "socks5", "host": "127.0.0.1", "port": 2080, "label": "Local proxy" },
                { "kind": "socks5", "host": "proxy.example", "port": 1080,
                  "username": "player", "password": "secret" },
            ],
        }));
        let nodes = request.resolved_nodes();
        assert_eq!(nodes.len(), 3);
        assert!(matches!(nodes[0], NodeSpec::WireGuard { .. }));
        assert_eq!(nodes[0].label().as_deref(), Some("Provider A"));
        assert_eq!(nodes[1].label().as_deref(), Some("Local proxy"));
        assert_eq!(nodes[1].describe(), "SOCKS5 proxy 127.0.0.1:2080");
        assert_eq!(nodes[2].label(), None);
        assert_eq!(nodes[2].default_label(3), "SOCKS5 route 3");
        assert!(matches!(
            &nodes[2],
            NodeSpec::Socks5 { username, password, .. }
                if username.as_deref() == Some("player") && password.as_deref() == Some("secret")
        ));
    }

    #[test]
    fn a_wireguard_only_request_still_works_without_the_node_list() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "wireguardConfigs": ["[Interface] one", "[Interface] two"],
            "routeLabels": ["Falcon", "  "],
        }));
        let nodes = request.resolved_nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].label().as_deref(), Some("Falcon"));
        // A blank label falls back to the generated route name.
        assert_eq!(nodes[1].label(), None);
        assert_eq!(nodes[1].default_label(2), "WireGuard route 2");
    }

    #[test]
    fn a_request_without_a_mode_still_means_a_relay_session() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "wireguardConfigs": ["[Interface] one"],
        }));
        assert_eq!(request.mode, SessionMode::Relay);
        assert_eq!(request.strategy, Strategy::Adaptive);
    }

    #[test]
    fn a_manual_request_keeps_all_healthy_paths_enabled() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "strategy": "all-paths",
            "wireguardConfigs": ["[Interface] one"],
        }));
        assert_eq!(request.strategy, Strategy::AllPaths);
    }

    #[test]
    fn a_direct_request_carries_no_relay_details() {
        let request = session_request(json!({
            "mode": "direct",
            "nodes": [{ "kind": "wireguard", "config": "[Interface]", "label": "Provider A" }],
        }));
        assert_eq!(request.mode, SessionMode::Direct);
        assert_eq!(request.mode.as_str(), "direct");
        assert!(request.relay_host.is_empty());
        assert_eq!(request.relay_port, 0);
        assert!(request.enrollment_token.is_empty());
        assert_eq!(request.resolved_nodes().len(), 1);
    }

    /// A WireGuard peer that answers ICMP echoes through the tunnel, and stops
    /// answering anything once `alive` is cleared — a node going down.
    fn spawn_echoing_peer(
        server_secret: [u8; 32],
        client_public: [u8; 32],
        alive: Arc<AtomicBool>,
    ) -> u16 {
        use boringtun::noise::{Tunn, TunnResult};
        use boringtun::x25519::{PublicKey, StaticSecret};

        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        thread::spawn(move || {
            let mut tunnel = Tunn::new(
                StaticSecret::from(server_secret),
                PublicKey::from(client_public),
                None,
                None,
                1,
                None,
            );
            let mut network = [0_u8; 65_535];
            let mut scratch = vec![0_u8; 65_535];
            while alive.load(Ordering::Acquire) {
                let Ok((length, from)) = socket.recv_from(&mut network) else {
                    continue;
                };
                let mut input: &[u8] = &network[..length];
                loop {
                    match tunnel.decapsulate(None, input, &mut scratch) {
                        TunnResult::WriteToNetwork(packet) => {
                            let _ = socket.send_to(packet, from);
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            let request = packet.to_vec();
                            let (source, destination) =
                                (request[12..16].to_vec(), request[16..20].to_vec());
                            let identifier = u16::from_be_bytes([request[24], request[25]]);
                            let sequence = u16::from_be_bytes([request[26], request[27]]);
                            let echo = icmp_echo_packet(
                                std::net::Ipv4Addr::new(
                                    destination[0],
                                    destination[1],
                                    destination[2],
                                    destination[3],
                                ),
                                std::net::Ipv4Addr::new(source[0], source[1], source[2], source[3]),
                                identifier,
                                sequence,
                                true,
                            );
                            let mut out = vec![0_u8; echo.len() + 128];
                            if let TunnResult::WriteToNetwork(sealed) =
                                tunnel.encapsulate(&echo, &mut out)
                            {
                                let _ = socket.send_to(sealed, from);
                            }
                            break;
                        }
                        _ => break,
                    }
                    input = &[];
                }
            }
        });
        port
    }

    fn wait_for(
        statuses: &Arc<Mutex<Vec<PathSessionStatus>>>,
        limit: Duration,
        ready: impl Fn(&PathSessionStatus) -> bool,
    ) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if ready(&statuses.lock().unwrap()[0]) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn a_direct_node_that_stops_answering_stops_reporting_itself_healthy() {
        use base64::engine::general_purpose::STANDARD;
        use boringtun::x25519::{PublicKey, StaticSecret};

        let (client_secret, server_secret) = ([11_u8; 32], [13_u8; 32]);
        let client_public = *PublicKey::from(&StaticSecret::from(client_secret)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_secret)).as_bytes();
        let alive = Arc::new(AtomicBool::new(true));
        let port = spawn_echoing_peer(server_secret, client_public, Arc::clone(&alive));
        let address = std::net::Ipv4Addr::new(10, 66, 66, 2);
        let config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {address}/32\n[Peer]\nPublicKey = {}\nEndpoint = 127.0.0.1:{port}\nAllowedIPs = 0.0.0.0/0",
            STANDARD.encode(client_secret),
            STANDARD.encode(server_public),
        );
        let path = NodeSpec::WireGuard {
            config,
            label: None,
        }
        .open_direct()
        .unwrap();

        let statuses = Arc::new(Mutex::new(vec![initial_status(
            1,
            KIND_WIREGUARD,
            "Provider A".into(),
            format!("127.0.0.1:{port}"),
        )]));
        let stop = Arc::new(AtomicBool::new(false));
        let (_commands, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let (inbound_tx, _inbound) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let telemetry = PathTelemetry {
            iterations: Arc::new(vec![AtomicU64::new(0)]),
            queue_depth: Arc::new(vec![AtomicU64::new(0)]),
            queue_peak: Arc::new(vec![AtomicU64::new(0)]),
            dropped: Arc::new(vec![AtomicU64::new(0)]),
            queue_full_dropped: Arc::new(vec![AtomicU64::new(0)]),
            stale_dropped: Arc::new(vec![AtomicU64::new(0)]),
            inbound_dropped: Arc::new(vec![AtomicU64::new(0)]),
            worker_gap_peak_ms: Arc::new(vec![AtomicU64::new(0)]),
            healthy_mask: Arc::new(AtomicU64::new(0)),
            uplink: Arc::new(UplinkMonitor::new()),
        };
        let worker = thread::spawn({
            let (stop, statuses) = (Arc::clone(&stop), Arc::clone(&statuses));
            move || {
                run_direct_path(
                    path,
                    address,
                    stop,
                    statuses,
                    command_rx,
                    inbound_tx,
                    Arc::new(Mutex::new(vec![PathMetrics::new("0".to_owned())])),
                    telemetry,
                    1,
                )
            }
        });

        assert!(
            wait_for(&statuses, Duration::from_secs(10), |status| {
                status.reachable && status.probes_received > 0
            }),
            "the node never came up: {:?}",
            statuses.lock().unwrap()[0].last_error
        );
        {
            let current = statuses.lock().unwrap();
            // Every answered probe is counted against one that was sent.
            assert!(current[0].probes_sent >= current[0].probes_received);
            assert!(current[0].handshake_ms.is_some());
            assert!(current[0].latency_ms.is_some());
            assert!(current[0].last_error.is_none());
        }

        // The node goes away. A completed handshake is not evidence that it is
        // still there, so the path has to notice and say so.
        alive.store(false, Ordering::Release);
        assert!(
            wait_for(&statuses, Duration::from_secs(20), |status| !status
                .reachable),
            "a node that stopped answering still reported itself healthy"
        );
        assert!(
            statuses.lock().unwrap()[0]
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("stopped answering")),
            "{:?}",
            statuses.lock().unwrap()[0].last_error
        );

        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

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
    fn prepare_plans_a_direct_session_without_relay_details() {
        let plan = prepare_session(json!({
            "mode": "direct",
            "routeIds": ["node-1"],
            "trafficMode": "split",
            "rules": [{ "kind": "application", "value": "C:\\Games\\game.exe" }],
        }))
        .unwrap();
        assert_eq!(plan["mode"], "direct");
        assert_eq!(plan["state"], "prepared");
        // Nothing relay-shaped is invented for a session that has no relay.
        assert!(plan["relay"].is_null());
        assert!(plan["clientId"].is_null());
        assert!(plan["virtualIpv4"].is_null());
        // The capture policy is still planned, and still has to compile.
        assert!(!plan["interception"].is_null());
        assert!(
            prepare_session(json!({
                "mode": "direct", "routeIds": ["node-1"], "trafficMode": "split", "rules": [],
            }))
            .is_err()
        );
    }

    #[test]
    fn prepare_rejects_no_routes() {
        let result = prepare_session(json!({
            "routeIds": [], "trafficMode": "all", "rules": [],
            "relayHost": "relay.example", "relayPort": 51821, "enrollmentToken": "bad"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn prepare_accepts_all_traffic_without_rules() {
        let enrollment = EnrollmentToken::generate("10.203.0.2".parse().unwrap())
            .encode()
            .unwrap();
        let result = prepare_session(json!({
            "routeIds": ["one", "two"], "trafficMode": "all", "rules": [],
            "relayHost": "relay.example", "relayPort": 51821, "enrollmentToken": enrollment
        }))
        .unwrap();
        assert_eq!(result["state"], "prepared");
    }

    #[test]
    fn icmp_probe_packet_has_valid_checksums() {
        let source = "10.203.0.1".parse().unwrap();
        let destination = "10.203.0.2".parse().unwrap();
        let packet = icmp_echo_packet(source, destination, 42, 1, true);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert!(is_matching_icmp_reply(&packet, source, destination, 42));
    }

    #[test]
    fn scheduler_mask_keeps_single_route_armed_after_loss() {
        let mut route = PathMetrics::new("0");
        route.record_probe(40.0);
        route.record_loss();
        assert_eq!(
            mask_for_decision(choose_paths(&[route], Strategy::Adaptive), 0b1),
            0b1
        );
    }

    #[test]
    fn scheduler_mask_keeps_two_healthy_routes_ready() {
        let mut slower = PathMetrics::new("0");
        slower.record_probe(70.0);
        let mut faster = PathMetrics::new("1");
        faster.record_probe(35.0);
        assert_eq!(
            mask_for_decision(choose_paths(&[slower, faster], Strategy::Adaptive), 0b11),
            0b11
        );
    }

    #[test]
    fn scheduler_mask_duplicates_degraded_routes() {
        let mut degraded = PathMetrics::new("0");
        degraded.record_probe(35.0);
        degraded.record_loss();
        let mut backup = PathMetrics::new("1");
        backup.record_probe(50.0);
        assert_eq!(
            mask_for_decision(choose_paths(&[degraded, backup], Strategy::Adaptive), 0b11),
            0b11
        );
    }

    #[test]
    fn scheduler_mask_falls_back_when_all_routes_are_unrated() {
        let routes = [PathMetrics::new("0"), PathMetrics::new("1")];
        assert_eq!(
            mask_for_decision(choose_paths(&routes, Strategy::Adaptive), 0b11),
            0b11
        );
    }
}
