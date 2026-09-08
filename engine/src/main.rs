use base64::Engine as _;
use gamepath_engine::adapter::inspect_library;
use gamepath_engine::auth::{EnrollmentToken, SessionCrypto};
use gamepath_engine::policy::{RuleSpec, compile as compile_policy};
use gamepath_engine::relay_path::{
    DirectPath, KIND_WIREGUARD, NodeSpec, RelayPath, SessionMode, Socks5RelayPath,
};
use gamepath_engine::scheduler::{Decision, PathMetrics, Strategy, choose_paths};
use gamepath_engine::socks5::{Socks5NodeConfig, Socks5UdpPath};
use gamepath_engine::timer::HighResolutionTimer;
use gamepath_engine::wfp::inspect_backend;
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
    node_latency_ms: Option<f64>,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    probes_sent: u64,
    probes_received: u64,
    probes_lost: u64,
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
    overlay: SessionOverlay,
    session_id: u64,
    started_at: u128,
    stop: Arc<AtomicBool>,
    paths: Arc<Mutex<Vec<PathSessionStatus>>>,
    workers: Vec<JoinHandle<()>>,
    skipped_routes: Vec<usize>,
    commands: Vec<mpsc::Sender<PathCommand>>,
    data_receiver: Arc<DataReceiver>,
    virtual_ipv4: std::net::Ipv4Addr,
    sequences: Arc<AtomicU64>,
    decision_mask: Arc<AtomicU64>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    path_worker_iterations: Arc<Vec<AtomicU64>>,
    bypass_ips: Vec<std::net::Ipv4Addr>,
    // Held for the session so the path workers wake on a millisecond timer
    // instead of Windows' default ~15.6 ms one.
    timer: HighResolutionTimer,
}

/// How the inbound queue's contents have to be unwrapped.
enum ReceiveMode {
    Relay {
        client_id: [u8; 16],
        session_id: u64,
        crypto: Arc<SessionCrypto>,
        server_replay: Mutex<SequenceWindow>,
    },
    /// The worker already checked that these packets came out of the tunnel
    /// addressed to us, and WireGuard already authenticated them.
    Direct,
}

pub(crate) struct DataReceiver {
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    mode: ReceiveMode,
}

impl DataReceiver {
    pub(crate) fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT};

        let response = match self.inbound.lock().unwrap().recv_timeout(timeout) {
            Ok(response) => response,
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("all path receivers stopped".into());
            }
        };
        let ReceiveMode::Relay {
            client_id,
            session_id,
            crypto,
            server_replay,
        } = &self.mode
        else {
            return Ok(Some(response));
        };
        let (header, plaintext) = crypto.open_server(&response)?;
        if header.client_id != *client_id
            || header.session_id != *session_id
            || header.flags & FLAG_SERVER_TO_CLIENT == 0
            || header.flags & FLAG_CONTROL != 0
            || !server_replay.lock().unwrap().accept(header.sequence)
        {
            return Ok(None);
        }
        Ok(Some(plaintext))
    }
}

#[derive(Default)]
struct SequenceWindow {
    highest: u64,
    bitmap: u64,
    initialized: bool,
}

impl SequenceWindow {
    fn accept(&mut self, sequence: u64) -> bool {
        if !self.initialized {
            self.highest = sequence;
            self.bitmap = 1;
            self.initialized = true;
            return true;
        }
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
            return true;
        }
        let age = self.highest - sequence;
        if age >= 64 || self.bitmap & (1_u64 << age) != 0 {
            return false;
        }
        self.bitmap |= 1_u64 << age;
        true
    }
}

struct PathCommand {
    frame: Vec<u8>,
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
            return Err("at least one WireGuard or SOCKS5 node is required".into());
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
        let mut paths: Vec<(usize, String, Box<dyn RelayPath>)> = Vec::new();
        let mut skipped_routes = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let route = index + 1;
            // A SOCKS5 node dials its proxy here, so name the failing node.
            let path = node
                .open(relay)
                .map_err(|error| format!("route {route} ({}): {error}", node.describe()))?;
            if paths
                .iter()
                .any(|(_, _, current)| current.identity() == path.identity())
            {
                skipped_routes.push(route);
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
            paths.push((route, label, path));
        }
        let mut bypass_ips = vec![relay_ip];
        bypass_ips.extend(paths.iter().filter_map(|(_, _, path)| path.bypass_ipv4()));
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
            .map(|(route, label, path)| {
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
        let path_worker_iterations = Arc::new(
            (0..route_count)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>(),
        );
        let mut workers = Vec::with_capacity(route_count);
        let mut commands = Vec::with_capacity(route_count);
        let (inbound_tx, inbound_rx) = mpsc::channel();
        for (index, (_, _, path)) in paths.into_iter().enumerate() {
            let status_index = index;
            let (command_tx, command_rx) = mpsc::channel();
            commands.push(command_tx);
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
            let worker_inbound = inbound_tx.clone();
            let worker_metrics = Arc::clone(&scheduler_metrics);
            let worker_decision = Arc::clone(&decision_mask);
            let worker_iterations = Arc::clone(&path_worker_iterations);
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
                            worker_metrics,
                            worker_decision,
                            initial_mask,
                            worker_iterations,
                        )
                    })
                    .map_err(|error| format!("could not start path worker: {error}"))?,
            );
        }
        let data_receiver = Arc::new(DataReceiver {
            inbound: Mutex::new(inbound_rx),
            mode: ReceiveMode::Relay {
                client_id,
                session_id,
                crypto: Arc::clone(&crypto),
                server_replay: Mutex::new(SequenceWindow::default()),
            },
        });
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Relay,
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
            scheduler_metrics,
            path_worker_iterations,
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
                 Enable a single WireGuard node, or switch to relay mode to combine them.",
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
        let statuses = Arc::new(Mutex::new(vec![initial_status(1, kind, label, endpoint)]));
        let scheduler_metrics = Arc::new(Mutex::new(vec![PathMetrics::new("0".to_owned())]));
        let path_worker_iterations = Arc::new(vec![AtomicU64::new(0)]);
        let (command_tx, command_rx) = mpsc::channel();
        let (inbound_tx, inbound_rx) = mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        let worker_statuses = Arc::clone(&statuses);
        let worker_metrics = Arc::clone(&scheduler_metrics);
        let worker_iterations = Arc::clone(&path_worker_iterations);
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
                    worker_iterations,
                )
            })
            .map_err(|error| format!("could not start path worker: {error}"))?;
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Direct,
            overlay: SessionOverlay::Direct,
            session_id: rand::random::<u64>(),
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers: vec![worker],
            skipped_routes: Vec::new(),
            commands: vec![command_tx],
            data_receiver: Arc::new(DataReceiver {
                inbound: Mutex::new(inbound_rx),
                mode: ReceiveMode::Direct,
            }),
            virtual_ipv4,
            sequences: Arc::new(AtomicU64::new(1)),
            // One path, always selected: there is nothing to schedule between.
            decision_mask: Arc::new(AtomicU64::new(1)),
            scheduler_metrics,
            path_worker_iterations,
            bypass_ips,
            timer,
        });
        Ok(())
    }

    /// Holds until every path reports itself usable, so traffic is never
    /// captured into a session that cannot carry it yet.
    fn wait_until_ready(&mut self) -> Result<Value, String> {
        let deadline = Instant::now() + Duration::from_secs(12);
        while Instant::now() < deadline {
            if self.all_paths_reachable() {
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
        let benchmark_server = std::net::Ipv4Addr::new(1, 1, 1, 1);
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
        Ok(json!({
            "reachable": true,
            "latencyMs": end_to_end,
            "userToRelayMs": user_to_relay,
            "relayToServerMs": (end_to_end - user_to_relay).max(0.0),
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
        let mut dispatched = 0;
        let decision = session.decision_mask.load(Ordering::Acquire);
        for (index, sender) in session.commands.iter().enumerate() {
            let bit = 1_u64.checked_shl(index as u32).unwrap_or(0);
            if decision & bit == 0 {
                continue;
            }
            if sender
                .send(PathCommand {
                    frame: frame.clone(),
                })
                .is_ok()
            {
                dispatched += 1;
            }
        }
        if dispatched == 0 {
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

    fn status(&self) -> Value {
        let Some(session) = &self.active else {
            return json!({ "state": "idle", "paths": [] });
        };
        let paths = session.paths.lock().unwrap().clone();
        let decision = session.decision_mask.load(Ordering::Acquire);
        let selected_routes = paths
            .iter()
            .enumerate()
            .filter(|(index, _)| decision & 1_u64.checked_shl(*index as u32).unwrap_or(0) != 0)
            .map(|(_, path)| path.route)
            .collect::<Vec<_>>();
        let scheduler_metrics = session.scheduler_metrics.lock().unwrap().clone();
        let path_worker_iterations = session
            .path_worker_iterations
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
                SessionMode::Relay => "adaptive",
                // One path cannot be scheduled between, so nothing is chosen.
                SessionMode::Direct => "single-path",
            },
            "selectedRoutes": selected_routes,
            "schedulerMetrics": scheduler_metrics,
            "pathWorkerIterations": path_worker_iterations,
            "highResolutionTimer": session.timer.active(),
        })
    }

    fn stop(&mut self) -> Value {
        let Some(mut session) = self.active.take() else {
            return json!({ "state": "idle", "paths": [] });
        };
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
        self.stop();
        let (virtual_ipv4, bypass_ips, data_receiver) = {
            let manager = sessions.lock().unwrap();
            (
                manager
                    .virtual_ipv4()
                    .ok_or("start the multipath session before packet capture")?,
                manager.bypass_ips(),
                manager
                    .data_receiver()
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
            )?;
            let target_count = split.target_count();
            self.active_split = Some(split);
            return Ok(json!({
                "state": "capturing",
                "backend": "windivert",
                "trafficMode": "split",
                "targetCount": target_count,
            }));
        }
        if input.traffic_mode != "all" {
            return Err("traffic mode must be all or split".into());
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
                    Some(0x7f0a_9828_52ef_4ddd_913d_c11ff0d4a58a_u128),
                )
            })
            .map_err(|error| format!("could not create GamePath adapter: {error}"))?;
        let adapter_index = adapter
            .get_adapter_index()
            .map_err(|error| format!("could not read GamePath adapter index: {error}"))?;
        configure_tunnel_interface(adapter_index)?;
        adapter
            .set_network_addresses_tuple(
                virtual_ipv4.into(),
                std::net::Ipv4Addr::new(255, 255, 255, 0).into(),
                None,
            )
            .map_err(|error| format!("could not configure GamePath adapter: {error}"))?;
        adapter
            .set_mtu(1380)
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
fn configure_tunnel_interface(interface_index: u32) -> Result<(), String> {
    let script = format!(
        "Set-NetIPInterface -InterfaceIndex {interface_index} -AddressFamily IPv4 -DadTransmits 0 -AutomaticMetric Disabled -InterfaceMetric 5 -NlMtuBytes 1380 -ErrorAction Stop"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|error| format!("could not configure GamePath interface: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "could not configure GamePath interface: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
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
        node_latency_ms: None,
        packets_sent: 0,
        packets_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
        probes_sent: 0,
        probes_received: 0,
        probes_lost: 0,
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
/// Where a direct session's latency probe is aimed. A public resolver that
/// answers echo requests, reached through the node like any game server.
const DIRECT_PROBE_TARGET: std::net::Ipv4Addr = std::net::Ipv4Addr::new(1, 1, 1, 1);

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
    inbound: mpsc::Sender<Vec<u8>>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    worker_iterations: Arc<Vec<AtomicU64>>,
) {
    let identifier = rand::random::<u16>();
    let mut probe_sequence = 0_u16;
    let mut next_probe = Instant::now();
    let mut pending_probe: Option<Instant> = None;
    let mut probes_attempted = 0_u64;
    let mut consecutive_losses = 0_u64;
    let mut icmp_answered = false;
    let mut probing = true;
    let mut published_health = (None, false);
    let mut published_error = false;
    // Set once this worker has a specific answer for why the node is not
    // usable. Transport errors are noisier and less useful than that answer,
    // so they stop overwriting it.
    let mut verdict = false;
    let started = Instant::now();
    let mut reported_silence = false;
    let endpoint = path.endpoint();

    while !stop.load(Ordering::Acquire) {
        worker_iterations[0].fetch_add(1, Ordering::Relaxed);
        // Health is decided first so the rest of the iteration can see it, and
        // published only when it moves: this lock is on the hot path.
        let handshake = path.handshake_latency_ms();
        let losing = icmp_answered && consecutive_losses >= DIRECT_LOSS_LIMIT;
        let reachable = handshake.is_some() && !losing;
        if (handshake, reachable) != published_health {
            let mut current = statuses.lock().unwrap();
            current[0].reachable = reachable;
            current[0].node_latency_ms = handshake;
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
        while let Ok(command) = commands.try_recv() {
            let length = command.frame.len();
            let result = path.send_packet(&command.frame);
            record_path_send(&statuses, 0, length, result);
        }
        if probing && pending_probe.is_none() && Instant::now() >= next_probe {
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
            next_probe = Instant::now() + Duration::from_millis(500);
        }
        match path.receive_packets(Duration::from_millis(1)) {
            Ok(packets) => {
                for packet in packets {
                    if is_matching_icmp_reply(&packet, DIRECT_PROBE_TARGET, address, identifier) {
                        let Some(started) = pending_probe.take() else {
                            continue;
                        };
                        let latency = started.elapsed().as_secs_f64() * 1000.0;
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
                        continue;
                    }
                    record_path_receive(&statuses, 0, packet.len());
                    let _ = inbound.send(packet);
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
        if pending_probe.is_some_and(|started| started.elapsed() > Duration::from_millis(1500)) {
            pending_probe = None;
            if icmp_answered {
                consecutive_losses += 1;
                statuses.lock().unwrap()[0].probes_lost += 1;
                scheduler_metrics.lock().unwrap()[0].record_loss();
            } else if probes_attempted >= DIRECT_PROBE_ATTEMPTS {
                // Never answered once: this node does not carry ICMP, which
                // says nothing about the traffic it does carry.
                probing = false;
            }
        }
    }
}

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
    inbound: mpsc::Sender<Vec<u8>>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    decision_mask: Arc<AtomicU64>,
    fallback_mask: u64,
    worker_iterations: Arc<Vec<AtomicU64>>,
) {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};

    let Ok(crypto) = SessionCrypto::new(&key, session_id) else {
        return;
    };
    let mut next_probe = Instant::now();
    let mut pending_probe = None;
    let mut published_setup_latency = None;
    while !stop.load(Ordering::Acquire) {
        worker_iterations[index].fetch_add(1, Ordering::Relaxed);
        while let Ok(command) = commands.try_recv() {
            let result = path.send_frame(&command.frame);
            record_path_send(&statuses, index, command.frame.len(), result);
        }
        if Instant::now() >= next_probe && pending_probe.is_none() {
            let sequence = sequences.fetch_add(1, Ordering::Relaxed);
            let result = (|| {
                let header = FrameHeader {
                    flags: FLAG_CONTROL,
                    client_id,
                    session_id,
                    sequence,
                };
                let overlay = crypto.seal_client(header, b"ping")?;
                {
                    let mut current = statuses.lock().unwrap();
                    current[index].packets_sent += 1;
                    current[index].probes_sent += 1;
                }
                path.send_frame(&overlay)
            })();
            match result {
                Ok(()) => pending_probe = Some(Instant::now()),
                Err(error) => {
                    statuses.lock().unwrap()[index].probes_lost += 1;
                    update_scheduler_probe(
                        &scheduler_metrics,
                        &decision_mask,
                        fallback_mask,
                        index,
                        None,
                    );
                    update_path_status(&statuses, index, Err(error));
                    next_probe = Instant::now() + Duration::from_millis(500);
                }
            }
        }
        match path.receive_frames(Duration::from_millis(1)) {
            Ok(frames) => {
                for frame in frames {
                    if let Ok((header, plaintext)) = crypto.open_server(&frame) {
                        if header.flags & FLAG_CONTROL != 0 && plaintext == b"pong" {
                            if let Some(started) = pending_probe.take() {
                                let latency = started.elapsed().as_secs_f64() * 1000.0;
                                statuses.lock().unwrap()[index].probes_received += 1;
                                update_path_status(&statuses, index, Ok(latency));
                                update_scheduler_probe(
                                    &scheduler_metrics,
                                    &decision_mask,
                                    fallback_mask,
                                    index,
                                    Some(latency),
                                );
                                next_probe = Instant::now() + Duration::from_millis(500);
                            }
                        } else if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
                            record_path_receive(&statuses, index, frame.len());
                            let _ = inbound.send(frame);
                        }
                    }
                }
            }
            Err(error) => update_path_status(&statuses, index, Err(error)),
        }
        // Setup latency is fixed once a path is up, and this lock is shared by
        // every path worker, so it is taken only when the value actually moves.
        let setup_latency = path.setup_latency_ms();
        if setup_latency != published_setup_latency {
            statuses.lock().unwrap()[index].node_latency_ms = setup_latency;
            published_setup_latency = setup_latency;
        }
        if pending_probe.is_some_and(|started| started.elapsed() > Duration::from_millis(1500)) {
            pending_probe = None;
            statuses.lock().unwrap()[index].probes_lost += 1;
            update_scheduler_probe(
                &scheduler_metrics,
                &decision_mask,
                fallback_mask,
                index,
                None,
            );
            let note = path.health_note();
            update_path_status(
                &statuses,
                index,
                Err(match note {
                    Some(note) => format!("path health check timed out: {note}"),
                    None => "path health check timed out".to_owned(),
                }),
            );
            next_probe = Instant::now() + Duration::from_millis(500);
        }
    }
}

fn update_scheduler_probe(
    metrics: &Mutex<Vec<PathMetrics>>,
    decision_mask: &AtomicU64,
    fallback_mask: u64,
    index: usize,
    latency_ms: Option<f64>,
) {
    let mut metrics = metrics.lock().unwrap();
    let Some(path) = metrics.get_mut(index) else {
        return;
    };
    match latency_ms {
        Some(latency) => path.record_probe(latency),
        None => path.record_loss(),
    }
    let decision = choose_paths(&metrics, Strategy::Adaptive);
    decision_mask.store(
        mask_for_decision(decision, fallback_mask),
        Ordering::Release,
    );
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
        let (_commands, command_rx) = mpsc::channel();
        let (inbound_tx, _inbound) = mpsc::channel();
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
                    Arc::new(vec![AtomicU64::new(0)]),
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
            assert!(current[0].node_latency_ms.is_some());
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
        assert!(error.contains("single WireGuard node"), "{error}");
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
    fn scheduler_mask_selects_the_best_healthy_route() {
        let mut slower = PathMetrics::new("0");
        slower.record_probe(70.0);
        let mut faster = PathMetrics::new("1");
        faster.record_probe(35.0);
        assert_eq!(
            mask_for_decision(choose_paths(&[slower, faster], Strategy::Adaptive), 0b11),
            0b10
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
