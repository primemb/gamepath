use base64::Engine as _;
use gamepath_engine::adapter::inspect_library;
use gamepath_engine::auth::EnrollmentToken;
use gamepath_engine::policy::{RuleSpec, compile as compile_policy};
use gamepath_engine::scheduler::{Decision, PathMetrics, Strategy, choose_paths};
use gamepath_engine::wfp::inspect_backend;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
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
    relay_host: String,
    relay_port: u16,
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

struct ActiveWireGuardSession {
    session_id: u64,
    started_at: u128,
    stop: Arc<AtomicBool>,
    paths: Arc<Mutex<Vec<PathSessionStatus>>>,
    workers: Vec<JoinHandle<()>>,
    skipped_routes: Vec<usize>,
    commands: Vec<mpsc::Sender<PathCommand>>,
    data_receiver: Arc<DataReceiver>,
    client_id: [u8; 16],
    key: [u8; 32],
    virtual_ipv4: std::net::Ipv4Addr,
    sequences: Arc<AtomicU64>,
    bypass_ips: Vec<std::net::Ipv4Addr>,
}

pub(crate) struct DataReceiver {
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    client_id: [u8; 16],
    key: [u8; 32],
    session_id: u64,
    server_replay: Mutex<SequenceWindow>,
}

impl DataReceiver {
    pub(crate) fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        use gamepath_engine::auth::SessionCrypto;
        use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT};

        let response = match self.inbound.lock().unwrap().recv_timeout(timeout) {
            Ok(response) => response,
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("all path receivers stopped".into());
            }
        };
        let crypto = SessionCrypto::new(&self.key, self.session_id)?;
        let (header, plaintext) = crypto.open_server(&response)?;
        if header.client_id != self.client_id
            || header.session_id != self.session_id
            || header.flags & FLAG_SERVER_TO_CLIENT == 0
            || header.flags & FLAG_CONTROL != 0
            || !self.server_replay.lock().unwrap().accept(header.sequence)
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
        use gamepath_engine::userspace_wireguard::UserSpaceWireGuardPath;

        let input: WireGuardProbeRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid WireGuard session: {error}"))?;
        if input.wireguard_configs.is_empty() {
            return Err("at least one WireGuard configuration is required".into());
        }
        let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
        let (client_id, key) = enrollment.material()?;
        let relay_ip = resolve_ipv4(&input.relay_host, input.relay_port)?;
        let parsed_paths = input
            .wireguard_configs
            .iter()
            .map(|source| UserSpaceWireGuardPath::from_config(source))
            .collect::<Result<Vec<_>, _>>()?;
        let mut paths = Vec::new();
        let mut skipped_routes = Vec::new();
        for (config_index, path) in parsed_paths.into_iter().enumerate() {
            if paths
                .iter()
                .any(|(_, current): &(usize, UserSpaceWireGuardPath)| path.conflicts_with(current))
            {
                skipped_routes.push(config_index + 1);
            } else {
                paths.push((config_index + 1, path));
            }
        }
        let mut bypass_ips = vec![relay_ip];
        bypass_ips.extend(
            paths
                .iter()
                .filter_map(|(_, path)| match path.endpoint().ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    std::net::IpAddr::V6(_) => None,
                }),
        );
        bypass_ips.sort_unstable();
        bypass_ips.dedup();

        self.stop();
        let session_id = rand::random::<u64>();
        let relay_port = input.relay_port;
        let stop = Arc::new(AtomicBool::new(false));
        let sequences = Arc::new(AtomicU64::new(1));
        let initial_statuses = paths
            .iter()
            .map(|(config_index, path)| PathSessionStatus {
                route: *config_index,
                path_kind: "wireguard".into(),
                label: format!("WireGuard route {config_index}"),
                endpoint: path.endpoint().to_string(),
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
            })
            .collect::<Vec<_>>();
        let statuses = Arc::new(Mutex::new(initial_statuses));
        let route_count = paths.len();
        let mut workers = Vec::with_capacity(route_count);
        let mut commands = Vec::with_capacity(route_count);
        let (inbound_tx, inbound_rx) = mpsc::channel();
        for (index, (_, path)) in paths.into_iter().enumerate() {
            let status_index = index;
            let (command_tx, command_rx) = mpsc::channel();
            commands.push(command_tx);
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
            let worker_inbound = inbound_tx.clone();
            workers.push(
                thread::Builder::new()
                    .name(format!("gamepath-wireguard-{}", index + 1))
                    .spawn(move || {
                        run_wireguard_path(
                            path,
                            status_index,
                            worker_sequences,
                            relay_ip,
                            relay_port,
                            client_id,
                            key,
                            session_id,
                            worker_stop,
                            worker_statuses,
                            command_rx,
                            worker_inbound,
                        )
                    })
                    .map_err(|error| format!("could not start WireGuard path worker: {error}"))?,
            );
        }
        let data_receiver = Arc::new(DataReceiver {
            inbound: Mutex::new(inbound_rx),
            client_id,
            key,
            session_id,
            server_replay: Mutex::new(SequenceWindow::default()),
        });
        self.active = Some(ActiveWireGuardSession {
            session_id,
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers,
            skipped_routes,
            commands,
            data_receiver,
            client_id,
            key,
            virtual_ipv4: enrollment.virtual_ipv4,
            sequences,
            bypass_ips,
        });

        let deadline = Instant::now() + Duration::from_secs(12);
        while Instant::now() < deadline {
            if self.all_paths_reachable() {
                return Ok(self.status());
            }
            thread::sleep(Duration::from_millis(100));
        }
        let detail = self
            .active
            .as_ref()
            .map(|session| {
                session
                    .paths
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|path| path.last_error.as_deref())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        self.stop();
        if detail.is_empty() {
            Err("WireGuard paths did not become ready before timeout".into())
        } else {
            Err(format!("WireGuard paths did not become ready: {detail}"))
        }
    }

    fn probe_data_plane(&mut self) -> Result<Value, String> {
        let virtual_ipv4 = self
            .active
            .as_ref()
            .ok_or("start the WireGuard session before probing its data plane")?
            .virtual_ipv4;
        let benchmark_server = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let identifier = rand::random::<u16>();
        let request = icmp_echo_packet(virtual_ipv4, benchmark_server, identifier, 1, false);
        let started = Instant::now();
        let reply = self.send_data_packet(&request)?;
        if !is_matching_icmp_reply(&reply, benchmark_server, virtual_ipv4, identifier) {
            return Err("relay data plane returned an unexpected packet".into());
        }
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

    fn send_data_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        self.enqueue_data_packet(packet)?;
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(packet) = self.receive_data_packet(remaining)? {
                return Ok(packet);
            }
        }
        Err("no path returned the relayed packet before timeout".into())
    }

    fn enqueue_data_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        use gamepath_engine::auth::SessionCrypto;
        use gamepath_engine::protocol::FrameHeader;

        let session = self
            .active
            .as_mut()
            .ok_or("start the WireGuard session before sending packets")?;
        if !session
            .paths
            .lock()
            .unwrap()
            .iter()
            .any(|path| path.reachable)
        {
            return Err("no relay path is currently reachable".into());
        }
        let sequence = session.sequences.fetch_add(1, Ordering::Relaxed);
        let header = FrameHeader {
            flags: 0,
            client_id: session.client_id,
            session_id: session.session_id,
            sequence,
        };
        let crypto = SessionCrypto::new(&session.key, session.session_id)?;
        let frame = crypto.seal_client(header, packet)?;
        let mut dispatched = 0;
        for sender in &session.commands {
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
        let state = if paths.iter().any(|path| path.reachable) {
            "connected"
        } else {
            "connecting"
        };
        json!({
            "state": state,
            "sessionId": session.session_id.to_string(),
            "startedAt": session.started_at,
            "paths": paths,
            "skippedRoutes": session.skipped_routes,
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
    worker: Option<JoinHandle<()>>,
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
        let worker_stop = Arc::clone(&stop);
        let worker_session = Arc::clone(&session);
        let worker = thread::Builder::new()
            .name("gamepath-wintun".into())
            .spawn(move || {
                run_wintun_pump(
                    worker_session,
                    sessions,
                    data_receiver,
                    virtual_ipv4,
                    worker_stop,
                )
            })
            .map_err(|error| format!("could not start Wintun packet pump: {error}"))?;

        let mut capture = WindowsPacketCapture {
            stop,
            session,
            worker: Some(worker),
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
        let tunnel_gateway = std::net::Ipv4Addr::new(10, 203, 0, 1);
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
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        for route in self.routes.iter().rev() {
            let _ = remove_ipv4_route(route);
        }
    }
}

#[cfg(windows)]
fn run_wintun_pump(
    session: Arc<wintun::Session>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    data_receiver: Arc<DataReceiver>,
    virtual_ipv4: std::net::Ipv4Addr,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        for _ in 0..128 {
            let packet = match session.try_receive() {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(_) => return,
            };
            let bytes = packet.bytes().to_vec();
            drop(packet);
            if ipv4_source_address(&bytes) == Some(virtual_ipv4) {
                let _ = sessions.lock().unwrap().enqueue_data_packet(&bytes);
            }
        }
        for _ in 0..128 {
            let reply = match data_receiver.receive(Duration::ZERO) {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
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
        thread::sleep(Duration::from_millis(1));
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
fn run_wireguard_path(
    mut path: gamepath_engine::userspace_wireguard::UserSpaceWireGuardPath,
    index: usize,
    sequences: Arc<AtomicU64>,
    relay_ip: std::net::Ipv4Addr,
    relay_port: u16,
    client_id: [u8; 16],
    key: [u8; 32],
    session_id: u64,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
    inbound: mpsc::Sender<Vec<u8>>,
) {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};
    use gamepath_engine::userspace_wireguard::{ipv4_udp_packet, ipv4_udp_payload};
    use rand::Rng;

    let Ok(crypto) = SessionCrypto::new(&key, session_id) else {
        return;
    };
    let source_port = rand::rng().random_range(49_152..=65_535);
    let mut next_probe = Instant::now();
    let mut pending_probe = None;
    while !stop.load(Ordering::Acquire) {
        while let Ok(command) = commands.try_recv() {
            let result = ipv4_udp_packet(
                path.address(),
                relay_ip,
                source_port,
                relay_port,
                &command.frame,
            )
            .and_then(|inner| path.send_inner(&inner));
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
                let inner =
                    ipv4_udp_packet(path.address(), relay_ip, source_port, relay_port, &overlay)?;
                {
                    let mut current = statuses.lock().unwrap();
                    current[index].packets_sent += 1;
                    current[index].probes_sent += 1;
                }
                path.send_inner(&inner)
            })();
            match result {
                Ok(()) => pending_probe = Some(Instant::now()),
                Err(error) => {
                    statuses.lock().unwrap()[index].probes_lost += 1;
                    update_path_status(&statuses, index, Err(error));
                    next_probe = Instant::now() + Duration::from_secs(1);
                }
            }
        }
        match path.receive_inner(Duration::from_millis(1)) {
            Ok(packets) => {
                for packet in packets {
                    let Some((
                        reply_source_ip,
                        reply_destination_ip,
                        reply_source_port,
                        reply_destination_port,
                        response_frame,
                    )) = ipv4_udp_payload(&packet)
                    else {
                        continue;
                    };
                    if reply_source_ip != relay_ip
                        || reply_destination_ip != path.address()
                        || reply_source_port != relay_port
                        || reply_destination_port != source_port
                    {
                        continue;
                    }
                    if let Ok((header, plaintext)) = crypto.open_server(response_frame) {
                        if header.flags & FLAG_CONTROL != 0 && plaintext == b"pong" {
                            if let Some(started) = pending_probe.take() {
                                statuses.lock().unwrap()[index].probes_received += 1;
                                update_path_status(
                                    &statuses,
                                    index,
                                    Ok(started.elapsed().as_secs_f64() * 1000.0),
                                );
                                next_probe = Instant::now() + Duration::from_secs(10);
                            }
                        } else if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
                            record_path_receive(&statuses, index, response_frame.len());
                            let _ = inbound.send(response_frame.to_vec());
                        }
                    }
                }
            }
            Err(error) => update_path_status(&statuses, index, Err(error)),
        }
        {
            let mut current = statuses.lock().unwrap();
            current[index].node_latency_ms = path.handshake_latency_ms();
        }
        if pending_probe.is_some_and(|started| started.elapsed() > Duration::from_secs(8)) {
            pending_probe = None;
            statuses.lock().unwrap()[index].probes_lost += 1;
            update_path_status(
                &statuses,
                index,
                Err("WireGuard path health check timed out".into()),
            );
            next_probe = Instant::now() + Duration::from_secs(1);
        }
    }
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
    if input.relay_host.trim().is_empty() || input.relay_port == 0 {
        return Err("a relay host and port are required".into());
    }
    let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
    let (client_id, _) = enrollment.material()?;
    let plan_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    Ok(json!({
        "planId": plan_id,
        "routeCount": input.route_ids.len(),
        "trafficMode": input.traffic_mode,
        "interception": interception,
        "relay": { "host": input.relay_host, "port": input.relay_port },
        "clientId": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_id),
        "virtualIpv4": enrollment.virtual_ipv4,
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
}
