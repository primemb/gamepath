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
use std::process::Command;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    packets_sent: u64,
    packets_received: u64,
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
    client_id: [u8; 16],
    key: [u8; 32],
    virtual_ipv4: std::net::Ipv4Addr,
    sequences: Arc<AtomicU64>,
}

struct PathCommand {
    frame: Vec<u8>,
    response: mpsc::Sender<Result<Vec<u8>, String>>,
}

#[derive(Default)]
struct WireGuardSessionManager {
    active: Option<ActiveWireGuardSession>,
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut sessions = WireGuardSessionManager::default();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, &mut sessions),
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

fn handle_request(request: Request, sessions: &mut WireGuardSessionManager) -> Response {
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
        "start-wireguard-session" => sessions.start(request.payload),
        "wireguard-session-status" => Ok(sessions.status()),
        "probe-data-plane" => sessions.probe_data_plane(),
        "stop-wireguard-session" => Ok(sessions.stop()),
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

        self.stop();
        let session_id = rand::random::<u64>();
        let relay_port = input.relay_port;
        let stop = Arc::new(AtomicBool::new(false));
        let sequences = Arc::new(AtomicU64::new(1));
        let mut initial_statuses = vec![PathSessionStatus {
            route: 0,
            path_kind: "direct".into(),
            label: "Direct ISP".into(),
            endpoint: format!("{relay_ip}:{relay_port}"),
            reachable: false,
            latency_ms: None,
            packets_sent: 0,
            packets_received: 0,
            last_error: None,
        }];
        initial_statuses.extend(paths.iter().map(|(config_index, path)| PathSessionStatus {
            route: *config_index,
            path_kind: "wireguard".into(),
            label: format!("WireGuard route {config_index}"),
            endpoint: path.endpoint().to_string(),
            reachable: false,
            latency_ms: None,
            packets_sent: 0,
            packets_received: 0,
            last_error: None,
        }));
        let statuses = Arc::new(Mutex::new(initial_statuses));
        let route_count = paths.len() + 1;
        let mut workers = Vec::with_capacity(route_count);
        let mut commands = Vec::with_capacity(route_count);
        {
            let (command_tx, command_rx) = mpsc::channel();
            commands.push(command_tx);
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
            workers.push(
                thread::Builder::new()
                    .name("gamepath-direct".into())
                    .spawn(move || {
                        run_direct_path(
                            relay_ip,
                            relay_port,
                            client_id,
                            key,
                            session_id,
                            worker_sequences,
                            worker_stop,
                            worker_statuses,
                            command_rx,
                        )
                    })
                    .map_err(|error| format!("could not start direct path worker: {error}"))?,
            );
        }
        for (index, (_, path)) in paths.into_iter().enumerate() {
            let status_index = index + 1;
            let (command_tx, command_rx) = mpsc::channel();
            commands.push(command_tx);
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
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
                        )
                    })
                    .map_err(|error| format!("could not start WireGuard path worker: {error}"))?,
            );
        }
        self.active = Some(ActiveWireGuardSession {
            session_id,
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers,
            skipped_routes,
            commands,
            client_id,
            key,
            virtual_ipv4: enrollment.virtual_ipv4,
            sequences,
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
        let mut relay_tun = virtual_ipv4.octets();
        relay_tun[3] = 1;
        let identifier = rand::random::<u16>();
        let request = icmp_echo_packet(
            virtual_ipv4,
            std::net::Ipv4Addr::from(relay_tun),
            identifier,
            1,
            false,
        );
        let started = Instant::now();
        let reply = self.send_data_packet(&request)?;
        if !is_matching_icmp_reply(
            &reply,
            std::net::Ipv4Addr::from(relay_tun),
            virtual_ipv4,
            identifier,
        ) {
            return Err("relay data plane returned an unexpected packet".into());
        }
        Ok(json!({
            "reachable": true,
            "latencyMs": started.elapsed().as_secs_f64() * 1000.0,
            "bytes": reply.len(),
        }))
    }

    fn send_data_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        use gamepath_engine::auth::SessionCrypto;
        use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};

        let session = self
            .active
            .as_mut()
            .ok_or("start the WireGuard session before sending packets")?;
        let sequence = session.sequences.fetch_add(1, Ordering::Relaxed);
        let header = FrameHeader {
            flags: 0,
            client_id: session.client_id,
            session_id: session.session_id,
            sequence,
        };
        let crypto = SessionCrypto::new(&session.key, session.session_id)?;
        let frame = crypto.seal_client(header, packet)?;
        let (response_tx, response_rx) = mpsc::channel();
        let mut dispatched = 0;
        for sender in &session.commands {
            if sender
                .send(PathCommand {
                    frame: frame.clone(),
                    response: response_tx.clone(),
                })
                .is_ok()
            {
                dispatched += 1;
            }
        }
        drop(response_tx);
        if dispatched == 0 {
            return Err("no active path workers accepted the packet".into());
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut errors = Vec::new();
        while Instant::now() < deadline && errors.len() < dispatched {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match response_rx.recv_timeout(remaining) {
                Ok(Ok(response)) => {
                    let (reply_header, plaintext) = crypto.open_server(&response)?;
                    if reply_header.client_id == session.client_id
                        && reply_header.session_id == session.session_id
                        && reply_header.flags & FLAG_SERVER_TO_CLIENT != 0
                        && reply_header.flags & FLAG_CONTROL == 0
                    {
                        return Ok(plaintext);
                    }
                    errors.push("path returned an unrelated packet".into());
                }
                Ok(Err(error)) => errors.push(error),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        Err(format!(
            "no path returned the relayed packet{}",
            if errors.is_empty() {
                String::new()
            } else {
                format!(": {}", errors.join("; "))
            }
        ))
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
        let state = if paths.iter().all(|path| path.reachable) {
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

#[allow(clippy::too_many_arguments)]
fn run_direct_path(
    relay_ip: std::net::Ipv4Addr,
    relay_port: u16,
    client_id: [u8; 16],
    key: [u8; 32],
    session_id: u64,
    sequences: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
) {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};

    let relay = SocketAddr::from((relay_ip, relay_port));
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    if socket.connect(relay).is_err()
        || socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .is_err()
    {
        return;
    }
    let Ok(crypto) = SessionCrypto::new(&key, session_id) else {
        return;
    };
    while !stop.load(Ordering::Acquire) {
        let sequence = sequences.fetch_add(1, Ordering::Relaxed);
        let result = (|| {
            let header = FrameHeader {
                flags: FLAG_CONTROL,
                client_id,
                session_id,
                sequence,
            };
            let frame = crypto.seal_client(header, b"ping")?;
            {
                let mut current = statuses.lock().unwrap();
                current[0].packets_sent += 1;
            }
            let started = Instant::now();
            socket
                .send(&frame)
                .map_err(|error| format!("direct path send failed: {error}"))?;
            let mut response = [0_u8; 2048];
            let length = socket
                .recv(&mut response)
                .map_err(|error| format!("direct path did not answer: {error}"))?;
            let (response_header, plaintext) = crypto.open_server(&response[..length])?;
            if response_header.client_id != client_id
                || response_header.session_id != session_id
                || response_header.flags & (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
                    != (FLAG_CONTROL | FLAG_SERVER_TO_CLIENT)
                || plaintext != b"pong"
            {
                return Err("direct path returned an invalid authenticated relay response".into());
            }
            Ok::<f64, String>(started.elapsed().as_secs_f64() * 1000.0)
        })();
        let succeeded = result.is_ok();
        update_path_status(&statuses, 0, result);
        let wait = if succeeded { 10_000 } else { 1_000 };
        for _ in 0..wait / 100 {
            if stop.load(Ordering::Acquire) {
                return;
            }
            match commands.try_recv() {
                Ok(command) => {
                    let response = direct_data_transaction(&socket, &crypto, &command.frame);
                    let _ = command.response.send(response);
                }
                Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
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
) {
    use gamepath_engine::auth::SessionCrypto;
    use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader};
    use gamepath_engine::userspace_wireguard::{ipv4_udp_packet, ipv4_udp_payload};
    use rand::Rng;

    let Ok(crypto) = SessionCrypto::new(&key, session_id) else {
        return;
    };
    let source_port = rand::rng().random_range(49_152..=65_535);
    while !stop.load(Ordering::Acquire) {
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
            }
            let started = Instant::now();
            let reply = path.transact(&inner, Duration::from_secs(8))?;
            let (
                reply_source_ip,
                reply_destination_ip,
                reply_source_port,
                reply_destination_port,
                response_frame,
            ) = ipv4_udp_payload(&reply).ok_or("WireGuard path returned a non-UDP packet")?;
            if reply_source_ip != relay_ip
                || reply_destination_ip != path.address()
                || reply_source_port != relay_port
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
                return Err(
                    "WireGuard path returned an invalid authenticated relay response".into(),
                );
            }
            Ok::<f64, String>(started.elapsed().as_secs_f64() * 1000.0)
        })();
        let succeeded = result.is_ok();
        update_path_status(&statuses, index, result);
        let wait = if succeeded { 10_000 } else { 1_000 };
        for _ in 0..wait / 100 {
            if stop.load(Ordering::Acquire) {
                return;
            }
            match commands.try_recv() {
                Ok(command) => {
                    let response = wireguard_data_transaction(
                        &mut path,
                        relay_ip,
                        relay_port,
                        source_port,
                        &crypto,
                        &command.frame,
                    );
                    let _ = command.response.send(response);
                }
                Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            thread::sleep(Duration::from_millis(100));
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

fn direct_data_transaction(
    socket: &UdpSocket,
    crypto: &gamepath_engine::auth::SessionCrypto,
    frame: &[u8],
) -> Result<Vec<u8>, String> {
    use gamepath_engine::protocol::FLAG_CONTROL;

    socket
        .send(frame)
        .map_err(|error| format!("direct data send failed: {error}"))?;
    let mut response = [0_u8; 65_535];
    loop {
        let length = socket
            .recv(&mut response)
            .map_err(|error| format!("direct data path did not answer: {error}"))?;
        if let Ok((header, _)) = crypto.open_server(&response[..length]) {
            if header.flags & FLAG_CONTROL == 0 {
                return Ok(response[..length].to_vec());
            }
        }
    }
}

fn wireguard_data_transaction(
    path: &mut gamepath_engine::userspace_wireguard::UserSpaceWireGuardPath,
    relay_ip: std::net::Ipv4Addr,
    relay_port: u16,
    source_port: u16,
    crypto: &gamepath_engine::auth::SessionCrypto,
    frame: &[u8],
) -> Result<Vec<u8>, String> {
    use gamepath_engine::protocol::FLAG_CONTROL;
    use gamepath_engine::userspace_wireguard::{ipv4_udp_packet, ipv4_udp_payload};

    let inner = ipv4_udp_packet(path.address(), relay_ip, source_port, relay_port, frame)?;
    let reply = path.transact(&inner, Duration::from_secs(8))?;
    let (source_ip, destination_ip, source_port_reply, destination_port, response_frame) =
        ipv4_udp_payload(&reply).ok_or("WireGuard data path returned a non-UDP packet")?;
    if source_ip != relay_ip
        || destination_ip != path.address()
        || source_port_reply != relay_port
        || destination_port != source_port
    {
        return Err("WireGuard data path returned an unexpected UDP flow".into());
    }
    let (header, _) = crypto.open_server(response_frame)?;
    if header.flags & FLAG_CONTROL != 0 {
        return Err("WireGuard data path returned a control packet".into());
    }
    Ok(response_frame.to_vec())
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
