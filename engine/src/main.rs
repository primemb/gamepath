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
use std::time::{SystemTime, UNIX_EPOCH};

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

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request),
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

fn handle_request(request: Request) -> Response {
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
    if input.route_ids.len() < 2 {
        return Err("at least two active routes are required".into());
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
    fn prepare_rejects_one_route() {
        let result = prepare_session(json!({
            "routeIds": ["one"], "trafficMode": "all", "rules": [],
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
}
