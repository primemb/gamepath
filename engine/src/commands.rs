//! The one-shot commands: everything the service can ask the engine that
//! neither starts nor inspects a running session.

use crate::ipc::{PrepareRequest, ProbeRequest, Socks5ProbeRequest, WireGuardProbeRequest};
use crate::netutil::resolve_ipv4;
use base64::Engine as _;
use gamepath_engine::adapter::inspect_library;
use gamepath_engine::auth::EnrollmentToken;
use gamepath_engine::policy::compile as compile_policy;
use gamepath_engine::relay_path::{RelayPath, SessionMode, Socks5RelayPath};
use gamepath_engine::scheduler::{Decision, PathMetrics, Strategy, choose_paths};
use gamepath_engine::socks5::{Socks5NodeConfig, Socks5UdpPath};
use gamepath_engine::wfp::inspect_backend;
use serde_json::{Value, json};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn inspect_system() -> Value {
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

pub(crate) fn prepare_session(payload: Value) -> Result<Value, String> {
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

pub(crate) fn probe_relay(payload: Value) -> Result<Value, String> {
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

pub(crate) fn probe_wireguard_routes(payload: Value) -> Result<Value, String> {
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

/// Proves a SOCKS5 proxy can carry GamePath traffic before it is saved as a
/// node. Accepting UDP ASSOCIATE is not enough on its own: some proxies accept
/// the association and then never forward a datagram, so this waits for an
/// authenticated reply that only the relay can produce.
pub(crate) fn probe_socks5_node(payload: Value) -> Result<Value, String> {
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

pub(crate) fn scheduler_demo() -> Value {
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
}
