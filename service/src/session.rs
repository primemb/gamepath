//! Start, stop, status and live updates for one session slot.

use crate::bypass_routes::BypassRoutes;
use crate::engine_process::EngineProcess;
use crate::l2tp::{
    L2tpSession, apply_direct_l2tp_prefixes, apply_direct_l2tp_routes, connect_l2tp_nodes,
    direct_l2tp_prefixes, native_l2tp_result, probe_direct_l2tp, sample_l2tp_usage,
};
use crate::registry::{Registry, STOPPED_FOR_GAME_ALL_TRAFFIC, SlotSummary};
use crate::slot::{SessionSlot, SlotId};
use crate::validate::{ValidateRequest, carries_direct};
use gamepath_engine::relay_path::{NodeSpec, SessionMode};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// `[vpn vpn-3f9a1c]` when the client named the session, `[vpn]` otherwise.
fn session_tag(id: SlotId, payload: &Value) -> String {
    match payload["sessionId"].as_str().filter(|value| {
        !value.is_empty()
            && value.len() <= 40
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    }) {
        Some(session_id) => format!("[{} {session_id}]", id.as_str()),
        None => format!("[{}]", id.as_str()),
    }
}

fn summary_of(slot: &SessionSlot, status: &str, bypass: Vec<Ipv4Addr>) -> SlotSummary {
    SlotSummary {
        status: status.into(),
        traffic_mode: slot.traffic_mode.clone(),
        route_count: slot.route_count,
        bypass,
        stop_reason: None,
    }
}

/// The addresses the engine reported its own tunnel traffic goes to.
fn engine_bypass(paths: &Value) -> Vec<Ipv4Addr> {
    paths["bypassIps"]
        .as_array()
        .map(|addresses| {
            addresses
                .iter()
                .filter_map(|address| address.as_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// `foreign` is the other slot: its tunnel is kept out of this capture, and
/// while it runs the VPN leaves the machine's name lookups to the game.
fn capture_request(slot: &SessionSlot, rules: &Value, foreign: &SlotSummary) -> Value {
    let remote_dns = slot.remote_dns;
    json!({
        "trafficMode": slot.traffic_mode,
        "rules": rules,
        "remoteDns": remote_dns,
        "killSwitch": slot.kill_switch,
        "ownHostnames": slot.own_hostnames,
        "foreignBypass": foreign.bypass,
        "otherSessionActive": foreign.is_active(),
    })
}

/// The client's list of its own hostnames, bounded so a malformed request
/// cannot make every captured lookup pay for a huge set.
fn own_hostnames(payload: &Value) -> Vec<String> {
    const MAX: usize = 256;
    payload["ownHostnames"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .filter(|name| !name.is_empty() && name.len() <= 253)
                .take(MAX)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn start_session(
    mut payload: Value,
    id: SlotId,
    registry: &Arc<Registry>,
) -> Result<Value, String> {
    let mut runtime = registry.slot(id).lock().unwrap();
    // A session that is still running is torn down properly, so its routes
    // go with it. Killing the engine outright skipped that, and a half-default
    // route left behind black-holed the next split session.
    if runtime.engine.is_some() || !runtime.l2tp_sessions.is_empty() {
        runtime.log("replacing the running session");
    }
    runtime.take_for_teardown(None).run();
    runtime.tag = session_tag(id, &payload);
    runtime.log("starting privileged network session");
    let result = start_slot(&mut payload, &mut runtime, registry);
    if let Err(error) = &result {
        runtime.warn(&format!("session did not start: {error}"));
        runtime.take_for_teardown(None).run();
        registry.publish(id, SlotSummary::idle(None));
    }
    result
}

fn start_slot(
    payload: &mut Value,
    runtime: &mut SessionSlot,
    registry: &Arc<Registry>,
) -> Result<Value, String> {
    let id = runtime.id;
    let lan_proxy = if id == SlotId::Game {
        lan_proxy_request(payload)
    } else {
        None
    };
    let request: ValidateRequest = serde_json::from_value(payload.clone())
        .map_err(|error| format!("invalid session request: {error}"))?;
    // Absent means on, matching the engine: a caller that predates the
    // setting gets the protective behaviour rather than a silent leak.
    let remote_dns = payload["remoteDns"].as_bool().unwrap_or(true);
    let mut nodes = request.resolved_nodes();
    for (index, node) in nodes.iter().enumerate() {
        node.validate()
            .map_err(|error| format!("route {}: {error}", index + 1))?;
    }
    if id == SlotId::Vpn {
        if request.mode != SessionMode::Direct || nodes.len() != 1 {
            return Err("the VPN connects straight to exactly one node".into());
        }
        if !carries_direct(id, &nodes[0]) {
            return Err(format!("{} cannot carry the VPN", nodes[0].describe()));
        }
        if registry.summary(SlotId::Game).owns_all_traffic() {
            return Err(format!(
                "{STOPPED_FOR_GAME_ALL_TRAFFIC}: the game session is carrying all traffic, \
                 so the VPN waits until it stops"
            ));
        }
    }
    let relay_address = if request.mode == SessionMode::Relay {
        let host = payload["relayHost"]
            .as_str()
            .ok_or("a relay session needs the relay address")?;
        let port = payload["relayPort"].as_u64().unwrap_or(0) as u16;
        Some(
            (host, port)
                .to_socket_addrs()
                .map_err(|error| format!("could not resolve the relay: {error}"))?
                .find_map(|address| match address.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                })
                .ok_or("the relay did not resolve to IPv4")?,
        )
    } else {
        None
    };
    let traffic_mode = payload["trafficMode"].as_str().unwrap_or("all").to_owned();
    if traffic_mode != "all" && traffic_mode != "split" {
        return Err("traffic mode must be all or split".into());
    }
    runtime.traffic_mode = traffic_mode.clone();
    runtime.remote_dns = remote_dns;
    runtime.kill_switch = id == SlotId::Vpn && payload["killSwitch"].as_bool() == Some(true);
    runtime.own_hostnames = own_hostnames(payload);
    // Published before anything is opened: a game taking all traffic stops
    // the VPN now, before its own routes go in.
    registry.publish(id, summary_of(runtime, "starting", Vec::new()));
    let foreign = registry.summary(id.other());
    let foreign_bypass = foreign.bypass.clone();
    let rules = payload["rules"].clone();
    if request.mode == SessionMode::Direct && matches!(nodes.as_slice(), [NodeSpec::L2tp { .. }]) {
        return start_native_l2tp(
            runtime,
            registry,
            &mut nodes,
            rules,
            &foreign_bypass,
            lan_proxy,
        );
    }
    // Starting the engine child and dialling L2TP do not depend on each
    // other, and the dial is the long pole in bringing a session up: IKE
    // negotiation plus waiting for the RAS adapter to appear takes seconds
    // during which the engine would not even have been spawned yet. The
    // child only has to exist before it is asked to start the session, so
    // the two run together and the session begins roughly one of them
    // sooner.
    let engine_start = thread::spawn(move || EngineProcess::start(id));
    let l2tp_sessions = match connect_l2tp_nodes(&mut nodes, relay_address, true, &runtime.tag) {
        Ok(sessions) => sessions,
        Err(error) => {
            // `EngineProcess` kills its child when dropped, so collecting
            // the thread here is what stops a failed dial from leaving an
            // orphaned engine behind.
            drop(engine_start.join());
            return Err(error);
        }
    };
    runtime.l2tp_sessions = l2tp_sessions;
    payload["nodes"] = serde_json::to_value(&nodes)
        .map_err(|error| format!("could not prepare L2TP runtime: {error}"))?;
    let engine = engine_start
        .join()
        .map_err(|_| "the native engine panicked while starting".to_owned())??;
    runtime.log("native engine child ready");
    let engine = runtime.engine.insert(engine);
    let paths = engine.request("start-wireguard-session", payload.clone())?;
    let bypass = engine_bypass(&paths);
    let path_count = paths["paths"].as_array().map_or(0, Vec::len);
    let data_plane = engine.request("probe-data-plane", json!({}))?;
    runtime.log(&format!(
        "{path_count} path(s) connected; benchmark packet {}",
        if data_plane["reachable"] == json!(true) {
            "returned"
        } else {
            "not answered"
        }
    ));
    let capture_payload = capture_request(runtime, &rules, &foreign);
    let engine = runtime.engine.as_mut().ok_or("no active network session")?;
    let capture = engine.request("start-packet-capture", capture_payload)?;
    // After capture, and never fatal: a session that routes the game is
    // worth more than the proxy beside it.
    let lan_proxy_status = match lan_proxy {
        Some(request) => start_lan_proxy(runtime, request),
        None => json!({ "state": "stopped" }),
    };
    runtime.log(&format!(
        "packet capture started: traffic={traffic_mode} foreignBypass={}",
        foreign_bypass.len()
    ));
    runtime.session_status = "connected".into();
    runtime.route_count = path_count;
    runtime.session_rules = rules;
    runtime.renew_lease();
    runtime.lan_proxy = lan_proxy_status.clone();
    registry.publish(runtime.id, summary_of(runtime, "connected", bypass));
    Ok(json!({
        "paths": paths,
        "dataPlane": data_plane,
        "capture": capture,
        "lanProxy": lan_proxy_status,
    }))
}

fn start_native_l2tp(
    runtime: &mut SessionSlot,
    registry: &Arc<Registry>,
    nodes: &mut [NodeSpec],
    rules: Value,
    foreign_bypass: &[Ipv4Addr],
    lan_proxy: Option<Value>,
) -> Result<Value, String> {
    let label = nodes[0]
        .label()
        .unwrap_or_else(|| nodes[0].default_label(1));
    let split = runtime.traffic_mode == "split";
    // Reject selectors Windows routes cannot express before creating a
    // VPN profile or changing any route.
    let direct_prefixes = if split {
        direct_l2tp_prefixes(&rules)?
    } else {
        Vec::new()
    };
    // RAS takes the default route over in all-traffic mode, so the physical
    // gateway has to be found first; the other slot's tunnel is then routed
    // around the VPN through it.
    let mut bypass_routes = if !split && runtime.id == SlotId::Vpn {
        Some(BypassRoutes::on_physical_uplink()?)
    } else {
        None
    };
    runtime.l2tp_sessions = connect_l2tp_nodes(nodes, None, split, &runtime.tag)?;
    let session = runtime
        .l2tp_sessions
        .first_mut()
        .ok_or("the L2TP direct session did not create a Windows connection")?;
    if split {
        apply_direct_l2tp_prefixes(session, &direct_prefixes)?;
    }
    if let Some(routes) = bypass_routes.as_mut() {
        routes.apply(foreign_bypass)?;
    }
    let target_count = rules.as_array().map_or(0, Vec::len);
    let (paths, data_plane, capture) =
        native_l2tp_result(session, &label, &runtime.traffic_mode, target_count);
    if data_plane["reachable"] != json!(true) {
        return Err(
            "Windows connected L2TP/IPsec, but no data returned through the VPN adapter".into(),
        );
    }
    let server = session.server_address;
    let connection = session.connection;
    runtime.session_status = "connected".into();
    runtime.route_count = 1;
    runtime.session_rules = rules;
    runtime.renew_lease();
    runtime.native_l2tp_direct = true;
    runtime.native_l2tp_status = paths.clone();
    runtime.native_l2tp_capture = capture.clone();
    runtime.native_l2tp_probe_supported = true;
    runtime.native_l2tp_probe_failures = 0;
    runtime.bypass_routes = bypass_routes;
    sample_l2tp_usage(connection, &mut runtime.native_l2tp_usage);
    runtime.log("native Windows L2TP direct routing started");
    let lan_proxy = apply_lan_proxy(runtime, lan_proxy);
    registry.publish(runtime.id, summary_of(runtime, "connected", vec![server]));
    Ok(json!({
        "paths": paths,
        "dataPlane": data_plane,
        "capture": capture,
        "lanProxy": lan_proxy,
    }))
}

/// Stops `id`. `reason` is set when the client did not ask for it, so the
/// client can say why the session ended.
pub(crate) fn stop_session(id: SlotId, registry: &Arc<Registry>, reason: Option<&str>) -> Value {
    let mut runtime = registry.slot(id).lock().unwrap();
    let was_running = runtime.is_connected() || runtime.engine.is_some();
    if was_running {
        runtime.log(&match reason {
            Some(reason) => format!("stopping the session: {reason}"),
            None => "stopping the session".to_owned(),
        });
    }
    // Torn down under the slot's lock, so a start that follows straight
    // after cannot race the old session's route removal.
    runtime.take_for_teardown(reason).run();
    registry.publish(id, SlotSummary::idle(reason.map(str::to_owned)));
    json!({ "sessionStatus": "idle", "stopReason": reason })
}

pub(crate) fn expire_lease(id: SlotId, registry: &Arc<Registry>) {
    let mut runtime = registry.slot(id).lock().unwrap();
    if !runtime.lease_expired(std::time::Instant::now()) {
        return;
    }
    runtime.warn("session lease expired; stopping packet capture");
    runtime.take_for_teardown(Some("lease-expired")).run();
    registry.publish(id, SlotSummary::idle(Some("lease-expired".into())));
}

/// The proxy settings a `start-session` or `update-lan-proxy` payload asks
/// for, or `None` when the proxy is off.
fn lan_proxy_request(payload: &Value) -> Option<Value> {
    let settings = payload.get("lanProxy")?;
    (settings["enabled"].as_bool() == Some(true)).then(|| {
        json!({
            "port": settings["port"].as_u64().unwrap_or(1080),
            "username": settings["username"],
            "password": settings["password"],
        })
    })
}

fn start_lan_proxy(runtime: &mut SessionSlot, request: Value) -> Value {
    let Some(engine) = runtime.engine.as_mut() else {
        return json!({ "state": "error", "error": "no active network session" });
    };
    match engine.request("start-socks-server", request) {
        Ok(status) => status,
        Err(error) => {
            runtime.warn(&format!("LAN proxy did not start: {error}"));
            json!({ "state": "error", "error": error })
        }
    }
}

/// Starts, restarts or stops the proxy for the running session.
///
/// Native L2TP/IPsec routes through Windows with no engine at all, so the
/// proxy gets an engine child of its own there, sending through sockets
/// pinned to the VPN adapter.
fn apply_lan_proxy(runtime: &mut SessionSlot, request: Option<Value>) -> Value {
    let status = match request {
        None => {
            if let Some(engine) = runtime.engine.as_mut() {
                let _ = engine.request("stop-socks-server", json!({}));
            }
            if runtime.native_l2tp_direct {
                runtime.engine = None;
            }
            json!({ "state": "stopped" })
        }
        Some(mut request) => {
            let mut failure = None;
            if runtime.native_l2tp_direct {
                match runtime.l2tp_sessions.first() {
                    Some(session) => {
                        request["egress"] = json!({
                            "kind": "interface",
                            "address": session.local_address,
                            "interfaceIndex": session.interface_index,
                        });
                    }
                    None => failure = Some("no active L2TP connection".to_owned()),
                }
                if failure.is_none() && runtime.engine.is_none() {
                    match EngineProcess::start(runtime.id) {
                        Ok(engine) => runtime.engine = Some(engine),
                        Err(error) => failure = Some(error),
                    }
                }
            }
            match failure {
                None => start_lan_proxy(runtime, request),
                Some(error) => json!({ "state": "error", "error": error }),
            }
        }
    };
    runtime.lan_proxy = status.clone();
    status
}

pub(crate) fn update_lan_proxy(
    payload: Value,
    id: SlotId,
    registry: &Arc<Registry>,
) -> Result<Value, String> {
    let mut runtime = registry.slot(id).lock().unwrap();
    if id != SlotId::Game || !runtime.is_connected() {
        return Ok(json!({ "state": "stopped" }));
    }
    let request = lan_proxy_request(&payload);
    runtime.log(if request.is_some() {
        "LAN proxy settings applied to the running session"
    } else {
        "LAN proxy turned off for the running session"
    });
    Ok(apply_lan_proxy(&mut runtime, request))
}

/// The live figures while the proxy runs, otherwise why it is not running.
fn lan_proxy_status(runtime: &mut SessionSlot) -> Value {
    if runtime.lan_proxy["state"] == json!("listening") {
        if let Some(engine) = runtime.engine.as_mut() {
            if let Ok(status) = engine.request("socks-server-status", json!({})) {
                return status;
            }
        }
    }
    runtime.lan_proxy.clone()
}

pub(crate) fn update_session_rules(
    payload: Value,
    id: SlotId,
    registry: &Arc<Registry>,
) -> Result<Value, String> {
    let rules = payload
        .get("rules")
        .filter(|rules| rules.is_array())
        .cloned()
        .ok_or("live target update requires a rules array")?;
    let foreign = registry.summary(id.other());
    let mut runtime = registry.slot(id).lock().unwrap();
    if !runtime.is_connected() || runtime.traffic_mode != "split" {
        return Err("live target updates require a connected split session".into());
    }
    let previous_rules = runtime.session_rules.clone();
    if runtime.native_l2tp_direct {
        let session = runtime
            .l2tp_sessions
            .first_mut()
            .ok_or("no active L2TP direct session")?;
        if let Err(error) = apply_direct_l2tp_routes(session, &rules) {
            let rollback = apply_direct_l2tp_routes(session, &previous_rules);
            return match rollback {
                Ok(()) => Err(format!("could not apply live L2TP targets: {error}")),
                Err(rollback_error) => Err(format!(
                    "could not apply live L2TP targets: {error}; restoring the previous routes also failed: {rollback_error}"
                )),
            };
        }
        let target_count = rules.as_array().map_or(0, Vec::len);
        runtime.session_rules = rules;
        runtime.renew_lease();
        runtime.native_l2tp_capture["state"] =
            json!(if target_count == 0 { "idle" } else { "routing" });
        runtime.native_l2tp_capture["targetCount"] = json!(target_count);
        runtime.log("native L2TP split routes updated without reconnecting");
        return Ok(runtime.native_l2tp_capture.clone());
    }
    let rules_are_empty = rules.as_array().is_some_and(Vec::is_empty);
    let previous_rules_are_empty = previous_rules.as_array().is_some_and(Vec::is_empty);
    if rules_are_empty {
        runtime
            .engine
            .as_mut()
            .ok_or("no active network session")?
            .request("stop-packet-capture", json!({}))?;
        runtime.session_rules = rules;
        runtime.renew_lease();
        runtime.log("split capture paused because no targets are enabled");
        return Ok(json!({
            "state": "idle",
            "trafficMode": "split",
            "targetCount": 0,
        }));
    }
    let update = capture_request(&runtime, &rules, &foreign);
    let restore = capture_request(&runtime, &previous_rules, &foreign);
    let target_count = rules.as_array().map_or(0, Vec::len);
    let engine = runtime.engine.as_mut().ok_or("no active network session")?;
    let command = if previous_rules_are_empty {
        "start-packet-capture"
    } else {
        "update-packet-capture"
    };
    let capture = match engine.request(command, update) {
        Ok(capture) => capture,
        Err(error) => {
            // A failure after WinDivert handles were swapped must not leave
            // the connected session with no capture. Restore the last
            // confirmed policy before reporting the rejected edit.
            let rollback = if previous_rules_are_empty {
                engine.request("stop-packet-capture", json!({}))
            } else {
                engine.request("start-packet-capture", restore)
            };
            return match rollback {
                Ok(_) => Err(format!("could not apply live targets: {error}")),
                Err(rollback_error) => Err(format!(
                    "could not apply live targets: {error}; restoring the previous capture also failed: {rollback_error}"
                )),
            };
        }
    };
    runtime.session_rules = rules;
    runtime.renew_lease();
    runtime.log(&format!(
        "split capture targets updated without restarting the session: count={target_count}"
    ));
    Ok(capture)
}

/// Keeps `id`'s capture and routes clear of the other slot's tunnel after
/// that slot started, stopped or moved relay.
pub(crate) fn set_foreign_bypass(id: SlotId, registry: &Arc<Registry>, foreign: &SlotSummary) {
    let addresses = foreign.bypass.as_slice();
    let mut runtime = registry.slot(id).lock().unwrap();
    if !runtime.is_connected() {
        return;
    }
    let native = runtime.native_l2tp_direct;
    let result = if let Some(routes) = runtime.bypass_routes.as_mut() {
        routes.apply(addresses).map(|_| routes.len())
    } else if native {
        // Split routes carry only the user's targets; nothing to keep clear.
        Ok(0)
    } else if let Some(engine) = runtime.engine.as_mut() {
        engine
            .request(
                "set-foreign-bypass",
                json!({ "addresses": addresses, "otherSessionActive": foreign.is_active() }),
            )
            .map(|_| addresses.len())
    } else {
        Ok(0)
    };
    match result {
        Ok(count) => runtime.log(&format!(
            "other session's tunnel kept clear: {count} address(es)"
        )),
        Err(error) => runtime.warn(&format!(
            "could not keep the other session's tunnel clear: {error}"
        )),
    }
}

pub(crate) fn session_status(id: SlotId, registry: &Arc<Registry>) -> Result<Value, String> {
    let mut runtime = registry.slot(id).lock().unwrap();
    if runtime.native_l2tp_direct {
        return Ok(native_l2tp_status(&mut runtime));
    }
    let Some(engine) = runtime.engine.as_mut() else {
        return Err(match &runtime.stop_reason {
            Some(reason) => format!("no active network session ({reason})"),
            None => "no active network session".into(),
        });
    };
    let mut result = engine.request("wireguard-session-status", json!({}))?;
    let capture = engine.request("packet-capture-status", json!({}))?;
    if let Some(object) = result.as_object_mut() {
        object.insert("capture".into(), capture);
    }
    result["lanProxy"] = lan_proxy_status(&mut runtime);
    runtime.renew_lease();
    Ok(result)
}

fn native_l2tp_status(runtime: &mut SessionSlot) -> Value {
    let mut result = runtime.native_l2tp_status.clone();
    let ras_connected = runtime
        .l2tp_sessions
        .first()
        .is_some_and(L2tpSession::is_connected);
    let probe = if ras_connected && runtime.native_l2tp_probe_supported {
        runtime
            .l2tp_sessions
            .first()
            .map(|session| probe_direct_l2tp(session, Duration::from_secs(1)))
    } else {
        None
    };
    if let Some((true, latency_ms)) = probe {
        runtime.native_l2tp_probe_failures = 0;
        result["paths"][0]["latencyMs"] = json!(latency_ms);
        let received = result["paths"][0]["probesReceived"].as_u64().unwrap_or(0) + 1;
        result["paths"][0]["probesReceived"] = json!(received);
    } else if probe.is_some() {
        runtime.native_l2tp_probe_failures = runtime.native_l2tp_probe_failures.saturating_add(1);
        let lost = result["paths"][0]["probesLost"].as_u64().unwrap_or(0) + 1;
        result["paths"][0]["probesLost"] = json!(lost);
    }
    if probe.is_some() {
        let sent = result["paths"][0]["probesSent"].as_u64().unwrap_or(0) + 1;
        result["paths"][0]["probesSent"] = json!(sent);
    }
    let data_reachable = runtime.native_l2tp_probe_failures < 3;
    let connected = ras_connected && data_reachable;
    result["state"] = json!(if connected { "connected" } else { "degraded" });
    result["selectedRoutes"] = if connected { json!([1]) } else { json!([]) };
    result["degradedRoutes"] = if connected { json!([]) } else { json!([1]) };
    result["paths"][0]["reachable"] = json!(connected);
    result["paths"][0]["lastError"] = if connected {
        Value::Null
    } else if !ras_connected {
        json!("the Windows L2TP connection is no longer active")
    } else {
        json!("the L2TP connection is active but its data plane stopped answering")
    };
    if ras_connected {
        if let Some(connection) = runtime
            .l2tp_sessions
            .first()
            .map(|session| session.connection)
        {
            sample_l2tp_usage(connection, &mut runtime.native_l2tp_usage);
        }
    }
    result["userBytesSent"] = json!(runtime.native_l2tp_usage.sent);
    result["userBytesReceived"] = json!(runtime.native_l2tp_usage.received);
    result["paths"][0]["bytesSent"] = json!(runtime.native_l2tp_usage.sent);
    result["paths"][0]["bytesReceived"] = json!(runtime.native_l2tp_usage.received);
    runtime.native_l2tp_status = result.clone();
    let mut capture = runtime.native_l2tp_capture.clone();
    capture["state"] = if connected {
        if capture["trafficMode"] == json!("split") && capture["targetCount"].as_u64() == Some(0) {
            json!("idle")
        } else {
            json!("routing")
        }
    } else {
        json!("degraded")
    };
    runtime.native_l2tp_capture = capture.clone();
    if let Some(object) = result.as_object_mut() {
        object.insert("capture".into(), capture);
    }
    result["lanProxy"] = lan_proxy_status(runtime);
    runtime.renew_lease();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_id_tags_the_log_only_when_it_is_safe_to_print() {
        assert_eq!(
            session_tag(SlotId::Vpn, &json!({ "sessionId": "vpn-3f9a1c" })),
            "[vpn vpn-3f9a1c]"
        );
        assert_eq!(session_tag(SlotId::Game, &json!({})), "[game]");
        assert_eq!(
            session_tag(SlotId::Vpn, &json!({ "sessionId": "x\ninjected line" })),
            "[vpn]"
        );
    }

    #[test]
    fn the_engine_bypass_list_ignores_what_is_not_an_ipv4_address() {
        let bypass = engine_bypass(&json!({ "bypassIps": ["198.51.100.7", "nope", 4, "::1"] }));
        assert_eq!(bypass, [Ipv4Addr::new(198, 51, 100, 7)]);
        assert!(engine_bypass(&json!({})).is_empty());
    }

    #[test]
    fn own_hostnames_reach_the_capture_lowercased_and_bounded() {
        let names = own_hostnames(&json!({
            "ownHostnames": ["Turkey1.Pingkhor.xyz", "", 7, "x".repeat(254)],
        }));
        assert_eq!(names, ["turkey1.pingkhor.xyz"]);
        let mut slot = SessionSlot::new(SlotId::Game);
        slot.own_hostnames = names;
        let request = capture_request(&slot, &json!([]), &SlotSummary::idle(None));
        assert_eq!(request["ownHostnames"], json!(["turkey1.pingkhor.xyz"]));
        assert_eq!(request["otherSessionActive"], json!(false));
        let game = SlotSummary {
            status: "starting".into(),
            ..SlotSummary::idle(None)
        };
        let request = capture_request(&slot, &json!([]), &game);
        assert_eq!(request["otherSessionActive"], json!(true));
    }

    #[test]
    fn a_vpn_does_not_start_while_the_game_carries_all_traffic() {
        let registry = Registry::new();
        registry.publish(
            SlotId::Game,
            SlotSummary {
                status: "connected".into(),
                traffic_mode: "all".into(),
                route_count: 1,
                bypass: Vec::new(),
                stop_reason: None,
            },
        );
        let error = start_session(
            json!({
                "slot": "vpn",
                "mode": "direct",
                "trafficMode": "split",
                "rules": [],
                "nodes": [{ "kind": "socks5", "host": "proxy.example", "port": 1080 }],
            }),
            SlotId::Vpn,
            &registry,
        )
        .unwrap_err();
        assert!(error.starts_with(STOPPED_FOR_GAME_ALL_TRAFFIC), "{error}");
        assert_eq!(registry.summary(SlotId::Vpn).status, "idle");
    }

    #[test]
    fn the_vpn_refuses_a_relay_session() {
        let registry = Registry::new();
        let error = start_session(
            json!({
                "mode": "relay",
                "relayHost": "203.0.113.8",
                "relayPort": 51821,
                "trafficMode": "split",
                "nodes": [{ "kind": "socks5", "host": "proxy.example", "port": 1080 }],
            }),
            SlotId::Vpn,
            &registry,
        )
        .unwrap_err();
        assert!(error.contains("exactly one node"), "{error}");
    }

    #[test]
    fn stopping_an_idle_slot_is_harmless_and_reports_why() {
        let registry = Registry::new();
        let result = stop_session(SlotId::Vpn, &registry, Some(STOPPED_FOR_GAME_ALL_TRAFFIC));
        assert_eq!(result["sessionStatus"], "idle");
        assert_eq!(
            registry.summary(SlotId::Vpn).stop_reason.as_deref(),
            Some(STOPPED_FOR_GAME_ALL_TRAFFIC)
        );
        assert_eq!(registry.summary(SlotId::Game).status, "idle");
    }
}
