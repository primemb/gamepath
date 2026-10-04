//! The engine binary: a JSON-RPC loop over stdio.
//!
//! The same executable runs twice with different privileges. Electron starts
//! it as an unprivileged planner and prober; the Windows service starts it
//! again, elevated, as the data plane that owns Wintun, WinDivert and the
//! transports. Which one it is depends only on which commands it is sent.

mod capture;
mod commands;
#[cfg(windows)]
mod dns_guard;
#[cfg(windows)]
mod file_icon;
mod icmp;
mod ipc;
mod netutil;
mod session;
mod teardown;

#[cfg(windows)]
mod proxy_identity;
#[cfg(windows)]
mod socket_table;
#[cfg(all(windows, feature = "socks-server"))]
mod socks;
#[cfg(windows)]
mod split_capture;
#[cfg(windows)]
mod tcp_reset;
#[cfg(windows)]
mod udp_classifier;

use capture::PacketCaptureManager;
use commands::{
    inspect_system, prepare_session, probe_relay, probe_socks5_node, probe_wireguard_routes,
    scheduler_demo,
};
use gamepath_engine::role::Role;
use gamepath_engine::{log_error, log_info, log_warn};
use ipc::{Request, Response};
use serde_json::json;
use session::WireGuardSessionManager;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

/// A request answered slower than this is logged by name.
const SLOW_REQUEST: std::time::Duration = std::time::Duration::from_secs(2);

fn main() {
    let role = match Role::from_args(std::env::args()) {
        Ok(role) => role,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    role.install();
    // stdout carries the JSON-RPC the service reads, so the log must not go
    // there. The directory is shared with the other components; stderr is off
    // because the service captures it and would record every line twice.
    gamepath_engine::log::init(
        role.log_component(),
        Some(gamepath_engine::log::log_path(role.log_component())),
        false,
    );
    log_info!(
        "gamepath-engine {} started as the {} engine",
        env!("CARGO_PKG_VERSION"),
        role.as_str()
    );
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let sessions = Arc::new(Mutex::new(WireGuardSessionManager::default()));
    let mut capture = PacketCaptureManager::default();
    let mut proxy = LanProxy::default();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => {
                let command = request.command.clone();
                let started = std::time::Instant::now();
                let response = handle_request(request, &sessions, &mut capture, &mut proxy);
                // The client gives up on a session after a few unanswered
                // polls, so a slow answer is worth naming before that happens.
                if started.elapsed() >= SLOW_REQUEST {
                    log_warn!(
                        "request {command} took {:.1} s",
                        started.elapsed().as_secs_f64()
                    );
                }
                response
            }
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

#[cfg(all(windows, feature = "socks-server"))]
type LanProxy = socks::SocksServerManager;

/// Stands in where the proxy is not built, so every caller can still ask.
#[cfg(not(all(windows, feature = "socks-server")))]
#[derive(Default)]
struct LanProxy;

#[cfg(not(all(windows, feature = "socks-server")))]
impl LanProxy {
    fn start(
        &mut self,
        _payload: serde_json::Value,
        _sessions: &Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<serde_json::Value, String> {
        Err("this engine was built without the LAN proxy".into())
    }

    fn status(&self) -> serde_json::Value {
        json!({ "state": "stopped" })
    }

    fn stop(&mut self) -> serde_json::Value {
        self.status()
    }
}

/// Where other devices can reach this PC. Needs no privilege, so the client's
/// own engine answers it before any session exists.
fn lan_addresses() -> serde_json::Value {
    #[cfg(windows)]
    return json!(gamepath_engine::netconfig::lan_ipv4_addresses());
    #[cfg(not(windows))]
    json!([])
}

fn handle_request(
    request: Request,
    sessions: &Arc<Mutex<WireGuardSessionManager>>,
    capture: &mut PacketCaptureManager,
    proxy: &mut LanProxy,
) -> Response {
    let result = match request.command.as_str() {
        "hello" => Ok(json!({
            "engine": "gamepath",
            "version": env!("CARGO_PKG_VERSION"),
            "protocolVersion": 1,
        })),
        "inspect-system" => Ok(inspect_system()),
        "lan-addresses" => Ok(lan_addresses()),
        #[cfg(windows)]
        "file-icon" => file_icon::file_icon(request.payload),
        "prepare-session" => prepare_session(request.payload),
        "probe-relay" => probe_relay(request.payload),
        "probe-wireguard-routes" => probe_wireguard_routes(request.payload),
        "probe-socks5-node" => probe_socks5_node(request.payload),
        #[cfg(all(windows, feature = "socks-server"))]
        "probe-socks5-proxy" => commands::probe_socks5_proxy(request.payload),
        "start-wireguard-session" => {
            // Its flows live in the session being replaced.
            proxy.stop();
            let mut manager = sessions.lock().unwrap();
            // The service keeps these out of the other session's capture.
            manager.start(request.payload).map(|mut status| {
                status["bypassIps"] = json!(manager.bypass_ips());
                status
            })
        }
        "wireguard-session-status" => Ok(sessions.lock().unwrap().status()),
        "probe-data-plane" => sessions.lock().unwrap().probe_data_plane(),
        "start-packet-capture" => capture.start(request.payload, Arc::clone(sessions)),
        #[cfg(windows)]
        "start-native-dns" => capture.start_native_dns(request.payload),
        "update-packet-capture" => capture.update(request.payload, Arc::clone(sessions)),
        "set-foreign-bypass" => capture.set_foreign_bypass(request.payload, Arc::clone(sessions)),
        "set-other-session-active" => Ok(capture.set_other_session_active(&request.payload)),
        "packet-capture-status" => Ok(capture.status()),
        "stop-packet-capture" => Ok(capture.stop()),
        "start-socks-server" => proxy.start(request.payload, sessions),
        "socks-server-status" => Ok(proxy.status()),
        "stop-socks-server" => Ok(proxy.stop()),
        "stop-wireguard-session" => {
            let _watch = teardown::watch("stopping the session");
            // Before the session: the proxy's thread takes the session lock
            // for every packet, and is joined here.
            teardown::step("LAN proxy");
            proxy.stop();
            teardown::step("packet capture");
            capture.stop();
            teardown::step("waiting for the session lock");
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
