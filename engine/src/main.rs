//! The engine binary: a JSON-RPC loop over stdio.
//!
//! The same executable runs twice with different privileges. Electron starts
//! it as an unprivileged planner and prober; the Windows service starts it
//! again, elevated, as the data plane that owns Wintun, WinDivert and the
//! transports. Which one it is depends only on which commands it is sent.

mod capture;
mod commands;
mod icmp;
mod ipc;
mod netutil;
mod session;

#[cfg(windows)]
mod split_capture;

use capture::PacketCaptureManager;
use commands::{
    inspect_system, prepare_session, probe_relay, probe_socks5_node, probe_wireguard_routes,
    scheduler_demo,
};
use gamepath_engine::{log_error, log_info};
use ipc::{Request, Response};
use serde_json::json;
use session::WireGuardSessionManager;
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

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
