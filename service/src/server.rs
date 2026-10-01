//! The service process: the Windows service wrapper, the loopback listener
//! and the request dispatcher.

use crate::l2tp::probe_l2tp_node;
use crate::registry::{Registry, watch_lease};
use crate::session::{
    session_status, start_session, stop_session, update_lan_proxy, update_session_rules,
};
use crate::slot::SlotId;
use crate::validate::validate_runtime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;
use windows_service::{
    Result as ServiceResult, define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const SERVICE_NAME: &str = "GamePathService";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
const DEFAULT_PORT: u16 = 47_983;
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

/// How long a connected client has to finish sending its request line. The
/// UI writes one line and waits, so this only ever fires on a caller that
/// connects and then says nothing - which without it would hold a thread
/// for as long as it liked.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Time allowed to write the response back, so a client that stops reading
/// cannot pin a handler either.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Handlers that may run at once. The UI makes one request at a time per
/// session; this is the ceiling that stops a local process opening threads
/// without end.
const MAX_CONCURRENT_REQUESTS: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    id: u64,
    token: String,
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

pub(crate) fn run() -> ServiceResult<()> {
    // A service has no console to print to, so the file is the only record
    // of what it did. Mirrored to stderr as well for `--console` runs.
    gamepath_engine::log::init(
        "service",
        Some(gamepath_engine::log::log_path("service")),
        true,
    );
    gamepath_engine::log_info!("gamepath-service {} starting", env!("CARGO_PKG_VERSION"));
    if env::args().any(|argument| argument == "--console") {
        let token_file = argument("--token-file")
            .map(PathBuf::from)
            .unwrap_or_else(default_token_file);
        let port = argument("--port")
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_PORT);
        let stop = Arc::new(AtomicBool::new(false));
        run_server(&token_file, port, stop).map_err(windows_service::Error::Winapi)
    } else {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    let _ = run_service();
}

fn run_service() -> ServiceResult<()> {
    cleanup_stale_routes();
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop => {
            handler_stop.store(true, Ordering::Release);
            let _ = shutdown_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    let worker_stop = Arc::clone(&stop);
    let worker =
        thread::spawn(move || run_server(&default_token_file(), DEFAULT_PORT, worker_stop));
    let _ = shutdown_rx.recv();
    stop.store(true, Ordering::Release);
    let _ = worker.join();

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;
    Ok(())
}

/// Removes what a previous service process left behind if it died without
/// tearing down. `GamePath*` covers both slots' adapters.
fn cleanup_stale_routes() {
    let script = "$i=@(Get-NetAdapter -Name 'GamePath*' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty ifIndex);if($i.Count){Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.InterfaceIndex -in $i -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}|Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue};Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue|Where-Object {$_.Name -like 'GamePath-L2TP-*'}|ForEach-Object {& rasdial.exe $_.Name /disconnect 2>$null|Out-Null;Remove-VpnConnection -Name $_.Name -AllUserConnection -Force -ErrorAction SilentlyContinue}";
    let _ = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000)
        .status();
}

fn run_server(token_file: &Path, port: u16, stop: Arc<AtomicBool>) -> std::io::Result<()> {
    let expected_token = fs::read_to_string(token_file)?.trim().to_owned();
    if expected_token.len() < 40 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "service token is invalid",
        ));
    }
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    let registry = Registry::new();
    let watchdogs: Vec<_> = SlotId::ALL
        .into_iter()
        .map(|slot| {
            let registry = Arc::clone(&registry);
            let stop = Arc::clone(&stop);
            thread::spawn(move || watch_lease(registry, slot, stop))
        })
        .collect();
    let in_flight = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Refuse rather than spawn once the ceiling is reached: a
                // rejected caller retries, a queued thread never leaves.
                if in_flight.load(Ordering::Acquire) >= MAX_CONCURRENT_REQUESTS {
                    reject_overloaded(stream);
                    continue;
                }
                in_flight.fetch_add(1, Ordering::AcqRel);
                let token = expected_token.clone();
                let registry = Arc::clone(&registry);
                let in_flight = Arc::clone(&in_flight);
                thread::spawn(move || {
                    handle_connection(stream, &token, &registry);
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(error),
        }
    }
    for watchdog in watchdogs {
        let _ = watchdog.join();
    }
    // The VPN first: it routes around the game, never the other way round.
    stop_session(SlotId::Vpn, &registry, Some("service-stopping"));
    stop_session(SlotId::Game, &registry, Some("service-stopping"));
    Ok(())
}

/// Tells a caller the service is busy without spending a thread on it.
fn reject_overloaded(mut stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(RESPONSE_WRITE_TIMEOUT));
    gamepath_engine::log_warn!("refused a request: too many in flight");
    let response = failure(0, "service is busy; retry".into());
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
}

fn handle_connection(mut stream: TcpStream, expected_token: &str, registry: &Arc<Registry>) {
    // The listener is non-blocking so the accept loop can poll `stop`, and
    // on Windows an accepted socket inherits that. Left alone, `read_line`
    // below fails the instant the request has not landed yet - which on
    // loopback is pure scheduling luck - and the timeouts are ignored
    // entirely. Both depend on this being a blocking socket.
    //
    // Without the timeouts a caller that connects and then stalls holds
    // this thread open indefinitely.
    if stream.set_nonblocking(false).is_err()
        || stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT)).is_err()
        || stream
            .set_write_timeout(Some(RESPONSE_WRITE_TIMEOUT))
            .is_err()
    {
        gamepath_engine::log_warn!("dropping a connection that could not be configured");
        return;
    }
    let mut line = String::new();
    let read = BufReader::new(&stream)
        .take(MAX_REQUEST_BYTES)
        .read_line(&mut line);
    let response = match read {
        Ok(0) => return,
        Ok(_) => match serde_json::from_str::<Request>(&line) {
            Ok(request) => handle_request(request, expected_token, registry),
            Err(error) => {
                gamepath_engine::log_warn!("could not parse a request: {error}");
                failure(0, format!("invalid request: {error}"))
            }
        },
        Err(error) => {
            gamepath_engine::log_warn!("could not read a request: {error}");
            failure(0, format!("request read failed: {error}"))
        }
    };
    let _ = serde_json::to_writer(&mut stream, &response);
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

fn handle_request(request: Request, expected_token: &str, registry: &Arc<Registry>) -> Response {
    if !constant_time_equal(request.token.as_bytes(), expected_token.as_bytes()) {
        return failure(request.id, "service authentication failed".into());
    }
    let slot = match SlotId::from_payload(&request.payload) {
        Ok(slot) => slot,
        Err(error) => return failure(request.id, error),
    };
    let result = match request.command.as_str() {
        "status" => Ok(registry.status()),
        "validate-runtime" => validate_runtime(request.payload, slot),
        "probe-l2tp-node" => probe_l2tp_node(request.payload),
        "start-session" => start_session(request.payload, slot, registry),
        "update-session-rules" => update_session_rules(request.payload, slot, registry),
        "update-lan-proxy" => update_lan_proxy(request.payload, slot, registry),
        "session-status" => session_status(slot, registry),
        "stop-session" => Ok(stop_session(slot, registry, None)),
        _ => Err(format!("unknown service command: {}", request.command)),
    };
    match result {
        Ok(value) => Response {
            id: request.id,
            ok: true,
            result: Some(value),
            error: None,
        },
        Err(error) => failure(request.id, error),
    }
}

fn failure(id: u64, error: String) -> Response {
    Response {
        id,
        ok: false,
        result: None,
        error: Some(error),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
    }
    difference == 0
}

fn default_token_file() -> PathBuf {
    let root = env::var_os("PROGRAMDATA").unwrap_or_else(|| OsString::from(r"C:\ProgramData"));
    PathBuf::from(root).join("GamePath").join("service-token")
}

fn argument(name: &str) -> Option<String> {
    let arguments: Vec<String> = env::args().collect();
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Instant;

    /// Accepts one connection and hands it to `handle_connection`, the way
    /// the serve loop does.
    fn serve_one(listener: TcpListener) -> thread::JoinHandle<Duration> {
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let registry = Registry::new();
            let started = Instant::now();
            handle_connection(stream, "token", &registry);
            started.elapsed()
        })
    }

    /// Mirrors the real accept path, which the other tests do not: the
    /// production listener is non-blocking, and on Windows an accepted
    /// socket inherits that from its listener.
    #[test]
    fn a_request_is_read_even_when_it_arrives_after_the_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            // The request lands after the handler has already started
            // reading, which on loopback is a matter of scheduling luck.
            thread::sleep(Duration::from_millis(300));
            socket
                .write_all(b"{\"id\":7,\"command\":\"status\",\"token\":\"token\"}\n")
                .unwrap();
            let mut response = String::new();
            BufReader::new(&socket).read_line(&mut response).unwrap();
            response
        });
        let (stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        handle_connection(stream, "token", &Registry::new());
        let response = client.join().unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        // The id has to come back, or the client cannot match the reply to
        // its request and reports a mismatch instead of the real outcome.
        assert_eq!(parsed["id"], json!(7), "got: {response}");
        assert_eq!(parsed["ok"], json!(true), "got: {response}");
    }

    #[test]
    fn a_client_that_connects_and_says_nothing_does_not_hold_a_handler_forever() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handler = serve_one(listener);
        // Connect, then never send a request line.
        let _client = TcpStream::connect(address).unwrap();
        let elapsed = handler.join().unwrap();
        assert!(
            elapsed >= REQUEST_READ_TIMEOUT,
            "returned before the timeout could have fired: {elapsed:?}"
        );
        assert!(
            elapsed < REQUEST_READ_TIMEOUT * 3,
            "the read timeout did not bound the handler: {elapsed:?}"
        );
    }

    #[test]
    fn a_complete_request_is_answered_without_waiting_for_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handler = serve_one(listener);
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"{\"id\":1,\"command\":\"status\",\"token\":\"token\"}\n")
            .unwrap();
        let mut response = String::new();
        BufReader::new(&client).read_line(&mut response).unwrap();
        let elapsed = handler.join().unwrap();
        assert!(elapsed < REQUEST_READ_TIMEOUT, "answered late: {elapsed:?}");
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], json!(true));
        // Both slots are reported, with the game's still at the top level.
        assert_eq!(parsed["result"]["sessionStatus"], json!("idle"));
        assert_eq!(
            parsed["result"]["slots"]["vpn"]["sessionStatus"],
            json!("idle")
        );
    }

    #[test]
    fn a_rejected_caller_is_told_why_instead_of_being_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            reject_overloaded(stream);
        });
        let client = TcpStream::connect(address).unwrap();
        let mut response = String::new();
        BufReader::new(&client).read_line(&mut response).unwrap();
        server.join().unwrap();
        let parsed: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["ok"], json!(false));
        assert!(
            parsed["error"].as_str().unwrap().contains("busy"),
            "unhelpful rejection: {parsed}"
        );
    }

    #[test]
    fn token_comparison_checks_length_and_content() {
        assert!(constant_time_equal(b"secret", b"secret"));
        assert!(!constant_time_equal(b"secret", b"secrex"));
        assert!(!constant_time_equal(b"secret", b"secret-long"));
    }

    #[test]
    fn an_unknown_slot_is_refused_before_anything_runs() {
        let response = handle_request(
            Request {
                id: 3,
                token: "token".into(),
                command: "stop-session".into(),
                payload: json!({ "slot": "other" }),
            },
            "token",
            &Registry::new(),
        );
        assert!(!response.ok);
        assert_eq!(response.id, 3);
        assert!(response.error.unwrap().contains("unknown session slot"));
    }
}
