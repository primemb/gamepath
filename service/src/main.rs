#[cfg(not(windows))]
fn main() {
    eprintln!("gamepath-service is available only on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    gamepath_service::run()
}

#[cfg(windows)]
mod gamepath_service {
    use gamepath_engine::wireguard_runtime::narrow_to_relay;
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
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

    #[derive(Default)]
    struct RuntimeState {
        session_status: String,
        route_count: usize,
        traffic_mode: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ValidateRequest {
        relay_ip: IpAddr,
        traffic_mode: String,
        wireguard_configs: Vec<String>,
    }

    pub fn run() -> ServiceResult<()> {
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
        let state = Arc::new(Mutex::new(RuntimeState {
            session_status: "idle".into(),
            ..RuntimeState::default()
        }));
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let token = expected_token.clone();
                    let state = Arc::clone(&state);
                    thread::spawn(move || handle_connection(stream, &token, &state));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn handle_connection(mut stream: TcpStream, expected_token: &str, state: &Mutex<RuntimeState>) {
        let mut line = String::new();
        let read = BufReader::new(&stream)
            .take(MAX_REQUEST_BYTES)
            .read_line(&mut line);
        let response = match read {
            Ok(0) => return,
            Ok(_) => match serde_json::from_str::<Request>(&line) {
                Ok(request) => handle_request(request, expected_token, state),
                Err(error) => failure(0, format!("invalid request: {error}")),
            },
            Err(error) => failure(0, format!("request read failed: {error}")),
        };
        let _ = serde_json::to_writer(&mut stream, &response);
        let _ = stream.write_all(b"\n");
        let _ = stream.flush();
    }

    fn handle_request(
        request: Request,
        expected_token: &str,
        state: &Mutex<RuntimeState>,
    ) -> Response {
        if !constant_time_equal(request.token.as_bytes(), expected_token.as_bytes()) {
            return failure(request.id, "service authentication failed".into());
        }
        let result = match request.command.as_str() {
            "status" => {
                let state = state.lock().unwrap();
                Ok(json!({
                    "service": "gamepath",
                    "version": env!("CARGO_PKG_VERSION"),
                    "elevated": true,
                    "sessionStatus": state.session_status,
                    "routeCount": state.route_count,
                    "trafficMode": state.traffic_mode,
                }))
            }
            "validate-runtime" => validate_runtime(request.payload, state),
            "stop-session" => {
                let mut state = state.lock().unwrap();
                state.session_status = "idle".into();
                state.route_count = 0;
                state.traffic_mode.clear();
                Ok(json!({ "sessionStatus": "idle" }))
            }
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

    fn validate_runtime(payload: Value, state: &Mutex<RuntimeState>) -> Result<Value, String> {
        let input: ValidateRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid runtime request: {error}"))?;
        if input.traffic_mode != "all" && input.traffic_mode != "split" {
            return Err("traffic mode must be all or split".into());
        }
        if input.wireguard_configs.is_empty() {
            return Err("at least one WireGuard configuration is required".into());
        }
        let routes = input
            .wireguard_configs
            .iter()
            .map(|source| narrow_to_relay(source, input.relay_ip))
            .collect::<Result<Vec<_>, _>>()?;
        let mut runtime = state.lock().unwrap();
        runtime.session_status = "validated".into();
        runtime.route_count = routes.len();
        runtime.traffic_mode = input.traffic_mode.clone();
        Ok(json!({
            "sessionStatus": "validated",
            "routeCount": routes.len(),
            "trafficMode": input.traffic_mode,
            "tunnelAddresses": routes.iter().map(|route| route.tunnel_address).collect::<Vec<_>>(),
        }))
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
            difference |=
                usize::from(*left.get(index).unwrap_or(&0) ^ *right.get(index).unwrap_or(&0));
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

        #[test]
        fn token_comparison_checks_length_and_content() {
            assert!(constant_time_equal(b"secret", b"secret"));
            assert!(!constant_time_equal(b"secret", b"secrex"));
            assert!(!constant_time_equal(b"secret", b"secret-long"));
        }
    }
}
