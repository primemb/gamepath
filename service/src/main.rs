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
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_service::{
        Result as ServiceResult, define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    const SERVICE_NAME: &str = "GamePathService";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const DEFAULT_PORT: u16 = 47_983;
    const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
    const SESSION_LEASE: Duration = Duration::from_secs(10);

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
        engine: Option<EngineProcess>,
        lease_deadline: Option<Instant>,
    }

    struct EngineProcess {
        child: Child,
        job: isize,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
        next_id: u64,
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

    fn cleanup_stale_routes() {
        let script = "$i=@(Get-NetAdapter -Name 'GamePath*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifIndex); if($i.Count){Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.InterfaceIndex -in $i -and $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue}";
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
        let state = Arc::new(Mutex::new(RuntimeState {
            session_status: "idle".into(),
            ..RuntimeState::default()
        }));
        let watchdog_state = Arc::clone(&state);
        let watchdog_stop = Arc::clone(&stop);
        let watchdog = thread::spawn(move || {
            while !watchdog_stop.load(Ordering::Acquire) {
                let expired_engine = {
                    let mut runtime = watchdog_state.lock().unwrap();
                    if runtime
                        .lease_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        log_event("session lease expired; stopping packet capture");
                        runtime.lease_deadline = None;
                        runtime.session_status = "idle".into();
                        runtime.route_count = 0;
                        runtime.traffic_mode.clear();
                        runtime.engine.take()
                    } else {
                        None
                    }
                };
                drop(expired_engine);
                thread::sleep(Duration::from_millis(250));
            }
        });
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
        let _ = watchdog.join();
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
            "start-session" => start_session(request.payload, state),
            "session-status" => session_status(state),
            "stop-session" => {
                let mut state = state.lock().unwrap();
                if let Some(mut engine) = state.engine.take() {
                    let _ = engine.request("stop-wireguard-session", json!({}));
                    let _ = engine.child.kill();
                    let _ = engine.child.wait();
                }
                state.session_status = "idle".into();
                state.route_count = 0;
                state.traffic_mode.clear();
                state.lease_deadline = None;
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

    impl EngineProcess {
        fn start() -> Result<Self, String> {
            let executable = env::current_exe()
                .map_err(|error| error.to_string())?
                .parent()
                .ok_or("service executable has no parent directory")?
                .join("gamepath-engine.exe");
            if !executable.is_file() {
                return Err(format!(
                    "native engine is missing: {}",
                    executable.display()
                ));
            }
            let mut child = Command::new(executable)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .creation_flags(0x0800_0000)
                .spawn()
                .map_err(|error| format!("could not start native engine: {error}"))?;
            let job = match create_kill_on_close_job(&child) {
                Ok(job) => job,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            let stdin = child
                .stdin
                .take()
                .ok_or("native engine stdin is unavailable")?;
            let stdout = child
                .stdout
                .take()
                .ok_or("native engine stdout is unavailable")?;
            let mut process = Self {
                child,
                job,
                stdin,
                stdout: BufReader::new(stdout),
                next_id: 1,
            };
            process.request("hello", json!({}))?;
            Ok(process)
        }

        fn request(&mut self, command: &str, payload: Value) -> Result<Value, String> {
            let id = self.next_id;
            self.next_id += 1;
            serde_json::to_writer(
                &mut self.stdin,
                &json!({ "id": id, "command": command, "payload": payload }),
            )
            .map_err(|error| error.to_string())?;
            self.stdin
                .write_all(b"\n")
                .and_then(|_| self.stdin.flush())
                .map_err(|error| format!("native engine request failed: {error}"))?;
            let mut line = String::new();
            self.stdout
                .read_line(&mut line)
                .map_err(|error| format!("native engine response failed: {error}"))?;
            if line.is_empty() {
                return Err("native engine stopped unexpectedly".into());
            }
            let response: Value = serde_json::from_str(&line)
                .map_err(|error| format!("invalid native engine response: {error}"))?;
            if response["id"].as_u64() != Some(id) {
                return Err("native engine returned a mismatched response".into());
            }
            if response["ok"].as_bool() != Some(true) {
                return Err(response["error"]
                    .as_str()
                    .unwrap_or("native engine request failed")
                    .to_owned());
            }
            Ok(response["result"].clone())
        }
    }

    impl Drop for EngineProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            unsafe {
                CloseHandle(self.job);
            }
        }
    }

    fn create_kill_on_close_job(child: &Child) -> Result<isize, String> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job == 0 {
                return Err(format!(
                    "could not create engine job: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            let assigned = if configured != 0 {
                AssignProcessToJobObject(job, child.as_raw_handle() as isize)
            } else {
                0
            };
            if configured == 0 || assigned == 0 {
                let error = std::io::Error::last_os_error();
                CloseHandle(job);
                return Err(format!("could not contain engine process: {error}"));
            }
            Ok(job)
        }
    }

    fn start_session(payload: Value, state: &Mutex<RuntimeState>) -> Result<Value, String> {
        log_event("starting privileged engine session");
        let mut runtime = state.lock().unwrap();
        if let Some(mut current) = runtime.engine.take() {
            let _ = current.child.kill();
            let _ = current.child.wait();
        }
        let mut engine = EngineProcess::start().inspect_err(|error| log_event(error))?;
        log_event("native engine child ready");
        let traffic_mode = payload["trafficMode"].as_str().unwrap_or("all").to_owned();
        let rules = payload["rules"].clone();
        let paths = engine
            .request("start-wireguard-session", payload)
            .inspect_err(|error| log_event(error))?;
        log_event("multipath workers connected");
        let data_plane = engine
            .request("probe-data-plane", json!({}))
            .inspect_err(|error| log_event(error))?;
        log_event("relay benchmark packet returned");
        let capture = engine
            .request(
                "start-packet-capture",
                json!({ "trafficMode": traffic_mode, "rules": rules }),
            )
            .inspect_err(|error| log_event(error))?;
        log_event("Windows packet capture started");
        runtime.session_status = "connected".into();
        runtime.route_count = paths["paths"].as_array().map_or(0, Vec::len);
        runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
        runtime.engine = Some(engine);
        Ok(json!({ "paths": paths, "dataPlane": data_plane, "capture": capture }))
    }

    fn log_event(message: &str) {
        use std::fs::OpenOptions;
        use std::time::{SystemTime, UNIX_EPOCH};

        let path = default_token_file().with_file_name("service.log");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{timestamp} {message}");
        }
    }

    fn session_status(state: &Mutex<RuntimeState>) -> Result<Value, String> {
        let mut runtime = state.lock().unwrap();
        let engine = runtime.engine.as_mut().ok_or("no active network session")?;
        let result = engine.request("wireguard-session-status", json!({}))?;
        runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
        Ok(result)
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
