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
    use gamepath_engine::l2tp::L2tpRuntime;
    use gamepath_engine::mtu::{EffectiveMtu, LINK_MTU};
    use gamepath_engine::netconfig;
    use gamepath_engine::policy::{RuleSpec, compile as compile_policy};
    use gamepath_engine::relay_path::{NodeSpec, SessionMode};
    use gamepath_engine::transport::bind_to_interface;
    use gamepath_engine::wireguard_runtime::{inspect, narrow_to_relay};
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{
        IpAddr, Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
    };
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    use windows_sys::Win32::NetworkManagement::Rras::{
        HRASCONN, RASCONNSTATUSW, RASCS_Disconnected, RASDIALPARAMSW, RASP_PppIp, RASPPPIPW,
        RasDeleteEntryW, RasDialW, RasGetConnectStatusW, RasGetErrorStringW, RasGetProjectionInfoW,
        RasHangUpW,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
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

    /// Handlers that may run at once. The UI makes one request at a time; this
    /// is the ceiling that stops a local process opening threads without end.
    const MAX_CONCURRENT_REQUESTS: usize = 16;
    /// How long the service keeps a session alive without hearing from the
    /// client. The client renews this every few seconds from its main process;
    /// the window is wide enough that a stalled request or a busy engine cannot
    /// tear down a working session, and still short enough that routes do not
    /// outlive a client that has actually died.
    const SESSION_LEASE: Duration = Duration::from_secs(30);
    static L2TP_PROFILE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

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
        /// Remembered so a live rule edit reapplies the session's DNS choice
        /// rather than silently reverting it to the default.
        remote_dns: bool,
        session_rules: Value,
        engine: Option<EngineProcess>,
        l2tp_sessions: Vec<L2tpSession>,
        native_l2tp_direct: bool,
        native_l2tp_status: Value,
        native_l2tp_capture: Value,
        native_l2tp_probe_supported: bool,
        native_l2tp_probe_failures: u32,
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
        /// Absent for callers written before direct sessions existed, all of
        /// which meant a relay session.
        #[serde(default)]
        mode: SessionMode,
        /// A direct session has no relay to narrow the tunnels towards.
        #[serde(default)]
        relay_ip: Option<IpAddr>,
        traffic_mode: String,
        #[serde(default)]
        nodes: Vec<NodeSpec>,
        #[serde(default)]
        wireguard_configs: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct L2tpProbeRequest {
        server: String,
        username: String,
        password: String,
        pre_shared_key: String,
    }

    struct L2tpSession {
        connection: HRASCONN,
        profile_name: String,
        phonebook: Vec<u16>,
        server: String,
        server_address: Ipv4Addr,
        local_address: Ipv4Addr,
        interface_index: u32,
        setup_latency_ms: f64,
        split_tunneling: bool,
        /// MTU of the physical route that carried the L2TP/IPsec session into
        /// Windows RAS. Kept for truthful capture/MSS telemetry.
        uplink_mtu: u16,
        mtu: u16,
        routes: Vec<String>,
    }

    unsafe impl Send for L2tpSession {}

    impl ValidateRequest {
        /// Callers may send the tagged node list or, for WireGuard-only
        /// sessions, the original flat configuration list.
        fn resolved_nodes(&self) -> Vec<NodeSpec> {
            if !self.nodes.is_empty() {
                return self.nodes.clone();
            }
            self.wireguard_configs
                .iter()
                .map(|config| NodeSpec::WireGuard {
                    config: config.clone(),
                    label: None,
                })
                .collect()
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn put_wide(destination: &mut [u16], value: &str, name: &str) -> Result<(), String> {
        let encoded = value.encode_utf16().collect::<Vec<_>>();
        if encoded.len() >= destination.len() {
            return Err(format!("the L2TP {name} is too long"));
        }
        destination[..encoded.len()].copy_from_slice(&encoded);
        destination[encoded.len()] = 0;
        Ok(())
    }

    fn take_wide(value: &[u16]) -> String {
        String::from_utf16_lossy(
            &value[..value
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(value.len())],
        )
    }

    fn ras_error(code: u32) -> String {
        let mut message = [0_u16; 512];
        let result =
            unsafe { RasGetErrorStringW(code, message.as_mut_ptr(), message.len() as u32) };
        if result == 0 {
            format!("{} (RAS error {code})", take_wide(&message).trim())
        } else {
            format!("RAS error {code}")
        }
    }

    fn all_users_phonebook() -> PathBuf {
        let root = env::var_os("PROGRAMDATA").unwrap_or_else(|| OsString::from(r"C:\ProgramData"));
        PathBuf::from(root)
            .join("Microsoft")
            .join("Network")
            .join("Connections")
            .join("Pbk")
            .join("rasphone.pbk")
    }

    fn current_user_phonebook() -> PathBuf {
        let root = env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(
                    env::var_os("USERPROFILE")
                        .unwrap_or_else(|| OsString::from(r"C:\Users\Default")),
                )
                .join("AppData")
                .join("Roaming")
            });
        root.join("Microsoft")
            .join("Network")
            .join("Connections")
            .join("Pbk")
            .join("rasphone.pbk")
    }

    fn run_l2tp_profile_script(
        name: &str,
        server: &str,
        pre_shared_key: &str,
        all_users: bool,
        split_tunneling: bool,
    ) -> Result<(), String> {
        // The PSK travels over the child's anonymous stdin, never its command
        // line. PowerShell owns the supported all-users VPN profile format;
        // dialing and credentials stay in the native RAS API below.
        const SCRIPT: &str = "$ErrorActionPreference='Stop';$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;$a=@{Name=$p.name;ServerAddress=$p.server;TunnelType='L2tp';L2tpPsk=$p.psk;AuthenticationMethod='MSChapv2';EncryptionLevel='Optional';SplitTunneling=$p.splitTunneling;RememberCredential=$false;Force=$true};if($p.allUsers){Get-VpnConnection -Name $p.name -AllUserConnection -ErrorAction SilentlyContinue|Remove-VpnConnection -AllUserConnection -Force -ErrorAction SilentlyContinue;Add-VpnConnection @a -AllUserConnection|Out-Null}else{Get-VpnConnection -Name $p.name -ErrorAction SilentlyContinue|Remove-VpnConnection -Force -ErrorAction SilentlyContinue;Add-VpnConnection @a|Out-Null}";
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .creation_flags(0x0800_0000)
            .spawn()
            .map_err(|error| format!("could not configure the Windows L2TP profile: {error}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            serde_json::to_writer(
                &mut stdin,
                &json!({
                    "name": name,
                    "server": server,
                    "psk": pre_shared_key,
                    "allUsers": all_users,
                    // The non-elevated branch exists only for local live tests;
                    // it needs a default route because it cannot add a /32.
                    "splitTunneling": split_tunneling,
                }),
            )
            .map_err(|error| format!("could not configure the Windows L2TP profile: {error}"))?;
            stdin.flush().map_err(|error| {
                format!("could not configure the Windows L2TP profile: {error}")
            })?;
        }
        let output = child
            .wait_with_output()
            .map_err(|error| format!("could not configure the Windows L2TP profile: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let detail = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "Windows could not create the L2TP/IPsec profile: {}",
                detail.lines().next().unwrap_or("PowerShell failed").trim()
            ))
        }
    }

    fn create_l2tp_profile(
        name: &str,
        server: &str,
        pre_shared_key: &str,
        split_tunneling: bool,
        allow_user_fallback: bool,
    ) -> Result<(PathBuf, bool), String> {
        match run_l2tp_profile_script(name, server, pre_shared_key, true, split_tunneling) {
            Ok(()) => Ok((all_users_phonebook(), split_tunneling)),
            Err(all_users_error) => {
                // A developer console is intentionally not elevated. The real
                // service runs as LocalSystem, but a per-user fallback keeps
                // connection tests useful without weakening the release path.
                if !allow_user_fallback || !env::args().any(|argument| argument == "--console") {
                    return Err(all_users_error);
                }
                run_l2tp_profile_script(name, server, pre_shared_key, false, false)
                    .map(|_| (current_user_phonebook(), false))
                    .map_err(|user_error| {
                        format!("{all_users_error}; per-user fallback also failed: {user_error}")
                    })
            }
        }
    }

    fn l2tp_interface_index(local_address: Ipv4Addr) -> Result<u32, String> {
        netconfig::wait_for_interface_index(local_address, Duration::from_secs(5))
            .map_err(|error| format!("could not inspect the L2TP adapter: {error}"))
    }

    fn configure_l2tp_mtu(interface_index: u32, desired: u16) -> Result<u16, String> {
        let actual = netconfig::set_interface_mtu(interface_index, desired)
            .map_err(|error| format!("could not configure the L2TP MTU: {error}"))?;
        let actual =
            u16::try_from(actual).map_err(|_| "Windows returned an invalid L2TP MTU".to_owned())?;
        if actual != desired {
            return Err(format!(
                "Windows kept the L2TP MTU at {actual}; GamePath needs {desired} to prevent nested-tunnel fragmentation"
            ));
        }
        Ok(actual)
    }

    /// Looks up the NIC MTU for the route Windows would use to reach the VPN
    /// server before the RAS connection changes any default routes. A failed
    /// lookup is intentionally non-fatal; callers retain the 1500-byte safe
    /// fallback so users on older Windows builds can still connect.
    fn route_link_mtu(destination: Ipv4Addr) -> Result<u16, String> {
        netconfig::route_link_mtu(destination)
            .map_err(|error| format!("could not inspect route MTU for {destination}: {error}"))
    }

    fn l2tp_server_ipv4(server: &str) -> Result<Ipv4Addr, String> {
        let mut addresses = (server, 1701)
            .to_socket_addrs()
            .map_err(|error| format!("could not resolve the L2TP server: {error}"))?;
        addresses
            .find_map(|address| match address.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .ok_or("the L2TP server did not resolve to IPv4".into())
    }

    fn close_l2tp(connection: HRASCONN, phonebook: &[u16], profile_name: &str) {
        if connection != 0 {
            unsafe {
                RasHangUpW(connection);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
                status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
                let result = unsafe { RasGetConnectStatusW(connection, &mut status) };
                if result != 0 || status.rasconnstate == RASCS_Disconnected {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        let profile = wide(profile_name);
        unsafe {
            RasDeleteEntryW(phonebook.as_ptr(), profile.as_ptr());
        }
    }

    impl L2tpSession {
        fn dial(
            profile_name: String,
            server: &str,
            username: &str,
            password: &str,
            pre_shared_key: &str,
            split_tunneling: bool,
            allow_user_fallback: bool,
        ) -> Result<Self, String> {
            if server.trim().is_empty()
                || username.trim().is_empty()
                || password.is_empty()
                || pre_shared_key.is_empty()
            {
                return Err(
                    "L2TP/IPsec needs a server, pre-shared key, username and password".into(),
                );
            }
            // Resolve and inspect the physical route before RAS adds any VPN
            // routes. The RAS adapter must leave room for L2TP/IPsec inside
            // that real uplink, not inside a presumed 1500-byte Ethernet link.
            let server_address = l2tp_server_ipv4(server)?;
            let uplink_mtu = match route_link_mtu(server_address) {
                Ok(mtu) => mtu,
                Err(error) => {
                    log_event(&format!(
                        "{error}; L2TP will use the safe 1500-byte fallback"
                    ));
                    LINK_MTU
                }
            };
            let desired_mtu =
                EffectiveMtu::for_session(SessionMode::Direct, ["l2tp"], uplink_mtu).mtu;
            let (phonebook_path, actual_split_tunneling) = create_l2tp_profile(
                &profile_name,
                server,
                pre_shared_key,
                split_tunneling,
                allow_user_fallback,
            )?;
            let phonebook = wide(&phonebook_path.to_string_lossy());
            let mut params: RASDIALPARAMSW = unsafe { std::mem::zeroed() };
            params.dwSize = std::mem::size_of::<RASDIALPARAMSW>() as u32;
            if let Err(error) = put_wide(&mut params.szEntryName, &profile_name, "profile name")
                .and_then(|_| put_wide(&mut params.szUserName, username, "username"))
                .and_then(|_| put_wide(&mut params.szPassword, password, "password"))
            {
                close_l2tp(0, &phonebook, &profile_name);
                return Err(error);
            }
            let started = Instant::now();
            let mut connection: HRASCONN = 0;
            let status = unsafe {
                RasDialW(
                    std::ptr::null(),
                    phonebook.as_ptr(),
                    &params,
                    0,
                    std::ptr::null(),
                    &mut connection,
                )
            };
            params.szUserName.fill(0);
            params.szPassword.fill(0);
            if status != 0 {
                close_l2tp(connection, &phonebook, &profile_name);
                return Err(format!(
                    "L2TP/IPsec connection failed: {}",
                    ras_error(status)
                ));
            }
            let mut projection: RASPPPIPW = unsafe { std::mem::zeroed() };
            projection.dwSize = std::mem::size_of::<RASPPPIPW>() as u32;
            let mut projection_size = std::mem::size_of::<RASPPPIPW>() as u32;
            let projection_status = unsafe {
                RasGetProjectionInfoW(
                    connection,
                    RASP_PppIp,
                    (&mut projection as *mut RASPPPIPW).cast(),
                    &mut projection_size,
                )
            };
            if projection_status != 0 || projection.dwError != 0 {
                close_l2tp(connection, &phonebook, &profile_name);
                return Err(format!(
                    "L2TP connected but did not receive an IPv4 address: {}",
                    ras_error(if projection_status != 0 {
                        projection_status
                    } else {
                        projection.dwError
                    })
                ));
            }
            let local_address: Ipv4Addr = match take_wide(&projection.szIpAddress).parse() {
                Ok(address) => address,
                Err(_) => {
                    close_l2tp(connection, &phonebook, &profile_name);
                    return Err("L2TP connected but returned an invalid IPv4 address".into());
                }
            };
            let interface_index = match l2tp_interface_index(local_address) {
                Ok(index) => index,
                Err(error) => {
                    close_l2tp(connection, &phonebook, &profile_name);
                    return Err(error);
                }
            };
            let mtu = if allow_user_fallback && !actual_split_tunneling {
                // A non-elevated console probe cannot tune interfaces. It does
                // not carry a session, so the production MTU invariant is not
                // weakened by leaving this short-lived fallback alone.
                desired_mtu
            } else {
                match configure_l2tp_mtu(interface_index, desired_mtu) {
                    Ok(mtu) => mtu,
                    Err(error) => {
                        close_l2tp(connection, &phonebook, &profile_name);
                        return Err(error);
                    }
                }
            };
            Ok(Self {
                connection,
                profile_name,
                phonebook,
                server: server.to_owned(),
                server_address,
                local_address,
                interface_index,
                setup_latency_ms: started.elapsed().as_secs_f64() * 1000.0,
                split_tunneling: actual_split_tunneling,
                uplink_mtu,
                mtu,
                routes: Vec::new(),
            })
        }

        fn add_route(&mut self, prefix: &str) -> Result<(), String> {
            if !self.split_tunneling {
                // Non-elevated live-test fallback owns the default route.
                return Ok(());
            }
            let (destination, length) = split_ipv4_prefix(prefix)?;
            netconfig::add_route(destination, length, self.interface_index)
                .map_err(|error| format!("could not add the L2TP route: {error}"))?;
            if !self.routes.iter().any(|route| route == prefix) {
                self.routes.push(prefix.to_owned());
            }
            Ok(())
        }

        fn remove_routes(&mut self) {
            for prefix in self.routes.drain(..) {
                // The prefix was parsed before it was ever installed, so a
                // failure here would mean it was never a route to begin with.
                if let Ok((destination, length)) = split_ipv4_prefix(&prefix) {
                    netconfig::remove_route(destination, length, self.interface_index);
                }
            }
        }

        fn runtime(&self, route: usize) -> L2tpRuntime {
            let third = 200_u8.saturating_add((route % 50) as u8);
            L2tpRuntime {
                local_address: self.local_address,
                virtual_address: Ipv4Addr::new(10, 203, third, 2),
                server_address: self.server_address,
                interface_index: self.interface_index,
                mtu: self.mtu,
                setup_latency_ms: self.setup_latency_ms,
                profile_name: self.profile_name.clone(),
                phonebook_path: String::from_utf16_lossy(
                    &self.phonebook[..self.phonebook.len().saturating_sub(1)],
                ),
            }
        }

        fn is_connected(&self) -> bool {
            if self.connection == 0 {
                return false;
            }
            let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
            status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
            let result = unsafe { RasGetConnectStatusW(self.connection, &mut status) };
            result == 0 && status.rasconnstate != RASCS_Disconnected
        }
    }

    impl Drop for L2tpSession {
        fn drop(&mut self) {
            self.remove_routes();
            close_l2tp(self.connection, &self.phonebook, &self.profile_name);
        }
    }

    fn connect_l2tp_nodes(
        nodes: &mut [NodeSpec],
        relay: Option<Ipv4Addr>,
        split_tunneling: bool,
    ) -> Result<Vec<L2tpSession>, String> {
        let mut sessions = Vec::new();
        for (index, node) in nodes.iter_mut().enumerate() {
            let NodeSpec::L2tp {
                server,
                username,
                password,
                pre_shared_key,
                runtime,
                ..
            } = node
            else {
                continue;
            };
            let profile_name = format!(
                "GamePath-L2TP-{}-{}-{}",
                std::process::id(),
                index + 1,
                L2TP_PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            );
            let mut session = L2tpSession::dial(
                profile_name,
                server,
                username,
                password,
                pre_shared_key,
                split_tunneling,
                false,
            )
            .map_err(|error| format!("route {}: {error}", index + 1))?;
            if let Some(relay) = relay {
                session
                    .add_route(&format!("{relay}/32"))
                    .map_err(|error| format!("route {}: {error}", index + 1))?;
                // In relay mode this adapter exists only to carry GamePath's
                // IPv4 frames to the relay, so an IPv6 default route picked up
                // from the link's Router Advertisements is never wanted.
                //
                // A direct session is deliberately left alone. There Windows
                // routes the user's own traffic through this adapter natively,
                // and taking IPv6 off it would push that traffic onto the
                // physical interface instead - turning a tunnelled protocol
                // into a leak rather than fixing anything.
                //
                // Non-fatal either way: a session that carries traffic is worth
                // more than this, and IPv6 exposure is reported separately.
                if let Err(error) = netconfig::disable_ipv6_default_route(session.interface_index) {
                    log_event(&format!(
                        "route {}: {error}; the L2TP adapter may keep an IPv6 default route",
                        index + 1
                    ));
                }
            }
            *runtime = Some(session.runtime(index + 1));
            // Relay workers keep the login only inside the privileged engine
            // child so they can redial a RAS connection after a real drop. The
            // PSK is already sealed in the temporary Windows profile and does
            // not cross the child-process boundary.
            pre_shared_key.clear();
            sessions.push(session);
        }
        Ok(sessions)
    }

    /// Splits an `a.b.c.d/len` prefix into the pair the routing API takes.
    fn split_ipv4_prefix(value: &str) -> Result<(Ipv4Addr, u8), String> {
        let (address, length) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid IPv4 route: {value}"))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("invalid IPv4 route: {value}"))?;
        let length: u8 = length
            .parse()
            .map_err(|_| format!("invalid IPv4 route: {value}"))?;
        if length > 32 {
            return Err(format!("invalid IPv4 route: {value}"));
        }
        Ok((address, length))
    }

    fn canonical_ipv4_prefix(value: &str) -> Result<String, String> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid IPv4 route: {value}"))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| format!("L2TP direct split mode cannot route IPv6 target {value}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("invalid IPv4 route: {value}"))?;
        if prefix > 32 {
            return Err(format!("invalid IPv4 route: {value}"));
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        Ok(format!(
            "{}/{}",
            Ipv4Addr::from(u32::from(address) & mask),
            prefix
        ))
    }

    /// Windows RAS split tunnelling is route based. IP and exact-hostname
    /// targets map cleanly to routes; process/folder ownership and wildcard
    /// DNS matching require a WFP callout and are deliberately rejected.
    fn direct_l2tp_prefixes(rules: &Value) -> Result<Vec<String>, String> {
        let rules: Vec<RuleSpec> = serde_json::from_value(rules.clone())
            .map_err(|error| format!("invalid split targets: {error}"))?;
        if rules.is_empty() {
            return Ok(Vec::new());
        }
        let plan = compile_policy("split", &rules)?;
        if !plan.application_paths.is_empty() || !plan.folder_prefixes.is_empty() {
            return Err(
                "L2TP direct split mode supports IP and exact hostname targets. Application and folder targets need all-traffic mode or a WireGuard/OpenVPN direct node."
                    .into(),
            );
        }
        let mut prefixes = std::collections::BTreeSet::new();
        for network in plan.ip_networks {
            prefixes.insert(canonical_ipv4_prefix(&network)?);
        }
        for hostname in plan.hostnames {
            if hostname.starts_with("*.") {
                return Err(
                    "L2TP direct split mode cannot keep wildcard hostnames updated. Use an exact hostname, an IP range, or all-traffic mode."
                        .into(),
                );
            }
            let addresses = (hostname.as_str(), 0)
                .to_socket_addrs()
                .map_err(|error| format!("could not resolve split target {hostname}: {error}"))?;
            let mut resolved = 0;
            for address in addresses {
                if let IpAddr::V4(address) = address.ip() {
                    prefixes.insert(format!("{address}/32"));
                    resolved += 1;
                }
            }
            if resolved == 0 {
                return Err(format!(
                    "split target {hostname} did not resolve to an IPv4 address"
                ));
            }
        }
        Ok(prefixes.into_iter().collect())
    }

    fn apply_direct_l2tp_prefixes(
        session: &mut L2tpSession,
        prefixes: &[String],
    ) -> Result<(), String> {
        session.remove_routes();
        for prefix in prefixes {
            session.add_route(prefix)?;
        }
        Ok(())
    }

    fn apply_direct_l2tp_routes(session: &mut L2tpSession, rules: &Value) -> Result<(), String> {
        let prefixes = direct_l2tp_prefixes(rules)?;
        apply_direct_l2tp_prefixes(session, &prefixes)
    }

    fn probe_direct_l2tp(session: &L2tpSession, timeout: Duration) -> (bool, f64) {
        let started = Instant::now();
        let reachable = (|| -> Result<(), String> {
            let socket = UdpSocket::bind(SocketAddrV4::new(session.local_address, 0))
                .map_err(|error| error.to_string())?;
            bind_to_interface(
                &socket,
                IpAddr::V4(session.local_address),
                session.interface_index,
            )
            .map_err(|error| error.to_string())?;
            socket
                .set_read_timeout(Some(timeout))
                .map_err(|error| error.to_string())?;
            socket
                .set_write_timeout(Some(timeout))
                .map_err(|error| error.to_string())?;
            socket
                .connect(SocketAddrV4::new(gamepath_engine::BENCHMARK_TARGET, 53))
                .map_err(|error| error.to_string())?;
            // A standard recursive A query for the DNS root. The fixed ID is
            // checked in the response; no name or user data leaves the host.
            let query = [
                0x47, 0x50, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x01,
            ];
            socket.send(&query).map_err(|error| error.to_string())?;
            let mut response = [0_u8; 512];
            let length = socket
                .recv(&mut response)
                .map_err(|error| error.to_string())?;
            if length < 12 || response[..2] != query[..2] || response[2] & 0x80 == 0 {
                return Err("invalid DNS probe response".into());
            }
            Ok(())
        })()
        .is_ok();
        (reachable, started.elapsed().as_secs_f64() * 1000.0)
    }

    fn is_globally_routable_ipv6(address: std::net::Ipv6Addr) -> bool {
        let first = address.segments()[0];
        !address.is_loopback()
            && !address.is_unspecified()
            && first & 0xffc0 != 0xfe80
            && first & 0xfe00 != 0xfc00
    }

    fn ipv6_route_interface() -> Option<u32> {
        let source = UdpSocket::bind("[::]:0")
            .and_then(|socket| {
                socket.connect("[2606:4700:4700::1111]:53")?;
                socket.local_addr()
            })
            .ok()
            .and_then(|address| match address.ip() {
                IpAddr::V6(address) if is_globally_routable_ipv6(address) => Some(address),
                _ => None,
            })?;
        let script = format!(
            "$i=Get-NetIPAddress -AddressFamily IPv6 -IPAddress '{source}' -ErrorAction SilentlyContinue|Select-Object -First 1 -ExpandProperty InterfaceIndex;if($null-eq $i){{exit 2}};[Console]::Out.Write($i)"
        );
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(Stdio::null())
            .creation_flags(0x0800_0000)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
            .flatten()
    }

    fn l2tp_ipv6_exposure(session: &L2tpSession) -> Value {
        classify_l2tp_ipv6(ipv6_route_interface(), session.interface_index)
    }

    fn classify_l2tp_ipv6(route_interface: Option<u32>, l2tp_interface: u32) -> Value {
        let carried = route_interface == Some(l2tp_interface);
        json!({
            "carried": carried,
            "systemHasRoute": route_interface.is_some() && !carried,
        })
    }

    fn native_l2tp_result(
        session: &L2tpSession,
        label: &str,
        traffic_mode: &str,
        target_count: usize,
    ) -> (Value, Value, Value) {
        let (reachable, latency_ms) = probe_direct_l2tp(session, Duration::from_secs(2));
        let mtu = EffectiveMtu::for_session(SessionMode::Direct, ["l2tp"], session.uplink_mtu);
        debug_assert_eq!(mtu.mtu, session.mtu);
        let paths = json!({
            "state": "connected",
            "mode": "direct",
            "paths": [{
                "route": 1,
                "pathKind": "l2tp",
                "label": label,
                "endpoint": session.server,
                "reachable": reachable,
                "latencyMs": if reachable { Some(latency_ms) } else { None },
                "handshakeMs": session.setup_latency_ms,
                "handshakeRoundTrips": Value::Null,
                "packetsSent": 0,
                "packetsReceived": 0,
                "bytesSent": 0,
                "bytesReceived": 0,
                "probesSent": 1,
                "probesReceived": if reachable { 1 } else { 0 },
                "probesLost": if reachable { 0 } else { 1 },
                // Native L2TP routing is polled one probe at a time rather
                // than by a worker keeping an EWMA, so the latest probe is the
                // whole of what is currently known about loss.
                "lossPercent": if reachable { 0.0 } else { 100.0 },
                "lastError": Value::Null,
            }],
            "skippedRoutes": [],
            "strategy": "single-path",
            "selectedRoutes": [1],
            "degradedRoutes": [],
            "queueDepth": [0],
            "droppedPackets": [0],
            "queueCapacity": Value::Null,
            "effectiveMtu": mtu.mtu,
            "transportOverhead": mtu.overhead,
        });
        let data_plane = json!({
            "reachable": reachable,
            "latencyMs": latency_ms,
            "benchmarkServer": gamepath_engine::BENCHMARK_TARGET.to_string(),
            "relayToServerMs": Value::Null,
        });
        let ipv6 = l2tp_ipv6_exposure(session);
        let capture = json!({
            "state": "routing",
            "backend": "windows-ras",
            "adapterIndex": session.interface_index,
            "splitTunneling": session.split_tunneling,
            "trafficMode": traffic_mode,
            "targetCount": target_count,
            "effectiveMtu": mtu.mtu,
            "tcpMss": mtu.tcp_mss(),
            "transportOverhead": mtu.overhead,
            "ipv6": ipv6,
        });
        (paths, data_plane, capture)
    }

    pub fn run() -> ServiceResult<()> {
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
        let state = Arc::new(Mutex::new(RuntimeState {
            session_status: "idle".into(),
            ..RuntimeState::default()
        }));
        let watchdog_state = Arc::clone(&state);
        let watchdog_stop = Arc::clone(&stop);
        let watchdog = thread::spawn(move || {
            while !watchdog_stop.load(Ordering::Acquire) {
                let expired_session = {
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
                        runtime.session_rules = Value::Null;
                        runtime.native_l2tp_direct = false;
                        runtime.native_l2tp_status = Value::Null;
                        runtime.native_l2tp_capture = Value::Null;
                        runtime.native_l2tp_probe_supported = false;
                        runtime.native_l2tp_probe_failures = 0;
                        Some((
                            runtime.engine.take(),
                            std::mem::take(&mut runtime.l2tp_sessions),
                        ))
                    } else {
                        None
                    }
                };
                if let Some((engine, sessions)) = expired_session {
                    if let Some(mut engine) = engine {
                        let _ = engine.request("stop-wireguard-session", json!({}));
                    }
                    drop(sessions);
                }
                thread::sleep(Duration::from_millis(250));
            }
        });
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
                    let state = Arc::clone(&state);
                    let in_flight = Arc::clone(&in_flight);
                    thread::spawn(move || {
                        handle_connection(stream, &token, &state);
                        in_flight.fetch_sub(1, Ordering::AcqRel);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(error) => return Err(error),
            }
        }
        let _ = watchdog.join();
        let (engine, sessions) = {
            let mut runtime = state.lock().unwrap();
            (
                runtime.engine.take(),
                std::mem::take(&mut runtime.l2tp_sessions),
            )
        };
        if let Some(mut engine) = engine {
            let _ = engine.request("stop-wireguard-session", json!({}));
        }
        drop(sessions);
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

    fn handle_connection(mut stream: TcpStream, expected_token: &str, state: &Mutex<RuntimeState>) {
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
                Ok(request) => handle_request(request, expected_token, state),
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
            "probe-l2tp-node" => probe_l2tp_node(request.payload),
            "start-session" => start_session(request.payload, state),
            "update-session-rules" => update_session_rules(request.payload, state),
            "session-status" => session_status(state),
            "stop-session" => {
                let mut state = state.lock().unwrap();
                if let Some(mut engine) = state.engine.take() {
                    let _ = engine.request("stop-wireguard-session", json!({}));
                    let _ = engine.child.kill();
                    let _ = engine.child.wait();
                }
                state.l2tp_sessions.clear();
                state.session_status = "idle".into();
                state.route_count = 0;
                state.traffic_mode.clear();
                state.remote_dns = false;
                state.session_rules = Value::Null;
                state.native_l2tp_direct = false;
                state.native_l2tp_status = Value::Null;
                state.native_l2tp_capture = Value::Null;
                state.native_l2tp_probe_supported = false;
                state.native_l2tp_probe_failures = 0;
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

    fn probe_l2tp_node(payload: Value) -> Result<Value, String> {
        let input: L2tpProbeRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid L2TP test request: {error}"))?;
        let profile = format!(
            "GamePath-L2TP-Probe-{}-{}",
            std::process::id(),
            L2TP_PROFILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let session = L2tpSession::dial(
            profile,
            &input.server,
            &input.username,
            &input.password,
            &input.pre_shared_key,
            true,
            true,
        )?;
        let (reachable, data_latency_ms) = probe_direct_l2tp(&session, Duration::from_secs(2));
        if !reachable {
            return Err(
                "Windows authenticated L2TP/IPsec, but no data returned through the VPN adapter"
                    .into(),
            );
        }
        Ok(json!({
            "reachable": reachable,
            "server": session.server.clone(),
            "assignedIpv4": session.local_address,
            "interfaceIndex": session.interface_index,
            "setupLatencyMs": session.setup_latency_ms,
            "dataLatencyMs": data_latency_ms,
        }))
    }

    fn start_session(mut payload: Value, state: &Mutex<RuntimeState>) -> Result<Value, String> {
        log_event("starting privileged network session");
        let mut runtime = state.lock().unwrap();
        if let Some(mut current) = runtime.engine.take() {
            let _ = current.child.kill();
            let _ = current.child.wait();
        }
        runtime.l2tp_sessions.clear();
        runtime.native_l2tp_direct = false;
        runtime.native_l2tp_status = Value::Null;
        runtime.native_l2tp_capture = Value::Null;
        runtime.native_l2tp_probe_supported = false;
        runtime.native_l2tp_probe_failures = 0;
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
        let rules = payload["rules"].clone();
        if request.mode == SessionMode::Direct
            && matches!(nodes.as_slice(), [NodeSpec::L2tp { .. }])
        {
            let label = nodes[0]
                .label()
                .unwrap_or_else(|| nodes[0].default_label(1));
            // Reject selectors Windows routes cannot express before creating a
            // VPN profile or changing any route.
            let direct_prefixes = if traffic_mode == "split" {
                direct_l2tp_prefixes(&rules)?
            } else {
                Vec::new()
            };
            let mut l2tp_sessions = connect_l2tp_nodes(&mut nodes, None, traffic_mode == "split")?;
            let session = l2tp_sessions
                .first_mut()
                .ok_or("the L2TP direct session did not create a Windows connection")?;
            if traffic_mode == "split" {
                apply_direct_l2tp_prefixes(session, &direct_prefixes)?;
            }
            let target_count = rules.as_array().map_or(0, Vec::len);
            let (paths, data_plane, capture) =
                native_l2tp_result(session, &label, &traffic_mode, target_count);
            if data_plane["reachable"] != json!(true) {
                return Err(
                    "Windows connected L2TP/IPsec, but no data returned through the VPN adapter"
                        .into(),
                );
            }
            runtime.session_status = "connected".into();
            runtime.route_count = 1;
            runtime.traffic_mode = traffic_mode;
            runtime.remote_dns = remote_dns;
            runtime.session_rules = rules;
            runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
            runtime.native_l2tp_direct = true;
            runtime.native_l2tp_status = paths.clone();
            runtime.native_l2tp_capture = capture.clone();
            runtime.native_l2tp_probe_supported = true;
            runtime.native_l2tp_probe_failures = 0;
            runtime.l2tp_sessions = l2tp_sessions;
            log_event("native Windows L2TP direct routing started");
            return Ok(json!({ "paths": paths, "dataPlane": data_plane, "capture": capture }));
        }
        // Starting the engine child and dialling L2TP do not depend on each
        // other, and the dial is the long pole in bringing a session up: IKE
        // negotiation plus waiting for the RAS adapter to appear takes seconds
        // during which the engine would not even have been spawned yet. The
        // child only has to exist before it is asked to start the session, so
        // the two run together and the session begins roughly one of them
        // sooner.
        let engine_start = thread::spawn(EngineProcess::start);
        let l2tp_sessions = match connect_l2tp_nodes(&mut nodes, relay_address, true) {
            Ok(sessions) => sessions,
            Err(error) => {
                // `EngineProcess` kills its child when dropped, so collecting
                // the thread here is what stops a failed dial from leaving an
                // orphaned engine behind.
                drop(engine_start.join());
                return Err(error);
            }
        };
        payload["nodes"] = serde_json::to_value(&nodes)
            .map_err(|error| format!("could not prepare L2TP runtime: {error}"))?;
        let mut engine = engine_start
            .join()
            .map_err(|_| "the native engine panicked while starting".to_owned())?
            .inspect_err(|error| log_event(error))?;
        log_event("native engine child ready");
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
                json!({ "trafficMode": traffic_mode, "rules": rules, "remoteDns": remote_dns }),
            )
            .inspect_err(|error| log_event(error))?;
        log_event("Windows packet capture started");
        runtime.session_status = "connected".into();
        runtime.route_count = paths["paths"].as_array().map_or(0, Vec::len);
        runtime.traffic_mode = traffic_mode;
        runtime.remote_dns = remote_dns;
        runtime.session_rules = rules;
        runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
        runtime.engine = Some(engine);
        runtime.l2tp_sessions = l2tp_sessions;
        Ok(json!({ "paths": paths, "dataPlane": data_plane, "capture": capture }))
    }

    fn update_session_rules(payload: Value, state: &Mutex<RuntimeState>) -> Result<Value, String> {
        let rules = payload
            .get("rules")
            .filter(|rules| rules.is_array())
            .cloned()
            .ok_or("live target update requires a rules array")?;
        let mut runtime = state.lock().unwrap();
        if runtime.session_status != "connected" || runtime.traffic_mode != "split" {
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
            runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
            runtime.native_l2tp_capture["state"] =
                json!(if target_count == 0 { "idle" } else { "routing" });
            runtime.native_l2tp_capture["targetCount"] = json!(target_count);
            log_event("native L2TP split routes updated without reconnecting");
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
            runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
            log_event("split capture paused because no targets are enabled");
            return Ok(json!({
                "state": "idle",
                "trafficMode": "split",
                "targetCount": 0,
            }));
        }
        let remote_dns = runtime.remote_dns;
        let update = json!({ "trafficMode": "split", "rules": rules, "remoteDns": remote_dns });
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
                    engine.request(
                        "start-packet-capture",
                        json!({ "trafficMode": "split", "rules": previous_rules, "remoteDns": remote_dns }),
                    )
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
        runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
        log_event("split capture targets updated without restarting the session");
        Ok(capture)
    }

    fn log_event(message: &str) {
        gamepath_engine::log_info!("{message}");
    }

    fn session_status(state: &Mutex<RuntimeState>) -> Result<Value, String> {
        let mut runtime = state.lock().unwrap();
        if runtime.native_l2tp_direct {
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
                runtime.native_l2tp_probe_failures =
                    runtime.native_l2tp_probe_failures.saturating_add(1);
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
            runtime.native_l2tp_status = result.clone();
            let mut capture = runtime.native_l2tp_capture.clone();
            capture["state"] = if connected {
                if capture["trafficMode"] == json!("split")
                    && capture["targetCount"].as_u64() == Some(0)
                {
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
            runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
            return Ok(result);
        }
        let engine = runtime.engine.as_mut().ok_or("no active network session")?;
        let mut result = engine.request("wireguard-session-status", json!({}))?;
        let capture = engine.request("packet-capture-status", json!({}))?;
        if let Some(object) = result.as_object_mut() {
            object.insert("capture".into(), capture);
        }
        runtime.lease_deadline = Some(Instant::now() + SESSION_LEASE);
        Ok(result)
    }

    fn validate_runtime(payload: Value, state: &Mutex<RuntimeState>) -> Result<Value, String> {
        let input: ValidateRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid runtime request: {error}"))?;
        if input.traffic_mode != "all" && input.traffic_mode != "split" {
            return Err("traffic mode must be all or split".into());
        }
        let nodes = input.resolved_nodes();
        if nodes.is_empty() {
            return Err(
                "at least one WireGuard, OpenVPN, L2TP/IPsec, or SOCKS5 node is required".into(),
            );
        }
        // A direct session has no relay behind the node, so the node itself has
        // to be able to route. Catch that here, before anything is opened.
        if input.mode == SessionMode::Direct {
            if nodes.len() != 1 {
                return Err(format!(
                    "direct mode sends traffic through exactly one node, but {} are enabled. \
                     Enable a single WireGuard, OpenVPN, or L2TP/IPsec node, or switch to relay mode to combine them.",
                    nodes.len()
                ));
            }
            if !nodes[0].supports_direct() {
                return Err(format!(
                    "{} cannot carry a direct session on its own. Use a WireGuard, OpenVPN, or L2TP/IPsec node for \
                     direct mode, or set up a relay to reach this proxy through.",
                    nodes[0].describe()
                ));
            }
        }
        let mut tunnel_addresses = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let route = index + 1;
            node.validate()
                .map_err(|error| format!("route {route}: {error}"))?;
            // A proxy on this machine reaches its own upstream over the default
            // route. In all-traffic mode the tunnel owns that route, so the
            // proxy's forwarded traffic would be captured and fed back into it.
            if input.traffic_mode == "all" && node.is_loopback_proxy() {
                return Err(format!(
                    "route {route} ({}) runs on this PC and cannot be used in all-traffic mode, \
                     because its own upstream traffic would be captured and looped back. \
                     Use split-tunnel mode for a local proxy, or add a remote SOCKS5 proxy.",
                    node.describe()
                ));
            }
            if let NodeSpec::WireGuard { config, .. } = node {
                // A relay session narrows the tunnel to the relay alone; a
                // direct session keeps the routes the provider shipped.
                let runtime = match input.relay_ip.filter(|_| input.mode == SessionMode::Relay) {
                    Some(relay_ip) => narrow_to_relay(config, relay_ip),
                    None if input.mode == SessionMode::Relay => {
                        Err("a relay session needs the relay address".to_owned())
                    }
                    None => inspect(config),
                };
                tunnel_addresses.push(
                    runtime
                        .map_err(|error| format!("route {route}: {error}"))?
                        .tunnel_address,
                );
            }
        }
        let mut runtime = state.lock().unwrap();
        runtime.session_status = "validated".into();
        runtime.route_count = nodes.len();
        runtime.traffic_mode = input.traffic_mode.clone();
        Ok(json!({
            "sessionStatus": "validated",
            "mode": input.mode.as_str(),
            "routeCount": nodes.len(),
            "trafficMode": input.traffic_mode,
            "tunnelAddresses": tunnel_addresses,
            "nodeKinds": nodes.iter().map(NodeSpec::kind).collect::<Vec<_>>(),
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

        /// Accepts one connection and hands it to `handle_connection`, the way
        /// the serve loop does.
        fn serve_one(listener: TcpListener) -> thread::JoinHandle<Duration> {
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let state = Mutex::new(RuntimeState::default());
                let started = Instant::now();
                handle_connection(stream, "token", &state);
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
                    .write_all(
                        b"{\"id\":7,\"command\":\"status\",\"token\":\"token\"}
",
                    )
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
            let state = Mutex::new(RuntimeState::default());
            handle_connection(stream, "token", &state);
            let response = client.join().unwrap();
            let parsed: Value = serde_json::from_str(&response).unwrap();
            // The id has to come back, or the client cannot match the reply to
            // its request and reports a mismatch instead of the real outcome.
            assert_eq!(parsed["id"], serde_json::json!(7), "got: {response}");
            assert_eq!(parsed["ok"], serde_json::json!(true), "got: {response}");
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
            assert_eq!(parsed["ok"], serde_json::json!(true));
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
            assert_eq!(parsed["ok"], serde_json::json!(false));
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

        const WIREGUARD_CONFIG: &str = "[Interface]\nPrivateKey = key\nAddress = 10.88.0.2/32\n\n[Peer]\nPublicKey = peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n";
        const OPENVPN_CONFIG: &str = "client\ndev tun\nremote vpn.example 1194 udp\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIBIjCByaADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3QgQ0Ew\n-----END CERTIFICATE-----\n</ca>\n";

        fn validate(traffic_mode: &str, nodes: Value) -> Result<Value, String> {
            validate_runtime(
                json!({
                    "relayIp": "203.0.113.8",
                    "trafficMode": traffic_mode,
                    "nodes": nodes,
                }),
                &Mutex::new(RuntimeState::default()),
            )
        }

        #[test]
        fn a_wireguard_and_socks5_pair_validates_together() {
            let result = validate(
                "split",
                json!([
                    { "kind": "wireguard", "config": WIREGUARD_CONFIG },
                    { "kind": "socks5", "host": "127.0.0.1", "port": 2080 },
                ]),
            )
            .unwrap();
            assert_eq!(result["routeCount"], 2);
            assert_eq!(result["nodeKinds"][0], "wireguard");
            assert_eq!(result["nodeKinds"][1], "socks5");
            // Only WireGuard routes have a tunnel address to narrow.
            assert_eq!(result["tunnelAddresses"].as_array().unwrap().len(), 1);
        }

        #[test]
        fn a_local_proxy_is_refused_in_all_traffic_mode() {
            let error = validate(
                "all",
                json!([{ "kind": "socks5", "host": "127.0.0.1", "port": 2080 }]),
            )
            .err()
            .unwrap();
            assert!(error.contains("looped back"), "{error}");
            // The same node is fine when only selected traffic is captured.
            assert!(
                validate(
                    "split",
                    json!([{ "kind": "socks5", "host": "127.0.0.1", "port": 2080 }]),
                )
                .is_ok()
            );
            // A remote proxy is fine in either mode.
            assert!(
                validate(
                    "all",
                    json!([{ "kind": "socks5", "host": "203.0.113.9", "port": 1080 }]),
                )
                .is_ok()
            );
        }

        fn validate_direct(nodes: Value) -> Result<Value, String> {
            // A direct session sends no relay address at all.
            validate_runtime(
                json!({ "mode": "direct", "trafficMode": "split", "nodes": nodes }),
                &Mutex::new(RuntimeState::default()),
            )
        }

        #[test]
        fn a_direct_session_keeps_the_nodes_own_routes() {
            let result =
                validate_direct(json!([{ "kind": "wireguard", "config": WIREGUARD_CONFIG }]))
                    .unwrap();
            assert_eq!(result["mode"], "direct");
            assert_eq!(result["routeCount"], 1);
            assert_eq!(result["tunnelAddresses"][0], "10.88.0.2");
            // The default is still a relay session, for callers that send no mode.
            assert_eq!(
                validate(
                    "split",
                    json!([{ "kind": "wireguard", "config": WIREGUARD_CONFIG }])
                )
                .unwrap()["mode"],
                "relay"
            );

            // OpenVPN is also a tunnelling node: it is valid as the direct
            // session's only hop and needs neither a relay address nor a
            // WireGuard runtime inspection.
            let openvpn = validate_direct(json!([{
                "kind": "openvpn",
                "config": OPENVPN_CONFIG,
                "username": "someone",
                "password": "secret",
            }]))
            .unwrap();
            assert_eq!(openvpn["mode"], "direct");
            assert_eq!(openvpn["routeCount"], 1);
            assert_eq!(openvpn["nodeKinds"][0], "openvpn");

            let l2tp = validate_direct(json!([{
                "kind": "l2tp",
                "server": "vpn.example",
                "username": "someone",
                "password": "secret",
                "preSharedKey": "shared-secret",
            }]))
            .unwrap();
            assert_eq!(l2tp["mode"], "direct");
            assert_eq!(l2tp["routeCount"], 1);
            assert_eq!(l2tp["nodeKinds"][0], "l2tp");
        }

        #[test]
        fn a_direct_session_turns_away_nodes_it_cannot_route_through() {
            let error = validate_direct(
                json!([{ "kind": "socks5", "host": "proxy.example", "port": 1080 }]),
            )
            .err()
            .unwrap();
            assert!(
                error.contains("WireGuard, OpenVPN, or L2TP/IPsec node for direct mode"),
                "{error}"
            );
            assert!(error.contains("relay"), "{error}");

            let error = validate_direct(json!([
                { "kind": "wireguard", "config": WIREGUARD_CONFIG },
                { "kind": "wireguard", "config": WIREGUARD_CONFIG },
            ]))
            .err()
            .unwrap();
            assert!(error.contains("exactly one node"), "{error}");

            // A broken configuration is still caught the same way.
            assert!(
                validate_direct(json!([{ "kind": "wireguard", "config": "[Interface]" }])).is_err()
            );
        }

        #[test]
        fn l2tp_direct_routes_canonicalize_ipv4_targets() {
            let prefixes = direct_l2tp_prefixes(&json!([
                { "kind": "ip", "value": "203.0.113.42/24" },
                { "kind": "ip", "value": "198.51.100.9" },
                { "kind": "ip", "value": "198.51.100.9/32" },
            ]))
            .unwrap();
            assert_eq!(prefixes, ["198.51.100.9/32", "203.0.113.0/24"]);
        }

        #[test]
        fn l2tp_direct_split_rejects_selectors_windows_routes_cannot_express() {
            let application = direct_l2tp_prefixes(&json!([{
                "kind": "application",
                "value": r"C:\Games\Demo\game.exe",
            }]))
            .unwrap_err();
            assert!(
                application.contains("Application and folder"),
                "{application}"
            );

            let wildcard = direct_l2tp_prefixes(&json!([{
                "kind": "hostname",
                "value": "*.game.example.com",
            }]))
            .unwrap_err();
            assert!(wildcard.contains("wildcard"), "{wildcard}");

            let ipv6 = direct_l2tp_prefixes(&json!([{
                "kind": "ip",
                "value": "2001:db8::1",
            }]))
            .unwrap_err();
            assert!(ipv6.contains("IPv6"), "{ipv6}");
        }

        #[test]
        fn l2tp_ipv6_reports_whether_the_preferred_route_bypasses_the_vpn() {
            let bypass = classify_l2tp_ipv6(Some(7), 12);
            assert_eq!(bypass["carried"], json!(false));
            assert_eq!(bypass["systemHasRoute"], json!(true));

            let carried = classify_l2tp_ipv6(Some(12), 12);
            assert_eq!(carried["carried"], json!(true));
            assert_eq!(carried["systemHasRoute"], json!(false));

            let unavailable = classify_l2tp_ipv6(None, 12);
            assert_eq!(unavailable["carried"], json!(false));
            assert_eq!(unavailable["systemHasRoute"], json!(false));
        }

        #[test]
        fn a_relay_session_still_needs_its_relay_address() {
            let error = validate_runtime(
                json!({
                    "trafficMode": "split",
                    "nodes": [{ "kind": "wireguard", "config": WIREGUARD_CONFIG }],
                }),
                &Mutex::new(RuntimeState::default()),
            )
            .err()
            .unwrap();
            assert!(error.contains("relay address"), "{error}");
        }

        #[test]
        fn a_malformed_node_names_its_route() {
            let error = validate(
                "split",
                json!([
                    { "kind": "socks5", "host": "proxy.example", "port": 1080 },
                    { "kind": "socks5", "host": "proxy.example", "port": 0 },
                ]),
            )
            .err()
            .unwrap();
            assert!(error.starts_with("route 2:"), "{error}");
        }

        #[test]
        fn a_wireguard_only_request_still_validates_without_the_node_list() {
            let result = validate_runtime(
                json!({
                    "relayIp": "203.0.113.8",
                    "trafficMode": "all",
                    "wireguardConfigs": [WIREGUARD_CONFIG],
                }),
                &Mutex::new(RuntimeState::default()),
            )
            .unwrap();
            assert_eq!(result["routeCount"], 1);
            assert_eq!(result["tunnelAddresses"][0], "10.88.0.2");
        }
    }
}
