//! L2TP/IPsec through Windows RAS: the temporary profile, the dial, its
//! routes and the probes that measure it.

use crate::log_event;
use gamepath_engine::l2tp::L2tpRuntime;
use gamepath_engine::mtu::{EffectiveMtu, LINK_MTU};
use gamepath_engine::netconfig;
use gamepath_engine::policy::{RuleSpec, compile as compile_policy};
use gamepath_engine::relay_path::{NodeSpec, SessionMode};
use gamepath_engine::transport::bind_to_interface;
use serde::Deserialize;
use serde_json::{Value, json};
use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::Rras::{
    HRASCONN, RAS_STATS, RASCONNSTATUSW, RASCS_Disconnected, RASDIALPARAMSW, RASP_PppIp, RASPPPIPW,
    RasDeleteEntryW, RasDialW, RasGetConnectStatusW, RasGetConnectionStatistics,
    RasGetErrorStringW, RasGetProjectionInfoW, RasHangUpW,
};

static L2TP_PROFILE_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

#[derive(Default)]
pub(crate) struct NativeL2tpUsage {
    last: Option<(u32, u32, u32)>,
    pub(crate) sent: u64,
    pub(crate) received: u64,
}

impl NativeL2tpUsage {
    pub(crate) fn sample(&mut self, sent: u32, received: u32, duration: u32) {
        if let Some((old_sent, old_received, old_duration)) = self.last {
            if duration >= old_duration {
                self.sent += u64::from(sent.wrapping_sub(old_sent));
                self.received += u64::from(received.wrapping_sub(old_received));
            }
        }
        self.last = Some((sent, received, duration));
    }
}

pub(crate) fn sample_l2tp_usage(connection: HRASCONN, usage: &mut NativeL2tpUsage) {
    let mut statistics: RAS_STATS = unsafe { std::mem::zeroed() };
    statistics.dwSize = std::mem::size_of::<RAS_STATS>() as u32;
    if unsafe { RasGetConnectionStatistics(connection, &mut statistics) } == 0 {
        usage.sample(
            statistics.dwBytesXmited,
            statistics.dwBytesRcved,
            statistics.dwConnectDuration,
        );
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2tpProbeRequest {
    server: String,
    username: String,
    password: String,
    pre_shared_key: String,
}

pub(crate) struct L2tpSession {
    pub(crate) connection: HRASCONN,
    profile_name: String,
    phonebook: Vec<u16>,
    server: String,
    pub(crate) server_address: Ipv4Addr,
    pub(crate) local_address: Ipv4Addr,
    pub(crate) interface_index: u32,
    setup_latency_ms: f64,
    split_tunneling: bool,
    /// MTU of the physical route that carried the L2TP/IPsec session into
    /// Windows RAS. Kept for truthful capture/MSS telemetry.
    uplink_mtu: u16,
    mtu: u16,
    routes: Vec<String>,
    remote_dns: bool,
}

unsafe impl Send for L2tpSession {}

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
    let result = unsafe { RasGetErrorStringW(code, message.as_mut_ptr(), message.len() as u32) };
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
                env::var_os("USERPROFILE").unwrap_or_else(|| OsString::from(r"C:\Users\Default")),
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
        stdin
            .flush()
            .map_err(|error| format!("could not configure the Windows L2TP profile: {error}"))?;
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
        // Microsoft's contract is to poll until the handle is invalid:
        // only then is the port released. Stopping at RASCS_Disconnected,
        // then deleting the profile, left the port busy, and a session
        // started seconds later lost this route to RAS error 633.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
            status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
            if unsafe { RasGetConnectStatusW(connection, &mut status) } != 0 {
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
            return Err("L2TP/IPsec needs a server, pre-shared key, username and password".into());
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
        let desired_mtu = EffectiveMtu::for_session(SessionMode::Direct, ["l2tp"], uplink_mtu).mtu;
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
            remote_dns: false,
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

    pub(crate) fn enable_remote_dns(&mut self) -> Result<(), String> {
        self.remote_dns = true;
        self.install_dns_routes()
    }

    fn install_dns_routes(&mut self) -> Result<(), String> {
        if self.remote_dns {
            for resolver in gamepath_engine::dns::FALLBACK_RESOLVERS {
                let prefix = format!("{resolver}/32");
                netconfig::add_route(resolver, 32, self.interface_index)?;
                if !self.routes.contains(&prefix) {
                    self.routes.push(prefix);
                }
            }
        }
        Ok(())
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

    pub(crate) fn is_connected(&self) -> bool {
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

/// Dials every L2TP node. A direct session has exactly one node, so its
/// failure is the session's. In relay mode a failed node is only marked:
/// the engine skips that route with the reason and runs on the rest, the
/// same as it does for a dead WireGuard or OpenVPN node.
pub(crate) fn connect_l2tp_nodes(
    nodes: &mut [NodeSpec],
    relay: Option<Ipv4Addr>,
    split_tunneling: bool,
    tag: &str,
) -> Result<Vec<L2tpSession>, String> {
    let mut sessions = Vec::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        let NodeSpec::L2tp {
            server,
            username,
            password,
            pre_shared_key,
            runtime,
            dial_error,
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
        let dialed = L2tpSession::dial(
            profile_name,
            server,
            username,
            password,
            pre_shared_key,
            split_tunneling,
            false,
        )
        .and_then(|mut session| {
            if let Some(relay) = relay {
                session.add_route(&format!("{relay}/32"))?;
            }
            Ok(session)
        });
        let session = match dialed {
            Ok(session) => session,
            Err(error) if relay.is_some() => {
                log_event(&format!(
                    "{tag} route {}: {error}; continuing without it",
                    index + 1
                ));
                pre_shared_key.clear();
                *dial_error = Some(error);
                continue;
            }
            Err(error) => return Err(format!("route {}: {error}", index + 1)),
        };
        if relay.is_some() {
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
                    "{tag} route {}: {error}; the L2TP adapter may keep an IPv6 default route",
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
pub(crate) fn validate_direct_l2tp_rules(rules: &Value) -> Result<(), String> {
    let rules: Vec<RuleSpec> = serde_json::from_value(rules.clone())
        .map_err(|error| format!("invalid split targets: {error}"))?;
    if rules.is_empty() {
        return Ok(());
    }
    let plan = compile_policy("split", &rules)?;
    if !plan.application_paths.is_empty() || !plan.folder_prefixes.is_empty() {
        return Err(
            "L2TP direct split mode supports IP and exact hostname targets. Application and folder targets need all-traffic mode or a WireGuard/OpenVPN direct node."
                .into(),
        );
    }
    if plan
        .hostnames
        .iter()
        .any(|hostname| hostname.starts_with("*."))
    {
        return Err("L2TP direct split mode cannot keep wildcard hostnames updated. Use an exact hostname, an IP range, or all-traffic mode.".into());
    }
    Ok(())
}

pub(crate) fn direct_l2tp_prefixes(rules: &Value) -> Result<Vec<String>, String> {
    validate_direct_l2tp_rules(rules)?;
    let rules: Vec<RuleSpec> = serde_json::from_value(rules.clone())
        .map_err(|error| format!("invalid split targets: {error}"))?;
    if rules.is_empty() {
        return Ok(Vec::new());
    }
    let plan = compile_policy("split", &rules)?;
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

pub(crate) fn apply_direct_l2tp_prefixes(
    session: &mut L2tpSession,
    prefixes: &[String],
) -> Result<(), String> {
    session.remove_routes();
    session.install_dns_routes()?;
    for prefix in prefixes {
        session.add_route(prefix)?;
    }
    Ok(())
}

pub(crate) fn apply_direct_l2tp_routes(
    session: &mut L2tpSession,
    rules: &Value,
) -> Result<(), String> {
    let prefixes = direct_l2tp_prefixes(rules)?;
    apply_direct_l2tp_prefixes(session, &prefixes)
}

pub(crate) fn probe_direct_l2tp(session: &L2tpSession, timeout: Duration) -> (bool, f64) {
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

pub(crate) fn native_l2tp_result(
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

pub(crate) fn probe_l2tp_node(payload: Value) -> Result<Value, String> {
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
            "Windows authenticated L2TP/IPsec, but no data returned through the VPN adapter".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2tp_usage_extends_wrapped_counters_without_counting_a_redial() {
        let mut usage = NativeL2tpUsage::default();
        usage.sample(u32::MAX - 10, 40, 1000);
        usage.sample(20, 60, 2000);
        assert_eq!((usage.sent, usage.received), (31, 20));
        usage.sample(5, 5, 100);
        assert_eq!((usage.sent, usage.received), (31, 20));
        usage.sample(15, 25, 200);
        assert_eq!((usage.sent, usage.received), (41, 40));
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
}
