//! Windows L2TP/IPsec relay transport.
//!
//! Windows RAS owns IKE, IPsec, L2TP and PPP. The privileged service dials the
//! connection and hands this module the temporary profile plus adapter
//! coordinates. Relay traffic uses an interface-pinned UDP socket; after a
//! failed path probe this module can redial that profile without disturbing
//! other transports. Direct L2TP is handled by the service through native
//! Windows routing, outside the packet engine.

use crate::relay_path::{PathIdentity, RelayPath};
use crate::rtt::MIN_TIMEOUT;
use crate::transport::{bind_to_interface, socket_read_timeout};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct L2tpRuntime {
    pub local_address: Ipv4Addr,
    pub virtual_address: Ipv4Addr,
    pub server_address: Ipv4Addr,
    pub interface_index: u32,
    /// Inner MTU the privileged service derived from the route to this L2TP
    /// server. A RAS redial receives a new adapter and must restore the same
    /// budget before relay traffic is pinned to it.
    #[serde(default = "default_l2tp_mtu")]
    pub mtu: u16,
    pub setup_latency_ms: f64,
    pub profile_name: String,
    pub phonebook_path: String,
}

// Older privileged-service builds did not include this field in their handoff
// JSON. Keeping their established safe value makes an in-place update benign.
fn default_l2tp_mtu() -> u16 {
    1384
}

pub struct L2tpRelayPath {
    socket: UdpSocket,
    server: String,
    runtime: L2tpRuntime,
    receive_buffer: Vec<u8>,
    #[cfg(windows)]
    _redialed_connection: Option<OwnedRasConnection>,
}

impl L2tpRelayPath {
    pub fn open(
        server: &str,
        username: &str,
        password: &str,
        runtime: &L2tpRuntime,
        relay: SocketAddrV4,
    ) -> Result<Self, String> {
        Self::open_inner(server, username, password, runtime, relay, false)
    }

    pub fn reopen(
        server: &str,
        username: &str,
        password: &str,
        runtime: &L2tpRuntime,
        relay: SocketAddrV4,
    ) -> Result<Self, String> {
        Self::open_inner(server, username, password, runtime, relay, true)
    }

    fn open_inner(
        server: &str,
        username: &str,
        password: &str,
        runtime: &L2tpRuntime,
        relay: SocketAddrV4,
        force_redial: bool,
    ) -> Result<Self, String> {
        let mut runtime = runtime.clone();
        #[cfg(windows)]
        let mut redialed_connection = None;

        let initial_socket = if !force_redial && runtime_is_active(&runtime) {
            open_socket(&runtime, relay)
        } else {
            Err(if force_redial {
                "the L2TP data plane stopped answering"
            } else {
                "the Windows L2TP adapter is no longer active"
            }
            .into())
        };
        let socket = match initial_socket {
            Ok(socket) => socket,
            Err(original_error) => {
                #[cfg(windows)]
                {
                    if force_redial {
                        disconnect_profile(&runtime);
                    }
                    let connection = redial_ras(&runtime, username, password, relay).map_err(
                        |redial_error| {
                            format!(
                                "the L2TP adapter stopped working ({original_error}); Windows could not reconnect it: {redial_error}"
                            )
                        },
                    )?;
                    runtime.local_address = connection.local_address;
                    runtime.interface_index = connection.interface_index;
                    let socket = open_socket(&runtime, relay).map_err(|error| {
                        format!(
                            "Windows reconnected L2TP but its relay socket could not open: {error}"
                        )
                    })?;
                    redialed_connection = Some(connection);
                    socket
                }
                #[cfg(not(windows))]
                {
                    return Err(original_error);
                }
            }
        };
        Ok(Self {
            socket,
            server: server.to_owned(),
            runtime,
            receive_buffer: vec![0; 65_535],
            #[cfg(windows)]
            _redialed_connection: redialed_connection,
        })
    }
}

#[cfg(windows)]
fn disconnect_profile(runtime: &L2tpRuntime) {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let _ = Command::new("rasdial.exe")
        .args([&runtime.profile_name, "/disconnect"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000)
        .status();
}

#[cfg(windows)]
fn runtime_is_active(runtime: &L2tpRuntime) -> bool {
    adapter_address_is_active(runtime.interface_index, runtime.local_address)
}

#[cfg(windows)]
fn adapter_address_is_active(interface_index: u32, local_address: Ipv4Addr) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let script = format!(
        "if(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex {} -IPAddress '{}' -ErrorAction SilentlyContinue){{exit 0}}else{{exit 1}}",
        interface_index, local_address
    );
    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(not(windows))]
fn runtime_is_active(_runtime: &L2tpRuntime) -> bool {
    false
}

fn open_socket(runtime: &L2tpRuntime, relay: SocketAddrV4) -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind(SocketAddrV4::new(runtime.local_address, 0))
        .map_err(|error| format!("could not bind the L2TP route: {error}"))?;
    bind_to_interface(
        &socket,
        IpAddr::V4(runtime.local_address),
        runtime.interface_index,
    )
    .map_err(|error| format!("could not pin the relay socket to the L2TP adapter: {error}"))?;
    socket
        .connect(relay)
        .map_err(|error| format!("could not reach the relay through L2TP: {error}"))?;
    Ok(socket)
}

impl RelayPath for L2tpRelayPath {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.socket
            .send(frame)
            .map(|_| ())
            .map_err(|error| format!("L2TP relay send failed: {error}"))
    }

    fn receive_frames(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        self.socket
            .set_read_timeout(Some(socket_read_timeout(timeout)))
            .map_err(|error| format!("could not configure the L2TP relay socket: {error}"))?;
        match self.socket.recv(&mut self.receive_buffer) {
            Ok(length) => Ok(vec![self.receive_buffer[..length].to_vec()]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(Vec::new())
            }
            Err(error) => Err(format!("L2TP relay receive failed: {error}")),
        }
    }

    fn kind(&self) -> &'static str {
        "l2tp"
    }

    fn endpoint(&self) -> String {
        self.server.clone()
    }

    fn setup_latency_ms(&self) -> Option<f64> {
        Some(self.runtime.setup_latency_ms)
    }

    fn setup_round_trips(&self) -> Option<u8> {
        None
    }

    fn identity(&self) -> PathIdentity {
        PathIdentity::L2tp {
            server: self.runtime.server_address,
        }
    }

    fn bypass_ipv4(&self) -> Option<Ipv4Addr> {
        Some(self.runtime.server_address)
    }

    fn probe_deadline_floor(&self) -> Duration {
        MIN_TIMEOUT
    }
}

#[cfg(windows)]
struct OwnedRasConnection {
    handle: windows_sys::Win32::NetworkManagement::Rras::HRASCONN,
    local_address: Ipv4Addr,
    interface_index: u32,
    relay_prefix: Option<String>,
}

#[cfg(windows)]
unsafe impl Send for OwnedRasConnection {}

#[cfg(windows)]
impl Drop for OwnedRasConnection {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::NetworkManagement::Rras::RasHangUpW(self.handle);
        }
        // A replacement connection can reuse the same PPP interface. Wait for
        // this handle to finish disconnecting, then remove the route only when
        // no live connection owns that address/index pair; otherwise we would
        // delete the replacement's freshly installed route during the swap.
        use windows_sys::Win32::NetworkManagement::Rras::{
            RASCONNSTATUSW, RASCS_Disconnected, RasGetConnectStatusW,
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
            status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
            let result = unsafe { RasGetConnectStatusW(self.handle, &mut status) };
            if result != 0 || status.rasconnstate == RASCS_Disconnected {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !adapter_address_is_active(self.interface_index, self.local_address) {
            if let Some(prefix) = &self.relay_prefix {
                remove_route(prefix, self.interface_index);
            }
        }
    }
}

#[cfg(windows)]
fn redial_ras(
    runtime: &L2tpRuntime,
    username: &str,
    password: &str,
    relay: SocketAddrV4,
) -> Result<OwnedRasConnection, String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    use windows_sys::Win32::NetworkManagement::Rras::{
        HRASCONN, RASDIALPARAMSW, RASP_PppIp, RASPPPIPW, RasDialW, RasGetProjectionInfoW,
        RasHangUpW,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn put(destination: &mut [u16], value: &str) -> Result<(), String> {
        let encoded = value.encode_utf16().collect::<Vec<_>>();
        if encoded.len() >= destination.len() {
            return Err("the L2TP login is too long".into());
        }
        destination[..encoded.len()].copy_from_slice(&encoded);
        Ok(())
    }
    fn take(value: &[u16]) -> String {
        String::from_utf16_lossy(
            &value[..value
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(value.len())],
        )
    }

    let phonebook = wide(&runtime.phonebook_path);
    let mut params: RASDIALPARAMSW = unsafe { std::mem::zeroed() };
    params.dwSize = std::mem::size_of::<RASDIALPARAMSW>() as u32;
    put(&mut params.szEntryName, &runtime.profile_name)?;
    put(&mut params.szUserName, username)?;
    put(&mut params.szPassword, password)?;
    let mut handle: HRASCONN = 0;
    let status = unsafe {
        RasDialW(
            std::ptr::null(),
            phonebook.as_ptr(),
            &params,
            0,
            std::ptr::null(),
            &mut handle,
        )
    };
    params.szUserName.fill(0);
    params.szPassword.fill(0);
    if status != 0 {
        if handle != 0 {
            unsafe { RasHangUpW(handle) };
        }
        return Err(format!("RAS error {status}"));
    }
    let mut owned = OwnedRasConnection {
        handle,
        local_address: Ipv4Addr::UNSPECIFIED,
        interface_index: 0,
        relay_prefix: None,
    };
    let mut projection: RASPPPIPW = unsafe { std::mem::zeroed() };
    projection.dwSize = std::mem::size_of::<RASPPPIPW>() as u32;
    let mut size = std::mem::size_of::<RASPPPIPW>() as u32;
    let projection_status = unsafe {
        RasGetProjectionInfoW(
            handle,
            RASP_PppIp,
            (&mut projection as *mut RASPPPIPW).cast(),
            &mut size,
        )
    };
    let local_address = take(&projection.szIpAddress)
        .parse::<Ipv4Addr>()
        .map_err(|_| "Windows reconnected L2TP without a valid IPv4 address".to_owned());
    if projection_status != 0 || projection.dwError != 0 || local_address.is_err() {
        return Err(format!(
            "Windows reconnected L2TP but IPv4 projection failed (RAS error {})",
            if projection_status != 0 {
                projection_status
            } else {
                projection.dwError
            }
        ));
    }
    let local_address = local_address.unwrap();
    owned.local_address = local_address;
    let script = format!(
        "$d=(Get-Date).AddSeconds(5);do{{$i=Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{local_address}' -ErrorAction SilentlyContinue|Select-Object -First 1 -ExpandProperty InterfaceIndex;if($null-ne $i){{[Console]::Out.Write($i);exit 0}};Start-Sleep -Milliseconds 100}}while((Get-Date)-lt$d);exit 2"
    );
    let started = Instant::now();
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|error| format!("could not inspect the reconnected L2TP adapter: {error}"))?;
    if !output.status.success() || started.elapsed() > Duration::from_secs(6) {
        return Err("the reconnected L2TP adapter did not become ready".into());
    }
    let interface_index = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| "Windows returned an invalid L2TP adapter index".to_owned())?;
    configure_mtu(interface_index, runtime.mtu)?;
    let relay_prefix = format!("{}/32", relay.ip());
    add_route(&relay_prefix, interface_index)?;
    owned.interface_index = interface_index;
    owned.relay_prefix = Some(relay_prefix);
    Ok(owned)
}

#[cfg(windows)]
fn configure_mtu(interface_index: u32, mtu: u16) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let script = format!(
        "Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex {interface_index} -NlMtuBytes {mtu} -ErrorAction Stop"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|error| format!("could not restore the L2TP MTU after reconnect: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Windows could not restore the L2TP MTU after reconnect: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(windows)]
fn add_route(prefix: &str, interface_index: u32) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let script = format!(
        "Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} -ErrorAction SilentlyContinue|Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue;New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction Stop|Out-Null"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .creation_flags(0x0800_0000)
        .output()
        .map_err(|error| format!("could not route the relay through reconnected L2TP: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

#[cfg(windows)]
fn remove_route(prefix: &str, interface_index: u32) {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let script = format!(
        "Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{prefix}' -InterfaceIndex {interface_index} -ErrorAction SilentlyContinue|Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    );
    let _ = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000)
        .status();
}
