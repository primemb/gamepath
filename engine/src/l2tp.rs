//! Windows L2TP/IPsec relay transport.
//!
//! Windows RAS owns IKE, IPsec, L2TP and PPP. The privileged service dials the
//! connection and hands this module the temporary profile plus adapter
//! coordinates. Relay traffic uses an interface-pinned UDP socket; after a
//! failed path probe this module can redial that profile without disturbing
//! other transports. Direct L2TP is handled by the service through native
//! Windows routing, outside the packet engine.

use crate::relay_path::{PathIdentity, RelayPath, ReopenEffort};
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
    /// Set once a send has failed in a way that says the adapter underneath
    /// this socket is gone. Sticky: nothing short of a new socket clears it.
    transport_failed: bool,
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
        Self::open_inner(
            server,
            username,
            password,
            runtime,
            relay,
            ReopenEffort::Cheap,
        )
    }

    pub fn reopen(
        server: &str,
        username: &str,
        password: &str,
        runtime: &L2tpRuntime,
        relay: SocketAddrV4,
        effort: ReopenEffort,
    ) -> Result<Self, String> {
        Self::open_inner(server, username, password, runtime, relay, effort)
    }

    fn open_inner(
        server: &str,
        username: &str,
        password: &str,
        runtime: &L2tpRuntime,
        relay: SocketAddrV4,
        effort: ReopenEffort,
    ) -> Result<Self, String> {
        let mut runtime = runtime.clone();
        #[cfg(windows)]
        let mut redialed_connection = None;

        // A RAS session that is still up is worth keeping. Rebuilding the
        // socket pinned to it costs microseconds, where redialling costs tens
        // of seconds of IKE, IPsec, L2TP and PPP - twenty-one of them on a
        // measured session - and most of what takes this path out is the relay
        // going quiet rather than the adapter dying. When the adapter has gone
        // this falls through on its own, so the cheap attempt is never a
        // detour, only a chance.
        #[cfg(windows)]
        if effort == ReopenEffort::Cheap {
            // Take the session's current coordinates, not the ones handed over
            // when it was first dialled.
            if let Some((address, index)) = live_adapter(&runtime.profile_name) {
                runtime.local_address = address;
                runtime.interface_index = index;
            }
        }
        let reuse_adapter = effort == ReopenEffort::Cheap && runtime_is_active(&runtime);
        let initial_socket = if reuse_adapter {
            open_socket(&runtime, relay)
        } else {
            Err(match effort {
                ReopenEffort::Cheap => "the Windows L2TP adapter is no longer active",
                ReopenEffort::Full => "the L2TP data plane stopped answering",
            }
            .into())
        };
        let socket = match initial_socket {
            Ok(socket) => socket,
            Err(original_error) => {
                #[cfg(windows)]
                {
                    disconnect_profile(&runtime);
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
            transport_failed: false,
            #[cfg(windows)]
            _redialed_connection: redialed_connection,
        })
    }
}

#[cfg(windows)]
fn disconnect_profile(runtime: &L2tpRuntime) {
    use windows_sys::Win32::NetworkManagement::Rras::RasHangUpW;
    let Some(handle) = find_connection(&runtime.profile_name) else {
        // Nothing to hang up. This is the ordinary case on a redial - the
        // adapter going away is usually why we are here - and discovering it
        // used to cost a process start.
        return;
    };
    unsafe { RasHangUpW(handle) };
    wait_for_disconnect(handle);
}

/// Reads a fixed-width RAS wide string up to its terminator.
#[cfg(windows)]
fn take_wide(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

/// The live RAS connection for `entry_name`, if there still is one.
#[cfg(windows)]
fn find_connection(
    entry_name: &str,
) -> Option<windows_sys::Win32::NetworkManagement::Rras::HRASCONN> {
    use windows_sys::Win32::NetworkManagement::Rras::{RASCONNW, RasEnumConnectionsW};
    // The first entry carries the struct size so RAS knows the layout it is
    // filling. Sixteen is far more simultaneous connections than a desktop
    // has, and a truncated enumeration would only mean falling through to a
    // full redial, which is what the caller would have done anyway.
    let mut connections: [RASCONNW; 16] = unsafe { std::mem::zeroed() };
    connections[0].dwSize = std::mem::size_of::<RASCONNW>() as u32;
    let mut size = std::mem::size_of_val(&connections) as u32;
    let mut count = 0_u32;
    let status = unsafe { RasEnumConnectionsW(connections.as_mut_ptr(), &mut size, &mut count) };
    if status != 0 {
        return None;
    }
    connections
        .iter()
        .take(count as usize)
        .find(|connection| take_wide(&connection.szEntryName) == entry_name)
        .map(|connection| connection.hrasconn)
}

/// The IPv4 address PPP negotiated on a live RAS connection.
#[cfg(windows)]
fn projected_ipv4(
    handle: windows_sys::Win32::NetworkManagement::Rras::HRASCONN,
) -> Result<Ipv4Addr, String> {
    use windows_sys::Win32::NetworkManagement::Rras::{
        RASP_PppIp, RASPPPIPW, RasGetProjectionInfoW,
    };
    let mut projection: RASPPPIPW = unsafe { std::mem::zeroed() };
    projection.dwSize = std::mem::size_of::<RASPPPIPW>() as u32;
    let mut size = std::mem::size_of::<RASPPPIPW>() as u32;
    let status = unsafe {
        RasGetProjectionInfoW(
            handle,
            RASP_PppIp,
            (&mut projection as *mut RASPPPIPW).cast(),
            &mut size,
        )
    };
    if status != 0 || projection.dwError != 0 {
        return Err(format!(
            "IPv4 projection failed (RAS error {})",
            if status != 0 {
                status
            } else {
                projection.dwError
            }
        ));
    }
    take_wide(&projection.szIpAddress)
        .parse()
        .map_err(|_| "IPv4 projection returned no usable address".to_owned())
}

/// Where a live RAS session for this profile can be reached right now.
///
/// Asked of RAS rather than read from the handover this process was given,
/// because every redial renegotiates both the address and the adapter, and the
/// stored pair then describes something that no longer exists. Without this the
/// cheap reopen would only ever work for the first outage of a session.
#[cfg(windows)]
fn live_adapter(profile_name: &str) -> Option<(Ipv4Addr, u32)> {
    let handle = find_connection(profile_name)?;
    let address = projected_ipv4(handle).ok()?;
    let index = crate::netconfig::interface_index_for_address(address)
        .ok()
        .flatten()?;
    Some((address, index))
}

/// Waits for a hung-up RAS connection to finish tearing down.
///
/// `RasHangUpW` returns before the session is gone, and dialling the same entry
/// while the previous one is still disconnecting is how a redial races itself.
#[cfg(windows)]
fn wait_for_disconnect(handle: windows_sys::Win32::NetworkManagement::Rras::HRASCONN) {
    use windows_sys::Win32::NetworkManagement::Rras::{
        RASCONNSTATUSW, RASCS_Disconnected, RasGetConnectStatusW,
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let mut status: RASCONNSTATUSW = unsafe { std::mem::zeroed() };
        status.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
        let result = unsafe { RasGetConnectStatusW(handle, &mut status) };
        if result != 0 || status.rasconnstate == RASCS_Disconnected {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(windows)]
fn runtime_is_active(runtime: &L2tpRuntime) -> bool {
    adapter_address_is_active(runtime.interface_index, runtime.local_address)
}

#[cfg(windows)]
fn adapter_address_is_active(interface_index: u32, local_address: Ipv4Addr) -> bool {
    crate::netconfig::address_is_active(interface_index, local_address)
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
        self.socket.send(frame).map(|_| ()).map_err(|error| {
            if is_fatal_send_error(&error) {
                self.transport_failed = true;
            }
            format!("L2TP relay send failed: {error}")
        })
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

    fn transport_failed(&self) -> bool {
        self.transport_failed
    }
}

/// Whether a send error means this socket can never carry anything again.
///
/// The relay socket is bound to the RAS adapter's address and pinned to its
/// interface with `IP_UNICAST_IF`. When Windows tears that adapter down - which
/// happens on every redial, and on this provider rather often - the socket
/// outlives it and every send fails from then on. That is a different thing
/// from a datagram being dropped, and it needs a different answer: no probe
/// will succeed either, so waiting for three of them to time out only buys the
/// user three seconds of traffic pushed into a socket that cannot carry it.
///
/// Observed live as `WSAEINVAL` (10022), reported to the user as "L2TP relay
/// send failed: An invalid argument was supplied".
///
/// The list is deliberately short. `WSAECONNRESET` and `WSAEHOSTUNREACH` are
/// left out because Windows raises those from an ICMP message about an earlier
/// datagram - the socket is fine and the next send may well work, which is the
/// same reason [`crate::socks5`] swallows them on receive.
#[cfg(windows)]
fn is_fatal_send_error(error: &std::io::Error) -> bool {
    /// The bound local address no longer exists.
    const WSAEINVAL: i32 = 10022;
    /// The handle is no longer a socket.
    const WSAENOTSOCK: i32 = 10038;
    /// The interface underneath it was removed.
    const WSAEADDRNOTAVAIL: i32 = 10049;
    /// The network subsystem or that interface has gone down.
    const WSAENETDOWN: i32 = 10050;
    /// The connection was broken by the interface being reset.
    const WSAENETRESET: i32 = 10052;
    matches!(
        error.raw_os_error(),
        Some(WSAEINVAL | WSAENOTSOCK | WSAEADDRNOTAVAIL | WSAENETDOWN | WSAENETRESET)
    )
}

#[cfg(not(windows))]
fn is_fatal_send_error(_error: &std::io::Error) -> bool {
    false
}

#[cfg(windows)]
struct OwnedRasConnection {
    handle: windows_sys::Win32::NetworkManagement::Rras::HRASCONN,
    local_address: Ipv4Addr,
    interface_index: u32,
    /// The relay this connection installed a host route for, so the route can
    /// be withdrawn again when the connection goes away.
    relay: Option<Ipv4Addr>,
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
        wait_for_disconnect(self.handle);
        if !adapter_address_is_active(self.interface_index, self.local_address) {
            if let Some(relay) = self.relay {
                crate::netconfig::remove_route(relay, 32, self.interface_index);
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
    use windows_sys::Win32::NetworkManagement::Rras::{
        HRASCONN, RASDIALPARAMSW, RasDialW, RasHangUpW,
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
        relay: None,
    };
    let local_address =
        projected_ipv4(handle).map_err(|error| format!("Windows reconnected L2TP but {error}"))?;
    owned.local_address = local_address;
    let interface_index =
        crate::netconfig::wait_for_interface_index(local_address, Duration::from_secs(5))
            .map_err(|_| "the reconnected L2TP adapter did not become ready".to_owned())?;
    configure_mtu(interface_index, runtime.mtu)?;
    // A redial gets a fresh adapter, so the IPv6 default route the link
    // advertises has to be taken off this one too. Relay paths are always the
    // IPv4-only, relay-scoped case; see the matching call in the service.
    if let Err(error) = crate::netconfig::disable_ipv6_default_route(interface_index) {
        crate::log_warn!("{error}; the reconnected L2TP adapter may keep an IPv6 default route");
    }
    add_route(*relay.ip(), interface_index)?;
    owned.interface_index = interface_index;
    owned.relay = Some(*relay.ip());
    Ok(owned)
}

#[cfg(windows)]
fn configure_mtu(interface_index: u32, mtu: u16) -> Result<(), String> {
    crate::netconfig::set_interface_mtu(interface_index, mtu)
        .map(|_| ())
        .map_err(|error| format!("could not restore the L2TP MTU after reconnect: {error}"))
}

#[cfg(windows)]
fn add_route(relay: Ipv4Addr, interface_index: u32) -> Result<(), String> {
    crate::netconfig::add_route(relay, 32, interface_index)
        .map_err(|error| format!("could not route the relay through reconnected L2TP: {error}"))
}

#[cfg(all(test, windows))]
mod tests {
    use super::is_fatal_send_error;
    use std::io::{Error, ErrorKind};

    /// The distinction the whole flag rests on: some send errors mean the
    /// socket is finished, and most do not.
    #[test]
    fn a_vanished_adapter_is_fatal_but_an_icmp_reply_is_not() {
        // What a user actually saw, reported as "L2TP relay send failed: An
        // invalid argument was supplied": the RAS adapter went away underneath
        // a socket still bound to its address.
        assert!(is_fatal_send_error(&Error::from_raw_os_error(10022)));
        assert!(is_fatal_send_error(&Error::from_raw_os_error(10038)));
        assert!(is_fatal_send_error(&Error::from_raw_os_error(10049)));
        assert!(is_fatal_send_error(&Error::from_raw_os_error(10050)));
        assert!(is_fatal_send_error(&Error::from_raw_os_error(10052)));

        // Windows raises these from an ICMP message about a datagram already
        // sent. The socket is fine and the next send may well succeed, so
        // tearing the path down for one would be the more expensive mistake.
        assert!(!is_fatal_send_error(&Error::from_raw_os_error(10054)));
        assert!(!is_fatal_send_error(&Error::from_raw_os_error(10065)));
        assert!(!is_fatal_send_error(&Error::from_raw_os_error(10051)));

        // An error carrying no OS code cannot be classified, so it is not.
        assert!(!is_fatal_send_error(&Error::new(
            ErrorKind::Other,
            "no code"
        )));
    }
}
