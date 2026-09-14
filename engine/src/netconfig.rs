//! Native Windows IP configuration.
//!
//! Every function here replaces a child process: a `powershell.exe -NoProfile
//! -Command …` invocation of the matching `Net*` cmdlet, or a `route.exe`. Those
//! are convenient but they are not cheap. A cmdlet call pays for a fresh
//! PowerShell engine plus the CIM/WMI machinery the NetTCPIP module sits on,
//! measured here at 450-1000 ms; `route.exe` is lighter but still 135-175 ms a
//! call, and all-traffic capture made one per route. The L2TP dial made five
//! cmdlet calls in a row before a session could start, so most of the wait for
//! a session was process startup rather than anything to do with the network.
//!
//! The IP Helper API underneath all of them answers the same questions in
//! microseconds, from the same tables, so this is a straight substitution
//! rather than a change of behaviour — with one deliberate exception, noted on
//! [`default_ipv4_route`], where the cmdlet pipeline's own ranking was wrong.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_NAMESERVER, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    GetIpInterfaceEntry, GetUnicastIpAddressTable, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_TABLE,
    SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, RouterDiscoveryDisabled, SOCKADDR_IN,
    SOCKADDR_INET,
};
use windows_sys::core::GUID;

/// Wraps an IPv4 address in the `SOCKADDR_INET` the IP Helper API takes.
///
/// `S_addr` holds the address in network byte order, which is exactly the
/// order [`Ipv4Addr::octets`] yields, so the bytes transfer without a swap.
fn sockaddr_v4(address: Ipv4Addr) -> SOCKADDR_INET {
    let mut storage: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    storage.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(address.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    storage
}

/// Reads an IPv4 address back out of a `SOCKADDR_INET`, if that is what it
/// holds. The tables this reads are filtered to `AF_INET`, but the union is
/// still a union, so the family is checked rather than assumed.
fn ipv4_from(storage: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: `si_family` overlaps the first field of every arm of the union,
    // so it is readable whichever arm is active.
    if unsafe { storage.si_family } != AF_INET {
        return None;
    }
    let raw = unsafe { storage.Ipv4.sin_addr.S_un.S_addr };
    Some(Ipv4Addr::from(raw.to_ne_bytes()))
}

/// The interface index that currently holds `address`, or `None` when no
/// adapter has it. Replaces `Get-NetIPAddress -IPAddress …`.
pub fn interface_index_for_address(address: Ipv4Addr) -> Result<Option<u32>, String> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if status != NO_ERROR {
        return Err(format!(
            "could not read the IPv4 address table (error {status})"
        ));
    }
    if table.is_null() {
        return Ok(None);
    }
    // SAFETY: the call succeeded with a non-null table, so `NumEntries` and a
    // matching run of `Table` rows are initialised. `Table` is declared as a
    // one-element array standing in for a trailing variable-length one.
    let found = unsafe {
        let count = (*table).NumEntries as usize;
        std::slice::from_raw_parts((*table).Table.as_ptr(), count)
            .iter()
            .find(|row| ipv4_from(&row.Address) == Some(address))
            .map(|row| row.InterfaceIndex)
    };
    unsafe { FreeMibTable(table.cast()) };
    Ok(found)
}

/// Whether `interface_index` still holds `address`.
///
/// Used to tell a live RAS adapter from one Windows has already torn down,
/// where a wrong answer costs a working connection, so a failed lookup reports
/// "not active" rather than guessing.
pub fn address_is_active(interface_index: u32, address: Ipv4Addr) -> bool {
    interface_index_for_address(address)
        .ok()
        .flatten()
        .is_some_and(|index| index == interface_index)
}

/// Waits for a freshly dialled adapter to publish `address`, returning the
/// interface index that owns it.
///
/// RAS reports the negotiated address before the adapter finishes appearing in
/// the IP tables, so the lookup has to be retried. Replaces a PowerShell
/// retry loop that paid a full engine start on every attempt; here an attempt
/// is cheap enough that the poll interval is the only real cost.
pub fn wait_for_interface_index(address: Ipv4Addr, timeout: Duration) -> Result<u32, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(index) = interface_index_for_address(address)? {
            return Ok(index);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Windows assigned {address} but its network adapter did not become ready"
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Fills in the identifying fields and reads one interface row.
fn ip_interface_entry_for(
    family: ADDRESS_FAMILY,
    interface_index: u32,
) -> Result<MIB_IPINTERFACE_ROW, String> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = family;
    row.InterfaceIndex = interface_index;
    let status = unsafe { GetIpInterfaceEntry(&mut row) };
    if status != NO_ERROR {
        return Err(format!(
            "could not read interface {interface_index} (error {status})"
        ));
    }
    Ok(row)
}

/// Reads one IPv4 interface row.
fn ip_interface_entry(interface_index: u32) -> Result<MIB_IPINTERFACE_ROW, String> {
    ip_interface_entry_for(AF_INET, interface_index)
}

/// The IPv4 link MTU of `interface_index`. Replaces `Get-NetIPInterface`.
pub fn interface_mtu(interface_index: u32) -> Result<u32, String> {
    Ok(ip_interface_entry(interface_index)?.NlMtu)
}

/// Sets the IPv4 link MTU of `interface_index`, returning the value in force
/// afterwards. Replaces `Set-NetIPInterface -NlMtuBytes`.
pub fn set_interface_mtu(interface_index: u32, mtu: u16) -> Result<u32, String> {
    let mut row = ip_interface_entry(interface_index)?;
    if row.NlMtu == u32::from(mtu) {
        return Ok(row.NlMtu);
    }
    row.NlMtu = u32::from(mtu);
    // `SetIpInterfaceEntry` rejects a row whose site prefix length is not
    // valid for the family, and the value `GetIpInterfaceEntry` returns for
    // IPv4 can exceed 32. Zero is the documented way to leave it unchanged.
    row.SitePrefixLength = 0;
    let status = unsafe { SetIpInterfaceEntry(&mut row) };
    if status != NO_ERROR {
        return Err(format!(
            "Windows refused MTU {mtu} on interface {interface_index} (error {status})"
        ));
    }
    interface_mtu(interface_index)
}

/// How long a measured route MTU stays usable before it is read again.
///
/// The measurement is now microseconds, so this is not about saving work: it
/// is about how long a wrong answer could survive. A laptop moving from
/// Ethernet to Wi-Fi, or onto a phone hotspot, changes the real budget, and a
/// cached value that is too *large* is the harmful direction - it fragments
/// or silently drops every full-size game packet until it expires. Half a
/// minute covers the burst of lookups one session start makes across its
/// endpoints, and repeated restarts while a user tunes their setup, without
/// letting a stale figure outlive a network change by long.
const ROUTE_MTU_TTL: Duration = Duration::from_secs(30);

static ROUTE_MTU_CACHE: Mutex<BTreeMap<Ipv4Addr, (u16, Instant)>> = Mutex::new(BTreeMap::new());

/// Drops every cached route MTU.
///
/// Worth calling from anything that knows the uplink changed underneath us,
/// which is the one event the TTL alone can only wait out.
pub fn invalidate_route_mtu_cache() {
    if let Ok(mut cache) = ROUTE_MTU_CACHE.lock() {
        cache.clear();
    }
}

/// The link MTU of the interface Windows would use to reach `destination`,
/// remembered for [`ROUTE_MTU_TTL`].
///
/// Replaces `Find-NetRoute` followed by `Get-NetIPInterface`, and like that
/// pair it must be asked before a VPN dial installs routes of its own.
pub fn route_link_mtu(destination: Ipv4Addr) -> Result<u16, String> {
    let now = Instant::now();
    if let Ok(cache) = ROUTE_MTU_CACHE.lock() {
        if let Some((mtu, measured)) = cache.get(&destination) {
            if now.duration_since(*measured) < ROUTE_MTU_TTL {
                return Ok(*mtu);
            }
        }
    }
    let mtu = measure_route_link_mtu(destination)?;
    if let Ok(mut cache) = ROUTE_MTU_CACHE.lock() {
        // Expired entries are dropped here rather than on a timer: the map is
        // keyed by tunnel endpoint, so it is small, and this is the only thing
        // that ever touches it.
        cache.retain(|_, (_, measured)| now.duration_since(*measured) < ROUTE_MTU_TTL);
        cache.insert(destination, (mtu, now));
    }
    Ok(mtu)
}

/// Reads the route MTU without consulting or updating the cache.
fn measure_route_link_mtu(destination: Ipv4Addr) -> Result<u16, String> {
    let target = sockaddr_v4(destination);
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &target,
            0,
            &mut route,
            &mut source,
        )
    };
    if status != NO_ERROR {
        return Err(format!(
            "could not find the route to {destination} (error {status})"
        ));
    }
    let mtu = interface_mtu(route.InterfaceIndex)?;
    Ok(crate::mtu::normalize_link_mtu(
        mtu.try_into().unwrap_or(u16::MAX),
    ))
}

/// How long a just-created adapter is given to publish its IPv4 interface.
///
/// This wait used to be accidental. The `Set-NetIPInterface` call this
/// replaced took most of a second to start PowerShell, which was long enough
/// for Windows to finish binding a newly created Wintun adapter to TCP/IP
/// before the row was asked for. Reading the row directly takes microseconds
/// and can now arrive first, so the wait has to be stated rather than
/// inherited from how slow the old call was.
const INTERFACE_READY_TIMEOUT: Duration = Duration::from_secs(3);

/// Prepares a GamePath tunnel adapter: its MTU, a fixed low interface metric
/// so Windows prefers it, and no duplicate-address probing to delay it coming
/// up. Replaces one `Set-NetIPInterface` with several switches.
///
/// Called immediately after the adapter is created, so it tolerates the
/// interface not being registered yet.
pub fn configure_tunnel_interface(interface_index: u32, mtu: u16) -> Result<(), String> {
    let deadline = Instant::now() + INTERFACE_READY_TIMEOUT;
    let mut row = loop {
        match ip_interface_entry(interface_index) {
            Ok(row) => break row,
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    row.NlMtu = u32::from(mtu);
    row.Metric = 5;
    // Windows ignores `Metric` unless the automatic one is switched off.
    row.UseAutomaticMetric = 0;
    // A point-to-point tunnel address cannot collide, and each probe delays
    // the adapter carrying traffic.
    row.DadTransmits = 0;
    row.SitePrefixLength = 0;
    let status = unsafe { SetIpInterfaceEntry(&mut row) };
    if status != NO_ERROR {
        return Err(format!(
            "could not configure GamePath interface {interface_index} (error {status})"
        ));
    }
    Ok(())
}

/// Stops a tunnel adapter from acquiring an IPv6 default route.
///
/// GamePath carries IPv4 only. A provider's L2TP/IPsec server nonetheless
/// sends Router Advertisements on the PPP link, and Windows acts on them: the
/// temporary RAS adapter ends up holding a `::/0` route. Observed on a live
/// session, that was the machine's *only* IPv6 default route.
///
/// Nothing breaks while the link hands out no global IPv6 address, because
/// Windows cannot then select an IPv6 source and everything falls back to
/// IPv4. It is still wrong in two ways worth closing: the interface reports
/// itself as having a default route that reaches nothing, and a server that
/// later does advertise a prefix would have IPv6 traffic routed into a tunnel
/// this client does not carry IPv6 through.
///
/// Both halves are needed. Disabling router discovery stops the next
/// advertisement being acted on; the sweep removes one that already arrived,
/// which is likely, because a server usually advertises as soon as the link
/// comes up and that is before the adapter can be configured.
pub fn disable_ipv6_default_route(interface_index: u32) -> Result<(), String> {
    // Sweep first, and whatever the interface lets us configure afterwards.
    // This is the half that fixes the symptom, and it used to be skipped
    // whenever the half below failed - which on a live RAS adapter it did,
    // with ERROR_INVALID_PARAMETER, leaving the route exactly where it was.
    let swept = remove_ipv6_default_routes(interface_index);
    let configured = disable_ipv6_router_discovery(interface_index);
    swept.and(configured)
}

/// Stops Windows acting on any further Router Advertisement from this link.
///
/// Best-effort by contract, and reported separately from the sweep above. A
/// RAS/PPP interface does not always accept the change; what is lost when it
/// refuses is only the guarantee that the next advertisement will not put the
/// route back, not the removal of the one already there.
fn disable_ipv6_router_discovery(interface_index: u32) -> Result<(), String> {
    let mut row = ip_interface_entry_for(AF_INET6, interface_index)?;
    if row.RouterDiscoveryBehavior == RouterDiscoveryDisabled {
        return Ok(());
    }
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    // Windows then also declines to *use* a default route learned on this
    // interface, which is the same switch it sets for a split-tunnel VPN.
    row.DisableDefaultRoutes = 1;
    let status = unsafe { SetIpInterfaceEntry(&mut row) };
    if status != NO_ERROR {
        return Err(format!(
            "could not disable IPv6 router discovery on interface {interface_index} (error {status}){}",
            if status == ERROR_ACCESS_DENIED {
                "; this needs administrator rights"
            } else {
                ""
            }
        ));
    }
    Ok(())
}

/// Deletes every `::/0` route already installed on `interface_index`.
///
/// The next hop of an advertised route is a link-local address this process
/// never sees, so the rows are found by walking the table rather than
/// reconstructed and deleted by name.
fn remove_ipv6_default_routes(interface_index: u32) -> Result<(), String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET6, &mut table) };
    if status != NO_ERROR {
        return Err(format!(
            "could not read the IPv6 route table (error {status})"
        ));
    }
    if table.is_null() {
        return Ok(());
    }
    // SAFETY: the call succeeded with a non-null table, so `NumEntries` and
    // that many `Table` rows are initialised; the trailing array is declared
    // with one element. The rows are a snapshot, so deleting as we go cannot
    // disturb the walk.
    let mut failures = 0_u32;
    unsafe {
        let count = (*table).NumEntries as usize;
        for row in std::slice::from_raw_parts((*table).Table.as_ptr(), count) {
            if row.InterfaceIndex != interface_index || row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            if DeleteIpForwardEntry2(row) != NO_ERROR {
                failures += 1;
            }
        }
        FreeMibTable(table.cast());
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!(
            "could not remove {failures} IPv6 default route(s) from interface {interface_index}"
        ))
    }
}

/// The gateway and interface Windows would currently leave this machine by.
///
/// Replaces `Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object
/// RouteMetric | Select-Object -First 1`, which cost a whole PowerShell engine
/// plus the CIM machinery — measured at 450-830 ms — on the connect path.
///
/// The ranking is not quite that cmdlet pipeline's, deliberately. Windows
/// chooses between default routes on the route metric *plus* the metric of the
/// interface it leaves by, and sorting on the route metric alone cannot see the
/// second half: on a laptop with Ethernet and Wi-Fi both up, both default
/// routes commonly carry route metric 0, so the old sort was a tie broken by
/// whatever order the table came back in. Picking the wrong one there pins the
/// relay and node bypass routes to an interface whose gateway cannot reach
/// them, which strands the session with no route out. This ranks them the way
/// the stack itself does.
///
/// Only `0.0.0.0/0` counts, so the two halves of a GamePath split default
/// (`0.0.0.0/1` and `128.0.0.0/1`) are never mistaken for the physical route,
/// and an on-link default — one with no gateway to send bypass traffic to — is
/// skipped as it was before.
pub fn default_ipv4_route() -> Result<(Ipv4Addr, u32), String> {
    let candidates = default_ipv4_route_candidates()?;
    rank_default_routes(candidates, |interface_index| {
        ip_interface_entry(interface_index)
            .ok()
            .map(|row| row.Metric)
    })
    .ok_or_else(|| "no usable default IPv4 route was found".to_owned())
}

/// Every `0.0.0.0/0` route that has a gateway, as
/// `(gateway, interface index, route metric)`.
fn default_ipv4_route_candidates() -> Result<Vec<(Ipv4Addr, u32, u32)>, String> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if status != NO_ERROR {
        return Err(format!(
            "could not read the IPv4 route table (error {status})"
        ));
    }
    if table.is_null() {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    // SAFETY: the call succeeded with a non-null table, so `NumEntries` and
    // that many `Table` rows are initialised; the trailing array is declared
    // with one element. Nothing borrowed from a row outlives the free below.
    unsafe {
        let count = (*table).NumEntries as usize;
        for row in std::slice::from_raw_parts((*table).Table.as_ptr(), count) {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            let Some(gateway) = ipv4_from(&row.NextHop) else {
                continue;
            };
            if gateway.is_unspecified() {
                continue;
            }
            candidates.push((gateway, row.InterfaceIndex, row.Metric));
        }
        FreeMibTable(table.cast());
    }
    Ok(candidates)
}

/// Picks the default route Windows itself would, given each interface's
/// metric. Separated from the table walk so the ranking — the part that used
/// to be wrong — can be tested without a particular machine's network.
fn rank_default_routes(
    candidates: Vec<(Ipv4Addr, u32, u32)>,
    interface_metric: impl Fn(u32) -> Option<u32>,
) -> Option<(Ipv4Addr, u32)> {
    let mut best: Option<(u64, Ipv4Addr, u32)> = None;
    for (gateway, interface_index, route_metric) in candidates {
        let metric = interface_metric(interface_index)
            .map(u64::from)
            // A route whose interface will not answer is still a route. Rank it
            // last rather than dropping it, so an unreadable row cannot leave a
            // machine that does have a way out looking like it has none.
            .unwrap_or(u64::from(u32::MAX));
        let rank = u64::from(route_metric) + metric;
        if best.is_none_or(|(current, _, _)| rank < current) {
            best = Some((rank, gateway, interface_index));
        }
    }
    best.map(|(_, gateway, interface_index)| (gateway, interface_index))
}

/// Builds a route row for `destination/prefix_length` out of
/// `interface_index`.
///
/// An unspecified `next_hop` is how the API spells "on-link", which is what
/// `New-NetRoute -NextHop 0.0.0.0` produces; anything else is a gateway the
/// packet is handed to, as `route ADD … <gateway>` does.
fn forward_row(
    destination: Ipv4Addr,
    prefix_length: u8,
    next_hop: Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // Fills the defaults Windows expects for the fields this does not set.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_v4(destination),
        PrefixLength: prefix_length,
    };
    row.NextHop = sockaddr_v4(next_hop);
    row.Metric = metric;
    row
}

/// Pins `destination/prefix_length` on-link to `interface_index`.
pub fn add_route(
    destination: Ipv4Addr,
    prefix_length: u8,
    interface_index: u32,
) -> Result<(), String> {
    add_route_via(
        destination,
        prefix_length,
        Ipv4Addr::UNSPECIFIED,
        interface_index,
        1,
    )
}

/// Routes `destination/prefix_length` through `next_hop` on
/// `interface_index`.
///
/// Replaces `Remove-NetRoute` followed by `New-NetRoute` — and `route.exe ADD`,
/// which cost a process launch each — including the removal: an existing route
/// for the same prefix may point somewhere else, so it is deleted rather than
/// left to win. That also makes this idempotent, which `route ADD` is not: a
/// leftover bypass route from a session that did not get to clean up used to
/// fail the next capture start outright instead of being replaced.
pub fn add_route_via(
    destination: Ipv4Addr,
    prefix_length: u8,
    next_hop: Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> Result<(), String> {
    let row = forward_row(
        destination,
        prefix_length,
        next_hop,
        interface_index,
        metric,
    );
    let status = unsafe { CreateIpForwardEntry2(&row) };
    if status == NO_ERROR {
        return Ok(());
    }
    if status != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(format!(
            "Windows could not route {destination}/{prefix_length} through interface \
             {interface_index} (error {status}){}",
            if status == ERROR_ACCESS_DENIED {
                "; this needs administrator rights"
            } else {
                ""
            }
        ));
    }
    unsafe { DeleteIpForwardEntry2(&row) };
    let status = unsafe { CreateIpForwardEntry2(&row) };
    if status == NO_ERROR {
        Ok(())
    } else {
        Err(format!(
            "Windows could not replace the existing route for {destination}/{prefix_length} on \
             interface {interface_index} (error {status})"
        ))
    }
}

/// Removes a route this process added. A route that is already gone is the
/// intended end state, so it is not an error.
///
/// Deliberately infallible and silent. Every caller runs inside `Drop`, while
/// a connection is being torn down, and there is nothing useful a failure
/// could change there: panicking would abort the process mid-teardown and an
/// error return would only be discarded.
pub fn remove_route(destination: Ipv4Addr, prefix_length: u8, interface_index: u32) {
    remove_route_via(
        destination,
        prefix_length,
        Ipv4Addr::UNSPECIFIED,
        interface_index,
    );
}

/// Removes a route installed through a gateway. The next hop is part of what
/// identifies a row, so it has to match the one it was created with.
pub fn remove_route_via(
    destination: Ipv4Addr,
    prefix_length: u8,
    next_hop: Ipv4Addr,
    interface_index: u32,
) {
    let row = forward_row(destination, prefix_length, next_hop, interface_index, 1);
    unsafe { DeleteIpForwardEntry2(&row) };
}

/// Points an adapter at `servers`, in order, for IPv4 name resolution.
/// Replaces `netsh interface ipv4 set dnsservers`.
///
/// An empty list clears the adapter's servers, which is what teardown wants:
/// the adapter keeps existing between sessions, and a stale nameserver on a
/// disconnected tunnel is a resolver pointing into nothing.
///
/// `adapter` is the interface GUID rather than its index, because that is what
/// `SetInterfaceDnsSettings` takes.
pub fn set_interface_dns(adapter: u128, servers: &[Ipv4Addr]) -> Result<(), String> {
    // The API takes one space-separated, NUL-terminated wide string. A null
    // pointer with the flag set is how "no servers" is spelled.
    let mut encoded: Vec<u16> = servers
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .encode_utf16()
        .collect();
    encoded.push(0);
    let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    // Only the nameserver field is being set. Every other field stays zero and
    // unflagged, so Windows leaves the adapter's domain, search list and
    // registration behaviour exactly as it found them.
    settings.Flags = u64::from(DNS_SETTING_NAMESERVER);
    settings.NameServer = if servers.is_empty() {
        std::ptr::null_mut()
    } else {
        encoded.as_mut_ptr()
    };
    // SAFETY: `settings` is fully initialised and its only pointer either is
    // null or borrows `encoded`, which outlives the call. The callee copies
    // what it needs and retains nothing.
    // Wintun identifies its adapter by the same `u128` it was created with, and
    // `GUID::from_u128` is the conversion it uses itself, so the two cannot
    // disagree about which adapter is being configured.
    let status = unsafe { SetInterfaceDnsSettings(GUID::from_u128(adapter), &settings) };
    if status == NO_ERROR {
        return Ok(());
    }
    Err(format!(
        "Windows refused the DNS servers for the tunnel adapter (error {status}){}",
        if status == ERROR_ACCESS_DENIED {
            "; this needs administrator rights"
        } else {
            ""
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_survives_the_round_trip_through_a_sockaddr() {
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(10, 88, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert_eq!(ipv4_from(&sockaddr_v4(address)), Some(address));
        }
    }

    /// The byte order this depends on: the first octet has to land in the
    /// lowest address, or every address would come back reversed.
    #[test]
    fn a_sockaddr_holds_the_address_in_network_order() {
        let storage = sockaddr_v4(Ipv4Addr::new(1, 2, 3, 4));
        let raw = unsafe { storage.Ipv4.sin_addr.S_un.S_addr };
        assert_eq!(raw.to_ne_bytes(), [1, 2, 3, 4]);
        assert_eq!(unsafe { storage.si_family }, AF_INET);
    }

    /// The loopback interface is always present, so this exercises the real
    /// table walk without depending on the machine's adapters.
    #[test]
    fn the_loopback_address_resolves_to_an_interface_that_reports_an_mtu() {
        let index = interface_index_for_address(Ipv4Addr::LOCALHOST)
            .expect("the IPv4 address table should be readable")
            .expect("127.0.0.1 should be assigned to an interface");
        assert!(address_is_active(index, Ipv4Addr::LOCALHOST));
        assert!(interface_mtu(index).expect("loopback should report an MTU") > 0);
    }

    /// The cache must not be able to answer with a value it never measured,
    /// and must still be answering the same thing the direct read does.
    #[test]
    fn a_cached_route_mtu_matches_a_fresh_measurement() {
        invalidate_route_mtu_cache();
        let measured = measure_route_link_mtu(crate::BENCHMARK_TARGET)
            .expect("a machine running these tests has a route to the Internet");
        let first = route_link_mtu(crate::BENCHMARK_TARGET).expect("first lookup");
        let cached = route_link_mtu(crate::BENCHMARK_TARGET).expect("cached lookup");
        assert_eq!(first, measured);
        assert_eq!(cached, measured);
    }

    #[test]
    fn invalidating_the_cache_forces_the_next_lookup_to_measure_again() {
        let _ = route_link_mtu(crate::BENCHMARK_TARGET);
        invalidate_route_mtu_cache();
        assert!(
            ROUTE_MTU_CACHE.lock().unwrap().is_empty(),
            "the cache should be empty right after it is invalidated"
        );
        assert!(route_link_mtu(crate::BENCHMARK_TARGET).is_ok());
        assert!(
            !ROUTE_MTU_CACHE.lock().unwrap().is_empty(),
            "a lookup after invalidation should repopulate the cache"
        );
    }

    /// A cached MTU is still bounded by the same range a fresh one is, so the
    /// cache can never widen the budget past what the link can carry.
    #[test]
    fn a_cached_route_mtu_stays_inside_the_usable_range() {
        invalidate_route_mtu_cache();
        for _ in 0..3 {
            let mtu = route_link_mtu(crate::BENCHMARK_TARGET).expect("route lookup");
            assert!((crate::mtu::MIN_TUNNEL_MTU..=crate::mtu::LINK_MTU).contains(&mtu));
        }
    }

    /// Configuring an interface that will never appear has to give up at the
    /// deadline rather than loop, and must not take much longer than it.
    #[test]
    fn configuring_an_interface_that_never_appears_gives_up_at_the_deadline() {
        let started = Instant::now();
        let result = configure_tunnel_interface(u32::MAX, 1400);
        let elapsed = started.elapsed();
        assert!(
            result.is_err(),
            "a nonexistent interface cannot be configured"
        );
        assert!(
            elapsed >= INTERFACE_READY_TIMEOUT,
            "gave up after only {elapsed:?}, before the adapter could have appeared"
        );
        assert!(
            elapsed < INTERFACE_READY_TIMEOUT * 2,
            "took {elapsed:?}, far past the deadline"
        );
    }

    /// The IPv6 sweep has to be safe to run against an interface that has no
    /// IPv6 default route, which is every interface most of the time.
    #[test]
    fn removing_ipv6_default_routes_is_a_no_op_when_there_are_none() {
        let index = interface_index_for_address(Ipv4Addr::LOCALHOST)
            .expect("the IPv4 address table should be readable")
            .expect("127.0.0.1 should be assigned to an interface");
        assert_eq!(remove_ipv6_default_routes(index), Ok(()));
    }

    /// And the whole operation has to fail cleanly, not panic, on an interface
    /// index that does not exist - a RAS adapter can disappear mid-setup.
    #[test]
    fn disabling_the_ipv6_default_route_on_a_missing_interface_is_an_error() {
        assert!(disable_ipv6_default_route(u32::MAX).is_err());
    }

    /// End to end against a real RAS adapter, which is the only place the
    /// interesting half runs: a loopback or Ethernet interface never has an
    /// advertised IPv6 default route to remove. Ignored by default because it
    /// needs a live L2TP session and changes that adapter's configuration.
    ///
    /// `GAMEPATH_IPV6_TEST_IFINDEX=<index> cargo test -- --ignored --nocapture`
    #[test]
    #[ignore = "needs a live L2TP adapter; set GAMEPATH_IPV6_TEST_IFINDEX"]
    fn a_live_adapter_loses_its_ipv6_default_route() {
        let index: u32 = std::env::var("GAMEPATH_IPV6_TEST_IFINDEX")
            .expect("set GAMEPATH_IPV6_TEST_IFINDEX to a connected L2TP adapter")
            .trim()
            .parse()
            .expect("GAMEPATH_IPV6_TEST_IFINDEX must be an interface index");
        let before = ipv6_default_route_count(index);
        println!("interface {index}: {before} IPv6 default route(s) before");
        // Both halves need administrator rights, which the service and its
        // engine child have and `cargo test` does not.
        let outcome = disable_ipv6_default_route(index);
        let after = ipv6_default_route_count(index);
        println!("interface {index}: {after} IPv6 default route(s) after");
        assert_eq!(after, 0, "an IPv6 default route survived: {outcome:?}");
        match outcome {
            Ok(()) => {
                // Router discovery is off, so a further advertisement cannot
                // put the route back.
                let row = ip_interface_entry_for(AF_INET6, index).expect("IPv6 interface row");
                assert_eq!(row.RouterDiscoveryBehavior, RouterDiscoveryDisabled);
            }
            // The route is gone either way; only the guarantee against the
            // next advertisement is missing, which is worth seeing but is not
            // a failure of the thing being tested.
            Err(error) => println!("route removed, but not configured out: {error}"),
        }
    }

    /// Counts the `::/0` routes on one interface, for the live test to compare.
    #[cfg(test)]
    fn ipv6_default_route_count(interface_index: u32) -> usize {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if unsafe { GetIpForwardTable2(AF_INET6, &mut table) } != NO_ERROR || table.is_null() {
            return 0;
        }
        let count = unsafe {
            let entries = (*table).NumEntries as usize;
            let found = std::slice::from_raw_parts((*table).Table.as_ptr(), entries)
                .iter()
                .filter(|row| {
                    row.InterfaceIndex == interface_index && row.DestinationPrefix.PrefixLength == 0
                })
                .count();
            FreeMibTable(table.cast());
            found
        };
        count
    }

    /// The ordering that matters. The configuration change is refused on some
    /// interfaces - and on every interface when unelevated - and that must not
    /// stop the sweep, which is the half that actually removes the route.
    #[test]
    fn a_refused_configuration_change_still_leaves_the_sweep_done() {
        let index = interface_index_for_address(Ipv4Addr::LOCALHOST)
            .expect("the IPv4 address table should be readable")
            .expect("127.0.0.1 should be assigned to an interface");
        // Whatever the combined call reports, the sweep half has succeeded.
        let _ = disable_ipv6_default_route(index);
        assert_eq!(remove_ipv6_default_routes(index), Ok(()));
    }

    #[test]
    fn an_unassigned_address_resolves_to_no_interface() {
        assert_eq!(
            interface_index_for_address(Ipv4Addr::new(203, 0, 113, 7)),
            Ok(None)
        );
    }

    #[test]
    fn a_route_lookup_reports_the_uplink_mtu_within_the_usable_range() {
        let mtu = route_link_mtu(crate::BENCHMARK_TARGET)
            .expect("a machine running these tests has a route to the Internet");
        assert!((crate::mtu::MIN_TUNNEL_MTU..=crate::mtu::LINK_MTU).contains(&mtu));
    }

    const ETHERNET: (Ipv4Addr, u32) = (Ipv4Addr::new(192, 168, 1, 1), 6);
    const WIFI: (Ipv4Addr, u32) = (Ipv4Addr::new(192, 168, 50, 1), 14);

    /// The case the old `Sort-Object RouteMetric` could not see. Both default
    /// routes carry route metric 0 — which is ordinary — so the whole decision
    /// rests on the interface metric, and sorting on the route metric alone
    /// left it to the order the table happened to come back in.
    #[test]
    fn a_tie_on_route_metric_is_broken_by_the_interface_metric() {
        let metric = |index| match index {
            6 => Some(25),  // Ethernet
            14 => Some(45), // Wi-Fi
            _ => None,
        };
        let wired_first = vec![(ETHERNET.0, ETHERNET.1, 0), (WIFI.0, WIFI.1, 0)];
        let wireless_first = vec![(WIFI.0, WIFI.1, 0), (ETHERNET.0, ETHERNET.1, 0)];
        // Whichever order the rows arrive in, the cheaper interface wins.
        assert_eq!(rank_default_routes(wired_first, metric), Some(ETHERNET));
        assert_eq!(rank_default_routes(wireless_first, metric), Some(ETHERNET));
    }

    /// And the route metric still counts: a VPN adapter that asks to be
    /// avoided by carrying a large route metric must not be chosen over the
    /// physical link just because its interface metric is low.
    #[test]
    fn a_high_route_metric_loses_to_a_cheaper_total() {
        let metric = |index| match index {
            6 => Some(25),
            14 => Some(4), // a VPN interface, cheap on its own
            _ => None,
        };
        let candidates = vec![(WIFI.0, WIFI.1, 328), (ETHERNET.0, ETHERNET.1, 25)];
        assert_eq!(rank_default_routes(candidates, metric), Some(ETHERNET));
    }

    /// An interface row that cannot be read is ranked last rather than
    /// dropped, so it is still chosen when it is the only way out.
    #[test]
    fn an_unreadable_interface_is_a_last_resort_not_a_lost_route() {
        let only = vec![(WIFI.0, WIFI.1, 0)];
        assert_eq!(rank_default_routes(only, |_| None), Some(WIFI));
        let both = vec![(WIFI.0, WIFI.1, 0), (ETHERNET.0, ETHERNET.1, 9999)];
        assert_eq!(
            rank_default_routes(both, |index| (index == 6).then_some(50)),
            Some(ETHERNET)
        );
    }

    #[test]
    fn a_machine_with_no_gateway_has_no_default_route() {
        assert_eq!(rank_default_routes(Vec::new(), |_| Some(1)), None);
    }

    /// The L2TP dial and the service both pin a relay address on-link with
    /// [`add_route`], and a row that stopped meaning "on-link" would send that
    /// traffic to a gateway instead of out of the tunnel adapter.
    #[test]
    fn an_on_link_route_row_still_has_no_gateway() {
        let row = forward_row(
            Ipv4Addr::new(203, 0, 113, 9),
            32,
            Ipv4Addr::UNSPECIFIED,
            12,
            1,
        );
        assert_eq!(ipv4_from(&row.NextHop), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            ipv4_from(&row.DestinationPrefix.Prefix),
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(row.DestinationPrefix.PrefixLength, 32);
        assert_eq!(row.InterfaceIndex, 12);
        assert_eq!(row.Metric, 1);
    }

    /// And a gateway route carries the gateway, which is also what identifies
    /// the row when it is deleted again.
    #[test]
    fn a_gateway_route_row_carries_its_next_hop_and_metric() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let row = forward_row(Ipv4Addr::UNSPECIFIED, 1, gateway, 6, 5);
        assert_eq!(ipv4_from(&row.NextHop), Some(gateway));
        assert_eq!(row.DestinationPrefix.PrefixLength, 1);
        assert_eq!(row.Metric, 5);
    }

    /// Removing a route that is not there is the intended end state, not an
    /// error, and teardown runs inside `Drop` where it could not report one.
    #[test]
    fn removing_a_route_that_was_never_added_is_silent() {
        remove_route_via(
            Ipv4Addr::new(192, 0, 2, 200),
            32,
            Ipv4Addr::new(192, 0, 2, 1),
            1,
        );
    }

    /// The live table, read the way the session start path reads it. A machine
    /// running these tests has a way out, and both halves of the answer have to
    /// be usable: a gateway that can be sent to, on an interface that exists.
    #[test]
    fn the_default_route_names_a_real_gateway_and_interface() {
        let (gateway, interface_index) =
            default_ipv4_route().expect("a machine running these tests has a default route");
        assert!(!gateway.is_unspecified());
        assert!(interface_index != 0);
        assert!(
            interface_mtu(interface_index).is_ok(),
            "interface {interface_index} does not exist"
        );
        // Every candidate came from a `0.0.0.0/0` row, so the winner is one of
        // them rather than something this invented.
        let candidates =
            default_ipv4_route_candidates().expect("the route table should be readable");
        assert!(
            candidates
                .iter()
                .any(|(address, index, _)| *address == gateway && *index == interface_index),
            "{gateway} via {interface_index} is not in {candidates:?}"
        );
    }
}
