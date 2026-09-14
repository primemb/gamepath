//! Native Windows IP configuration.
//!
//! Every function here replaces a `powershell.exe -NoProfile -Command …`
//! invocation of the matching `Net*` cmdlet. Those cmdlets are convenient but
//! they are not cheap: each call pays for a fresh PowerShell engine plus the
//! CIM/WMI machinery the NetTCPIP module sits on, which measures at roughly
//! 850-1000 ms on an ordinary desktop. The L2TP dial made five such calls in a
//! row before a session could start, so most of the wait for a session was
//! process startup rather than anything to do with the network.
//!
//! The IP Helper API underneath those cmdlets answers the same questions in
//! microseconds, from the same tables, so this is a straight substitution
//! rather than a change of behaviour.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
    GetIpInterfaceEntry, GetUnicastIpAddressTable, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_TABLE,
    SetIpInterfaceEntry,
};
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, RouterDiscoveryDisabled, SOCKADDR_IN,
    SOCKADDR_INET,
};

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
    let mut row = ip_interface_entry_for(AF_INET6, interface_index)?;
    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    // See `set_interface_mtu`: the value read back is not always one the
    // setter will accept, and zero means "leave it alone".
    row.SitePrefixLength = 0;
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
    remove_ipv6_default_routes(interface_index)
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

/// Builds an on-link route row for `destination/prefix_length` out of
/// `interface_index`.
fn forward_row(
    destination: Ipv4Addr,
    prefix_length: u8,
    interface_index: u32,
) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // Fills the defaults Windows expects for the fields this does not set.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_v4(destination),
        PrefixLength: prefix_length,
    };
    // An unspecified next hop is how the API spells "on-link", which is what
    // `New-NetRoute -NextHop 0.0.0.0` produces.
    row.NextHop = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
    row.Metric = 1;
    row
}

/// Pins `destination/prefix_length` to `interface_index`.
///
/// Replaces `Remove-NetRoute` followed by `New-NetRoute`, including the
/// removal: an existing route for the same prefix may point somewhere else, so
/// it is deleted rather than left to win.
pub fn add_route(
    destination: Ipv4Addr,
    prefix_length: u8,
    interface_index: u32,
) -> Result<(), String> {
    let row = forward_row(destination, prefix_length, interface_index);
    let status = unsafe { CreateIpForwardEntry2(&row) };
    if status == NO_ERROR {
        return Ok(());
    }
    if status != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(format!(
            "Windows could not route {destination}/{prefix_length} through interface \
             {interface_index} (error {status})"
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
/// Deliberately infallible and silent. Both callers run inside `Drop`, while
/// a connection is being torn down, and there is nothing useful a failure
/// could change there: panicking would abort the process mid-teardown and an
/// error return would only be discarded.
pub fn remove_route(destination: Ipv4Addr, prefix_length: u8, interface_index: u32) {
    let row = forward_row(destination, prefix_length, interface_index);
    unsafe { DeleteIpForwardEntry2(&row) };
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
        if let Err(error) = disable_ipv6_default_route(index) {
            // Both halves of this need administrator rights, which the service
            // and its engine child have and `cargo test` does not.
            panic!("{error} -- run this test from an elevated shell");
        }
        let after = ipv6_default_route_count(index);
        println!("interface {index}: {after} IPv6 default route(s) after");
        assert_eq!(after, 0, "an IPv6 default route survived");
        // Router discovery is off, so a second advertisement cannot undo it.
        let row = ip_interface_entry_for(AF_INET6, index).expect("IPv6 interface row");
        assert_eq!(row.RouterDiscoveryBehavior, RouterDiscoveryDisabled);
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
}
