#![cfg(windows)]

use crate::session::{DataReceiver, WireGuardSessionManager};
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::policy::{InterceptionPlan, RuleSpec, compile};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsString, c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

type OpenFn = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> isize;
type RecvFn = unsafe extern "C" fn(isize, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(isize, *const c_void, u32, *mut u32, *const Address) -> i32;
type CloseFn = unsafe extern "C" fn(isize) -> i32;
type ShutdownFn = unsafe extern "C" fn(isize, u32) -> i32;
type SetParamFn = unsafe extern "C" fn(isize, u32, u64) -> i32;
type ChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NetworkData {
    interface_index: u32,
    subinterface_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketData {
    endpoint_id: u64,
    _parent_endpoint_id: u64,
    process_id: u32,
    _local_address: [u32; 4],
    _remote_address: [u32; 4],
    local_port: u16,
    remote_port: u16,
    protocol: u8,
    _padding: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
union AddressData {
    network: NetworkData,
    socket: SocketData,
    reserved: [u8; 64],
}

impl Default for AddressData {
    fn default() -> Self {
        Self { reserved: [0; 64] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Address {
    _timestamp: i64,
    flags: u32,
    _reserved: u32,
    data: AddressData,
}

impl Address {
    fn event(self) -> u8 {
        ((self.flags >> 8) & 0xff) as u8
    }

    fn network_data(self) -> NetworkData {
        unsafe { self.data.network }
    }

    fn socket_data(self) -> SocketData {
        unsafe { self.data.socket }
    }

    fn inbound(interface_index: u32, subinterface_index: u32) -> Self {
        Self {
            data: AddressData {
                network: NetworkData {
                    interface_index,
                    subinterface_index,
                },
            },
            ..Self::default()
        }
    }
}

struct Api {
    _library: libloading::Library,
    recv: RecvFn,
    send: SendFn,
    close: CloseFn,
    shutdown: ShutdownFn,
    set_param: SetParamFn,
    checksums: ChecksumsFn,
}

unsafe impl Send for Api {}
unsafe impl Sync for Api {}

struct Handle {
    api: Arc<Api>,
    raw: isize,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    fn open(path: &Path, filter: &str, layer: u32, flags: u64) -> Result<Self, String> {
        let filter = CString::new(filter).map_err(|_| "WinDivert filter contains NUL")?;
        unsafe {
            let library = libloading::Library::new(path)
                .map_err(|error| format!("could not load WinDivert: {error}"))?;
            let open = *library
                .get::<OpenFn>(b"WinDivertOpen\0")
                .map_err(|error| error.to_string())?;
            let api = Arc::new(Api {
                recv: *library
                    .get::<RecvFn>(b"WinDivertRecv\0")
                    .map_err(|error| error.to_string())?,
                send: *library
                    .get::<SendFn>(b"WinDivertSend\0")
                    .map_err(|error| error.to_string())?,
                close: *library
                    .get::<CloseFn>(b"WinDivertClose\0")
                    .map_err(|error| error.to_string())?,
                shutdown: *library
                    .get::<ShutdownFn>(b"WinDivertShutdown\0")
                    .map_err(|error| error.to_string())?,
                set_param: *library
                    .get::<SetParamFn>(b"WinDivertSetParam\0")
                    .map_err(|error| error.to_string())?,
                checksums: *library
                    .get::<ChecksumsFn>(b"WinDivertHelperCalcChecksums\0")
                    .map_err(|error| error.to_string())?,
                _library: library,
            });
            let raw = open(filter.as_ptr(), layer, 0, flags);
            if raw == -1 {
                return Err(format!(
                    "WinDivertOpen failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self { api, raw })
        }
    }

    fn recv(&self, capacity: usize) -> Result<(Vec<u8>, Address), String> {
        let mut packet = vec![0_u8; capacity];
        let mut length = 0;
        let mut address = Address::default();
        let pointer = if capacity == 0 {
            std::ptr::null_mut()
        } else {
            packet.as_mut_ptr().cast()
        };
        if unsafe {
            (self.api.recv)(
                self.raw,
                pointer,
                capacity as u32,
                &mut length,
                &mut address,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        packet.truncate(length as usize);
        Ok((packet, address))
    }

    fn recv_into(&self, packet: &mut [u8]) -> Result<(usize, Address), std::io::Error> {
        let mut length = 0;
        let mut address = Address::default();
        if unsafe {
            (self.api.recv)(
                self.raw,
                packet.as_mut_ptr().cast(),
                packet.len() as u32,
                &mut length,
                &mut address,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok((length as usize, address))
    }

    fn send(&self, packet: &[u8], address: &Address) -> Result<(), String> {
        let mut sent = 0;
        if unsafe {
            (self.api.send)(
                self.raw,
                packet.as_ptr().cast(),
                packet.len() as u32,
                &mut sent,
                address,
            )
        } == 0
            || sent as usize != packet.len()
        {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    fn set_param(&self, parameter: u32, value: u64) -> Result<(), String> {
        if unsafe { (self.api.set_param)(self.raw, parameter, value) } == 0 {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    fn checksums(&self, packet: &mut [u8], address: &mut Address) -> Result<(), String> {
        if unsafe {
            (self.api.checksums)(packet.as_mut_ptr().cast(), packet.len() as u32, address, 0)
        } == 0
        {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    fn shutdown_receive(&self) {
        unsafe {
            (self.api.shutdown)(self.raw, 1);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.raw);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReturnKey {
    protocol: u8,
    remote_ip: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
}

#[derive(Clone, Copy)]
struct ReturnPath {
    local_ip: Ipv4Addr,
    interface_index: u32,
    subinterface_index: u32,
    process_id: Option<u32>,
    last_seen: Instant,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HandledConnection {
    application: String,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    protocol: String,
    started_at: u64,
    #[serde(skip)]
    process_id: Option<u32>,
}

/// A packet that is not ours, waiting to be put back on the network stack.
///
/// Reinjection is a syscall, and on this configuration it happens for every
/// outbound packet on the machine that is not selected. Doing it on the capture
/// loop puts the game's packets behind a download's: they share one loop, so
/// each reinject syscall is latency the next selected packet inherits. Handing
/// them to a dedicated thread takes that cost off the path game traffic uses.
struct Bypass {
    packet: Vec<u8>,
    address: Address,
}

/// Bypass packets held before the capture loop reinjects inline instead.
///
/// Deep enough to absorb a burst, and overflow is never a drop: the packet
/// belongs to some other application, and losing it to make room would break
/// that application's connection.
const BYPASS_QUEUE_DEPTH: usize = 2048;

/// Bytes the bypass queue may hold, checked alongside the depth.
///
/// The depth alone does not bound memory: with send offload Windows hands
/// WinDivert segments far larger than an MTU, so 2048 of them could be well
/// over a hundred megabytes. This is the bound that actually holds.
const BYPASS_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Packet processing above this duration can be felt by the selected game
/// even when every tunnel probe remains healthy.
const SLOW_CAPTURE_LOOP: Duration = Duration::from_millis(100);

/// Capture anomalies are combined into one line and never emitted more often
/// than this, even during a large burst.
const CAPTURE_ANOMALY_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Soft ceiling for reply routing state.
///
/// Socket close notifications normally remove these entries. The ceiling is a
/// second line of defence for providers, drivers, or abrupt process exits that
/// fail to produce a close event. An active path is never evicted to enforce it.
const RETURN_PATH_TARGET: usize = 4096;

/// Dead process checks are deliberately off the packet path. Two seconds is
/// quick enough for the UI and port reuse while remaining negligible beside
/// the socket-event stream.
const PROCESS_REAP_INTERVAL: Duration = Duration::from_secs(2);

/// Never tear down a route from one fallible system snapshot. Socket close
/// events are authoritative; fallback cleanup requires about 30 seconds of
/// consecutive evidence so a protected process or a table race cannot disrupt
/// an active game.
const STALE_FLOW_CONFIRMATIONS: u8 = 15;

/// The connection list is a live view, not session history. A flow remains
/// visible briefly between packets so ordinary game traffic does not flicker.
const ACTIVE_CONNECTION_WINDOW: Duration = Duration::from_secs(30);

/// Capture threads reading the shared WinDivert handle.
///
/// WinDivert supports concurrent receives on one handle, which is what stops a
/// burst of unrelated traffic from queueing ahead of the game's packets. Kept
/// small: the work each thread does per packet is a parse and a hash lookup,
/// and the tunnel enqueue serialises anyway, so a handful is enough to keep the
/// driver's queue drained.
fn capture_thread_count() -> usize {
    // Overridable so a machine that misbehaves with concurrent receives can be
    // pinned to a single reader without a rebuild.
    if let Some(count) = std::env::var("GAMEPATH_CAPTURE_THREADS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        return count.clamp(1, 8);
    }
    // Never more readers than the machine has cores: on a single-core box the
    // extra threads would only take turns, and a capture thread blocked in
    // `recv` is not what needs parallelising there.
    std::thread::available_parallelism()
        .map(|count| count.get().min(4))
        .unwrap_or(1)
}

struct PendingSyn {
    packet: Vec<u8>,
    address: Address,
    fields: Ipv4Fields,
    deadline: std::time::Instant,
}

/// Read-optimised view of the selector set.
///
/// Every captured packet is classified against this, so classification has to
/// be a couple of hash lookups and a binary search rather than a linear scan of
/// a map held under a mutex. Selectors change when a connection opens or
/// closes, which is rare enough that rebuilding the whole table then is far
/// cheaper than paying for the scan on every packet.
#[derive(Default)]
struct SelectorTable {
    /// Destination ranges, sorted by their first address and merged so at most
    /// one range can contain any given address.
    destinations: Vec<(u32, u32)>,
    /// Keyed by the exact tuple a packet presents, so both the port-specific
    /// and the any-port form of a flow selector are direct lookups.
    flows: HashMap<(u8, u16, Option<u16>), Selection>,
    len: usize,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Selection {
    application: Option<String>,
    process_id: Option<u32>,
}

#[derive(Clone, Debug)]
struct FlowOwner {
    endpoint_id: Option<u64>,
    process_id: u32,
    path: String,
    stale_observations: u8,
}

#[derive(Default)]
struct SelectorState {
    selectors: HashMap<TrafficSelector, Option<String>>,
    flow_owners: HashMap<TrafficSelector, Vec<FlowOwner>>,
}

impl SelectorTable {
    #[cfg(test)]
    fn build(selectors: &HashMap<TrafficSelector, Option<String>>) -> Self {
        Self::build_with_owners(selectors, &HashMap::new())
    }

    fn build_state(state: &SelectorState) -> Self {
        Self::build_with_owners(&state.selectors, &state.flow_owners)
    }

    fn build_with_owners(
        selectors: &HashMap<TrafficSelector, Option<String>>,
        flow_owners: &HashMap<TrafficSelector, Vec<FlowOwner>>,
    ) -> Self {
        let mut destinations = Vec::new();
        let mut flows = HashMap::new();
        for (selector, application) in selectors {
            match *selector {
                TrafficSelector::Destination { first, last } => destinations.push((first, last)),
                TrafficSelector::Flow {
                    protocol,
                    local_port,
                    remote_port,
                } => {
                    flows.insert(
                        (protocol, local_port, remote_port),
                        Selection {
                            application: application.clone(),
                            process_id: flow_owners
                                .get(selector)
                                .and_then(|owners| owners.last())
                                .map(|owner| owner.process_id),
                        },
                    );
                }
            }
        }
        destinations.sort_unstable();
        // Overlapping rules are ordinary - a /24 and a host inside it - and
        // merging them is what lets the search stop at the first candidate.
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(destinations.len());
        for (first, last) in destinations {
            match merged.last_mut() {
                Some(previous) if first <= previous.1.saturating_add(1) => {
                    previous.1 = previous.1.max(last);
                }
                _ => merged.push((first, last)),
            }
        }
        Self {
            destinations: merged,
            flows,
            len: selectors.len(),
        }
    }

    /// The application a packet is selected for, or `None` when nothing
    /// matches. A destination match has no application attached to it.
    fn lookup(&self, fields: Ipv4Fields) -> Option<(Option<&str>, Option<u32>)> {
        // Flows are checked first: they name the process that owns the
        // connection, which is the more specific of the two answers.
        if let Some(application) = self
            .flows
            .get(&(
                fields.protocol,
                fields.source_port,
                Some(fields.destination_port),
            ))
            .or_else(|| self.flows.get(&(fields.protocol, fields.source_port, None)))
        {
            return Some((application.application.as_deref(), application.process_id));
        }
        let destination = u32::from(fields.destination);
        let index = self
            .destinations
            .partition_point(|(first, _)| *first <= destination);
        let (_, last) = self.destinations.get(index.checked_sub(1)?)?;
        (destination <= *last).then_some((None, None))
    }
}

struct Registry {
    dll: PathBuf,
    bypass: String,
    handles: Mutex<Vec<Arc<Handle>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    selector_state: Mutex<SelectorState>,
    /// Rebuilt from `selectors` on every change. Behind an `RwLock` so
    /// classifying a packet never contends with another classifier.
    table: RwLock<Arc<SelectorTable>>,
    /// Bumped with every `table` swap, so the capture loop can hold its own
    /// copy and take the lock only when the set has actually changed.
    table_version: AtomicU64,
    handled_connections: Mutex<HashMap<ReturnKey, HandledConnection>>,
    /// Each selected remote endpoint is logged once per capture session. The
    /// fixed cap preserves enough game-server context without turning a busy
    /// application's connection churn into log spam.
    logged_destinations: Mutex<HashSet<(u8, Ipv4Addr, u16)>>,
    capture_loop_buckets: [AtomicU64; 8],
    capture_loop_peak_us: AtomicU64,
    slow_capture_loops: AtomicU64,
    capture_receive_errors: AtomicU64,
    pending_syn_depth: AtomicU64,
    pending_syn_peak: AtomicU64,
    pending_syn_overflow: AtomicU64,
    applications: Vec<String>,
    folders: Vec<String>,
    matched_sockets: AtomicU64,
    /// Times the bypass queue was full and the capture loop had to reinject
    /// inline. A climbing count means the reinjector cannot keep up.
    bypass_queue_full: AtomicU64,
    /// Bytes currently sitting in the bypass queue, so memory is bounded by
    /// size and not only by packet count.
    bypass_queued_bytes: AtomicUsize,
    capture_threads: AtomicU64,
    /// MSS advertised on captured TCP handshakes, derived from what the chosen
    /// transports add to a packet rather than fixed at a guess.
    tcp_mss: u16,
    captured_packets: AtomicU64,
    captured_bytes: AtomicU64,
    relayed_packets: AtomicU64,
    bypassed_packets: AtomicU64,
    relay_return_packets: AtomicU64,
    /// Name lookups sent through the tunnel that no rule selected. Visible
    /// because it is the one thing split mode captures without being asked
    /// to, and a zero here on a machine that is resolving names means the
    /// queries are going out some other way.
    tunnelled_dns: AtomicU64,
    /// Packets a rule selected whose destination the relay cannot reach, so
    /// they were left on the local network instead. A steadily climbing count
    /// means a selected application is talking to something on the LAN.
    local_destinations: AtomicU64,
    injected_return_packets: AtomicU64,
    /// Return packets that could not be delivered, split by why. They sum to
    /// [`Registry::unmatched_return_packets`], and exist because the three
    /// causes want different answers: a malformed packet is a bug here, a
    /// wrong destination means the relay sent something unexpected, and no
    /// flow means the table lost a connection the far end still believes in.
    return_not_ipv4: AtomicU64,
    return_wrong_destination: AtomicU64,
    return_without_flow: AtomicU64,
    unmatched_return_packets: AtomicU64,
    return_injection_errors: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum TrafficSelector {
    Destination {
        first: u32,
        last: u32,
    },
    Flow {
        protocol: u8,
        local_port: u16,
        remote_port: Option<u16>,
    },
}

impl TrafficSelector {
    /// The plain definition of a match. [`SelectorTable`] is the indexed form
    /// used on the hot path; a test asserts the two agree, which is what this
    /// is kept for.
    #[cfg(test)]
    fn matches(self, fields: Ipv4Fields) -> bool {
        match self {
            Self::Destination { first, last } => {
                let destination = u32::from(fields.destination);
                destination >= first && destination <= last
            }
            Self::Flow {
                protocol,
                local_port,
                remote_port,
            } => {
                fields.protocol == protocol
                    && fields.source_port == local_port
                    && remote_port.is_none_or(|port| fields.destination_port == port)
            }
        }
    }
}

pub struct SplitPacketCapture {
    stop: Arc<AtomicBool>,
    registry: Arc<Registry>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    target_count: usize,
    scope: CaptureScope,
}

/// How much of the outbound stream the kernel filter admits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureScope {
    /// WinDivert filter clause narrowing the capture.
    clause: String,
    /// True when the clause admits every outbound IPv4 packet, so unselected
    /// traffic is classified in user space and reinjected.
    broad: bool,
    /// Why the broad filter was needed, for diagnostics.
    reason: &'static str,
}

/// The kernel-filter half of [`is_name_resolution`].
const DNS_CLAUSE: &str = "(udp.DstPort == 53 or tcp.DstPort == 53)";

/// Ranges beyond which a destination filter stops being worth building. Each
/// range costs two comparisons in the kernel's filter program, and past this
/// the scan is no cheaper than classifying in user space.
const MAX_FILTER_RANGES: usize = 48;

/// Builds the narrowest kernel filter the plan allows.
fn capture_scope(plan: &InterceptionPlan, destinations: &[(u32, u32)]) -> CaptureScope {
    let broad = |reason| CaptureScope {
        clause: "true".to_owned(),
        broad: true,
        reason,
    };
    if !plan.application_paths.is_empty() || !plan.folder_prefixes.is_empty() {
        // The ports these rules match are only known once the process opens a
        // socket, which is after this filter is fixed.
        return broad("application and folder rules are classified in user space");
    }
    if !plan.hostnames.is_empty() {
        // A hostname's addresses can change mid-session as DNS answers arrive.
        return broad("hostname rules resolve to addresses while the session runs");
    }
    if destinations.is_empty() {
        return broad("no destination rules to narrow the filter with");
    }
    if destinations.len() > MAX_FILTER_RANGES {
        return broad("too many destination ranges for a kernel filter");
    }
    let clause = destinations
        .iter()
        .map(|(first, last)| {
            let first = Ipv4Addr::from(*first);
            let last = Ipv4Addr::from(*last);
            if first == last {
                format!("ip.DstAddr == {first}")
            } else {
                format!("(ip.DstAddr >= {first} and ip.DstAddr <= {last})")
            }
        })
        .collect::<Vec<_>>()
        .join(" or ");
    CaptureScope {
        // Name resolution is added to every narrow filter, because the
        // classifier behind it selects DNS whoever asked for it and a packet
        // the kernel never hands up cannot be selected at all.
        clause: format!("(({clause}) or {DNS_CLAUSE})"),
        broad: false,
        reason: "destination rules are matched in the kernel",
    }
}

impl SplitPacketCapture {
    pub fn start(
        rules: &[RuleSpec],
        virtual_ipv4: Ipv4Addr,
        bypass_ips: &[Ipv4Addr],
        sessions: Arc<Mutex<WireGuardSessionManager>>,
        data_receiver: Arc<DataReceiver>,
        effective_mtu: EffectiveMtu,
    ) -> Result<Self, String> {
        let plan = compile("split", rules)?;
        let registry = Arc::new(Registry {
            dll: dll_path()?,
            bypass: bypass_clause(bypass_ips),
            handles: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
            selector_state: Mutex::new(SelectorState::default()),
            table: RwLock::new(Arc::new(SelectorTable::default())),
            table_version: AtomicU64::new(0),
            handled_connections: Mutex::new(HashMap::new()),
            logged_destinations: Mutex::new(HashSet::new()),
            capture_loop_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            capture_loop_peak_us: AtomicU64::new(0),
            slow_capture_loops: AtomicU64::new(0),
            capture_receive_errors: AtomicU64::new(0),
            pending_syn_depth: AtomicU64::new(0),
            pending_syn_peak: AtomicU64::new(0),
            pending_syn_overflow: AtomicU64::new(0),
            applications: plan.application_paths.clone(),
            folders: plan.folder_prefixes.clone(),
            matched_sockets: AtomicU64::new(0),
            bypass_queue_full: AtomicU64::new(0),
            bypass_queued_bytes: AtomicUsize::new(0),
            capture_threads: AtomicU64::new(0),
            captured_packets: AtomicU64::new(0),
            captured_bytes: AtomicU64::new(0),
            relayed_packets: AtomicU64::new(0),
            bypassed_packets: AtomicU64::new(0),
            relay_return_packets: AtomicU64::new(0),
            tunnelled_dns: AtomicU64::new(0),
            local_destinations: AtomicU64::new(0),
            injected_return_packets: AtomicU64::new(0),
            return_not_ipv4: AtomicU64::new(0),
            return_wrong_destination: AtomicU64::new(0),
            return_without_flow: AtomicU64::new(0),
            unmatched_return_packets: AtomicU64::new(0),
            return_injection_errors: AtomicU64::new(0),
            tcp_mss: effective_mtu.tcp_mss(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let return_paths = Arc::new(Mutex::new(HashMap::new()));
        let send_handle = Arc::new(Handle::open(&registry.dll, "false", 0, 0x0008)?);

        for selector in destination_selectors(&plan)? {
            add_selector(&registry, selector);
        }
        for ip in resolve_hostnames(&plan) {
            add_selector(
                &registry,
                TrafficSelector::Destination {
                    first: u32::from(ip),
                    last: u32::from(ip),
                },
            );
        }

        if !plan.application_paths.is_empty() || !plan.folder_prefixes.is_empty() {
            spawn_process_tracker(
                &plan,
                Arc::clone(&registry),
                Arc::clone(&return_paths),
                Arc::clone(&stop),
            )?;
        }
        if !plan.hostnames.is_empty() {
            spawn_dns_tracker(
                plan.hostnames.clone(),
                Arc::clone(&registry),
                Arc::clone(&stop),
            )?;
        }

        // Keep one network handle open before applications create connections.
        // Classification happens in memory, removing the race where a TCP SYN
        // escaped while a new per-socket WinDivert handle was being created.
        //
        // When every rule names a destination, that whole set is expressible in
        // the kernel filter and unrelated traffic never leaves the kernel at
        // all. Process and hostname rules cannot be: a WinDivert filter is
        // fixed when the handle opens, while those two learn new addresses and
        // ports while the session runs, so they need the broad filter and the
        // in-memory classifier behind it.
        let scope = capture_scope(&plan, &selector_table(&registry).destinations);
        let network_filter = format!(
            "outbound and ip and !loopback and {} and {}",
            scope.clause, registry.bypass
        );
        let network_handle = Arc::new(Handle::open(&registry.dll, &network_filter, 0, 0)?);
        network_handle.set_param(0, 1024)?;
        network_handle.set_param(1, 100)?;
        network_handle.set_param(2, 8 * 1024 * 1024)?;
        registry
            .handles
            .lock()
            .unwrap()
            .push(Arc::clone(&network_handle));
        let (pending_tx, pending_rx) = mpsc::sync_channel(256);
        let pending_handle = Arc::clone(&network_handle);
        let pending_stop = Arc::clone(&stop);
        let pending_sessions = Arc::clone(&sessions);
        let pending_returns = Arc::clone(&return_paths);
        let pending_registry = Arc::clone(&registry);
        let worker = thread::Builder::new()
            .name("gamepath-windivert-pending-syn".into())
            .spawn(move || {
                run_pending_syns(
                    pending_handle,
                    pending_stop,
                    pending_sessions,
                    pending_returns,
                    virtual_ipv4,
                    pending_registry,
                    pending_rx,
                )
            })
            .map_err(|error| format!("could not start pending SYN classifier: {error}"))?;
        registry.workers.lock().unwrap().push(worker);
        let (bypass_tx, bypass_rx) = mpsc::sync_channel(BYPASS_QUEUE_DEPTH);
        let bypass_handle = Arc::clone(&network_handle);
        let bypass_stop = Arc::clone(&stop);
        let bypass_registry = Arc::clone(&registry);
        let worker = thread::Builder::new()
            .name("gamepath-windivert-bypass".into())
            .spawn(move || {
                run_bypass_injector(bypass_handle, bypass_stop, bypass_registry, bypass_rx)
            })
            .map_err(|error| format!("could not start the bypass injector: {error}"))?;
        registry.workers.lock().unwrap().push(worker);

        let threads = capture_thread_count();
        registry
            .capture_threads
            .store(threads as u64, Ordering::Relaxed);
        for index in 0..threads {
            let capture_handle = Arc::clone(&network_handle);
            let capture_registry = Arc::clone(&registry);
            let capture_stop = Arc::clone(&stop);
            let capture_sessions = Arc::clone(&sessions);
            let capture_returns = Arc::clone(&return_paths);
            let capture_pending = pending_tx.clone();
            let capture_bypass = bypass_tx.clone();
            let worker = thread::Builder::new()
                .name(format!("gamepath-windivert-selected-{}", index + 1))
                .spawn(move || {
                    run_selected_capture(
                        capture_handle,
                        capture_stop,
                        capture_sessions,
                        capture_returns,
                        virtual_ipv4,
                        capture_registry,
                        capture_pending,
                        capture_bypass,
                    )
                })
                .map_err(|error| format!("could not start selected packet capture: {error}"))?;
            registry.workers.lock().unwrap().push(worker);
        }

        let inject_stop = Arc::clone(&stop);
        let inject_returns = Arc::clone(&return_paths);
        let inject_registry = Arc::clone(&registry);
        let worker = thread::Builder::new()
            .name("gamepath-windivert-inject".into())
            .spawn(move || {
                run_reply_injector(
                    send_handle,
                    inject_stop,
                    data_receiver,
                    inject_returns,
                    virtual_ipv4,
                    inject_registry,
                )
            })
            .map_err(|error| format!("could not start split reply injector: {error}"))?;
        registry.workers.lock().unwrap().push(worker);

        let diagnostic_stop = Arc::clone(&stop);
        let diagnostic_registry = Arc::clone(&registry);
        let worker = thread::Builder::new()
            .name("gamepath-capture-diagnostics".into())
            .spawn(move || run_capture_diagnostics(diagnostic_stop, diagnostic_registry))
            .map_err(|error| format!("could not start capture diagnostics: {error}"))?;
        registry.workers.lock().unwrap().push(worker);

        Ok(Self {
            stop,
            registry,
            return_paths,
            target_count: rules.len(),
            scope,
        })
    }

    pub fn target_count(&self) -> usize {
        self.target_count
    }

    pub fn diagnostics(&self) -> serde_json::Value {
        let observed_at = Instant::now();
        let return_paths = self.return_paths.lock().unwrap();
        let mut handled_connections = self
            .registry
            .handled_connections
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(key, connection)| {
                return_paths
                    .get(key)
                    .is_some_and(|path| {
                        observed_at.saturating_duration_since(path.last_seen)
                            <= ACTIVE_CONNECTION_WINDOW
                    })
                    .then_some(connection.clone())
            })
            .collect::<Vec<_>>();
        handled_connections.sort_by_key(|connection| std::cmp::Reverse(connection.started_at));
        let capture_loop_histogram = [10_u64, 25, 50, 100, 250, 500, 1000, u64::MAX]
            .into_iter()
            .zip(self.registry.capture_loop_buckets.iter())
            .map(|(upper_bound_us, count)| {
                serde_json::json!({
                    "upperBoundUs": (upper_bound_us != u64::MAX).then_some(upper_bound_us),
                    "count": count.load(Ordering::Relaxed),
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "matchedSockets": self.registry.matched_sockets.load(Ordering::Relaxed),
            "captureFilterCount": selector_table(&self.registry).len,
            "captureScope": if self.scope.broad { "all-outbound" } else { "destinations" },
            "captureThreads": self.registry.capture_threads.load(Ordering::Relaxed),
            "bypassQueueFull": self.registry.bypass_queue_full.load(Ordering::Relaxed),
            "bypassQueuedBytes": self.registry.bypass_queued_bytes.load(Ordering::Relaxed),
            "captureScopeReason": self.scope.reason,
            "captureFilter": self.scope.clause,
            "tcpMss": self.registry.tcp_mss,
            "capturedPackets": self.registry.captured_packets.load(Ordering::Relaxed),
            "capturedBytes": self.registry.captured_bytes.load(Ordering::Relaxed),
            "relayedPackets": self.registry.relayed_packets.load(Ordering::Relaxed),
            "bypassedPackets": self.registry.bypassed_packets.load(Ordering::Relaxed),
            "handledConnections": handled_connections,
            "captureLoopHistogram": capture_loop_histogram,
            "captureLoopPeakUs": self.registry.capture_loop_peak_us.load(Ordering::Relaxed),
            "slowCaptureLoops": self.registry.slow_capture_loops.load(Ordering::Relaxed),
            "captureReceiveErrors": self.registry.capture_receive_errors.load(Ordering::Relaxed),
            "pendingSynDepth": self.registry.pending_syn_depth.load(Ordering::Relaxed),
            "pendingSynPeak": self.registry.pending_syn_peak.load(Ordering::Relaxed),
            "pendingSynOverflow": self.registry.pending_syn_overflow.load(Ordering::Relaxed),
            "relayReturnPackets": self.registry.relay_return_packets.load(Ordering::Relaxed),
            "injectedReturnPackets": self.registry.injected_return_packets.load(Ordering::Relaxed),
            "unmatchedReturnPackets": self.registry.unmatched_return_packets.load(Ordering::Relaxed),
            "unmatchedReturnsNotIpv4": self.registry.return_not_ipv4.load(Ordering::Relaxed),
            "unmatchedReturnsWrongDestination": self.registry.return_wrong_destination.load(Ordering::Relaxed),
            "unmatchedReturnsWithoutFlow": self.registry.return_without_flow.load(Ordering::Relaxed),
            "tunnelledDnsQueries": self.registry.tunnelled_dns.load(Ordering::Relaxed),
            "localDestinationsLeftUntunnelled": self.registry.local_destinations.load(Ordering::Relaxed),
            "returnInjectionErrors": self.registry.return_injection_errors.load(Ordering::Relaxed),
            "driverQueueTimeMs": 100,
        })
    }
}

impl Drop for SplitPacketCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for handle in self.registry.handles.lock().unwrap().iter() {
            handle.shutdown_receive();
        }
        let workers = std::mem::take(&mut *self.registry.workers.lock().unwrap());
        for worker in workers {
            let _ = worker.join();
        }
    }
}

fn add_selector(registry: &Registry, selector: TrafficSelector) {
    let mut state = registry.selector_state.lock().unwrap();
    if state.selectors.insert(selector, None).is_none() {
        publish_selectors(registry, &state);
    }
}

fn add_process_selector(
    registry: &Registry,
    selector: TrafficSelector,
    path: String,
    process_id: u32,
    endpoint_id: Option<u64>,
) {
    let application = process_name(&path);
    let owner = FlowOwner {
        endpoint_id,
        process_id,
        path,
        stale_observations: 0,
    };
    let mut state = registry.selector_state.lock().unwrap();
    let owners = state.flow_owners.entry(selector).or_default();
    // A packet-table lookup may discover a TCP flow just before WinDivert's
    // CONNECT notification arrives. Replace that PID-only fallback with the
    // endpoint-owned record so the later CLOSE notification can remove it.
    if endpoint_id.is_some() {
        owners.retain(|held| !(held.endpoint_id.is_none() && held.process_id == process_id));
    }
    let owner_added = match owners.iter_mut().find(|held| {
        held.endpoint_id == owner.endpoint_id
            && held.process_id == owner.process_id
            && held.path == owner.path
    }) {
        Some(held) => {
            held.stale_observations = 0;
            false
        }
        None => {
            owners.push(owner);
            true
        }
    };
    let label_changed =
        state.selectors.insert(selector, Some(application.clone())) != Some(Some(application));
    if owner_added || label_changed {
        publish_selectors(registry, &state);
    }
}

/// Swaps in a fresh classification table. Called with the selector lock held so
/// the table is never built from a half-applied change.
fn publish_selectors(registry: &Registry, state: &SelectorState) {
    *registry.table.write().unwrap() = Arc::new(SelectorTable::build_state(state));
    registry.table_version.fetch_add(1, Ordering::Release);
}

/// The current classification table. The read lock is released before any
/// packet work, so a selector change is never blocked behind one.
fn selector_table(registry: &Registry) -> Arc<SelectorTable> {
    Arc::clone(&registry.table.read().unwrap())
}

struct CaptureLoopTimer<'a> {
    started: Instant,
    registry: &'a Registry,
}

impl Drop for CaptureLoopTimer<'_> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_micros() as u64;
        self.registry
            .capture_loop_peak_us
            .fetch_max(elapsed, Ordering::Relaxed);
        if elapsed >= SLOW_CAPTURE_LOOP.as_micros() as u64 {
            self.registry
                .slow_capture_loops
                .fetch_add(1, Ordering::Relaxed);
        }
        let bucket = [10_u64, 25, 50, 100, 250, 500, 1000]
            .iter()
            .position(|upper| elapsed <= *upper)
            .unwrap_or(7);
        self.registry.capture_loop_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_selected_capture(
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
    registry: Arc<Registry>,
    pending_syns: mpsc::SyncSender<PendingSyn>,
    bypass: mpsc::SyncSender<Bypass>,
) {
    let mut packet_buffer = vec![0_u8; 65_535];
    let mut tunnel_buffer = Vec::with_capacity(65_535);
    // The table is swapped only when a connection opens or closes, so the loop
    // keeps its own copy and touches the lock on the versions that change.
    let mut table_version = registry.table_version.load(Ordering::Acquire);
    let mut table = selector_table(&registry);
    while !stop.load(Ordering::Acquire) {
        let (packet_length, address) = match handle.recv_into(&mut packet_buffer) {
            Ok(packet) => packet,
            Err(error) => {
                if !stop.load(Ordering::Acquire) {
                    registry
                        .capture_receive_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
                if !stop.load(Ordering::Acquire) && matches!(error.raw_os_error(), Some(122 | 232))
                {
                    continue;
                }
                break;
            }
        };
        let _loop_timer = CaptureLoopTimer {
            started: Instant::now(),
            registry: &registry,
        };
        let current_version = registry.table_version.load(Ordering::Acquire);
        if current_version != table_version {
            table = selector_table(&registry);
            table_version = current_version;
        }
        let packet = &packet_buffer[..packet_length];
        let Some(fields) = ipv4_fields(packet) else {
            reinject(&handle, &bypass, &registry, packet, address);
            continue;
        };
        let (mut selected, application, mut process_id) = match table.lookup(fields) {
            Some((application, process_id)) => (true, application.map(Cow::Borrowed), process_id),
            None => (false, None, None),
        };
        let mut application = application;
        // Name resolution goes through the tunnel no matter which process asked
        // for it, and this is the only place it can be caught.
        //
        // An application rule cannot do it. Windows applications do not send
        // DNS themselves: they call the resolver, and the DNS Client service
        // inside svchost.exe sends the query. So a rule naming a game selects
        // every packet that game sends and still leaves its name lookups going
        // out untunnelled, owned by a process the user never selected. On a
        // connection that filters DNS by name, the game then resolves its own
        // servers to a blackhole address while the tunnel beside it is
        // perfectly healthy - which looks like the tunnel failing and is not.
        // Measured on such a connection: `steamcommunity.com` and
        // `discord.com` resolved to 10.10.34.36, while unlisted names resolved
        // correctly.
        //
        // TCP as well as UDP: a truncated answer is retried over TCP, so
        // selecting only UDP would leak exactly the largest replies.
        //
        // If the session cannot carry it, `route_selected_packet` fails open
        // and the query takes the normal route, so this can cost lookups
        // latency but never the ability to resolve.
        if !selected && is_name_resolution(fields) {
            selected = true;
            registry.tunnelled_dns.fetch_add(1, Ordering::Relaxed);
        }
        // CONNECT and the first TCP SYN can run on different scheduler threads.
        // Briefly hold only an unmatched SYN so the socket observer can classify it.
        if !selected && is_tcp_syn(packet) {
            if let Some((matched_process_id, path)) =
                tcp_socket_process(fields, &registry.applications, &registry.folders)
            {
                application = Some(Cow::Owned(process_name(&path)));
                process_id = Some(matched_process_id);
                add_process_selector(
                    &registry,
                    TrafficSelector::Flow {
                        protocol: 6,
                        local_port: fields.source_port,
                        remote_port: Some(fields.destination_port),
                    },
                    path,
                    matched_process_id,
                    None,
                );
                registry.matched_sockets.fetch_add(1, Ordering::Relaxed);
                selected = true;
            } else {
                let pending = PendingSyn {
                    packet: packet.to_vec(),
                    address,
                    fields,
                    deadline: Instant::now() + Duration::from_millis(3),
                };
                let depth = registry.pending_syn_depth.fetch_add(1, Ordering::Relaxed) + 1;
                match pending_syns.try_send(pending) {
                    Ok(()) => {
                        registry
                            .pending_syn_peak
                            .fetch_max(depth, Ordering::Relaxed);
                    }
                    Err(mpsc::TrySendError::Full(pending)) => {
                        registry.pending_syn_depth.fetch_sub(1, Ordering::Relaxed);
                        registry
                            .pending_syn_overflow
                            .fetch_add(1, Ordering::Relaxed);
                        let _ = handle.send(&pending.packet, &pending.address);
                    }
                    Err(mpsc::TrySendError::Disconnected(pending)) => {
                        registry.pending_syn_depth.fetch_sub(1, Ordering::Relaxed);
                        let _ = handle.send(&pending.packet, &pending.address);
                    }
                }
                continue;
            }
        }
        // A rule says which traffic the user wants carried; it cannot say the
        // relay is able to carry it. A private, link-local or multicast
        // destination means something different at the far end of the tunnel -
        // the relay resolving `192.168.1.10` would find its own LAN or nothing
        // at all - so selecting one does not redirect the packet, it discards
        // it. Observed live: an application rule sent the launcher's mDNS
        // discovery to `224.0.0.251:5353` down the tunnel.
        //
        // This is the general form of the check `is_name_resolution` makes for
        // itself. It applies to every way a packet can be selected, because a
        // rule naming an application selects a LAN game server, a printer or a
        // NAS exactly as readily as it selects the game's own servers.
        if selected && !crate::netutil::is_globally_routable_ipv4(fields.destination) {
            selected = false;
            registry.local_destinations.fetch_add(1, Ordering::Relaxed);
        }
        if !selected {
            reinject(&handle, &bypass, &registry, packet, address);
            continue;
        }
        route_selected_packet(
            &handle,
            &sessions,
            &return_paths,
            virtual_ipv4,
            &registry,
            packet,
            address,
            fields,
            application.as_deref(),
            process_id,
            &mut tunnel_buffer,
        );
    }
}

/// Hands a packet that is not ours to the reinjector, or puts it back inline
/// if that queue is full.
///
/// Falling back inline costs this loop a syscall, which is the thing being
/// avoided - but dropping the packet would break some other application's
/// connection, and that is worse than the latency.
fn reinject(
    handle: &Handle,
    bypass: &mpsc::SyncSender<Bypass>,
    registry: &Registry,
    packet: &[u8],
    address: Address,
) {
    // Reserved before the packet is copied, so the byte bound holds even with
    // every capture thread queueing at once. A failed reservation reinjects
    // inline, which costs this loop a syscall but never loses the packet.
    let reserved =
        registry
            .bypass_queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                (queued + packet.len() <= BYPASS_QUEUE_BYTES).then(|| queued + packet.len())
            });
    if reserved.is_ok() {
        let length = packet.len();
        match bypass.try_send(Bypass {
            packet: packet.to_vec(),
            address,
        }) {
            Ok(()) => return,
            Err(mpsc::TrySendError::Full(held) | mpsc::TrySendError::Disconnected(held)) => {
                // The depth bound rejected it, so give the reservation back
                // before falling through to the inline path.
                registry
                    .bypass_queued_bytes
                    .fetch_sub(length, Ordering::AcqRel);
                registry.bypass_queue_full.fetch_add(1, Ordering::Relaxed);
                let _ = handle.send(&held.packet, &held.address);
                return;
            }
        }
    }
    registry.bypass_queue_full.fetch_add(1, Ordering::Relaxed);
    let _ = handle.send(packet, &address);
}

/// Puts packets that were not selected back on the network stack.
///
/// One thread, so the traffic it carries keeps its order: these are other
/// applications' packets and reordering them is a cost with no upside.
fn run_bypass_injector(
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    registry: Arc<Registry>,
    bypass: mpsc::Receiver<Bypass>,
) {
    let send = |item: &Bypass| {
        let _ = handle.send(&item.packet, &item.address);
        registry
            .bypass_queued_bytes
            .fetch_sub(item.packet.len(), Ordering::AcqRel);
    };
    loop {
        match bypass.recv_timeout(Duration::from_millis(50)) {
            Ok(item) => send(&item),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
            // Every capture thread has gone; drain what is left so nothing is
            // taken out of the network stack and never put back.
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                while let Ok(item) = bypass.try_recv() {
                    send(&item);
                }
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn route_selected_packet(
    handle: &Handle,
    sessions: &Mutex<WireGuardSessionManager>,
    return_paths: &Mutex<HashMap<ReturnKey, ReturnPath>>,
    virtual_ipv4: Ipv4Addr,
    registry: &Registry,
    packet: &[u8],
    address: Address,
    fields: Ipv4Fields,
    application: Option<&str>,
    process_id: Option<u32>,
    tunnel_buffer: &mut Vec<u8>,
) {
    let connection_key = ReturnKey::outbound(fields);
    let now = Instant::now();
    let mut paths = return_paths.lock().unwrap();
    if !paths.contains_key(&connection_key) && paths.len() >= RETURN_PATH_TARGET {
        if let Some(oldest) = paths
            .iter()
            .filter(|(_, path)| {
                path.process_id.is_none()
                    && now.saturating_duration_since(path.last_seen) > ACTIVE_CONNECTION_WINDOW
            })
            .min_by_key(|(_, path)| path.last_seen)
            .map(|(key, _)| *key)
        {
            paths.remove(&oldest);
            registry.handled_connections.lock().unwrap().remove(&oldest);
        }
    }
    let previous = paths.insert(
        connection_key,
        ReturnPath {
            local_ip: fields.source,
            interface_index: address.network_data().interface_index,
            subinterface_index: address.network_data().subinterface_index,
            process_id,
            last_seen: now,
        },
    );
    drop(paths);
    let is_new_connection = previous.is_none_or(|path| path.process_id != process_id);
    if is_new_connection {
        record_handled_connection(registry, connection_key, fields, application, process_id);
    }
    registry.captured_packets.fetch_add(1, Ordering::Relaxed);
    registry
        .captured_bytes
        .fetch_add(packet.len() as u64, Ordering::Relaxed);
    tunnel_buffer.clear();
    tunnel_buffer.extend_from_slice(packet);
    let tunneled = &mut tunnel_buffer[..];
    tunneled[12..16].copy_from_slice(&virtual_ipv4.octets());
    clamp_tcp_mss(tunneled, registry.tcp_mss);
    let mut checksum_address = address;
    if handle.checksums(tunneled, &mut checksum_address).is_err()
        || sessions
            .lock()
            .unwrap()
            .enqueue_data_packet(tunneled)
            .is_err()
    {
        // Fail open for the selected connection when the relay is unavailable.
        registry.bypassed_packets.fetch_add(1, Ordering::Relaxed);
        let _ = handle.send(packet, &address);
    } else {
        registry.relayed_packets.fetch_add(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_pending_syns(
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
    registry: Arc<Registry>,
    pending: mpsc::Receiver<PendingSyn>,
) {
    let mut tunnel_buffer = Vec::with_capacity(65_535);
    loop {
        let item = match pending.recv_timeout(Duration::from_millis(10)) {
            Ok(item) => item,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        registry.pending_syn_depth.fetch_sub(1, Ordering::Relaxed);
        if stop.load(Ordering::Acquire) {
            // The capture handle is shutting down. Reinject every packet that
            // was already removed from the network stack before exiting.
            let _ = handle.send(&item.packet, &item.address);
            continue;
        }
        if let Some(wait) = item.deadline.checked_duration_since(Instant::now()) {
            thread::sleep(wait);
        }
        let table = selector_table(&registry);
        if let Some((application, process_id)) = table.lookup(item.fields) {
            route_selected_packet(
                &handle,
                &sessions,
                &return_paths,
                virtual_ipv4,
                &registry,
                &item.packet,
                item.address,
                item.fields,
                application,
                process_id,
                &mut tunnel_buffer,
            );
        } else {
            let _ = handle.send(&item.packet, &item.address);
        }
    }
}

fn spawn_process_tracker(
    plan: &InterceptionPlan,
    registry: Arc<Registry>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    // SOCKET events are observation-only. SNIFF|RECV_ONLY copies events while
    // allowing Windows to create every socket normally.
    let handle = Arc::new(Handle::open(&registry.dll, "true", 3, 0x0005)?);
    registry.handles.lock().unwrap().push(Arc::clone(&handle));
    let applications = plan.application_paths.clone();
    let folders = plan.folder_prefixes.clone();
    let worker_registry = Arc::clone(&registry);
    let worker_stop = Arc::clone(&stop);
    let worker_returns = Arc::clone(&return_paths);
    let worker = thread::Builder::new()
        .name("gamepath-windivert-processes".into())
        .spawn(move || {
            // WinDivert reports only future socket events. Seed UDP filters for game
            // sockets that already existed when the user pressed Start session.
            // Existing TCP connections cannot move to a different public IP safely.
            for socket in existing_ipv4_udp_sockets().unwrap_or_default() {
                if let Some(path) = process_path(socket.process_id)
                    .filter(|path| path_matches(path, &applications, &folders))
                {
                    worker_registry
                        .matched_sockets
                        .fetch_add(1, Ordering::Relaxed);
                    add_process_selector(
                        &worker_registry,
                        socket.selector(),
                        path,
                        socket.process_id,
                        None,
                    );
                }
            }
            while !worker_stop.load(Ordering::Acquire) {
                let Ok((_, address)) = handle.recv(0) else {
                    break;
                };
                let event_kind = address.event();
                let event = address.socket_data();
                if event_kind == 7 {
                    remove_closed_socket(&worker_registry, &worker_returns, event);
                    continue;
                }
                if !matches!(event_kind, 3 | 4) {
                    continue;
                }
                // WinDivert SOCKET-layer ports are already in host byte order.
                let port = event.local_port;
                let Some(path) = process_path(event.process_id)
                    .filter(|path| path_matches(path, &applications, &folders))
                else {
                    continue;
                };
                if port == 0 {
                    continue;
                }
                let protocol = match event.protocol {
                    6 | 17 => event.protocol,
                    _ => continue,
                };
                let remote_port = event.remote_port;
                worker_registry
                    .matched_sockets
                    .fetch_add(1, Ordering::Relaxed);
                add_process_selector(
                    &worker_registry,
                    TrafficSelector::Flow {
                        protocol,
                        local_port: port,
                        remote_port: (remote_port != 0).then_some(remote_port),
                    },
                    path,
                    event.process_id,
                    (event.endpoint_id != 0).then_some(event.endpoint_id),
                );
            }
        })
        .map_err(|error| format!("could not start process tracker: {error}"))?;
    registry.workers.lock().unwrap().push(worker);

    let reaper_registry = Arc::clone(&registry);
    let reaper_returns = Arc::clone(&return_paths);
    let reaper_stop = Arc::clone(&stop);
    let reaper = thread::Builder::new()
        .name("gamepath-flow-reaper".into())
        .spawn(move || {
            while !reaper_stop.load(Ordering::Acquire) {
                thread::sleep(PROCESS_REAP_INTERVAL);
                reap_stale_flows(&reaper_registry, &reaper_returns);
            }
        })
        .map_err(|error| format!("could not start process reaper: {error}"))?;
    registry.workers.lock().unwrap().push(reaper);
    Ok(())
}

fn remove_closed_socket(
    registry: &Registry,
    return_paths: &Mutex<HashMap<ReturnKey, ReturnPath>>,
    event: SocketData,
) {
    let mut state = registry.selector_state.lock().unwrap();
    let mut emptied = Vec::new();
    let mut relabeled = Vec::new();
    let mut removed_owners = HashSet::new();
    for (selector, owners) in &mut state.flow_owners {
        let before = owners.len();
        owners.retain(|owner| {
            let exact_endpoint =
                event.endpoint_id != 0 && owner.endpoint_id == Some(event.endpoint_id);
            if exact_endpoint {
                removed_owners.insert((owner.process_id, *selector));
            }
            !exact_endpoint
        });
        if owners.is_empty() {
            emptied.push(*selector);
        } else if owners.len() != before {
            relabeled.push((*selector, process_name(&owners.last().unwrap().path)));
        }
    }
    for (selector, application) in relabeled {
        state.selectors.insert(selector, Some(application));
    }
    for selector in &emptied {
        state.flow_owners.remove(selector);
        state.selectors.remove(selector);
    }
    if !removed_owners.is_empty() {
        publish_selectors(registry, &state);
    }
    // Different endpoints can share the selector's reduced port tuple. Keep
    // their common reply state while any owner from the same process survives.
    removed_owners.retain(|(process_id, selector)| {
        !state
            .flow_owners
            .get(selector)
            .is_some_and(|owners| owners.iter().any(|owner| owner.process_id == *process_id))
    });
    drop(state);
    remove_owned_routes(registry, return_paths, &removed_owners);
}

fn reap_stale_flows(registry: &Registry, return_paths: &Mutex<HashMap<ReturnKey, ReturnPath>>) {
    // Missing inventory is uncertainty, not evidence that every socket died.
    let Some(active_sockets) = existing_ipv4_process_sockets() else {
        return;
    };
    let observed_at = Instant::now();
    let recently_routed = {
        let paths = return_paths.lock().unwrap();
        paths
            .iter()
            .filter_map(|(key, path)| {
                let process_id = path.process_id?;
                (observed_at.saturating_duration_since(path.last_seen) <= ACTIVE_CONNECTION_WINDOW)
                    .then_some((
                        process_id,
                        TrafficSelector::Flow {
                            protocol: key.protocol,
                            local_port: key.local_port,
                            remote_port: Some(key.remote_port),
                        },
                    ))
            })
            .flat_map(|(process_id, selector)| {
                let TrafficSelector::Flow {
                    protocol,
                    local_port,
                    ..
                } = selector
                else {
                    unreachable!();
                };
                [
                    (process_id, selector),
                    (
                        process_id,
                        TrafficSelector::Flow {
                            protocol,
                            local_port,
                            remote_port: None,
                        },
                    ),
                ]
            })
            .collect::<HashSet<_>>()
    };
    let process_ids = {
        let state = registry.selector_state.lock().unwrap();
        state
            .flow_owners
            .values()
            .flatten()
            .map(|owner| owner.process_id)
            .collect::<HashSet<_>>()
    };
    let process_paths = process_ids
        .into_iter()
        .map(|process_id| (process_id, process_path(process_id)))
        .collect::<HashMap<_, _>>();

    let mut state = registry.selector_state.lock().unwrap();
    let mut emptied = Vec::new();
    let mut relabeled = Vec::new();
    let mut stale_owners = HashSet::new();
    let mut reaped = 0_u64;
    for (selector, owners) in &mut state.flow_owners {
        let before = owners.len();
        owners.retain_mut(|owner| {
            let socket_missing = !socket_is_active(*selector, owner.process_id, &active_sockets);
            let identity_changed = process_paths
                .get(&owner.process_id)
                .and_then(|current| current.as_deref())
                .is_some_and(|current| !current.eq_ignore_ascii_case(&owner.path));
            let recent_traffic = recently_routed.contains(&(owner.process_id, *selector));
            if identity_changed || (socket_missing && !recent_traffic) {
                owner.stale_observations = owner.stale_observations.saturating_add(1);
            } else {
                // A present socket or recent routed packet is enough to keep a
                // protected process whose executable path cannot be queried.
                owner.stale_observations = 0;
            }
            let stale = owner.stale_observations >= STALE_FLOW_CONFIRMATIONS;
            if stale {
                stale_owners.insert((owner.process_id, *selector));
            }
            !stale
        });
        reaped += (before - owners.len()) as u64;
        if owners.is_empty() {
            emptied.push(*selector);
        } else if owners.len() != before {
            relabeled.push((*selector, process_name(&owners.last().unwrap().path)));
        }
    }
    for (selector, application) in relabeled {
        state.selectors.insert(selector, Some(application));
    }
    for selector in &emptied {
        state.flow_owners.remove(selector);
        state.selectors.remove(selector);
    }
    if reaped != 0 {
        publish_selectors(registry, &state);
    }
    stale_owners.retain(|(process_id, selector)| {
        !state
            .flow_owners
            .get(selector)
            .is_some_and(|owners| owners.iter().any(|owner| owner.process_id == *process_id))
    });
    drop(state);

    if stale_owners.is_empty() {
        return;
    }

    remove_owned_routes(registry, return_paths, &stale_owners);
}

fn remove_owned_routes(
    registry: &Registry,
    return_paths: &Mutex<HashMap<ReturnKey, ReturnPath>>,
    removed_owners: &HashSet<(u32, TrafficSelector)>,
) {
    if removed_owners.is_empty() {
        return;
    }
    let mut paths = return_paths.lock().unwrap();
    paths.retain(|key, path| {
        path.process_id.is_none_or(|process_id| {
            !stale_owner_matches_return_key(removed_owners, process_id, key)
        })
    });
    drop(paths);
    registry
        .handled_connections
        .lock()
        .unwrap()
        .retain(|key, connection| {
            connection.process_id.is_none_or(|process_id| {
                !stale_owner_matches_return_key(removed_owners, process_id, key)
            })
        });
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ExistingSocket {
    process_id: u32,
    protocol: u8,
    local_port: u16,
    remote_port: u16,
}

impl ExistingSocket {
    fn selector(self) -> TrafficSelector {
        TrafficSelector::Flow {
            protocol: self.protocol,
            local_port: self.local_port,
            remote_port: (self.remote_port != 0).then_some(self.remote_port),
        }
    }
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
    fn GetExtendedUdpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

fn tcp_socket_process(
    fields: Ipv4Fields,
    applications: &[String],
    folders: &[String],
) -> Option<(u32, String)> {
    let buffer = ip_table(|table, size| unsafe { GetExtendedTcpTable(table, size, 0, 2, 5, 0) })?;
    dword_rows(&buffer, 6).into_iter().find_map(|row| {
        if port_from_dword(row[2]) != fields.source_port
            || port_from_dword(row[4]) != fields.destination_port
            || Ipv4Addr::from(row[3].to_ne_bytes()) != fields.destination
        {
            return None;
        }
        process_path(row[5])
            .filter(|path| path_matches(path, applications, folders))
            .map(|path| (row[5], path))
    })
}

fn socket_is_active(
    selector: TrafficSelector,
    process_id: u32,
    sockets: &HashSet<ExistingSocket>,
) -> bool {
    let TrafficSelector::Flow {
        protocol,
        local_port,
        remote_port,
    } = selector
    else {
        return true;
    };
    if protocol == 17 || remote_port.is_some() {
        return sockets.contains(&ExistingSocket {
            process_id,
            protocol,
            local_port,
            remote_port: remote_port.unwrap_or(0),
        });
    }
    sockets.iter().any(|socket| {
        socket.process_id == process_id
            && socket.protocol == protocol
            && socket.local_port == local_port
    })
}

fn stale_owner_matches_return_key(
    stale: &HashSet<(u32, TrafficSelector)>,
    process_id: u32,
    key: &ReturnKey,
) -> bool {
    stale.contains(&(
        process_id,
        TrafficSelector::Flow {
            protocol: key.protocol,
            local_port: key.local_port,
            remote_port: Some(key.remote_port),
        },
    )) || stale.contains(&(
        process_id,
        TrafficSelector::Flow {
            protocol: key.protocol,
            local_port: key.local_port,
            remote_port: None,
        },
    ))
}

fn existing_ipv4_udp_sockets() -> Option<Vec<ExistingSocket>> {
    let mut sockets = Vec::new();
    // MIB_UDPROW_OWNER_PID is three DWORDs; UDP has no fixed remote endpoint.
    let buffer = ip_table(|table, size| unsafe { GetExtendedUdpTable(table, size, 0, 2, 1, 0) })?;
    for row in dword_rows(&buffer, 3) {
        let local_port = port_from_dword(row[1]);
        if local_port != 0 {
            sockets.push(ExistingSocket {
                process_id: row[2],
                protocol: 17,
                local_port,
                remote_port: 0,
            });
        }
    }
    Some(sockets)
}

fn existing_ipv4_process_sockets() -> Option<HashSet<ExistingSocket>> {
    let mut sockets = existing_ipv4_udp_sockets()?
        .into_iter()
        .collect::<HashSet<_>>();
    // MIB_TCPROW_OWNER_PID is six DWORDs: state, local address/port,
    // remote address/port, and PID. Closed/TIME_WAIT rows owned by PID zero do
    // not keep a process flow alive.
    let buffer = ip_table(|table, size| unsafe { GetExtendedTcpTable(table, size, 0, 2, 5, 0) })?;
    for row in dword_rows(&buffer, 6) {
        let local_port = port_from_dword(row[2]);
        let remote_port = port_from_dword(row[4]);
        let process_id = row[5];
        if process_id != 0 && local_port != 0 {
            sockets.insert(ExistingSocket {
                process_id,
                protocol: 6,
                local_port,
                remote_port,
            });
        }
    }
    Some(sockets)
}

fn ip_table(call: impl Fn(*mut c_void, *mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0_u32;
    let _ = call(std::ptr::null_mut(), &mut size);
    if size < 4 {
        return None;
    }
    let mut buffer = vec![0_u8; size as usize];
    // The table may grow between the size probe and the read. Windows updates
    // `size` with the new requirement, so retry without ever treating a
    // temporary inventory failure as an empty table.
    for _ in 0..3 {
        let status = call(buffer.as_mut_ptr().cast(), &mut size);
        if status == 0 {
            return Some(buffer);
        }
        if status != 122 || size < 4 {
            return None;
        }
        buffer.resize(size as usize, 0);
    }
    None
}

fn dword_rows(buffer: &[u8], width: usize) -> Vec<Vec<u32>> {
    if buffer.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_ne_bytes(buffer[0..4].try_into().unwrap()) as usize;
    let row_bytes = width * 4;
    (0..count)
        .filter_map(|index| {
            let start = 4 + index * row_bytes;
            let bytes = buffer.get(start..start + row_bytes)?;
            Some(
                bytes
                    .chunks_exact(4)
                    .map(|part| u32::from_ne_bytes(part.try_into().unwrap()))
                    .collect(),
            )
        })
        .collect()
}

fn port_from_dword(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn spawn_dns_tracker(
    hostnames: Vec<String>,
    registry: Arc<Registry>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    // SNIFF|RECV_ONLY copies DNS replies; it never diverts them from Windows.
    let handle = Arc::new(Handle::open(
        &registry.dll,
        "inbound and ip and udp.SrcPort == 53",
        0,
        0x0005,
    )?);
    registry.handles.lock().unwrap().push(Arc::clone(&handle));
    let worker_registry = Arc::clone(&registry);
    let worker_stop = Arc::clone(&stop);
    let worker = thread::Builder::new()
        .name("gamepath-windivert-dns".into())
        .spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                let Ok((packet, _)) = handle.recv(65_535) else {
                    break;
                };
                for address in dns_addresses(&packet, &hostnames) {
                    add_selector(
                        &worker_registry,
                        TrafficSelector::Destination {
                            first: u32::from(address),
                            last: u32::from(address),
                        },
                    );
                }
            }
        })
        .map_err(|error| format!("could not start hostname tracker: {error}"))?;
    registry.workers.lock().unwrap().push(worker);
    Ok(())
}

fn run_reply_injector(
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    data_receiver: Arc<DataReceiver>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
    registry: Arc<Registry>,
) {
    while !stop.load(Ordering::Acquire) {
        let received = data_receiver.receive(Duration::from_millis(20));
        let mut packet = match received {
            Ok(Some(packet)) => {
                registry
                    .relay_return_packets
                    .fetch_add(1, Ordering::Relaxed);
                packet
            }
            Ok(None) => continue,
            Err(_) => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
        };
        let Some(fields) = ipv4_fields(&packet) else {
            registry.return_not_ipv4.fetch_add(1, Ordering::Relaxed);
            registry
                .unmatched_return_packets
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if fields.destination != virtual_ipv4 {
            registry
                .return_wrong_destination
                .fetch_add(1, Ordering::Relaxed);
            registry
                .unmatched_return_packets
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let path = {
            let mut paths = return_paths.lock().unwrap();
            let Some(path) = paths.get_mut(&ReturnKey::inbound(fields)) else {
                registry.return_without_flow.fetch_add(1, Ordering::Relaxed);
                registry
                    .unmatched_return_packets
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            path.last_seen = Instant::now();
            *path
        };
        packet[16..20].copy_from_slice(&path.local_ip.octets());
        clamp_tcp_mss(&mut packet, 1000);
        let mut address = Address::inbound(path.interface_index, path.subinterface_index);
        if handle.checksums(&mut packet, &mut address).is_ok()
            && handle.send(&packet, &address).is_ok()
        {
            registry
                .injected_return_packets
                .fetch_add(1, Ordering::Relaxed);
        } else {
            registry
                .return_injection_errors
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Watches counters outside the packet path and writes one combined incident
/// record. Keeping formatting and logging here ensures a burst never makes a
/// capture thread do disk I/O or emit one warning per packet.
fn run_capture_diagnostics(stop: Arc<AtomicBool>, registry: Arc<Registry>) {
    let read = || {
        [
            registry.bypassed_packets.load(Ordering::Relaxed),
            registry.bypass_queue_full.load(Ordering::Relaxed),
            registry.capture_receive_errors.load(Ordering::Relaxed),
            registry.pending_syn_overflow.load(Ordering::Relaxed),
            registry.slow_capture_loops.load(Ordering::Relaxed),
            // The three causes rather than their sum. They want different
            // answers, and a return packet discarded because the flow table
            // lost a connection the far end still believes in -- a game losing
            // its inbound stream while every tunnel probe stays healthy --
            // cannot be told apart from ordinary socket teardown once they are
            // added together.
            registry.return_not_ipv4.load(Ordering::Relaxed),
            registry.return_wrong_destination.load(Ordering::Relaxed),
            registry.return_without_flow.load(Ordering::Relaxed),
            registry.return_injection_errors.load(Ordering::Relaxed),
        ]
    };
    let mut reported = read();
    let mut last_log: Option<Instant> = None;
    while !stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(250));
        let observed_at = Instant::now();
        let current = read();
        let changed = current
            .iter()
            .zip(&reported)
            .any(|(value, previous)| value > previous);
        if !changed
            || last_log.is_some_and(|logged| {
                observed_at.duration_since(logged) < CAPTURE_ANOMALY_LOG_INTERVAL
            })
        {
            continue;
        }
        let delta =
            std::array::from_fn::<_, 9, _>(|index| current[index].saturating_sub(reported[index]));
        gamepath_engine::log_warn!(
            "split capture anomaly: selected-fail-open=+{} bypass-queue-full=+{} \
             receive-errors=+{} pending-syn-overflow=+{} slow-loops=+{} \
             returns-dropped=+{}/{}/{} (not-ipv4/wrong-dest/no-flow) \n             return-injection-errors=+{} peak-loop={}us",
            delta[0],
            delta[1],
            delta[2],
            delta[3],
            delta[4],
            delta[5],
            delta[6],
            delta[7],
            delta[8],
            registry.capture_loop_peak_us.load(Ordering::Relaxed),
        );
        reported = current;
        last_log = Some(observed_at);
    }
}

fn clamp_tcp_mss(packet: &mut [u8], maximum: u16) {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return;
    }
    let ip_header = usize::from(packet[0] & 0x0f) * 4;
    if packet.len() < ip_header + 20 || packet[ip_header + 13] & 0x02 == 0 {
        return;
    }
    let tcp_header = usize::from(packet[ip_header + 12] >> 4) * 4;
    if tcp_header < 20 || packet.len() < ip_header + tcp_header {
        return;
    }
    let mut offset = ip_header + 20;
    let end = ip_header + tcp_header;
    while offset < end {
        match packet[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let Some(&length) = packet.get(offset + 1) else {
                    break;
                };
                let length = usize::from(length);
                if length < 2 || offset + length > end {
                    break;
                }
                if kind == 2 && length == 4 {
                    let current = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                    if current > maximum {
                        packet[offset + 2..offset + 4].copy_from_slice(&maximum.to_be_bytes());
                    }
                    break;
                }
                offset += length;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Ipv4Fields {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
}

/// Whether this is a name lookup the tunnel can actually carry.
///
/// Port 53 is not enough on its own. A home machine's resolver is usually its
/// own router, and `192.168.1.1` means the relay's LAN — or nothing — once the
/// packet arrives there, so tunnelling such a query does not redirect it, it
/// drops it. Observed live: a split session selected `UDP 192.168.1.1:53` and
/// sent it to a relay that could never answer it.
///
/// So only a query already addressed to a public resolver is taken. That is
/// the case this can improve — the same public resolver, reached from the
/// relay instead of through a filter that rewrites the answer on the way. A
/// query to a LAN resolver is left alone, because the honest alternatives are
/// to break it or to change which resolver the machine uses, and silently
/// doing the second from inside a packet filter is not something split mode
/// should do.
fn is_name_resolution(fields: Ipv4Fields) -> bool {
    matches!(fields.protocol, 6 | 17)
        && fields.destination_port == 53
        && crate::netutil::is_globally_routable_ipv4(fields.destination)
}

impl ReturnKey {
    fn outbound(fields: Ipv4Fields) -> Self {
        Self {
            protocol: fields.protocol,
            remote_ip: fields.destination,
            local_port: fields.source_port,
            remote_port: fields.destination_port,
        }
    }

    fn inbound(fields: Ipv4Fields) -> Self {
        Self {
            protocol: fields.protocol,
            remote_ip: fields.source,
            local_port: fields.destination_port,
            remote_port: fields.source_port,
        }
    }
}

fn ipv4_fields(packet: &[u8]) -> Option<Ipv4Fields> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    if header < 20 || packet.len() < header + 4 {
        return None;
    }
    let protocol = packet[9];
    let (source_port, destination_port) = if matches!(protocol, 6 | 17) {
        (
            u16::from_be_bytes([packet[header], packet[header + 1]]),
            u16::from_be_bytes([packet[header + 2], packet[header + 3]]),
        )
    } else if protocol == 1 && packet.len() >= header + 8 {
        let id = u16::from_be_bytes([packet[header + 4], packet[header + 5]]);
        (id, id)
    } else {
        (0, 0)
    };
    Some(Ipv4Fields {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol,
        source_port,
        destination_port,
    })
}

fn destination_selectors(plan: &InterceptionPlan) -> Result<Vec<TrafficSelector>, String> {
    let mut selectors = Vec::new();
    for network in &plan.ip_networks {
        let (address, prefix) = network.split_once('/').unwrap();
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("invalid IP target: {network}"))?;
        let IpAddr::V4(address) = address else {
            continue;
        };
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| format!("invalid CIDR target: {network}"))?;
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let first = Ipv4Addr::from(u32::from(address) & mask);
        let last = Ipv4Addr::from(u32::from(first) | !mask);
        selectors.push(TrafficSelector::Destination {
            first: u32::from(first),
            last: u32::from(last),
        });
    }
    Ok(selectors)
}

fn is_tcp_syn(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    packet
        .get(header + 13)
        .is_some_and(|flags| flags & 0x02 != 0)
}

fn resolve_hostnames(plan: &InterceptionPlan) -> HashSet<Ipv4Addr> {
    let mut addresses = HashSet::new();
    for hostname in &plan.hostnames {
        let host = hostname.strip_prefix("*.").unwrap_or(hostname);
        if let Ok(resolved) = (host, 0).to_socket_addrs() {
            addresses.extend(resolved.filter_map(|address| match address.ip() {
                IpAddr::V4(ip) => Some(ip),
                _ => None,
            }));
        }
    }
    addresses
}

fn bypass_clause(addresses: &[Ipv4Addr]) -> String {
    let parts = addresses
        .iter()
        .map(|ip| format!("ip.DstAddr != {ip}"))
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "true".into()
    } else {
        parts.join(" and ")
    }
}

fn dll_path() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let installed = executable
        .parent()
        .ok_or("engine executable has no parent directory")?
        .join("WinDivert.dll");
    if installed.is_file() {
        return Ok(installed);
    }
    let project = std::env::current_dir()
        .unwrap_or_default()
        .join("vendor")
        .join("windivert")
        .join("WinDivert.dll");
    project
        .is_file()
        .then_some(project)
        .ok_or_else(|| "WinDivert.dll was not found".into())
}

fn path_matches(path: &str, applications: &[String], folders: &[String]) -> bool {
    applications.iter().any(|target| target == path)
        || folders.iter().any(|folder| {
            path == folder
                || path
                    .strip_prefix(folder)
                    .is_some_and(|suffix| suffix.starts_with('\\'))
        })
}

fn process_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_owned()
}

fn record_handled_connection(
    registry: &Registry,
    key: ReturnKey,
    fields: Ipv4Fields,
    application: Option<&str>,
    process_id: Option<u32>,
) {
    let protocol = match fields.protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => "IP",
    };
    let application = application.unwrap_or("Matched destination");
    let first_seen = {
        let mut logged = registry.logged_destinations.lock().unwrap();
        logged.len() < 64
            && logged.insert((fields.protocol, fields.destination, fields.destination_port))
    };
    if first_seen {
        gamepath_engine::log_info!(
            "split capture selected {application}: {protocol} {}:{}",
            fields.destination,
            fields.destination_port
        );
    }
    let mut connections = registry.handled_connections.lock().unwrap();
    if connections.len() >= 64 && !connections.contains_key(&key) {
        let oldest = connections
            .iter()
            .min_by_key(|(_, connection)| connection.started_at)
            .map(|(key, _)| *key);
        // `None` only when the map is empty, which the length check rules out.
        if let Some(oldest) = oldest {
            connections.remove(&oldest);
        }
    }
    connections.insert(
        key,
        HandledConnection {
            application: application.to_owned(),
            destination_ip: fields.destination,
            destination_port: fields.destination_port,
            protocol: protocol.into(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            process_id,
        },
    );
}

fn process_path(process_id: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
        if handle == 0 {
            return None;
        }
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        Some(
            OsString::from_wide(&buffer[..length as usize])
                .to_string_lossy()
                .replace('/', "\\")
                .to_lowercase(),
        )
    }
}

fn dns_addresses(packet: &[u8], hostnames: &[String]) -> Vec<Ipv4Addr> {
    let Some(fields) = ipv4_fields(packet) else {
        return Vec::new();
    };
    if fields.protocol != 17 || fields.source_port != 53 {
        return Vec::new();
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let Some(dns) = packet.get(header + 8..) else {
        return Vec::new();
    };
    if dns.len() < 12 || dns[2] & 0x80 == 0 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([dns[4], dns[5]]) as usize;
    let answers = u16::from_be_bytes([dns[6], dns[7]]) as usize;
    let mut offset = 12;
    let mut matched = false;
    for _ in 0..questions {
        let Some((name, next)) = dns_name(dns, offset) else {
            return Vec::new();
        };
        matched |= hostnames
            .iter()
            .any(|target| hostname_matches(&name, target));
        offset = next + 4;
        if offset > dns.len() {
            return Vec::new();
        }
    }
    if !matched {
        return Vec::new();
    }
    let mut result = Vec::new();
    for _ in 0..answers {
        let Some((_, next)) = dns_name(dns, offset) else {
            break;
        };
        offset = next;
        if offset + 10 > dns.len() {
            break;
        }
        let kind = u16::from_be_bytes([dns[offset], dns[offset + 1]]);
        let length = u16::from_be_bytes([dns[offset + 8], dns[offset + 9]]) as usize;
        offset += 10;
        if offset + length > dns.len() {
            break;
        }
        if kind == 1 && length == 4 {
            result.push(Ipv4Addr::new(
                dns[offset],
                dns[offset + 1],
                dns[offset + 2],
                dns[offset + 3],
            ));
        }
        offset += length;
    }
    result
}

fn dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut next = None;
    let mut jumps = 0;
    loop {
        let length = *packet.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(offset + 1)?;
            next.get_or_insert(offset + 2);
            offset = (usize::from(length & 0x3f) << 8) | usize::from(low);
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        offset += 1;
        if length == 0 {
            break;
        }
        let end = offset + usize::from(length);
        labels.push(std::str::from_utf8(packet.get(offset..end)?).ok()?);
        offset = end;
    }
    Some((labels.join(".").to_lowercase(), next.unwrap_or(offset)))
}

fn hostname_matches(name: &str, target: &str) -> bool {
    target.strip_prefix("*.").map_or(name == target, |suffix| {
        name == suffix || name.ends_with(&format!(".{suffix}"))
    })
}

#[cfg(test)]
mod tests {

    /// An ICMP error carries no ports, so it keys as port 0 in both directions
    /// and can never match a TCP or UDP flow. Whatever else is behind the
    /// unmatched count, this part of it is structural.
    #[test]
    fn an_icmp_return_cannot_key_to_a_tcp_or_udp_flow() {
        let game = Ipv4Fields {
            source: Ipv4Addr::new(169, 150, 202, 130),
            destination: Ipv4Addr::new(10, 203, 0, 5),
            protocol: 17,
            source_port: 17000,
            destination_port: 51000,
        };
        let icmp = Ipv4Fields {
            protocol: 1,
            source_port: 0,
            destination_port: 0,
            ..game
        };
        assert_ne!(ReturnKey::inbound(game), ReturnKey::inbound(icmp));
    }
    use super::*;

    fn fields(
        destination: Ipv4Addr,
        protocol: u8,
        source_port: u16,
        destination_port: u16,
    ) -> Ipv4Fields {
        Ipv4Fields {
            source: Ipv4Addr::new(192, 168, 1, 20),
            destination,
            protocol,
            source_port,
            destination_port,
        }
    }

    fn table_of(entries: &[(TrafficSelector, Option<String>)]) -> SelectorTable {
        SelectorTable::build(&entries.iter().cloned().collect())
    }

    fn plan_for(rules: &[(&str, &str)]) -> InterceptionPlan {
        let rules = rules
            .iter()
            .map(|(kind, value)| RuleSpec {
                kind: (*kind).into(),
                value: (*value).into(),
            })
            .collect::<Vec<_>>();
        compile("split", &rules).unwrap()
    }

    /// The byte reservation is what actually bounds bypass memory, and every
    /// capture thread contends on it at once. It must never exceed the budget
    /// and must never leak a reservation.
    #[test]
    fn concurrent_bypass_reservations_stay_inside_the_byte_budget() {
        use std::sync::Barrier;

        let queued = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let granted = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let packet = 60_000_usize;
        let mut threads = Vec::new();
        for _ in 0..8 {
            let (queued, peak, granted, barrier) = (
                Arc::clone(&queued),
                Arc::clone(&peak),
                Arc::clone(&granted),
                Arc::clone(&barrier),
            );
            threads.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..500 {
                    let reserved =
                        queued.fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                            (held + packet <= BYPASS_QUEUE_BYTES).then(|| held + packet)
                        });
                    if let Ok(previous) = reserved {
                        granted.fetch_add(1, Ordering::Relaxed);
                        peak.fetch_max(previous + packet, Ordering::Relaxed);
                        // The injector releases it again.
                        queued.fetch_sub(packet, Ordering::AcqRel);
                    }
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(
            granted.load(Ordering::Relaxed) > 0,
            "nothing was ever queued"
        );
        assert!(
            peak.load(Ordering::Relaxed) <= BYPASS_QUEUE_BYTES,
            "the byte budget was exceeded: {} > {BYPASS_QUEUE_BYTES}",
            peak.load(Ordering::Relaxed)
        );
        // Every reservation was released, so nothing leaked.
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_packet_larger_than_the_whole_budget_is_never_queued() {
        let queued = AtomicUsize::new(0);
        let oversized = BYPASS_QUEUE_BYTES + 1;
        let reserved = queued.fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
            (held + oversized <= BYPASS_QUEUE_BYTES).then(|| held + oversized)
        });
        assert!(reserved.is_err(), "it would have to be reinjected inline");
        assert_eq!(queued.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_capture_thread_count_stays_within_its_bounds() {
        let threads = capture_thread_count();
        assert!(
            (1..=4).contains(&threads),
            "{threads} capture threads is outside the intended range"
        );
        assert!(
            threads
                <= std::thread::available_parallelism()
                    .map(|count| count.get())
                    .unwrap_or(1),
            "more capture threads than cores"
        );
    }

    /// A bypassed packet belongs to some other application. Losing one breaks
    /// that application's connection, so a full queue has to hand the packet
    /// back for the caller to reinject inline rather than swallow it.
    #[test]
    fn a_full_bypass_queue_hands_the_packet_back_instead_of_dropping_it() {
        let (sender, _receiver) = mpsc::sync_channel::<Bypass>(1);
        let address = Address::default();
        assert!(
            sender
                .try_send(Bypass {
                    packet: vec![1, 2, 3],
                    address
                })
                .is_ok()
        );
        let overflow = sender.try_send(Bypass {
            packet: vec![4, 5, 6],
            address,
        });
        let held = match &overflow {
            Err(mpsc::TrySendError::Full(held) | mpsc::TrySendError::Disconnected(held)) => held,
            Ok(()) => panic!("the queue should have been full"),
        };
        // The exact bytes come back, which is what makes the inline fallback in
        // `reinject` able to put this packet on the wire unchanged.
        assert_eq!(held.packet, vec![4, 5, 6]);
    }

    /// A disconnected queue must also hand the packet back, so a capture thread
    /// outliving the injector still puts traffic back on the network stack.
    #[test]
    fn a_disconnected_bypass_queue_also_hands_the_packet_back() {
        let (sender, receiver) = mpsc::sync_channel::<Bypass>(4);
        drop(receiver);
        let result = sender.try_send(Bypass {
            packet: vec![7, 8],
            address: Address::default(),
        });
        match &result {
            Err(mpsc::TrySendError::Disconnected(held)) => assert_eq!(held.packet, vec![7, 8]),
            other => panic!("expected the packet back, got {:?}", other.is_ok()),
        }
    }

    #[test]
    fn the_lookup_table_agrees_with_the_selector_definition() {
        let entries = [
            (
                TrafficSelector::Destination {
                    first: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                    last: u32::from(Ipv4Addr::new(203, 0, 113, 255)),
                },
                None,
            ),
            (
                TrafficSelector::Destination {
                    first: u32::from(Ipv4Addr::new(198, 51, 100, 7)),
                    last: u32::from(Ipv4Addr::new(198, 51, 100, 7)),
                },
                None,
            ),
            (
                TrafficSelector::Flow {
                    protocol: 6,
                    local_port: 51_000,
                    remote_port: Some(443),
                },
                Some("game.exe".to_owned()),
            ),
            (
                TrafficSelector::Flow {
                    protocol: 17,
                    local_port: 51_001,
                    remote_port: None,
                },
                Some("voice.exe".to_owned()),
            ),
        ];
        let table = table_of(&entries);
        let probes = [
            fields(Ipv4Addr::new(203, 0, 113, 9), 17, 40_000, 7777),
            fields(Ipv4Addr::new(203, 0, 114, 9), 17, 40_000, 7777),
            fields(Ipv4Addr::new(198, 51, 100, 7), 6, 40_000, 80),
            fields(Ipv4Addr::new(198, 51, 100, 8), 6, 40_000, 80),
            fields(Ipv4Addr::new(8, 8, 8, 8), 6, 51_000, 443),
            fields(Ipv4Addr::new(8, 8, 8, 8), 6, 51_000, 444),
            fields(Ipv4Addr::new(8, 8, 8, 8), 17, 51_001, 1234),
            fields(Ipv4Addr::new(8, 8, 8, 8), 17, 51_002, 1234),
            fields(Ipv4Addr::new(0, 0, 0, 0), 6, 1, 1),
            fields(Ipv4Addr::new(255, 255, 255, 255), 6, 1, 1),
        ];
        for probe in probes {
            let expected = entries.iter().any(|(selector, _)| selector.matches(probe));
            assert_eq!(
                table.lookup(probe).is_some(),
                expected,
                "disagreement on {probe:?}"
            );
        }
    }

    #[test]
    fn a_flow_match_carries_the_application_and_a_destination_match_does_not() {
        let table = table_of(&[
            (
                TrafficSelector::Flow {
                    protocol: 6,
                    local_port: 51_000,
                    remote_port: Some(443),
                },
                Some("game.exe".to_owned()),
            ),
            (
                TrafficSelector::Destination {
                    first: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                    last: u32::from(Ipv4Addr::new(203, 0, 113, 255)),
                },
                None,
            ),
        ]);
        assert_eq!(
            table.lookup(fields(Ipv4Addr::new(8, 8, 8, 8), 6, 51_000, 443)),
            Some((Some("game.exe"), None))
        );
        assert_eq!(
            table.lookup(fields(Ipv4Addr::new(203, 0, 113, 5), 17, 1, 1)),
            Some((None, None))
        );
    }

    #[test]
    fn an_owned_flow_carries_the_process_id_into_the_read_table() {
        let selector = TrafficSelector::Flow {
            protocol: 17,
            local_port: 51_001,
            remote_port: None,
        };
        let mut state = SelectorState::default();
        state
            .selectors
            .insert(selector, Some("game.exe".to_owned()));
        state.flow_owners.insert(
            selector,
            vec![FlowOwner {
                endpoint_id: Some(99),
                process_id: 1234,
                path: r"C:\Games\game.exe".to_owned(),
                stale_observations: 0,
            }],
        );
        let table = SelectorTable::build_state(&state);
        assert_eq!(
            table.lookup(fields(Ipv4Addr::new(8, 8, 8, 8), 17, 51_001, 9999)),
            Some((Some("game.exe"), Some(1234)))
        );
    }

    #[test]
    fn overlapping_destination_rules_merge_into_one_range() {
        let table = table_of(&[
            (
                TrafficSelector::Destination {
                    first: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                    last: u32::from(Ipv4Addr::new(203, 0, 113, 255)),
                },
                None,
            ),
            (
                TrafficSelector::Destination {
                    first: u32::from(Ipv4Addr::new(203, 0, 113, 40)),
                    last: u32::from(Ipv4Addr::new(203, 0, 113, 40)),
                },
                None,
            ),
        ]);
        assert_eq!(table.destinations.len(), 1);
        assert!(
            table
                .lookup(fields(Ipv4Addr::new(203, 0, 113, 40), 6, 1, 1))
                .is_some()
        );
        assert!(
            table
                .lookup(fields(Ipv4Addr::new(203, 0, 114, 0), 6, 1, 1))
                .is_none()
        );
    }

    #[test]
    fn destination_only_rules_are_matched_in_the_kernel() {
        let plan = plan_for(&[("ip", "203.0.113.0/24"), ("ip", "198.51.100.7/32")]);
        let table = SelectorTable::build(
            &destination_selectors(&plan)
                .unwrap()
                .into_iter()
                .map(|selector| (selector, None))
                .collect(),
        );
        let scope = capture_scope(&plan, &table.destinations);
        assert!(!scope.broad);
        assert!(scope.clause.contains("ip.DstAddr >= 203.0.113.0"));
        assert!(scope.clause.contains("ip.DstAddr <= 203.0.113.255"));
        assert!(scope.clause.contains("ip.DstAddr == 198.51.100.7"));
        // A narrow filter still has to hand up name lookups, or the classifier
        // behind it never gets the chance to select them.
        assert!(
            scope.clause.contains("udp.DstPort == 53"),
            "a narrow filter would never see DNS: {}",
            scope.clause
        );
    }

    #[test]
    fn application_rules_still_need_the_broad_filter() {
        let plan = plan_for(&[
            ("ip", "203.0.113.0/24"),
            ("application", "C:\\Games\\game.exe"),
        ]);
        let scope = capture_scope(&plan, &[(0, u32::MAX)]);
        assert!(scope.broad);
        assert_eq!(scope.clause, "true");
    }

    #[test]
    fn too_many_ranges_fall_back_to_the_broad_filter() {
        let plan = plan_for(&[("ip", "203.0.113.0/24")]);
        let ranges = (0..=MAX_FILTER_RANGES as u32)
            .map(|index| (index * 4, index * 4 + 1))
            .collect::<Vec<_>>();
        assert!(capture_scope(&plan, &ranges).broad);
    }

    #[test]
    fn destination_range_is_compiled() {
        let plan = compile(
            "split",
            &[RuleSpec {
                kind: "ip".into(),
                value: "203.0.113.0/24".into(),
            }],
        )
        .unwrap();
        assert_eq!(
            destination_selectors(&plan).unwrap(),
            [TrafficSelector::Destination {
                first: u32::from(Ipv4Addr::new(203, 0, 113, 0)),
                last: u32::from(Ipv4Addr::new(203, 0, 113, 255)),
            }]
        );
    }

    #[test]
    fn wildcard_hostname_matches_subdomains() {
        assert!(hostname_matches("eu.game.example", "*.game.example"));
        assert!(hostname_matches("game.example", "*.game.example"));
        assert!(!hostname_matches("other.example", "*.game.example"));
    }

    /// A TCP SYN advertising `mss`.
    fn syn_with_mss(mss: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 44];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[20 + 12] = 0x60;
        packet[20 + 13] = 0x02;
        packet[40..42].copy_from_slice(&[2, 4]);
        packet[42..44].copy_from_slice(&mss.to_be_bytes());
        packet
    }

    #[test]
    fn nested_tunnel_clamps_tcp_mss() {
        let mut packet = syn_with_mss(1460);
        clamp_tcp_mss(&mut packet, 1000);
        assert_eq!(&packet[42..44], &1000_u16.to_be_bytes());
    }

    #[test]
    fn the_clamp_only_ever_lowers_the_advertised_mss() {
        // The derived clamp is far above the old fixed 1000, so it matters that
        // a peer offering less is left alone rather than talked upwards.
        let mut packet = syn_with_mss(536);
        clamp_tcp_mss(&mut packet, 1316);
        assert_eq!(&packet[42..44], &536_u16.to_be_bytes());
    }

    #[test]
    fn the_derived_mss_and_its_headers_fit_inside_the_derived_mtu() {
        for kinds in [
            vec!["wireguard"],
            vec!["socks5"],
            vec!["wireguard", "socks5"],
        ] {
            for mode in [
                gamepath_engine::relay_path::SessionMode::Relay,
                gamepath_engine::relay_path::SessionMode::Direct,
            ] {
                let mtu = EffectiveMtu::for_session(mode, kinds.clone(), 1500);
                let segment = u32::from(mtu.tcp_mss()) + 20 + 20;
                assert!(
                    segment <= u32::from(mtu.mtu),
                    "{kinds:?} {mode:?}: a full segment overruns the tunnel MTU"
                );
                assert!(
                    segment + u32::from(mtu.overhead) <= 1500,
                    "{kinds:?} {mode:?}: a full segment overruns the physical link"
                );
            }
        }
    }

    /// A query to a public resolver, which is the case split mode carries.
    fn dns_fields(protocol: u8, destination_port: u16) -> Ipv4Fields {
        Ipv4Fields {
            source: Ipv4Addr::new(192, 168, 1, 10),
            destination: Ipv4Addr::new(8, 8, 8, 8),
            protocol,
            source_port: 51_000,
            destination_port,
        }
    }

    /// Both transports, because a truncated answer is retried over TCP and
    /// selecting only UDP would leak the largest replies.
    #[test]
    fn name_resolution_is_selected_on_either_transport() {
        assert!(is_name_resolution(dns_fields(17, 53)), "UDP/53");
        assert!(is_name_resolution(dns_fields(6, 53)), "TCP/53");
    }

    /// It must not swallow ordinary traffic. A game talking to port 53 of
    /// something that is not a resolver is not what this is for, but the cost
    /// of that is one tunnelled flow; the cost of matching on source port
    /// would be capturing every reply a local resolver sends.
    #[test]
    fn ordinary_traffic_is_not_mistaken_for_name_resolution() {
        assert!(!is_name_resolution(dns_fields(17, 443)));
        assert!(!is_name_resolution(dns_fields(6, 80)));
        // ICMP has no ports; the field is meaningless rather than zero.
        assert!(!is_name_resolution(dns_fields(1, 53)));
    }

    /// The live regression. A home machine resolves through its own router, and
    /// that address means the relay's own LAN once the packet gets there, so
    /// tunnelling the query destroys it instead of redirecting it.
    #[test]
    fn a_lan_resolver_is_left_on_the_local_network() {
        for resolver in [
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            // Carrier-grade NAT: the ISP's interior, no more reachable from
            // the relay than a home LAN is.
            Ipv4Addr::new(100, 100, 0, 1),
        ] {
            let mut fields = dns_fields(17, 53);
            fields.destination = resolver;
            assert!(
                !is_name_resolution(fields),
                "{resolver} would have been sent to a relay that cannot reach it"
            );
        }
    }

    /// And a public resolver is still taken, which is the case this improves.
    #[test]
    fn a_public_resolver_is_still_carried() {
        for resolver in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(9, 9, 9, 9),
        ] {
            let mut fields = dns_fields(17, 53);
            fields.destination = resolver;
            assert!(is_name_resolution(fields), "{resolver} should be carried");
        }
    }

    /// The kernel clause and the user-space predicate have to agree, or a
    /// narrow filter would drop exactly what the classifier wants to select.
    #[test]
    fn the_kernel_clause_and_the_classifier_agree() {
        assert!(DNS_CLAUSE.contains("udp.DstPort == 53"));
        assert!(DNS_CLAUSE.contains("tcp.DstPort == 53"));
    }
}
