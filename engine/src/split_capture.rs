#![cfg(windows)]

use crate::{DataReceiver, WireGuardSessionManager};
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::policy::{InterceptionPlan, RuleSpec, compile};
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsString, c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HandledConnection {
    application: String,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    protocol: String,
    started_at: u64,
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
    flows: HashMap<(u8, u16, Option<u16>), Option<String>>,
    len: usize,
}

impl SelectorTable {
    fn build(selectors: &HashMap<TrafficSelector, Option<String>>) -> Self {
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
                    flows.insert((protocol, local_port, remote_port), application.clone());
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
    fn lookup(&self, fields: Ipv4Fields) -> Option<Option<String>> {
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
            return Some(application.clone());
        }
        let destination = u32::from(fields.destination);
        let index = self
            .destinations
            .partition_point(|(first, _)| *first <= destination);
        let (_, last) = self.destinations.get(index.checked_sub(1)?)?;
        (destination <= *last).then_some(None)
    }
}

struct Registry {
    dll: PathBuf,
    bypass: String,
    handles: Mutex<Vec<Arc<Handle>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    selectors: Mutex<HashMap<TrafficSelector, Option<String>>>,
    /// Rebuilt from `selectors` on every change. Behind an `RwLock` so
    /// classifying a packet never contends with another classifier.
    table: RwLock<Arc<SelectorTable>>,
    /// Bumped with every `table` swap, so the capture loop can hold its own
    /// copy and take the lock only when the set has actually changed.
    table_version: AtomicU64,
    handled_connections: Mutex<HashMap<ReturnKey, HandledConnection>>,
    capture_loop_buckets: [AtomicU64; 8],
    capture_receive_errors: AtomicU64,
    pending_syn_depth: AtomicU64,
    pending_syn_peak: AtomicU64,
    pending_syn_overflow: AtomicU64,
    applications: Vec<String>,
    folders: Vec<String>,
    matched_sockets: AtomicU64,
    /// MSS advertised on captured TCP handshakes, derived from what the chosen
    /// transports add to a packet rather than fixed at a guess.
    tcp_mss: u16,
    captured_packets: AtomicU64,
    captured_bytes: AtomicU64,
    relayed_packets: AtomicU64,
    bypassed_packets: AtomicU64,
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
        clause: format!("({clause})"),
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
            selectors: Mutex::new(HashMap::new()),
            table: RwLock::new(Arc::new(SelectorTable::default())),
            table_version: AtomicU64::new(0),
            handled_connections: Mutex::new(HashMap::new()),
            capture_loop_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            capture_receive_errors: AtomicU64::new(0),
            pending_syn_depth: AtomicU64::new(0),
            pending_syn_peak: AtomicU64::new(0),
            pending_syn_overflow: AtomicU64::new(0),
            applications: plan.application_paths.clone(),
            folders: plan.folder_prefixes.clone(),
            matched_sockets: AtomicU64::new(0),
            captured_packets: AtomicU64::new(0),
            captured_bytes: AtomicU64::new(0),
            relayed_packets: AtomicU64::new(0),
            bypassed_packets: AtomicU64::new(0),
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
        let capture_registry = Arc::clone(&registry);
        let capture_stop = Arc::clone(&stop);
        let capture_sessions = Arc::clone(&sessions);
        let capture_returns = Arc::clone(&return_paths);
        let worker = thread::Builder::new()
            .name("gamepath-windivert-selected".into())
            .spawn(move || {
                run_selected_capture(
                    network_handle,
                    capture_stop,
                    capture_sessions,
                    capture_returns,
                    virtual_ipv4,
                    capture_registry,
                    pending_tx,
                )
            })
            .map_err(|error| format!("could not start selected packet capture: {error}"))?;
        registry.workers.lock().unwrap().push(worker);

        let inject_stop = Arc::clone(&stop);
        let inject_returns = Arc::clone(&return_paths);
        let worker = thread::Builder::new()
            .name("gamepath-windivert-inject".into())
            .spawn(move || {
                run_reply_injector(
                    send_handle,
                    inject_stop,
                    data_receiver,
                    inject_returns,
                    virtual_ipv4,
                )
            })
            .map_err(|error| format!("could not start split reply injector: {error}"))?;
        registry.workers.lock().unwrap().push(worker);

        Ok(Self {
            stop,
            registry,
            target_count: rules.len(),
            scope,
        })
    }

    pub fn target_count(&self) -> usize {
        self.target_count
    }

    pub fn diagnostics(&self) -> serde_json::Value {
        let mut handled_connections = self
            .registry
            .handled_connections
            .lock()
            .unwrap()
            .values()
            .cloned()
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
            "captureScopeReason": self.scope.reason,
            "captureFilter": self.scope.clause,
            "tcpMss": self.registry.tcp_mss,
            "capturedPackets": self.registry.captured_packets.load(Ordering::Relaxed),
            "capturedBytes": self.registry.captured_bytes.load(Ordering::Relaxed),
            "relayedPackets": self.registry.relayed_packets.load(Ordering::Relaxed),
            "bypassedPackets": self.registry.bypassed_packets.load(Ordering::Relaxed),
            "handledConnections": handled_connections,
            "captureLoopHistogram": capture_loop_histogram,
            "captureReceiveErrors": self.registry.capture_receive_errors.load(Ordering::Relaxed),
            "pendingSynDepth": self.registry.pending_syn_depth.load(Ordering::Relaxed),
            "pendingSynPeak": self.registry.pending_syn_peak.load(Ordering::Relaxed),
            "pendingSynOverflow": self.registry.pending_syn_overflow.load(Ordering::Relaxed),
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
    let mut selectors = registry.selectors.lock().unwrap();
    if selectors.insert(selector, None).is_none() {
        publish_selectors(registry, &selectors);
    }
}

fn add_process_selector(registry: &Registry, selector: TrafficSelector, application: String) {
    let mut selectors = registry.selectors.lock().unwrap();
    let previous = selectors.insert(selector, Some(application.clone()));
    if previous != Some(Some(application)) {
        publish_selectors(registry, &selectors);
    }
}

/// Swaps in a fresh classification table. Called with the selector lock held so
/// the table is never built from a half-applied change.
fn publish_selectors(registry: &Registry, selectors: &HashMap<TrafficSelector, Option<String>>) {
    *registry.table.write().unwrap() = Arc::new(SelectorTable::build(selectors));
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
        let bucket = [10_u64, 25, 50, 100, 250, 500, 1000]
            .iter()
            .position(|upper| elapsed <= *upper)
            .unwrap_or(7);
        self.registry.capture_loop_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}

fn run_selected_capture(
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
    registry: Arc<Registry>,
    pending_syns: mpsc::SyncSender<PendingSyn>,
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
            let _ = handle.send(packet, &address);
            continue;
        };
        let (mut selected, mut application) = match table.lookup(fields) {
            Some(application) => (true, application),
            None => (false, None),
        };
        // CONNECT and the first TCP SYN can run on different scheduler threads.
        // Briefly hold only an unmatched SYN so the socket observer can classify it.
        if !selected && is_tcp_syn(packet) {
            if let Some(path) =
                tcp_socket_process(fields, &registry.applications, &registry.folders)
            {
                application = Some(process_name(&path));
                add_process_selector(
                    &registry,
                    TrafficSelector::Flow {
                        protocol: 6,
                        local_port: fields.source_port,
                        remote_port: Some(fields.destination_port),
                    },
                    application.clone().unwrap(),
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
        if !selected {
            let _ = handle.send(packet, &address);
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
            application,
            &mut tunnel_buffer,
        );
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
    application: Option<String>,
    tunnel_buffer: &mut Vec<u8>,
) {
    let connection_key = ReturnKey::outbound(fields);
    let is_new_connection = return_paths
        .lock()
        .unwrap()
        .insert(
            connection_key,
            ReturnPath {
                local_ip: fields.source,
                interface_index: address.network_data().interface_index,
                subinterface_index: address.network_data().subinterface_index,
            },
        )
        .is_none();
    if is_new_connection {
        record_handled_connection(registry, connection_key, fields, application);
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
        let application = selector_table(&registry).lookup(item.fields);
        if let Some(application) = application {
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
    let worker = thread::Builder::new()
        .name("gamepath-windivert-processes".into())
        .spawn(move || {
            // WinDivert reports only future socket events. Seed UDP filters for game
            // sockets that already existed when the user pressed Start session.
            // Existing TCP connections cannot move to a different public IP safely.
            for socket in existing_ipv4_udp_sockets() {
                if let Some(path) = process_path(socket.process_id)
                    .filter(|path| path_matches(path, &applications, &folders))
                {
                    worker_registry
                        .matched_sockets
                        .fetch_add(1, Ordering::Relaxed);
                    add_process_selector(&worker_registry, socket.selector(), process_name(&path));
                }
            }
            while !worker_stop.load(Ordering::Acquire) {
                let Ok((_, address)) = handle.recv(0) else {
                    break;
                };
                let event_kind = address.event();
                let event = address.socket_data();
                if event_kind == 7 {
                    {
                        let mut selectors = worker_registry.selectors.lock().unwrap();
                        let before = selectors.len();
                        selectors.retain(|selector, _| {
                            !matches!(
                                selector,
                                TrafficSelector::Flow { protocol, local_port, remote_port }
                                    if *protocol == event.protocol
                                        && *local_port == event.local_port
                                        && (remote_port.is_none()
                                            || *remote_port == Some(event.remote_port))
                            )
                        });
                        if selectors.len() != before {
                            publish_selectors(&worker_registry, &selectors);
                        }
                    }
                    return_paths.lock().unwrap().retain(|key, _| {
                        key.protocol != event.protocol
                            || key.local_port != event.local_port
                            || (event.remote_port != 0 && key.remote_port != event.remote_port)
                    });
                    worker_registry
                        .handled_connections
                        .lock()
                        .unwrap()
                        .retain(|key, _| {
                            key.protocol != event.protocol
                                || key.local_port != event.local_port
                                || (event.remote_port != 0 && key.remote_port != event.remote_port)
                        });
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
                    process_name(&path),
                );
            }
        })
        .map_err(|error| format!("could not start process tracker: {error}"))?;
    registry.workers.lock().unwrap().push(worker);
    Ok(())
}

#[derive(Clone, Copy)]
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
) -> Option<String> {
    let buffer = ip_table(|table, size| unsafe { GetExtendedTcpTable(table, size, 0, 2, 5, 0) })?;
    dword_rows(&buffer, 6).into_iter().find_map(|row| {
        if port_from_dword(row[2]) != fields.source_port
            || port_from_dword(row[4]) != fields.destination_port
            || Ipv4Addr::from(row[3].to_ne_bytes()) != fields.destination
        {
            return None;
        }
        process_path(row[5]).filter(|path| path_matches(path, applications, folders))
    })
}

fn existing_ipv4_udp_sockets() -> Vec<ExistingSocket> {
    let mut sockets = Vec::new();
    // MIB_UDPROW_OWNER_PID is three DWORDs; UDP has no fixed remote endpoint.
    if let Some(buffer) =
        ip_table(|table, size| unsafe { GetExtendedUdpTable(table, size, 0, 2, 1, 0) })
    {
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
    }
    sockets
}

fn ip_table(call: impl Fn(*mut c_void, *mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0_u32;
    let _ = call(std::ptr::null_mut(), &mut size);
    if size < 4 {
        return None;
    }
    let mut buffer = vec![0_u8; size as usize];
    (call(buffer.as_mut_ptr().cast(), &mut size) == 0).then_some(buffer)
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
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|part| u32::from_ne_bytes(*part))
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
) {
    while !stop.load(Ordering::Acquire) {
        let received = data_receiver.receive(Duration::from_millis(20));
        let mut packet = match received {
            Ok(Some(packet)) => packet,
            Ok(None) => continue,
            Err(_) => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
        };
        let Some(fields) = ipv4_fields(&packet) else {
            continue;
        };
        if fields.destination != virtual_ipv4 {
            continue;
        }
        let Some(path) = return_paths
            .lock()
            .unwrap()
            .get(&ReturnKey::inbound(fields))
            .copied()
        else {
            continue;
        };
        packet[16..20].copy_from_slice(&path.local_ip.octets());
        clamp_tcp_mss(&mut packet, 1000);
        let mut address = Address::inbound(path.interface_index, path.subinterface_index);
        if handle.checksums(&mut packet, &mut address).is_ok() {
            let _ = handle.send(&packet, &address);
        }
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
    application: Option<String>,
) {
    let mut connections = registry.handled_connections.lock().unwrap();
    if connections.len() >= 64
        && !connections.contains_key(&key)
        && let Some(oldest) = connections
            .iter()
            .min_by_key(|(_, connection)| connection.started_at)
            .map(|(key, _)| *key)
    {
        connections.remove(&oldest);
    }
    connections.entry(key).or_insert_with(|| HandledConnection {
        application: application.unwrap_or_else(|| "Matched destination".into()),
        destination_ip: fields.destination,
        destination_port: fields.destination_port,
        protocol: match fields.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "IP",
        }
        .into(),
        started_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });
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
    use super::*;

    fn fields(destination: Ipv4Addr, protocol: u8, source_port: u16, destination_port: u16) -> Ipv4Fields {
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
            let expected = entries
                .iter()
                .any(|(selector, _)| selector.matches(probe));
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
            Some(Some("game.exe".to_owned()))
        );
        assert_eq!(
            table.lookup(fields(Ipv4Addr::new(203, 0, 113, 5), 17, 1, 1)),
            Some(None)
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
        assert!(table.lookup(fields(Ipv4Addr::new(203, 0, 113, 40), 6, 1, 1)).is_some());
        assert!(table.lookup(fields(Ipv4Addr::new(203, 0, 114, 0), 6, 1, 1)).is_none());
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
}
