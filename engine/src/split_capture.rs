#![cfg(windows)]

use crate::WireGuardSessionManager;
use gamepath_engine::policy::{InterceptionPlan, RuleSpec, compile};
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsString, c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
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

struct Registry {
    dll: PathBuf,
    bypass: String,
    handles: Mutex<Vec<Arc<Handle>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    filters: Mutex<HashSet<String>>,
}

pub struct SplitPacketCapture {
    stop: Arc<AtomicBool>,
    registry: Arc<Registry>,
    target_count: usize,
}

impl SplitPacketCapture {
    pub fn start(
        rules: &[RuleSpec],
        virtual_ipv4: Ipv4Addr,
        bypass_ips: &[Ipv4Addr],
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Self, String> {
        let plan = compile("split", rules)?;
        let registry = Arc::new(Registry {
            dll: dll_path()?,
            bypass: bypass_clause(bypass_ips),
            handles: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
            filters: Mutex::new(HashSet::new()),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let return_paths = Arc::new(Mutex::new(HashMap::new()));
        let send_handle = Arc::new(Handle::open(&registry.dll, "false", 0, 0x0008)?);

        let mut initial = destination_terms(&plan)?;
        initial.extend(
            resolve_hostnames(&plan)
                .into_iter()
                .map(|ip| format!("ip.DstAddr == {ip}")),
        );
        if !initial.is_empty() {
            spawn_capture(
                initial.join(" or "),
                Arc::clone(&registry),
                Arc::clone(&stop),
                Arc::clone(&sessions),
                Arc::clone(&return_paths),
                virtual_ipv4,
            )?;
        }

        if !plan.application_paths.is_empty() || !plan.folder_prefixes.is_empty() {
            spawn_process_tracker(
                &plan,
                Arc::clone(&registry),
                Arc::clone(&stop),
                Arc::clone(&sessions),
                Arc::clone(&return_paths),
                virtual_ipv4,
            )?;
        }
        if !plan.hostnames.is_empty() {
            spawn_dns_tracker(
                plan.hostnames.clone(),
                Arc::clone(&registry),
                Arc::clone(&stop),
                Arc::clone(&sessions),
                Arc::clone(&return_paths),
                virtual_ipv4,
            )?;
        }

        let inject_stop = Arc::clone(&stop);
        let inject_returns = Arc::clone(&return_paths);
        let worker = thread::Builder::new()
            .name("gamepath-windivert-inject".into())
            .spawn(move || {
                run_reply_injector(
                    send_handle,
                    inject_stop,
                    sessions,
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
        })
    }

    pub fn target_count(&self) -> usize {
        self.target_count
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

fn spawn_capture(
    target_filter: String,
    registry: Arc<Registry>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
) -> Result<(), String> {
    let filter = format!(
        "outbound and ip and ({target_filter}) and {}",
        registry.bypass
    );
    if !registry.filters.lock().unwrap().insert(filter.clone()) {
        return Ok(());
    }
    let handle = Arc::new(Handle::open(&registry.dll, &filter, 0, 0)?);
    handle.set_param(0, 8192)?;
    handle.set_param(2, 32 * 1024 * 1024)?;
    registry.handles.lock().unwrap().push(Arc::clone(&handle));
    let worker = thread::Builder::new()
        .name("gamepath-windivert-selected".into())
        .spawn(move || run_selected_capture(handle, stop, sessions, return_paths, virtual_ipv4))
        .map_err(|error| format!("could not start selected packet capture: {error}"))?;
    registry.workers.lock().unwrap().push(worker);
    Ok(())
}

fn run_selected_capture(
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
) {
    while !stop.load(Ordering::Acquire) {
        let Ok((packet, address)) = handle.recv(65_535) else {
            break;
        };
        let Some(fields) = ipv4_fields(&packet) else {
            let _ = handle.send(&packet, &address);
            continue;
        };
        return_paths.lock().unwrap().insert(
            ReturnKey::outbound(fields),
            ReturnPath {
                local_ip: fields.source,
                interface_index: address.network_data().interface_index,
                subinterface_index: address.network_data().subinterface_index,
            },
        );
        let mut tunneled = packet.clone();
        tunneled[12..16].copy_from_slice(&virtual_ipv4.octets());
        let mut checksum_address = address;
        if handle
            .checksums(&mut tunneled, &mut checksum_address)
            .is_err()
            || sessions
                .lock()
                .unwrap()
                .enqueue_data_packet(&tunneled)
                .is_err()
        {
            // Fail open for the selected connection when the relay is unavailable.
            let _ = handle.send(&packet, &address);
        }
    }
}

fn spawn_process_tracker(
    plan: &InterceptionPlan,
    registry: Arc<Registry>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
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
            while !worker_stop.load(Ordering::Acquire) {
                let Ok((_, address)) = handle.recv(0) else {
                    break;
                };
                if !matches!(address.event(), 3 | 4) {
                    continue;
                }
                let event = address.socket_data();
                let port = u16::from_be(event.local_port);
                if port == 0
                    || !process_path(event.process_id)
                        .is_some_and(|path| path_matches(&path, &applications, &folders))
                {
                    continue;
                }
                let protocol = match event.protocol {
                    6 => "tcp",
                    17 => "udp",
                    _ => continue,
                };
                let remote_port = u16::from_be(event.remote_port);
                let remote_term = if remote_port == 0 {
                    String::new()
                } else {
                    format!(" and {protocol}.DstPort == {remote_port}")
                };
                let _ = spawn_capture(
                    format!("{protocol}.SrcPort == {port}{remote_term}"),
                    Arc::clone(&worker_registry),
                    Arc::clone(&worker_stop),
                    Arc::clone(&sessions),
                    Arc::clone(&return_paths),
                    virtual_ipv4,
                );
            }
        })
        .map_err(|error| format!("could not start process tracker: {error}"))?;
    registry.workers.lock().unwrap().push(worker);
    Ok(())
}

fn spawn_dns_tracker(
    hostnames: Vec<String>,
    registry: Arc<Registry>,
    stop: Arc<AtomicBool>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
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
                    let _ = spawn_capture(
                        format!("ip.DstAddr == {address}"),
                        Arc::clone(&worker_registry),
                        Arc::clone(&worker_stop),
                        Arc::clone(&sessions),
                        Arc::clone(&return_paths),
                        virtual_ipv4,
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
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    return_paths: Arc<Mutex<HashMap<ReturnKey, ReturnPath>>>,
    virtual_ipv4: Ipv4Addr,
) {
    while !stop.load(Ordering::Acquire) {
        let Ok(Some(mut packet)) = sessions
            .lock()
            .unwrap()
            .receive_data_packet(Duration::from_millis(20))
        else {
            continue;
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
        let mut address = Address::inbound(path.interface_index, path.subinterface_index);
        if handle.checksums(&mut packet, &mut address).is_ok() {
            let _ = handle.send(&packet, &address);
        }
    }
}

#[derive(Clone, Copy)]
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

fn destination_terms(plan: &InterceptionPlan) -> Result<Vec<String>, String> {
    let mut terms = Vec::new();
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
        terms.push(if first == last {
            format!("ip.DstAddr == {first}")
        } else {
            format!("(ip.DstAddr >= {first} and ip.DstAddr <= {last})")
        });
    }
    Ok(terms)
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
            destination_terms(&plan).unwrap(),
            ["(ip.DstAddr >= 203.0.113.0 and ip.DstAddr <= 203.0.113.255)"]
        );
    }

    #[test]
    fn wildcard_hostname_matches_subdomains() {
        assert!(hostname_matches("eu.game.example", "*.game.example"));
        assert!(hostname_matches("game.example", "*.game.example"));
        assert!(!hostname_matches("other.example", "*.game.example"));
    }
}
