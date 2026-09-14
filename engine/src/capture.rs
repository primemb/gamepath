//! Owns the packet capture that feeds a running session.
//!
//! All-traffic mode puts a Wintun adapter in front of the default route;
//! split mode hands the work to [`crate::split_capture`], which filters in the
//! kernel with WinDivert. Both are torn down and replaced by a policy change
//! without the multipath session underneath ever restarting.

use crate::ipc::PacketCaptureRequest;
use crate::netutil::ipv6_exposure;
use crate::session::{DataReceiver, WireGuardSessionManager};
use gamepath_engine::policy::compile as compile_policy;
use gamepath_engine::{log_info, log_warn};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Default)]
pub(crate) struct PacketCaptureManager {
    #[cfg(windows)]
    active: Option<WindowsPacketCapture>,
    #[cfg(windows)]
    active_split: Option<crate::split_capture::SplitPacketCapture>,
}

#[cfg(windows)]
struct WindowsPacketCapture {
    stop: Arc<AtomicBool>,
    session: Arc<wintun::Session>,
    workers: Vec<JoinHandle<()>>,
    routes: Vec<InstalledRoute>,
    adapter_index: u32,
    /// Set only when this capture configured the adapter's resolvers, so
    /// teardown clears exactly what it set and leaves an adapter it never
    /// touched alone.
    dns_adapter: Option<u128>,
}

/// A route this capture added, kept so teardown can remove exactly it. The
/// gateway is part of what identifies a row, so it is remembered rather than
/// reconstructed.
#[cfg(windows)]
struct InstalledRoute {
    destination: std::net::Ipv4Addr,
    prefix_length: u8,
    gateway: std::net::Ipv4Addr,
    interface_index: u32,
}

/// Points Windows at a resolver reachable through the tunnel, and says which.
///
/// Without this the tunnel carries everything *except* name resolution.
/// Windows picks its resolver per interface, the GamePath adapter had none, so
/// lookups fell back to the physical adapter's — typically the home router,
/// which sits on an on-link `/24` far more specific than the `0.0.0.0/1` this
/// installs. Every lookup therefore went straight to the ISP. That is a
/// privacy leak, but the reason it is worth fixing on the connect path is
/// blunter: a filtered or poisoned resolver hands back a dead or wrong address
/// while the tunnel is perfectly healthy, and steers a game to whichever
/// region the *local* resolver prefers rather than one near the exit.
///
/// The relay's own resolver is preferred because its address exists only
/// inside the tunnel and so cannot leak by any route; a public resolver still
/// follows it, because it is reached through the tunnel too and is what keeps
/// the machine resolving if the relay's own resolver stops.
#[cfg(windows)]
fn configure_tunnel_dns(
    adapter_guid: u128,
    sessions: &Mutex<WireGuardSessionManager>,
    tunnel_gateway: std::net::Ipv4Addr,
) -> Vec<std::net::Ipv4Addr> {
    let relay = sessions
        .lock()
        .unwrap()
        .tunnel_resolver_answers(tunnel_gateway)
        .then_some(tunnel_gateway);
    if relay.is_none() {
        log_info!(
            "{tunnel_gateway} did not answer a name lookup, so this session resolves through the \
             public fallback instead; install a resolver on the relay to keep lookups inside it"
        );
    }
    let servers = gamepath_engine::dns::resolver_order(relay);
    match gamepath_engine::netconfig::set_interface_dns(adapter_guid, &servers) {
        Ok(()) => {
            log_info!(
                "tunnel DNS: {}",
                servers
                    .iter()
                    .map(std::net::Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            servers
        }
        // Not fatal. A session that carries traffic is worth more than this,
        // and leaving the adapter without servers is exactly the behaviour
        // every previous release had.
        Err(error) => {
            log_warn!("name resolution will not go through the tunnel: {error}");
            Vec::new()
        }
    }
}

impl PacketCaptureManager {
    #[cfg(windows)]
    pub(crate) fn start(
        &mut self,
        payload: Value,
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        let input: PacketCaptureRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid packet capture request: {error}"))?;
        match input.traffic_mode.as_str() {
            // Validate before dropping a live capture. This makes a rejected
            // live rule edit leave the previous policy fully operational.
            "split" => {
                compile_policy("split", &input.rules)?;
            }
            "all" => {}
            _ => return Err("traffic mode must be all or split".into()),
        }
        self.stop();
        let (virtual_ipv4, bypass_ips, data_receiver, effective_mtu) = {
            let manager = sessions.lock().unwrap();
            (
                manager
                    .virtual_ipv4()
                    .ok_or("start the multipath session before packet capture")?,
                manager.bypass_ips(),
                manager
                    .data_receiver()
                    .ok_or("start the multipath session before packet capture")?,
                manager
                    .effective_mtu()
                    .ok_or("start the multipath session before packet capture")?,
            )
        };
        if input.traffic_mode == "split" {
            let split = crate::split_capture::SplitPacketCapture::start(
                &input.rules,
                virtual_ipv4,
                &bypass_ips,
                sessions,
                data_receiver,
                effective_mtu,
            )?;
            let target_count = split.target_count();
            self.active_split = Some(split);
            return Ok(json!({
                "state": "capturing",
                "backend": "windivert",
                "trafficMode": "split",
                "targetCount": target_count,
                "effectiveMtu": effective_mtu.mtu,
                "tcpMss": effective_mtu.tcp_mss(),
                // Selected targets are matched as IPv4. A game reaching the
                // same server over IPv6 is not captured at all, so the
                // exposure is worth reporting in split mode too.
                "ipv6": ipv6_exposure(),
            }));
        }
        let (default_gateway, default_interface) =
            gamepath_engine::netconfig::default_ipv4_route()?;
        let executable_dir = std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .ok_or("engine executable has no parent directory")?
            .to_path_buf();
        let installed_dll = executable_dir.join("wintun.dll");
        let project_dll = std::env::current_dir()
            .unwrap_or_default()
            .join("vendor")
            .join("wintun")
            .join("wintun.dll");
        let dll = if installed_dll.is_file() {
            installed_dll
        } else {
            project_dll
        };
        // SAFETY: only the repository's verified Wintun DLL or the installed
        // copy beside the privileged engine is loaded.
        let wintun = unsafe { wintun::load_from_path(&dll) }
            .map_err(|error| format!("could not load Wintun: {error}"))?;
        let adapter = wintun::Adapter::open(&wintun, "GamePath")
            .or_else(|_| {
                wintun::Adapter::create(
                    &wintun,
                    "GamePath",
                    "GamePath",
                    Some(0x7f0a_9828_52ef_4ddd_913d_c11f_f0d4_a58a_u128),
                )
            })
            .map_err(|error| format!("could not create GamePath adapter: {error}"))?;
        let adapter_index = adapter
            .get_adapter_index()
            .map_err(|error| format!("could not read GamePath adapter index: {error}"))?;
        configure_tunnel_interface(adapter_index, effective_mtu.mtu)?;
        adapter
            .set_network_addresses_tuple(
                virtual_ipv4.into(),
                std::net::Ipv4Addr::new(255, 255, 255, 0).into(),
                None,
            )
            .map_err(|error| format!("could not configure GamePath adapter: {error}"))?;
        // Sized from what the selected transports actually add to a packet, so
        // a full-size packet still fits the physical link once it is wrapped.
        adapter
            .set_mtu(usize::from(effective_mtu.mtu))
            .map_err(|error| format!("could not set GamePath MTU: {error}"))?;
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|error| format!("could not start Wintun packet ring: {error}"))?,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let uplink_sessions = Arc::clone(&sessions);
        let uplink_stop = Arc::clone(&stop);
        let uplink_session = Arc::clone(&session);
        let uplink = thread::Builder::new()
            .name("gamepath-wintun-uplink".into())
            .spawn(move || {
                run_wintun_uplink(uplink_session, uplink_sessions, virtual_ipv4, uplink_stop)
            })
            .map_err(|error| format!("could not start Wintun uplink: {error}"))?;
        let downlink_stop = Arc::clone(&stop);
        let downlink_session = Arc::clone(&session);
        let downlink = thread::Builder::new()
            .name("gamepath-wintun-downlink".into())
            .spawn(move || run_wintun_downlink(downlink_session, data_receiver, downlink_stop))
            .map_err(|error| format!("could not start Wintun downlink: {error}"))?;

        let mut capture = WindowsPacketCapture {
            stop,
            session,
            workers: vec![uplink, downlink],
            routes: Vec::new(),
            adapter_index,
            dns_adapter: None,
        };
        for address in bypass_ips {
            capture.routes.push(add_ipv4_route(
                address,
                32,
                default_gateway,
                default_interface,
                1,
            )?);
        }
        // The next hop has to sit inside the adapter's own /24 for Windows to
        // accept the route. A relay hands out 10.203.0.x, so this is the same
        // 10.203.0.1 as before; a direct session's address comes from the
        // node's provider and gets the matching first host of its subnet.
        let octets = virtual_ipv4.octets();
        let tunnel_gateway = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1);
        // Two halves rather than one 0.0.0.0/0, so the physical default route
        // is left in place and simply out-specified.
        capture.routes.push(add_ipv4_route(
            std::net::Ipv4Addr::UNSPECIFIED,
            1,
            tunnel_gateway,
            adapter_index,
            5,
        )?);
        capture.routes.push(add_ipv4_route(
            std::net::Ipv4Addr::new(128, 0, 0, 0),
            1,
            tunnel_gateway,
            adapter_index,
            5,
        )?);
        // Only now: the probe and every later lookup travel the routes above,
        // so pointing Windows at a tunnel resolver before they exist would ask
        // it to resolve through a path that is not there yet.
        let adapter_guid = adapter.get_guid();
        let resolvers = configure_tunnel_dns(adapter_guid, &sessions, tunnel_gateway);
        capture.dns_adapter = (!resolvers.is_empty()).then_some(adapter_guid);
        self.active = Some(capture);
        Ok(json!({
            "state": "capturing",
            "backend": "wintun",
            "adapterIndex": adapter_index,
            "virtualIpv4": virtual_ipv4,
            "trafficMode": input.traffic_mode,
            "effectiveMtu": effective_mtu.mtu,
            "transportOverhead": effective_mtu.overhead,
            "dnsServers": resolvers.iter().map(std::net::Ipv4Addr::to_string).collect::<Vec<_>>(),
            "ipv6": ipv6_exposure(),
        }))
    }

    #[cfg(not(windows))]
    fn start(
        &mut self,
        _payload: Value,
        _sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        Err("packet capture is available only on Windows".into())
    }

    /// Applies a new split policy without touching the multipath session.
    /// WinDivert's kernel expression is immutable, so this intentionally
    /// replaces the capture handles while retaining every relay path.
    #[cfg(windows)]
    pub(crate) fn update(
        &mut self,
        payload: Value,
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        if self.active_split.is_none() {
            return Err("live target updates require an active split capture".into());
        }
        if payload["trafficMode"].as_str() != Some("split") {
            return Err("live target updates require split traffic mode".into());
        }
        self.start(payload, sessions)
    }

    #[cfg(not(windows))]
    fn update(
        &mut self,
        _payload: Value,
        _sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        Err("packet capture is available only on Windows".into())
    }

    pub(crate) fn status(&self) -> Value {
        #[cfg(windows)]
        if let Some(capture) = &self.active {
            return json!({
                "state": "capturing",
                "backend": "wintun",
                "adapterIndex": capture.adapter_index,
            });
        }
        #[cfg(windows)]
        if let Some(capture) = &self.active_split {
            let diagnostics = capture.diagnostics();
            return json!({
                "state": "capturing",
                "backend": "windivert",
                "trafficMode": "split",
                "targetCount": capture.target_count(),
                "diagnostics": diagnostics,
            });
        }
        json!({ "state": "idle" })
    }

    pub(crate) fn stop(&mut self) -> Value {
        #[cfg(windows)]
        {
            drop(self.active.take());
            drop(self.active_split.take());
        }
        json!({ "state": "idle" })
    }
}

impl Drop for PacketCaptureManager {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(windows)]
impl Drop for WindowsPacketCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.session.shutdown();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        // Before the routes, so there is never a moment where Windows is
        // pointed at a resolver the tunnel can no longer reach.
        if let Some(adapter) = self.dns_adapter {
            if let Err(error) = gamepath_engine::netconfig::set_interface_dns(adapter, &[]) {
                log_warn!("could not clear the tunnel adapter's DNS servers: {error}");
            }
        }
        for route in self.routes.iter().rev() {
            remove_ipv4_route(route);
        }
    }
}

#[cfg(windows)]
fn run_wintun_uplink(
    session: Arc<wintun::Session>,
    sessions: Arc<Mutex<WireGuardSessionManager>>,
    virtual_ipv4: std::net::Ipv4Addr,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        let packet = match session.receive_blocking() {
            Ok(packet) => packet,
            Err(_) => return,
        };
        let bytes = packet.bytes().to_vec();
        drop(packet);
        if ipv4_source_address(&bytes) == Some(virtual_ipv4) {
            let _ = sessions.lock().unwrap().enqueue_data_packet(&bytes);
        }
    }
}

#[cfg(windows)]
fn run_wintun_downlink(
    session: Arc<wintun::Session>,
    data_receiver: Arc<DataReceiver>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Acquire) {
        let reply = match data_receiver.receive(Duration::from_millis(250)) {
            Ok(Some(packet)) => packet,
            Ok(None) => continue,
            Err(_) => return,
        };
        if reply.len() > u16::MAX as usize {
            continue;
        }
        if let Ok(mut packet) = session.allocate_send_packet(reply.len() as u16) {
            packet.bytes_mut().copy_from_slice(&reply);
            session.send_packet(packet);
        }
    }
}

#[cfg(windows)]
fn configure_tunnel_interface(interface_index: u32, mtu: u16) -> Result<(), String> {
    gamepath_engine::netconfig::configure_tunnel_interface(interface_index, mtu)
}

/// Adds one route and remembers what it takes to remove it again.
///
/// This used to launch `route.exe` per route, at 135-175 ms each, on top of a
/// `Get-NetRoute` pipeline for the gateway at 450-830 ms. A session with three
/// nodes installs six routes, so starting capture spent well over a second
/// waiting on processes before a packet could move. The IP Helper calls
/// underneath do the same work in microseconds.
#[cfg(windows)]
fn add_ipv4_route(
    destination: std::net::Ipv4Addr,
    prefix_length: u8,
    gateway: std::net::Ipv4Addr,
    interface_index: u32,
    metric: u32,
) -> Result<InstalledRoute, String> {
    gamepath_engine::netconfig::add_route_via(
        destination,
        prefix_length,
        gateway,
        interface_index,
        metric,
    )?;
    Ok(InstalledRoute {
        destination,
        prefix_length,
        gateway,
        interface_index,
    })
}

#[cfg(windows)]
fn remove_ipv4_route(route: &InstalledRoute) {
    gamepath_engine::netconfig::remove_route_via(
        route.destination,
        route.prefix_length,
        route.gateway,
        route.interface_index,
    );
}

fn ipv4_source_address(packet: &[u8]) -> Option<std::net::Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}
