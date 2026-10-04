//! Owns the packet capture that feeds a running session.
//!
//! All-traffic mode puts a Wintun adapter in front of the default route;
//! split mode hands the work to [`crate::split_capture`], which filters in the
//! kernel with WinDivert. Both are torn down and replaced by a policy change
//! without the multipath session underneath ever restarting.

use crate::ipc::PacketCaptureRequest;
use crate::netutil::ipv6_exposure;
use crate::session::{DataReceiver, SenderCache, WireGuardSessionManager};
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
    #[cfg(windows)]
    dns_guard: Option<crate::dns_guard::DnsGuard>,
    #[cfg(windows)]
    native_dns_adapter: Option<u128>,
    /// The request the running capture was started with, so a change to the
    /// other session's tunnel can be applied without the caller resending it.
    last_request: Option<Value>,
}

#[cfg(windows)]
struct WindowsPacketCapture {
    stop: Arc<AtomicBool>,
    session: Arc<wintun::Session>,
    workers: Vec<JoinHandle<()>>,
    routes: Vec<InstalledRoute>,
    adapter_index: u32,
    virtual_ipv4: std::net::Ipv4Addr,
    /// Set only when this capture configured the adapter's resolvers, so
    /// teardown clears exactly what it set and leaves an adapter it never
    /// touched alone.
    dns_adapter: Option<u128>,
    /// The physical route the bypass routes go through.
    default_gateway: std::net::Ipv4Addr,
    default_interface: u32,
    /// Host routes keeping the other session's tunnel off this one, replaced
    /// as that session comes and goes.
    foreign_routes: Vec<InstalledRoute>,
}

#[cfg(windows)]
impl WindowsPacketCapture {
    fn set_foreign_bypass(&mut self, addresses: &[std::net::Ipv4Addr]) -> Result<(), String> {
        let (keep, stale): (Vec<_>, Vec<_>) = std::mem::take(&mut self.foreign_routes)
            .into_iter()
            .partition(|route| addresses.contains(&route.destination));
        for route in &stale {
            remove_ipv4_route(route);
        }
        self.foreign_routes = keep;
        for address in addresses {
            if self
                .foreign_routes
                .iter()
                .any(|route| route.destination == *address)
            {
                continue;
            }
            self.foreign_routes.push(add_ipv4_route(
                *address,
                32,
                self.default_gateway,
                self.default_interface,
                1,
            )?);
        }
        Ok(())
    }
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
) -> Result<Vec<std::net::Ipv4Addr>, String> {
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
            Ok(servers)
        }
        Err(error) => Err(format!(
            "could not configure remote DNS; refusing local fallback: {error}"
        )),
    }
}

/// Says where the tunnel's resolvers sit in the order Windows will ask them.
///
/// The interface metric decides this, and the metric is a fixed number that
/// cannot be right for every machine ([`TUNNEL_INTERFACE_METRIC`] explains the
/// choice). Rather than assume the intended ordering held, this reports what
/// actually outranks the tunnel, so a machine where another client took a
/// lower metric - or a fast NIC left on automatic tied with us - says so in
/// the log instead of quietly resolving somewhere unexpected.
#[cfg(windows)]
fn log_resolver_priority(adapter_index: u32) {
    let ahead = gamepath_engine::netconfig::lower_metric_ipv4_interfaces(adapter_index);
    if ahead.is_empty() {
        log_info!("tunnel resolvers are first in line for this machine's name lookups");
        return;
    }
    let ahead = ahead
        .iter()
        .map(|(index, metric)| format!("interface {index} (metric {metric})"))
        .collect::<Vec<_>>()
        .join(", ");
    // Not a warning. Another live tunnel ranking above this one is the
    // expected arrangement, and its resolver is reached through its own
    // tunnel, so lookups are still not going to the local network.
    log_info!("name lookups are offered to {ahead} before the tunnel's resolvers");
}

/// Whether the game's capture leaves other applications' own name lookups
/// alone because the VPN is running. With the VPN off the game resolves
/// everything, as it always did.
#[cfg(windows)]
fn yields_foreign_lookups(other_session_active: bool) -> bool {
    gamepath_engine::role::Role::current() == gamepath_engine::role::Role::Game
        && other_session_active
}

/// Opens this engine's Wintun adapter, creating it if this is the first
/// session since boot. Both traffic modes use the same adapter and the same
/// GUID, so a mode change reuses the interface rather than making a second one.
/// The game and the VPN each have their own, so neither can overwrite the
/// other's addresses, routes or resolvers.
#[cfg(windows)]
fn open_session_adapter() -> Result<std::sync::Arc<wintun::Adapter>, String> {
    let identity = gamepath_engine::role::Role::current().adapter();
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
    // SAFETY: only the repository's verified Wintun DLL or the installed copy
    // beside the privileged engine is loaded.
    let wintun = unsafe { wintun::load_from_path(&dll) }
        .map_err(|error| format!("could not load Wintun: {error}"))?;
    wintun::Adapter::open(&wintun, identity.name)
        .or_else(|_| {
            wintun::Adapter::create(&wintun, identity.name, "GamePath", Some(identity.guid))
        })
        .map_err(|error| format!("could not create the {} adapter: {error}", identity.name))
}

impl PacketCaptureManager {
    #[cfg(windows)]
    pub(crate) fn start_native_dns(&mut self, payload: Value) -> Result<Value, String> {
        let input: PacketCaptureRequest = serde_json::from_value(payload.clone())
            .map_err(|error| format!("invalid native DNS request: {error}"))?;
        let index = payload["interfaceIndex"]
            .as_u64()
            .and_then(|index| u32::try_from(index).ok())
            .ok_or("native DNS needs the VPN interface index")?;
        if input.remote_dns {
            let guard = crate::dns_guard::DnsGuard::start(&input, Some(index))?;
            let servers = gamepath_engine::dns::resolver_order(None);
            let guid = gamepath_engine::netconfig::set_interface_dns_by_index(index, &servers)?;
            self.native_dns_adapter = Some(guid);
            self.dns_guard = Some(guard);
            gamepath_engine::netconfig::flush_dns_cache();
        } else {
            self.dns_guard = None;
            if let Some(adapter) = self.native_dns_adapter.take() {
                gamepath_engine::netconfig::set_interface_dns(adapter, &[])?;
                gamepath_engine::netconfig::flush_dns_cache();
            }
        }
        self.last_request = Some(payload);
        Ok(json!({"remoteDns": input.remote_dns,
            "dnsServers": if input.remote_dns { gamepath_engine::dns::resolver_order(None) } else { vec![] }}))
    }

    #[cfg(windows)]
    pub(crate) fn start(
        &mut self,
        payload: Value,
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        let input: PacketCaptureRequest = serde_json::from_value(payload.clone())
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
        #[cfg(windows)]
        let previous_dns = self.dns_mode();
        // Keep assigned DNS closed while replacing a live capture policy.
        #[cfg(windows)]
        let _transition_dns_guard = if input.remote_dns {
            Some(crate::dns_guard::DnsGuard::start(&input, Some(u32::MAX))?)
        } else {
            None
        };
        #[cfg(windows)]
        let carried = {
            drop(self.active.take());
            self.active_split
                .take()
                .map(crate::split_capture::SplitPacketCapture::into_carried)
        };
        self.last_request = Some(payload);
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
            self.dns_guard = if input.remote_dns {
                Some(crate::dns_guard::DnsGuard::start(&input, None)?)
            } else {
                None
            };
            let own_apps_only = gamepath_engine::role::Role::current()
                == gamepath_engine::role::Role::Vpn
                && input.other_session_active;
            let mut excluded = bypass_ips;
            excluded.extend(&input.foreign_bypass);
            let split = crate::split_capture::SplitPacketCapture::start(
                &input.rules,
                virtual_ipv4,
                &excluded,
                sessions,
                data_receiver,
                effective_mtu,
                crate::split_capture::SplitOptions {
                    kill_switch: input.kill_switch,
                    remote_dns: input.remote_dns,
                    own_apps_only,
                    yield_foreign_lookups: yields_foreign_lookups(
                        input.other_session_active && input.other_session_app_dns,
                    ),
                    own_hostnames: input.own_hostnames.clone(),
                    carried,
                    // Only the VPN, and only with no game running: the VPN
                    // cannot see the game's rules, and must never end a
                    // connection the game carries.
                    reset_existing: gamepath_engine::role::Role::current()
                        == gamepath_engine::role::Role::Vpn
                        && !input.other_session_active,
                },
            )?;
            let target_count = split.target_count();
            // The game always wins name resolution too. Its own lookups, made
            // for it by Windows, must not come back as the VPN proxy's fake
            // IPs: the game's tunnel cannot reach those, so the game would end
            // up carried by the VPN.
            let own_apps_only = gamepath_engine::role::Role::current()
                == gamepath_engine::role::Role::Vpn
                && input.other_session_active;
            split.set_redirect_dns(input.remote_dns, own_apps_only);
            split.set_yield_foreign_lookups(yields_foreign_lookups(
                input.other_session_active && input.other_session_app_dns,
            ));
            self.active_split = Some(split);
            let dns = self.dns_mode();
            // Answers cached before the switch would outlive it: the router's
            // filtered ones going in, a proxy's fake-IP ones coming out.
            if dns != previous_dns {
                gamepath_engine::netconfig::flush_dns_cache();
                match dns {
                    Some(false) => log_info!(
                        "split tunnel DNS: lookups to LAN resolvers are answered by {} through the tunnel",
                        crate::split_capture::TUNNEL_RESOLVER
                    ),
                    Some(true) => log_info!(
                        "the game session is running: only this session's own apps resolve through it"
                    ),
                    None => {}
                }
            }
            let dns_servers = self.split_dns_servers();
            return Ok(json!({
                "state": "capturing",
                "backend": "windivert",
                "trafficMode": "split",
                "targetCount": target_count,
                "effectiveMtu": effective_mtu.mtu,
                "tcpMss": effective_mtu.tcp_mss(),
                "dnsServers": dns_servers,
                // Selected targets are matched as IPv4. A game reaching the
                // same server over IPv6 is not captured at all, so the
                // exposure is worth reporting in split mode too.
                "ipv6": ipv6_exposure(),
            }));
        }
        let (default_gateway, default_interface) =
            gamepath_engine::netconfig::default_ipv4_route()?;
        let adapter = open_session_adapter()?;
        let adapter_index = adapter
            .get_adapter_index()
            .map_err(|error| format!("could not read GamePath adapter index: {error}"))?;
        configure_tunnel_interface(adapter_index, effective_mtu.mtu)?;
        gamepath_engine::netconfig::set_interface_ipv4_address(adapter_index, virtual_ipv4, 24)
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
        let diagnostics = sessions
            .lock()
            .unwrap()
            .packet_diagnostics()
            .ok_or("start the multipath session before packet capture")?;
        let uplink_diagnostics = Arc::clone(&diagnostics);
        let uplink_sessions = Arc::clone(&sessions);
        let uplink_stop = Arc::clone(&stop);
        let uplink_session = Arc::clone(&session);
        let uplink = thread::Builder::new()
            .name("gamepath-wintun-uplink".into())
            .spawn(move || {
                gamepath_engine::thread_priority::raise_current_for_data_plane();
                run_wintun_uplink(
                    uplink_session,
                    uplink_sessions,
                    virtual_ipv4,
                    uplink_stop,
                    uplink_diagnostics,
                )
            })
            .map_err(|error| format!("could not start Wintun uplink: {error}"))?;
        let downlink_stop = Arc::clone(&stop);
        let downlink_session = Arc::clone(&session);
        let downlink = thread::Builder::new()
            .name("gamepath-wintun-downlink".into())
            .spawn(move || {
                gamepath_engine::thread_priority::raise_current_for_data_plane();
                run_wintun_downlink(downlink_session, data_receiver, downlink_stop, diagnostics)
            })
            .map_err(|error| format!("could not start Wintun downlink: {error}"))?;

        let mut capture = WindowsPacketCapture {
            stop,
            session,
            workers: vec![uplink, downlink],
            routes: Vec::new(),
            adapter_index,
            virtual_ipv4,
            dns_adapter: None,
            default_gateway,
            default_interface,
            foreign_routes: Vec::new(),
        };
        capture.set_foreign_bypass(&input.foreign_bypass)?;
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
        self.dns_guard = if input.remote_dns {
            Some(crate::dns_guard::DnsGuard::start(
                &input,
                Some(adapter_index),
            )?)
        } else {
            None
        };
        // With the setting off the adapter is left without servers, so Windows
        // falls back to the physical interface's - the behaviour every release
        // before the setting had.
        let resolvers = if input.remote_dns {
            configure_tunnel_dns(adapter_guid, &sessions, tunnel_gateway)?
        } else {
            log_info!("remote DNS is off: name resolution stays with the local resolver");
            Vec::new()
        };
        capture.dns_adapter = (!resolvers.is_empty()).then_some(adapter_guid);
        if capture.dns_adapter.is_some() {
            gamepath_engine::netconfig::flush_dns_cache();
            log_resolver_priority(adapter_index);
        }
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

    /// Keeps the other session's tunnel clear of this capture after that
    /// session started, stopped or moved. All-traffic mode only swaps host
    /// routes; split mode has to reopen its kernel filter, which keeps the
    /// session and its paths exactly as a live rule edit does.
    #[cfg(windows)]
    pub(crate) fn set_foreign_bypass(
        &mut self,
        payload: Value,
        sessions: Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        let addresses: Vec<std::net::Ipv4Addr> =
            serde_json::from_value(payload["addresses"].clone())
                .map_err(|error| format!("invalid bypass addresses: {error}"))?;
        let Some(mut request) = self.last_request.clone() else {
            return Ok(json!({ "state": "idle" }));
        };
        request["foreignBypass"] = json!(addresses);
        request["otherSessionActive"] = json!(payload["otherSessionActive"] == json!(true));
        if let Some(capture) = self.active.as_mut() {
            capture.set_foreign_bypass(&addresses)?;
            self.last_request = Some(request);
            log_info!(
                "other session's tunnel routed around this one: {} address(es)",
                addresses.len()
            );
            return Ok(self.status());
        }
        if self.active_split.is_some() {
            let result = self.start(request, sessions)?;
            log_info!(
                "other session's tunnel kept out of this capture: {} address(es)",
                addresses.len()
            );
            return Ok(result);
        }
        self.last_request = Some(request);
        Ok(json!({ "state": "idle" }))
    }

    #[cfg(not(windows))]
    pub(crate) fn set_foreign_bypass(
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
                "dnsServers": self.split_dns_servers(),
                "diagnostics": diagnostics,
            });
        }
        json!({ "state": "idle" })
    }

    pub(crate) fn stop(&mut self) -> Value {
        self.last_request = None;
        #[cfg(windows)]
        {
            crate::teardown::step("DNS guard");
            self.dns_guard = None;
            if let Some(adapter) = self.native_dns_adapter.take() {
                let _ = gamepath_engine::netconfig::set_interface_dns(adapter, &[]);
                gamepath_engine::netconfig::flush_dns_cache();
            }
        }
        #[cfg(windows)]
        {
            let was_redirecting = self.dns_mode().is_some();
            let tunnel_address = self.active.as_ref().map(|capture| capture.virtual_ipv4);
            crate::teardown::step("all-traffic capture");
            drop(self.active.take());
            let carried = self
                .active_split
                .take()
                .map(crate::split_capture::SplitPacketCapture::into_carried);
            if was_redirecting {
                gamepath_engine::netconfig::flush_dns_cache();
            }
            // Capture and routes must be gone and DNS fresh before apps retry.
            // A live policy replacement uses into_carried without closing flows.
            crate::teardown::step("ending tunnel TCP connections");
            let closed = if let Some(carried) = carried {
                carried.close_tcp_connections()
            } else if let Some(address) = tunnel_address {
                crate::tcp_reset::close_matching(|connection| *connection.local.ip() == address)
            } else {
                0
            };
            if closed != 0 {
                log_info!(
                    "ended {closed} tunnel TCP connection(s) so applications reconnect after disconnect"
                );
            }
        }
        json!({ "state": "idle" })
    }

    /// How the split capture redirects lookups: `None` not at all, else
    /// whether only its own apps' lookups.
    /// The other session started or stopped. Only the game acts on it, by
    /// leaving other applications' own name lookups to the VPN; the capture
    /// is not reopened, so the game's traffic is never interrupted for it.
    #[cfg(windows)]
    pub(crate) fn set_other_session_active(&mut self, payload: &Value) -> Value {
        let active = payload["active"] == json!(true);
        let can_route_apps = payload["canRouteAppDns"].as_bool().unwrap_or(true);
        if let Some(request) = self.last_request.as_mut() {
            request["otherSessionActive"] = json!(active);
            request["otherSessionAppDns"] = json!(can_route_apps);
        }
        if let Some(split) = &self.active_split {
            split.set_yield_foreign_lookups(yields_foreign_lookups(active && can_route_apps));
        }
        if let Some(guard) = &self.dns_guard {
            guard.set_other_active(active, can_route_apps);
        }
        json!({ "otherSessionActive": active })
    }

    #[cfg(not(windows))]
    pub(crate) fn set_other_session_active(&mut self, _payload: &Value) -> Value {
        json!({ "state": "idle" })
    }

    #[cfg(windows)]
    fn dns_mode(&self) -> Option<bool> {
        self.active_split
            .as_ref()
            .and_then(crate::split_capture::SplitPacketCapture::dns_mode)
    }

    #[cfg(windows)]
    fn split_dns_servers(&self) -> Vec<String> {
        if self.dns_mode().is_some() {
            vec![crate::split_capture::TUNNEL_RESOLVER.to_string()]
        } else {
            Vec::new()
        }
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
            gamepath_engine::netconfig::flush_dns_cache();
        }
        for route in self.foreign_routes.iter().chain(self.routes.iter()).rev() {
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
    diagnostics: Arc<gamepath_engine::packet_diagnostics::PacketDiagnostics>,
) {
    let mut sender = SenderCache::new(sessions);
    while !stop.load(Ordering::Acquire) {
        let packet = match session.receive_blocking() {
            Ok(packet) => packet,
            Err(error) => {
                if !stop.load(Ordering::Acquire) {
                    gamepath_engine::log_error!(
                        "Wintun capture receiver stopped unexpectedly: {error}"
                    );
                }
                return;
            }
        };
        let bytes = packet.bytes().to_vec();
        drop(packet);
        if ipv4_source_address(&bytes) == Some(virtual_ipv4) {
            let _ = sender.send(&bytes);
        } else {
            diagnostics.record(
                gamepath_engine::packet_diagnostics::Reason::WintunInvalidSource,
                &bytes,
            );
        }
    }
}

#[cfg(windows)]
fn run_wintun_downlink(
    session: Arc<wintun::Session>,
    data_receiver: Arc<DataReceiver>,
    stop: Arc<AtomicBool>,
    diagnostics: Arc<gamepath_engine::packet_diagnostics::PacketDiagnostics>,
) {
    while !stop.load(Ordering::Acquire) {
        let reply = match data_receiver.receive(Duration::from_millis(250)) {
            Ok(Some(packet)) => packet,
            Ok(None) => continue,
            Err(error) => {
                if !stop.load(Ordering::Acquire) {
                    gamepath_engine::log_error!(
                        "Wintun reply receiver stopped unexpectedly: {error}"
                    );
                }
                return;
            }
        };
        if reply.len() > u16::MAX as usize {
            diagnostics.record(
                gamepath_engine::packet_diagnostics::Reason::OversizedReply,
                &reply,
            );
            continue;
        }
        match session.allocate_send_packet(reply.len() as u16) {
            Ok(mut packet) => {
                packet.bytes_mut().copy_from_slice(&reply);
                session.send_packet(packet);
            }
            Err(error) => diagnostics.record_error(
                gamepath_engine::packet_diagnostics::Reason::WintunInject,
                &reply,
                &error.to_string(),
            ),
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
