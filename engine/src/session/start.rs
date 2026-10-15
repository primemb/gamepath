//! Bringing a session up.
//!
//! This is the spine of the engine, and the two halves are deliberately
//! different shapes. A relay session dials every enabled node, keeps the ones
//! that answered and records why the rest were left out, then derives one
//! capture MTU that fits the tightest of them. A direct session has a single
//! node that *is* the last hop, so there is nothing to duplicate across and
//! nothing to seal frames for.

use super::dialer::PathDialer;
use super::direct_worker::{DirectRoute, run_direct_path};
use super::dispatch::Dispatch;
use super::join::{JoinGate, RouteStart, RouteTransport, START_RETRY_WINDOW, dial_routes};
use super::local_tap::{InboundSink, LocalTap};
use super::monitors::{spawn_session_summary, spawn_uplink_monitor};
use super::nodes::{MAX_DIRECT_NODES, SessionNode, SessionNodes};
use super::path_mtu::SessionMtu;
use super::relay_worker::run_path;
use super::repair::{LossRepair, spawn_flusher};
use super::state::{
    ActiveWireGuardSession, DataReceiver, PathSessionStatus, RelayIngress, SessionOverlay,
    SkippedRoute, initial_status,
};
use super::worker::{INBOUND_QUEUE_DEPTH, PATH_QUEUE_DEPTH, PathTelemetry};
use super::{WireGuardSessionManager, unix_time_millis};
use crate::ipc::SessionRequest;
use crate::netutil::{link_mtu_for_endpoints, resolve_ipv4, warn_if_below_link_budget};
use gamepath_engine::auth::{EnrollmentToken, SessionCrypto};
use gamepath_engine::l2tp::L2tpRuntime;
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::relay_path::{DirectPath, KIND_SOCKS5, NodeSpec, RelayPath, SessionMode};
use gamepath_engine::role::Role;
use gamepath_engine::scheduler::{PathMetrics, Strategy};
use gamepath_engine::thread_priority;
use gamepath_engine::timer::HighResolutionTimer;
use gamepath_engine::{log_info, log_warn};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// One route of a relay session, open or still joining.
struct SessionRoute {
    route: usize,
    label: String,
    node: NodeSpec,
    transport: RouteTransport,
    /// Every address the route's dial may use, resolved before it opened.
    endpoints: Vec<Ipv4Addr>,
    /// The last failed attempt of a route that is still retrying.
    retrying: Option<String>,
    service_dial: Option<mpsc::Sender<Result<L2tpRuntime, String>>>,
}

impl SessionRoute {
    fn open_path(&self) -> Option<&dyn RelayPath> {
        match &self.transport {
            RouteTransport::Open(path) => Some(path.as_ref()),
            RouteTransport::Joining(_) => None,
        }
    }

    fn is_open(&self) -> bool {
        self.open_path().is_some()
    }

    fn kind(&self) -> &'static str {
        self.open_path()
            .map_or_else(|| self.node.kind(), |path| path.kind())
    }

    /// The outer address its traffic leaves by: the one it opened on, or each
    /// one it may open on.
    fn link_endpoints(&self) -> Vec<Ipv4Addr> {
        match self.open_path() {
            Some(path) => path.bypass_ipv4().into_iter().collect(),
            None => self.endpoints.clone(),
        }
    }

    /// A stream-carried path never sends a datagram the link has to fit.
    fn measured_endpoints(&self) -> Vec<Ipv4Addr> {
        match self.open_path() {
            Some(path) if path.carried_by_stream() => Vec::new(),
            _ => self.link_endpoints(),
        }
    }

    fn initial_status(&self) -> PathSessionStatus {
        match self.open_path() {
            Some(path) => {
                initial_status(self.route, path.kind(), self.label.clone(), path.endpoint())
            }
            None => {
                let mut status = initial_status(
                    self.route,
                    self.node.kind(),
                    self.label.clone(),
                    self.node.describe(),
                );
                status.joining = true;
                status.last_error = Some(match &self.retrying {
                    Some(note) => note.clone(),
                    None if self.node.awaits_service_dial() => {
                        "Windows is still connecting L2TP/IPsec; joins the session when it is up"
                            .into()
                    }
                    None => "still connecting; joins the session when it opens".into(),
                });
                status
            }
        }
    }
}

impl WireGuardSessionManager {
    /// Brings up a relay session: every node carries sealed frames to the
    /// relay, and the scheduler decides how many of them each packet takes.
    pub(super) fn start_relay(
        &mut self,
        input: &SessionRequest,
        nodes: &[NodeSpec],
    ) -> Result<(), String> {
        let enrollment = EnrollmentToken::decode(&input.enrollment_token)?;
        let (client_id, key) = enrollment.material()?;
        let relay_ip = resolve_ipv4(&input.relay_host, input.relay_port)?;
        let relay = SocketAddrV4::new(relay_ip, input.relay_port);
        let strategy = input.strategy;
        let stop = Arc::new(AtomicBool::new(false));
        let mut routes: Vec<SessionRoute> = Vec::new();
        let mut skipped_routes = Vec::new();
        let mut identities = Vec::new();
        // A SOCKS5 node dials its proxy and an OpenVPN node completes a
        // handshake, so this is where a dead provider shows up. One node
        // failing costs its own route, and one still dialling joins later.
        for dialled in dial_routes(nodes, relay, &stop, START_RETRY_WINDOW)? {
            let index = dialled.index;
            let route = index + 1;
            let node = &nodes[index];
            let label = node
                .label()
                .or_else(|| {
                    input
                        .route_labels
                        .get(index)
                        .map(|label| label.trim().to_owned())
                        .filter(|label| !label.is_empty())
                })
                .unwrap_or_else(|| node.default_label(route));
            let (transport, node, service_dial) = match dialled.start {
                RouteStart::Failed(reason) => {
                    skipped_routes.push(SkippedRoute {
                        route,
                        label: node.describe(),
                        reason,
                    });
                    continue;
                }
                RouteStart::Open(joined) => {
                    let identity = joined.path.identity();
                    if identities.contains(&identity) {
                        skipped_routes.push(SkippedRoute {
                            route,
                            label: node.describe(),
                            reason: "another enabled route already uses this endpoint and key"
                                .into(),
                        });
                        continue;
                    }
                    identities.push(identity);
                    (RouteTransport::Open(joined.path), joined.node, None)
                }
                RouteStart::Joining(dial) => (
                    RouteTransport::Joining(dial.result),
                    node.clone(),
                    dial.service_dial,
                ),
            };
            routes.push(SessionRoute {
                route,
                label,
                node,
                transport,
                endpoints: dialled.endpoints,
                retrying: dialled.retrying,
                service_dial,
            });
        }
        let paths = routes;
        for skipped in &skipped_routes {
            // A route silently missing from the session is the thing nobody can
            // explain later, so each one says why on its own line.
            log_warn!(
                "route {} ({}) did not join: {}",
                skipped.route,
                skipped.label,
                skipped.reason
            );
        }
        // Every node failed to dial. There is no session to degrade into, so
        // this reports each one rather than a bare timeout.
        if !paths.iter().any(SessionRoute::is_open) {
            // Routes still retrying have nothing left to join.
            stop.store(true, Ordering::Release);
            let still_trying = paths.iter().map(|route| {
                let reason = route.retrying.as_deref().unwrap_or("still connecting");
                (route.route, route.label.as_str(), reason)
            });
            return Err(format!(
                "no route could be opened: {}",
                skipped_routes
                    .iter()
                    .map(|skipped| (
                        skipped.route,
                        skipped.label.as_str(),
                        skipped.reason.as_str()
                    ))
                    .chain(still_trying)
                    .map(|(route, label, reason)| format!("route {route} ({label}): {reason}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        // One capture adapter serves every selected path, including the ones
        // still joining: its MTU must fit the smallest outer route and the
        // strictest provider tunnel cap of every route that may carry traffic,
        // because it cannot change once capture has started.
        let link_mtu = link_mtu_for_endpoints(paths.iter().flat_map(SessionRoute::link_endpoints));
        let provider_mtu = paths
            .iter()
            .filter_map(|route| route.node.configured_tunnel_mtu())
            .min();
        let kinds = paths.iter().map(SessionRoute::kind).collect::<Vec<_>>();
        let effective_mtu =
            EffectiveMtu::for_session(SessionMode::Relay, kinds.iter().copied(), link_mtu)
                .with_tunnel_limit(provider_mtu);
        let session_mtu = Arc::new(SessionMtu::measure(
            effective_mtu,
            link_mtu,
            paths.iter().flat_map(SessionRoute::measured_endpoints),
            move |link_mtu| {
                EffectiveMtu::for_session(SessionMode::Relay, kinds, link_mtu)
                    .with_tunnel_limit(provider_mtu)
            },
        ));
        let route_summary = paths
            .iter()
            .map(|route| {
                format!(
                    "{}:{}/{}{}",
                    route.route,
                    route.label,
                    route.kind(),
                    if route.is_open() { "" } else { " (joining)" }
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        // Every address a route may dial, not only the one it opened on: a
        // joining route's first packet and a redial to another remote must
        // both leave outside the capture.
        let mut bypass_ips = vec![relay_ip];
        for route in &paths {
            bypass_ips.extend(route.link_endpoints());
            bypass_ips.extend(route.endpoints.iter().copied());
        }
        bypass_ips.sort_unstable();
        bypass_ips.dedup();

        self.stop();
        let timer = HighResolutionTimer::raise();
        let session_id = rand::random::<u64>();
        let crypto = Arc::new(SessionCrypto::new(&key, session_id)?);
        let sequences = Arc::new(AtomicU64::new(1));
        let initial_statuses = paths
            .iter()
            .map(SessionRoute::initial_status)
            .collect::<Vec<_>>();
        let statuses = Arc::new(Mutex::new(initial_statuses));
        let route_count = paths.len();
        let scheduler_metrics = Arc::new(Mutex::new(
            (0..route_count)
                .map(|index| PathMetrics::new(index.to_string()))
                .collect::<Vec<_>>(),
        ));
        // Only the routes that are open: a joining one has nothing to carry a
        // packet with, and enters the pick through its first answered probe.
        let initial_mask = paths
            .iter()
            .enumerate()
            .filter(|(_, route)| route.is_open())
            .fold(0_u64, |mask, (index, _)| {
                mask | 1_u64.checked_shl(index as u32).unwrap_or(0)
            });
        let initial_mask = super::health::initial_selection(initial_mask, strategy);
        let decision_mask = Arc::new(AtomicU64::new(initial_mask));
        let telemetry = PathTelemetry::new(route_count);
        let mut workers = Vec::with_capacity(route_count + 1);
        let (commands, receivers): (Vec<_>, Vec<_>) = (0..route_count)
            .map(|_| mpsc::sync_channel(PATH_QUEUE_DEPTH))
            .unzip();
        let dispatch = Arc::new(Dispatch {
            commands,
            telemetry: telemetry.clone(),
        });
        let loss_repair = Arc::new(LossRepair::new(
            Arc::clone(&crypto),
            client_id,
            session_id,
            Arc::clone(&sequences),
            Arc::clone(&dispatch),
            Arc::clone(&decision_mask),
            effective_mtu.mtu,
        ));
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let local_tap = Arc::new(LocalTap::default());
        let inbound = InboundSink::new(inbound_tx, Arc::clone(&local_tap));
        let ingress = Arc::new(RelayIngress::new(
            client_id,
            session_id,
            Arc::clone(&telemetry.packet_diagnostics),
        ));
        let skipped_count = skipped_routes.len();
        let skipped_routes = Arc::new(Mutex::new(skipped_routes));
        let gate = Arc::new(JoinGate::new(
            bypass_ips.clone(),
            identities,
            Arc::clone(&skipped_routes),
        ));
        let mut service_dials = HashMap::new();
        for (index, (route, command_rx)) in paths.into_iter().zip(receivers).enumerate() {
            let status_index = index;
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
            let worker_inbound = inbound.clone();
            let worker_ingress = Arc::clone(&ingress);
            let worker_repair = Arc::clone(&loss_repair);
            let worker_metrics = Arc::clone(&scheduler_metrics);
            let worker_decision = Arc::clone(&decision_mask);
            let worker_telemetry = telemetry.clone();
            let worker_gate = Arc::clone(&gate);
            let worker_kind = route.kind();
            if let Some(dial) = route.service_dial {
                service_dials.insert(route.route, dial);
            }
            let worker_dialer = PathDialer {
                node: route.node,
                relay,
                cheap_reopen: Arc::new(AtomicBool::new(true)),
            };
            let transport = route.transport;
            workers.push(
                thread::Builder::new()
                    .name(format!("gamepath-{worker_kind}-{}", index + 1))
                    .spawn(move || {
                        thread_priority::raise_current_for_data_plane();
                        run_path(
                            transport,
                            status_index,
                            worker_sequences,
                            client_id,
                            key,
                            session_id,
                            worker_stop,
                            worker_statuses,
                            command_rx,
                            worker_inbound,
                            worker_ingress,
                            worker_repair,
                            worker_metrics,
                            worker_decision,
                            initial_mask,
                            strategy,
                            worker_telemetry,
                            worker_dialer,
                            worker_gate,
                            route_count,
                        )
                    })
                    .map_err(|error| format!("could not start path worker: {error}"))?,
            );
        }
        workers.push(
            spawn_flusher(&loss_repair, &stop)
                .map_err(|error| format!("could not start loss repair: {error}"))?,
        );
        let data_receiver = Arc::new(DataReceiver {
            inbound: Mutex::new(inbound_rx),
            user_bytes_received: AtomicU64::new(0),
        });
        workers.extend(spawn_uplink_monitor(&stop, &telemetry));
        let summary = spawn_session_summary(
            session_id,
            &stop,
            &statuses,
            &telemetry,
            &decision_mask,
            &scheduler_metrics,
        );
        workers.extend(summary);
        log_info!(
            "relay session {session_id} up: {route_count} route(s) [{route_summary}], \
             uplink mtu {link_mtu}, tunnel mtu {} overhead {}, {skipped_count} skipped",
            effective_mtu.mtu,
            effective_mtu.overhead,
        );
        warn_if_below_link_budget(effective_mtu, link_mtu);
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Relay,
            strategy,
            overlay: SessionOverlay::Relay { client_id, crypto },
            session_id,
            started_at: unix_time_millis(),
            user_bytes_sent: Arc::new(AtomicU64::new(0)),
            stop,
            paths: statuses,
            workers,
            skipped_routes,
            service_dials,
            dispatch,
            loss_repair: Some(loss_repair),
            ingress: Some(ingress),
            data_receiver,
            virtual_ipv4: enrollment.virtual_ipv4,
            sequences,
            decision_mask,
            telemetry,
            scheduler_metrics,
            // The relay is the one node: the scheduler picks its routes.
            nodes: Arc::new(SessionNodes::new(vec![SessionNode {
                address: enrollment.virtual_ipv4,
                mtu: Arc::clone(&session_mtu),
                socks_proxy: None,
            }])),
            mtu: session_mtu,
            bypass_ips,
            local_tap,
            timer,
        });
        Ok(())
    }

    /// Brings up a direct session: no relay, and each node doing the routing
    /// that a relay would otherwise do for the flows pinned to it.
    pub(super) fn start_direct(&mut self, nodes: &[NodeSpec]) -> Result<(), String> {
        // Duplication needs a relay to recognise the copies, so several nodes
        // only make sense when each flow is pinned to one of them, which is
        // the VPN's per-app routing. Say so rather than silently using the
        // first node and leaving the rest looking active.
        if nodes.len() > 1 && Role::current() != Role::Vpn {
            return Err(format!(
                "direct mode sends traffic through exactly one node, but {} are enabled. \
                 Enable a single WireGuard, OpenVPN or L2TP/IPsec node, or switch to relay mode to combine them.",
                nodes.len()
            ));
        }
        if nodes.is_empty() || nodes.len() > MAX_DIRECT_NODES {
            return Err(format!(
                "a direct session uses between 1 and {MAX_DIRECT_NODES} nodes, but {} were given",
                nodes.len()
            ));
        }
        // Together: each OpenVPN node is a handshake of its own, and one slow
        // provider must not hold the others.
        let opened = thread::scope(|scope| {
            nodes
                .iter()
                .map(|node| scope.spawn(move || node.open_direct()))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|opening| {
                    opening
                        .join()
                        .unwrap_or_else(|_| Err("opening the node panicked".to_owned()))
                })
                .collect::<Vec<_>>()
        });
        // A node that did not open keeps being dialled by its worker, so the
        // session starts on the others; only a session with none fails.
        if opened.iter().all(Result::is_err) {
            return Err(nodes
                .iter()
                .zip(&opened)
                .filter_map(|(node, path)| {
                    Some(format!("{}: {}", node.describe(), path.as_ref().err()?))
                })
                .collect::<Vec<_>>()
                .join("; "));
        }

        self.stop();
        let timer = HighResolutionTimer::raise();
        let stop = Arc::new(AtomicBool::new(false));
        let session_id = rand::random::<u64>();
        let count = nodes.len();
        let mut bypass_ips = Vec::new();
        let mut session_nodes = Vec::with_capacity(count);
        let mut initial_statuses = Vec::with_capacity(count);
        let mut summary = Vec::with_capacity(count);
        for (index, (node, path)) in nodes.iter().zip(&opened).enumerate() {
            let route = index + 1;
            let path = path.as_ref();
            let kind = path.map_or_else(|_| node.kind(), DirectPath::kind);
            // Every address the node may dial, so a redial to another one
            // still leaves outside the capture.
            let mut endpoints = node.endpoint_ipv4s();
            endpoints.extend(path.ok().and_then(DirectPath::bypass_ipv4));
            endpoints.sort_unstable();
            endpoints.dedup();
            let link_mtu = link_mtu_for_endpoints(endpoints.iter().copied());
            let provider_mtu = node.configured_tunnel_mtu();
            let effective_mtu = EffectiveMtu::for_session(SessionMode::Direct, [kind], link_mtu)
                .with_tunnel_limit(provider_mtu);
            warn_if_below_link_budget(effective_mtu, link_mtu);
            let measured = path
                .ok()
                .filter(|path| !path.carried_by_stream())
                .and_then(DirectPath::bypass_ipv4);
            let mtu = Arc::new(SessionMtu::measure(
                effective_mtu,
                link_mtu,
                measured,
                move |link_mtu| {
                    EffectiveMtu::for_session(SessionMode::Direct, [kind], link_mtu)
                        .with_tunnel_limit(provider_mtu)
                },
            ));
            let label = node.label().unwrap_or_else(|| node.default_label(route));
            let mut status = initial_status(
                route,
                kind,
                label.clone(),
                path.map_or_else(|_| node.describe(), |path| path.endpoint().to_string()),
            );
            if let Err(error) = path {
                log_warn!("route {route} ({label}) did not open, retrying: {error}");
                status.joining = true;
                status.last_error = Some(error.clone());
            }
            summary.push(format!(
                "{route}:{label}/{kind} mtu {}{}",
                effective_mtu.mtu,
                if path.is_ok() { "" } else { " (dialling)" }
            ));
            session_nodes.push(SessionNode {
                address: path.map_or(Ipv4Addr::UNSPECIFIED, DirectPath::address),
                mtu,
                socks_proxy: match path {
                    Ok(path) if kind == KIND_SOCKS5 => Some(path.endpoint()),
                    _ => proxy_address(node),
                },
            });
            initial_statuses.push(status);
            bypass_ips.extend(endpoints);
        }
        bypass_ips.sort_unstable();
        bypass_ips.dedup();
        let session_mtu = Arc::clone(&session_nodes[0].mtu);
        let session_nodes = Arc::new(SessionNodes::new(session_nodes));
        let statuses = Arc::new(Mutex::new(initial_statuses));
        let scheduler_metrics = Arc::new(Mutex::new(
            (0..count)
                .map(|index| PathMetrics::new(index.to_string()))
                .collect::<Vec<_>>(),
        ));
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let local_tap = Arc::new(LocalTap::default());
        let inbound = InboundSink::new(inbound_tx, Arc::clone(&local_tap));
        let telemetry = PathTelemetry::new(count);
        let (commands, receivers): (Vec<_>, Vec<_>) = (0..count)
            .map(|_| mpsc::sync_channel(PATH_QUEUE_DEPTH))
            .unzip();
        let mut workers = Vec::with_capacity(count + 2);
        for (index, ((node, path), command_rx)) in
            nodes.iter().zip(opened).zip(receivers).enumerate()
        {
            let route = DirectRoute {
                index,
                node: node.clone(),
                nodes: Arc::clone(&session_nodes),
            };
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_inbound = inbound.clone();
            let worker_metrics = Arc::clone(&scheduler_metrics);
            let worker_telemetry = telemetry.clone();
            workers.push(
                thread::Builder::new()
                    .name(format!("gamepath-direct-{}", index + 1))
                    .spawn(move || {
                        thread_priority::raise_current_for_data_plane();
                        run_direct_path(
                            path.ok(),
                            route,
                            worker_stop,
                            worker_statuses,
                            command_rx,
                            worker_inbound,
                            worker_metrics,
                            worker_telemetry,
                            session_id,
                        )
                    })
                    .map_err(|error| format!("could not start path worker: {error}"))?,
            );
        }
        // Every node is in the pick; capture says which one each flow takes.
        let decision_mask = Arc::new(AtomicU64::new(u64::MAX >> (64 - count)));
        workers.extend(spawn_uplink_monitor(&stop, &telemetry));
        workers.extend(spawn_session_summary(
            session_id,
            &stop,
            &statuses,
            &telemetry,
            &decision_mask,
            &scheduler_metrics,
        ));
        log_info!(
            "direct session up: {count} node(s) [{}]",
            summary.join(", ")
        );
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Direct,
            strategy: Strategy::FastestPath,
            overlay: SessionOverlay::Direct,
            session_id,
            started_at: unix_time_millis(),
            user_bytes_sent: Arc::new(AtomicU64::new(0)),
            stop,
            paths: statuses,
            workers,
            skipped_routes: Arc::default(),
            service_dials: HashMap::new(),
            dispatch: Arc::new(Dispatch {
                commands,
                telemetry: telemetry.clone(),
            }),
            loss_repair: None,
            ingress: None,
            data_receiver: Arc::new(DataReceiver {
                inbound: Mutex::new(inbound_rx),
                user_bytes_received: AtomicU64::new(0),
            }),
            virtual_ipv4: session_nodes.address(0),
            sequences: Arc::new(AtomicU64::new(1)),
            decision_mask,
            telemetry,
            scheduler_metrics,
            mtu: session_mtu,
            nodes: session_nodes,
            bypass_ips,
            local_tap,
            timer,
        });
        Ok(())
    }
}

/// Where a SOCKS5 node's proxy listens, before it has been opened.
fn proxy_address(node: &NodeSpec) -> Option<SocketAddr> {
    let NodeSpec::Socks5 { port, .. } = node else {
        return None;
    };
    let address = *node.endpoint_ipv4s().first()?;
    Some(SocketAddr::from((address, *port)))
}
