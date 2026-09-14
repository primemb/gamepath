//! Bringing a session up.
//!
//! This is the spine of the engine, and the two halves are deliberately
//! different shapes. A relay session dials every enabled node, keeps the ones
//! that answered and records why the rest were left out, then derives one
//! capture MTU that fits the tightest of them. A direct session has a single
//! node that *is* the last hop, so there is nothing to duplicate across and
//! nothing to seal frames for.

use super::dialer::PathDialer;
use super::direct_worker::run_direct_path;
use super::monitors::{spawn_session_summary, spawn_uplink_monitor};
use super::relay_worker::run_path;
use super::state::{
    ActiveWireGuardSession, DataReceiver, RelayIngress, SessionOverlay, SkippedRoute,
    initial_status,
};
use super::worker::{INBOUND_QUEUE_DEPTH, PATH_QUEUE_DEPTH, PathTelemetry};
use super::{WireGuardSessionManager, unix_time_millis};
use crate::ipc::SessionRequest;
use crate::netutil::{link_mtu_for_endpoints, resolve_ipv4, warn_if_below_link_budget};
use gamepath_engine::auth::{EnrollmentToken, SessionCrypto};
use gamepath_engine::mtu::EffectiveMtu;
use gamepath_engine::relay_path::{NodeSpec, RelayPath, SessionMode};
use gamepath_engine::replay::ReplayWindow;
use gamepath_engine::scheduler::{PathMetrics, Strategy};
use gamepath_engine::timer::HighResolutionTimer;
use gamepath_engine::uplink::UplinkMonitor;
use gamepath_engine::{log_info, log_warn};
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

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
        let mut paths: Vec<(usize, String, NodeSpec, Box<dyn RelayPath>)> = Vec::new();
        let mut skipped_routes = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let route = index + 1;
            // A SOCKS5 node dials its proxy here and an OpenVPN node completes
            // a handshake, so this is where a dead provider shows up. One node
            // failing costs its own route: the session runs on the rest, and
            // the worker set does not include a path that was never opened.
            let path = match node.open(relay) {
                Ok(path) => path,
                Err(error) => {
                    skipped_routes.push(SkippedRoute {
                        route,
                        label: node.describe(),
                        reason: error,
                    });
                    continue;
                }
            };
            if paths
                .iter()
                .any(|(_, _, _, current)| current.identity() == path.identity())
            {
                skipped_routes.push(SkippedRoute {
                    route,
                    label: node.describe(),
                    reason: "another enabled route already uses this endpoint and key".into(),
                });
                continue;
            }
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
            paths.push((route, label, node.clone(), path));
        }
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
        if paths.is_empty() {
            return Err(format!(
                "no route could be opened: {}",
                skipped_routes
                    .iter()
                    .map(|skipped| format!(
                        "route {} ({}): {}",
                        skipped.route, skipped.label, skipped.reason
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        // One capture adapter serves every selected path. Its MTU must fit the
        // smallest actual outer route and the strictest provider tunnel cap.
        let link_mtu = link_mtu_for_endpoints(
            paths
                .iter()
                .filter_map(|(_, _, _, path)| path.bypass_ipv4()),
        );
        let provider_mtu = paths
            .iter()
            .filter_map(|(_, _, node, _)| node.configured_tunnel_mtu())
            .min();
        let effective_mtu = EffectiveMtu::for_session(
            SessionMode::Relay,
            paths.iter().map(|(_, _, _, path)| path.kind()),
            link_mtu,
        )
        .with_tunnel_limit(provider_mtu);
        let route_summary = paths
            .iter()
            .map(|(route, label, _, path)| format!("{route}:{label}/{}", path.kind()))
            .collect::<Vec<_>>()
            .join(", ");
        let mut bypass_ips = vec![relay_ip];
        bypass_ips.extend(
            paths
                .iter()
                .filter_map(|(_, _, _, path)| path.bypass_ipv4()),
        );
        bypass_ips.sort_unstable();
        bypass_ips.dedup();

        self.stop();
        let timer = HighResolutionTimer::raise();
        let session_id = rand::random::<u64>();
        let crypto = Arc::new(SessionCrypto::new(&key, session_id)?);
        let stop = Arc::new(AtomicBool::new(false));
        let sequences = Arc::new(AtomicU64::new(1));
        let initial_statuses = paths
            .iter()
            .map(|(route, label, _, path)| {
                initial_status(*route, path.kind(), label.clone(), path.endpoint())
            })
            .collect::<Vec<_>>();
        let statuses = Arc::new(Mutex::new(initial_statuses));
        let route_count = paths.len();
        let scheduler_metrics = Arc::new(Mutex::new(
            (0..route_count)
                .map(|index| PathMetrics::new(index.to_string()))
                .collect::<Vec<_>>(),
        ));
        let initial_mask = if route_count >= 64 {
            u64::MAX
        } else {
            (1_u64 << route_count) - 1
        };
        let decision_mask = Arc::new(AtomicU64::new(initial_mask));
        let counters = || {
            Arc::new(
                (0..route_count)
                    .map(|_| AtomicU64::new(0))
                    .collect::<Vec<_>>(),
            )
        };
        let telemetry = PathTelemetry {
            iterations: counters(),
            queue_depth: counters(),
            queue_peak: counters(),
            dropped: counters(),
            queue_full_dropped: counters(),
            stale_dropped: counters(),
            inbound_dropped: counters(),
            worker_gap_peak_ms: counters(),
            healthy_mask: Arc::new(AtomicU64::new(0)),
            uplink: Arc::new(UplinkMonitor::new()),
        };
        let mut workers = Vec::with_capacity(route_count);
        let mut commands = Vec::with_capacity(route_count);
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let ingress = Arc::new(RelayIngress {
            client_id,
            session_id,
            server_replay: Mutex::new(ReplayWindow::default()),
        });
        for (index, (_, _, node, path)) in paths.into_iter().enumerate() {
            let status_index = index;
            let (command_tx, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
            commands.push(command_tx);
            let worker_stop = Arc::clone(&stop);
            let worker_statuses = Arc::clone(&statuses);
            let worker_sequences = Arc::clone(&sequences);
            let worker_inbound = inbound_tx.clone();
            let worker_ingress = Arc::clone(&ingress);
            let worker_metrics = Arc::clone(&scheduler_metrics);
            let worker_decision = Arc::clone(&decision_mask);
            let worker_telemetry = telemetry.clone();
            let worker_dialer = PathDialer {
                node,
                relay,
                cheap_reopen: Arc::new(AtomicBool::new(true)),
            };
            let worker_kind = path.kind();
            workers.push(
                thread::Builder::new()
                    .name(format!("gamepath-{worker_kind}-{}", index + 1))
                    .spawn(move || {
                        run_path(
                            path,
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
                            worker_metrics,
                            worker_decision,
                            initial_mask,
                            strategy,
                            worker_telemetry,
                            worker_dialer,
                            route_count,
                        )
                    })
                    .map_err(|error| format!("could not start path worker: {error}"))?,
            );
        }
        let data_receiver = Arc::new(DataReceiver {
            inbound: Mutex::new(inbound_rx),
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
             uplink mtu {link_mtu}, tunnel mtu {} overhead {}, {} skipped",
            effective_mtu.mtu,
            effective_mtu.overhead,
            skipped_routes.len()
        );
        warn_if_below_link_budget(effective_mtu, link_mtu);
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Relay,
            strategy,
            overlay: SessionOverlay::Relay { client_id, crypto },
            session_id,
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers,
            skipped_routes,
            commands,
            data_receiver,
            virtual_ipv4: enrollment.virtual_ipv4,
            sequences,
            decision_mask,
            telemetry,
            scheduler_metrics,
            effective_mtu,
            bypass_ips,
            timer,
        });
        Ok(())
    }

    /// Brings up a direct session: no relay, and one tunnelling node doing the
    /// routing that a relay would otherwise do.
    pub(super) fn start_direct(&mut self, nodes: &[NodeSpec]) -> Result<(), String> {
        // Duplication is the only reason to run several paths, and duplication
        // needs a relay to recognise the copies. Say so rather than silently
        // using the first node and leaving the rest looking active.
        let [node] = nodes else {
            return Err(format!(
                "direct mode sends traffic through exactly one node, but {} are enabled. \
                 Enable a single WireGuard, OpenVPN or L2TP/IPsec node, or switch to relay mode to combine them.",
                nodes.len()
            ));
        };
        let path = node
            .open_direct()
            .map_err(|error| format!("{}: {error}", node.describe()))?;
        let virtual_ipv4 = path.address();
        let bypass_ips = path.bypass_ipv4().into_iter().collect::<Vec<_>>();
        let label = node.label().unwrap_or_else(|| node.default_label(1));
        let endpoint = path.endpoint().to_string();

        self.stop();
        let timer = HighResolutionTimer::raise();
        let stop = Arc::new(AtomicBool::new(false));
        let kind = path.kind();
        let label_for_log = label.clone();
        let link_mtu = link_mtu_for_endpoints(path.bypass_ipv4());
        let effective_mtu = EffectiveMtu::for_session(SessionMode::Direct, [kind], link_mtu)
            .with_tunnel_limit(node.configured_tunnel_mtu());
        let statuses = Arc::new(Mutex::new(vec![initial_status(1, kind, label, endpoint)]));
        let scheduler_metrics = Arc::new(Mutex::new(vec![PathMetrics::new("0".to_owned())]));
        let (command_tx, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let (inbound_tx, inbound_rx) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let telemetry = PathTelemetry {
            iterations: Arc::new(vec![AtomicU64::new(0)]),
            queue_depth: Arc::new(vec![AtomicU64::new(0)]),
            queue_peak: Arc::new(vec![AtomicU64::new(0)]),
            dropped: Arc::new(vec![AtomicU64::new(0)]),
            queue_full_dropped: Arc::new(vec![AtomicU64::new(0)]),
            stale_dropped: Arc::new(vec![AtomicU64::new(0)]),
            inbound_dropped: Arc::new(vec![AtomicU64::new(0)]),
            worker_gap_peak_ms: Arc::new(vec![AtomicU64::new(0)]),
            healthy_mask: Arc::new(AtomicU64::new(0)),
            uplink: Arc::new(UplinkMonitor::new()),
        };
        let worker_telemetry = telemetry.clone();
        let worker_stop = Arc::clone(&stop);
        let worker_statuses = Arc::clone(&statuses);
        let worker_metrics = Arc::clone(&scheduler_metrics);
        let session_id = rand::random::<u64>();
        let worker = thread::Builder::new()
            .name("gamepath-direct-1".into())
            .spawn(move || {
                run_direct_path(
                    path,
                    virtual_ipv4,
                    worker_stop,
                    worker_statuses,
                    command_rx,
                    inbound_tx,
                    worker_metrics,
                    worker_telemetry,
                    session_id,
                )
            })
            .map_err(|error| format!("could not start path worker: {error}"))?;
        let mut workers = vec![worker];
        warn_if_below_link_budget(effective_mtu, link_mtu);
        workers.extend(spawn_uplink_monitor(&stop, &telemetry));
        workers.extend(spawn_session_summary(
            session_id,
            &stop,
            &statuses,
            &telemetry,
            &Arc::new(AtomicU64::new(1)),
            &scheduler_metrics,
        ));
        log_info!(
            "direct session up: {label_for_log} ({kind}), uplink mtu {link_mtu}, tunnel mtu {} overhead {}",
            effective_mtu.mtu,
            effective_mtu.overhead
        );
        self.active = Some(ActiveWireGuardSession {
            mode: SessionMode::Direct,
            strategy: Strategy::FastestPath,
            overlay: SessionOverlay::Direct,
            session_id,
            started_at: unix_time_millis(),
            stop,
            paths: statuses,
            workers,
            skipped_routes: Vec::new(),
            commands: vec![command_tx],
            data_receiver: Arc::new(DataReceiver {
                inbound: Mutex::new(inbound_rx),
            }),
            virtual_ipv4,
            sequences: Arc::new(AtomicU64::new(1)),
            // One path, always selected: there is nothing to schedule between.
            decision_mask: Arc::new(AtomicU64::new(1)),
            telemetry,
            scheduler_metrics,
            effective_mtu,
            bypass_ips,
            timer,
        });
        Ok(())
    }
}
