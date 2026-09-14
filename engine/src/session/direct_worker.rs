//! The single thread a direct session runs: no relay to exchange control
//! frames with, so the node's own handshake decides whether it is up and an
//! ICMP echo through the tunnel is telemetry on top of that.

use super::health::{PROBE_INTERVAL, publish_path_health, record_path_receive, record_path_send};
use super::latency::{LatencyEvent, LatencyWatch};
use super::state::PathSessionStatus;
use super::worker::{
    PathCommand, PathTelemetry, WORKER_GAP_LOG_INTERVAL, WORKER_GAP_WARN, WORKER_RECEIVE_TIMEOUT,
    drain_send_queue,
};
use crate::icmp::{icmp_echo_packet, is_matching_icmp_reply};
use gamepath_engine::relay_path::{DirectPath, KIND_WIREGUARD};
use gamepath_engine::rtt::RttEstimator;
use gamepath_engine::scheduler::PathMetrics;
use gamepath_engine::{log_info, log_warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// How many unanswered probes it takes to conclude the node filters ICMP.
const DIRECT_PROBE_ATTEMPTS: u64 = 3;

/// How many probes a node that *had* been answering may miss in a row before
/// it is reported as down. There is no second path to fail over to here, so
/// this only decides when the user is told, and a twitchier number would
/// report a hiccup as an outage.
const DIRECT_LOSS_LIMIT: u64 = 3;

/// How recently the node must have sent something authenticated for the path to
/// count as carrying traffic regardless of what the ICMP probes say.
const DIRECT_LIVENESS_WINDOW: Duration = Duration::from_secs(5);

/// Probe interval once a node has shown it will not answer ICMP. Slow enough
/// to be free, frequent enough that a node which starts answering is noticed.
const DIRECT_QUIET_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Where a direct session's latency probe is aimed. A public resolver that
/// answers echo requests, reached through the node like any game server.
const DIRECT_PROBE_TARGET: std::net::Ipv4Addr = gamepath_engine::BENCHMARK_TARGET;

/// Carries a direct session's traffic through its single node.
///
/// There is no relay here to exchange control frames with, so health and
/// latency come from two different places. The WireGuard handshake decides
/// whether the node is up: it either answered or it did not, and nothing about
/// the user's traffic can make that ambiguous. An ICMP echo through the tunnel
/// then measures the whole trip out to the Internet — but only as telemetry.
/// Plenty of providers filter ICMP while routing everything else perfectly, so
/// after a few unanswered probes this stops asking and stops counting them as
/// loss, rather than reporting a healthy node as totally lossy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_direct_path(
    mut path: DirectPath,
    address: std::net::Ipv4Addr,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
    inbound: mpsc::SyncSender<Vec<u8>>,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    telemetry: PathTelemetry,
    session_id: u64,
) {
    let identifier = rand::random::<u16>();
    let mut probe_sequence = 0_u16;
    let mut next_probe = Instant::now();
    let mut pending_probe: Option<Instant> = None;
    // The probe deadline follows this node's own round trip, so a provider that
    // is simply distant is not mistaken for one that is losing packets.
    let mut rtt = RttEstimator::default();
    let mut latency_watch = LatencyWatch::default();
    let mut last_iteration = Instant::now();
    let mut last_worker_gap_log: Option<Instant> = None;
    let mut probes_attempted = 0_u64;
    let mut consecutive_losses = 0_u64;
    let mut icmp_answered = false;
    let mut published_health = (None, false);
    let mut published_error = false;
    // Set once this worker has a specific answer for why the node is not
    // usable. Transport errors are noisier and less useful than that answer,
    // so they stop overwriting it.
    let mut verdict = false;
    let started = Instant::now();
    let mut reported_silence = false;
    // Any packet the node sends back has already passed WireGuard's or
    // OpenVPN's authentication, so it proves the tunnel is alive whether or not
    // ICMP is carried. Handshake age alone does not: a node can complete one
    // and then stop forwarding.
    let mut last_authenticated_receive: Option<Instant> = None;
    let mut published_healthy = false;
    let endpoint = path.endpoint();

    while !stop.load(Ordering::Acquire) {
        let iteration_started = Instant::now();
        let worker_gap = iteration_started.saturating_duration_since(last_iteration);
        last_iteration = iteration_started;
        let worker_gap_ms = worker_gap.as_millis().min(u128::from(u64::MAX)) as u64;
        telemetry.worker_gap_peak_ms[0].fetch_max(worker_gap_ms, Ordering::Relaxed);
        if worker_gap >= WORKER_GAP_WARN
            && last_worker_gap_log.is_none_or(|logged| logged.elapsed() >= WORKER_GAP_LOG_INTERVAL)
        {
            last_worker_gap_log = Some(iteration_started);
            log_warn!(
                "session {session_id} route 1 worker gap {worker_gap_ms} ms; q={} drop={} uplink={:?}",
                telemetry.queue_depth[0].load(Ordering::Relaxed),
                telemetry.dropped[0].load(Ordering::Relaxed),
                telemetry.uplink.state()
            );
        }
        telemetry.iterations[0].fetch_add(1, Ordering::Relaxed);
        // Health is decided first so the rest of the iteration can see it, and
        // published only when it moves: this lock is on the hot path.
        let handshake = path.handshake_latency_ms();
        // Authenticated return traffic outranks the probe verdict: a node that
        // is demonstrably carrying packets is not down because ICMP to
        // 1.1.1.1 is being filtered somewhere past it.
        let carrying =
            last_authenticated_receive.is_some_and(|seen| seen.elapsed() <= DIRECT_LIVENESS_WINDOW);
        let losing = icmp_answered && consecutive_losses >= DIRECT_LOSS_LIMIT && !carrying;
        let reachable = handshake.is_some() && !losing;
        if reachable != published_healthy {
            publish_path_health(&telemetry.healthy_mask, 0, reachable);
            published_healthy = reachable;
        }
        if (handshake, reachable) != published_health {
            let mut current = statuses.lock().unwrap();
            current[0].reachable = reachable;
            current[0].handshake_ms = handshake;
            // WireGuard's handshake is one round trip, so it doubles as a hop
            // estimate. OpenVPN's spans a TLS negotiation whose round-trip
            // count depends on the server, so none is offered.
            current[0].handshake_round_trips = (path.kind() == KIND_WIREGUARD).then_some(1);
            if let Some(latency) = handshake {
                // Stand in for the end-to-end number until a probe answers, so
                // a node that filters ICMP still reports a real measurement.
                current[0].latency_ms.get_or_insert(latency);
            }
            current[0].last_error = losing
                .then(|| format!("{endpoint} stopped answering probes sent through the tunnel"));
            published_error = losing;
            verdict = losing;
            published_health = (handshake, reachable);
        }
        drain_send_queue(
            &commands,
            0,
            &telemetry.queue_depth,
            &telemetry.dropped,
            &telemetry.stale_dropped,
            |frame| (frame.len(), path.send_packet(frame)),
            |length, result| record_path_send(&statuses, 0, length, result),
        );
        if pending_probe.is_none() && Instant::now() >= next_probe {
            probe_sequence = probe_sequence.wrapping_add(1);
            let probe = icmp_echo_packet(
                address,
                DIRECT_PROBE_TARGET,
                identifier,
                probe_sequence,
                false,
            );
            match path.send_packet(&probe) {
                Ok(()) => {
                    probes_attempted += 1;
                    // Until one probe is answered nothing is published, so a
                    // node that filters ICMP never reports probes it did send
                    // and never looks totally lossy because of it.
                    if icmp_answered {
                        statuses.lock().unwrap()[0].probes_sent += 1;
                    }
                    pending_probe = Some(Instant::now());
                }
                // The handshake, not this probe, decides whether the node is
                // up, so a failed send is recorded and the loop carries on.
                Err(error) => {
                    if !verdict {
                        statuses.lock().unwrap()[0].last_error = Some(error);
                        published_error = true;
                    }
                }
            }
            next_probe = Instant::now() + PROBE_INTERVAL;
        }
        match path.receive_packets(WORKER_RECEIVE_TIMEOUT) {
            Ok(packets) => {
                for packet in packets {
                    if is_matching_icmp_reply(&packet, DIRECT_PROBE_TARGET, address, identifier) {
                        let Some(started) = pending_probe.take() else {
                            continue;
                        };
                        let elapsed = started.elapsed();
                        rtt.record(elapsed);
                        let latency = elapsed.as_secs_f64() * 1000.0;
                        let first = !icmp_answered;
                        icmp_answered = true;
                        consecutive_losses = 0;
                        {
                            let mut current = statuses.lock().unwrap();
                            // The probe this answers was sent before ICMP was
                            // known to work, so it was not counted then.
                            current[0].probes_sent += u64::from(first);
                            current[0].probes_received += 1;
                            current[0].latency_ms = Some(latency);
                        }
                        scheduler_metrics.lock().unwrap()[0].record_probe(latency);
                        match latency_watch.observe(latency, Instant::now()) {
                            Some(LatencyEvent::Degraded {
                                baseline_ms,
                                observed_ms,
                            }) => log_warn!(
                                "session {session_id} route 1 data-plane RTT degraded: \
                                 {observed_ms:.0} ms vs {baseline_ms:.0} ms baseline; \
                                 q={} drop={} uplink={:?}",
                                telemetry.queue_depth[0].load(Ordering::Relaxed),
                                telemetry.dropped[0].load(Ordering::Relaxed),
                                telemetry.uplink.state()
                            ),
                            Some(LatencyEvent::Recovered {
                                baseline_ms,
                                peak_ms,
                                duration,
                            }) => log_info!(
                                "session {session_id} route 1 data-plane RTT recovered after \
                                 {:.1} s (baseline {baseline_ms:.0} ms, peak {peak_ms:.0} ms)",
                                duration.as_secs_f64()
                            ),
                            None => {}
                        }
                        last_authenticated_receive = Some(Instant::now());
                        continue;
                    }
                    record_path_receive(&statuses, 0, packet.len());
                    last_authenticated_receive = Some(Instant::now());
                    // Blocking here would stall the probe and timer work that
                    // decides whether this path is still usable.
                    if let Err(mpsc::TrySendError::Full(_)) = inbound.try_send(packet) {
                        telemetry.dropped[0].fetch_add(1, Ordering::Relaxed);
                        telemetry.inbound_dropped[0].fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Windows reports an unreachable endpoint on the next read of a
                // connected UDP socket, so a restarting node leaves an error
                // behind that its next reply disproves. Clearing it costs a
                // lock, so it is taken only when the state actually changes.
                if published_error && reachable {
                    statuses.lock().unwrap()[0].last_error = None;
                    published_error = false;
                }
            }
            Err(error) => {
                if !verdict {
                    statuses.lock().unwrap()[0].last_error = Some(error);
                    published_error = true;
                }
            }
        }
        // A silent peer is the usual way a direct session fails to start, and
        // the timeout alone would not say which part of the file to look at.
        if !reported_silence
            && path.kind() == KIND_WIREGUARD
            && path.handshake_latency_ms().is_none()
            && started.elapsed() > Duration::from_secs(3)
        {
            reported_silence = true;
            published_error = true;
            verdict = true;
            statuses.lock().unwrap()[0].last_error = Some(format!(
                "no WireGuard handshake reply from {endpoint}; check the configuration's Endpoint, \
                 PrivateKey and Peer PublicKey"
            ));
        }
        if pending_probe.is_some_and(|started| started.elapsed() > rtt.timeout()) {
            pending_probe = None;
            if icmp_answered {
                consecutive_losses += 1;
                statuses.lock().unwrap()[0].probes_lost += 1;
                scheduler_metrics.lock().unwrap()[0].record_loss();
            } else if probes_attempted >= DIRECT_PROBE_ATTEMPTS {
                // Never answered once: this node does not carry ICMP, which
                // says nothing about the traffic it does carry. Back off to a
                // slow retry rather than stopping for the session, so a node
                // that starts answering later is measured again.
                next_probe = Instant::now() + DIRECT_QUIET_PROBE_INTERVAL;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::state::initial_status;
    use super::super::worker::{INBOUND_QUEUE_DEPTH, PATH_QUEUE_DEPTH};
    use super::*;
    use base64::Engine as _;
    use gamepath_engine::relay_path::NodeSpec;
    use gamepath_engine::uplink::UplinkMonitor;
    use std::net::UdpSocket;
    use std::sync::atomic::AtomicU64;
    use std::thread;

    /// A WireGuard peer that answers ICMP echoes through the tunnel, and stops
    /// answering anything once `alive` is cleared — a node going down.
    fn spawn_echoing_peer(
        server_secret: [u8; 32],
        client_public: [u8; 32],
        alive: Arc<AtomicBool>,
    ) -> u16 {
        use boringtun::noise::{Tunn, TunnResult};
        use boringtun::x25519::{PublicKey, StaticSecret};

        let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        thread::spawn(move || {
            let mut tunnel = Tunn::new(
                StaticSecret::from(server_secret),
                PublicKey::from(client_public),
                None,
                None,
                1,
                None,
            );
            let mut network = [0_u8; 65_535];
            let mut scratch = vec![0_u8; 65_535];
            while alive.load(Ordering::Acquire) {
                let Ok((length, from)) = socket.recv_from(&mut network) else {
                    continue;
                };
                let mut input: &[u8] = &network[..length];
                loop {
                    match tunnel.decapsulate(None, input, &mut scratch) {
                        TunnResult::WriteToNetwork(packet) => {
                            let _ = socket.send_to(packet, from);
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            let request = packet.to_vec();
                            let (source, destination) =
                                (request[12..16].to_vec(), request[16..20].to_vec());
                            let identifier = u16::from_be_bytes([request[24], request[25]]);
                            let sequence = u16::from_be_bytes([request[26], request[27]]);
                            let echo = icmp_echo_packet(
                                std::net::Ipv4Addr::new(
                                    destination[0],
                                    destination[1],
                                    destination[2],
                                    destination[3],
                                ),
                                std::net::Ipv4Addr::new(source[0], source[1], source[2], source[3]),
                                identifier,
                                sequence,
                                true,
                            );
                            let mut out = vec![0_u8; echo.len() + 128];
                            if let TunnResult::WriteToNetwork(sealed) =
                                tunnel.encapsulate(&echo, &mut out)
                            {
                                let _ = socket.send_to(sealed, from);
                            }
                            break;
                        }
                        _ => break,
                    }
                    input = &[];
                }
            }
        });
        port
    }

    fn wait_for(
        statuses: &Arc<Mutex<Vec<PathSessionStatus>>>,
        limit: Duration,
        ready: impl Fn(&PathSessionStatus) -> bool,
    ) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if ready(&statuses.lock().unwrap()[0]) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn a_direct_node_that_stops_answering_stops_reporting_itself_healthy() {
        use base64::engine::general_purpose::STANDARD;
        use boringtun::x25519::{PublicKey, StaticSecret};

        let (client_secret, server_secret) = ([11_u8; 32], [13_u8; 32]);
        let client_public = *PublicKey::from(&StaticSecret::from(client_secret)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_secret)).as_bytes();
        let alive = Arc::new(AtomicBool::new(true));
        let port = spawn_echoing_peer(server_secret, client_public, Arc::clone(&alive));
        let address = std::net::Ipv4Addr::new(10, 66, 66, 2);
        let config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {address}/32\n[Peer]\nPublicKey = {}\nEndpoint = 127.0.0.1:{port}\nAllowedIPs = 0.0.0.0/0",
            STANDARD.encode(client_secret),
            STANDARD.encode(server_public),
        );
        let path = NodeSpec::WireGuard {
            config,
            label: None,
        }
        .open_direct()
        .unwrap();

        let statuses = Arc::new(Mutex::new(vec![initial_status(
            1,
            KIND_WIREGUARD,
            "Provider A".into(),
            format!("127.0.0.1:{port}"),
        )]));
        let stop = Arc::new(AtomicBool::new(false));
        let (_commands, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let (inbound_tx, _inbound) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
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
        let worker = thread::spawn({
            let (stop, statuses) = (Arc::clone(&stop), Arc::clone(&statuses));
            move || {
                run_direct_path(
                    path,
                    address,
                    stop,
                    statuses,
                    command_rx,
                    inbound_tx,
                    Arc::new(Mutex::new(vec![PathMetrics::new("0".to_owned())])),
                    telemetry,
                    1,
                )
            }
        });

        assert!(
            wait_for(&statuses, Duration::from_secs(10), |status| {
                status.reachable && status.probes_received > 0
            }),
            "the node never came up: {:?}",
            statuses.lock().unwrap()[0].last_error
        );
        {
            let current = statuses.lock().unwrap();
            // Every answered probe is counted against one that was sent.
            assert!(current[0].probes_sent >= current[0].probes_received);
            assert!(current[0].handshake_ms.is_some());
            assert!(current[0].latency_ms.is_some());
            assert!(current[0].last_error.is_none());
        }

        // The node goes away. A completed handshake is not evidence that it is
        // still there, so the path has to notice and say so.
        alive.store(false, Ordering::Release);
        assert!(
            wait_for(&statuses, Duration::from_secs(20), |status| !status
                .reachable),
            "a node that stopped answering still reported itself healthy"
        );
        assert!(
            statuses.lock().unwrap()[0]
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("stopped answering")),
            "{:?}",
            statuses.lock().unwrap()[0].last_error
        );

        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }
}
