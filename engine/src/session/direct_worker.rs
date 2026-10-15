//! A direct session's worker, one per node: setup proves initial
//! availability, while tunnelled ICMP echoes and authenticated replies provide
//! live health.

use super::dialer::{RECONNECT_BACKOFF_MIN, next_backoff};
use super::health::{PROBE_INTERVAL, publish_path_health, record_path_receive, record_path_send};
use super::latency::{LatencyEvent, LatencyWatch};
use super::local_tap::{InboundQueue, InboundSink};
use super::nodes::SessionNodes;
use super::state::PathSessionStatus;
use super::worker::{
    PassProfile, PathCommand, PathTelemetry, WORKER_GAP_LOG_INTERVAL, WORKER_GAP_WARN,
    WORKER_RECEIVE_TIMEOUT, drain_send_queue,
};
use crate::icmp::{icmp_echo_packet, icmp_reply_sequence};
use gamepath_engine::relay_path::{DirectPath, KIND_SOCKS5, KIND_WIREGUARD, NodeSpec};
use gamepath_engine::rtt::RttEstimator;
use gamepath_engine::scheduler::PathMetrics;
use gamepath_engine::uplink::UplinkState;
use gamepath_engine::{log_info, log_warn};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
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

/// Each SOCKS5 probe opens a connection and asks DNS through it. Keep that
/// extra work out of the packet path and modest on the user's proxy server.
const SOCKS5_PROBE_INTERVAL: Duration = Duration::from_secs(5);
// DNS can need its own upstream dial and retry; the datagram RTT deadline
// would call a working but slow resolver dead on a restricted connection.
const SOCKS5_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Probe interval once a node has shown it will not answer ICMP. Slow enough
/// to be free, frequent enough that a node which starts answering is noticed.
const DIRECT_QUIET_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Where a direct session's latency probe is aimed. A public resolver that
/// answers echo requests, reached through the node like any game server.
const DIRECT_PROBE_TARGET: std::net::Ipv4Addr = gamepath_engine::BENCHMARK_TARGET;

fn take_matching_probe(pending: &mut Option<(u16, Instant)>, sequence: u16) -> Option<Instant> {
    if pending.is_some_and(|(expected, _)| expected == sequence) {
        pending.take().map(|(_, started)| started)
    } else {
        None
    }
}

fn probe_outage(requires_probe: bool, answered: bool, losses: u64, carrying: bool) -> bool {
    (requires_probe || answered) && losses >= DIRECT_LOSS_LIMIT && (requires_probe || !carrying)
}

/// Which node of the session a worker carries, and what it needs to dial that
/// node again.
pub(crate) struct DirectRoute {
    pub(crate) index: usize,
    pub(crate) node: NodeSpec,
    pub(crate) nodes: Arc<SessionNodes>,
}

/// The health of one open transport. A redial starts it again from nothing,
/// because nothing the old transport proved says anything about the new one.
struct PathWatch {
    address: Ipv4Addr,
    endpoint: SocketAddr,
    max_age: Option<Duration>,
    requires_probe: bool,
    probe_interval: Duration,
    probe_sequence: u16,
    next_probe: Instant,
    pending_probe: Option<(u16, Instant)>,
    rtt: RttEstimator,
    latency_watch: LatencyWatch,
    probes_attempted: u64,
    consecutive_losses: u64,
    icmp_answered: bool,
    published_health: (Option<f64>, bool),
    published_error: bool,
    /// Set once this worker has a specific answer for why the node is not
    /// usable. Transport errors are noisier and less useful than that answer,
    /// so they stop overwriting it.
    verdict: bool,
    started: Instant,
    reported_silence: bool,
    /// Any packet the node sends back has already passed WireGuard's or
    /// OpenVPN's authentication, so it proves the tunnel is alive whether or
    /// not ICMP is carried. Handshake age alone does not: a node can complete
    /// one and then stop forwarding.
    last_authenticated_receive: Option<Instant>,
    published_healthy: bool,
}

impl PathWatch {
    fn new(path: &DirectPath) -> Self {
        // A SOCKS5 node is a TCP stack in this process, not a network; see
        // `drain_send_queue`.
        let requires_probe = path.kind() == KIND_SOCKS5;
        Self {
            address: path.address(),
            endpoint: path.endpoint(),
            max_age: (!requires_probe).then_some(super::worker::PATH_QUEUE_MAX_AGE),
            requires_probe,
            probe_interval: if requires_probe {
                SOCKS5_PROBE_INTERVAL
            } else {
                PROBE_INTERVAL
            },
            probe_sequence: 0,
            next_probe: Instant::now(),
            pending_probe: None,
            // The probe deadline follows this node's own round trip, so a
            // provider that is simply distant is not mistaken for one that is
            // losing packets.
            rtt: RttEstimator::with_floor(path.probe_deadline_floor()),
            latency_watch: LatencyWatch::default(),
            probes_attempted: 0,
            consecutive_losses: 0,
            icmp_answered: false,
            published_health: (None, false),
            published_error: false,
            verdict: false,
            started: Instant::now(),
            reported_silence: false,
            last_authenticated_receive: None,
            published_healthy: false,
        }
    }
}

/// Opens `node` on a thread of its own, so the worker keeps draining and
/// probing while an OpenVPN handshake takes its seconds.
fn begin_dial(node: &NodeSpec, route: usize) -> Option<mpsc::Receiver<Result<DirectPath, String>>> {
    let (result, receiver) = mpsc::channel();
    let node = node.clone();
    thread::Builder::new()
        .name(format!("gamepath-direct-dial-{route}"))
        .spawn(move || {
            // Nobody is listening once the session has stopped; the path is
            // then simply closed again.
            let _ = result.send(node.open_direct());
        })
        .map_err(|error| log_warn!("could not start dialling route {route}: {error}"))
        .ok()?;
    Some(receiver)
}

/// Carries a direct session's traffic through one of its nodes.
///
/// There is no relay here to exchange control frames with, so health and
/// latency come from two different places. The handshake proves the node
/// answered at setup. An ICMP echo through the tunnel measures the whole trip
/// out to the Internet and, once answered, provides a live health signal.
/// Plenty of providers filter ICMP while routing everything else perfectly, so
/// after a few unanswered probes this backs off and stops counting them as
/// loss, rather than reporting a healthy node as totally lossy.
///
/// `path` is `None` when the node did not open with the session. The worker
/// then keeps dialling it, and the flows pinned to it start moving the moment
/// it opens, without the session or the other nodes noticing. An OpenVPN node
/// that stops answering is dialled again the same way: unlike WireGuard it has
/// no handshake timer of its own to bring a dead link back.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_direct_path(
    mut path: Option<DirectPath>,
    route: DirectRoute,
    stop: Arc<AtomicBool>,
    statuses: Arc<Mutex<Vec<PathSessionStatus>>>,
    commands: mpsc::Receiver<PathCommand>,
    inbound: InboundSink,
    scheduler_metrics: Arc<Mutex<Vec<PathMetrics>>>,
    telemetry: PathTelemetry,
    session_id: u64,
) {
    let index = route.index;
    let number = index + 1;
    let identifier = rand::random::<u16>();
    let mut watch = path.as_ref().map(PathWatch::new);
    let mut dial: Option<mpsc::Receiver<Result<DirectPath, String>>> = None;
    // A node that failed to open has just been tried, so its first retry
    // waits; a node that fails later is redialled at once.
    let mut backoff = if path.is_some() {
        RECONNECT_BACKOFF_MIN
    } else {
        next_backoff(RECONNECT_BACKOFF_MIN)
    };
    let mut next_redial = path.is_none().then(|| Instant::now() + backoff);
    let mut last_iteration = Instant::now();
    let mut last_worker_gap_log: Option<Instant> = None;
    let mut pass = PassProfile::default();

    while !stop.load(Ordering::Acquire) {
        if let Some(receiver) = &dial {
            let result = match receiver.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("the dial stopped without a result".to_owned()))
                }
            };
            match result {
                Some(Ok(opened)) => {
                    dial = None;
                    let fresh = PathWatch::new(&opened);
                    route.nodes.set_address(index, fresh.address);
                    publish_path_health(&telemetry.healthy_mask, index, false);
                    {
                        let mut current = statuses.lock().unwrap();
                        current[index].endpoint = fresh.endpoint.to_string();
                        current[index].joining = false;
                        current[index].reachable = false;
                        current[index].last_error = None;
                    }
                    log_info!(
                        "session {session_id} route {number} ({}) {} at {}",
                        opened.kind(),
                        if path.is_some() {
                            "redialled"
                        } else {
                            "opened"
                        },
                        fresh.address
                    );
                    watch = Some(fresh);
                    path = Some(opened);
                    backoff = RECONNECT_BACKOFF_MIN;
                }
                Some(Err(error)) => {
                    dial = None;
                    backoff = next_backoff(backoff);
                    next_redial = Some(Instant::now() + backoff);
                    log_warn!(
                        "session {session_id} route {number} could not be dialled: {error}; \
                         retrying in {} s",
                        backoff.as_secs()
                    );
                    statuses.lock().unwrap()[index].last_error = Some(error);
                    if let Some(watch) = watch.as_mut() {
                        watch.published_error = true;
                    }
                }
                None => {}
            }
        }
        // A dial has nowhere to go while the uplink itself is down, and a
        // node that is still carrying is not thrown away for it.
        if dial.is_none()
            && next_redial.is_some_and(|due| Instant::now() >= due)
            && telemetry.uplink.state() != UplinkState::Down
        {
            next_redial = None;
            dial = begin_dial(&route.node, number);
            if dial.is_none() {
                next_redial = Some(Instant::now() + next_backoff(backoff));
            }
        }
        let (Some(path), Some(watch)) = (path.as_mut(), watch.as_mut()) else {
            // Nothing can carry these yet. Holding them would only hand the
            // node stale packets when it opens.
            drain_send_queue(
                &commands,
                None,
                index,
                &telemetry.queue_depth,
                &telemetry.dropped,
                &telemetry.stale_dropped,
                |frame| (frame.len(), Err("the node is not open".to_owned())),
                |_, _| {
                    telemetry.dropped[index].fetch_add(1, Ordering::Relaxed);
                },
            );
            thread::sleep(WORKER_RECEIVE_TIMEOUT);
            continue;
        };
        let address = watch.address;
        let endpoint = watch.endpoint;
        let iteration_started = Instant::now();
        let worker_gap = iteration_started.saturating_duration_since(last_iteration);
        last_iteration = iteration_started;
        let worker_gap_ms = worker_gap.as_millis().min(u128::from(u64::MAX)) as u64;
        telemetry.worker_gap_peak_ms[index].fetch_max(worker_gap_ms, Ordering::Relaxed);
        if worker_gap >= WORKER_GAP_WARN
            && last_worker_gap_log.is_none_or(|logged| logged.elapsed() >= WORKER_GAP_LOG_INTERVAL)
        {
            last_worker_gap_log = Some(iteration_started);
            log_warn!(
                "session {session_id} route {number} worker gap {worker_gap_ms} ms; q={} drop={} uplink={:?}; {pass}",
                telemetry.queue_depth[index].load(Ordering::Relaxed),
                telemetry.dropped[index].load(Ordering::Relaxed),
                telemetry.uplink.state()
            );
        }
        pass = PassProfile::default();
        telemetry.iterations[index].fetch_add(1, Ordering::Relaxed);
        // Health is decided first so the rest of the iteration can see it, and
        // published only when it moves: this lock is on the hot path.
        let handshake = path.handshake_latency_ms();
        // Authenticated return traffic outranks the probe verdict: a node that
        // is demonstrably carrying packets is not down because ICMP to
        // the benchmark target is being filtered somewhere past it.
        let carrying = watch
            .last_authenticated_receive
            .is_some_and(|seen| seen.elapsed() <= DIRECT_LIVENESS_WINDOW);
        // SOCKS5 generates SYN/ACK, resets and SERVFAIL locally; those packets
        // cannot disprove an outage beyond the proxy's listener.
        let losing = probe_outage(
            watch.requires_probe,
            watch.icmp_answered,
            watch.consecutive_losses,
            carrying,
        );
        if losing && path.needs_redial_when_lost() && dial.is_none() && next_redial.is_none() {
            next_redial = Some(Instant::now() + backoff);
        }
        let reachable = handshake.is_some() && !losing;
        if reachable != watch.published_healthy {
            publish_path_health(&telemetry.healthy_mask, index, reachable);
            watch.published_healthy = reachable;
        }
        if (handshake, reachable) != watch.published_health {
            let mut current = statuses.lock().unwrap();
            current[index].reachable = reachable;
            current[index].handshake_ms = handshake;
            // WireGuard's handshake is one round trip, so it doubles as a hop
            // estimate. OpenVPN's spans a TLS negotiation whose round-trip
            // count depends on the server, so none is offered.
            current[index].handshake_round_trips = (path.kind() == KIND_WIREGUARD).then_some(1);
            if let Some(latency) = handshake {
                // Stand in for the end-to-end number until a probe answers, so
                // a node that filters ICMP still reports a real measurement.
                current[index].latency_ms.get_or_insert(latency);
            }
            current[index].last_error = losing
                .then(|| format!("{endpoint} stopped answering probes sent through the tunnel"));
            watch.published_error = losing;
            watch.verdict = losing;
            watch.published_health = (handshake, reachable);
        }
        pass.bookkeeping = iteration_started.elapsed();
        let (mut socket_send, mut status_lock, mut frames_sent) =
            (Duration::ZERO, Duration::ZERO, 0);
        drain_send_queue(
            &commands,
            watch.max_age,
            index,
            &telemetry.queue_depth,
            &telemetry.dropped,
            &telemetry.stale_dropped,
            |frame| {
                let started = Instant::now();
                let result = path.send_packet(frame);
                if let Err(error) = &result {
                    telemetry.dropped[index].fetch_add(1, Ordering::Relaxed);
                    telemetry.send_failed[index].fetch_add(1, Ordering::Relaxed);
                    telemetry.packet_diagnostics.record_error(
                        gamepath_engine::packet_diagnostics::Reason::TransportSend,
                        frame,
                        error,
                    );
                }
                socket_send += started.elapsed();
                frames_sent += 1;
                (frame.len(), result)
            },
            |length, result| {
                let started = Instant::now();
                record_path_send(&statuses, index, length, result);
                status_lock += started.elapsed();
            },
        );
        (pass.socket_send, pass.status_lock, pass.frames_sent) =
            (socket_send, status_lock, frames_sent);
        let probe_started = Instant::now();
        if watch.pending_probe.is_none() && Instant::now() >= watch.next_probe {
            watch.probe_sequence = watch.probe_sequence.wrapping_add(1);
            let probe = icmp_echo_packet(
                address,
                DIRECT_PROBE_TARGET,
                identifier,
                watch.probe_sequence,
                false,
            );
            match path.send_probe(&probe) {
                Ok(()) => {
                    watch.probes_attempted += 1;
                    // Until one probe is answered nothing is published, so a
                    // node that filters ICMP never reports probes it did send
                    // and never looks totally lossy because of it.
                    if watch.icmp_answered || watch.requires_probe {
                        statuses.lock().unwrap()[index].probes_sent += 1;
                    }
                    watch.pending_probe = Some((watch.probe_sequence, Instant::now()));
                }
                // The handshake, not this probe, decides whether the node is
                // up, so a failed send is recorded and the loop carries on.
                Err(error) => {
                    if !watch.verdict {
                        statuses.lock().unwrap()[index].last_error = Some(error);
                        watch.published_error = true;
                    }
                }
            }
            watch.next_probe = Instant::now() + watch.probe_interval;
        }
        pass.probe = probe_started.elapsed();
        let receive_started = Instant::now();
        match path.receive_packets(WORKER_RECEIVE_TIMEOUT) {
            Ok(packets) => {
                for packet in packets {
                    if let Some(sequence) =
                        icmp_reply_sequence(&packet, DIRECT_PROBE_TARGET, address, identifier)
                    {
                        // A late reply must not consume the next probe's timer.
                        let Some(started) = take_matching_probe(&mut watch.pending_probe, sequence)
                        else {
                            continue;
                        };
                        let elapsed = started.elapsed();
                        watch.rtt.record(elapsed);
                        let latency = elapsed.as_secs_f64() * 1000.0;
                        let first = !watch.icmp_answered;
                        watch.icmp_answered = true;
                        watch.consecutive_losses = 0;
                        {
                            let mut current = statuses.lock().unwrap();
                            // The probe this answers was sent before ICMP was
                            // known to work, so it was not counted then.
                            current[index].probes_sent += u64::from(first && !watch.requires_probe);
                            current[index].probes_received += 1;
                            current[index].latency_ms = Some(latency);
                        }
                        scheduler_metrics.lock().unwrap()[index].record_probe(latency);
                        match watch.latency_watch.observe(latency, Instant::now()) {
                            Some(LatencyEvent::Degraded {
                                baseline_ms,
                                observed_ms,
                            }) => log_warn!(
                                "session {session_id} route {number} data-plane RTT degraded: \
                                 {observed_ms:.0} ms vs {baseline_ms:.0} ms baseline; \
                                 q={} drop={} uplink={:?}",
                                telemetry.queue_depth[index].load(Ordering::Relaxed),
                                telemetry.dropped[index].load(Ordering::Relaxed),
                                telemetry.uplink.state()
                            ),
                            Some(LatencyEvent::Recovered {
                                baseline_ms,
                                peak_ms,
                                duration,
                            }) => log_info!(
                                "session {session_id} route {number} data-plane RTT recovered after \
                                 {:.1} s (baseline {baseline_ms:.0} ms, peak {peak_ms:.0} ms)",
                                duration.as_secs_f64()
                            ),
                            None => {}
                        }
                        watch.last_authenticated_receive = Some(Instant::now());
                        continue;
                    }
                    record_path_receive(&statuses, index, packet.len());
                    watch.last_authenticated_receive = Some(Instant::now());
                    // Blocking here would stall the probe and timer work that
                    // decides whether this path is still usable.
                    if let Err(mpsc::TrySendError::Full(_)) = inbound.try_send(packet) {
                        telemetry.dropped[index].fetch_add(1, Ordering::Relaxed);
                        telemetry.inbound_dropped[index].fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Windows reports an unreachable endpoint on the next read of a
                // connected UDP socket, so a restarting node leaves an error
                // behind that its next reply disproves. Clearing it costs a
                // lock, so it is taken only when the state actually changes.
                if watch.published_error && reachable {
                    statuses.lock().unwrap()[index].last_error = None;
                    watch.published_error = false;
                }
            }
            Err(error) => {
                if !watch.verdict {
                    statuses.lock().unwrap()[index].last_error = Some(error);
                    watch.published_error = true;
                }
            }
        }
        telemetry.record_transport_drops(index, path.take_transport_drops());
        pass.receive = receive_started.elapsed();
        // A silent peer is the usual way a direct session fails to start, and
        // the timeout alone would not say which part of the file to look at.
        if !watch.reported_silence
            && path.kind() == KIND_WIREGUARD
            && path.handshake_latency_ms().is_none()
            && watch.started.elapsed() > Duration::from_secs(3)
        {
            watch.reported_silence = true;
            watch.published_error = true;
            watch.verdict = true;
            statuses.lock().unwrap()[index].last_error = Some(format!(
                "no WireGuard handshake reply from {endpoint}; check the configuration's Endpoint, \
                 PrivateKey and Peer PublicKey"
            ));
        }
        let probe_timeout = if watch.requires_probe {
            SOCKS5_PROBE_TIMEOUT
        } else {
            watch.rtt.timeout()
        };
        if watch
            .pending_probe
            .is_some_and(|(_, started)| started.elapsed() > probe_timeout)
        {
            watch.pending_probe = None;
            if watch.icmp_answered || watch.requires_probe {
                watch.consecutive_losses += 1;
                statuses.lock().unwrap()[index].probes_lost += 1;
                scheduler_metrics.lock().unwrap()[index].record_loss();
            } else if watch.probes_attempted >= DIRECT_PROBE_ATTEMPTS {
                // Never answered once: this node does not carry ICMP, which
                // says nothing about the traffic it does carry. Back off to a
                // slow retry rather than stopping for the session, so a node
                // that starts answering later is measured again.
                watch.next_probe = Instant::now() + DIRECT_QUIET_PROBE_INTERVAL;
            }
        }
        pass.total = iteration_started.elapsed();
    }
}

#[cfg(test)]
mod tests {
    use super::super::state::initial_status;
    use super::super::worker::{INBOUND_QUEUE_DEPTH, PATH_QUEUE_DEPTH};
    use super::*;
    use base64::Engine as _;
    use std::net::UdpSocket;
    use std::thread;

    #[test]
    fn a_late_reply_cannot_answer_or_clear_a_newer_probe() {
        let started = Instant::now();
        let mut pending = Some((10, started));
        assert_eq!(take_matching_probe(&mut pending, 9), None);
        assert_eq!(pending, Some((10, started)));
        assert_eq!(take_matching_probe(&mut pending, 10), Some(started));
        assert_eq!(pending, None);
        assert_eq!(take_matching_probe(&mut pending, 10), None);
    }

    #[test]
    fn local_proxy_replies_cannot_hide_failed_dns_probes() {
        assert!(probe_outage(true, true, DIRECT_LOSS_LIMIT, true));
        assert!(probe_outage(true, false, DIRECT_LOSS_LIMIT, true));
        assert!(!probe_outage(true, true, DIRECT_LOSS_LIMIT - 1, true));
        assert!(!probe_outage(true, true, 0, false));
        assert!(!probe_outage(false, true, DIRECT_LOSS_LIMIT, true));
        assert!(!probe_outage(false, false, DIRECT_LOSS_LIMIT, false));
        assert!(probe_outage(false, true, DIRECT_LOSS_LIMIT, false));
    }

    /// A WireGuard peer that answers ICMP echoes through the tunnel, and stops
    /// answering anything once `alive` is cleared â€” a node going down.
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
        let node = NodeSpec::WireGuard {
            config,
            label: None,
        };
        let path = node.open_direct().unwrap();
        let nodes = Arc::new(SessionNodes::new(vec![super::super::nodes::SessionNode {
            address,
            mtu: Arc::new(super::super::path_mtu::SessionMtu::measure(
                gamepath_engine::mtu::EffectiveMtu::for_session(
                    gamepath_engine::relay_path::SessionMode::Direct,
                    [KIND_WIREGUARD],
                    1500,
                ),
                1500,
                [],
                |_| unreachable!(),
            )),
            socks_proxy: None,
        }]));

        let statuses = Arc::new(Mutex::new(vec![initial_status(
            1,
            KIND_WIREGUARD,
            "Provider A".into(),
            format!("127.0.0.1:{port}"),
        )]));
        let stop = Arc::new(AtomicBool::new(false));
        let (_commands, command_rx) = mpsc::sync_channel(PATH_QUEUE_DEPTH);
        let (inbound_tx, _inbound) = mpsc::sync_channel(INBOUND_QUEUE_DEPTH);
        let telemetry = PathTelemetry::new(1);
        let worker = thread::spawn({
            let (stop, statuses) = (Arc::clone(&stop), Arc::clone(&statuses));
            move || {
                run_direct_path(
                    Some(path),
                    DirectRoute {
                        index: 0,
                        node,
                        nodes,
                    },
                    stop,
                    statuses,
                    command_rx,
                    InboundSink::new(inbound_tx, Arc::default()),
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
