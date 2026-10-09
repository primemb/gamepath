//! Routes that join a session already carrying traffic.
//!
//! Every node dials on its own thread, and a relay session starts as soon as
//! one of them is open. A slow OpenVPN handshake - up to thirty seconds per
//! remote, tried over UDP and then TCP - or a Windows RAS negotiation no longer
//! holds back the routes that were ready in milliseconds. The rest come in
//! through here as their dials finish, and are probed into the scheduler like
//! a route that has just reconnected.
//!
//! A dial that fails is tried again before the route is given up for the
//! session. On a filtered uplink a provider refusing one handshake is often
//! back seconds later, and a route lost for the whole match over that is a
//! route the player never gets to use.

use super::state::{PathSessionStatus, SkippedRoute};
use super::worker::{PathCommand, PathTelemetry, drain_send_queue};
use gamepath_engine::l2tp::L2tpRuntime;
use gamepath_engine::relay_path::{NodeSpec, PathIdentity, RelayPath};
use gamepath_engine::{log_info, log_warn};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// How often a joining worker checks for its dial and for a session stop.
const JOIN_POLL: Duration = Duration::from_millis(20);

/// Dials a route gets before it is given up for this session.
pub(crate) const JOIN_ATTEMPTS: u32 = 5;

/// The wait after the first failed dial, doubling after each one after it:
/// 1, 2, 4 and 8 seconds, so all five attempts land inside about fifteen
/// seconds of waiting plus the dials themselves.
const JOIN_RETRY_STEP: Duration = Duration::from_secs(1);

/// How long a start with no route open yet keeps waiting for routes that are
/// retrying. Bounded well inside the client's own start timeout, so a session
/// with nothing reachable still fails with each route's reason.
pub(crate) const START_RETRY_WINDOW: Duration = Duration::from_secs(10);

/// The wait before attempt `failed + 1`, after `failed` dials have failed.
fn retry_delay(failed: u32) -> Duration {
    JOIN_RETRY_STEP * 2_u32.pow(failed.saturating_sub(1).min(4))
}

/// A route's transport once its dial has finished.
pub(crate) struct Joined {
    pub(crate) path: Box<dyn RelayPath>,
    /// The node as it was opened. An L2TP node now carries the runtime its
    /// later redials need.
    pub(crate) node: NodeSpec,
}

pub(crate) type JoinResult = Result<Box<Joined>, String>;

/// What a route's dial reports, in order: any failed attempts it is retrying,
/// then its outcome.
pub(crate) enum DialUpdate {
    Retrying { attempt: u32, error: String },
    Done(JoinResult),
}

/// Where a path worker gets its transport from.
pub(crate) enum RouteTransport {
    Open(Box<dyn RelayPath>),
    Joining(mpsc::Receiver<DialUpdate>),
}

/// What the start hears from the dials while it decides when to go. Progress
/// only wakes it; what happened waits on the route's own channel.
pub(crate) enum DialEvent {
    Resolved(usize, Vec<Ipv4Addr>),
    Progress,
}

/// One route being dialled in the background.
pub(crate) struct RouteDial {
    pub(crate) result: mpsc::Receiver<DialUpdate>,
    /// Hands over an L2TP node's runtime once the service has dialled it.
    pub(crate) service_dial: Option<mpsc::Sender<Result<L2tpRuntime, String>>>,
}

/// Sleeps `delay`, or less if the session stops first. True if it did not.
fn wait_unless_stopped(delay: Duration, stop: &AtomicBool) -> bool {
    let deadline = Instant::now() + delay;
    while Instant::now() < deadline {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        thread::sleep(JOIN_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
    !stop.load(Ordering::Acquire)
}

/// Resolves and opens `node` on a thread of its own, retrying a failed dial.
///
/// `stop` belongs to the session the route is for. Once it is set the service
/// has hung that session's L2TP connections up, and opening one now would
/// redial it behind the service's back.
///
/// An L2TP node is opened once: the service owns its RAS dial and already
/// retries that, and what reaches here is either its runtime or its final
/// error.
pub(crate) fn begin_dial(
    index: usize,
    node: NodeSpec,
    relay: SocketAddrV4,
    stop: Arc<AtomicBool>,
    events: mpsc::Sender<DialEvent>,
) -> Result<RouteDial, String> {
    let (updates, result) = mpsc::channel();
    let (service_dial, service_result) = if node.awaits_service_dial() {
        let (sender, receiver) = mpsc::channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let attempts = if matches!(node, NodeSpec::L2tp { .. }) {
        1
    } else {
        JOIN_ATTEMPTS
    };
    thread::Builder::new()
        .name(format!("gamepath-dial-{}", index + 1))
        .spawn(move || {
            let _ = events.send(DialEvent::Resolved(index, node.endpoint_ipv4s()));
            let node = match service_result {
                Some(dial) => match dial.recv() {
                    Ok(dial) => node.with_service_dial(dial),
                    // The session ended before the service finished.
                    Err(_) => return,
                },
                None => node,
            };
            for attempt in 1..=attempts {
                if stop.load(Ordering::Acquire) {
                    return;
                }
                let error = match node.open(relay) {
                    Ok(path) => {
                        let _ = updates.send(DialUpdate::Done(Ok(Box::new(Joined { path, node }))));
                        break;
                    }
                    Err(error) => error,
                };
                if attempt == attempts {
                    let error = if attempts > 1 {
                        format!("{error} (gave up after {attempts} attempts)")
                    } else {
                        error
                    };
                    let _ = updates.send(DialUpdate::Done(Err(error)));
                    break;
                }
                // Nobody is waiting for this route any more: the session
                // failed to start or its worker has stopped.
                if updates
                    .send(DialUpdate::Retrying { attempt, error })
                    .is_err()
                {
                    return;
                }
                let _ = events.send(DialEvent::Progress);
                if !wait_unless_stopped(retry_delay(attempt), &stop) {
                    return;
                }
            }
            let _ = events.send(DialEvent::Progress);
        })
        .map_err(|error| format!("could not start dialling route {}: {error}", index + 1))?;
    Ok(RouteDial {
        result,
        service_dial,
    })
}

/// Where one route stands when the session starts.
pub(crate) enum RouteStart {
    Open(Box<Joined>),
    Failed(String),
    Joining(RouteDial),
}

/// One route at session start, with every address its dial may use.
pub(crate) struct DialledRoute {
    pub(crate) index: usize,
    pub(crate) endpoints: Vec<Ipv4Addr>,
    /// What the last failed attempt of a route still retrying says.
    pub(crate) retrying: Option<String>,
    pub(crate) start: RouteStart,
}

/// Dials every node at once and returns as soon as the session can start: one
/// route is open and every endpoint is known, so whatever joins later is
/// already routed around the capture. A node the service is still dialling is
/// never waited for here - it cannot finish until this returns.
///
/// Routes that failed their first attempt keep retrying. They hold the start
/// only while nothing else is open, and then for `retry_window` at most.
pub(crate) fn dial_routes(
    nodes: &[NodeSpec],
    relay: SocketAddrV4,
    stop: &Arc<AtomicBool>,
    retry_window: Duration,
) -> Result<Vec<DialledRoute>, String> {
    let started = Instant::now();
    let (events_tx, events) = mpsc::channel();
    let mut dials = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            begin_dial(
                index,
                node.clone(),
                relay,
                Arc::clone(stop),
                events_tx.clone(),
            )
            .map(Some)
        })
        .collect::<Result<Vec<_>, _>>()?;
    drop(events_tx);
    let count = nodes.len();
    let mut endpoints: Vec<Option<Vec<Ipv4Addr>>> = vec![None; count];
    let mut retrying: Vec<Option<String>> = vec![None; count];
    let mut finished: Vec<Option<JoinResult>> = nodes.iter().map(|_| None).collect();
    loop {
        // Swept on every wake, so a dial thread that died without reporting
        // counts as failed instead of holding the start for ever.
        for (index, dial) in dials.iter().enumerate() {
            let Some(dial) = dial else { continue };
            while finished[index].is_none() && !nodes[index].awaits_service_dial() {
                match dial.result.try_recv() {
                    Ok(DialUpdate::Retrying { attempt, error }) => {
                        log_warn!(
                            "route {} attempt {attempt} of {JOIN_ATTEMPTS} failed: {error}; retrying",
                            index + 1
                        );
                        retrying[index] = Some(retrying_note(attempt, &error));
                    }
                    Ok(DialUpdate::Done(result)) => finished[index] = Some(result),
                    Err(mpsc::TryRecvError::Disconnected) => {
                        finished[index] = Some(Err("the dial stopped without a result".into()));
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                }
            }
        }
        let unfinished = |i: usize| finished[i].is_none() && !nodes[i].awaits_service_dial();
        let resolved = (0..count).all(|i| endpoints[i].is_some() || finished[i].is_some());
        let opened = finished.iter().any(|result| matches!(result, Some(Ok(_))));
        let first_attempts = (0..count).any(|i| unfinished(i) && retrying[i].is_none());
        let retries = (0..count).any(|i| unfinished(i) && retrying[i].is_some());
        let given_up_waiting = !retries || started.elapsed() >= retry_window;
        if resolved && (opened || (!first_attempts && given_up_waiting)) {
            break;
        }
        match events.recv_timeout(Duration::from_millis(100)) {
            Ok(DialEvent::Resolved(index, addresses)) => endpoints[index] = Some(addresses),
            Ok(DialEvent::Progress) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(dials
        .iter_mut()
        .enumerate()
        .map(|(index, dial)| {
            let dial = dial.take().expect("every route has a dial");
            let start = match finished[index].take() {
                Some(Ok(joined)) => RouteStart::Open(joined),
                Some(Err(reason)) => RouteStart::Failed(reason),
                None => RouteStart::Joining(dial),
            };
            DialledRoute {
                index,
                endpoints: endpoints[index].take().unwrap_or_default(),
                retrying: retrying[index].take(),
                start,
            }
        })
        .collect())
}

/// What a route has to pass to join: its endpoint must already be routed
/// around the capture, and no route in the session may share its identity.
pub(crate) struct JoinGate {
    bypass: Vec<Ipv4Addr>,
    identities: Mutex<Vec<PathIdentity>>,
    pub(crate) skipped: Arc<Mutex<Vec<SkippedRoute>>>,
}

impl JoinGate {
    pub(crate) fn new(
        bypass: Vec<Ipv4Addr>,
        identities: Vec<PathIdentity>,
        skipped: Arc<Mutex<Vec<SkippedRoute>>>,
    ) -> Self {
        Self {
            bypass,
            identities: Mutex::new(identities),
            skipped,
        }
    }

    fn admit(&self, path: &dyn RelayPath) -> Result<(), String> {
        if let Some(address) = path.bypass_ipv4() {
            if !self.bypass.contains(&address) {
                return Err(format!(
                    "it resolved to {address}, which the session did not route around the tunnel; \
                     it joins the next session"
                ));
            }
        }
        let identity = path.identity();
        let mut identities = self.identities.lock().unwrap();
        if identities.contains(&identity) {
            return Err("another enabled route already uses this endpoint and key".into());
        }
        identities.push(identity);
        Ok(())
    }
}

/// What the route card says while a failed dial waits for its next attempt.
pub(crate) fn retrying_note(attempt: u32, error: &str) -> String {
    format!("attempt {attempt} of {JOIN_ATTEMPTS} failed: {error}; retrying")
}

/// Holds a path worker until its route's dial finishes, and returns the
/// transport it joins with, or `None` when the route is not joining at all.
#[allow(clippy::too_many_arguments)]
pub(crate) fn await_join(
    receiver: mpsc::Receiver<DialUpdate>,
    index: usize,
    stop: &AtomicBool,
    commands: &mpsc::Receiver<PathCommand>,
    telemetry: &PathTelemetry,
    statuses: &Mutex<Vec<PathSessionStatus>>,
    gate: &JoinGate,
    node: &mut NodeSpec,
) -> Option<Box<dyn RelayPath>> {
    while !stop.load(Ordering::Acquire) {
        // Nothing is dispatched to a route that has not joined, but anything
        // that is has to leave the queue rather than count against it.
        drain_send_queue(
            commands,
            Some(Duration::ZERO),
            index,
            &telemetry.queue_depth,
            &telemetry.dropped,
            &telemetry.stale_dropped,
            |_| (0, Ok(())),
            |_, _| {},
        );
        let joined = match receiver.recv_timeout(JOIN_POLL) {
            Ok(DialUpdate::Retrying { attempt, error }) => {
                let mut current = statuses.lock().unwrap();
                let status = &mut current[index];
                log_warn!(
                    "route {} ({}) attempt {attempt} of {JOIN_ATTEMPTS} failed: {error}; retrying",
                    status.route,
                    status.label
                );
                status.last_error = Some(retrying_note(attempt, &error));
                continue;
            }
            Ok(DialUpdate::Done(result)) => {
                result.and_then(|joined| gate.admit(joined.path.as_ref()).map(|()| joined))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        };
        let mut current = statuses.lock().unwrap();
        let status = &mut current[index];
        status.joining = false;
        return match joined {
            Ok(joined) => {
                log_info!(
                    "route {} ({}) joined the running session via {}; awaiting relay probe",
                    status.route,
                    status.label,
                    joined.path.endpoint()
                );
                status.endpoint = joined.path.endpoint();
                status.last_error = Some("joined; waiting for a probe".into());
                *node = joined.node;
                Some(joined.path)
            }
            Err(reason) => {
                log_warn!(
                    "route {} ({}) did not join: {reason}",
                    status.route,
                    status.label
                );
                status.last_error = Some(reason.clone());
                gate.skipped.lock().unwrap().push(SkippedRoute {
                    route: status.route,
                    label: status.label.clone(),
                    reason,
                });
                None
            }
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::state::initial_status;
    use base64::Engine as _;
    use std::net::{TcpListener, UdpSocket};
    use std::time::Instant;

    const RELAY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 51_820);

    /// Opens at once: user-space WireGuard defers its handshake.
    fn wireguard_node(peer: &UdpSocket, key: u8) -> NodeSpec {
        let key = base64::engine::general_purpose::STANDARD.encode([key; 32]);
        NodeSpec::WireGuard {
            config: format!(
                "[Interface]\nPrivateKey = {key}\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = {key}\n\
                 Endpoint = 127.0.0.1:{}\nAllowedIPs = 0.0.0.0/0",
                peer.local_addr().unwrap().port()
            ),
            label: None,
        }
    }

    /// A proxy that accepts the connection and never answers the greeting,
    /// which is what a provider throttled by DPI looks like from here.
    fn silent_socks_node(listener: &TcpListener) -> NodeSpec {
        NodeSpec::Socks5 {
            host: "127.0.0.1".into(),
            port: listener.local_addr().unwrap().port(),
            username: None,
            password: None,
            label: None,
        }
    }

    fn pending_l2tp_node() -> NodeSpec {
        NodeSpec::L2tp {
            server: "203.0.113.20".into(),
            username: "player".into(),
            password: "secret".into(),
            pre_shared_key: String::new(),
            label: None,
            runtime: None,
            dial_error: None,
            pending: true,
        }
    }

    #[test]
    fn the_session_starts_on_the_first_route_while_a_slow_one_is_still_dialling() {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let routes = dial_routes(
            &[silent_socks_node(&proxy), wireguard_node(&peer, 7)],
            RELAY,
            &stop,
            START_RETRY_WINDOW,
        )
        .unwrap();
        // The silent proxy would hold the start for its whole handshake timeout.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the start waited {:?} for a route that was not ready",
            started.elapsed()
        );
        assert!(matches!(routes[0].start, RouteStart::Joining(_)));
        assert!(matches!(routes[1].start, RouteStart::Open(_)));
        stop.store(true, Ordering::Release);
    }

    #[test]
    fn a_route_the_service_is_still_dialling_never_holds_the_start() {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let routes = dial_routes(
            &[pending_l2tp_node(), wireguard_node(&peer, 7)],
            RELAY,
            &stop,
            START_RETRY_WINDOW,
        )
        .unwrap();
        let RouteStart::Joining(dial) = &routes[0].start else {
            panic!("the L2TP route should still be joining");
        };
        assert!(dial.service_dial.is_some());
        // Resolved up front so it is routed around the capture before it joins.
        assert_eq!(routes[0].endpoints, vec![Ipv4Addr::new(203, 0, 113, 20)]);
        assert!(matches!(routes[1].start, RouteStart::Open(_)));
    }

    /// Bound and released: nothing listens, so every connect is refused.
    fn refused_socks_node() -> NodeSpec {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        NodeSpec::Socks5 {
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
            label: None,
        }
    }

    #[test]
    fn a_start_with_nothing_open_stops_waiting_for_retries_at_its_window() {
        let stop = Arc::new(AtomicBool::new(false));
        let routes = dial_routes(&[refused_socks_node()], RELAY, &stop, Duration::ZERO).unwrap();
        // Still retrying, and saying why, rather than waiting out every attempt.
        let RouteStart::Joining(_) = &routes[0].start else {
            panic!("the refused route should still be retrying");
        };
        let note = routes[0].retrying.as_deref().unwrap();
        assert!(note.starts_with("attempt 1 of 5 failed"), "{note}");
        stop.store(true, Ordering::Release);
    }

    #[test]
    fn a_failed_dial_is_retried_until_the_session_stops() {
        let stop = Arc::new(AtomicBool::new(false));
        let (events, _events) = mpsc::channel();
        let dial = begin_dial(0, refused_socks_node(), RELAY, Arc::clone(&stop), events).unwrap();
        let Ok(DialUpdate::Retrying { attempt, .. }) =
            dial.result.recv_timeout(Duration::from_secs(10))
        else {
            panic!("a refused dial should be retried");
        };
        assert_eq!(attempt, 1);
        stop.store(true, Ordering::Release);
        // The wait before the next attempt ends with the session, and no
        // further attempt is made.
        let started = Instant::now();
        assert!(matches!(
            dial.result.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn retries_back_off_and_all_five_fit_in_seconds() {
        let waits = (1..JOIN_ATTEMPTS).map(retry_delay).collect::<Vec<_>>();
        assert_eq!(
            waits,
            [1, 2, 4, 8].map(Duration::from_secs).to_vec(),
            "the waits between five attempts"
        );
        assert!(waits.iter().sum::<Duration>() <= Duration::from_secs(15));
    }

    fn open(node: &NodeSpec) -> Box<dyn RelayPath> {
        node.open(RELAY).unwrap()
    }

    #[test]
    fn a_route_joins_only_through_a_bypassed_address_and_an_unused_identity() {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let node = wireguard_node(&peer, 7);
        let unrouted = JoinGate::new(Vec::new(), Vec::new(), Arc::default());
        let error = unrouted.admit(open(&node).as_ref()).unwrap_err();
        assert!(error.contains("did not route around the tunnel"), "{error}");

        let gate = JoinGate::new(vec![Ipv4Addr::LOCALHOST], Vec::new(), Arc::default());
        gate.admit(open(&node).as_ref()).unwrap();
        let error = gate.admit(open(&node).as_ref()).unwrap_err();
        assert!(error.contains("already uses this endpoint"), "{error}");
        // A different key on the same endpoint is a different route.
        gate.admit(open(&wireguard_node(&peer, 9)).as_ref())
            .unwrap();
    }

    fn joining_status() -> Mutex<Vec<PathSessionStatus>> {
        let mut status = initial_status(2, "socks5", "route two".into(), "proxy".into());
        status.joining = true;
        Mutex::new(vec![status])
    }

    #[test]
    fn a_route_that_fails_to_join_is_reported_as_skipped() {
        let (result_tx, result) = mpsc::channel();
        let (_commands_tx, commands) = mpsc::sync_channel(4);
        let statuses = joining_status();
        let gate = JoinGate::new(Vec::new(), Vec::new(), Arc::default());
        let mut node = pending_l2tp_node();
        result_tx
            .send(DialUpdate::Done(Err("RAS error 628".into())))
            .unwrap();
        let joined = await_join(
            result,
            0,
            &AtomicBool::new(false),
            &commands,
            &PathTelemetry::new(1),
            &statuses,
            &gate,
            &mut node,
        );
        assert!(joined.is_none());
        assert!(!statuses.lock().unwrap()[0].joining);
        let skipped = gate.skipped.lock().unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].route, 2);
        assert_eq!(skipped[0].reason, "RAS error 628");
    }

    #[test]
    fn a_joining_route_takes_the_node_it_opened_with() {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let opened = wireguard_node(&peer, 7);
        let (result_tx, result) = mpsc::channel();
        let (_commands_tx, commands) = mpsc::sync_channel(4);
        let statuses = joining_status();
        let gate = JoinGate::new(vec![Ipv4Addr::LOCALHOST], Vec::new(), Arc::default());
        let mut node = pending_l2tp_node();
        result_tx
            .send(DialUpdate::Retrying {
                attempt: 1,
                error: "connection refused".into(),
            })
            .unwrap();
        result_tx
            .send(DialUpdate::Done(Ok(Box::new(Joined {
                path: open(&opened),
                node: opened,
            }))))
            .unwrap();
        let joined = await_join(
            result,
            0,
            &AtomicBool::new(false),
            &commands,
            &PathTelemetry::new(1),
            &statuses,
            &gate,
            &mut node,
        );
        assert!(joined.is_some());
        // Its redials need what the dial learnt, not the placeholder.
        assert!(matches!(node, NodeSpec::WireGuard { .. }));
        let status = &statuses.lock().unwrap()[0];
        assert!(!status.joining);
        assert!(status.endpoint.starts_with("127.0.0.1:"));
    }

    #[test]
    fn a_stopped_session_does_not_wait_for_a_joining_route() {
        let (_result_tx, result) = mpsc::channel();
        let (_commands_tx, commands) = mpsc::sync_channel(4);
        let statuses = joining_status();
        let gate = JoinGate::new(Vec::new(), Vec::new(), Arc::default());
        let started = Instant::now();
        let joined = await_join(
            result,
            0,
            &AtomicBool::new(true),
            &commands,
            &PathTelemetry::new(1),
            &statuses,
            &gate,
            &mut pending_l2tp_node(),
        );
        assert!(joined.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(gate.skipped.lock().unwrap().is_empty());
    }
}
