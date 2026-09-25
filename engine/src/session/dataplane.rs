//! Sending a packet into a running session and getting one back.
//!
//! The dispatcher lives here: it seals a captured packet under the session
//! overlay, narrows the scheduler's pick to the paths actually carrying
//! traffic, and hands a copy to each of them. Capture calls it per packet, so
//! everything on this path is deliberately lock-light.

use super::WireGuardSessionManager;
use super::health::selected_paths;
use super::state::SessionOverlay;
use super::worker::PathCommand;
use crate::icmp::{icmp_echo_packet, is_matching_icmp_reply};
use gamepath_engine::relay_path::SessionMode;
use gamepath_engine::userspace_wireguard::{ipv4_udp_packet, ipv4_udp_payload};
use gamepath_engine::{dns, log_warn};
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long the resolver probe waits. Short on purpose: it sits on the connect
/// path, and a resolver that needs longer than this to answer one cached-name
/// query is not one to hand a game's name lookups to. Failing it costs the
/// public fallback, never the session.
const RESOLVER_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

impl WireGuardSessionManager {
    /// Whether `resolver` answers DNS through this session.
    ///
    /// Sent as a real query over the live data plane, before anything is
    /// configured, so the answer reflects the path the user's lookups would
    /// actually take rather than this machine's own connectivity.
    ///
    /// A DNS round trip is normally weak evidence — a proxy or a filter can
    /// answer one without forwarding anything, which is why
    /// `answers_dns_without_forwarding` exists elsewhere in this codebase. It
    /// is strong evidence *here* precisely because the relay's tunnel address
    /// exists only inside the tunnel: nothing between this machine and the
    /// relay can see that address, let alone reply from it.
    pub(crate) fn tunnel_resolver_answers(&mut self, resolver: Ipv4Addr) -> bool {
        let Some(session) = self.active.as_ref() else {
            return false;
        };
        let address = session.virtual_ipv4;
        let id = rand::random::<u16>();
        let source_port = rand::random_range(49_152..=65_535);
        let Some(question) = dns::query(id, dns::PROBE_HOSTNAME) else {
            return false;
        };
        let Ok(packet) = ipv4_udp_packet(address, resolver, source_port, 53, &question) else {
            return false;
        };
        if let Err(error) = self.enqueue_data_packet(&packet) {
            log_warn!("could not ask {resolver} to resolve a name: {error}");
            return false;
        }
        let deadline = Instant::now() + RESOLVER_PROBE_TIMEOUT;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(Some(reply)) = self.receive_data_packet(remaining) else {
                continue;
            };
            // Anything else arriving on the tunnel right now is not this
            // answer; the session carries no user traffic until capture starts.
            let Some((from, to, from_port, to_port, payload)) = ipv4_udp_payload(&reply) else {
                continue;
            };
            if from != resolver || to != address || from_port != 53 || to_port != source_port {
                continue;
            }
            return match dns::verdict(payload, id) {
                dns::ResolverVerdict::Mismatched => continue,
                // Reachable and speaking DNS is the whole question. A resolver
                // that refuses this one name still resolves everything else,
                // and is still better than leaking to the ISP.
                verdict => {
                    if let dns::ResolverVerdict::Refused { rcode } = verdict {
                        log_warn!(
                            "{resolver} answered the resolver probe with DNS code {rcode}; using it anyway"
                        );
                    }
                    true
                }
            };
        }
        false
    }

    pub(crate) fn probe_data_plane(&mut self) -> Result<Value, String> {
        let session = self
            .active
            .as_ref()
            .ok_or("start the WireGuard session before probing its data plane")?;
        let (virtual_ipv4, mode) = (session.virtual_ipv4, session.mode);
        let benchmark_server = gamepath_engine::BENCHMARK_TARGET;
        let identifier = rand::random::<u16>();
        let request = icmp_echo_packet(virtual_ipv4, benchmark_server, identifier, 1, false);
        let started = Instant::now();
        // A relay session has to answer: the relay is the user's own, and this
        // round trip is what proves the whole chain carries traffic. A direct
        // session's node belongs to a provider who may simply filter ICMP,
        // which says nothing about the game traffic it will carry — so there
        // the probe is telemetry, and a silent node is not a failed session.
        let timeout = match mode {
            SessionMode::Relay => Duration::from_secs(8),
            SessionMode::Direct => Duration::from_secs(2),
        };
        let reply = match self.send_data_packet(&request, timeout) {
            Ok(reply)
                if is_matching_icmp_reply(&reply, benchmark_server, virtual_ipv4, identifier) =>
            {
                reply
            }
            outcome => {
                if mode == SessionMode::Relay {
                    return Err(match outcome {
                        Ok(_) => "relay data plane returned an unexpected packet".to_owned(),
                        Err(error) => error,
                    });
                }
                return Ok(json!({
                    "reachable": false,
                    "latencyMs": Value::Null,
                    "userToRelayMs": Value::Null,
                    "relayToServerMs": Value::Null,
                    "benchmarkServer": benchmark_server.to_string(),
                    "note": "the node did not answer a test ping, which many providers filter",
                }));
            }
        };
        let end_to_end = started.elapsed().as_secs_f64() * 1000.0;
        let user_to_relay = self
            .active
            .as_ref()
            .and_then(|session| {
                session
                    .paths
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|path| path.latency_ms)
                    .reduce(f64::min)
            })
            .unwrap_or(end_to_end);
        // These timings come from independent samples. If the fresh end-to-end
        // probe happens to beat the route EWMA, subtraction produces zero or a
        // negative number; reporting 0 ms invents a physically impossible hop.
        let relay_to_server = (end_to_end > user_to_relay).then_some(end_to_end - user_to_relay);
        Ok(json!({
            "reachable": true,
            "latencyMs": end_to_end,
            "userToRelayMs": user_to_relay,
            "relayToServerMs": relay_to_server,
            "benchmarkServer": benchmark_server.to_string(),
            "bytes": reply.len(),
        }))
    }

    fn send_data_packet(&mut self, packet: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        self.enqueue_data_packet(packet)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(packet) = self.receive_data_packet(remaining)? {
                return Ok(packet);
            }
        }
        Err("no path returned the relayed packet before timeout".into())
    }

    pub(crate) fn enqueue_data_packet(&mut self, packet: &[u8]) -> Result<bool, String> {
        use gamepath_engine::protocol::FrameHeader;

        let session = self
            .active
            .as_mut()
            .ok_or("start the WireGuard session before sending packets")?;
        let frame = match &session.overlay {
            SessionOverlay::Relay { client_id, crypto } => {
                let sequence = session.sequences.fetch_add(1, Ordering::Relaxed);
                let header = FrameHeader {
                    flags: 0,
                    client_id: *client_id,
                    session_id: session.session_id,
                    sequence,
                };
                crypto.seal_client(header, packet)?
            }
            // The node routes the packet as it stands, so there is nothing to
            // wrap it in and no sequence for anyone to compare copies by.
            SessionOverlay::Direct => packet.to_vec(),
        };
        // The scheduler's pick, narrowed to the paths that are actually
        // carrying traffic. A path that never came up would otherwise take a
        // copy of every packet and throw it away.
        let decision = session.decision_mask.load(Ordering::Acquire);
        let healthy = session.telemetry.healthy_mask.load(Ordering::Acquire);
        let selected = selected_paths(decision, healthy);
        let mut selected_paths = 0;
        let mut accepted_paths = 0;
        let queued_at = Instant::now();
        for (index, sender) in session.commands.iter().enumerate() {
            let bit = 1_u64.checked_shl(index as u32).unwrap_or(0);
            if selected & bit == 0 {
                continue;
            }
            selected_paths += 1;
            match sender.try_send(PathCommand {
                frame: frame.clone(),
                queued_at,
            }) {
                Ok(()) => {
                    accepted_paths += 1;
                    if let Some(depth) = session.telemetry.queue_depth.get(index) {
                        let current = depth.fetch_add(1, Ordering::Relaxed) + 1;
                        if let Some(peak) = session.telemetry.queue_peak.get(index) {
                            peak.fetch_max(current, Ordering::Relaxed);
                        }
                    }
                }
                // A full queue means the path is already behind. Shedding the
                // newest packet keeps the backlog bounded: game traffic is
                // stale by the time it would drain, and TCP retransmits.
                Err(mpsc::TrySendError::Full(_)) => {
                    if let Some(dropped) = session.telemetry.dropped.get(index) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(dropped) = session.telemetry.queue_full_dropped.get(index) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {}
            }
        }
        // Nothing to send down. Split mode reads this as the relay being
        // unavailable and lets the packet take the normal route; that fail-open
        // is only correct here, when no path was ever chosen. A packet dropped
        // because every chosen path is saturated must not bypass: half a flow
        // arriving from a different source address breaks it at the server.
        if selected_paths == 0 {
            return Err("no active path workers accepted the packet".into());
        }
        if accepted_paths > 0 {
            session
                .user_bytes_sent
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
        }
        Ok(accepted_paths > 0)
    }

    fn receive_data_packet(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, String> {
        let session = self
            .active
            .as_mut()
            .ok_or("start the WireGuard session before receiving packets")?;
        session.data_receiver.receive(timeout)
    }
}
