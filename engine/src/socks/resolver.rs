//! Resolves the names proxy clients ask for, through the same egress their
//! connections use.
//!
//! A SOCKS5 or HTTP client that sends a hostname is asking the proxy to look
//! it up. Doing that with the PC's own resolver would leak the name to the
//! local network and, on a filtered connection, hand back a blackhole address
//! for exactly the game servers the tunnel exists to reach. So each question
//! goes out through the tunnel to every configured resolver at once, and the
//! first real answer wins.

use super::egress::{Egress, FlowId};
use gamepath_engine::dns::{self, Answer};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// Asked again at this interval until [`QUERY_TIMEOUT`].
const RETRY_INTERVAL: Duration = Duration::from_millis(700);
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);
/// Bounds on how long an answer is reused. The floor stops a zero-TTL record
/// costing a round trip per connection; the ceiling keeps a moved server from
/// being remembered all evening.
const MIN_TTL: Duration = Duration::from_secs(30);
const MAX_TTL: Duration = Duration::from_secs(600);
const NEGATIVE_TTL: Duration = Duration::from_secs(10);
const CACHE_LIMIT: usize = 4096;

struct Query<W> {
    id: u16,
    message: Vec<u8>,
    started: Instant,
    last_sent: Instant,
    waiters: Vec<W>,
}

pub(crate) struct Resolver<W> {
    flow: Option<FlowId>,
    servers: Vec<Ipv4Addr>,
    pending: HashMap<String, Query<W>>,
    cache: HashMap<String, (Option<Vec<Ipv4Addr>>, Instant)>,
    rotation: usize,
}

/// Spreads connections over a name's addresses the way a client's own
/// resolver would.
fn pick(rotation: &mut usize, addresses: &[Ipv4Addr]) -> Ipv4Addr {
    *rotation = rotation.wrapping_add(1);
    addresses[*rotation % addresses.len()]
}

pub(crate) enum Lookup {
    Ready(Ipv4Addr),
    Pending,
    Failed(String),
}

impl<W> Resolver<W> {
    pub(crate) fn new(servers: Vec<Ipv4Addr>) -> Self {
        Self {
            flow: None,
            servers,
            pending: HashMap::new(),
            cache: HashMap::new(),
            rotation: 0,
        }
    }

    /// Answers from the cache, or starts (or joins) a lookup that will finish
    /// in [`Resolver::poll`].
    pub(crate) fn lookup(&mut self, egress: &mut dyn Egress, name: &str, waiter: W) -> Lookup {
        if let Some((addresses, expires)) = self.cache.get(name) {
            if Instant::now() < *expires {
                return match addresses {
                    Some(addresses) => Lookup::Ready(pick(&mut self.rotation, addresses)),
                    None => Lookup::Failed(format!("{name} did not resolve")),
                };
            }
        }
        if let Some(query) = self.pending.get_mut(name) {
            query.waiters.push(waiter);
            return Lookup::Pending;
        }
        let flow = match self.flow {
            Some(flow) => flow,
            None => match egress.udp_open() {
                Ok(flow) => *self.flow.insert(flow),
                Err(error) => return Lookup::Failed(error),
            },
        };
        let id = rand::random::<u16>();
        let Some(message) = dns::query(id, name) else {
            return Lookup::Failed(format!("{name} is not a valid hostname"));
        };
        let now = Instant::now();
        for server in &self.servers {
            egress.udp_send(flow, SocketAddrV4::new(*server, 53), &message);
        }
        self.pending.insert(
            name.to_owned(),
            Query {
                id,
                message,
                started: now,
                last_sent: now,
                waiters: vec![waiter],
            },
        );
        Lookup::Pending
    }

    /// Reads answers, retries and expires queries, and returns every waiter
    /// whose lookup finished.
    pub(crate) fn poll(&mut self, egress: &mut dyn Egress) -> Vec<(W, Result<Ipv4Addr, String>)> {
        let mut finished = Vec::new();
        let Some(flow) = self.flow else {
            return finished;
        };
        while let Some((from, response)) = egress.udp_recv(flow) {
            if from.port() != 53 || !self.servers.contains(from.ip()) {
                continue;
            }
            let Some((name, answer)) = self.pending.iter().find_map(|(name, query)| {
                dns::read_answer(&response, query.id).map(|answer| (name.clone(), answer))
            }) else {
                continue;
            };
            let query = self.pending.remove(&name).expect("found above");
            let (addresses, ttl) = match answer {
                Answer::Addresses { addresses, ttl } => (
                    Some(addresses),
                    Duration::from_secs(u64::from(ttl)).clamp(MIN_TTL, MAX_TTL),
                ),
                Answer::NoAddress { .. } => (None, NEGATIVE_TTL),
            };
            for waiter in query.waiters {
                let result = match &addresses {
                    Some(addresses) => Ok(pick(&mut self.rotation, addresses)),
                    None => Err(format!("{name} has no IPv4 address")),
                };
                finished.push((waiter, result));
            }
            if self.cache.len() >= CACHE_LIMIT {
                let now = Instant::now();
                self.cache.retain(|_, (_, expires)| *expires > now);
                if self.cache.len() >= CACHE_LIMIT {
                    self.cache.clear();
                }
            }
            self.cache.insert(name, (addresses, Instant::now() + ttl));
        }
        let now = Instant::now();
        let expired = self
            .pending
            .iter()
            .filter(|(_, query)| now.duration_since(query.started) >= QUERY_TIMEOUT)
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in expired {
            let query = self.pending.remove(&name).expect("listed above");
            for waiter in query.waiters {
                finished.push((waiter, Err(format!("no resolver answered for {name}"))));
            }
        }
        for query in self.pending.values_mut() {
            if now.duration_since(query.last_sent) >= RETRY_INTERVAL {
                query.last_sent = now;
                for server in &self.servers {
                    egress.udp_send(flow, SocketAddrV4::new(*server, 53), &query.message);
                }
            }
        }
        finished
    }

    /// When the next retry or expiry is due.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending
            .values()
            .map(|query| (query.last_sent + RETRY_INTERVAL).min(query.started + QUERY_TIMEOUT))
            .min()
    }

    pub(crate) fn release(&mut self, egress: &mut dyn Egress) {
        if let Some(flow) = self.flow.take() {
            egress.udp_release(flow);
        }
    }
}
