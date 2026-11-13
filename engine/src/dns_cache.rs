//! Optimistic cache for the name lookups a session carries through its tunnel.
//!
//! Windows' DNS Client already caches every answer for its TTL, so a lookup
//! that reaches capture is one it no longer has. Popular names carry 20-300 s
//! TTLs, so going back to a site costs a tunnel round trip per name - 100-300
//! ms from a filtered uplink to its relay - before the first connection can
//! open. An expired entry is therefore answered at once and refreshed behind
//! the answer, as sing-box's `optimistic` cache and RFC 8767 serve-stale do.
//! The same answers keep a launcher resolving through a path failover or a
//! provider stall instead of failing after its own timeout.
//!
//! Every entry is a reply that came back through the tunnel to a query this
//! cache saw leave through it, so remote DNS stays fail closed: nothing here
//! ever comes from the local resolver. Entries are kept per node, because a
//! CDN or matchmaking name answers by where the lookup exits.

use crate::dns::skip_name;
use crate::icmp::internet_checksum;
use crate::role::Role;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;
const PROTOCOL_UDP: u8 = 17;
const TYPE_A: u16 = 1;
const TYPE_SOA: u16 = 6;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_CHECKING_DISABLED: u16 = 0x0010;
const OPCODE_MASK: u16 = 0x7800;

/// What an expired answer is served with: long enough that the client does
/// not ask again at once, short enough that the refreshed answer replaces it
/// within seconds if the address moved.
const STALE_TTL: u32 = 5;
/// "No such name" is kept briefly and never served once expired: a name that
/// has just been created must not stay missing.
const NEGATIVE_TTL_LIMIT: u32 = 60;
const TTL_LIMIT: u32 = 86_400;
/// A refresh unanswered for this long is presumed lost and may be sent again.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(4);
const ENTRY_LIMIT: usize = 4096;
const PENDING_LIMIT: usize = 1024;
/// Bounds memory at 16 MiB however many large answers arrive.
const MESSAGE_LIMIT: usize = 4096;

/// How long past its TTL an answer may still be served. A game's servers
/// rarely move, but a wrong one costs a match, so the game keeps a much
/// shorter horizon than the VPN's browsing.
pub fn stale_limit(role: Role) -> Duration {
    match role {
        Role::Game => Duration::from_secs(60 * 60),
        Role::Vpn => Duration::from_secs(24 * 60 * 60),
    }
}

/// An unfragmented IPv4/UDP datagram's DNS message, with its endpoints.
pub struct Datagram<'a> {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    pub message: &'a [u8],
}

/// The datagram in `packet` when it is a whole UDP datagram to or from port
/// 53. Fragments are left alone: the cache only answers what it read whole.
pub fn datagram(packet: &[u8]) -> Option<Datagram<'_>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != PROTOCOL_UDP {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header < 20 || total > packet.len() || total < header + 8 {
        return None;
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    let udp = &packet[header..total];
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if length < 8 || length > udp.len() {
        return None;
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    if source_port != DNS_PORT && destination_port != DNS_PORT {
        return None;
    }
    let address =
        |at: usize| Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3]);
    Some(Datagram {
        source: SocketAddrV4::new(address(12), source_port),
        destination: SocketAddrV4::new(address(16), destination_port),
        message: &udp[8..length],
    })
}

/// The IPv4/UDP datagram carrying `message` back to whoever sent `query`, as
/// if from the resolver it asked.
pub fn reply_packet(query: &Datagram<'_>, message: &[u8]) -> Vec<u8> {
    let (from, to) = (query.destination, query.source);
    let udp_length = 8 + message.len();
    let total = 20 + udp_length;
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 64, PROTOCOL_UDP, 0, 0]);
    packet.extend_from_slice(&from.ip().octets());
    packet.extend_from_slice(&to.ip().octets());
    let header_checksum = internet_checksum(&packet);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet.extend_from_slice(&from.port().to_be_bytes());
    packet.extend_from_slice(&to.port().to_be_bytes());
    packet.extend_from_slice(&(udp_length as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(message);
    let mut summed = Vec::with_capacity(12 + udp_length);
    summed.extend_from_slice(&from.ip().octets());
    summed.extend_from_slice(&to.ip().octets());
    summed.extend_from_slice(&[0, PROTOCOL_UDP]);
    summed.extend_from_slice(&(udp_length as u16).to_be_bytes());
    summed.extend_from_slice(&packet[20..]);
    // A computed zero is sent as all ones; zero means "no checksum".
    let checksum = match internet_checksum(&summed) {
        0 => 0xffff,
        checksum => checksum,
    };
    packet[26..28].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// What to do with a query the session is about to carry.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Send it on; nothing was answered.
    Forward,
    /// Deliver `reply` to the client now. With `forward`, send the query on
    /// as well: its reply refreshes the entry and is never delivered.
    Answer { reply: Vec<u8>, forward: bool },
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Key {
    node: u8,
    /// The question name in wire format, lowercased.
    name: Box<[u8]>,
    record_type: u16,
    /// Recursion desired, checking disabled, EDNS and DNSSEC OK, by bit: an
    /// answer is only reused for the kind of query that produced it.
    flavour: u8,
}

struct Entry {
    response: Vec<u8>,
    question_end: usize,
    stored: Instant,
    ttl: u32,
    negative: bool,
    refreshing: Option<Instant>,
    last_used: Instant,
}

impl Entry {
    fn expired_for_good(&self, now: Instant, stale_limit: Duration) -> bool {
        let age = now.saturating_duration_since(self.stored);
        let ttl = Duration::from_secs(u64::from(self.ttl));
        age >= if self.negative {
            ttl
        } else {
            ttl + stale_limit
        }
    }
}

type PendingKey = (SocketAddrV4, Ipv4Addr, u16);

struct Pending {
    key: Key,
    sent: Instant,
    refresh: bool,
}

#[derive(Default)]
struct Counters {
    answered: u64,
    stale_answered: u64,
    refreshed: u64,
    forwarded: u64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, Entry>,
    pending: HashMap<PendingKey, Pending>,
    counters: Counters,
}

pub struct DnsCache {
    inner: Mutex<Inner>,
    stale_limit: Duration,
}

impl DnsCache {
    pub fn new(stale_limit: Duration) -> Self {
        Self {
            inner: Mutex::default(),
            stale_limit,
        }
    }

    /// A UDP query from `client` to `resolver`, about to leave through `node`.
    pub fn on_query(
        &self,
        node: u8,
        client: SocketAddrV4,
        resolver: Ipv4Addr,
        message: &[u8],
        now: Instant,
    ) -> Outcome {
        let Some(key) = query_key(node, message) else {
            return Outcome::Forward;
        };
        let id = u16::from_be_bytes([message[0], message[1]]);
        let mut inner = self.inner.lock().unwrap();
        let mut served = None;
        if let Some(entry) = inner.entries.get_mut(&key) {
            let age = now.saturating_duration_since(entry.stored);
            let ttl = Duration::from_secs(u64::from(entry.ttl));
            let refreshing = entry
                .refreshing
                .is_some_and(|sent| now.saturating_duration_since(sent) < REFRESH_TIMEOUT);
            if age < ttl {
                let elapsed = age.as_secs() as u32;
                let refresh = !entry.negative && !refreshing && ttl - age <= refresh_ahead(ttl);
                // Never longer than the entry itself lives: a negative
                // answer's SOA would otherwise hand out its full hour.
                let lifetime = entry.ttl;
                served = answer(entry, message, |record_ttl| {
                    record_ttl.min(lifetime).saturating_sub(elapsed).max(1)
                })
                .map(|reply| (reply, refresh, false));
            } else if !entry.negative && age - ttl < self.stale_limit {
                served =
                    answer(entry, message, |_| STALE_TTL).map(|reply| (reply, !refreshing, true));
            }
            if let Some((_, refresh, _)) = &served {
                entry.last_used = now;
                if *refresh {
                    entry.refreshing = Some(now);
                }
            }
        }
        match served {
            Some((reply, forward, stale)) => {
                if stale {
                    inner.counters.stale_answered += 1;
                } else {
                    inner.counters.answered += 1;
                }
                if forward {
                    inner.track((client, resolver, id), key, true, now);
                }
                Outcome::Answer { reply, forward }
            }
            None => {
                inner.entries.remove(&key);
                inner.counters.forwarded += 1;
                inner.track((client, resolver, id), key, false, now);
                Outcome::Forward
            }
        }
    }

    /// A UDP reply from `resolver` on its way to `client`. False when it
    /// answers a refresh, whose client was already answered from the cache,
    /// and must not be delivered.
    pub fn on_response(
        &self,
        client: SocketAddrV4,
        resolver: Ipv4Addr,
        message: &[u8],
        now: Instant,
    ) -> bool {
        if message.len() < HEADER_LEN
            || u16::from_be_bytes([message[2], message[3]]) & FLAG_RESPONSE == 0
        {
            return true;
        }
        let id = u16::from_be_bytes([message[0], message[1]]);
        let mut inner = self.inner.lock().unwrap();
        let Some(pending) = inner.pending.remove(&(client, resolver, id)) else {
            return true;
        };
        let verdict = read_question(message)
            .filter(|question| {
                question.name == pending.key.name && question.record_type == pending.key.record_type
            })
            .filter(|_| message.len() <= MESSAGE_LIMIT)
            .and_then(|question| Some((question.end, cacheable(message, question.end)?)));
        match verdict {
            Some((question_end, (ttl, negative))) => {
                if pending.refresh {
                    inner.counters.refreshed += 1;
                }
                inner.store(
                    pending.key,
                    message,
                    question_end,
                    ttl,
                    negative,
                    now,
                    self.stale_limit,
                );
            }
            // A failed refresh keeps the answer it was refreshing: during an
            // outage the old address is still the best one on offer.
            None => {
                if let Some(entry) = inner.entries.get_mut(&pending.key) {
                    entry.refreshing = None;
                }
            }
        }
        !pending.refresh
    }

    pub fn status(&self) -> Value {
        let inner = self.inner.lock().unwrap();
        json!({
            "entries": inner.entries.len(),
            "answered": inner.counters.answered,
            "staleAnswered": inner.counters.stale_answered,
            "refreshed": inner.counters.refreshed,
            "forwarded": inner.counters.forwarded,
        })
    }
}

impl Inner {
    fn track(&mut self, pending: PendingKey, key: Key, refresh: bool, now: Instant) {
        if self.pending.len() >= PENDING_LIMIT {
            self.pending
                .retain(|_, entry| now.saturating_duration_since(entry.sent) < REFRESH_TIMEOUT);
        }
        if self.pending.len() < PENDING_LIMIT {
            self.pending.insert(
                pending,
                Pending {
                    key,
                    sent: now,
                    refresh,
                },
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn store(
        &mut self,
        key: Key,
        message: &[u8],
        question_end: usize,
        ttl: u32,
        negative: bool,
        now: Instant,
        stale_limit: Duration,
    ) {
        if self.entries.len() >= ENTRY_LIMIT && !self.entries.contains_key(&key) {
            self.entries
                .retain(|_, entry| !entry.expired_for_good(now, stale_limit));
            if self.entries.len() >= ENTRY_LIMIT {
                if let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| key.clone())
                {
                    self.entries.remove(&oldest);
                }
            }
        }
        self.entries.insert(
            key,
            Entry {
                response: message.to_vec(),
                question_end,
                stored: now,
                ttl,
                negative,
                refreshing: None,
                last_used: now,
            },
        );
    }
}

/// Refreshed this close to expiry, so a name in steady use never expires.
fn refresh_ahead(ttl: Duration) -> Duration {
    (ttl / 10).max(Duration::from_secs(2))
}

struct Question {
    name: Box<[u8]>,
    record_type: u16,
    class: u16,
    end: usize,
}

fn read_question(message: &[u8]) -> Option<Question> {
    let mut at = HEADER_LEN;
    loop {
        let length = usize::from(*message.get(at)?);
        if length == 0 {
            at += 1;
            break;
        }
        // A question never uses compression.
        if length > 63 || at + length - HEADER_LEN > 255 {
            return None;
        }
        at += 1 + length;
    }
    let fixed = message.get(at..at + 4)?;
    Some(Question {
        // Length bytes are at most 63, below every letter, so they survive.
        name: message[HEADER_LEN..at]
            .to_ascii_lowercase()
            .into_boxed_slice(),
        record_type: u16::from_be_bytes([fixed[0], fixed[1]]),
        class: u16::from_be_bytes([fixed[2], fixed[3]]),
        end: at + 4,
    })
}

/// The key for a plain recursive query, or `None` for anything the cache
/// should not answer: several questions, zone transfers, or an EDNS option
/// such as client subnet or a cookie that a reused answer could not honour.
fn query_key(node: u8, message: &[u8]) -> Option<Key> {
    let field = |at: usize| {
        Some(u16::from_be_bytes([
            *message.get(at)?,
            *message.get(at + 1)?,
        ]))
    };
    let flags = field(2)?;
    if flags & (FLAG_RESPONSE | OPCODE_MASK) != 0
        || field(4)? != 1
        || field(6)? != 0
        || field(8)? != 0
    {
        return None;
    }
    let question = read_question(message)?;
    if question.class != CLASS_IN || matches!(question.record_type, 251..=255) {
        return None;
    }
    let mut flavour = 0;
    if flags & FLAG_RECURSION_DESIRED != 0 {
        flavour |= 1;
    }
    if flags & FLAG_CHECKING_DISABLED != 0 {
        flavour |= 2;
    }
    match field(10)? {
        0 => {}
        1 => {
            let opt = message.get(question.end..question.end + 11)?;
            if opt[0] != 0
                || u16::from_be_bytes([opt[1], opt[2]]) != TYPE_OPT
                || u16::from_be_bytes([opt[9], opt[10]]) != 0
            {
                return None;
            }
            flavour |= 4;
            if opt[7] & 0x80 != 0 {
                flavour |= 8;
            }
        }
        _ => return None,
    }
    Some(Key {
        node,
        name: question.name,
        record_type: question.record_type,
        flavour,
    })
}

struct Record<'a> {
    record_type: u16,
    ttl: u32,
    ttl_at: usize,
    data: &'a [u8],
    next: usize,
}

fn record(message: &[u8], at: usize) -> Option<Record<'_>> {
    let at = skip_name(message, at)?;
    let fixed = message.get(at..at + 10)?;
    let length = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
    Some(Record {
        record_type: u16::from_be_bytes([fixed[0], fixed[1]]),
        ttl: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        ttl_at: at + 4,
        data: message.get(at + 10..at + 10 + length)?,
        next: at + 10 + length,
    })
}

fn record_count(message: &[u8]) -> usize {
    (6..12)
        .step_by(2)
        .map(|at| usize::from(u16::from_be_bytes([message[at], message[at + 1]])))
        .sum()
}

/// How long a reply may be kept, and whether it says the name has no answer.
/// `None` for a reply never worth keeping: a failure, a truncated answer, a
/// TTL of zero, or a proxy's fake-IP address, which is only meaningful to the
/// proxy that invented it for as long as it remembers it.
fn cacheable(message: &[u8], question_end: usize) -> Option<(u32, bool)> {
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = flags & 0x000f;
    if flags & (FLAG_TRUNCATED | OPCODE_MASK) != 0 || (rcode != 0 && rcode != RCODE_NXDOMAIN) {
        return None;
    }
    let count = |at: usize| usize::from(u16::from_be_bytes([message[at], message[at + 1]]));
    let (answers, authorities) = (count(6), count(8));
    let mut at = question_end;
    let mut answer_ttl = u32::MAX;
    let mut negative_ttl = None;
    for index in 0..record_count(message) {
        let record = record(message, at)?;
        at = record.next;
        if record.record_type == TYPE_OPT {
            continue;
        }
        if index < answers {
            if record.record_type == TYPE_A && record.data.len() == 4 && is_fake_ip(record.data) {
                return None;
            }
            answer_ttl = answer_ttl.min(record.ttl);
        } else if index < answers + authorities
            && record.record_type == TYPE_SOA
            && record.data.len() >= 22
        {
            let minimum = &record.data[record.data.len() - 4..];
            let minimum = u32::from_be_bytes([minimum[0], minimum[1], minimum[2], minimum[3]]);
            negative_ttl = Some(record.ttl.min(minimum));
        }
    }
    let (ttl, negative) = if rcode == 0 && answers > 0 {
        (answer_ttl.min(TTL_LIMIT), false)
    } else {
        (negative_ttl?.min(NEGATIVE_TTL_LIMIT), true)
    };
    (ttl > 0).then_some((ttl, negative))
}

/// The fake-IP range sing-box, Clash and Xray answer from, 198.18.0.0/15.
fn is_fake_ip(address: &[u8]) -> bool {
    address[0] == 198 && address[1] & 0xfe == 18
}

/// The cached reply re-addressed to `query`: its id, its own spelling of the
/// name, and every TTL passed through `ttl_for`.
fn answer(entry: &Entry, query: &[u8], ttl_for: impl Fn(u32) -> u32) -> Option<Vec<u8>> {
    let mut reply = entry.response.clone();
    reply[..2].copy_from_slice(query.get(..2)?);
    reply[HEADER_LEN..entry.question_end]
        .copy_from_slice(query.get(HEADER_LEN..entry.question_end)?);
    let mut at = entry.question_end;
    for _ in 0..record_count(&reply) {
        let record = record(&reply, at)?;
        let (record_type, ttl, ttl_at, next) =
            (record.record_type, record.ttl, record.ttl_at, record.next);
        // An OPT record's TTL field holds flags, not a lifetime.
        if record_type != TYPE_OPT {
            reply[ttl_at..ttl_at + 4].copy_from_slice(&ttl_for(ttl).to_be_bytes());
        }
        at = next;
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: u8 = 0;
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 1);
    const LIMIT: Duration = Duration::from_secs(3600);

    fn client(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 203, 0, 2), port)
    }

    fn query(id: u16, name: &str) -> Vec<u8> {
        crate::dns::query(id, name).unwrap()
    }

    /// A reply to `query`: one A record per address, each `ttl` seconds.
    fn reply(query: &[u8], ttl: u32, addresses: &[[u8; 4]]) -> Vec<u8> {
        let mut message = query.to_vec();
        message[2] = 0x81;
        message[3] = 0x80;
        message[7] = addresses.len() as u8;
        for address in addresses {
            message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&[0, 4]);
            message.extend_from_slice(address);
        }
        message
    }

    fn nxdomain(query: &[u8], soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut message = query.to_vec();
        message[2] = 0x81;
        message[3] = 0x83;
        message[9] = 1;
        message.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1]);
        message.extend_from_slice(&soa_ttl.to_be_bytes());
        let mut data = vec![0xc0, 0x0c, 0xc0, 0x0c];
        for value in [1_u32, 7200, 3600, 1_209_600, minimum] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        message.extend_from_slice(&(data.len() as u16).to_be_bytes());
        message.extend_from_slice(&data);
        message
    }

    fn ttls(message: &[u8]) -> Vec<u32> {
        let mut at = read_question(message).unwrap().end;
        (0..record_count(message))
            .map(|_| {
                let record = record(message, at).unwrap();
                at = record.next;
                record.ttl
            })
            .collect()
    }

    /// Asks, lets the resolver answer with `response`, and returns what the
    /// client would receive from that exchange.
    fn learn(cache: &DnsCache, port: u16, query: &[u8], response: &[u8], now: Instant) -> bool {
        assert_eq!(
            cache.on_query(NODE, client(port), RESOLVER, query, now),
            Outcome::Forward
        );
        cache.on_response(client(port), RESOLVER, response, now)
    }

    fn answered(outcome: Outcome) -> (Vec<u8>, bool) {
        match outcome {
            Outcome::Answer { reply, forward } => (reply, forward),
            Outcome::Forward => panic!("expected an answer from the cache"),
        }
    }

    #[test]
    fn a_fresh_answer_is_reused_with_its_remaining_ttl_and_the_clients_id() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        assert!(learn(
            &cache,
            5000,
            &first,
            &reply(&first, 300, &[[93, 184, 216, 34]]),
            start
        ));

        let second = query(2, "Example.COM");
        let (reply, forward) = answered(cache.on_query(
            NODE,
            client(5001),
            RESOLVER,
            &second,
            start + Duration::from_secs(100),
        ));
        assert!(!forward);
        assert_eq!(&reply[..2], &[0, 2]);
        // The client's own spelling, so a resolver library comparing names
        // byte for byte accepts it.
        assert_eq!(
            read_question(&reply).unwrap().end,
            read_question(&second).unwrap().end
        );
        assert_eq!(&reply[12..17], &second[12..17]);
        assert_eq!(ttls(&reply), [200]);
    }

    #[test]
    fn an_expired_answer_is_served_at_once_and_refreshed_behind_it() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        assert!(learn(
            &cache,
            5000,
            &first,
            &reply(&first, 60, &[[1, 1, 1, 1]]),
            start
        ));

        let later = start + Duration::from_secs(120);
        let second = query(2, "example.com");
        let (reply_now, forward) =
            answered(cache.on_query(NODE, client(5001), RESOLVER, &second, later));
        assert!(forward);
        assert_eq!(ttls(&reply_now), [STALE_TTL]);
        // A second lookup while the refresh is out is answered without
        // sending another.
        let (_, again) = answered(cache.on_query(
            NODE,
            client(5002),
            RESOLVER,
            &query(3, "example.com"),
            later,
        ));
        assert!(!again);

        // The refresh is stored and swallowed: its client already has an answer.
        let refreshed = reply(&second, 60, &[[2, 2, 2, 2]]);
        assert!(!cache.on_response(client(5001), RESOLVER, &refreshed, later));
        let (current, _) = answered(cache.on_query(
            NODE,
            client(5003),
            RESOLVER,
            &query(4, "example.com"),
            later,
        ));
        assert_eq!(&current[current.len() - 4..], &[2, 2, 2, 2]);
        assert_eq!(cache.status()["refreshed"], 1);
        assert_eq!(cache.status()["staleAnswered"], 2);
    }

    #[test]
    fn a_failed_refresh_keeps_the_old_answer() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        learn(
            &cache,
            5000,
            &first,
            &reply(&first, 10, &[[1, 1, 1, 1]]),
            start,
        );
        let later = start + Duration::from_secs(30);
        let second = query(2, "example.com");
        answered(cache.on_query(NODE, client(5001), RESOLVER, &second, later));
        let mut servfail = second.clone();
        servfail[2] = 0x81;
        servfail[3] = 0x82;
        assert!(!cache.on_response(client(5001), RESOLVER, &servfail, later));
        // And the next lookup may try again straight away.
        let (_, forward) = answered(cache.on_query(
            NODE,
            client(5002),
            RESOLVER,
            &query(3, "example.com"),
            later,
        ));
        assert!(forward);
    }

    #[test]
    fn a_lost_refresh_is_sent_again_after_its_timeout() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        learn(
            &cache,
            5000,
            &first,
            &reply(&first, 10, &[[1, 1, 1, 1]]),
            start,
        );
        let later = start + Duration::from_secs(30);
        let (_, forward) = answered(cache.on_query(
            NODE,
            client(5001),
            RESOLVER,
            &query(2, "example.com"),
            later,
        ));
        assert!(forward);
        let (_, forward) = answered(cache.on_query(
            NODE,
            client(5002),
            RESOLVER,
            &query(3, "example.com"),
            later + REFRESH_TIMEOUT,
        ));
        assert!(forward);
    }

    #[test]
    fn an_answer_in_steady_use_is_refreshed_before_it_expires() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        learn(
            &cache,
            5000,
            &first,
            &reply(&first, 100, &[[1, 1, 1, 1]]),
            start,
        );
        let early = answered(cache.on_query(
            NODE,
            client(5001),
            RESOLVER,
            &query(2, "example.com"),
            start,
        ));
        assert!(!early.1);
        let late = start + Duration::from_secs(95);
        let (reply, forward) =
            answered(cache.on_query(NODE, client(5002), RESOLVER, &query(3, "example.com"), late));
        assert!(forward);
        assert_eq!(ttls(&reply), [5]);
    }

    #[test]
    fn nothing_is_served_past_the_stale_limit() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        learn(
            &cache,
            5000,
            &first,
            &reply(&first, 60, &[[1, 1, 1, 1]]),
            start,
        );
        let outcome = cache.on_query(
            NODE,
            client(5001),
            RESOLVER,
            &query(2, "example.com"),
            start + Duration::from_secs(60) + LIMIT,
        );
        assert_eq!(outcome, Outcome::Forward);
    }

    #[test]
    fn each_node_keeps_its_own_answers() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "matchmaking.example");
        learn(
            &cache,
            5000,
            &first,
            &reply(&first, 300, &[[1, 1, 1, 1]]),
            start,
        );
        let other_node = cache.on_query(
            1,
            client(5001),
            RESOLVER,
            &query(2, "matchmaking.example"),
            start,
        );
        assert_eq!(other_node, Outcome::Forward);
    }

    #[test]
    fn an_edns_query_never_gets_an_answer_learned_without_edns() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "example.com");
        learn(
            &cache,
            5000,
            &first,
            &reply(&first, 300, &[[1, 1, 1, 1]]),
            start,
        );
        let mut edns = query(2, "example.com");
        edns[11] = 1;
        edns.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            cache.on_query(NODE, client(5001), RESOLVER, &edns, start),
            Outcome::Forward
        );
        // One carrying an option (client subnet, a cookie) is never cached.
        let mut subnet = query(3, "example.com");
        subnet[11] = 1;
        subnet.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 4, 0, 8, 0, 0]);
        assert_eq!(query_key(NODE, &subnet), None);
    }

    #[test]
    fn fake_ip_failures_truncation_and_zero_ttl_are_never_kept() {
        let start = Instant::now();
        let first = query(1, "example.com");
        let mut truncated = reply(&first, 300, &[[1, 1, 1, 1]]);
        truncated[2] |= 0x02;
        let mut servfail = first.clone();
        servfail[2] = 0x81;
        servfail[3] = 0x82;
        for response in [
            reply(&first, 300, &[[198, 19, 0, 7]]),
            reply(&first, 0, &[[1, 1, 1, 1]]),
            truncated,
            servfail,
        ] {
            let cache = DnsCache::new(LIMIT);
            assert!(learn(&cache, 5000, &first, &response, start));
            assert_eq!(cache.status()["entries"], 0);
        }
    }

    #[test]
    fn no_such_name_is_kept_briefly_and_never_served_stale() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        let first = query(1, "missing.example");
        learn(&cache, 5000, &first, &nxdomain(&first, 3600, 900), start);
        let (reply, forward) = answered(cache.on_query(
            NODE,
            client(5001),
            RESOLVER,
            &query(2, "missing.example"),
            start + Duration::from_secs(10),
        ));
        assert!(!forward);
        assert_eq!(reply[3] & 0x0f, 3);
        assert_eq!(ttls(&reply), [50]);
        let expired = start + Duration::from_secs(u64::from(NEGATIVE_TTL_LIMIT));
        let outcome = cache.on_query(
            NODE,
            client(5002),
            RESOLVER,
            &query(3, "missing.example"),
            expired,
        );
        assert_eq!(outcome, Outcome::Forward);
    }

    #[test]
    fn a_reply_the_cache_did_not_send_for_is_delivered_untouched() {
        let cache = DnsCache::new(LIMIT);
        let first = query(1, "example.com");
        assert!(cache.on_response(
            client(5000),
            RESOLVER,
            &reply(&first, 300, &[[1, 1, 1, 1]]),
            Instant::now()
        ));
        assert_eq!(cache.status()["entries"], 0);
    }

    #[test]
    fn the_answer_packet_goes_back_from_the_resolver_with_valid_checksums() {
        let message = query(7, "example.com");
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 203, 0, 2, 192, 168, 1, 1,
        ];
        packet.extend_from_slice(&[0xd4, 0x31, 0, 53]);
        packet.extend_from_slice(&((8 + message.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&message);
        let total = packet.len() as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        let query = datagram(&packet).unwrap();
        assert_eq!(
            query.destination,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 53)
        );

        let answer = reply_packet(&query, b"answer");
        let parsed = datagram(&answer).unwrap();
        assert_eq!(parsed.source, query.destination);
        assert_eq!(parsed.destination, query.source);
        assert_eq!(parsed.message, b"answer");
        assert_eq!(internet_checksum(&answer[..20]), 0);
        let mut summed = answer[12..20].to_vec();
        summed.extend_from_slice(&[0, 17]);
        summed.extend_from_slice(&answer[24..26]);
        summed.extend_from_slice(&answer[20..]);
        assert_eq!(internet_checksum(&summed), 0);
    }

    #[test]
    fn a_full_cache_evicts_what_is_least_recently_used() {
        let cache = DnsCache::new(LIMIT);
        let start = Instant::now();
        for index in 0..ENTRY_LIMIT + 1 {
            let name = format!("n{index}.example");
            let asked = query(1, &name);
            let now = start + Duration::from_millis(index as u64);
            learn(
                &cache,
                5000,
                &asked,
                &reply(&asked, 300, &[[1, 1, 1, 1]]),
                now,
            );
        }
        assert_eq!(cache.status()["entries"], ENTRY_LIMIT);
        let first = cache.on_query(NODE, client(5001), RESOLVER, &query(2, "n0.example"), start);
        assert_eq!(first, Outcome::Forward);
    }
}
