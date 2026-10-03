//! A capture-wide verdict for outbound IPv4 fragments, including reordered arrivals.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const PENDING_TTL: Duration = Duration::from_millis(100);
const VERDICT_TTL: Duration = Duration::from_secs(5);
const MAX_DATAGRAMS: usize = 64;
const MAX_PIECES: usize = 64;
const MAX_PENDING_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Tunnel(Option<Ipv4Addr>),
    Bypass,
    Drop,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Key([u8; 4], [u8; 4], u8, u16);

impl Key {
    fn of(packet: &[u8]) -> Self {
        Self(
            packet[12..16].try_into().unwrap(),
            packet[16..20].try_into().unwrap(),
            packet[9],
            u16::from_be_bytes([packet[4], packet[5]]),
        )
    }
}

pub struct Ticket {
    key: Key,
    generation: u64,
}

struct Datagram<A> {
    started: Instant,
    generation: u64,
    route: Option<Route>,
    waiting: Vec<(Vec<u8>, A)>,
}

pub enum Action {
    Route(Route),
    Held,
}

pub struct FragmentRouter<A> {
    datagrams: HashMap<Key, Datagram<A>>,
    generation: u64,
    pending_bytes: usize,
    discarded: u64,
}

impl<A> Default for FragmentRouter<A> {
    fn default() -> Self {
        Self {
            datagrams: HashMap::new(),
            generation: 0,
            pending_bytes: 0,
            discarded: 0,
        }
    }
}

impl<A> FragmentRouter<A> {
    pub fn expire(&mut self, now: Instant) {
        self.datagrams.retain(|_, datagram| {
            let ttl = if datagram.route.is_some() {
                VERDICT_TTL
            } else {
                PENDING_TTL
            };
            if now.saturating_duration_since(datagram.started) < ttl {
                return true;
            }
            self.pending_bytes -= datagram
                .waiting
                .iter()
                .map(|(packet, _)| packet.len())
                .sum::<usize>();
            self.discarded += datagram.waiting.len() as u64;
            false
        });
    }

    fn make_room(&mut self, key: Key) {
        if !self.datagrams.contains_key(&key) && self.datagrams.len() >= MAX_DATAGRAMS {
            let oldest = *self
                .datagrams
                .iter()
                .min_by_key(|(_, datagram)| datagram.started)
                .unwrap()
                .0;
            let old = self.datagrams.remove(&oldest).unwrap();
            self.pending_bytes -= old
                .waiting
                .iter()
                .map(|(packet, _)| packet.len())
                .sum::<usize>();
            self.discarded += old.waiting.len() as u64;
        }
    }

    /// Reserve before classifying or sending the first piece. Other readers must wait for its verdict.
    pub fn begin(&mut self, first: &[u8], now: Instant) -> Ticket {
        self.expire(now);
        let key = Key::of(first);
        self.make_room(key);
        self.generation = self.generation.wrapping_add(1).max(1);
        let waiting = match self.datagrams.remove(&key) {
            Some(old) if old.generation == 0 => old.waiting,
            Some(old) => {
                self.pending_bytes -= old
                    .waiting
                    .iter()
                    .map(|(packet, _)| packet.len())
                    .sum::<usize>();
                self.discarded += old.waiting.len() as u64;
                Vec::new()
            }
            None => Vec::new(),
        };
        self.datagrams.insert(
            key,
            Datagram {
                started: now,
                generation: self.generation,
                route: None,
                waiting,
            },
        );
        Ticket {
            key,
            generation: self.generation,
        }
    }

    pub fn later(&mut self, packet: &[u8], address: A, now: Instant) -> Action {
        self.expire(now);
        let key = Key::of(packet);
        self.make_room(key);
        let datagram = self.datagrams.entry(key).or_insert_with(|| Datagram {
            started: now,
            generation: 0,
            route: None,
            waiting: Vec::new(),
        });
        if let Some(route) = datagram.route {
            return Action::Route(route);
        }
        if datagram.waiting.len() >= MAX_PIECES
            || self.pending_bytes + packet.len() > MAX_PENDING_BYTES
        {
            self.pending_bytes -= datagram
                .waiting
                .iter()
                .map(|(packet, _)| packet.len())
                .sum::<usize>();
            self.discarded += datagram.waiting.len() as u64;
            datagram.waiting.clear();
            datagram.route = Some(Route::Drop);
            return Action::Route(Route::Drop);
        }
        self.pending_bytes += packet.len();
        datagram.waiting.push((packet.to_vec(), address));
        Action::Held
    }

    pub fn finish(&mut self, ticket: Ticket, route: Route, now: Instant) -> Vec<(Vec<u8>, A)> {
        let Some(datagram) = self.datagrams.get_mut(&ticket.key) else {
            return Vec::new();
        };
        if datagram.generation != ticket.generation {
            return Vec::new();
        }
        // Overflow has already abandoned this datagram; do not release another partial set.
        let route = if datagram.route == Some(Route::Drop) {
            Route::Drop
        } else {
            route
        };
        datagram.route = Some(route);
        datagram.started = now;
        let waiting = std::mem::take(&mut datagram.waiting);
        self.pending_bytes -= waiting
            .iter()
            .map(|(packet, _)| packet.len())
            .sum::<usize>();
        if route == Route::Drop {
            self.discarded += waiting.len() as u64;
            Vec::new()
        } else {
            waiting
        }
    }

    pub fn take_discarded(&mut self) -> u64 {
        std::mem::take(&mut self.discarded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn packet(id: u16, later: bool) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&(if later { 1_u16 } else { 0x2000_u16 }).to_be_bytes());
        packet[9] = 17;
        packet[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 1]);
        packet
    }

    #[test]
    fn another_worker_waits_for_the_first_workers_verdict() {
        let router = Arc::new(Mutex::new(FragmentRouter::default()));
        let now = Instant::now();
        let ticket = router.lock().unwrap().begin(&packet(1, false), now);
        let other = Arc::clone(&router);
        std::thread::spawn(move || {
            assert!(matches!(
                other.lock().unwrap().later(&packet(1, true), 7, now),
                Action::Held
            ));
        })
        .join()
        .unwrap();
        let waiting = router
            .lock()
            .unwrap()
            .finish(ticket, Route::Tunnel(None), now);
        assert_eq!(waiting, vec![(packet(1, true), 7)]);
        assert!(matches!(
            router.lock().unwrap().later(&packet(1, true), 8, now),
            Action::Route(Route::Tunnel(None))
        ));
    }

    #[test]
    fn later_before_first_follows_the_dns_redirect_or_known_bypass() {
        for route in [
            Route::Tunnel(Some(Ipv4Addr::new(192, 168, 1, 1))),
            Route::Bypass,
        ] {
            let mut router = FragmentRouter::default();
            let now = Instant::now();
            assert!(matches!(
                router.later(&packet(1, true), 1, now),
                Action::Held
            ));
            let ticket = router.begin(&packet(1, false), now);
            assert_eq!(
                router.finish(ticket, route, now),
                vec![(packet(1, true), 1)]
            );
            assert!(
                matches!(router.later(&packet(1, true), 2, now), Action::Route(actual) if actual == route)
            );
        }
    }

    #[test]
    fn unknown_fragments_expire_without_bypassing_and_reused_ids_replace_the_verdict() {
        let mut router = FragmentRouter::default();
        let now = Instant::now();
        router.later(&packet(1, true), (), now);
        router.expire(now + PENDING_TTL);
        assert_eq!(router.take_discarded(), 1);
        assert_eq!(router.pending_bytes, 0);
        let old = router.begin(&packet(1, false), now);
        let newer = router.begin(&packet(1, false), now);
        assert!(router.finish(old, Route::Bypass, now).is_empty());
        assert!(matches!(
            router.later(&packet(1, true), (), now),
            Action::Held
        ));
        assert_eq!(router.finish(newer, Route::Tunnel(None), now).len(), 1);
    }

    #[test]
    fn pending_storage_is_bounded_and_a_failed_first_discards_its_waiters() {
        let mut router = FragmentRouter::default();
        let now = Instant::now();
        for id in 0..100 {
            router.later(&packet(id, true), (), now);
        }
        assert_eq!(router.datagrams.len(), MAX_DATAGRAMS);
        assert_eq!(router.take_discarded(), 36);
        let ticket = router.begin(&packet(99, false), now);
        assert!(router.finish(ticket, Route::Drop, now).is_empty());
        assert_eq!(router.take_discarded(), 1);
        assert!(matches!(
            router.later(&packet(99, true), (), now),
            Action::Route(Route::Drop)
        ));
    }

    #[test]
    fn overflow_cannot_flush_a_partial_datagram() {
        let mut router = FragmentRouter::default();
        let now = Instant::now();
        let ticket = router.begin(&packet(1, false), now);
        for _ in 0..MAX_PIECES {
            router.later(&packet(1, true), (), now);
        }
        assert!(matches!(
            router.later(&packet(1, true), (), now),
            Action::Route(Route::Drop)
        ));
        assert!(router.finish(ticket, Route::Tunnel(None), now).is_empty());
        assert_eq!(router.pending_bytes, 0);
        assert_eq!(router.take_discarded(), MAX_PIECES as u64);
    }

    #[test]
    fn byte_limit_discards_waiters_without_partial_flush() {
        let mut router = FragmentRouter::default();
        let now = Instant::now();
        let ticket = router.begin(&packet(1, false), now);
        let mut large = packet(1, true);
        large.resize(65_535, 0);
        for _ in 0..16 {
            assert!(matches!(router.later(&large, (), now), Action::Held));
        }
        assert!(matches!(
            router.later(&large, (), now),
            Action::Route(Route::Drop)
        ));
        assert!(router.finish(ticket, Route::Tunnel(None), now).is_empty());
        assert_eq!(router.pending_bytes, 0);
        assert_eq!(router.take_discarded(), 16);
    }
}
