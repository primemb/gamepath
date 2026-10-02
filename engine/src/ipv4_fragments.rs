//! IPv4 fragments in split mode, in both directions.
//!
//! Only the first fragment carries the ports a flow is matched by, and
//! WinDivert's checksum helper refuses a TCP or UDP fragment outright.
//!
//! Inbound, the relay's tunnel interface fragments any reply larger than its
//! MTU, which a game negotiating 1492-byte packets (RakNet, used by Rust)
//! triggers on every large snapshot. Observed live: every fragmented reply
//! from a Rust server was lost, half as injection errors and half as "no
//! flow", and the join never completed. [`Reassembler`] rebuilds the datagram
//! so the injector delivers it whole, as a VPN adapter would.
//!
//! Outbound, Windows fragments a datagram larger than the path MTU before
//! capture sees it. [`FragmentTrail`] sends the later fragments wherever the
//! first one went, so a selected datagram is not split between the tunnel and
//! the open network, where neither half can be reassembled.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// The relay sends a datagram's fragments back to back. One still incomplete
/// after this has lost a piece, or is too late to matter to a game.
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DATAGRAMS: usize = 64;
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 64;
const MAX_DATAGRAM_LENGTH: usize = 65_535;
const MORE_FRAGMENTS: u16 = 0x2000;
const DONT_FRAGMENT: u16 = 0x4000;
const OFFSET_MASK: u16 = 0x1fff;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct DatagramKey {
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    identification: u16,
}

struct Partial {
    started: Instant,
    header: Option<Vec<u8>>,
    pieces: Vec<(usize, Vec<u8>)>,
    end: Option<usize>,
}

#[derive(Default)]
pub struct Reassembler {
    partials: HashMap<DatagramKey, Partial>,
    discarded: u64,
}

impl DatagramKey {
    fn of(packet: &[u8]) -> Self {
        Self {
            source: packet[12..16].try_into().unwrap(),
            destination: packet[16..20].try_into().unwrap(),
            protocol: packet[9],
            identification: u16::from_be_bytes([packet[4], packet[5]]),
        }
    }
}

fn flags(packet: &[u8]) -> u16 {
    u16::from_be_bytes([packet[6], packet[7]])
}

pub fn is_fragment(packet: &[u8]) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4 && flags(packet) & (MORE_FRAGMENTS | OFFSET_MASK) != 0
}

/// A fragment after the first: no transport header, so no ports.
pub fn is_later_fragment(packet: &[u8]) -> bool {
    is_fragment(packet) && flags(packet) & OFFSET_MASK != 0
}

pub fn is_first_fragment(packet: &[u8]) -> bool {
    is_fragment(packet) && flags(packet) & OFFSET_MASK == 0
}

/// Corrects the TCP or UDP checksum in `rewritten` after its IPv4 addresses
/// were changed from `original`'s. Used where the checksum covers bytes this
/// packet does not hold, a first fragment or the header an ICMP error quotes,
/// so it is updated incrementally (RFC 1624) for the address words that
/// changed. False when the checksum field itself is not in the packet.
pub fn readdress_transport_checksum(rewritten: &mut [u8], original: &[u8]) -> bool {
    let header = usize::from(rewritten[0] & 0x0f) * 4;
    let offset = match rewritten[9] {
        6 => header + 16,
        17 => header + 6,
        _ => return true,
    };
    if rewritten.len() < offset + 2 {
        return false;
    }
    let checksum = u16::from_be_bytes([rewritten[offset], rewritten[offset + 1]]);
    // A UDP checksum of zero means none was computed.
    if rewritten[9] == 17 && checksum == 0 {
        return true;
    }
    let mut sum = u32::from(!checksum);
    for word in (12..20).step_by(2) {
        sum += u32::from(!u16::from_be_bytes([original[word], original[word + 1]]));
        sum += u32::from(u16::from_be_bytes([rewritten[word], rewritten[word + 1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let mut updated = !(sum as u16);
    if rewritten[9] == 17 && updated == 0 {
        updated = 0xffff;
    }
    rewritten[offset..offset + 2].copy_from_slice(&updated.to_be_bytes());
    true
}

/// How long the later fragments of a datagram keep following its first.
const TRAIL_TTL: Duration = Duration::from_secs(5);
const TRAIL_LIMIT: usize = 64;

/// Where each recent outbound datagram's first fragment went: into the tunnel
/// (with the resolver a redirected lookup was rewritten to, if it was) or not.
#[derive(Default)]
pub struct FragmentTrail {
    datagrams: VecDeque<(DatagramKey, Option<Option<Ipv4Addr>>, Instant)>,
}

impl FragmentTrail {
    /// Records a first fragment's verdict, replacing any earlier datagram
    /// with the same identification: IP IDs are reused, and a later fragment
    /// must follow the newest datagram, never one that already went.
    pub fn record(&mut self, first: &[u8], tunnelled: Option<Option<Ipv4Addr>>, now: Instant) {
        let key = DatagramKey::of(first);
        self.datagrams.retain(|(datagram, _, seen)| {
            *datagram != key && now.duration_since(*seen) < TRAIL_TTL
        });
        if self.datagrams.len() >= TRAIL_LIMIT {
            self.datagrams.pop_front();
        }
        self.datagrams.push_back((key, tunnelled, now));
    }

    /// `Some(redirect)` when `later` belongs to a datagram that went into the
    /// tunnel.
    pub fn lookup(&self, later: &[u8], now: Instant) -> Option<Option<Ipv4Addr>> {
        let key = DatagramKey::of(later);
        self.datagrams
            .iter()
            .find(|(datagram, _, seen)| *datagram == key && now.duration_since(*seen) < TRAIL_TTL)
            .and_then(|(_, tunnelled, _)| *tunnelled)
    }
}

impl Reassembler {
    /// Takes one fragment and returns the whole datagram once its last
    /// missing piece arrives.
    pub fn push(&mut self, packet: &[u8], now: Instant) -> Option<Vec<u8>> {
        let before = self.partials.len();
        self.partials
            .retain(|_, partial| now.duration_since(partial.started) < FRAGMENT_TIMEOUT);
        self.discarded += (before - self.partials.len()) as u64;
        let header_length = usize::from(packet[0] & 0x0f) * 4;
        let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_length < 20 || total_length < header_length || total_length > packet.len() {
            self.discarded += 1;
            return None;
        }
        let flags = flags(packet);
        let offset = usize::from(flags & OFFSET_MASK) * 8;
        let more = flags & MORE_FRAGMENTS != 0;
        let payload = &packet[header_length..total_length];
        let key = DatagramKey::of(packet);
        let end = offset + payload.len();
        if (more && payload.len() % 8 != 0) || header_length + end > MAX_DATAGRAM_LENGTH {
            self.discard(&key);
            return None;
        }
        if !self.partials.contains_key(&key) && self.partials.len() >= MAX_DATAGRAMS {
            let oldest = self
                .partials
                .iter()
                .min_by_key(|(_, partial)| partial.started)
                .map(|(key, _)| *key)?;
            self.discard(&oldest);
        }
        let partial = self.partials.entry(key).or_insert_with(|| Partial {
            started: now,
            header: None,
            pieces: Vec::new(),
            end: None,
        });
        // Multipath delivers the same fragment more than once; only an exact
        // copy is a duplicate. A different piece at the same offset is a
        // conflict, and the datagram is not trusted.
        if let Some((_, known)) = partial.pieces.iter().find(|(start, _)| *start == offset) {
            if known.as_slice() != payload {
                self.discard(&key);
            }
            return None;
        }
        if !more {
            if partial.end.is_some_and(|known| known != end) {
                self.discard(&key);
                return None;
            }
            partial.end = Some(end);
        }
        if offset == 0 {
            partial.header = Some(packet[..header_length].to_vec());
        }
        partial.pieces.push((offset, payload.to_vec()));
        if partial.pieces.len() > MAX_FRAGMENTS_PER_DATAGRAM {
            self.discard(&key);
            return None;
        }
        let (Some(header), Some(end)) = (&partial.header, partial.end) else {
            return None;
        };
        // The first fragment's header is the one the datagram keeps, and its
        // options may make it longer than the fragment that completed it.
        if header.len() + end > MAX_DATAGRAM_LENGTH {
            self.discard(&key);
            return None;
        }
        partial.pieces.sort_unstable_by_key(|(start, _)| *start);
        let mut covered = 0;
        for (start, piece) in &partial.pieces {
            match (*start).cmp(&covered) {
                std::cmp::Ordering::Greater => return None,
                std::cmp::Ordering::Less => {
                    // Overlapping fragments are never produced by a router
                    // fragmenting honestly, so the datagram is not trusted.
                    self.discard(&key);
                    return None;
                }
                std::cmp::Ordering::Equal => covered += piece.len(),
            }
        }
        if covered != end {
            self.discard(&key);
            return None;
        }
        let mut datagram = Vec::with_capacity(header.len() + end);
        datagram.extend_from_slice(header);
        for (_, piece) in &partial.pieces {
            datagram.extend_from_slice(piece);
        }
        let length = datagram.len() as u16;
        let dont_fragment = flags_of_header(header) & DONT_FRAGMENT;
        datagram[2..4].copy_from_slice(&length.to_be_bytes());
        datagram[6..8].copy_from_slice(&dont_fragment.to_be_bytes());
        self.partials.remove(&key);
        Some(datagram)
    }

    /// Datagrams given up on since the last call: timed out, evicted,
    /// malformed or conflicting.
    pub fn take_discarded(&mut self) -> u64 {
        std::mem::take(&mut self.discarded)
    }

    fn discard(&mut self, key: &DatagramKey) {
        if self.partials.remove(key).is_some() {
            self.discarded += 1;
        }
    }
}

fn flags_of_header(header: &[u8]) -> u16 {
    u16::from_be_bytes([header[6], header[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(payload_length: usize) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + payload_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload_length) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[79, 137, 98, 19]);
        packet[16..20].copy_from_slice(&[10, 203, 0, 2]);
        for (index, byte) in packet[20..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        packet
    }

    /// Splits a datagram the way a router does, into pieces of `size` bytes.
    fn fragment(packet: &[u8], size: usize) -> Vec<Vec<u8>> {
        let payload = &packet[20..];
        payload
            .chunks(size)
            .enumerate()
            .map(|(index, piece)| {
                let mut fragment = packet[..20].to_vec();
                fragment.extend_from_slice(piece);
                let length = fragment.len() as u16;
                fragment[2..4].copy_from_slice(&length.to_be_bytes());
                let more = (index + 1) * size < payload.len();
                let flags = ((index * size / 8) as u16) | if more { MORE_FRAGMENTS } else { 0 };
                fragment[6..8].copy_from_slice(&flags.to_be_bytes());
                fragment
            })
            .collect()
    }

    #[test]
    fn a_reply_split_by_the_relay_is_rebuilt_whole() {
        let original = datagram(1472);
        let pieces = fragment(&original, 1264);
        assert!(pieces.iter().all(|piece| is_fragment(piece)));
        assert!(!is_fragment(&original));
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        assert_eq!(reassembler.push(&pieces[0], now), None);
        assert_eq!(reassembler.push(&pieces[1], now), Some(original));
        assert!(reassembler.partials.is_empty());
    }

    #[test]
    fn fragments_arriving_out_of_order_or_twice_still_rebuild_once() {
        let original = datagram(3000);
        let pieces = fragment(&original, 1000);
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        assert_eq!(reassembler.push(&pieces[2], now), None);
        assert_eq!(reassembler.push(&pieces[2], now), None);
        assert_eq!(reassembler.push(&pieces[0], now), None);
        assert_eq!(reassembler.push(&pieces[1], now), Some(original));
        assert_eq!(reassembler.push(&pieces[1], now), None);
    }

    #[test]
    fn a_datagram_missing_a_piece_is_forgotten() {
        let pieces = fragment(&datagram(3000), 1000);
        let mut reassembler = Reassembler::default();
        let start = Instant::now();
        reassembler.push(&pieces[0], start);
        reassembler.push(&pieces[2], start);
        assert_eq!(reassembler.push(&pieces[1], start + FRAGMENT_TIMEOUT), None);
        assert_eq!(reassembler.partials.len(), 1, "only the late piece remains");
        assert_eq!(reassembler.take_discarded(), 1);
    }

    #[test]
    fn overlapping_fragments_are_not_trusted() {
        let original = datagram(2000);
        let pieces = fragment(&original, 1000);
        let mut overlapping = fragment(&original, 504)[1].clone();
        overlapping[6..8].copy_from_slice(&((504 / 8) as u16 | MORE_FRAGMENTS).to_be_bytes());
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        reassembler.push(&pieces[0], now);
        reassembler.push(&overlapping, now);
        assert_eq!(reassembler.push(&pieces[1], now), None);
    }

    #[test]
    fn pending_datagrams_are_bounded() {
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        for identification in 0..(MAX_DATAGRAMS as u16 * 2) {
            let mut first = fragment(&datagram(2000), 1000)[0].clone();
            first[4..6].copy_from_slice(&identification.to_be_bytes());
            reassembler.push(&first, now);
        }
        assert_eq!(reassembler.partials.len(), MAX_DATAGRAMS);
    }

    /// The full UDP checksum, pseudo-header included.
    fn udp_checksum(packet: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let mut add = |bytes: &[u8]| {
            for pair in bytes.chunks(2) {
                sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
            }
        };
        let mut udp = packet[20..].to_vec();
        udp[6..8].fill(0);
        add(&packet[12..20]);
        add(&[0, 17]);
        add(&(udp.len() as u16).to_be_bytes());
        add(&udp);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn a_readdressed_first_fragment_keeps_a_valid_datagram_checksum() {
        let mut original = datagram(1472);
        let checksum = udp_checksum(&original);
        original[26..28].copy_from_slice(&checksum.to_be_bytes());
        let first = fragment(&original, 1264).remove(0);
        let mut rewritten = first.clone();
        rewritten[12..16].copy_from_slice(&[10, 203, 0, 9]);
        assert!(readdress_transport_checksum(&mut rewritten, &first));
        let mut whole = original.clone();
        whole[12..16].copy_from_slice(&[10, 203, 0, 9]);
        assert_eq!(
            u16::from_be_bytes([rewritten[26], rewritten[27]]),
            udp_checksum(&whole)
        );
    }

    #[test]
    fn later_fragments_follow_the_first_until_it_is_forgotten() {
        let pieces = fragment(&datagram(3000), 1000);
        assert!(is_first_fragment(&pieces[0]) && !is_later_fragment(&pieces[0]));
        assert!(is_later_fragment(&pieces[1]));
        let mut trail = FragmentTrail::default();
        let now = Instant::now();
        assert_eq!(trail.lookup(&pieces[1], now), None);
        trail.record(&pieces[0], Some(None), now);
        assert_eq!(trail.lookup(&pieces[1], now), Some(None));
        assert_eq!(trail.lookup(&pieces[2], now + TRAIL_TTL), None);
    }

    #[test]
    fn a_reused_ip_id_follows_the_newest_datagram() {
        let pieces = fragment(&datagram(3000), 1000);
        let mut trail = FragmentTrail::default();
        let now = Instant::now();
        trail.record(&pieces[0], Some(None), now);
        // A new datagram with the same ID whose first fragment stayed local.
        trail.record(&pieces[0], None, now);
        assert_eq!(trail.lookup(&pieces[1], now), None);
        trail.record(&pieces[0], Some(Some(Ipv4Addr::new(8, 8, 8, 8))), now);
        assert_eq!(
            trail.lookup(&pieces[1], now),
            Some(Some(Ipv4Addr::new(8, 8, 8, 8)))
        );
    }

    #[test]
    fn a_first_fragment_too_short_to_hold_its_checksum_is_reported() {
        let mut first = fragment(&datagram(2000), 1000)[0].clone();
        first[9] = 6;
        first.truncate(20 + 16);
        let original = first.clone();
        assert!(!readdress_transport_checksum(&mut first, &original));
    }

    #[test]
    fn a_conflicting_copy_of_a_fragment_discards_the_datagram() {
        let original = datagram(2000);
        let pieces = fragment(&original, 1000);
        let mut conflicting = pieces[0].clone();
        conflicting[30] ^= 0xff;
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        reassembler.push(&pieces[0], now);
        assert_eq!(
            reassembler.push(&pieces[0], now),
            None,
            "an exact copy is ignored"
        );
        assert_eq!(reassembler.take_discarded(), 0);
        reassembler.push(&conflicting, now);
        assert_eq!(reassembler.take_discarded(), 1);
        assert_eq!(reassembler.push(&pieces[1], now), None);
    }

    #[test]
    fn the_rebuilt_datagram_keeps_the_first_fragments_flags() {
        let mut original = datagram(2000);
        original[6..8].copy_from_slice(&DONT_FRAGMENT.to_be_bytes());
        let mut pieces = fragment(&datagram(2000), 1000);
        pieces[0][6..8].copy_from_slice(&(DONT_FRAGMENT | MORE_FRAGMENTS).to_be_bytes());
        let mut reassembler = Reassembler::default();
        let now = Instant::now();
        reassembler.push(&pieces[1], now);
        let rebuilt = reassembler.push(&pieces[0], now).unwrap();
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn a_truncated_fragment_is_ignored() {
        let mut first = fragment(&datagram(2000), 1000)[0].clone();
        first.truncate(500);
        assert_eq!(Reassembler::default().push(&first, Instant::now()), None);
    }
}
