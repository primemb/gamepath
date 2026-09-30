//! Loss repair for relay frames.
//!
//! Every relay frame already carries a sequence number, so a receiver knows
//! exactly which packets it is missing. A repair frame is the XOR of a small
//! group of recent data packets: when one member of the group is lost on every
//! path, the receiver rebuilds it from the repair and the members that did
//! arrive. Game traffic is UDP and nothing else would ever resend it; for TCP
//! the rebuild beats a retransmit timeout by hundreds of milliseconds.
//!
//! Data packets are never held back or re-encoded. They leave the moment they
//! are captured, exactly as before, and the repair follows when the group
//! closes. Only a packet that was lost pays any latency, the wait for its
//! group's repair, and [`GROUP_MAX_AGE`] bounds that.
//!
//! A group closes when the next packet cannot join it or when it has been open
//! for [`GROUP_MAX_AGE`], whichever comes first. Bulk traffic fills whole
//! groups, so it pays `1 / group size` in extra bandwidth. A game sending one
//! packet per tick gets a repair per packet a few milliseconds behind it,
//! which costs little at game packet rates, and that spacing is what lets a
//! repair survive the burst that took the original: duplicates sent at the
//! same instant cross the same Wi-Fi hiccup together.
//!
//! This module is pure bookkeeping with no I/O, shared by the client engine
//! and the relay so both ends encode and decode the same format.

use std::time::{Duration, Instant};

/// Largest group either end will encode. Member offsets and the MTU budget are
/// sized from it, so raising it is the one change a larger group needs.
pub const MAX_GROUP: usize = 4;

/// Group size while two or more paths are healthy: duplication already covers
/// a single path failing, so repairs only have to catch the loss both copies
/// share, and one repair per four packets does that at a quarter of the cost.
pub const MULTIPATH_GROUP: u8 = 4;

/// Group size while two or more paths are healthy but every one of them is
/// losing packets, which [`MultipathPolicy`] decides. Shared loss is then
/// frequent enough for two losses to land in one group of four, which a single
/// repair cannot undo.
pub const LOSSY_MULTIPATH_GROUP: u8 = 2;

/// Group size while only one path is healthy. There is no second copy of
/// anything, so every packet gets its own repair.
pub const SINGLE_PATH_GROUP: u8 = 1;

const _: () = assert!(
    SINGLE_PATH_GROUP >= 1
        && SINGLE_PATH_GROUP as usize <= MAX_GROUP
        && LOSSY_MULTIPATH_GROUP >= 1
        && LOSSY_MULTIPATH_GROUP as usize <= MAX_GROUP
        && MULTIPATH_GROUP >= 1
        && MULTIPATH_GROUP as usize <= MAX_GROUP,
    "every group size must fit the encoder, whose limit is MAX_GROUP"
);

/// Probe loss, over a path's [`ProbeHistory`], at which it counts as losing
/// packets: four of the last forty. One stray lost probe reads 2.5%.
pub const LOSSY_PATH_LOSS: f64 = 0.10;

/// Loss a path has to fall back under before the session counts as healthy
/// again. The gap below [`LOSSY_PATH_LOSS`] keeps a path hovering at the
/// threshold from flipping the group size on every probe.
pub const RECOVERED_PATH_LOSS: f64 = 0.04;

/// How long every healthy path has to stay lossy before the group shrinks.
pub const LOSSY_AFTER: Duration = Duration::from_secs(5);

/// How long the best path has to stay recovered before the group grows back.
/// Longer than [`LOSSY_AFTER`] on purpose: shrinking too late costs a few
/// unrecoverable losses, growing too early puts the session straight back into
/// them.
pub const RECOVERED_AFTER: Duration = Duration::from_secs(15);

/// Longest a group stays open. This is the most a rebuilt packet can trail
/// its original by, on top of the path's own latency.
pub const GROUP_MAX_AGE: Duration = Duration::from_millis(5);

/// Leads every repair payload. A relay from before loss repair treats a repair
/// frame as a data packet and forwards it only if it parses as IPv4 from the
/// client's address, so this byte must never read as IPv4's version nibble.
const VERSION: u8 = 1;
const _: () = assert!(VERSION >> 4 != 4);

/// Member offsets from the group's first sequence are one byte each.
const MAX_SPAN: u64 = u8::MAX as u64;

/// Most bytes a repair adds on top of the longest packet it covers: version,
/// first sequence, member count, one offset per further member, and the
/// XOR-ed length prefix. The relay MTU budget reserves this, so a repair
/// covering a full-size packet fits the link the packet did.
pub const REPAIR_HEADER_MAX: usize = 1 + 8 + 1 + (MAX_GROUP - 1) + 2;

const LENGTH_PREFIX: usize = 2;

/// Delivered packets the decoder keeps so a later repair can use them. Wider
/// than a group's widest span, so a repair overtaken by a slower path's data
/// still finds its members.
const RECENT_CAPACITY: usize = 512;
const _: () = assert!(RECENT_CAPACITY as u64 > MAX_SPAN * 2);

/// Repairs held while more than one member is still missing, waiting for the
/// others to arrive by a slower path.
const PENDING_CAPACITY: usize = 32;

/// How long such a repair is worth holding. A packet rebuilt later than this is
/// past any use a game has for it.
const PENDING_MAX_AGE: Duration = Duration::from_millis(500);

/// Offer control payload: the client asks the relay to protect its replies
/// with groups of the given size. Answered with [`ACCEPT`] by relays that
/// support loss repair and ignored by the rest, which is how the client tells
/// the two apart.
const OFFER: &[u8; 4] = b"fecq";
const ACCEPT: &[u8; 4] = b"feca";

/// Group size for a session with `healthy_paths` paths up, given what
/// [`MultipathPolicy`] currently says the multipath size should be.
pub fn group_size_for(healthy_paths: u32, multipath_group: u8) -> u8 {
    if healthy_paths >= 2 {
        multipath_group
    } else {
        SINGLE_PATH_GROUP
    }
}

/// Shrinks the multipath group from [`MULTIPATH_GROUP`] to
/// [`LOSSY_MULTIPATH_GROUP`] only once every healthy path has been losing
/// packets for [`LOSSY_AFTER`], and grows it back only once the best path has
/// been clean for [`RECOVERED_AFTER`].
///
/// It reads the lowest loss among the paths carrying data, because a packet is
/// lost for good only when every copy of it is: one clean carrying path means
/// duplication already delivers, and four is enough for what little it misses. Both the
/// threshold and the time have a gap between the two directions, so a session
/// sitting near either edge holds its size rather than flapping.
#[derive(Debug, Default)]
pub struct MultipathPolicy {
    lossy: bool,
    crossing_since: Option<Instant>,
}

impl MultipathPolicy {
    /// Takes the lowest [`ProbeHistory`] loss among the carrying paths, as a ratio,
    /// and returns the multipath group size to use from now on.
    pub fn observe(&mut self, best_loss: f64, now: Instant) -> u8 {
        let crossing = if self.lossy {
            best_loss < RECOVERED_PATH_LOSS
        } else {
            best_loss >= LOSSY_PATH_LOSS
        };
        if !crossing {
            self.crossing_since = None;
            return self.group();
        }
        let since = *self.crossing_since.get_or_insert(now);
        let hold = if self.lossy {
            RECOVERED_AFTER
        } else {
            LOSSY_AFTER
        };
        if now.saturating_duration_since(since) >= hold {
            self.lossy = !self.lossy;
            self.crossing_since = None;
        }
        self.group()
    }

    pub fn group(&self) -> u8 {
        if self.lossy {
            LOSSY_MULTIPATH_GROUP
        } else {
            MULTIPATH_GROUP
        }
    }

    /// Restarts the clock toward a change without changing the size, for a
    /// moment when there is nothing trustworthy to observe, such as every
    /// carrying path being down at once.
    pub fn interrupt(&mut self) {
        self.crossing_since = None;
    }
}

/// Probe outcomes [`MultipathPolicy`] judges a path by.
pub const LOSS_WINDOW: u32 = 40;

/// Outcomes a path needs before its loss counts at all. Until then it is
/// treated as clean, so a path that has only just joined cannot shrink groups.
pub const MIN_LOSS_SAMPLES: u32 = 20;

const _: () = assert!(LOSS_WINDOW <= u64::BITS && MIN_LOSS_SAMPLES <= LOSS_WINDOW);

/// The last [`LOSS_WINDOW`] probe outcomes of one path, with outages taken out.
///
/// The scheduler's loss average cannot serve here. While every path is down
/// its probes go out every 150 ms and all of them are lost, so a five-second
/// blackout of the whole uplink reads as 25-50% loss for half a minute after
/// it ends, on paths that are perfectly clean again. A blackout is not a path
/// in bad condition and a smaller group does nothing for it, so the run of
/// losses that ended in a path being declared down is forgotten here. What
/// remains is the scattered loss of a path that stays up, which is what two
/// losses landing in one group actually comes from.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProbeHistory {
    /// Bit 0 is the newest outcome; a set bit is a lost probe.
    lost: u64,
    samples: u32,
}

impl ProbeHistory {
    pub fn record(&mut self, lost: bool) {
        let window = u64::MAX >> (u64::BITS - LOSS_WINDOW);
        self.lost = ((self.lost << 1) | u64::from(lost)) & window;
        self.samples = (self.samples + 1).min(LOSS_WINDOW);
    }

    /// Forgets the unbroken run of losses at the newest end: the outage that
    /// took the path down, rather than loss on a path that was carrying.
    pub fn forget_outage(&mut self) {
        while self.samples > 0 && self.lost & 1 == 1 {
            self.lost >>= 1;
            self.samples -= 1;
        }
    }

    /// Lost share of the window, once it holds [`MIN_LOSS_SAMPLES`].
    pub fn loss(&self) -> Option<f64> {
        (self.samples >= MIN_LOSS_SAMPLES)
            .then(|| f64::from(self.lost.count_ones()) / f64::from(self.samples))
    }
}

/// What a client asks of the relay's replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub group_size: u8,
    /// The client session's tunnel MTU. It is derived per session from the
    /// client's own link and transports, which the relay cannot see, and a
    /// reply larger than it is left out of its group, like a client packet
    /// larger than the MTU is: its repair would not fit the client's link.
    pub mtu: u16,
}

pub fn offer(offer: Offer) -> Vec<u8> {
    let mut payload = control(OFFER, offer.group_size);
    payload.extend_from_slice(&offer.mtu.to_be_bytes());
    payload
}

pub fn accept(group_size: u8) -> Vec<u8> {
    control(ACCEPT, group_size)
}

/// What a well-formed offer asks for.
pub fn parse_offer(payload: &[u8]) -> Option<Offer> {
    let (head, mtu) = payload.split_at_checked(CONTROL_LEN)?;
    let mtu = u16::from_be_bytes(mtu.try_into().ok()?);
    Some(Offer {
        group_size: parse_control(OFFER, head)?,
        mtu,
    })
}

/// The group size a relay's acceptance confirms.
pub fn accepted_group(payload: &[u8]) -> Option<u8> {
    parse_control(ACCEPT, payload)
}

const CONTROL_LEN: usize = 6;

fn control(tag: &[u8; 4], group_size: u8) -> Vec<u8> {
    let mut payload = tag.to_vec();
    payload.extend_from_slice(&[VERSION, group_size]);
    payload
}

fn parse_control(tag: &[u8; 4], payload: &[u8]) -> Option<u8> {
    let [a, b, c, d, version, group] = payload else {
        return None;
    };
    ([*a, *b, *c, *d] == *tag && *version == VERSION && (1..=MAX_GROUP as u8).contains(group))
        .then_some(*group)
}

fn xor_member(parity: &mut Vec<u8>, packet: &[u8]) {
    let needed = LENGTH_PREFIX + packet.len();
    if parity.len() < needed {
        parity.resize(needed, 0);
    }
    let length = (packet.len() as u16).to_be_bytes();
    parity[0] ^= length[0];
    parity[1] ^= length[1];
    for (byte, source) in parity[LENGTH_PREFIX..].iter_mut().zip(packet) {
        *byte ^= source;
    }
}

/// Builds repairs for packets as they are sent.
pub struct Encoder {
    group_size: usize,
    max_packet: usize,
    base: u64,
    offsets: [u8; MAX_GROUP],
    count: usize,
    parity: Vec<u8>,
    opened_at: Option<Instant>,
}

impl Encoder {
    /// `max_packet` is the tunnel MTU. Anything larger was going to fragment
    /// anyway and is left unprotected, which keeps every repair inside the
    /// budget [`REPAIR_HEADER_MAX`] reserves.
    pub fn new(group_size: u8, max_packet: usize) -> Self {
        Self {
            group_size: usize::from(group_size).clamp(1, MAX_GROUP),
            max_packet: max_packet.min(usize::from(u16::MAX)),
            base: 0,
            offsets: [0; MAX_GROUP],
            count: 0,
            parity: Vec::with_capacity(LENGTH_PREFIX + max_packet),
            opened_at: None,
        }
    }

    pub fn group_size(&self) -> u8 {
        self.group_size as u8
    }

    /// Changes which packets are small enough to protect. Only packets pushed
    /// afterwards are affected.
    pub fn set_max_packet(&mut self, max_packet: usize) {
        self.max_packet = max_packet.min(usize::from(u16::MAX));
    }

    /// Changes the group size for the packets that follow. A group already open
    /// is closed first, so the packets in it are still covered.
    pub fn set_group_size(&mut self, group_size: u8) -> Option<Vec<u8>> {
        let group_size = usize::from(group_size).clamp(1, MAX_GROUP);
        if group_size == self.group_size {
            return None;
        }
        self.group_size = group_size;
        self.close()
    }

    /// Adds a packet that has just been sent as `sequence`. Returns the repair
    /// for the previous group when this packet could not join it.
    pub fn push(&mut self, sequence: u64, packet: &[u8], now: Instant) -> Option<Vec<u8>> {
        if packet.is_empty() || packet.len() > self.max_packet {
            return None;
        }
        let closed = if self.count > 0 && !self.can_join(sequence, now) {
            self.close()
        } else {
            None
        };
        if self.count == 0 {
            self.base = sequence;
            self.opened_at = Some(now);
        }
        self.offsets[self.count] = (sequence - self.base) as u8;
        self.count += 1;
        xor_member(&mut self.parity, packet);
        closed
    }

    fn can_join(&self, sequence: u64, now: Instant) -> bool {
        let last = self.base + u64::from(self.offsets[self.count - 1]);
        self.count < self.group_size
            && sequence > last
            && sequence - self.base <= MAX_SPAN
            && !self.expired(now)
    }

    fn expired(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|deadline| now >= deadline)
    }

    /// When the open group has to be closed by [`Self::flush_due`], if one is open.
    pub fn deadline(&self) -> Option<Instant> {
        self.opened_at.map(|opened| opened + GROUP_MAX_AGE)
    }

    /// Closes the open group once it has waited [`GROUP_MAX_AGE`] for more members.
    pub fn flush_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        if self.expired(now) {
            self.close()
        } else {
            None
        }
    }

    fn close(&mut self) -> Option<Vec<u8>> {
        if self.count == 0 {
            return None;
        }
        let mut repair = Vec::with_capacity(REPAIR_HEADER_MAX + self.parity.len());
        repair.push(VERSION);
        repair.extend_from_slice(&self.base.to_be_bytes());
        repair.push(self.count as u8);
        repair.extend_from_slice(&self.offsets[1..self.count]);
        repair.extend_from_slice(&self.parity);
        self.count = 0;
        self.parity.clear();
        self.opened_at = None;
        Some(repair)
    }
}

struct Repair {
    members: [u64; MAX_GROUP],
    count: usize,
    parity: Vec<u8>,
    received_at: Instant,
}

impl Repair {
    fn parse(payload: &[u8], now: Instant) -> Option<Self> {
        let (&version, rest) = payload.split_first()?;
        if version != VERSION || rest.len() < 9 {
            return None;
        }
        let base = u64::from_be_bytes(rest[..8].try_into().ok()?);
        let count = usize::from(rest[8]);
        if count == 0 || count > MAX_GROUP {
            return None;
        }
        let offsets = rest.get(9..9 + count - 1)?;
        let parity = rest.get(9 + count - 1..)?;
        if parity.len() <= LENGTH_PREFIX {
            return None;
        }
        let mut members = [0; MAX_GROUP];
        members[0] = base;
        for (index, offset) in offsets.iter().enumerate() {
            let member = base.checked_add(u64::from(*offset))?;
            if member <= members[index] {
                return None;
            }
            members[index + 1] = member;
        }
        Some(Self {
            members,
            count,
            parity: parity.to_vec(),
            received_at: now,
        })
    }

    fn members(&self) -> &[u64] {
        &self.members[..self.count]
    }

    fn missing(&self, delivered: &impl Fn(u64) -> bool) -> usize {
        self.members()
            .iter()
            .filter(|member| !delivered(**member))
            .count()
    }
}

/// Rebuilds lost packets from repairs and the packets that did arrive.
#[derive(Default)]
pub struct Decoder {
    recent: Vec<(u64, Vec<u8>)>,
    pending: Vec<Repair>,
    /// Groups of one carry their packet whole, so the decoder only keeps
    /// delivered packets once the peer has sent a group that needs them.
    storing: bool,
    pub repairs_received: u64,
    pub unrecoverable: u64,
}

impl Decoder {
    /// Keeps a delivered packet so a repair arriving later can use it.
    pub fn remember(&mut self, sequence: u64, packet: &[u8]) {
        if !self.storing {
            return;
        }
        if self.recent.is_empty() {
            self.recent = vec![(0, Vec::new()); RECENT_CAPACITY];
        }
        let slot = &mut self.recent[(sequence % RECENT_CAPACITY as u64) as usize];
        slot.0 = sequence;
        slot.1.clear();
        slot.1.extend_from_slice(packet);
    }

    fn stored(&self, sequence: u64) -> Option<&[u8]> {
        let (stored, packet) = self
            .recent
            .get((sequence % RECENT_CAPACITY as u64) as usize)?;
        (*stored == sequence && !packet.is_empty()).then_some(packet.as_slice())
    }

    /// Takes a repair payload. `delivered` says whether a sequence has already
    /// reached the receiver, by any path. Returns the packet it rebuilt, with
    /// its original sequence, when exactly one member was missing.
    pub fn accept_repair(
        &mut self,
        payload: &[u8],
        now: Instant,
        delivered: impl Fn(u64) -> bool,
    ) -> Option<(u64, Vec<u8>)> {
        let repair = Repair::parse(payload, now)?;
        self.repairs_received += 1;
        self.storing |= repair.count > 1;
        self.resolve(repair, &delivered)
    }

    /// Whether any repair is still waiting for members, so the caller knows
    /// [`Self::retry_pending`] has anything to do after a delivery.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Retries repairs that were waiting on more than one member, returning at
    /// most one rebuilt packet per call so `delivered` stays current between them.
    pub fn retry_pending(
        &mut self,
        now: Instant,
        delivered: impl Fn(u64) -> bool,
    ) -> Option<(u64, Vec<u8>)> {
        let before = self.pending.len();
        self.pending.retain(|repair| {
            now.saturating_duration_since(repair.received_at) < PENDING_MAX_AGE
                || repair.missing(&delivered) == 0
        });
        self.unrecoverable += (before - self.pending.len()) as u64;
        self.pending.retain(|repair| repair.missing(&delivered) > 0);
        let ready = self
            .pending
            .iter()
            .position(|repair| repair.missing(&delivered) == 1)?;
        let repair = self.pending.swap_remove(ready);
        self.resolve(repair, &delivered)
    }

    fn resolve(
        &mut self,
        repair: Repair,
        delivered: &impl Fn(u64) -> bool,
    ) -> Option<(u64, Vec<u8>)> {
        let mut missing = repair
            .members()
            .iter()
            .copied()
            .filter(|member| !delivered(*member));
        let lost = missing.next()?;
        if missing.next().is_some() {
            if self.pending.len() >= PENDING_CAPACITY {
                self.pending.remove(0);
                self.unrecoverable += 1;
            }
            self.pending.push(repair);
            return None;
        }
        let rebuilt = self.rebuild(&repair, lost);
        if rebuilt.is_none() {
            self.unrecoverable += 1;
        }
        rebuilt.map(|packet| (lost, packet))
    }

    fn rebuild(&self, repair: &Repair, lost: u64) -> Option<Vec<u8>> {
        let mut parity = repair.parity.clone();
        for member in repair.members().iter().filter(|member| **member != lost) {
            let packet = self.stored(*member)?;
            if LENGTH_PREFIX + packet.len() > parity.len() {
                return None;
            }
            xor_member(&mut parity, packet);
        }
        let length = usize::from(u16::from_be_bytes([parity[0], parity[1]]));
        if length == 0 || LENGTH_PREFIX + length > parity.len() {
            return None;
        }
        parity.truncate(LENGTH_PREFIX + length);
        parity.drain(..LENGTH_PREFIX);
        Some(parity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn storing_decoder() -> Decoder {
        Decoder {
            storing: true,
            ..Decoder::default()
        }
    }

    fn packet(tag: u8, length: usize) -> Vec<u8> {
        (0..length).map(|index| tag ^ index as u8).collect()
    }

    /// Sends `packets` through an encoder, returning each data frame and every
    /// repair in the order they would leave.
    type Sent = Vec<(u64, Vec<u8>)>;

    fn encode(group: u8, packets: &[Vec<u8>]) -> (Sent, Vec<Vec<u8>>) {
        let mut encoder = Encoder::new(group, 1400);
        let now = Instant::now();
        let mut data = Vec::new();
        let mut repairs = Vec::new();
        for (index, packet) in packets.iter().enumerate() {
            let sequence = index as u64 + 10;
            repairs.extend(encoder.push(sequence, packet, now));
            data.push((sequence, packet.clone()));
        }
        repairs.extend(encoder.flush_due(now + GROUP_MAX_AGE));
        (data, repairs)
    }

    fn receive(data: &[(u64, Vec<u8>)], repairs: &[Vec<u8>], lost: &[u64]) -> (HashSet<u64>, Sent) {
        // The receiver learns it needs to store packets from the first repair,
        // so a real stream primes it before the data this test cares about.
        let mut decoder = storing_decoder();
        let mut delivered = HashSet::new();
        let mut rebuilt = Vec::new();
        let now = Instant::now();
        for (sequence, packet) in data {
            if lost.contains(sequence) {
                continue;
            }
            delivered.insert(*sequence);
            decoder.remember(*sequence, packet);
        }
        for repair in repairs {
            if let Some((sequence, packet)) =
                decoder.accept_repair(repair, now, |member| delivered.contains(&member))
            {
                delivered.insert(sequence);
                decoder.remember(sequence, &packet);
                rebuilt.push((sequence, packet));
            }
        }
        (delivered, rebuilt)
    }

    #[test]
    fn a_packet_lost_from_a_full_group_is_rebuilt_exactly() {
        let packets: Vec<_> = [120, 1400, 64, 900]
            .iter()
            .enumerate()
            .map(|(tag, length)| packet(tag as u8, *length))
            .collect();
        let (data, repairs) = encode(4, &packets);
        assert_eq!(repairs.len(), 1);
        for lost in 10..14 {
            let (_, rebuilt) = receive(&data, &repairs, &[lost]);
            assert_eq!(rebuilt, vec![(lost, packets[(lost - 10) as usize].clone())]);
        }
    }

    #[test]
    fn two_losses_in_one_group_are_not_guessed_at() {
        let packets: Vec<_> = (0..4).map(|tag| packet(tag, 200)).collect();
        let (data, repairs) = encode(4, &packets);
        let (_, rebuilt) = receive(&data, &repairs, &[11, 12]);
        assert!(rebuilt.is_empty());
    }

    #[test]
    fn a_group_of_one_carries_its_packet_without_any_stored_history() {
        let packets: Vec<_> = (0..3).map(|tag| packet(tag, 300)).collect();
        let (data, repairs) = encode(1, &packets);
        assert_eq!(repairs.len(), 3);
        let mut decoder = Decoder::default();
        let rebuilt = decoder.accept_repair(&repairs[1], Instant::now(), |member| member != 11);
        assert_eq!(rebuilt, Some((11, data[1].1.clone())));
        assert!(decoder.recent.is_empty());
    }

    #[test]
    fn a_group_closes_when_the_next_packet_cannot_join_it() {
        let mut encoder = Encoder::new(4, 1400);
        let now = Instant::now();
        for sequence in 1..=4 {
            assert!(encoder.push(sequence, &[1; 50], now).is_none());
        }
        // The fifth packet opens the next group, closing the full one.
        assert!(encoder.push(5, &[1; 50], now).is_some());
    }

    #[test]
    fn a_sparse_stream_gets_its_repair_within_the_group_deadline() {
        let mut encoder = Encoder::new(4, 1400);
        let now = Instant::now();
        assert!(encoder.push(1, &[1; 50], now).is_none());
        assert_eq!(encoder.deadline(), Some(now + GROUP_MAX_AGE));
        assert!(encoder.flush_due(now + GROUP_MAX_AGE / 2).is_none());
        assert!(encoder.flush_due(now + GROUP_MAX_AGE).is_some());
        assert!(encoder.deadline().is_none());
    }

    #[test]
    fn changing_the_group_size_closes_the_open_group_first() {
        let mut encoder = Encoder::new(4, 1400);
        let now = Instant::now();
        encoder.push(1, &[1; 50], now);
        assert!(encoder.set_group_size(4).is_none());
        assert!(encoder.set_group_size(1).is_some());
        assert_eq!(encoder.group_size(), 1);
    }

    #[test]
    fn sequences_too_far_apart_start_a_new_group() {
        let mut encoder = Encoder::new(4, 1400);
        let now = Instant::now();
        encoder.push(1, &[1; 50], now);
        assert!(encoder.push(1 + MAX_SPAN + 1, &[1; 50], now).is_some());
    }

    #[test]
    fn a_packet_too_large_for_the_budget_is_left_out() {
        let mut encoder = Encoder::new(1, 1000);
        let now = Instant::now();
        assert!(encoder.push(1, &[1; 1001], now).is_none());
        assert!(encoder.deadline().is_none());
    }

    #[test]
    fn a_repair_waits_for_a_slower_path_to_deliver_the_rest() {
        let packets: Vec<_> = (0..4).map(|tag| packet(tag, 100)).collect();
        let (data, repairs) = encode(4, &packets);
        let mut decoder = storing_decoder();
        let mut delivered: HashSet<u64> = HashSet::new();
        let now = Instant::now();
        delivered.insert(10);
        decoder.remember(10, &data[0].1);
        // Three members are still in flight, so nothing can be rebuilt yet.
        assert!(
            decoder
                .accept_repair(&repairs[0], now, |member| delivered.contains(&member))
                .is_none()
        );
        assert!(decoder.has_pending());
        for (sequence, packet) in &data[1..3] {
            delivered.insert(*sequence);
            decoder.remember(*sequence, packet);
        }
        let rebuilt = decoder.retry_pending(now, |member| delivered.contains(&member));
        assert_eq!(rebuilt, Some((13, data[3].1.clone())));
        assert!(!decoder.has_pending());
    }

    #[test]
    fn a_repair_held_too_long_is_given_up_on() {
        let packets: Vec<_> = (0..4).map(|tag| packet(tag, 100)).collect();
        let (_, repairs) = encode(4, &packets);
        let mut decoder = Decoder::default();
        let now = Instant::now();
        assert!(decoder.accept_repair(&repairs[0], now, |_| false).is_none());
        assert!(
            decoder
                .retry_pending(now + PENDING_MAX_AGE, |_| false)
                .is_none()
        );
        assert!(!decoder.has_pending());
        assert_eq!(decoder.unrecoverable, 1);
    }

    #[test]
    fn a_member_evicted_from_history_is_not_rebuilt_from_garbage() {
        let packets: Vec<_> = (0..4).map(|tag| packet(tag, 100)).collect();
        let (data, repairs) = encode(4, &packets);
        let mut decoder = storing_decoder();
        for (sequence, packet) in &data[..3] {
            decoder.remember(*sequence, packet);
        }
        // A packet a whole history later lands in the same slot as 10.
        decoder.remember(10 + RECENT_CAPACITY as u64, &[9; 100]);
        let rebuilt = decoder.accept_repair(&repairs[0], Instant::now(), |member| member != 13);
        assert!(rebuilt.is_none());
        assert_eq!(decoder.unrecoverable, 1);
    }

    #[test]
    fn malformed_repairs_are_ignored() {
        let mut decoder = Decoder::default();
        let now = Instant::now();
        for payload in [
            vec![],
            vec![VERSION],
            vec![VERSION, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
            vec![VERSION, 0, 0, 0, 0, 0, 0, 0, 1, 9, 0, 0, 0],
            vec![VERSION, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0],
            vec![0x45, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 7],
        ] {
            assert!(decoder.accept_repair(&payload, now, |_| false).is_none());
        }
        assert_eq!(decoder.repairs_received, 0);
    }

    #[test]
    fn a_repair_never_reads_as_an_ipv4_packet() {
        let mut encoder = Encoder::new(1, 1400);
        let now = Instant::now();
        encoder.push(1, &[0x45; 60], now);
        let repair = encoder.flush_due(now + GROUP_MAX_AGE).unwrap();
        assert_ne!(repair[0] >> 4, 4);
    }

    #[test]
    fn a_repair_fits_the_reserved_budget() {
        let mut encoder = Encoder::new(4, 1356);
        let now = Instant::now();
        for sequence in 1..=4 {
            encoder.push(sequence * 3, &[7; 1356], now);
        }
        let repair = encoder.flush_due(now + GROUP_MAX_AGE).unwrap();
        assert_eq!(repair.len(), 1356 + REPAIR_HEADER_MAX);
    }

    #[test]
    fn control_messages_round_trip_and_reject_anything_else() {
        let asked = Offer {
            group_size: 4,
            mtu: 1341,
        };
        let with_group = |group_size| {
            offer(Offer {
                group_size,
                ..asked
            })
        };
        assert_eq!(parse_offer(&offer(asked)), Some(asked));
        assert_eq!(accepted_group(&accept(1)), Some(1));
        assert_eq!(parse_offer(&accept(4)), None);
        assert_eq!(accepted_group(&offer(asked)), None);
        assert_eq!(parse_offer(&with_group(0)), None);
        assert_eq!(parse_offer(&with_group(MAX_GROUP as u8 + 1)), None);
        assert_eq!(parse_offer(&offer(asked)[..CONTROL_LEN]), None);
        assert_eq!(parse_offer(b"ping"), None);
    }

    #[test]
    fn the_group_follows_the_healthy_paths() {
        assert_eq!(group_size_for(0, MULTIPATH_GROUP), SINGLE_PATH_GROUP);
        assert_eq!(group_size_for(1, LOSSY_MULTIPATH_GROUP), SINGLE_PATH_GROUP);
        assert_eq!(group_size_for(2, MULTIPATH_GROUP), MULTIPATH_GROUP);
        assert_eq!(
            group_size_for(3, LOSSY_MULTIPATH_GROUP),
            LOSSY_MULTIPATH_GROUP
        );
    }

    fn seconds(start: Instant, seconds: f64) -> Instant {
        start + Duration::from_secs_f64(seconds)
    }

    #[test]
    fn every_path_has_to_stay_lossy_before_the_group_shrinks() {
        let mut policy = MultipathPolicy::default();
        let start = Instant::now();
        // One stray lost probe reads 5%, well short of lossy.
        assert_eq!(policy.observe(0.05, start), MULTIPATH_GROUP);
        assert_eq!(policy.observe(0.12, seconds(start, 1.0)), MULTIPATH_GROUP);
        assert_eq!(policy.observe(0.12, seconds(start, 4.0)), MULTIPATH_GROUP);
        // A clean reading restarts the clock rather than pausing it.
        assert_eq!(policy.observe(0.08, seconds(start, 5.0)), MULTIPATH_GROUP);
        assert_eq!(policy.observe(0.12, seconds(start, 6.0)), MULTIPATH_GROUP);
        assert_eq!(policy.observe(0.12, seconds(start, 10.9)), MULTIPATH_GROUP);
        assert_eq!(
            policy.observe(0.12, seconds(start, 11.0)),
            LOSSY_MULTIPATH_GROUP
        );
    }

    #[test]
    fn the_group_grows_back_only_after_a_long_clean_spell() {
        let mut policy = MultipathPolicy::default();
        let start = Instant::now();
        policy.observe(0.2, start);
        assert_eq!(
            policy.observe(0.2, start + LOSSY_AFTER),
            LOSSY_MULTIPATH_GROUP
        );
        let recovered = start + LOSSY_AFTER;
        // Under the lossy threshold but above the recovered one: holds.
        for step in 1..=30 {
            assert_eq!(
                policy.observe(0.06, seconds(recovered, f64::from(step))),
                LOSSY_MULTIPATH_GROUP
            );
        }
        let clean = seconds(recovered, 31.0);
        assert_eq!(policy.observe(0.02, clean), LOSSY_MULTIPATH_GROUP);
        assert_eq!(
            policy.observe(0.02, clean + RECOVERED_AFTER / 2),
            LOSSY_MULTIPATH_GROUP
        );
        assert_eq!(
            policy.observe(0.02, clean + RECOVERED_AFTER),
            MULTIPATH_GROUP
        );
    }

    #[test]
    fn a_blackout_is_forgotten_but_scattered_loss_is_kept() {
        let mut history = ProbeHistory::default();
        for probe in 0..30 {
            // One loss in ten while the path stays up.
            history.record(probe % 10 == 9);
        }
        let before = history.loss().unwrap();
        assert!((before - 0.1).abs() < 1e-9);
        // The whole uplink goes dark: a run of losses that takes the path down.
        for _ in 0..15 {
            history.record(true);
        }
        history.forget_outage();
        history.record(false);
        let after = history.loss().unwrap();
        assert!(
            after <= before,
            "{after} after a blackout vs {before} before"
        );
    }

    #[test]
    fn a_path_is_clean_until_it_has_enough_history() {
        let mut history = ProbeHistory::default();
        for _ in 0..MIN_LOSS_SAMPLES - 1 {
            history.record(true);
        }
        assert_eq!(history.loss(), None);
        history.record(true);
        assert_eq!(history.loss(), Some(1.0));
    }

    #[test]
    fn the_window_keeps_only_the_newest_outcomes() {
        let mut history = ProbeHistory::default();
        for _ in 0..LOSS_WINDOW {
            history.record(true);
        }
        for _ in 0..LOSS_WINDOW {
            history.record(false);
        }
        assert_eq!(history.loss(), Some(0.0));
    }

    #[test]
    fn an_interruption_restarts_the_clock_without_changing_the_size() {
        let mut policy = MultipathPolicy::default();
        let start = Instant::now();
        policy.observe(0.2, start);
        policy.interrupt();
        assert_eq!(policy.observe(0.2, start + LOSSY_AFTER), MULTIPATH_GROUP);
        assert_eq!(
            policy.observe(0.2, start + LOSSY_AFTER * 2),
            LOSSY_MULTIPATH_GROUP
        );
    }

    #[test]
    fn a_smaller_mtu_leaves_larger_packets_out() {
        let mut encoder = Encoder::new(1, 1400);
        let now = Instant::now();
        encoder.set_max_packet(1200);
        assert!(encoder.push(1, &[1; 1300], now).is_none());
        assert!(encoder.deadline().is_none());
        encoder.push(2, &[1; 1200], now);
        assert!(encoder.deadline().is_some());
    }
}
