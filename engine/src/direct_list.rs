//! The VPN's direct list: destinations that keep the normal connection while
//! the VPN carries everything else around them.
//!
//! Users in a filtered country want the VPN for foreign sites and their own
//! connection for domestic ones. Domestic sites are faster that way, and many
//! of them (banks, government services, payment gateways) refuse visitors from
//! foreign addresses outright, so tunnelling them breaks them. The list is a
//! set of IPv4 ranges, usually a country's registered address space, plus
//! domain names whose answers are learned as the session resolves them.
//!
//! Pure data and parsing, so every rule here is tested without Windows. The
//! capture paths decide what "direct" means for their own mechanism: routes
//! via the physical gateway in all-traffic mode, an unselected verdict in
//! split mode.

use serde::Deserialize;
use std::collections::HashSet;
use std::net::Ipv4Addr;

/// Bounds what one request can make the engine hold. A country's registered
/// ranges are a few thousand at most (Iran is about 1,700, aggregated), and
/// domain categories a few hundred; these leave room for the largest
/// countries without letting a malformed request grow without limit.
pub const MAX_NETWORKS: usize = 65_536;
pub const MAX_DOMAINS: usize = 65_536;

/// Most addresses a session learns from answers for direct names. Each is a
/// route in all-traffic mode, so this bounds the routing table too.
pub const MAX_LEARNED: usize = 4096;

/// Shortest prefix accepted. All-traffic mode routes `0.0.0.0/1` and
/// `128.0.0.0/1` into the tunnel; a direct `/1` would tie with one of them on
/// length and win on metric, quietly turning the VPN off for half the
/// Internet. No country's registered space comes close to a `/8` boundary
/// from below, so this costs nothing real.
pub const MIN_PREFIX: u8 = 8;

/// What the client sends: IPv4 networks in CIDR form, and domains where
/// `*.example.com` covers the name and every subdomain and `example.com`
/// only that name.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectSpec {
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct DirectList {
    /// Sorted, merged and non-overlapping, so a lookup is one binary search.
    ranges: Vec<(u32, u32)>,
    exact: HashSet<String>,
    /// Stored without the `*.` they were written with.
    suffixes: HashSet<String>,
    /// Entries that were malformed, IPv6, or wider than [`MIN_PREFIX`].
    skipped: usize,
}

impl DirectList {
    /// Never fails: a downloaded list with one bad line must not keep the
    /// VPN from starting, so bad entries are counted and left out instead.
    pub fn compile(spec: &DirectSpec) -> Self {
        let mut list = Self::default();
        let mut ranges = Vec::with_capacity(spec.networks.len().min(MAX_NETWORKS));
        for network in spec.networks.iter().take(MAX_NETWORKS) {
            match parse_network(network) {
                Some(range) => ranges.push(range),
                None => list.skipped += 1,
            }
        }
        list.skipped += spec.networks.len().saturating_sub(MAX_NETWORKS);
        list.ranges = merge(ranges);
        for domain in spec.domains.iter().take(MAX_DOMAINS) {
            match parse_domain(domain) {
                Some((name, true)) => {
                    list.suffixes.insert(name);
                }
                Some((name, false)) => {
                    list.exact.insert(name);
                }
                None => list.skipped += 1,
            }
        }
        list.skipped += spec.domains.len().saturating_sub(MAX_DOMAINS);
        list
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty() && !self.has_domains()
    }

    pub fn has_domains(&self) -> bool {
        !self.exact.is_empty() || !self.suffixes.is_empty()
    }

    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    pub fn domain_count(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }

    pub fn skipped(&self) -> usize {
        self.skipped
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let address = u32::from(address);
        let index = self.ranges.partition_point(|(first, _)| *first <= address);
        index
            .checked_sub(1)
            .and_then(|index| self.ranges.get(index))
            .is_some_and(|(_, last)| address <= *last)
    }

    /// Whether `name` (lowercase, no trailing dot) is listed, directly or
    /// under a listed suffix. One hash lookup per label.
    pub fn matches_name(&self, name: &str) -> bool {
        if self.exact.contains(name) || self.suffixes.contains(name) {
            return true;
        }
        name.match_indices('.')
            .any(|(index, _)| self.suffixes.contains(&name[index + 1..]))
    }

    /// Takes `address` out of the ranges. All-traffic mode keeps the tunnel's
    /// own resolvers inside it this way: a direct range covering 8.8.8.8
    /// would otherwise send every lookup Windows makes past the tunnel, where
    /// the DNS guard drops it.
    pub fn exclude(&mut self, address: Ipv4Addr) {
        let address = u32::from(address);
        let index = self.ranges.partition_point(|(first, _)| *first <= address);
        let Some(index) = index.checked_sub(1) else {
            return;
        };
        let (first, last) = self.ranges[index];
        if address > last {
            return;
        }
        let mut pieces = Vec::with_capacity(2);
        if first < address {
            pieces.push((first, address - 1));
        }
        if address < last {
            pieces.push((address + 1, last));
        }
        self.ranges.splice(index..=index, pieces);
    }

    /// The ranges as the fewest CIDR blocks that cover exactly them, which is
    /// what a routing table takes.
    pub fn prefixes(&self) -> Vec<(Ipv4Addr, u8)> {
        let mut prefixes = Vec::with_capacity(self.ranges.len());
        for &(first, last) in &self.ranges {
            let mut start = u64::from(first);
            let end = u64::from(last);
            while start <= end {
                let alignment = if start == 0 {
                    32
                } else {
                    start.trailing_zeros()
                };
                let span = 63 - (end - start + 1).leading_zeros();
                let bits = alignment.min(span);
                prefixes.push((Ipv4Addr::from(start as u32), (32 - bits) as u8));
                start += 1 << bits;
            }
        }
        prefixes
    }

    /// The IPv4 addresses a DNS reply gives for a listed name, or nothing.
    ///
    /// `packet` is a whole IPv4 datagram. A reply counts when its question,
    /// or any name in its answer chain, is listed: a domestic site that
    /// CNAMEs to a domestic CDN is matched by either end of the chain.
    pub fn answered_addresses(&self, packet: &[u8]) -> Vec<Ipv4Addr> {
        if !self.has_domains() {
            return Vec::new();
        }
        let Some(message) = udp_dns_reply(packet) else {
            return Vec::new();
        };
        let Some(answer) = read_answer(message) else {
            return Vec::new();
        };
        if answer.names.iter().any(|name| self.matches_name(name)) {
            answer.addresses
        } else {
            Vec::new()
        }
    }
}

fn parse_network(value: &str) -> Option<(u32, u32)> {
    let value = value.trim();
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
        None => (value, 32),
    };
    let address: Ipv4Addr = address.parse().ok()?;
    if !(MIN_PREFIX..=32).contains(&prefix) {
        return None;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    let first = u32::from(address) & mask;
    Some((first, first | !mask))
}

/// A domain and whether it covers subdomains.
fn parse_domain(value: &str) -> Option<(String, bool)> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let (name, suffix) = match value.strip_prefix("*.") {
        Some(name) => (name.to_owned(), true),
        None => (value, false),
    };
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        });
    valid.then_some((name, suffix))
}

fn merge(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (first, last) in ranges {
        match merged.last_mut() {
            Some(previous) if first <= previous.1.saturating_add(1) => {
                previous.1 = previous.1.max(last);
            }
            _ => merged.push((first, last)),
        }
    }
    merged
}

/// Whether `packet` is a UDP datagram from port 53. Cheap enough to ask of
/// every packet on a data path before doing any real work.
pub fn is_dns_reply(packet: &[u8]) -> bool {
    udp_dns_reply(packet).is_some()
}

/// The name a DNS reply in `packet` answers.
pub fn reply_question(packet: &[u8]) -> Option<String> {
    read_name(udp_dns_reply(packet)?, 12).map(|(name, _)| name)
}

/// The DNS message inside a UDP datagram from port 53, if `packet` is one.
fn udp_dns_reply(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    // A fragment's ports are not where they would be in a whole datagram.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let udp = packet.get(header..header + 8)?;
    if u16::from_be_bytes([udp[0], udp[1]]) != 53 {
        return None;
    }
    packet.get(header + 8..)
}

struct Answer {
    /// The question, then every owner and CNAME target in the answers.
    names: Vec<String>,
    addresses: Vec<Ipv4Addr>,
}

/// Reads a response's names and A records. It has to survive anything a
/// network hands it, so every offset is checked and a malformed message is
/// `None` rather than a partial read.
fn read_answer(message: &[u8]) -> Option<Answer> {
    const TYPE_A: u16 = 1;
    const TYPE_CNAME: u16 = 5;
    if message.len() < 12 || message[2] & 0x80 == 0 || message[3] & 0x0f != 0 {
        return None;
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answers = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let mut names = Vec::new();
    let mut addresses = Vec::new();
    let mut offset = 12;
    for _ in 0..questions {
        let (name, next) = read_name(message, offset)?;
        names.push(name);
        offset = next + 4;
    }
    for _ in 0..answers {
        let (owner, next) = read_name(message, offset)?;
        let header = message.get(next..next + 10)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let data_start = next + 10;
        let data = message.get(data_start..data_start + length)?;
        match kind {
            TYPE_A if length == 4 => {
                addresses.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            TYPE_CNAME => {
                names.push(owner);
                if let Some((target, _)) = read_name(message, data_start) {
                    names.push(target);
                }
            }
            _ => {}
        }
        offset = data_start + length;
    }
    Some(Answer { names, addresses })
}

/// A possibly compressed name at `offset`, and where the record continues.
fn read_name(message: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut resume = None;
    let mut jumps = 0;
    loop {
        let length = *message.get(offset)?;
        if length & 0xc0 == 0xc0 {
            let low = *message.get(offset + 1)?;
            resume.get_or_insert(offset + 2);
            offset = (usize::from(length & 0x3f) << 8) | usize::from(low);
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length > 63 {
            return None;
        }
        offset += 1;
        if length == 0 {
            break;
        }
        let label = message.get(offset..offset + usize::from(length))?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        if name.len() > 253 {
            return None;
        }
        offset += usize::from(length);
    }
    Some((name, resume.unwrap_or(offset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(networks: &[&str], domains: &[&str]) -> DirectList {
        DirectList::compile(&DirectSpec {
            networks: networks.iter().map(|value| value.to_string()).collect(),
            domains: domains.iter().map(|value| value.to_string()).collect(),
        })
    }

    #[test]
    fn ranges_match_their_whole_block_and_nothing_else() {
        let direct = list(&["2.144.0.0/14", "5.10.248.7/23", "192.0.2.9"], &[]);
        assert!(direct.contains(Ipv4Addr::new(2, 144, 0, 0)));
        assert!(direct.contains(Ipv4Addr::new(2, 147, 255, 255)));
        assert!(!direct.contains(Ipv4Addr::new(2, 148, 0, 0)));
        // Host bits are masked away rather than rejected.
        assert!(direct.contains(Ipv4Addr::new(5, 10, 249, 1)));
        assert!(direct.contains(Ipv4Addr::new(192, 0, 2, 9)));
        assert!(!direct.contains(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn bad_wide_and_ipv6_entries_are_skipped_not_fatal() {
        let direct = list(
            &[
                "0.0.0.0/1",
                "2a01:5ec0::/29",
                "1.2.3.0/33",
                "nope",
                "10.0.0.0/8",
            ],
            &["", "bad domain.ir", "*.ir"],
        );
        assert_eq!(direct.range_count(), 1);
        assert_eq!(direct.domain_count(), 1);
        assert_eq!(direct.skipped(), 6);
    }

    #[test]
    fn adjacent_and_overlapping_ranges_merge() {
        let direct = list(&["10.0.0.0/25", "10.0.0.128/25", "10.0.0.5/32"], &[]);
        assert_eq!(direct.range_count(), 1);
        assert_eq!(direct.prefixes(), [(Ipv4Addr::new(10, 0, 0, 0), 24)]);
    }

    #[test]
    fn prefixes_cover_an_unaligned_range_exactly() {
        let mut direct = list(&["10.0.0.0/24"], &[]);
        direct.exclude(Ipv4Addr::new(10, 0, 0, 8));
        let prefixes = direct.prefixes();
        assert_eq!(
            prefixes,
            [
                (Ipv4Addr::new(10, 0, 0, 0), 29),
                (Ipv4Addr::new(10, 0, 0, 9), 32),
                (Ipv4Addr::new(10, 0, 0, 10), 31),
                (Ipv4Addr::new(10, 0, 0, 12), 30),
                (Ipv4Addr::new(10, 0, 0, 16), 28),
                (Ipv4Addr::new(10, 0, 0, 32), 27),
                (Ipv4Addr::new(10, 0, 0, 64), 26),
                (Ipv4Addr::new(10, 0, 0, 128), 25),
            ]
        );
        let covered: u32 = prefixes.iter().map(|(_, length)| 1 << (32 - length)).sum();
        assert_eq!(covered, 255);
        assert!(!direct.contains(Ipv4Addr::new(10, 0, 0, 8)));
    }

    #[test]
    fn excluding_the_edges_of_a_range_keeps_the_rest() {
        let mut direct = list(&["8.8.8.0/30"], &[]);
        direct.exclude(Ipv4Addr::new(8, 8, 8, 0));
        direct.exclude(Ipv4Addr::new(8, 8, 8, 3));
        direct.exclude(Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(
            direct.prefixes(),
            [
                (Ipv4Addr::new(8, 8, 8, 1), 32),
                (Ipv4Addr::new(8, 8, 8, 2), 32)
            ]
        );
    }

    #[test]
    fn a_suffix_covers_subdomains_and_an_exact_name_does_not() {
        let direct = list(&[], &["*.ir", "*.digikala.com", "time.example."]);
        assert!(direct.matches_name("ir"));
        assert!(direct.matches_name("www.shaparak.ir"));
        assert!(direct.matches_name("digikala.com"));
        assert!(direct.matches_name("api.digikala.com"));
        assert!(!direct.matches_name("notdigikala.com"));
        assert!(direct.matches_name("time.example"));
        assert!(!direct.matches_name("www.time.example"));
    }

    fn reply(question: &str, records: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        fn name(value: &str) -> Vec<u8> {
            let mut bytes = Vec::new();
            for label in value.split('.') {
                bytes.push(label.len() as u8);
                bytes.extend_from_slice(label.as_bytes());
            }
            bytes.push(0);
            bytes
        }
        let mut dns = vec![
            0x12,
            0x34,
            0x81,
            0x80,
            0,
            1,
            0,
            records.len() as u8,
            0,
            0,
            0,
            0,
        ];
        dns.extend(name(question));
        dns.extend_from_slice(&[0, 1, 0, 1]);
        for (owner, kind, data) in records {
            // The first owner points back at the question, as servers write it.
            if *owner == question {
                dns.extend_from_slice(&[0xc0, 12]);
            } else {
                dns.extend(name(owner));
            }
            dns.extend_from_slice(&kind.to_be_bytes());
            dns.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
            dns.extend_from_slice(&(data.len() as u16).to_be_bytes());
            dns.extend_from_slice(data);
        }
        let total = 28 + dns.len();
        let mut packet = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            17,
            0,
            0,
        ];
        packet.extend_from_slice(&[8, 8, 8, 8, 10, 0, 0, 2]);
        packet.extend_from_slice(&[0, 53, 0xd4, 0x31]);
        packet.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend(dns);
        packet
    }

    #[test]
    fn a_reply_for_a_listed_name_yields_its_addresses() {
        let direct = list(&[], &["*.digikala.com"]);
        let packet = reply(
            "www.digikala.com",
            &[
                ("www.digikala.com", 1, vec![185, 147, 178, 11]),
                ("www.digikala.com", 1, vec![185, 147, 178, 12]),
            ],
        );
        assert_eq!(
            direct.answered_addresses(&packet),
            [
                Ipv4Addr::new(185, 147, 178, 11),
                Ipv4Addr::new(185, 147, 178, 12)
            ]
        );
        let unlisted = reply("example.com", &[("example.com", 1, vec![93, 184, 215, 14])]);
        assert!(direct.answered_addresses(&unlisted).is_empty());
    }

    #[test]
    fn a_cname_into_a_listed_name_counts() {
        let direct = list(&[], &["*.ir"]);
        let mut target = Vec::new();
        for label in ["edge", "cdn", "ir"] {
            target.push(label.len() as u8);
            target.extend_from_slice(label.as_bytes());
        }
        target.push(0);
        let packet = reply(
            "shop.example",
            &[
                ("shop.example", 5, target),
                ("edge.cdn.ir", 1, vec![94, 182, 1, 2]),
            ],
        );
        assert_eq!(
            direct.answered_addresses(&packet),
            [Ipv4Addr::new(94, 182, 1, 2)]
        );
    }

    #[test]
    fn a_truncated_or_failed_reply_yields_nothing() {
        let direct = list(&[], &["*.ir"]);
        let packet = reply("bank.ir", &[("bank.ir", 1, vec![1, 2, 3, 4])]);
        assert!(
            direct
                .answered_addresses(&packet[..packet.len() - 2])
                .is_empty()
        );
        let mut failed = packet.clone();
        failed[28 + 3] |= 0x03;
        assert!(direct.answered_addresses(&failed).is_empty());
        let mut query = packet;
        query[28 + 2] &= 0x7f;
        assert!(direct.answered_addresses(&query).is_empty());
    }
}
