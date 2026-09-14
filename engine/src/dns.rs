//! Just enough DNS to ask one question and believe the answer.
//!
//! This is not a resolver. It exists so a session can find out, before it
//! configures anything, whether the resolver it is about to point Windows at
//! actually answers. Getting that wrong is worse than the leak it fixes: a
//! machine whose only nameserver is unreachable cannot resolve at all, which
//! the user experiences as the tunnel having broken everything.
//!
//! Split capture has its own DNS reader in `split_capture`, but that one
//! sniffs replies to other people's queries and has to survive whatever it is
//! handed. This one only ever reads the answer to a query it built itself, so
//! it can check the fields that prove the answer belongs to that query and
//! ignore the rest of the message.

use std::net::Ipv4Addr;

/// Standard query, recursion desired.
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RESPONSE: u16 = 0x8000;
const RCODE_MASK: u16 = 0x000f;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// The fixed-size part of a DNS message: id, flags and four section counts.
const HEADER_LEN: usize = 12;

/// Builds an A query for `hostname` tagged with `id`.
///
/// Returns `None` for a name that cannot be encoded — a label over 63 bytes,
/// or a name over the 255-byte wire limit — rather than emitting a message a
/// resolver would reject.
pub fn query(id: u16, hostname: &str) -> Option<Vec<u8>> {
    let mut message = Vec::with_capacity(HEADER_LEN + hostname.len() + 6);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&FLAG_RECURSION_DESIRED.to_be_bytes());
    // One question, no answer, authority or additional records.
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&[0; 6]);
    for label in hostname.split('.').filter(|label| !label.is_empty()) {
        if label.len() > 63 {
            return None;
        }
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    // The root label terminates the name.
    message.push(0);
    message.extend_from_slice(&TYPE_A.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    (message.len() <= 255 + HEADER_LEN + 5).then_some(message)
}

/// Why a resolver was not accepted, so the log can say which of "it said
/// nothing" and "it said no" happened.
#[derive(Debug, PartialEq, Eq)]
pub enum ResolverVerdict {
    /// The resolver answered this query and reported success.
    Answered,
    /// A DNS message arrived, but not an answer to the query that was asked.
    /// Treated as no answer at all: crediting it would let any stray datagram
    /// vouch for a resolver that never replied.
    Mismatched,
    /// The resolver answered and reported a failure code. It is reachable and
    /// speaking DNS, which is all this needs to decide; whether this one name
    /// exists is not the question being asked.
    Refused { rcode: u16 },
}

/// Whether `response` is this resolver's answer to the query `id` was sent
/// with.
///
/// Deliberately does not parse the answer records. What is being established
/// is that something at that address speaks DNS and is willing to answer *us*;
/// the addresses it returns are the user's business, not this probe's.
pub fn verdict(response: &[u8], id: u16) -> ResolverVerdict {
    if response.len() < HEADER_LEN {
        return ResolverVerdict::Mismatched;
    }
    if u16::from_be_bytes([response[0], response[1]]) != id {
        return ResolverVerdict::Mismatched;
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & FLAG_RESPONSE == 0 {
        return ResolverVerdict::Mismatched;
    }
    match flags & RCODE_MASK {
        0 => ResolverVerdict::Answered,
        rcode => ResolverVerdict::Refused { rcode },
    }
}

/// The name the probe asks for.
///
/// A name that certainly exists and is certainly not in any cache the relay
/// was shipped with, so the answer proves a live lookup rather than a canned
/// reply. It is never connected to — only resolved.
pub const PROBE_HOSTNAME: &str = "dns.google";

/// Public resolvers to fall back on when the relay has none of its own.
///
/// Reached *through* the tunnel, because all-traffic mode routes `0.0.0.0/1`
/// and `128.0.0.0/1` into it, so this is still a great deal better than the
/// machine's own ISP resolver. Google rather than Cloudflare for the reason
/// recorded on [`crate::BENCHMARK_TARGET`]: several national filters blackhole
/// or hijack 1.1.1.1 outright, and a user whose relay is down would then have
/// no working resolver at all.
pub const FALLBACK_RESOLVERS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];

/// The resolvers to hand Windows, given whether the relay answered.
///
/// The relay goes first when it works, and a public resolver still follows it.
/// That second entry is not redundant: the relay resolver can die while a
/// session is up — the VPS reboots, dnsmasq is restarted, the operator
/// reinstalls — and without it every name on the machine would stop resolving
/// until the user noticed and reconnected.
pub fn resolver_order(relay: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
    match relay {
        Some(relay) => vec![relay, FALLBACK_RESOLVERS[0]],
        None => FALLBACK_RESOLVERS.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_name(message: &[u8]) -> Vec<u8> {
        message[HEADER_LEN..message.len() - 4].to_vec()
    }

    #[test]
    fn a_query_encodes_its_name_as_length_prefixed_labels() {
        let message = query(0xbeef, "dns.google").expect("an ordinary name encodes");
        assert_eq!(&message[0..2], &[0xbe, 0xef]);
        assert_eq!(u16::from_be_bytes([message[2], message[3]]), 0x0100);
        // Exactly one question, and nothing in the other three sections.
        assert_eq!(u16::from_be_bytes([message[4], message[5]]), 1);
        assert_eq!(&message[6..12], &[0; 6]);
        assert_eq!(encoded_name(&message), b"\x03dns\x06google\0");
        let tail = &message[message.len() - 4..];
        assert_eq!(tail, &[0, 1, 0, 1], "A/IN");
    }

    #[test]
    fn the_probe_hostname_is_encodable() {
        assert!(query(1, PROBE_HOSTNAME).is_some());
    }

    #[test]
    fn a_name_that_cannot_be_encoded_is_refused_rather_than_truncated() {
        assert_eq!(query(1, &"a".repeat(64)), None);
        let too_long = std::iter::repeat_n("abcdefghij", 30)
            .collect::<Vec<_>>()
            .join(".");
        assert_eq!(query(1, &too_long), None);
    }

    /// The whole point of the probe: an answer to *this* query.
    #[test]
    fn a_matching_successful_response_is_accepted() {
        let mut response = query(0x1234, PROBE_HOSTNAME).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        assert_eq!(verdict(&response, 0x1234), ResolverVerdict::Answered);
    }

    /// A resolver that says NXDOMAIN is still a working resolver. Reachability
    /// is the question, not whether this one name exists.
    #[test]
    fn a_failure_code_still_proves_the_resolver_is_alive() {
        let mut response = query(0x1234, PROBE_HOSTNAME).unwrap();
        response[2] = 0x81;
        response[3] = 0x83;
        assert_eq!(
            verdict(&response, 0x1234),
            ResolverVerdict::Refused { rcode: 3 }
        );
    }

    #[test]
    fn a_reply_to_someone_elses_query_is_not_credited() {
        let mut response = query(0x1234, PROBE_HOSTNAME).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        assert_eq!(verdict(&response, 0x4321), ResolverVerdict::Mismatched);
    }

    /// Our own query echoed back is not an answer, and neither is a runt.
    #[test]
    fn a_query_or_a_truncated_message_is_not_an_answer() {
        let request = query(0x1234, PROBE_HOSTNAME).unwrap();
        assert_eq!(verdict(&request, 0x1234), ResolverVerdict::Mismatched);
        assert_eq!(verdict(&[], 0x1234), ResolverVerdict::Mismatched);
        assert_eq!(verdict(&request[..8], 0x1234), ResolverVerdict::Mismatched);
    }

    #[test]
    fn the_relay_resolver_leads_but_never_stands_alone() {
        let relay = Ipv4Addr::new(10, 203, 0, 1);
        assert_eq!(
            resolver_order(Some(relay)),
            vec![relay, FALLBACK_RESOLVERS[0]]
        );
        assert_eq!(resolver_order(None), FALLBACK_RESOLVERS.to_vec());
        // Never empty: handing Windows no resolver at all is the one outcome
        // that would leave the machine unable to resolve anything.
        assert!(!resolver_order(None).is_empty());
    }
}
