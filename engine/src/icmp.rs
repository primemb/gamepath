//! Hand-built ICMP echoes.
//!
//! Both session kinds measure the trip out to the Internet by sending an echo
//! request *through* the tunnel, which means building the IPv4 and ICMP
//! headers here rather than opening a raw socket the OS would route itself.

pub(crate) fn icmp_echo_packet(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    identifier: u16,
    sequence: u16,
    reply: bool,
) -> Vec<u8> {
    let payload = b"gamepath-data-plane";
    let total_length = 20 + 8 + payload.len();
    let mut packet = vec![0_u8; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[20] = if reply { 0 } else { 8 };
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    packet[26..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp_checksum = internet_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    packet
}

pub(crate) fn icmp_reply_sequence(
    packet: &[u8],
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    identifier: u16,
) -> Option<u16> {
    if packet.len() < 28 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_length < 20
        || total_length < header_length + 8
        || total_length > packet.len()
        || packet[9] != 1
        || packet[12..16] != source.octets()
        || packet[16..20] != destination.octets()
        || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
    {
        return None;
    }
    let echo = &packet[header_length..total_length];
    (echo[0] == 0
        && echo[1] == 0
        && u16::from_be_bytes([echo[4], echo[5]]) == identifier
        && internet_checksum(echo) == 0)
        .then(|| u16::from_be_bytes([echo[6], echo[7]]))
}

/// The ICMP "fragmentation needed" a router would return for `packet`, a
/// Don't Fragment datagram larger than `mtu`, built as WinDivert's driver
/// builds its own (`windivert_inject_packet_too_big`): from the original
/// destination, carrying the original header and its first eight bytes.
///
/// Split mode takes such a packet before any interface sees it, so without
/// this the sender learns nothing and its packets simply vanish (WinDivert
/// issue #278). With it, Windows lowers its path MTU for that destination and
/// the next oversized send fails with `WSAEMSGSIZE`, which is how RakNet's
/// MTU discovery moves straight to its next size.
pub(crate) fn fragmentation_needed(packet: &[u8], mtu: u16) -> Option<Vec<u8>> {
    let header_length = usize::from(*packet.first()? & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    let flags = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
    if packet[0] >> 4 != 4
        || header_length < 20
        || total_length > packet.len()
        || total_length <= usize::from(mtu)
        || flags & 0x4000 == 0
        || flags & 0x3fff != 0
        // Never an ICMP error about an ICMP error (RFC 1122 3.2.2).
        || (packet[9] == 1 && !matches!(packet.get(header_length), Some(0 | 8)))
    {
        return None;
    }
    let quoted = &packet[..(header_length + 8).min(total_length)];
    let length = 20 + 8 + quoted.len();
    let mut reply = vec![0_u8; length];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    reply[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    reply[8] = 64;
    reply[9] = 1;
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);
    let header_checksum = internet_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    reply[20] = 3;
    reply[21] = 4;
    reply[26..28].copy_from_slice(&mtu.to_be_bytes());
    reply[28..].copy_from_slice(quoted);
    let icmp_checksum = internet_checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    Some(reply)
}

pub(crate) fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RakNet's first MTU probe: 1492 bytes with Don't Fragment set.
    fn raknet_probe() -> Vec<u8> {
        let mut packet = vec![0_u8; 1492];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&1492_u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 128;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 168, 1, 20]);
        packet[16..20].copy_from_slice(&[79, 137, 98, 19]);
        packet[20..24].copy_from_slice(&[0xc3, 0x50, 0x6d, 0x60]);
        packet
    }

    #[test]
    fn an_oversized_dont_fragment_packet_gets_what_a_router_would_send() {
        let probe = raknet_probe();
        let reply = fragmentation_needed(&probe, 1280).unwrap();
        assert_eq!(reply.len(), 20 + 8 + 28);
        assert_eq!(internet_checksum(&reply[..20]), 0);
        assert_eq!(internet_checksum(&reply[20..]), 0);
        assert_eq!(&reply[12..16], &[79, 137, 98, 19], "from the destination");
        assert_eq!(&reply[16..20], &[192, 168, 1, 20], "to the sender");
        assert_eq!((reply[20], reply[21]), (3, 4));
        assert_eq!(u16::from_be_bytes([reply[26], reply[27]]), 1280);
        assert_eq!(&reply[28..], &probe[..28], "quotes the header and ports");
    }

    #[test]
    fn only_oversized_unfragmented_dont_fragment_packets_are_refused() {
        let probe = raknet_probe();
        assert!(fragmentation_needed(&probe, 1492).is_none(), "it fits");
        let mut fragmentable = probe.clone();
        fragmentable[6..8].fill(0);
        assert!(fragmentation_needed(&fragmentable, 1280).is_none());
        let mut fragment = probe.clone();
        fragment[6..8].copy_from_slice(&0x6000_u16.to_be_bytes());
        assert!(fragmentation_needed(&fragment, 1280).is_none());
        let mut icmp_error = probe.clone();
        icmp_error[9] = 1;
        icmp_error[20] = 3;
        assert!(fragmentation_needed(&icmp_error, 1280).is_none());
        icmp_error[20] = 8;
        assert!(
            fragmentation_needed(&icmp_error, 1280).is_some(),
            "an echo is"
        );
        assert!(fragmentation_needed(&probe[..100], 1280).is_none());
    }

    #[test]
    fn icmp_probe_packet_has_valid_checksums() {
        let source = "10.203.0.1".parse().unwrap();
        let destination = "10.203.0.2".parse().unwrap();
        let packet = icmp_echo_packet(source, destination, 42, 1, true);
        assert_eq!(internet_checksum(&packet[..20]), 0);
        assert_eq!(
            icmp_reply_sequence(&packet, source, destination, 42),
            Some(1)
        );
    }

    #[test]
    fn a_delayed_reply_keeps_its_original_sequence() {
        let source = "10.203.0.1".parse().unwrap();
        let destination = "10.203.0.2".parse().unwrap();
        let reply = icmp_echo_packet(source, destination, 42, 9, true);
        assert_eq!(
            icmp_reply_sequence(&reply, source, destination, 42),
            Some(9)
        );
        assert_eq!(icmp_reply_sequence(&reply, source, destination, 43), None);
    }

    #[test]
    fn a_reply_with_ipv4_options_is_matched_at_its_actual_header_length() {
        let source = "10.203.0.1".parse().unwrap();
        let destination = "10.203.0.2".parse().unwrap();
        let mut reply = icmp_echo_packet(source, destination, 42, 9, true);
        reply.splice(20..20, [1, 1, 1, 1]);
        reply[0] = 0x46;
        let length = reply.len() as u16;
        reply[2..4].copy_from_slice(&length.to_be_bytes());
        reply[10..12].fill(0);
        let checksum = internet_checksum(&reply[..24]);
        reply[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            icmp_reply_sequence(&reply, source, destination, 42),
            Some(9)
        );
    }

    #[test]
    fn truncated_or_fragmented_replies_are_not_measurements() {
        let source = "10.203.0.1".parse().unwrap();
        let destination = "10.203.0.2".parse().unwrap();
        let reply = icmp_echo_packet(source, destination, 42, 9, true);
        for length in 0..reply.len() {
            assert_eq!(
                icmp_reply_sequence(&reply[..length], source, destination, 42),
                None
            );
        }
        let mut fragmented = reply;
        fragmented[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert_eq!(
            icmp_reply_sequence(&fragmented, source, destination, 42),
            None
        );
    }
}
