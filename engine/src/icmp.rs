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

fn internet_checksum(bytes: &[u8]) -> u16 {
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
