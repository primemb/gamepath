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

pub(crate) fn is_matching_icmp_reply(
    packet: &[u8],
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    identifier: u16,
) -> bool {
    packet.len() >= 28
        && packet[0] >> 4 == 4
        && packet[9] == 1
        && packet[12..16] == source.octets()
        && packet[16..20] == destination.octets()
        && packet[20] == 0
        && u16::from_be_bytes([packet[24], packet[25]]) == identifier
        && internet_checksum(&packet[20..]) == 0
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
        assert!(is_matching_icmp_reply(&packet, source, destination, 42));
    }
}
