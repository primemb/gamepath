//! The few IPv4 packets the SOCKS5 stack reads and writes itself: everything
//! that is not TCP, which smoltcp handles.

use std::net::{Ipv4Addr, SocketAddrV4};

pub(crate) const PROTOCOL_ICMP: u8 = 1;
pub(crate) const PROTOCOL_TCP: u8 = 6;
pub(crate) const PROTOCOL_UDP: u8 = 17;
const TTL: u8 = 64;

pub(crate) struct Ipv4<'a> {
    pub(crate) protocol: u8,
    pub(crate) source: Ipv4Addr,
    pub(crate) destination: Ipv4Addr,
    pub(crate) fragmented: bool,
    pub(crate) payload: &'a [u8],
}

pub(crate) fn parse_ipv4(packet: &[u8]) -> Option<Ipv4<'_>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header < 20 || total < header || total > packet.len() {
        return None;
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    Some(Ipv4 {
        protocol: packet[9],
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        // More-fragments set, or any offset: not a whole datagram.
        fragmented: flags_offset & 0x3fff != 0,
        payload: &packet[header..total],
    })
}

pub(crate) struct Udp<'a> {
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) payload: &'a [u8],
}

pub(crate) fn parse_udp(segment: &[u8]) -> Option<Udp<'_>> {
    if segment.len() < 8 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
    if length < 8 || length > segment.len() {
        return None;
    }
    Some(Udp {
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        payload: &segment[8..length],
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TcpHead {
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) sequence: u32,
    pub(crate) syn: bool,
    pub(crate) ack: bool,
    pub(crate) rst: bool,
}

pub(crate) fn parse_tcp(segment: &[u8]) -> Option<TcpHead> {
    if segment.len() < 20 {
        return None;
    }
    let flags = segment[13];
    Some(TcpHead {
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        sequence: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
    })
}

fn sum(data: &[u8], mut accumulator: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        accumulator += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        accumulator += u32::from(*last) << 8;
    }
    accumulator
}

fn fold(mut accumulator: u32) -> u16 {
    while accumulator >> 16 != 0 {
        accumulator = (accumulator & 0xffff) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

fn pseudo_header(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, length: usize) -> u32 {
    let mut accumulator = sum(&source.octets(), 0);
    accumulator = sum(&destination.octets(), accumulator);
    accumulator + u32::from(protocol) + length as u32
}

fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    // Identification 0 with don't-fragment set, as for any atomic datagram.
    packet.extend_from_slice(&[0, 0, 0x40, 0, TTL, protocol, 0, 0]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    let checksum = fold(sum(&packet, 0));
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// A whole IPv4/UDP datagram from `source` to `destination`.
pub(crate) fn build_udp(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    payload: &[u8],
) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut segment = Vec::with_capacity(length);
    segment.extend_from_slice(&source.port().to_be_bytes());
    segment.extend_from_slice(&destination.port().to_be_bytes());
    segment.extend_from_slice(&(length as u16).to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let checksum = fold(sum(
        &segment,
        pseudo_header(*source.ip(), *destination.ip(), PROTOCOL_UDP, length),
    ));
    // A computed zero is sent as all ones; zero means "no checksum".
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    ipv4_packet(*source.ip(), *destination.ip(), PROTOCOL_UDP, &segment)
}

/// The reset that refuses a SYN, as a host with nothing listening would.
pub(crate) fn build_tcp_reset(from: SocketAddrV4, to: SocketAddrV4, acknowledges: u32) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20);
    segment.extend_from_slice(&from.port().to_be_bytes());
    segment.extend_from_slice(&to.port().to_be_bytes());
    segment.extend_from_slice(&0_u32.to_be_bytes());
    segment.extend_from_slice(&acknowledges.to_be_bytes());
    // Five-word header, RST and ACK, no window.
    segment.extend_from_slice(&[0x50, 0x14, 0, 0, 0, 0, 0, 0]);
    let checksum = fold(sum(
        &segment,
        pseudo_header(*from.ip(), *to.ip(), PROTOCOL_TCP, segment.len()),
    ));
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    ipv4_packet(*from.ip(), *to.ip(), PROTOCOL_TCP, &segment)
}

/// Whether `packet` is an ICMP echo request.
pub(crate) fn is_echo_request(packet: &Ipv4<'_>) -> bool {
    packet.protocol == PROTOCOL_ICMP && packet.payload.len() >= 8 && packet.payload[0] == 8
}

/// The echo reply `request` asks for: same identifier, sequence and data.
pub(crate) fn build_echo_reply(request: &Ipv4<'_>) -> Vec<u8> {
    let mut message = request.payload.to_vec();
    message[0] = 0;
    message[2..4].copy_from_slice(&[0, 0]);
    let checksum = fold(sum(&message, 0));
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    ipv4_packet(request.destination, request.source, PROTOCOL_ICMP, &message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 207, 0, 2), 50_000);
    const SERVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 53);

    /// A packet's checksums verify when summing over them gives zero.
    fn verifies(data: &[u8], start: u32) -> bool {
        fold(sum(data, start)) == 0
    }

    #[test]
    fn a_built_datagram_parses_back_with_valid_checksums() {
        let packet = build_udp(SERVER, APP, b"answer");
        let ip = parse_ipv4(&packet).unwrap();
        assert!(verifies(&packet[..20], 0));
        assert_eq!((ip.source, ip.destination), (*SERVER.ip(), *APP.ip()));
        assert!(!ip.fragmented);
        let udp = parse_udp(ip.payload).unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (53, 50_000));
        assert_eq!(udp.payload, b"answer");
        assert!(verifies(
            ip.payload,
            pseudo_header(ip.source, ip.destination, PROTOCOL_UDP, ip.payload.len())
        ));
    }

    #[test]
    fn a_reset_answers_the_syn_it_refuses() {
        let packet = build_tcp_reset(SERVER, APP, 1001);
        let ip = parse_ipv4(&packet).unwrap();
        let tcp = parse_tcp(ip.payload).unwrap();
        assert!(tcp.rst && tcp.ack && !tcp.syn);
        assert_eq!(
            u32::from_be_bytes(ip.payload[8..12].try_into().unwrap()),
            1001
        );
        assert!(verifies(
            ip.payload,
            pseudo_header(ip.source, ip.destination, PROTOCOL_TCP, ip.payload.len())
        ));
    }

    #[test]
    fn an_echo_reply_mirrors_the_request() {
        let mut message = vec![8, 0, 0, 0, 0x12, 0x34, 0, 7, b'p', b'i', b'n', b'g'];
        let checksum = fold(sum(&message, 0));
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let request_bytes = ipv4_packet(*APP.ip(), *SERVER.ip(), PROTOCOL_ICMP, &message);
        let request = parse_ipv4(&request_bytes).unwrap();
        assert!(is_echo_request(&request));
        let reply_bytes = build_echo_reply(&request);
        let reply = parse_ipv4(&reply_bytes).unwrap();
        assert_eq!((reply.source, reply.destination), (*SERVER.ip(), *APP.ip()));
        assert_eq!(reply.payload[0], 0);
        assert_eq!(&reply.payload[4..], &message[4..]);
        assert!(verifies(reply.payload, 0));
    }

    #[test]
    fn malformed_and_fragmented_packets_are_recognised() {
        assert!(parse_ipv4(&[0x45; 10]).is_none());
        assert!(parse_ipv4(&[0x60; 40]).is_none());
        let mut fragment = build_udp(APP, SERVER, b"part");
        fragment[6] = 0x20;
        assert!(parse_ipv4(&fragment).unwrap().fragmented);
        assert!(parse_udp(&[0; 4]).is_none());
        assert!(parse_tcp(&[0; 12]).is_none());
    }
}
