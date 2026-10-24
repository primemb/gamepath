//! TCP MSS clamping, so a connection's segments fit what the link carries
//! whole. Both directions' SYNs are clamped: each side sizes what it sends
//! from the MSS the other advertised.

/// Lowers the MSS a SYN advertises to `maximum`, leaving a smaller one alone.
/// The TCP checksum is not updated; true when the packet changed.
pub fn clamp(packet: &mut [u8], maximum: u16) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return false;
    }
    let ip_header = usize::from(packet[0] & 0x0f) * 4;
    if packet.len() < ip_header + 20 || packet[ip_header + 13] & 0x02 == 0 {
        return false;
    }
    let tcp_header = usize::from(packet[ip_header + 12] >> 4) * 4;
    if tcp_header < 20 || packet.len() < ip_header + tcp_header {
        return false;
    }
    let mut offset = ip_header + 20;
    let end = ip_header + tcp_header;
    while offset < end {
        match packet[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let Some(&length) = packet.get(offset + 1) else {
                    break;
                };
                let length = usize::from(length);
                if length < 2 || offset + length > end {
                    break;
                }
                if kind == 2 && length == 4 {
                    let current = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                    if current > maximum {
                        packet[offset + 2..offset + 4].copy_from_slice(&maximum.to_be_bytes());
                        return true;
                    }
                    break;
                }
                offset += length;
            }
        }
    }
    false
}

/// [`clamp`], then the TCP checksum recomputed, for a packet nothing else
/// will checksum before it is delivered.
pub fn clamp_with_checksum(packet: &mut [u8], maximum: u16) -> bool {
    if !clamp(packet, maximum) {
        return false;
    }
    let ip_header = usize::from(packet[0] & 0x0f) * 4;
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
    let segment_length = total_length.saturating_sub(ip_header);
    packet[ip_header + 16..ip_header + 18].fill(0);
    let mut sum = 0_u32;
    for word in packet[12..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    sum += 6 + segment_length as u32;
    let mut words = packet[ip_header..total_length].chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(&last) = words.remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[ip_header + 16..ip_header + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP SYN advertising `mss`.
    fn syn_with_mss(mss: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 44];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&44_u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 203, 0, 2]);
        packet[16..20].copy_from_slice(&[54, 115, 107, 161]);
        packet[20 + 12] = 0x60;
        packet[20 + 13] = 0x02;
        packet[40..42].copy_from_slice(&[2, 4]);
        packet[42..44].copy_from_slice(&mss.to_be_bytes());
        packet
    }

    /// Sums the pseudo-header and segment; zero when the checksum is right.
    fn verify(packet: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let mut add = |bytes: &[u8]| {
            for pair in bytes.chunks(2) {
                sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
            }
        };
        add(&packet[12..20]);
        add(&[0, 6]);
        add(&((packet.len() - 20) as u16).to_be_bytes());
        add(&packet[20..]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn nested_tunnel_clamps_tcp_mss() {
        let mut packet = syn_with_mss(1460);
        assert!(clamp(&mut packet, 1000));
        assert_eq!(&packet[42..44], &1000_u16.to_be_bytes());
    }

    #[test]
    fn the_clamp_only_ever_lowers_the_advertised_mss() {
        // The derived clamp is far above the old fixed 1000, so it matters that
        // a peer offering less is left alone rather than talked upwards.
        let mut packet = syn_with_mss(536);
        assert!(!clamp(&mut packet, 1316));
        assert_eq!(&packet[42..44], &536_u16.to_be_bytes());
    }

    #[test]
    fn a_clamped_syn_keeps_a_valid_checksum() {
        let mut packet = syn_with_mss(1240);
        assert!(clamp_with_checksum(&mut packet, 1188));
        assert_eq!(&packet[42..44], &1188_u16.to_be_bytes());
        assert_eq!(verify(&packet), 0);
    }
}
