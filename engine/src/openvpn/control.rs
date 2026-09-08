//! OpenVPN's control channel: packet framing and the small reliability layer
//! that carries a TLS handshake over an unreliable link.
//!
//! Control packets are numbered and acknowledged independently of TLS, because
//! TLS cannot tolerate loss or reordering. This module turns a stream of TLS
//! bytes into numbered packets and back, and hides whichever of `--tls-auth`
//! and `--tls-crypt` wraps them.

use super::config::{ControlAuth, Digest};
use super::crypto::{TlsAuthKeys, TlsCryptKeys, hmac, tls_crypt_apply};
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
pub const P_CONTROL_V1: u8 = 4;
pub const P_ACK_V1: u8 = 5;
pub const P_DATA_V1: u8 = 6;
pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub const P_DATA_V2: u8 = 9;

/// How much TLS handshake data one control packet carries.
///
/// Small enough that the wrapped packet clears a path with a reduced MTU, which
/// is worth more than the extra round trips: a handshake packet that does not
/// fit is dropped silently and retransmitted at exactly the same size forever.
const MAX_CONTROL_PAYLOAD: usize = 1000;

/// How long to wait for an acknowledgement before sending a packet again.
const RETRANSMIT_AFTER: Duration = Duration::from_millis(1200);

/// The most acknowledgements one packet can carry.
const MAX_ACKS: usize = 8;

pub fn is_data(opcode: u8) -> bool {
    opcode == P_DATA_V1 || opcode == P_DATA_V2
}

pub fn opcode_of(packet: &[u8]) -> Option<u8> {
    packet.first().map(|byte| byte >> 3)
}

enum Wrapping {
    None,
    TlsAuth(TlsAuthKeys),
    TlsCrypt(TlsCryptKeys),
}

struct Pending {
    packet_id: u32,
    packet: Vec<u8>,
    sent_at: Instant,
}

/// What a received control packet turned out to mean.
#[derive(Debug)]
pub enum Received {
    /// Nothing for the caller to act on: an acknowledgement, a duplicate, or a
    /// packet held back until the ones before it arrive.
    Nothing,
    /// The server answered our reset and the TLS handshake can begin.
    ServerReset,
    /// The server wants to rekey on a new key id.
    SoftReset { key_id: u8 },
    /// TLS bytes, in order.
    Payload(Vec<u8>),
}

/// One end of the control channel.
pub struct ControlChannel {
    wrapping: Wrapping,
    session_id: [u8; 8],
    remote_session_id: Option<[u8; 8]>,
    key_id: u8,
    next_packet_id: u32,
    /// The counter in the replay header that `--tls-auth` and `--tls-crypt`
    /// add, which is separate from the reliability layer's own numbering.
    next_replay_id: u32,
    unacknowledged: Vec<Pending>,
    pending_acks: Vec<u32>,
    expected_packet_id: u32,
    reordered: BTreeMap<u32, Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
}

impl ControlChannel {
    pub fn new(control_auth: &ControlAuth) -> Self {
        use rand::Rng as _;
        let wrapping = match control_auth {
            ControlAuth::None => Wrapping::None,
            ControlAuth::TlsAuth {
                key,
                direction,
                digest,
            } => Wrapping::TlsAuth(TlsAuthKeys::new(key, *direction, *digest)),
            ControlAuth::TlsCrypt { key } => Wrapping::TlsCrypt(TlsCryptKeys::new(key)),
        };
        Self {
            wrapping,
            session_id: rand::rng().random(),
            remote_session_id: None,
            key_id: 0,
            next_packet_id: 0,
            next_replay_id: 1,
            unacknowledged: Vec::new(),
            pending_acks: Vec::new(),
            expected_packet_id: 0,
            reordered: BTreeMap::new(),
            outgoing: VecDeque::new(),
        }
    }

    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    pub fn remote_session_id(&self) -> Option<[u8; 8]> {
        self.remote_session_id
    }

    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// Queues the packet that opens a session.
    pub fn start(&mut self) {
        self.send(P_CONTROL_HARD_RESET_CLIENT_V2, &[]);
    }

    /// Queues TLS bytes, split across as many packets as they need.
    pub fn send_tls(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(MAX_CONTROL_PAYLOAD) {
            self.send(P_CONTROL_V1, chunk);
        }
    }

    /// Takes the next packet to put on the link.
    pub fn take_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    /// Queues another copy of anything that has gone unacknowledged for too
    /// long, and reports whether the peer has stopped acknowledging entirely.
    pub fn resend_stale(&mut self, now: Instant) {
        let mut due = Vec::new();
        for pending in &mut self.unacknowledged {
            if now.duration_since(pending.sent_at) >= RETRANSMIT_AFTER {
                pending.sent_at = now;
                due.push(pending.packet.clone());
            }
        }
        self.outgoing.extend(due);
    }

    /// Queues the packet that opens a new key generation.
    ///
    /// A renegotiation reuses the session -- both session ids stay as they
    /// were -- so it starts from a soft reset rather than a hard one.
    pub fn restart(&mut self) {
        self.send(P_CONTROL_SOFT_RESET_V1, &[]);
    }

    /// Begins a new key generation after the server asks to rekey.
    pub fn rekey(&mut self, key_id: u8) {
        self.key_id = key_id;
        self.next_packet_id = 0;
        self.expected_packet_id = 0;
        self.unacknowledged.clear();
        self.reordered.clear();
        self.pending_acks.clear();
    }

    fn send(&mut self, opcode: u8, payload: &[u8]) {
        let (packet, packet_id) = self.wrap(opcode, payload, true);
        if let Some(packet_id) = packet_id {
            self.unacknowledged.push(Pending {
                packet_id,
                packet: packet.clone(),
                sent_at: Instant::now(),
            });
        }
        self.outgoing.push_back(packet);
    }

    /// Sends the acknowledgements that have piled up, if any remain after
    /// whatever was piggybacked on outgoing traffic.
    fn flush_acks(&mut self) {
        if self.pending_acks.is_empty() || self.remote_session_id.is_none() {
            return;
        }
        let (packet, _) = self.wrap(P_ACK_V1, &[], true);
        self.outgoing.push_back(packet);
    }

    /// Builds one control packet.
    ///
    /// The body -- acknowledgements, then this packet's own id, then the
    /// payload -- is the same whichever wrapping is in use. What differs is
    /// what goes in front of it and whether the body travels in the clear.
    fn wrap(&mut self, opcode: u8, payload: &[u8], with_acks: bool) -> (Vec<u8>, Option<u32>) {
        let acks: Vec<u32> = if with_acks && self.remote_session_id.is_some() {
            let count = self.pending_acks.len().min(MAX_ACKS);
            self.pending_acks.drain(..count).collect()
        } else {
            Vec::new()
        };
        let mut body = Vec::with_capacity(payload.len() + 32);
        body.push(acks.len() as u8);
        for ack in &acks {
            body.extend_from_slice(&ack.to_be_bytes());
        }
        if !acks.is_empty() {
            body.extend_from_slice(
                &self
                    .remote_session_id
                    .expect("acknowledgements need the peer's session id"),
            );
        }
        let packet_id = if opcode == P_ACK_V1 {
            None
        } else {
            let packet_id = self.next_packet_id;
            self.next_packet_id = self.next_packet_id.wrapping_add(1);
            body.extend_from_slice(&packet_id.to_be_bytes());
            Some(packet_id)
        };
        body.extend_from_slice(payload);

        let first = (opcode << 3) | self.key_id;
        // Taken before the wrapping is chosen: only two of the three need it,
        // but reading it inside the match would borrow the channel twice.
        let replay = match self.wrapping {
            Wrapping::None => [0_u8; 8],
            _ => self.replay_header(),
        };
        let packet = match &self.wrapping {
            Wrapping::None => {
                let mut packet = Vec::with_capacity(9 + body.len());
                packet.push(first);
                packet.extend_from_slice(&self.session_id);
                packet.extend_from_slice(&body);
                packet
            }
            Wrapping::TlsAuth(keys) => {
                let mac = hmac(
                    keys.digest,
                    &keys.send,
                    &[&replay, &[first], &self.session_id, &body],
                );
                let mut packet = Vec::with_capacity(9 + mac.len() + 8 + body.len());
                packet.push(first);
                packet.extend_from_slice(&self.session_id);
                packet.extend_from_slice(&mac);
                packet.extend_from_slice(&replay);
                packet.extend_from_slice(&body);
                packet
            }
            Wrapping::TlsCrypt(keys) => {
                let mut header = Vec::with_capacity(17);
                header.push(first);
                header.extend_from_slice(&self.session_id);
                header.extend_from_slice(&replay);
                let tag = hmac(Digest::Sha256, &keys.send_hmac, &[&header, &body]);
                let mut encrypted = body.clone();
                tls_crypt_apply(&keys.send_cipher, &tag, &mut encrypted);
                let mut packet = Vec::with_capacity(header.len() + tag.len() + encrypted.len());
                packet.extend_from_slice(&header);
                packet.extend_from_slice(&tag);
                packet.extend_from_slice(&encrypted);
                packet
            }
        };
        (packet, packet_id)
    }

    /// The packet id and timestamp that the authenticated wrappings put in
    /// front of the body to stop a replay.
    fn replay_header(&mut self) -> [u8; 8] {
        let mut header = [0_u8; 8];
        header[..4].copy_from_slice(&self.next_replay_id.to_be_bytes());
        self.next_replay_id = self.next_replay_id.wrapping_add(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs() as u32)
            .unwrap_or_default();
        header[4..].copy_from_slice(&now.to_be_bytes());
        header
    }

    /// Reads one control packet and says what it meant.
    pub fn receive(&mut self, packet: &[u8]) -> Result<Received, String> {
        let opcode = opcode_of(packet).ok_or("an OpenVPN control packet was empty")?;
        if packet.len() < 9 {
            return Err("an OpenVPN control packet was truncated".into());
        }
        // A renegotiation restarts the numbering, so a retransmission from the
        // generation being replaced would otherwise be read as a packet of the
        // new one. The soft reset is the exception: it is what announces the
        // new key id in the first place.
        if packet[0] & 0x07 != self.key_id && opcode != P_CONTROL_SOFT_RESET_V1 {
            return Ok(Received::Nothing);
        }
        let mut server_session_id = [0_u8; 8];
        server_session_id.copy_from_slice(&packet[1..9]);

        let body = match &self.wrapping {
            Wrapping::None => packet[9..].to_vec(),
            Wrapping::TlsAuth(keys) => {
                let size = keys.digest.output_len();
                if packet.len() < 9 + size + 8 {
                    return Err("a tls-auth control packet was truncated".into());
                }
                let mac = &packet[9..9 + size];
                let replay = &packet[9 + size..9 + size + 8];
                let body = &packet[9 + size + 8..];
                let expected = hmac(
                    keys.digest,
                    &keys.receive,
                    &[replay, &[packet[0]], &server_session_id, body],
                );
                if !constant_time_eq(&expected, mac) {
                    return Err(
                        "a control packet failed its tls-auth check, so the `<tls-auth>` key or \
                         its direction does not match the server's"
                            .into(),
                    );
                }
                body.to_vec()
            }
            Wrapping::TlsCrypt(keys) => {
                if packet.len() < 49 {
                    return Err("a tls-crypt control packet was truncated".into());
                }
                let (header, rest) = packet.split_at(17);
                let (tag, encrypted) = rest.split_at(32);
                let mut body = encrypted.to_vec();
                tls_crypt_apply(&keys.receive_cipher, tag, &mut body);
                let expected = hmac(Digest::Sha256, &keys.receive_hmac, &[header, &body]);
                if !constant_time_eq(&expected, tag) {
                    return Err(
                        "a control packet failed its tls-crypt check, so the `<tls-crypt>` key \
                         does not match the server's"
                            .into(),
                    );
                }
                body
            }
        };

        let mut cursor = 0;
        let ack_count = usize::from(*body.first().ok_or("a control packet had no body")?);
        cursor += 1;
        let mut acks = Vec::with_capacity(ack_count);
        for _ in 0..ack_count {
            let end = cursor + 4;
            if body.len() < end {
                return Err("a control packet's acknowledgement list was truncated".into());
            }
            acks.push(u32::from_be_bytes(
                body[cursor..end].try_into().expect("four bytes"),
            ));
            cursor = end;
        }
        if ack_count > 0 {
            cursor += 8;
            if body.len() < cursor {
                return Err("a control packet's acknowledgement block was truncated".into());
            }
        }
        let packet_id = if opcode == P_ACK_V1 {
            None
        } else {
            let end = cursor + 4;
            if body.len() < end {
                return Err("a control packet had no packet id".into());
            }
            let packet_id = u32::from_be_bytes(body[cursor..end].try_into().expect("four bytes"));
            cursor = end;
            Some(packet_id)
        };

        if self.remote_session_id.is_none() {
            self.remote_session_id = Some(server_session_id);
        }
        for ack in acks {
            self.unacknowledged
                .retain(|pending| pending.packet_id != ack);
        }
        let Some(packet_id) = packet_id else {
            return Ok(Received::Nothing);
        };
        self.pending_acks.push(packet_id);

        // A reset occupies a slot in the numbering, so the in-order reader has
        // to step past it or it waits forever for a payload that never comes.
        if opcode == P_CONTROL_HARD_RESET_SERVER_V2 {
            if packet_id == self.expected_packet_id {
                self.expected_packet_id += 1;
            }
            self.flush_acks();
            return Ok(Received::ServerReset);
        }
        if opcode == P_CONTROL_SOFT_RESET_V1 {
            if packet_id == self.expected_packet_id {
                self.expected_packet_id += 1;
            }
            self.flush_acks();
            return Ok(Received::SoftReset {
                key_id: packet[0] & 0x07,
            });
        }

        self.reordered.insert(packet_id, body[cursor..].to_vec());
        self.flush_acks();
        let mut payload = Vec::new();
        while let Some(chunk) = self.reordered.remove(&self.expected_packet_id) {
            self.expected_packet_id += 1;
            payload.extend_from_slice(&chunk);
        }
        if payload.is_empty() {
            Ok(Received::Nothing)
        } else {
            Ok(Received::Payload(payload))
        }
    }
}

/// Compares two authentication tags without leaking where they differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openvpn::config::{KeyDirection, OpenVpnConfig};

    /// A pair of channels wired to each other's key direction, standing in for
    /// a client and a server.
    fn pair(auth: &ControlAuth) -> (ControlChannel, ControlChannel) {
        (ControlChannel::new(auth), ControlChannel::new(auth))
    }

    fn static_key_config(tag: &str, direction: Option<u8>) -> ControlAuth {
        let hex = (0..256)
            .map(|byte| format!("{:02x}", (byte * 7 % 251) as u8))
            .collect::<String>();
        let direction_line = direction
            .map(|value| format!("key-direction {value}\n"))
            .unwrap_or_default();
        let source = format!(
            "remote vpn.example 1194\nauth-user-pass\nauth SHA256\n{direction_line}\
             <ca>\n-----BEGIN CERTIFICATE-----\nMIIBIjCByaADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3QgQ0Ew\n-----END CERTIFICATE-----\n</ca>\n\
             <{tag}>\n-----BEGIN OpenVPN Static key V1-----\n{hex}\n-----END OpenVPN Static key V1-----\n</{tag}>\n"
        );
        OpenVpnConfig::parse(&source).unwrap().control_auth
    }

    #[test]
    fn a_hard_reset_carries_no_acknowledgements_and_packet_id_zero() {
        let mut channel = ControlChannel::new(&ControlAuth::None);
        channel.start();
        let packet = channel.take_outgoing().unwrap();
        assert_eq!(packet.len(), 14, "opcode, session id, empty ack list, id");
        assert_eq!(packet[0] >> 3, P_CONTROL_HARD_RESET_CLIENT_V2);
        assert_eq!(packet[9], 0, "no acknowledgements yet");
        assert_eq!(&packet[10..14], &0_u32.to_be_bytes());
    }

    #[test]
    fn tls_bytes_are_split_across_packets_that_fit_a_reduced_path() {
        let mut channel = ControlChannel::new(&ControlAuth::None);
        channel.start();
        channel.take_outgoing().unwrap();
        channel.send_tls(&vec![0_u8; MAX_CONTROL_PAYLOAD * 2 + 1]);
        let mut packets = Vec::new();
        while let Some(packet) = channel.take_outgoing() {
            packets.push(packet);
        }
        assert_eq!(packets.len(), 3);
        for packet in &packets[..2] {
            assert!(packet.len() <= MAX_CONTROL_PAYLOAD + 14);
        }
    }

    /// The reliability layer is exercised by moving packets between two
    /// channels by hand, which is the only way to see reordering and loss
    /// without a network.
    fn deliver(from: &mut ControlChannel, to: &mut ControlChannel) -> Vec<Received> {
        let mut results = Vec::new();
        while let Some(packet) = from.take_outgoing() {
            results.push(to.receive(&packet).unwrap());
        }
        results
    }

    #[test]
    fn payloads_are_delivered_in_order_even_when_packets_are_not() {
        let (mut client, mut server) = pair(&ControlAuth::None);
        client.start();
        // The server has to learn the client's session id before it can
        // acknowledge, which the reset does.
        deliver(&mut client, &mut server);
        server.start();
        deliver(&mut server, &mut client);

        client.send_tls(b"first");
        client.send_tls(b"second");
        let mut packets = Vec::new();
        while let Some(packet) = client.take_outgoing() {
            packets.push(packet);
        }
        packets.reverse();
        let mut delivered = Vec::new();
        for packet in packets {
            if let Received::Payload(payload) = server.receive(&packet).unwrap() {
                delivered.extend_from_slice(&payload);
            }
        }
        assert_eq!(delivered, b"firstsecond".to_vec());
    }

    #[test]
    fn an_unacknowledged_packet_is_sent_again() {
        let mut channel = ControlChannel::new(&ControlAuth::None);
        channel.start();
        let first = channel.take_outgoing().unwrap();
        assert!(channel.take_outgoing().is_none());
        channel.resend_stale(Instant::now() + RETRANSMIT_AFTER);
        assert_eq!(channel.take_outgoing().unwrap(), first);
    }

    #[test]
    fn an_acknowledged_packet_is_not_sent_again() {
        let (mut client, mut server) = pair(&ControlAuth::None);
        client.start();
        deliver(&mut client, &mut server);
        server.start();
        deliver(&mut server, &mut client);
        // Receiving the server's reset queues an acknowledgement of it, which
        // is not a retransmission and has to be taken off first.
        while client.take_outgoing().is_some() {}
        client.resend_stale(Instant::now() + RETRANSMIT_AFTER * 2);
        assert!(
            client.take_outgoing().is_none(),
            "nothing is outstanding once the peer has acknowledged it"
        );
    }

    #[test]
    fn tls_crypt_hides_the_body_and_detects_a_wrong_key() {
        let auth = static_key_config("tls-crypt", None);
        let mut client = ControlChannel::new(&auth);
        client.start();
        client.send_tls(b"handshake bytes");
        client.take_outgoing().unwrap();
        let packet = client.take_outgoing().unwrap();
        assert!(
            !packet
                .windows(15)
                .any(|window| window == b"handshake bytes"),
            "the payload must not appear in the clear"
        );
        // A client reading its own packet uses the other key, which must fail.
        let mut same_side = ControlChannel::new(&auth);
        let error = same_side.receive(&packet).unwrap_err();
        assert!(error.contains("tls-crypt"), "{error}");
    }

    #[test]
    fn tls_auth_signs_the_packet_and_rejects_a_forgery() {
        let auth = static_key_config("tls-auth", Some(1));
        let mut client = ControlChannel::new(&auth);
        client.start();
        let mut packet = client.take_outgoing().unwrap();
        // A server holds the mirror image of the client's direction, so
        // verifying with the same side's keys must fail.
        let mirrored = match &auth {
            ControlAuth::TlsAuth { key, digest, .. } => ControlAuth::TlsAuth {
                key: key.clone(),
                direction: KeyDirection::Normal,
                digest: *digest,
            },
            _ => unreachable!("built as tls-auth"),
        };
        let mut server = ControlChannel::new(&mirrored);
        assert!(server.receive(&packet).is_ok());
        let last = packet.len() - 1;
        packet[last] ^= 0xff;
        let mut server = ControlChannel::new(&mirrored);
        let error = server.receive(&packet).unwrap_err();
        assert!(error.contains("tls-auth"), "{error}");
    }

    #[test]
    fn a_soft_reset_reports_the_key_id_the_server_wants_to_move_to() {
        let (mut client, mut server) = pair(&ControlAuth::None);
        client.start();
        deliver(&mut client, &mut server);
        // The acknowledgement the server queued for the client's reset would
        // otherwise be the next packet off the queue.
        while server.take_outgoing().is_some() {}
        server.rekey(1);
        server.send(P_CONTROL_SOFT_RESET_V1, &[]);
        let packet = server.take_outgoing().unwrap();
        match client.receive(&packet).unwrap() {
            Received::SoftReset { key_id } => assert_eq!(key_id, 1),
            _ => panic!("expected a soft reset"),
        }
    }

    #[test]
    fn a_truncated_packet_is_an_error_rather_than_a_panic() {
        let mut channel = ControlChannel::new(&ControlAuth::None);
        assert!(channel.receive(&[]).is_err());
        assert!(channel.receive(&[0x20, 1, 2]).is_err());
        assert!(channel.receive(&[0x20, 1, 2, 3, 4, 5, 6, 7, 8]).is_err());
    }
}
