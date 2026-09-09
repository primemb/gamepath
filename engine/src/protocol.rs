pub const MAGIC: u32 = 0x4750_5448;
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 40;

pub const FLAG_CONTROL: u8 = 1;
pub const FLAG_SERVER_TO_CLIENT: u8 = 2;

/// Echo the request identity in the payload, not the encrypted frame sequence:
/// server sequences are independent and must remain unique for AEAD nonces.
pub fn probe_request(sequence: u64) -> Vec<u8> {
    let mut payload = b"ping".to_vec();
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload
}

/// Retains the original response for clients that send an untagged ping.
pub fn probe_response(request: &[u8]) -> Option<Vec<u8>> {
    if request != b"ping" && !(request.len() == 12 && request.starts_with(b"ping")) {
        return None;
    }
    let mut response = b"pong".to_vec();
    response.extend_from_slice(&request[4..]);
    Some(response)
}

/// A legacy response cannot identify its request. Once a relay demonstrates
/// support for tagged responses, never accept an untagged one again.
pub fn probe_reply_matches(reply: &[u8], sequence: u64, allow_legacy: bool) -> bool {
    (allow_legacy && reply == b"pong")
        || (reply.len() == 12 && reply.starts_with(b"pong") && reply[4..] == sequence.to_be_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub flags: u8,
    pub client_id: [u8; 16],
    pub session_id: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeaderLength,
}

impl FrameHeader {
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        bytes[4] = VERSION;
        bytes[5] = self.flags;
        bytes[6..8].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        bytes[8..24].copy_from_slice(&self.client_id);
        bytes[24..32].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[32..40].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if u32::from_be_bytes(bytes[0..4].try_into().unwrap()) != MAGIC {
            return Err(DecodeError::InvalidMagic);
        }
        if bytes[4] != VERSION {
            return Err(DecodeError::UnsupportedVersion);
        }
        if u16::from_be_bytes(bytes[6..8].try_into().unwrap()) as usize != HEADER_LEN {
            return Err(DecodeError::InvalidHeaderLength);
        }
        Ok(Self {
            flags: bytes[5],
            client_id: bytes[8..24].try_into().unwrap(),
            session_id: u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            sequence: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delayed_reply_cannot_answer_the_next_probe() {
        let expired = probe_response(&probe_request(41)).unwrap();
        let current = probe_response(&probe_request(42)).unwrap();
        assert!(!probe_reply_matches(&expired, 42, true));
        assert!(!probe_reply_matches(&expired, 42, false));
        assert!(probe_reply_matches(&current, 42, false));
    }

    #[test]
    fn legacy_peers_remain_compatible_without_downgrading_tagged_peers() {
        assert_eq!(probe_response(b"ping"), Some(b"pong".to_vec()));
        assert!(probe_reply_matches(b"pong", 42, true));
        assert!(!probe_reply_matches(b"pong", 42, false));
        for malformed in [b"pongx".as_slice(), b"pong123456789", b"ping12345678"] {
            assert!(!probe_reply_matches(malformed, 42, true));
        }
        assert_eq!(probe_response(b"pingx"), None);
        assert_eq!(probe_response(b"unknown"), None);
    }

    #[test]
    fn encrypted_reply_matches_request_independently_of_server_sequence() {
        use crate::auth::SessionCrypto;
        let crypto = SessionCrypto::new(&[7; 32], 123).unwrap();
        let request_header = FrameHeader {
            flags: FLAG_CONTROL,
            client_id: [3; 16],
            session_id: 123,
            sequence: 42,
        };
        let request = crypto
            .seal_client(request_header, &probe_request(42))
            .unwrap();
        let (_, plaintext) = crypto.open_client(&request).unwrap();
        let response_header = FrameHeader {
            flags: FLAG_CONTROL | FLAG_SERVER_TO_CLIENT,
            sequence: 900,
            ..request_header
        };
        let response = crypto
            .seal_server(response_header, &probe_response(&plaintext).unwrap())
            .unwrap();
        let (header, plaintext) = crypto.open_server(&response).unwrap();
        assert_eq!(header.sequence, 900);
        assert!(probe_reply_matches(&plaintext, 42, false));
        assert!(!probe_reply_matches(&plaintext, 43, false));
    }

    #[test]
    fn frame_header_round_trips() {
        let header = FrameHeader {
            flags: 3,
            client_id: [7; 16],
            session_id: 42,
            sequence: 9_001,
        };
        assert_eq!(FrameHeader::decode(&header.encode()), Ok(header));
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut bytes = FrameHeader {
            flags: 0,
            client_id: [0; 16],
            session_id: 1,
            sequence: 1,
        }
        .encode();
        bytes[0] = 0;
        assert_eq!(FrameHeader::decode(&bytes), Err(DecodeError::InvalidMagic));
    }
}
