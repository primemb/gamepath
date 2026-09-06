pub const MAGIC: u32 = 0x4750_5448;
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub flags: u8,
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
        bytes[8..16].copy_from_slice(&self.session_id.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.sequence.to_be_bytes());
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
            session_id: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            sequence: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_round_trips() {
        let header = FrameHeader {
            flags: 3,
            session_id: 42,
            sequence: 9_001,
        };
        assert_eq!(FrameHeader::decode(&header.encode()), Ok(header));
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut bytes = FrameHeader {
            flags: 0,
            session_id: 1,
            sequence: 1,
        }
        .encode();
        bytes[0] = 0;
        assert_eq!(FrameHeader::decode(&bytes), Err(DecodeError::InvalidMagic));
    }
}
