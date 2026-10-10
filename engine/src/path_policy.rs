//! Authenticated per-path reply selection. Older relays ignore this control
//! payload and continue answering the unchanged health probes.

const REQUEST: &[u8; 4] = b"path";
const ACCEPT: &[u8; 4] = b"pata";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicy {
    pub path: u8,
    pub selected: bool,
}

impl PathPolicy {
    pub fn request(self) -> [u8; 6] {
        [
            REQUEST[0],
            REQUEST[1],
            REQUEST[2],
            REQUEST[3],
            self.path,
            u8::from(self.selected),
        ]
    }

    pub fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() != 6 || &payload[..4] != REQUEST || payload[4] >= 64 || payload[5] > 1 {
            return None;
        }
        Some(Self {
            path: payload[4],
            selected: payload[5] != 0,
        })
    }
}

pub fn accept() -> &'static [u8] {
    ACCEPT
}

pub fn accepted(payload: &[u8]) -> bool {
    payload == ACCEPT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_round_trip_and_reject_invalid_payloads() {
        for path in 0..64 {
            for selected in [false, true] {
                let policy = PathPolicy { path, selected };
                assert_eq!(PathPolicy::parse(&policy.request()), Some(policy));
            }
        }
        for payload in [
            b"path".as_slice(),
            b"path\x40\x01",
            b"path\x00\x02",
            b"path\x00\x01x",
            b"ping\x00\x01",
        ] {
            assert_eq!(PathPolicy::parse(payload), None);
        }
        assert!(accepted(accept()));
        assert!(!accepted(b"pong"));
    }
}
