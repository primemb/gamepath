use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::Ipv4Addr;

use crate::protocol::{FrameHeader, HEADER_LEN};

const TOKEN_PREFIX: &str = "gpe1_";
const CLIENT_TO_SERVER_NONCE: u32 = 0x4354_5331;
const SERVER_TO_CLIENT_NONCE: u32 = 0x5354_4331;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentToken {
    pub version: u8,
    pub client_id: String,
    pub pre_shared_key: String,
    pub virtual_ipv4: Ipv4Addr,
}

impl EnrollmentToken {
    pub fn generate(virtual_ipv4: Ipv4Addr) -> Self {
        let mut client_id = [0_u8; 16];
        let mut key = [0_u8; 32];
        rand::rng().fill_bytes(&mut client_id);
        rand::rng().fill_bytes(&mut key);
        Self {
            version: 1,
            client_id: URL_SAFE_NO_PAD.encode(client_id),
            pre_shared_key: URL_SAFE_NO_PAD.encode(key),
            virtual_ipv4,
        }
    }

    pub fn encode(&self) -> Result<String, String> {
        let json = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
    }

    pub fn decode(value: &str) -> Result<Self, String> {
        let payload = value
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or("invalid GamePath enrollment token prefix")?;
        let json = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "invalid GamePath enrollment token encoding")?;
        let token: Self = serde_json::from_slice(&json)
            .map_err(|_| "invalid GamePath enrollment token payload")?;
        token.material()?;
        Ok(token)
    }

    pub fn material(&self) -> Result<([u8; 16], [u8; 32]), String> {
        if self.version != 1 {
            return Err("unsupported GamePath enrollment version".into());
        }
        let id = URL_SAFE_NO_PAD
            .decode(&self.client_id)
            .map_err(|_| "invalid enrollment client ID")?;
        let key = URL_SAFE_NO_PAD
            .decode(&self.pre_shared_key)
            .map_err(|_| "invalid enrollment pre-shared key")?;
        Ok((
            id.try_into().map_err(|_| "client ID must be 16 bytes")?,
            key.try_into()
                .map_err(|_| "pre-shared key must be 32 bytes")?,
        ))
    }
}

pub struct SessionCrypto {
    client_to_server: ChaCha20Poly1305,
    server_to_client: ChaCha20Poly1305,
}

impl SessionCrypto {
    pub fn new(pre_shared_key: &[u8; 32], session_id: u64) -> Result<Self, String> {
        let hkdf = Hkdf::<Sha256>::new(Some(&session_id.to_be_bytes()), pre_shared_key);
        let mut client_key = [0_u8; 32];
        let mut server_key = [0_u8; 32];
        hkdf.expand(b"gamepath-v1 client-to-server", &mut client_key)
            .map_err(|_| "failed to derive client session key")?;
        hkdf.expand(b"gamepath-v1 server-to-client", &mut server_key)
            .map_err(|_| "failed to derive server session key")?;
        Ok(Self {
            client_to_server: ChaCha20Poly1305::new((&client_key).into()),
            server_to_client: ChaCha20Poly1305::new((&server_key).into()),
        })
    }

    pub fn seal_client(&self, header: FrameHeader, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        self.seal(
            &self.client_to_server,
            CLIENT_TO_SERVER_NONCE,
            header,
            plaintext,
        )
    }

    pub fn open_client(&self, frame: &[u8]) -> Result<(FrameHeader, Vec<u8>), String> {
        self.open(&self.client_to_server, CLIENT_TO_SERVER_NONCE, frame)
    }

    pub fn seal_server(&self, header: FrameHeader, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        self.seal(
            &self.server_to_client,
            SERVER_TO_CLIENT_NONCE,
            header,
            plaintext,
        )
    }

    pub fn open_server(&self, frame: &[u8]) -> Result<(FrameHeader, Vec<u8>), String> {
        self.open(&self.server_to_client, SERVER_TO_CLIENT_NONCE, frame)
    }

    fn seal(
        &self,
        cipher: &ChaCha20Poly1305,
        prefix: u32,
        header: FrameHeader,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let encoded = header.encode();
        let ciphertext = cipher
            .encrypt(
                nonce(prefix, header.sequence).as_ref().into(),
                Payload {
                    msg: plaintext,
                    aad: &encoded,
                },
            )
            .map_err(|_| "packet encryption failed")?;
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        frame.extend_from_slice(&encoded);
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    fn open(
        &self,
        cipher: &ChaCha20Poly1305,
        prefix: u32,
        frame: &[u8],
    ) -> Result<(FrameHeader, Vec<u8>), String> {
        let header =
            FrameHeader::decode(frame).map_err(|error| format!("invalid frame: {error:?}"))?;
        let plaintext = cipher
            .decrypt(
                nonce(prefix, header.sequence).as_ref().into(),
                Payload {
                    msg: &frame[HEADER_LEN..],
                    aad: &frame[..HEADER_LEN],
                },
            )
            .map_err(|_| "packet authentication failed")?;
        Ok((header, plaintext))
    }
}

fn nonce(prefix: u32, sequence: u64) -> [u8; 12] {
    let mut value = [0_u8; 12];
    value[..4].copy_from_slice(&prefix.to_be_bytes());
    value[4..].copy_from_slice(&sequence.to_be_bytes());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_round_trips() {
        let token = EnrollmentToken::generate("10.203.0.2".parse().unwrap());
        assert_eq!(
            EnrollmentToken::decode(&token.encode().unwrap()).unwrap(),
            token
        );
    }

    #[test]
    fn authenticated_frame_round_trips_and_rejects_changes() {
        let token = EnrollmentToken::generate("10.203.0.2".parse().unwrap());
        let (client_id, key) = token.material().unwrap();
        let crypto = SessionCrypto::new(&key, 88).unwrap();
        let header = FrameHeader {
            flags: 0,
            client_id,
            session_id: 88,
            sequence: 7,
        };
        let frame = crypto.seal_client(header, b"packet").unwrap();
        assert_eq!(
            crypto.open_client(&frame).unwrap(),
            (header, b"packet".to_vec())
        );
        let mut changed = frame;
        *changed.last_mut().unwrap() ^= 1;
        assert!(crypto.open_client(&changed).is_err());
    }
}
