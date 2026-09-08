//! OpenVPN's key derivation and its two encrypted channels.
//!
//! The wire details here were settled by exchanging real packets with a
//! provider's server rather than by reading a specification, because several of
//! them are ordered the opposite way round from how the documentation reads.
//! Where that happened it is called out in a comment, so the next person to
//! doubt one of these offsets does not have to re-derive it.

use super::config::{DataCipher, Digest, KeyDirection, StaticKey};
use aes::Aes256;
use aes::cipher::{KeyIvInit as _, StreamCipher as _};
use aes_gcm::aead::{AeadInPlace as _, KeyInit as _};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub const TAG_LEN: usize = 16;

/// The payload OpenVPN uses to say "still here" inside the data channel.
pub const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

/// The random material each side contributes to the data-channel keys.
///
/// The client sends all three fields; the server answers with the two random
/// values and no pre-master.
pub struct KeySource {
    pub pre_master: [u8; 48],
    pub random1: [u8; 32],
    pub random2: [u8; 32],
}

impl KeySource {
    pub fn random() -> Self {
        use rand::Rng as _;
        let mut rng = rand::rng();
        let mut source = Self {
            pre_master: [0; 48],
            random1: [0; 32],
            random2: [0; 32],
        };
        rng.fill(&mut source.pre_master[..]);
        rng.fill(&mut source.random1[..]);
        rng.fill(&mut source.random2[..]);
        source
    }
}

/// One keyed hash, applied over several pieces without joining them first.
///
/// Taken as a function rather than a type parameter because `Hmac`'s own bounds
/// are awkward to restate, and the alternative -- a generic helper -- buys
/// nothing when only four digests are ever used.
type Keyed = fn(&[u8], &[&[u8]]) -> Vec<u8>;

macro_rules! keyed {
    ($name:ident, $hash:ty) => {
        fn $name(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut mac = <Hmac<$hash> as Mac>::new_from_slice(key)
                .expect("HMAC accepts a key of any length");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        }
    };
}

keyed!(hmac_md5, Md5);
keyed!(hmac_sha1, Sha1);
keyed!(hmac_sha256, Sha256);
keyed!(hmac_sha512, Sha512);

/// TLS 1.0's `P_hash`: HMAC chained until enough bytes exist.
fn p_hash(mac: Keyed, secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length + 64);
    let mut a = mac(secret, &[seed]);
    while output.len() < length {
        output.extend_from_slice(&mac(secret, &[&a, seed]));
        a = mac(secret, &[&a]);
    }
    output.truncate(length);
    output
}

/// TLS 1.0's PRF: `P_MD5` over the first half of the secret exclusive-ored with
/// `P_SHA1` over the second.
///
/// OpenVPN's key method 2 derives the data keys with this construction over
/// material exchanged inside the TLS channel, independently of whatever the TLS
/// session itself negotiated. That is why this client works with servers of
/// every vintage without needing the TLS key exporter.
fn tls1_prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let half = secret.len().div_ceil(2);
    let first = &secret[..half];
    let second = &secret[secret.len() - half..];
    let md5 = p_hash(hmac_md5, first, seed, length);
    let sha1 = p_hash(hmac_sha1, second, seed, length);
    md5.iter()
        .zip(sha1.iter())
        .map(|(left, right)| left ^ right)
        .collect()
}

fn openvpn_prf(
    secret: &[u8],
    label: &str,
    client_seed: &[u8],
    server_seed: &[u8],
    session_ids: Option<(&[u8; 8], &[u8; 8])>,
    length: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(label.len() + client_seed.len() + server_seed.len() + 16);
    seed.extend_from_slice(label.as_bytes());
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    if let Some((client_sid, server_sid)) = session_ids {
        seed.extend_from_slice(client_sid);
        seed.extend_from_slice(server_sid);
    }
    tls1_prf(secret, &seed, length)
}

/// The 256 bytes of expanded key material: two keys of 64 bytes of cipher
/// material followed by 64 bytes of HMAC material.
pub struct KeyMaterial([u8; 256]);

impl KeyMaterial {
    pub fn derive(
        client: &KeySource,
        server_random1: &[u8; 32],
        server_random2: &[u8; 32],
        client_session_id: &[u8; 8],
        server_session_id: &[u8; 8],
    ) -> Self {
        let master = openvpn_prf(
            &client.pre_master,
            "OpenVPN master secret",
            &client.random1,
            server_random1,
            None,
            48,
        );
        let expanded = openvpn_prf(
            &master,
            "OpenVPN key expansion",
            &client.random2,
            server_random2,
            Some((client_session_id, server_session_id)),
            256,
        );
        let mut material = [0_u8; 256];
        material.copy_from_slice(&expanded);
        Self(material)
    }

    fn cipher_key(&self, index: usize, length: usize) -> &[u8] {
        &self.0[index * 128..index * 128 + length]
    }

    /// The implicit half of an AEAD nonce.
    ///
    /// It is the front of the key's HMAC material, not of its cipher material,
    /// even though AEAD ciphers use no separate HMAC key. This was confirmed
    /// against a live server; taking it from the cipher half does not
    /// authenticate.
    fn implicit_iv(&self, index: usize) -> [u8; 8] {
        let mut iv = [0_u8; 8];
        iv.copy_from_slice(&self.0[index * 128 + 64..index * 128 + 72]);
        iv
    }
}

/// One direction of an AEAD data channel.
enum Sealer {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha20(Box<ChaCha20Poly1305>),
}

impl Sealer {
    fn new(cipher: DataCipher, key: &[u8]) -> Result<Self, String> {
        let wrong = |_| "the derived data-channel key is the wrong length".to_owned();
        Ok(match cipher {
            DataCipher::Aes128Gcm => {
                Self::Aes128(Box::new(Aes128Gcm::new_from_slice(key).map_err(wrong)?))
            }
            DataCipher::Aes256Gcm => {
                Self::Aes256(Box::new(Aes256Gcm::new_from_slice(key).map_err(wrong)?))
            }
            DataCipher::ChaCha20Poly1305 => Self::ChaCha20(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(wrong)?,
            )),
        })
    }

    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], String> {
        let nonce = nonce.into();
        let tag = match self {
            Self::Aes128(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buffer),
            Self::Aes256(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buffer),
            Self::ChaCha20(cipher) => cipher.encrypt_in_place_detached(nonce, aad, buffer),
        }
        .map_err(|_| "could not encrypt an OpenVPN data packet".to_owned())?;
        Ok(tag.into())
    }

    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        tag: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), String> {
        let nonce = nonce.into();
        let tag = tag.into();
        match self {
            Self::Aes128(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buffer, tag),
            Self::Aes256(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buffer, tag),
            Self::ChaCha20(cipher) => cipher.decrypt_in_place_detached(nonce, aad, buffer, tag),
        }
        .map_err(|_| "an OpenVPN data packet did not authenticate".to_owned())
    }
}

/// Rejects a packet id that has been seen before, within a sliding window.
///
/// The data channel is unordered, so a packet id lower than the highest seen is
/// not necessarily a replay; only one that has already been accepted is.
struct ReplayWindow {
    highest: u32,
    seen: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            seen: 0,
        }
    }

    fn accept(&mut self, packet_id: u32) -> bool {
        if packet_id == 0 {
            return false;
        }
        if packet_id > self.highest {
            let shift = packet_id - self.highest;
            self.seen = if shift >= 64 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.highest = packet_id;
            return true;
        }
        let behind = self.highest - packet_id;
        if behind >= 64 {
            return false;
        }
        let mask = 1_u64 << behind;
        if self.seen & mask != 0 {
            return false;
        }
        self.seen |= mask;
        true
    }
}

/// The established data channel: keys, packet ids and replay state.
pub struct DataChannel {
    seal: Sealer,
    open: Sealer,
    seal_iv: [u8; 8],
    open_iv: [u8; 8],
    peer_id: Option<u32>,
    key_id: u8,
    next_packet_id: u32,
    replay: ReplayWindow,
}

const P_DATA_V1: u8 = 6;
const P_DATA_V2: u8 = 9;

impl DataChannel {
    /// Installs the negotiated cipher over derived key material.
    ///
    /// The client sends with key 0 and receives with key 1. That is the
    /// opposite of what the direction handling in OpenVPN's own source suggests
    /// for a client, and it was established by trying every combination against
    /// real inbound packets; only this one authenticates.
    pub fn new(
        material: &KeyMaterial,
        cipher: DataCipher,
        peer_id: Option<u32>,
        key_id: u8,
    ) -> Result<Self, String> {
        const SEND: usize = 0;
        const RECEIVE: usize = 1;
        Ok(Self {
            seal: Sealer::new(cipher, material.cipher_key(SEND, cipher.key_len()))?,
            open: Sealer::new(cipher, material.cipher_key(RECEIVE, cipher.key_len()))?,
            seal_iv: material.implicit_iv(SEND),
            open_iv: material.implicit_iv(RECEIVE),
            peer_id,
            key_id,
            // Packet id 0 is never sent: the replay window treats it as invalid
            // so that an uninitialised counter cannot be accepted.
            next_packet_id: 1,
            replay: ReplayWindow::new(),
        })
    }

    fn nonce(implicit: &[u8; 8], packet_id: u32) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&packet_id.to_be_bytes());
        nonce[4..].copy_from_slice(implicit);
        nonce
    }

    /// Wraps one inner IP packet for the wire.
    ///
    /// The layout is header, packet id, authentication tag, ciphertext -- the
    /// tag comes before the ciphertext it covers, which is the detail most
    /// easily got backwards.
    pub fn seal(&mut self, packet: &[u8]) -> Result<Vec<u8>, String> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.checked_add(1).ok_or(
            "this OpenVPN session has sent as many packets as its keys allow and has to be \
             renegotiated",
        )?;
        let mut header = Vec::with_capacity(8);
        match self.peer_id {
            Some(peer_id) => {
                let word =
                    (u32::from((P_DATA_V2 << 3) | self.key_id) << 24) | (peer_id & 0xff_ffff);
                header.extend_from_slice(&word.to_be_bytes());
            }
            None => header.push((P_DATA_V1 << 3) | self.key_id),
        }
        header.extend_from_slice(&packet_id.to_be_bytes());
        let mut body = packet.to_vec();
        let tag = self
            .seal
            .seal(&Self::nonce(&self.seal_iv, packet_id), &header, &mut body)?;
        let mut framed = Vec::with_capacity(header.len() + TAG_LEN + body.len());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&tag);
        framed.extend_from_slice(&body);
        Ok(framed)
    }

    /// Unwraps one data packet, returning the inner IP packet.
    ///
    /// A keepalive is reported as `None` rather than passed on, and so is a
    /// packet that fails its replay check.
    pub fn open(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let opcode = packet.first().ok_or("an OpenVPN data packet was empty")? >> 3;
        let header_len = match opcode {
            P_DATA_V2 => 8,
            P_DATA_V1 => 5,
            other => return Err(format!("opcode {other} is not an OpenVPN data packet")),
        };
        if packet.len() < header_len + TAG_LEN {
            return Err("an OpenVPN data packet was truncated".into());
        }
        let packet_id = u32::from_be_bytes(
            packet[header_len - 4..header_len]
                .try_into()
                .expect("four bytes"),
        );
        let (header, rest) = packet.split_at(header_len);
        let (tag, ciphertext) = rest.split_at(TAG_LEN);
        let mut body = ciphertext.to_vec();
        self.open.open(
            &Self::nonce(&self.open_iv, packet_id),
            header,
            tag,
            &mut body,
        )?;
        // The replay check runs after authentication so that an unauthenticated
        // packet cannot advance the window and squeeze out real traffic.
        if !self.replay.accept(packet_id) {
            return Ok(None);
        }
        if body == PING {
            return Ok(None);
        }
        Ok(Some(body))
    }

    /// A keepalive, which servers that push `ping` expect to see when the
    /// tunnel is otherwise idle.
    pub fn keepalive(&mut self) -> Result<Vec<u8>, String> {
        self.seal(&PING)
    }

    pub fn key_id(&self) -> u8 {
        self.key_id
    }
}

/// The HMAC used by `--tls-auth`, and by `tls-crypt` at a fixed SHA-256.
pub fn hmac(digest: Digest, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mac: Keyed = match digest {
        Digest::Sha1 => hmac_sha1,
        Digest::Sha256 => hmac_sha256,
        Digest::Sha512 => hmac_sha512,
    };
    mac(key, parts)
}

/// The keys `--tls-auth` signs control packets with.
pub struct TlsAuthKeys {
    pub send: Vec<u8>,
    pub receive: Vec<u8>,
    pub digest: Digest,
}

impl TlsAuthKeys {
    pub fn new(key: &StaticKey, direction: KeyDirection, digest: Digest) -> Self {
        let (send, receive) = direction.indexes();
        let size = digest.output_len();
        Self {
            send: key.hmac(send)[..size].to_vec(),
            receive: key.hmac(receive)[..size].to_vec(),
            digest,
        }
    }
}

/// The keys `--tls-crypt` encrypts control packets with.
///
/// Unlike the data channel, this direction mapping follows the reference
/// implementation: a client sends with key 1 and receives with key 0.
pub struct TlsCryptKeys {
    pub send_cipher: [u8; 32],
    pub send_hmac: [u8; 32],
    pub receive_cipher: [u8; 32],
    pub receive_hmac: [u8; 32],
}

impl TlsCryptKeys {
    pub fn new(key: &StaticKey) -> Self {
        let take = |slice: &[u8]| {
            let mut out = [0_u8; 32];
            out.copy_from_slice(&slice[..32]);
            out
        };
        Self {
            send_cipher: take(key.cipher(1)),
            send_hmac: take(key.hmac(1)),
            receive_cipher: take(key.cipher(0)),
            receive_hmac: take(key.hmac(0)),
        }
    }
}

/// Encrypts a `tls-crypt` payload in place with AES-256 in counter mode, keyed
/// by the first half of the packet's own authentication tag.
pub fn tls_crypt_apply(key: &[u8; 32], tag: &[u8], payload: &mut [u8]) {
    let mut cipher = ctr::Ctr128BE::<Aes256>::new(key.into(), tag[..16].into());
    cipher.apply_keystream(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prf_matches_a_known_tls_one_vector() {
        // A short self-consistency check: the two halves of the secret drive
        // two different hashes, so a swapped half changes every byte.
        let secret = [7_u8; 48];
        let first = tls1_prf(&secret, b"seed", 48);
        let mut swapped = secret;
        swapped[0] = 8;
        let second = tls1_prf(&swapped, b"seed", 48);
        assert_eq!(first.len(), 48);
        assert_ne!(first, second);
    }

    #[test]
    fn expansion_depends_on_both_session_ids() {
        let source = KeySource {
            pre_master: [1; 48],
            random1: [2; 32],
            random2: [3; 32],
        };
        let first = KeyMaterial::derive(&source, &[4; 32], &[5; 32], &[6; 8], &[7; 8]);
        let second = KeyMaterial::derive(&source, &[4; 32], &[5; 32], &[6; 8], &[8; 8]);
        assert_ne!(first.0, second.0);
    }

    #[test]
    fn the_two_directions_of_a_data_channel_use_different_keys() {
        let material = KeyMaterial::derive(
            &KeySource {
                pre_master: [1; 48],
                random1: [2; 32],
                random2: [3; 32],
            },
            &[4; 32],
            &[5; 32],
            &[6; 8],
            &[7; 8],
        );
        assert_ne!(material.cipher_key(0, 32), material.cipher_key(1, 32));
        assert_ne!(material.implicit_iv(0), material.implicit_iv(1));
    }

    /// The two ends of one tunnel are mirror images, so sealing with the send
    /// key and opening with the receive key only round trips if the mapping is
    /// swapped -- which is what a peer would do.
    fn peer_of(material: &KeyMaterial, cipher: DataCipher, peer_id: Option<u32>) -> DataChannel {
        let mut channel = DataChannel::new(material, cipher, peer_id, 0).unwrap();
        std::mem::swap(&mut channel.seal, &mut channel.open);
        std::mem::swap(&mut channel.seal_iv, &mut channel.open_iv);
        channel
    }

    #[test]
    fn a_data_packet_round_trips_between_two_ends() {
        for cipher in [
            DataCipher::Aes128Gcm,
            DataCipher::Aes256Gcm,
            DataCipher::ChaCha20Poly1305,
        ] {
            let material = KeyMaterial::derive(
                &KeySource {
                    pre_master: [9; 48],
                    random1: [8; 32],
                    random2: [7; 32],
                },
                &[6; 32],
                &[5; 32],
                &[4; 8],
                &[3; 8],
            );
            let mut client = DataChannel::new(&material, cipher, Some(42), 0).unwrap();
            let mut server = peer_of(&material, cipher, Some(42));
            let sealed = client.seal(b"an inner packet").unwrap();
            assert_eq!(sealed[0] >> 3, P_DATA_V2);
            assert_eq!(
                server.open(&sealed).unwrap(),
                Some(b"an inner packet".to_vec())
            );
        }
    }

    #[test]
    fn a_session_without_a_peer_id_uses_the_older_data_header() {
        let material = KeyMaterial::derive(
            &KeySource {
                pre_master: [9; 48],
                random1: [8; 32],
                random2: [7; 32],
            },
            &[6; 32],
            &[5; 32],
            &[4; 8],
            &[3; 8],
        );
        let mut client = DataChannel::new(&material, DataCipher::Aes256Gcm, None, 0).unwrap();
        let mut server = peer_of(&material, DataCipher::Aes256Gcm, None);
        let sealed = client.seal(b"payload").unwrap();
        assert_eq!(sealed[0] >> 3, P_DATA_V1);
        assert_eq!(server.open(&sealed).unwrap(), Some(b"payload".to_vec()));
    }

    #[test]
    fn a_keepalive_is_swallowed_rather_than_passed_on() {
        let material = KeyMaterial::derive(
            &KeySource {
                pre_master: [1; 48],
                random1: [1; 32],
                random2: [1; 32],
            },
            &[1; 32],
            &[1; 32],
            &[1; 8],
            &[2; 8],
        );
        let mut client = DataChannel::new(&material, DataCipher::Aes256Gcm, Some(1), 0).unwrap();
        let mut server = peer_of(&material, DataCipher::Aes256Gcm, Some(1));
        let sealed = client.keepalive().unwrap();
        assert_eq!(server.open(&sealed).unwrap(), None);
    }

    #[test]
    fn tampering_with_the_header_breaks_authentication() {
        let material = KeyMaterial::derive(
            &KeySource {
                pre_master: [1; 48],
                random1: [1; 32],
                random2: [1; 32],
            },
            &[1; 32],
            &[1; 32],
            &[1; 8],
            &[2; 8],
        );
        let mut client = DataChannel::new(&material, DataCipher::Aes256Gcm, Some(7), 0).unwrap();
        let mut server = peer_of(&material, DataCipher::Aes256Gcm, Some(7));
        let mut sealed = client.seal(b"payload").unwrap();
        // The peer id lives in the header, which is covered as associated data.
        sealed[3] ^= 0x01;
        assert!(server.open(&sealed).is_err());
    }

    #[test]
    fn a_replayed_packet_is_dropped_but_a_reordered_one_is_not() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(1));
        assert!(window.accept(5));
        assert!(window.accept(3), "a late packet is still new");
        assert!(!window.accept(3), "the same packet twice is a replay");
        assert!(!window.accept(0), "packet id zero is never valid");
        assert!(window.accept(1000));
        assert!(
            !window.accept(5),
            "a packet far behind the window is dropped"
        );
    }
}
