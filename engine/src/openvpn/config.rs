//! Parsing of the `.ovpn` files providers hand out.
//!
//! Only the directives that change what the client puts on the wire are read.
//! Everything else -- verbosity, reconnection policy, the many directives that
//! matter only to the reference implementation's own tun handling -- is ignored,
//! because a provider's file is full of them and failing on an unknown line
//! would reject configurations that work perfectly well.
//!
//! Directives we cannot honour are a different matter. Those are rejected by
//! name, so the user is told what about their file is unsupported instead of
//! watching a connection fail with no reason given.

use std::fmt::Write as _;
use std::net::SocketAddr;

/// How control packets are protected before TLS even starts.
#[derive(Clone)]
pub enum ControlAuth {
    /// Nothing wraps the control packets. Common for the username/password
    /// providers that ship a `<ca>` block and nothing else.
    None,
    /// `--tls-auth`: every control packet carries an HMAC.
    TlsAuth {
        key: Box<StaticKey>,
        direction: KeyDirection,
        digest: Digest,
    },
    /// `--tls-crypt`: control packets are encrypted as well as authenticated.
    TlsCrypt { key: Box<StaticKey> },
}

impl std::fmt::Debug for ControlAuth {
    /// Written by hand so that a static key cannot reach a log through a
    /// derived `Debug`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl ControlAuth {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "plain",
            Self::TlsAuth { .. } => "tls-auth",
            Self::TlsCrypt { .. } => "tls-crypt",
        }
    }
}

/// An `openvpn --genkey` static key: two independent keys, each 64 bytes of
/// cipher key followed by 64 bytes of HMAC key.
#[derive(Clone)]
pub struct StaticKey([u8; 256]);

impl StaticKey {
    /// The cipher half of one of the two keys.
    pub fn cipher(&self, index: usize) -> &[u8] {
        &self.0[index * 128..index * 128 + 64]
    }

    /// The HMAC half of one of the two keys.
    pub fn hmac(&self, index: usize) -> &[u8] {
        &self.0[index * 128 + 64..index * 128 + 128]
    }
}

/// Which of the two keys in a static key file each side sends with.
///
/// OpenVPN keeps two keys in one file and picks by direction, so that the two
/// ends never sign with the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDirection {
    /// `--key-direction 0`: send with key 0, receive with key 1.
    Normal,
    /// `--key-direction 1`, the client's usual setting: the mirror image.
    Inverse,
    /// No direction given, so both ends use key 0 for everything.
    Bidirectional,
}

impl KeyDirection {
    /// `(index of the key we send with, index of the key we receive with)`
    pub fn indexes(self) -> (usize, usize) {
        match self {
            Self::Normal => (0, 1),
            Self::Inverse => (1, 0),
            Self::Bidirectional => (0, 0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha512,
}

impl Digest {
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// The data-channel ciphers this client implements.
///
/// All three are AEAD. OpenVPN's older CBC-plus-HMAC construction is
/// deliberately absent: it is deprecated upstream, no current provider needs
/// it, and supporting it would double the size of the data channel for nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCipher {
    Aes256Gcm,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl DataCipher {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Aes128Gcm => "AES-128-GCM",
            Self::ChaCha20Poly1305 => "CHACHA20-POLY1305",
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            Self::Aes128Gcm => 16,
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "AES-256-GCM" => Some(Self::Aes256Gcm),
            "AES-128-GCM" => Some(Self::Aes128Gcm),
            "CHACHA20-POLY1305" | "CHACHA20POLY1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    /// The name used in the options string the two ends compare.
    pub fn options_name(self) -> &'static str {
        match self {
            Self::Udp => "UDPv4",
            Self::Tcp => "TCPv4_CLIENT",
        }
    }
}

/// One `remote` line: where to dial and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
}

impl Remote {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Everything the client needs from a provider's file.
#[derive(Clone)]
pub struct OpenVpnConfig {
    /// Every `remote` in the file, in the order they were written, with the
    /// protocol each one resolves to.
    pub remotes: Vec<Remote>,
    /// The CA certificates the server's chain has to end at, in DER form.
    pub ca: Vec<Vec<u8>>,
    /// A client certificate chain, when the provider authenticates by
    /// certificate rather than by password.
    pub client_certs: Vec<Vec<u8>>,
    /// The client key exactly as the file carried it. It is kept as PEM so the
    /// TLS stack can decide how to read it, rather than being flattened to
    /// bytes here and having to be told its own format again later.
    pub client_key: Option<String>,
    pub control_auth: ControlAuth,
    /// The ciphers to offer, most preferred first.
    pub data_ciphers: Vec<DataCipher>,
    /// `--auth`, which sizes the `--tls-auth` HMAC.
    pub digest: Digest,
    /// True when the server expects a username and password.
    pub wants_credentials: bool,
    pub reneg_seconds: Option<u64>,
    pub tun_mtu: u16,
}

impl std::fmt::Debug for OpenVpnConfig {
    /// Written by hand because the parsed configuration holds a client private
    /// key, and a derived `Debug` would put it in whatever printed it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVpnConfig")
            .field("remotes", &self.remotes)
            .field("certificate_authorities", &self.ca.len())
            .field("client_certificate", &!self.client_certs.is_empty())
            .field(
                "client_key",
                &self.client_key.as_ref().map(|_| "<redacted>"),
            )
            .field("control_auth", &self.control_auth)
            .field("data_ciphers", &self.data_ciphers)
            .field("digest", &self.digest)
            .field("wants_credentials", &self.wants_credentials)
            .field("reneg_seconds", &self.reneg_seconds)
            .field("tun_mtu", &self.tun_mtu)
            .finish()
    }
}

impl OpenVpnConfig {
    pub fn parse(source: &str) -> Result<Self, String> {
        Parser::default().run(source)
    }

    /// The options string the two ends exchange after the TLS handshake. It has
    /// to describe the same session the server thinks it is building, or a
    /// server running `--opt-verify` hangs up.
    pub fn options_string(&self, protocol: Protocol) -> String {
        let cipher = self.first_cipher();
        let mut options = String::from("V4,dev-type tun,link-mtu 1549");
        let _ = write!(options, ",tun-mtu {}", self.tun_mtu);
        let _ = write!(options, ",proto {}", protocol.options_name());
        let _ = write!(options, ",cipher {}", cipher.as_str());
        let _ = write!(options, ",auth {}", self.digest.as_str());
        let _ = write!(options, ",keysize {}", cipher.key_len() * 8);
        options.push_str(",key-method 2,tls-client");
        options
    }

    pub fn first_cipher(&self) -> DataCipher {
        self.data_ciphers
            .first()
            .copied()
            .unwrap_or(DataCipher::Aes256Gcm)
    }

    /// The `IV_` block that tells a modern server what this client supports.
    ///
    /// `IV_PROTO` bit 2 asks for `P_DATA_V2` and its peer id and bit 3 asks the
    /// server to push without being asked; `IV_CIPHERS` drives cipher
    /// negotiation so a current server can choose something better than the
    /// single `cipher` line an older file carries.
    pub fn peer_info(&self, remote: &Remote) -> String {
        let ciphers = self
            .data_ciphers
            .iter()
            .map(|cipher| cipher.as_str())
            .collect::<Vec<_>>()
            .join(":");
        let mut info = String::new();
        let _ = writeln!(info, "IV_VER=2.6.0");
        let _ = writeln!(info, "IV_PLAT=win");
        let _ = writeln!(info, "IV_TCPNL=1");
        let _ = writeln!(info, "IV_MTU={}", self.tun_mtu);
        let _ = writeln!(info, "IV_NCP=2");
        let _ = writeln!(info, "IV_CIPHERS={ciphers}");
        let _ = writeln!(info, "IV_PROTO={PEER_INFO_IV_PROTO}");
        let _ = writeln!(info, "IV_LZO_STUB=1");
        let _ = writeln!(info, "IV_COMP_STUB=1");
        let _ = writeln!(info, "IV_COMP_STUBv2=1");
        let _ = writeln!(info, "UV_ENDPOINT={}", remote.endpoint());
        info
    }
}

/// `IV_PROTO` flags: peer id and `P_DATA_V2` (2), request push (4), and
/// tolerance of a deferred authentication reply (16).
///
/// Bit 3, which asks for keys derived from the TLS exporter instead of
/// OpenVPN's own PRF, is deliberately absent: this client implements the PRF,
/// which every server supports, and advertising the newer scheme would make
/// servers that also support it derive keys we could not reproduce.
const PEER_INFO_IV_PROTO: u32 = 2 | 4 | 16;

const DEFAULT_CIPHERS: [DataCipher; 3] = [
    DataCipher::Aes256Gcm,
    DataCipher::Aes128Gcm,
    DataCipher::ChaCha20Poly1305,
];

/// A `remote` before `--proto` and `--port` elsewhere in the file have been
/// applied to it.
struct PendingRemote {
    host: String,
    port: Option<u16>,
    protocol: Option<Protocol>,
}

#[derive(Default)]
struct Parser {
    remotes: Vec<PendingRemote>,
    protocol: Option<Protocol>,
    port: Option<u16>,
    ca: Vec<Vec<u8>>,
    client_certs: Vec<Vec<u8>>,
    client_key: Option<String>,
    tls_auth: Option<Box<StaticKey>>,
    /// `--key-direction`, which may appear either side of the `<tls-auth>`
    /// block it applies to, so it cannot be resolved as it is read.
    key_direction: Option<u8>,
    tls_crypt: Option<Box<StaticKey>>,
    ciphers: Option<Vec<DataCipher>>,
    /// `--cipher`, kept apart from `--data-ciphers` because it is only what a
    /// server too old to negotiate will use.
    legacy_cipher: Option<DataCipher>,
    digest: Option<Digest>,
    wants_credentials: bool,
    reneg_seconds: Option<u64>,
    tun_mtu: Option<u16>,
}

impl Parser {
    fn run(mut self, source: &str) -> Result<OpenVpnConfig, String> {
        let mut lines = source.lines().peekable();
        while let Some(line) = lines.next() {
            let line = strip_comment(line);
            if line.is_empty() {
                continue;
            }
            if let Some(tag) = inline_open_tag(line) {
                let body = collect_inline(&mut lines, tag)?;
                self.inline(tag, &body)?;
                continue;
            }
            let tokens = tokenize(line);
            let Some((directive, arguments)) = tokens.split_first() else {
                continue;
            };
            self.directive(directive, arguments)?;
        }
        self.finish()
    }

    fn directive(&mut self, directive: &str, arguments: &[String]) -> Result<(), String> {
        let argument = |index: usize| arguments.get(index).map(String::as_str);
        match directive {
            "remote" => {
                let host = argument(0)
                    .ok_or("a `remote` line in the OpenVPN configuration has no host")?
                    .to_owned();
                self.remotes.push(PendingRemote {
                    host,
                    port: argument(1).map(parse_port).transpose()?,
                    protocol: argument(2).map(parse_protocol).transpose()?,
                });
                Ok(())
            }
            "proto" => {
                self.protocol = Some(parse_protocol(
                    argument(0).ok_or("`proto` needs udp or tcp")?,
                )?);
                Ok(())
            }
            "port" | "rport" => {
                self.port = Some(parse_port(argument(0).ok_or("`port` needs a number")?)?);
                Ok(())
            }
            "dev" | "dev-type" => match argument(0) {
                Some(name) if name.starts_with("tun") => Ok(()),
                Some(name) => Err(format!(
                    "this configuration uses `dev {name}`. GamePath carries IP packets, so it \
                     needs a `tun` configuration; ask the provider for one."
                )),
                None => Ok(()),
            },
            "auth" => {
                let name = argument(0).ok_or("`auth` needs a digest name")?;
                self.digest = Some(Digest::parse(name).ok_or_else(|| {
                    format!(
                        "this configuration asks for the `{name}` digest, which GamePath does not \
                         implement"
                    )
                })?);
                Ok(())
            }
            "cipher" => {
                // A server that can negotiate replaces this, so a name we do
                // not know is only a problem if negotiation never happens.
                self.legacy_cipher = DataCipher::parse(argument(0).unwrap_or_default());
                Ok(())
            }
            "data-ciphers" | "ncp-ciphers" => {
                let list = argument(0).ok_or("`data-ciphers` needs a list")?;
                let ciphers = list
                    .split(':')
                    .filter_map(DataCipher::parse)
                    .collect::<Vec<_>>();
                if ciphers.is_empty() {
                    return Err(format!(
                        "none of the ciphers in `data-ciphers {list}` are implemented by GamePath, \
                         which supports AES-256-GCM, AES-128-GCM and CHACHA20-POLY1305"
                    ));
                }
                self.ciphers = Some(ciphers);
                Ok(())
            }
            "auth-user-pass" => {
                if let Some(path) = argument(0) {
                    return Err(format!(
                        "this configuration reads its username and password from `{path}`. Remove \
                         that filename and enter the credentials in GamePath instead."
                    ));
                }
                self.wants_credentials = true;
                Ok(())
            }
            "reneg-sec" => {
                self.reneg_seconds = argument(0).and_then(|value| value.parse().ok());
                Ok(())
            }
            "tun-mtu" => {
                self.tun_mtu = argument(0).and_then(|value| value.parse().ok());
                Ok(())
            }
            "key-direction" => {
                self.key_direction = Some(
                    argument(0)
                        .and_then(|value| value.parse::<u8>().ok())
                        .ok_or("`key-direction` needs 0 or 1")?,
                );
                Ok(())
            }
            "ca" | "cert" | "key" | "tls-auth" | "tls-crypt" | "tls-crypt-v2" | "pkcs12" => {
                Err(format!(
                    "this configuration keeps its `{directive}` in a separate file. GamePath needs \
                     one self-contained file, with the certificates and keys inline between \
                     `<{directive}>` and `</{directive}>` tags."
                ))
            }
            "secret" => Err(
                "this configuration uses OpenVPN's static-key mode, which has no TLS handshake and \
                 is removed in current OpenVPN releases. Ask the provider for a normal TLS \
                 configuration."
                    .into(),
            ),
            "comp-lzo" | "compress" => match argument(0) {
                None | Some("no") | Some("stub") | Some("stub-v2") => Ok(()),
                Some(mode) => Err(format!(
                    "this configuration turns on `{directive} {mode}`. GamePath does not compress \
                     tunnelled traffic, because compression leaks information about it and adds \
                     latency. Ask the provider for a configuration without compression."
                )),
            },
            "fragment" => Err(
                "this configuration uses `--fragment`, OpenVPN's own packet splitting, which \
                 GamePath does not implement. Ask the provider for a configuration without it."
                    .into(),
            ),
            "http-proxy" | "socks-proxy" => Err(format!(
                "this configuration reaches its server through `{directive}`. Add that proxy as \
                 its own GamePath node instead of naming it inside the OpenVPN file."
            )),
            "static-challenge" => Err(
                "this configuration asks for a one-time code at connect time, which GamePath \
                 cannot prompt for."
                    .into(),
            ),
            _ => Ok(()),
        }
    }

    fn inline(&mut self, tag: &str, body: &str) -> Result<(), String> {
        match tag {
            "ca" => {
                self.ca = read_certificates(body, "ca")?;
                Ok(())
            }
            "cert" => {
                self.client_certs = read_certificates(body, "cert")?;
                Ok(())
            }
            "key" => {
                self.client_key = Some(read_private_key(body)?);
                Ok(())
            }
            "tls-auth" => {
                self.tls_auth = Some(read_static_key(body, tag)?);
                Ok(())
            }
            "tls-crypt" => {
                self.tls_crypt = Some(read_static_key(body, tag)?);
                Ok(())
            }
            "tls-crypt-v2" => Err(
                "this configuration uses `tls-crypt-v2`, which GamePath does not implement yet. A \
                 `tls-crypt` or plain configuration from the same provider will work."
                    .into(),
            ),
            "connection" => {
                // A `<connection>` block holds one alternative remote. Only its
                // own directives are read -- running the whole parser over it
                // would both let a block change a global setting from inside
                // and reject the block for lacking the `<ca>` that belongs to
                // the file around it.
                for line in body.lines() {
                    let line = strip_comment(line);
                    if line.is_empty() {
                        continue;
                    }
                    let tokens = tokenize(line);
                    let Some((directive, arguments)) = tokens.split_first() else {
                        continue;
                    };
                    if matches!(directive.as_str(), "remote" | "proto" | "port" | "rport") {
                        self.directive(directive, arguments)?;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn finish(self) -> Result<OpenVpnConfig, String> {
        if self.remotes.is_empty() {
            return Err(
                "this OpenVPN configuration has no `remote` line, so there is no server to \
                 connect to"
                    .into(),
            );
        }
        if self.ca.is_empty() {
            return Err(
                "this OpenVPN configuration has no `<ca>` block, so the server's certificate \
                 cannot be checked against anything."
                    .into(),
            );
        }
        if self.client_certs.is_empty() != self.client_key.is_none() {
            return Err(
                "this OpenVPN configuration has only one of `<cert>` and `<key>`. Certificate \
                 authentication needs both."
                    .into(),
            );
        }
        if !self.wants_credentials && self.client_key.is_none() {
            return Err(
                "this OpenVPN configuration has neither `auth-user-pass` nor a client \
                 certificate, so there is no way to authenticate to the server."
                    .into(),
            );
        }
        let digest = self.digest.unwrap_or(Digest::Sha1);
        let control_auth = match (self.tls_crypt, self.tls_auth) {
            // A file carrying both is contradictory; `tls-crypt` is the
            // stronger of the two and is what the reference client would use.
            (Some(key), _) => ControlAuth::TlsCrypt { key },
            (None, Some(key)) => ControlAuth::TlsAuth {
                key,
                direction: match self.key_direction {
                    Some(0) => KeyDirection::Normal,
                    Some(1) => KeyDirection::Inverse,
                    Some(other) => {
                        return Err(format!(
                            "`key-direction {other}` is neither 0 nor 1, so GamePath cannot tell \
                             which half of the `<tls-auth>` key to sign with"
                        ));
                    }
                    None => KeyDirection::Bidirectional,
                },
                digest,
            },
            (None, None) => ControlAuth::None,
        };
        // `--data-ciphers` is the negotiated list. When a file carries only the
        // older `--cipher`, that one is offered first and the rest are still
        // advertised so a current server can choose better.
        let data_ciphers = match (self.ciphers, self.legacy_cipher) {
            (Some(list), _) => list,
            (None, Some(cipher)) => {
                let mut list = vec![cipher];
                list.extend(
                    DEFAULT_CIPHERS
                        .iter()
                        .copied()
                        .filter(|kind| *kind != cipher),
                );
                list
            }
            (None, None) => DEFAULT_CIPHERS.to_vec(),
        };
        let default_protocol = self.protocol.unwrap_or(Protocol::Udp);
        let remotes = self
            .remotes
            .into_iter()
            .map(|remote| Remote {
                host: remote.host,
                port: self.port.or(remote.port).unwrap_or(1194),
                // An explicit protocol on the `remote` line wins over `--proto`,
                // which matches how the reference client reads a file that uses
                // both.
                protocol: remote.protocol.unwrap_or(default_protocol),
            })
            .collect();
        Ok(OpenVpnConfig {
            remotes,
            ca: self.ca,
            client_certs: self.client_certs,
            client_key: self.client_key,
            control_auth,
            data_ciphers,
            digest,
            wants_credentials: self.wants_credentials,
            reneg_seconds: self.reneg_seconds,
            tun_mtu: self.tun_mtu.unwrap_or(1500),
        })
    }
}

fn parse_protocol(name: &str) -> Result<Protocol, String> {
    match name.to_ascii_lowercase().as_str() {
        "udp" | "udp4" | "udp6" => Ok(Protocol::Udp),
        "tcp" | "tcp4" | "tcp6" | "tcp-client" | "tcp4-client" | "tcp6-client" => Ok(Protocol::Tcp),
        "tcp-server" | "udp-server" => Err(
            "this is a server configuration, not a client one; it listens rather than connecting"
                .into(),
        ),
        other => Err(format!("`{other}` is not a protocol GamePath understands")),
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("`{value}` is not a usable port number"))
}

fn strip_comment(line: &str) -> &str {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with(';') {
        return "";
    }
    line
}

fn inline_open_tag(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('<')?.strip_suffix('>')?;
    if inner.starts_with('/') || inner.is_empty() {
        return None;
    }
    Some(inner)
}

fn collect_inline<'a, I>(lines: &mut std::iter::Peekable<I>, tag: &str) -> Result<String, String>
where
    I: Iterator<Item = &'a str>,
{
    let closing = format!("</{tag}>");
    let mut body = String::new();
    for line in lines.by_ref() {
        if line.trim() == closing {
            return Ok(body);
        }
        body.push_str(line);
        body.push('\n');
    }
    Err(format!(
        "the OpenVPN configuration opens `<{tag}>` but never closes it"
    ))
}

/// Splits a directive into tokens, keeping quoted arguments whole.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in line.chars() {
        match character {
            '"' => quoted = !quoted,
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn read_certificates(body: &str, tag: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut reader = std::io::Cursor::new(body.as_bytes());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("the `<{tag}>` block is not readable PEM: {error}"))?;
    if certificates.is_empty() {
        return Err(format!(
            "the `<{tag}>` block does not contain a certificate"
        ));
    }
    Ok(certificates
        .into_iter()
        .map(|certificate| certificate.to_vec())
        .collect())
}

/// Checks that a `<key>` block holds a key we can read, and keeps the PEM.
///
/// The bytes are not unwrapped here: the TLS stack has to be told which of the
/// several private key encodings it is looking at, and the PEM label already
/// says, so throwing that away would only mean guessing later.
fn read_private_key(body: &str) -> Result<String, String> {
    let mut reader = std::io::Cursor::new(body.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| format!("the `<key>` block is not readable PEM: {error}"))?
        .ok_or(
            "the `<key>` block does not contain a private key GamePath can read. A              passphrase-protected key has to be decrypted first.",
        )?;
    Ok(body.to_owned())
}

/// Reads an `openvpn --genkey` static key: 2048 bits written as hex between a
/// header and a footer.
fn read_static_key(body: &str, tag: &str) -> Result<Box<StaticKey>, String> {
    let hex = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('-') && !line.starts_with('#'))
        .collect::<String>();
    if hex.len() != 512 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "the `<{tag}>` block is not an OpenVPN static key; it should hold 2048 bits written as \
             512 hex digits"
        ));
    }
    let mut key = Box::new(StaticKey([0_u8; 256]));
    for (index, slot) in key.0.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("the `<{tag}>` block holds a bad pair of hex digits"))?;
    }
    Ok(key)
}

/// Resolves a remote to an IPv4 socket address.
pub fn resolve(remote: &Remote) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    (remote.host.as_str(), remote.port)
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve OpenVPN server {}: {error}", remote.host))?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| {
            format!(
                "OpenVPN server {} did not resolve to an IPv4 address",
                remote.host
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway CA, so the parser's happy path can be exercised without a
    /// real provider's certificate.
    const CA: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBIjCByaADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3QgQ0Ew\n\
        -----END CERTIFICATE-----\n";

    fn config(body: &str) -> String {
        format!("{body}\n<ca>\n{CA}</ca>\n")
    }

    #[test]
    fn a_remote_line_names_its_own_protocol() {
        let parsed = OpenVpnConfig::parse(&config(
            "client\ndev tun\nremote vpn.example 1403 tcp\nauth-user-pass",
        ))
        .unwrap();
        assert_eq!(parsed.remotes.len(), 1);
        assert_eq!(parsed.remotes[0].protocol, Protocol::Tcp);
        assert_eq!(parsed.remotes[0].port, 1403);
    }

    #[test]
    fn proto_applies_to_remotes_that_did_not_name_one() {
        let parsed = OpenVpnConfig::parse(&config(
            "remote first.example 1194\nremote second.example 443 tcp\nproto udp\nauth-user-pass",
        ))
        .unwrap();
        assert_eq!(parsed.remotes[0].protocol, Protocol::Udp);
        // The explicit protocol on the second line is not overwritten.
        assert_eq!(parsed.remotes[1].protocol, Protocol::Tcp);
    }

    /// Providers that offer a choice of ports wrap each in a `<connection>`
    /// block. The block carries no certificates of its own, so it has to be
    /// read as an addition to the file rather than as a file in itself.
    #[test]
    fn a_connection_block_adds_a_remote_without_needing_its_own_certificates() {
        let parsed = OpenVpnConfig::parse(&config(
            "auth-user-pass
<connection>
remote vpn.example 1194 udp
</connection>
             <connection>
remote vpn.example 443 tcp
</connection>",
        ))
        .unwrap();
        assert_eq!(parsed.remotes.len(), 2);
        assert_eq!(parsed.remotes[0].protocol, Protocol::Udp);
        assert_eq!(parsed.remotes[1].port, 443);
        assert_eq!(parsed.remotes[1].protocol, Protocol::Tcp);
    }

    #[test]
    fn an_older_file_still_offers_the_ciphers_a_current_server_can_pick() {
        let parsed = OpenVpnConfig::parse(&config(
            "remote vpn.example 1403 udp\ncipher AES-128-GCM\nauth-user-pass",
        ))
        .unwrap();
        assert_eq!(parsed.data_ciphers[0], DataCipher::Aes128Gcm);
        assert!(parsed.data_ciphers.contains(&DataCipher::Aes256Gcm));
        assert!(parsed.data_ciphers.contains(&DataCipher::ChaCha20Poly1305));
    }

    #[test]
    fn a_configuration_with_no_way_to_authenticate_is_refused() {
        let error = OpenVpnConfig::parse(&config("remote vpn.example 1403 udp")).unwrap_err();
        assert!(
            error.contains("neither `auth-user-pass` nor a client certificate"),
            "{error}"
        );
    }

    #[test]
    fn compression_is_refused_by_name_but_a_stub_is_allowed() {
        let error = OpenVpnConfig::parse(&config(
            "remote vpn.example 1403\ncomp-lzo yes\nauth-user-pass",
        ))
        .unwrap_err();
        assert!(error.contains("does not compress"), "{error}");
        OpenVpnConfig::parse(&config(
            "remote vpn.example 1403\ncomp-lzo no\nauth-user-pass",
        ))
        .unwrap();
    }

    #[test]
    fn a_key_kept_in_a_separate_file_says_so() {
        let error = OpenVpnConfig::parse(&config(
            "remote vpn.example 1403\ntls-crypt /etc/openvpn/tc.key\nauth-user-pass",
        ))
        .unwrap_err();
        assert!(error.contains("self-contained"), "{error}");
    }

    #[test]
    fn a_tap_configuration_is_refused_because_it_carries_frames_not_packets() {
        let error =
            OpenVpnConfig::parse(&config("dev tap\nremote vpn.example 1403\nauth-user-pass"))
                .unwrap_err();
        assert!(error.contains("`tun`"), "{error}");
    }

    #[test]
    fn the_two_halves_of_a_static_key_are_addressed_by_direction() {
        assert_eq!(KeyDirection::Normal.indexes(), (0, 1));
        assert_eq!(KeyDirection::Inverse.indexes(), (1, 0));
        assert_eq!(KeyDirection::Bidirectional.indexes(), (0, 0));
    }

    #[test]
    fn an_options_string_describes_the_session_the_server_is_building() {
        let parsed = OpenVpnConfig::parse(&config(
            "remote vpn.example 1403 tcp\ncipher AES-128-GCM\nauth SHA1\nauth-user-pass",
        ))
        .unwrap();
        let options = parsed.options_string(Protocol::Tcp);
        assert!(options.contains("proto TCPv4_CLIENT"), "{options}");
        assert!(options.contains("cipher AES-128-GCM"), "{options}");
        assert!(options.contains("keysize 128"), "{options}");
        assert!(options.ends_with("key-method 2,tls-client"), "{options}");
    }

    #[test]
    fn a_static_key_is_read_as_two_keys_of_cipher_then_hmac_material() {
        let hex = (0..256)
            .map(|byte| format!("{:02x}", byte as u8))
            .collect::<String>();
        let body = format!(
            "-----BEGIN OpenVPN Static key V1-----\n{hex}\n-----END OpenVPN Static key V1-----"
        );
        let key = read_static_key(&body, "tls-auth").unwrap();
        assert_eq!(key.cipher(0)[0], 0);
        assert_eq!(key.hmac(0)[0], 64);
        assert_eq!(key.cipher(1)[0], 128);
        assert_eq!(key.hmac(1)[0], 192);
    }
}
