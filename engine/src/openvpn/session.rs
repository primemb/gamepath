//! Bringing up an OpenVPN session and moving IP packets through it.
//!
//! The order of events is fixed by the protocol: reset, then a TLS handshake
//! carried inside control packets, then an exchange of random material that the
//! data-channel keys are derived from, then a push of the tunnel's settings.
//! Only after all four does a packet get to move.

use super::config::{DataCipher, OpenVpnConfig, Protocol, Remote};
use super::control::{ControlChannel, Received, is_data, opcode_of};
use super::crypto::{DataChannel, KeyMaterial, KeySource};
use super::link::{Link, Urgency};
use super::verify::EmbeddedCaVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection};
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a whole session setup may take before it is called failed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// How often to ask for the tunnel's settings until they arrive.
const PUSH_INTERVAL: Duration = Duration::from_millis(1500);

/// How long a link may stay silent mid-handshake before the failure is
/// attributed to the link rather than to the server being slow.
const SILENCE_LIMIT: Duration = Duration::from_secs(6);

/// The wait used when draining whatever has already arrived.
///
/// Not zero: Windows rejects a zero socket timeout outright, so the shortest
/// wait it will accept stands in for "do not block".
const DRAIN: Duration = Duration::from_millis(1);

/// The credentials a provider that uses `auth-user-pass` expects.
#[derive(Clone, Default)]
pub struct Credentials {
    pub username: Option<String>,
    pub password: Option<String>,
}

impl std::fmt::Debug for Credentials {
    /// Written by hand so that a password cannot reach a log through a derived
    /// `Debug`. The username is not secret and is what identifies the account.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// What the server pushed once the session came up.
#[derive(Debug, Clone)]
pub struct Pushed {
    /// The address the tunnel gave us, which inner packets must come from.
    pub address: Ipv4Addr,
    /// The far end of the tunnel, used when a route needs a gateway.
    pub gateway: Option<Ipv4Addr>,
    pub cipher: DataCipher,
    pub peer_id: Option<u32>,
    /// How often the server expects to hear from us when nothing is flowing.
    pub keepalive: Option<Duration>,
}

enum Stage {
    /// Waiting for the server to answer the reset.
    Reset,
    /// TLS is running inside control packets.
    Tls,
    /// TLS is up and the random material has been sent.
    KeyExchange,
    /// The keys are derived and the tunnel's settings have been asked for.
    Push,
}

pub struct Session {
    config: OpenVpnConfig,
    credentials: Credentials,
    protocol: Protocol,
    link: Link,
    control: ControlChannel,
    tls: Option<ClientConnection>,
    tls_config: Arc<ClientConfig>,
    stage: Stage,
    key_source: KeySource,
    material: Option<KeyMaterial>,
    /// The live key generations, oldest first.
    ///
    /// A renegotiation brings up new keys while the old ones still have packets
    /// in flight, so both have to be able to open one until the old generation
    /// falls out of use. Sending always uses the newest.
    channels: Vec<DataChannel>,
    pushed: Option<Pushed>,
    /// TLS application data that has arrived but not yet been split into
    /// messages.
    control_messages: Vec<u8>,
    /// Whether the server's half of the random material has been read.
    server_material: bool,
    last_push_request: Option<Instant>,
    last_inbound: Instant,
    last_keepalive: Instant,
    handshake_latency_ms: Option<f64>,
    /// Inner packets that arrived while something else was being waited for.
    inbound: Vec<Vec<u8>>,
}

impl Session {
    /// Dials the server and runs the whole setup, returning once packets can
    /// flow.
    pub fn connect(
        config: OpenVpnConfig,
        remote: &Remote,
        address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Self, String> {
        if config.wants_credentials && credentials.username.is_none() {
            return Err(
                "this OpenVPN configuration needs a username and password, which have not been \
                 entered for this node"
                    .into(),
            );
        }
        let tls_config = Arc::new(build_tls_config(&config)?);
        let link = Link::connect(remote.protocol, address, Duration::from_secs(10))?;
        let now = Instant::now();
        let mut session = Self {
            control: ControlChannel::new(&config.control_auth),
            protocol: remote.protocol,
            config,
            credentials,
            link,
            tls: None,
            tls_config,
            stage: Stage::Reset,
            key_source: KeySource::random(),
            material: None,
            channels: Vec::new(),
            pushed: None,
            control_messages: Vec::new(),
            server_material: false,
            last_push_request: None,
            last_inbound: now,
            last_keepalive: now,
            handshake_latency_ms: None,
            inbound: Vec::new(),
        };
        session.control.start();
        session.flush()?;
        session.run_setup(now)?;
        Ok(session)
    }

    pub fn pushed(&self) -> &Pushed {
        self.pushed
            .as_ref()
            .expect("a session is only handed back once the server has pushed its settings")
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn handshake_latency_ms(&self) -> Option<f64> {
        self.handshake_latency_ms
    }

    /// Sends one inner IP packet through the tunnel.
    pub fn send_inner(&mut self, packet: &[u8]) -> Result<(), String> {
        self.send_inner_with_urgency(packet, Urgency::Realtime)
    }

    pub(super) fn send_inner_with_urgency(
        &mut self,
        packet: &[u8],
        urgency: Urgency,
    ) -> Result<(), String> {
        let sealed = self
            .channels
            .last_mut()
            .ok_or("the OpenVPN data channel is not up")?
            .seal(packet)?;
        self.last_keepalive = Instant::now();
        self.link.send(&sealed, urgency)
    }

    /// Collects the inner IP packets that have arrived, waiting at most
    /// `timeout` for the first one.
    pub fn receive_inner(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        let deadline = Instant::now() + timeout;
        let mut packets = std::mem::take(&mut self.inbound);
        loop {
            self.keepalive()?;
            // The reliability layer has to keep turning even while traffic is
            // flowing, or a retransmission needed part-way through a
            // renegotiation never goes out.
            self.control.resend_stale(Instant::now());
            self.flush()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(packets);
            }
            let Some(packet) = self
                .link
                .receive(remaining.min(Duration::from_millis(50)))?
            else {
                if !packets.is_empty() {
                    return Ok(packets);
                }
                continue;
            };
            self.last_inbound = Instant::now();
            match self.absorb(&packet)? {
                Some(inner) => packets.push(inner),
                None => continue,
            }
            // Anything else already queued is taken without waiting again, so a
            // burst is handed over in one go.
            while let Some(packet) = self.link.receive(DRAIN)? {
                if let Some(inner) = self.absorb(&packet)? {
                    packets.push(inner);
                }
            }
            return Ok(packets);
        }
    }

    /// Handles one packet from the link, returning an inner packet if that is
    /// what it held.
    ///
    /// Control traffic is handled here as well as during setup, because a
    /// session that has been up for an hour is asked to rekey and has to do it
    /// without interrupting what it is carrying.
    fn absorb(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let opcode = opcode_of(packet).ok_or("an OpenVPN packet was empty")?;
        if is_data(opcode) {
            return self.open_data(packet);
        }
        self.step(packet)?;
        self.flush()?;
        Ok(None)
    }

    /// Opens a data packet under whichever key generation sealed it.
    fn open_data(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let key_id = packet[0] & 0x07;
        let Some(channel) = self
            .channels
            .iter_mut()
            .find(|channel| channel.key_id() == key_id)
        else {
            // A packet on a generation that has already been retired is not an
            // error; it is traffic that was in flight when the keys moved on.
            return Ok(None);
        };
        channel.open(packet)
    }

    /// Sends a keepalive if the server expects one and nothing has gone out.
    fn keepalive(&mut self) -> Result<(), String> {
        let Some(interval) = self.pushed.as_ref().and_then(|pushed| pushed.keepalive) else {
            return Ok(());
        };
        if self.last_keepalive.elapsed() < interval {
            return Ok(());
        }
        let ping = self
            .channels
            .last_mut()
            .ok_or("the OpenVPN data channel is not up")?
            .keepalive()?;
        self.last_keepalive = Instant::now();
        self.link.send(&ping, Urgency::Reliable)
    }

    /// Drives the setup to completion.
    fn run_setup(&mut self, started: Instant) -> Result<(), String> {
        let deadline = started + HANDSHAKE_TIMEOUT;
        while Instant::now() < deadline {
            if self.pushed.is_some() {
                self.handshake_latency_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                return Ok(());
            }
            if let Some(packet) = self.link.receive(Duration::from_millis(100))? {
                self.last_inbound = Instant::now();
                self.step(&packet)?;
            }
            self.control.resend_stale(Instant::now());
            self.request_push()?;
            self.flush()?;
            self.check_silence()?;
        }
        Err(self.timeout_reason())
    }

    /// Explains a setup that ran out of time in terms of how far it got.
    fn timeout_reason(&self) -> String {
        let where_it_stopped = match self.stage {
            Stage::Reset => {
                "the server never answered the opening packet. Check the address, the port and \
                 whether this is a udp or tcp configuration."
            }
            Stage::Tls => {
                "the TLS handshake did not finish. Over UDP this usually means the server's \
                 handshake packets are too large for the path and are being dropped; the same \
                 provider's tcp configuration will normally connect."
            }
            Stage::KeyExchange => {
                "the server accepted the TLS handshake but never sent its key material."
            }
            Stage::Push => {
                "the server never pushed the tunnel's settings, which usually means it is still \
                 deciding whether to accept the credentials."
            }
        };
        format!("the OpenVPN session did not come up: {where_it_stopped}")
    }

    /// Fails early when the link has gone quiet, rather than waiting out the
    /// whole timeout with nothing to show.
    fn check_silence(&self) -> Result<(), String> {
        if self.last_inbound.elapsed() < SILENCE_LIMIT {
            return Ok(());
        }
        if matches!(self.stage, Stage::Reset) {
            return Err(format!(
                "the OpenVPN server at {} is not answering. Nothing has come back at all, so \
                 either the address and port are wrong or the connection is being blocked.",
                self.link
                    .peer_addr()
                    .map(|address| address.to_string())
                    .unwrap_or_else(|| "the configured address".into())
            ));
        }
        Err(format!(
            "the OpenVPN server stopped answering part-way through the handshake. {}",
            match self.protocol {
                Protocol::Udp =>
                    "Its handshake packets are probably too large for this connection; try the \
                     provider's tcp configuration.",
                Protocol::Tcp => "The connection stayed open but the server went quiet.",
            }
        ))
    }

    /// Advances the setup with one packet from the link.
    fn step(&mut self, packet: &[u8]) -> Result<(), String> {
        let opcode = opcode_of(packet).ok_or("an OpenVPN packet was empty")?;
        if is_data(opcode) {
            // Data can arrive before the push is read; it is kept rather than
            // dropped so that nothing is lost at the moment the tunnel opens.
            if let Some(inner) = self.open_data(packet)? {
                self.inbound.push(inner);
            }
            return Ok(());
        }
        match self.control.receive(packet)? {
            Received::ServerReset => self.begin_tls(),
            Received::Payload(payload) => self.feed_tls(&payload),
            Received::SoftReset { key_id } => self.renegotiate(key_id),
            Received::Nothing => Ok(()),
        }
    }

    /// Starts a fresh handshake on a new key id, keeping the session.
    ///
    /// Servers ask for this roughly once an hour. Both session ids stay as they
    /// were and the pushed settings still stand, so all that is rebuilt is the
    /// TLS exchange and the key material it produces.
    fn renegotiate(&mut self, key_id: u8) -> Result<(), String> {
        if key_id == self.control.key_id() {
            return Ok(());
        }
        self.control.rekey(key_id);
        self.control.restart();
        self.tls = None;
        self.material = None;
        self.server_material = false;
        self.control_messages.clear();
        self.key_source = KeySource::random();
        self.begin_tls()
    }

    fn begin_tls(&mut self) -> Result<(), String> {
        if self.tls.is_some() {
            return Ok(());
        }
        // OpenVPN does not use the server name for anything -- the certificate
        // is checked against the configuration's own CA -- so a placeholder is
        // used and the extension is switched off.
        let name = ServerName::try_from("openvpn.invalid")
            .map_err(|error| format!("could not build a TLS session: {error}"))?;
        let connection = ClientConnection::new(self.tls_config.clone(), name)
            .map_err(|error| format!("could not start the OpenVPN TLS handshake: {error}"))?;
        self.tls = Some(connection);
        self.stage = Stage::Tls;
        Ok(())
    }

    /// Hands received bytes to TLS and reads back whatever they unlocked.
    fn feed_tls(&mut self, payload: &[u8]) -> Result<(), String> {
        let Some(connection) = self.tls.as_mut() else {
            return Ok(());
        };
        let mut cursor = io::Cursor::new(payload);
        while (cursor.position() as usize) < payload.len() {
            connection
                .read_tls(&mut cursor)
                .map_err(|error| format!("could not read the OpenVPN TLS stream: {error}"))?;
            connection
                .process_new_packets()
                .map_err(|error| format!("the OpenVPN TLS handshake failed: {error}"))?;
        }
        let mut received = Vec::new();
        // An error here means the peer has not sent application data yet, which
        // is the normal state during a handshake.
        let _ = connection.reader().read_to_end(&mut received);
        let handshaking = connection.is_handshaking();
        if !received.is_empty() {
            self.control_messages.extend_from_slice(&received);
            self.read_control_messages()?;
        }
        if !handshaking && matches!(self.stage, Stage::Tls) {
            self.send_key_material()?;
        }
        Ok(())
    }

    /// Sends the client's half of the key method 2 exchange.
    fn send_key_material(&mut self) -> Result<(), String> {
        let options = self.config.options_string(self.protocol);
        let peer_info = self.config.peer_info(
            self.config
                .remotes
                .first()
                .expect("a configuration always has a remote"),
        );
        let mut blob = Vec::with_capacity(512);
        blob.extend_from_slice(&0_u32.to_be_bytes());
        blob.push(2);
        blob.extend_from_slice(&self.key_source.pre_master);
        blob.extend_from_slice(&self.key_source.random1);
        blob.extend_from_slice(&self.key_source.random2);
        write_string(&mut blob, Some(&options));
        write_string(&mut blob, self.credentials.username.as_deref());
        write_string(&mut blob, self.credentials.password.as_deref());
        write_string(&mut blob, Some(&peer_info));
        self.tls
            .as_mut()
            .expect("TLS is up by the time key material is sent")
            .writer()
            .write_all(&blob)
            .map_err(|error| format!("could not send the OpenVPN key material: {error}"))?;
        self.stage = Stage::KeyExchange;
        Ok(())
    }

    /// Reads the server's key material and then its text messages.
    fn read_control_messages(&mut self) -> Result<(), String> {
        if !self.server_material {
            // The server answers with four zero bytes, the key method, its two
            // random values and an options string.
            const FIXED: usize = 4 + 1 + 32 + 32 + 2;
            if self.control_messages.len() < FIXED {
                return Ok(());
            }
            if self.control_messages[..4] != [0, 0, 0, 0] || self.control_messages[4] != 2 {
                let text = String::from_utf8_lossy(&self.control_messages)
                    .replace('\0', "")
                    .trim()
                    .to_owned();
                return Err(describe_refusal(&text));
            }
            let options_len = usize::from(u16::from_be_bytes([
                self.control_messages[69],
                self.control_messages[70],
            ]));
            if self.control_messages.len() < FIXED + options_len {
                return Ok(());
            }
            let mut server_random1 = [0_u8; 32];
            let mut server_random2 = [0_u8; 32];
            server_random1.copy_from_slice(&self.control_messages[5..37]);
            server_random2.copy_from_slice(&self.control_messages[37..69]);
            let client_sid = self.control.session_id();
            let server_sid = self
                .control
                .remote_session_id()
                .ok_or("the OpenVPN server's session id is not known yet")?;
            self.material = Some(KeyMaterial::derive(
                &self.key_source,
                &server_random1,
                &server_random2,
                &client_sid,
                &server_sid,
            ));
            self.control_messages.drain(..FIXED + options_len);
            self.server_material = true;
            self.stage = Stage::Push;
            // On a renegotiation the settings are already known, so the new
            // keys can go into use the moment the material exists. On a first
            // handshake there is nothing to install until the server pushes.
            self.install_keys()?;
        }
        while let Some(end) = self.control_messages.iter().position(|byte| *byte == 0) {
            let message = String::from_utf8_lossy(&self.control_messages[..end]).into_owned();
            self.control_messages.drain(..=end);
            self.handle_message(&message)?;
        }
        Ok(())
    }

    fn handle_message(&mut self, message: &str) -> Result<(), String> {
        if let Some(options) = message.strip_prefix("PUSH_REPLY,") {
            if self.pushed.is_some() {
                return Ok(());
            }
            let pushed = self.read_push(options)?;
            if self.material.is_none() {
                return Err(
                    "the OpenVPN server pushed its settings before its key material".into(),
                );
            }
            self.pushed = Some(pushed);
            self.install_keys()?;
            return Ok(());
        }
        if message.starts_with("AUTH_FAILED")
            || message.starts_with("RESTART")
            || message.starts_with("HALT")
        {
            return Err(describe_refusal(message));
        }
        // `INFO`, `AUTH_PENDING` and anything else the server chooses to say
        // are progress notes rather than results.
        Ok(())
    }

    /// Brings a key generation into use once both halves of what it needs --
    /// the derived material and the negotiated settings -- are known.
    fn install_keys(&mut self) -> Result<(), String> {
        let (Some(material), Some(pushed)) = (self.material.as_ref(), self.pushed.as_ref()) else {
            return Ok(());
        };
        let key_id = self.control.key_id();
        if self.channels.iter().any(|live| live.key_id() == key_id) {
            return Ok(());
        }
        self.channels.push(DataChannel::new(
            material,
            pushed.cipher,
            pushed.peer_id,
            key_id,
        )?);
        // Only the generation being replaced is kept, so that packets still in
        // flight on it are not thrown away.
        if self.channels.len() > 2 {
            self.channels.remove(0);
        }
        Ok(())
    }

    /// Reads the settings the server pushed.
    fn read_push(&self, options: &str) -> Result<Pushed, String> {
        let mut address = None;
        let mut gateway = None;
        let mut cipher = self.config.first_cipher();
        let mut peer_id = None;
        let mut ping = None;
        for option in options.split(',') {
            let mut words = option.split_whitespace();
            match words.next() {
                Some("ifconfig") => address = words.next().and_then(|value| value.parse().ok()),
                Some("route-gateway") => {
                    gateway = words.next().and_then(|value| value.parse().ok());
                }
                Some("cipher") => {
                    let name = words.next().unwrap_or_default();
                    cipher = DataCipher::parse(name).ok_or_else(|| {
                        format!(
                            "the OpenVPN server chose the `{name}` cipher, which GamePath does not \
                             implement. Ask the provider for a configuration using AES-256-GCM, \
                             AES-128-GCM or CHACHA20-POLY1305."
                        )
                    })?;
                }
                Some("peer-id") => peer_id = words.next().and_then(|value| value.parse().ok()),
                Some("ping") => {
                    ping = words
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(Duration::from_secs);
                }
                _ => {}
            }
        }
        Ok(Pushed {
            address: address.ok_or(
                "the OpenVPN server did not push a tunnel address, so there is nothing for inner \
                 packets to come from",
            )?,
            gateway,
            cipher,
            peer_id,
            keepalive: ping,
        })
    }

    /// Asks for the tunnel's settings, repeating until they arrive.
    fn request_push(&mut self) -> Result<(), String> {
        if !self.server_material || self.pushed.is_some() {
            return Ok(());
        }
        let due = self
            .last_push_request
            .is_none_or(|last| last.elapsed() >= PUSH_INTERVAL);
        if !due {
            return Ok(());
        }
        self.last_push_request = Some(Instant::now());
        self.tls
            .as_mut()
            .expect("TLS is up by the time settings are asked for")
            .writer()
            .write_all(b"PUSH_REQUEST\0")
            .map_err(|error| format!("could not ask the OpenVPN server for its settings: {error}"))
    }

    /// Moves anything TLS wants to send into control packets, then puts every
    /// queued control packet on the link.
    fn flush(&mut self) -> Result<(), String> {
        if let Some(connection) = self.tls.as_mut() {
            let mut outbound = Vec::new();
            while connection.wants_write() {
                connection
                    .write_tls(&mut outbound)
                    .map_err(|error| format!("could not write the OpenVPN TLS stream: {error}"))?;
            }
            if !outbound.is_empty() {
                self.control.send_tls(&outbound);
            }
        }
        while let Some(packet) = self.control.take_outgoing() {
            self.link.send(&packet, Urgency::Reliable)?;
        }
        // Whatever the socket could not take is queued rather than dropped or
        // waited on, so every pass of the loop gets another chance to move it.
        self.link.flush_outbound()
    }
}

/// Writes one length-prefixed, NUL-terminated string, or an empty field.
fn write_string(buffer: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) if !value.is_empty() => {
            let length = value.len() + 1;
            buffer.extend_from_slice(&(length as u16).to_be_bytes());
            buffer.extend_from_slice(value.as_bytes());
            buffer.push(0);
        }
        _ => buffer.extend_from_slice(&0_u16.to_be_bytes()),
    }
}

/// Turns a server's refusal into something a user can act on.
///
/// A server that says more than `AUTH_FAILED` usually names the account it
/// turned away, which is the fastest way to spot a mistyped username, so its
/// own words are kept rather than replaced with a generic sentence.
fn describe_refusal(message: &str) -> String {
    let trimmed = message.trim();
    if let Some(detail) = trimmed.strip_prefix("AUTH_FAILED") {
        let detail = detail.trim_start_matches([',', ' ']).trim();
        return if detail.is_empty() {
            "the OpenVPN server rejected the username and password for this node".into()
        } else {
            format!("the OpenVPN server rejected this node's login: {detail}")
        };
    }
    if trimmed.is_empty() {
        return "the OpenVPN server closed the session without saying why".into();
    }
    format!("the OpenVPN server refused the session: {trimmed}")
}

fn build_tls_config(config: &OpenVpnConfig) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = EmbeddedCaVerifier::new(&config.ca, provider.clone())?;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("could not configure TLS for OpenVPN: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier));
    let mut client_config = match (&config.client_certs, &config.client_key) {
        (certs, Some(key)) if !certs.is_empty() => {
            let chain = certs
                .iter()
                .map(|der| CertificateDer::from(der.clone()))
                .collect();
            let key = read_client_key(key)?;
            builder.with_client_auth_cert(chain, key).map_err(|error| {
                format!("the `<cert>` and `<key>` blocks were rejected: {error}")
            })?
        }
        _ => builder.with_no_client_auth(),
    };
    // OpenVPN servers are addressed by IP as often as by name and do not
    // consult the extension, so sending it would only leak the hostname.
    client_config.enable_sni = false;
    Ok(client_config)
}

fn read_client_key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| format!("the `<key>` block is not readable: {error}"))?
        .ok_or_else(|| "the `<key>` block does not contain a usable private key".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_present_string_is_length_prefixed_and_terminated() {
        let mut buffer = Vec::new();
        write_string(&mut buffer, Some("ab"));
        assert_eq!(buffer, vec![0, 3, b'a', b'b', 0]);
    }

    #[test]
    fn an_absent_or_empty_string_is_written_as_an_empty_field() {
        let mut buffer = Vec::new();
        write_string(&mut buffer, None);
        write_string(&mut buffer, Some(""));
        assert_eq!(buffer, vec![0, 0, 0, 0]);
    }

    #[test]
    fn a_rejected_password_is_reported_as_a_rejected_password() {
        let message = describe_refusal("AUTH_FAILED");
        assert!(
            message.contains("rejected the username and password"),
            "{message}"
        );
    }

    /// Servers commonly name the account they turned away, which is what tells
    /// a user they mistyped it, so that detail is carried through.
    #[test]
    fn the_servers_own_reason_for_refusing_a_login_is_kept() {
        let message = describe_refusal("AUTH_FAILED, user primemb authentication failed");
        assert!(
            message.contains("user primemb authentication failed"),
            "{message}"
        );
    }

    #[test]
    fn another_refusal_is_passed_through_so_nothing_is_hidden() {
        let message = describe_refusal("RESTART,connection reset");
        assert!(message.contains("RESTART,connection reset"), "{message}");
    }
}
