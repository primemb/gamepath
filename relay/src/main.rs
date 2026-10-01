use clap::{Parser, Subcommand};
use gamepath_engine::auth::{EnrollmentToken, SessionCrypto};
use gamepath_engine::fec::{self, Decoder, Encoder, Offer};
use gamepath_engine::mtu::{LINK_MTU, relay_tun_mtu};
use gamepath_engine::protocol::{
    FLAG_CONTROL, FLAG_REPAIR, FLAG_SERVER_TO_CLIENT, FrameHeader, HEADER_LEN,
};
use gamepath_engine::replay::ReplayWindow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tun_rs::{DeviceBuilder, SyncDevice};

const MAX_PACKET: usize = 65_535;
const MAX_ENDPOINTS_PER_SESSION: usize = 8;
const ENDPOINT_TTL: Duration = Duration::from_secs(45);

/// How long a session survives without authenticated traffic. A client that
/// reconnects gets a new session id, so without this every reconnect would
/// leave its predecessor's replay window behind for the life of the process.
const SESSION_TTL: Duration = Duration::from_secs(180);

/// Sessions one enrolled client may hold at once. Roaming and a handful of
/// paths need a few; an enrolled client cycling session ids to grow the map
/// does not get to keep them.
const MAX_SESSIONS_PER_CLIENT: usize = 8;

/// How often the relay prints a line of counters. Frames turned away by the
/// replay window are invisible from both ends otherwise: the client sees
/// unanswered probes and the relay sees nothing at all.
const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Longest the repair flusher sleeps with no group open. Replies wake it when
/// they open a group, so this only bounds a missed wakeup.
const REPAIR_IDLE_WAIT: Duration = Duration::from_millis(250);

#[derive(Parser)]
#[command(name = "gamepath-relay", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "0.0.0.0:51821")]
        bind: SocketAddr,
        #[arg(long, default_value = "/etc/gamepath/clients")]
        clients_dir: PathBuf,
        #[arg(long, default_value = "gptun0")]
        tun_name: String,
        #[arg(long, default_value = "10.203.0.1")]
        tun_address: Ipv4Addr,
        #[arg(long, default_value_t = 24)]
        tun_prefix: u8,
    },
    Enroll {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "/etc/gamepath/clients")]
        clients_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        virtual_ip: Option<Ipv4Addr>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRecord {
    name: String,
    version: u8,
    client_id: String,
    pre_shared_key: String,
    virtual_ipv4: Ipv4Addr,
}

impl ClientRecord {
    fn token(&self) -> EnrollmentToken {
        EnrollmentToken {
            version: self.version,
            client_id: self.client_id.clone(),
            pre_shared_key: self.pre_shared_key.clone(),
            virtual_ipv4: self.virtual_ipv4,
        }
    }
}

struct RelayClient {
    record: ClientRecord,
    client_id: [u8; 16],
    key: [u8; 32],
    sessions: HashMap<u64, SessionState>,
}

struct SessionState {
    replay: ReplayWindow,
    endpoints: Vec<(SocketAddr, Instant)>,
    outbound_sequence: u64,
    last_seen: Instant,
    /// Frames the replay window turned away. Duplicates from a second path are
    /// expected and counted here too; a count climbing far faster than the
    /// duplicate rate means frames are arriving outside the window.
    rejected_frames: u64,
    /// Present once the client has offered loss repair. A client from before
    /// loss repair never offers, and its session carries no repairs either way.
    repair: Option<RepairState>,
}

struct RepairState {
    /// Protects replies, in groups sized by the client's latest offer.
    encoder: Encoder,
    /// Rebuilds client frames from the client's repairs.
    decoder: Decoder,
    /// Sequence of the offer applied last. Offers travel every path, so an
    /// older one overtaken on a faster path must not undo the newer one.
    offer_sequence: u64,
    recovered: u64,
}

impl RepairState {
    fn new(offer: Offer) -> Self {
        Self {
            encoder: Encoder::new(offer.group_size, reply_repair_limit(offer)),
            decoder: Decoder::default(),
            offer_sequence: 0,
            recovered: 0,
        }
    }
}

impl RelayClient {
    /// Drops sessions that have gone quiet, then enforces the per-client cap by
    /// evicting the least recently used. Called before a session is created,
    /// which is the only moment the map can grow.
    fn admit_session(&mut self, session_id: u64, now: Instant) -> &mut SessionState {
        self.sessions
            .retain(|_, session| now.duration_since(session.last_seen) <= SESSION_TTL);
        if !self.sessions.contains_key(&session_id) {
            while self.sessions.len() >= MAX_SESSIONS_PER_CLIENT {
                let Some(oldest) = self
                    .sessions
                    .iter()
                    .min_by_key(|(_, session)| session.last_seen)
                    .map(|(id, _)| *id)
                else {
                    break;
                };
                self.sessions.remove(&oldest);
            }
        }
        self.sessions
            .entry(session_id)
            .or_insert_with(SessionState::new)
    }
}

impl SessionState {
    fn new() -> Self {
        Self {
            replay: ReplayWindow::default(),
            endpoints: Vec::new(),
            outbound_sequence: fresh_outbound_sequence(),
            last_seen: Instant::now(),
            rejected_frames: 0,
            repair: None,
        }
    }

    /// Seals `payload` as the next reply-direction frame and sends it to every
    /// endpoint this session has been seen from recently. Returns the sequence
    /// used, or `None` when there is nowhere left to send it.
    fn fan_out(
        &mut self,
        socket: &UdpSocket,
        crypto: &SessionCrypto,
        client_id: [u8; 16],
        session_id: u64,
        flags: u8,
        payload: &[u8],
    ) -> Option<u64> {
        let now = Instant::now();
        self.endpoints
            .retain(|(_, seen)| now.duration_since(*seen) <= ENDPOINT_TTL);
        if self.endpoints.is_empty() {
            return None;
        }
        self.outbound_sequence = self.outbound_sequence.wrapping_add(1);
        let header = FrameHeader {
            flags: flags | FLAG_SERVER_TO_CLIENT,
            client_id,
            session_id,
            sequence: self.outbound_sequence,
        };
        let frame = crypto.seal_server(header, payload).ok()?;
        for (endpoint, _) in &self.endpoints {
            let _ = socket.send_to(&frame, endpoint);
        }
        Some(header.sequence)
    }

    fn observe_endpoint(&mut self, endpoint: SocketAddr) {
        let now = Instant::now();
        self.endpoints
            .retain(|(_, seen)| now.duration_since(*seen) <= ENDPOINT_TTL);
        if let Some(existing) = self
            .endpoints
            .iter_mut()
            .find(|(address, _)| *address == endpoint)
        {
            existing.1 = now;
        } else {
            if self.endpoints.len() >= MAX_ENDPOINTS_PER_SESSION {
                self.endpoints.sort_by_key(|(_, seen)| *seen);
                self.endpoints.remove(0);
            }
            self.endpoints.push((endpoint, now));
        }
        self.last_seen = now;
    }
}

/// Where a new session's reply sequence starts: the wall clock in microseconds.
///
/// A session's key comes from the enrolment key and its id alone, and the AEAD
/// nonce is the sequence, so a session the relay forgets and re-creates for the
/// same id - evicted, expired, or lost to a relay restart while the client kept
/// going - must not count from zero again. That reused every nonce of its
/// previous life under the same key, and the client's replay window, already
/// far ahead, discarded every reply as stale: a session that looked connected
/// and delivered nothing. The clock moves a million steps a second, faster than
/// any session sends, so a new start is past everything an earlier one used.
fn fresh_outbound_sequence() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as u64)
}

/// The answer to a reachability probe from a session this relay holds no state
/// for, sent without creating any.
///
/// Clients test a relay with a one-off session id per probe. Admitting each one
/// filled the per-client session cap with probes, and during an outage the real
/// session, silent while its paths were down, was the least recently used and
/// the one evicted. It also briefly became the newest session, which is where
/// replies are sent. A probe needs nothing kept to be answered, and its id is
/// never used again, so its fresh-sequence reply cannot repeat a nonce either.
fn stateless_probe_reply(
    client: &RelayClient,
    crypto: &SessionCrypto,
    header: &FrameHeader,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if header.flags & FLAG_CONTROL == 0 || client.sessions.contains_key(&header.session_id) {
        return None;
    }
    let response = gamepath_engine::protocol::probe_response(plaintext)?;
    let response_header = FrameHeader {
        flags: FLAG_CONTROL | FLAG_SERVER_TO_CLIENT,
        client_id: client.client_id,
        session_id: header.session_id,
        sequence: fresh_outbound_sequence(),
    };
    crypto.seal_server(response_header, &response).ok()
}

fn main() {
    gamepath_engine::log::init("relay", Some(gamepath_engine::log::log_path("relay")), true);
    if let Err(error) = run() {
        gamepath_engine::log_error!("{error}");
        gamepath_engine::log::flush();
        std::process::exit(1);
    }
    gamepath_engine::log::flush();
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Serve {
            bind,
            clients_dir,
            tun_name,
            tun_address,
            tun_prefix,
        } => serve(bind, &clients_dir, &tun_name, tun_address, tun_prefix)
            .map_err(|error| error.to_string()),
        Command::Enroll {
            name,
            clients_dir,
            output,
            virtual_ip,
        } => enroll(&name, &clients_dir, &output, virtual_ip).map_err(|error| error.to_string()),
    }
}

fn enroll(
    name: &str,
    clients_dir: &Path,
    output: &Path,
    virtual_ip: Option<Ipv4Addr>,
) -> io::Result<()> {
    if name.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "client name cannot be empty",
        ));
    }
    fs::create_dir_all(clients_dir)?;
    let records = read_records(clients_dir)?;
    let virtual_ip = virtual_ip.unwrap_or_else(|| next_virtual_ip(&records));
    if virtual_ip.octets()[..3] != [10, 203, 0] || virtual_ip.octets()[3] < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtual IP must be in 10.203.0.2/24",
        ));
    }
    if records
        .iter()
        .any(|record| record.virtual_ipv4 == virtual_ip)
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "virtual IP is already enrolled",
        ));
    }
    let token = EnrollmentToken::generate(virtual_ip);
    let record = ClientRecord {
        name: name.trim().into(),
        version: token.version,
        client_id: token.client_id.clone(),
        pre_shared_key: token.pre_shared_key.clone(),
        virtual_ipv4: token.virtual_ipv4,
    };
    let safe_name: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "-_".contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect();
    write_secret_json(&clients_dir.join(format!("{safe_name}.json")), &record)?;
    write_secret(
        output,
        format!("{}\n", token.encode().map_err(io::Error::other)?).as_bytes(),
    )?;
    println!(
        "Enrolled {name} as {virtual_ip}; token written to {}",
        output.display()
    );
    Ok(())
}

fn serve(
    bind: SocketAddr,
    clients_dir: &Path,
    tun_name: &str,
    tun_address: Ipv4Addr,
    tun_prefix: u8,
) -> io::Result<()> {
    let records = read_records(clients_dir)?;
    if records.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no enrolled clients found",
        ));
    }
    let mut clients = HashMap::new();
    for record in records {
        let (client_id, key) = record.token().material().map_err(io::Error::other)?;
        clients.insert(
            client_id,
            RelayClient {
                record,
                client_id,
                key,
                sessions: HashMap::new(),
            },
        );
    }
    let clients = Arc::new(Mutex::new(clients));
    let socket = Arc::new(UdpSocket::bind(bind)?);
    let tun = Arc::new(
        DeviceBuilder::new()
            .name(tun_name)
            .ipv4(tun_address, tun_prefix, None)
            // Sized from what a client's transports add on the way back,
            // not from the physical link: a packet written here is sealed and
            // re-encapsulated before it reaches anyone.
            .mtu(relay_tun_mtu(LINK_MTU))
            .build_sync()?,
    );
    let stats_clients = Arc::clone(&clients);
    thread::Builder::new()
        .name("gamepath-relay-stats".into())
        .spawn(move || {
            let mut reported = 0_u64;
            loop {
                thread::sleep(STATS_INTERVAL);
                let (sessions, endpoints, rejected, recovered) = {
                    let clients = stats_clients.lock().unwrap();
                    clients.values().fold((0, 0, 0, 0), |totals, client| {
                        client
                            .sessions
                            .values()
                            .fold(totals, |(s, e, r, f), session| {
                                (
                                    s + 1,
                                    e + session.endpoints.len(),
                                    r + session.rejected_frames,
                                    f + session
                                        .repair
                                        .as_ref()
                                        .map_or(0, |repair| repair.recovered),
                                )
                            })
                    })
                };
                // Only speak up when something changed, so an idle relay stays
                // quiet in the journal.
                if rejected != reported || sessions > 0 {
                    gamepath_engine::log_info!(
                        "sessions={sessions} endpoints={endpoints} rejected_frames={rejected} \
                         (+{} since last report) recovered_frames={recovered}",
                        rejected.saturating_sub(reported)
                    );
                    reported = rejected;
                }
            }
        })?;
    let repair_wake = Arc::new(Condvar::new());
    let flush_socket = Arc::clone(&socket);
    let flush_clients = Arc::clone(&clients);
    let flush_wake = Arc::clone(&repair_wake);
    thread::Builder::new()
        .name("gamepath-repair-flush".into())
        .spawn(move || flush_repairs(&flush_socket, &flush_clients, &flush_wake))?;
    let tun_writer = Arc::clone(&tun);
    let reply_socket = Arc::clone(&socket);
    let reply_clients = Arc::clone(&clients);
    let reply_wake = Arc::clone(&repair_wake);
    thread::Builder::new()
        .name("gamepath-tun-replies".into())
        .spawn(move || {
            let mut packet = [0_u8; MAX_PACKET];
            loop {
                match tun.recv(&mut packet) {
                    Ok(length) => forward_reply(
                        &reply_socket,
                        &reply_clients,
                        &reply_wake,
                        &packet[..length],
                    ),
                    Err(error) => {
                        gamepath_engine::log_error!("TUN receive failed: {error}");
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        })?;
    println!(
        "GamePath relay listening on {bind} with {} enrolled client(s)",
        clients.lock().unwrap().len()
    );
    let mut frame = [0_u8; MAX_PACKET];
    loop {
        let (length, endpoint) = socket.recv_from(&mut frame)?;
        if length < HEADER_LEN + 16 {
            continue;
        }
        let Ok(header) = FrameHeader::decode(&frame[..length]) else {
            continue;
        };
        if header.flags & FLAG_SERVER_TO_CLIENT != 0 {
            continue;
        }
        let mut clients = clients.lock().unwrap();
        let Some(client) = clients.get_mut(&header.client_id) else {
            continue;
        };
        let Ok(crypto) = SessionCrypto::new(&client.key, header.session_id) else {
            continue;
        };
        let Ok((verified_header, plaintext)) = crypto.open_client(&frame[..length]) else {
            continue;
        };
        if let Some(reply) = stateless_probe_reply(client, &crypto, &verified_header, &plaintext) {
            let _ = socket.send_to(&reply, endpoint);
            continue;
        }
        // Read before the session borrow, which holds `client` mutably.
        let client_id = client.client_id;
        let virtual_ipv4 = client.record.virtual_ipv4;
        // Only an authenticated frame reaches here, so an unenrolled sender
        // cannot make the session map grow at all.
        let session = client.admit_session(header.session_id, Instant::now());
        session.observe_endpoint(endpoint);
        if !session.replay.accept(verified_header.sequence) {
            // Either a genuine duplicate from a second path, or a frame so far
            // behind that the window has forgotten it. The counter separates a
            // relay that is deduplicating from one that is dropping real
            // traffic, which is otherwise invisible from either end.
            session.rejected_frames += 1;
            continue;
        }
        if verified_header.flags & FLAG_CONTROL != 0 {
            if let Some(offer) = fec::parse_offer(&plaintext) {
                apply_repair_offer(
                    session,
                    &socket,
                    &crypto,
                    (client_id, header.session_id),
                    verified_header.sequence,
                    offer,
                    endpoint,
                );
                continue;
            }
            let Some(response) = gamepath_engine::protocol::probe_response(&plaintext) else {
                continue;
            };
            session.outbound_sequence = session.outbound_sequence.wrapping_add(1);
            let response_header = FrameHeader {
                flags: FLAG_CONTROL | FLAG_SERVER_TO_CLIENT,
                client_id,
                session_id: header.session_id,
                sequence: session.outbound_sequence,
            };
            if let Ok(response) = crypto.seal_server(response_header, &response) {
                let _ = socket.send_to(&response, endpoint);
            }
            continue;
        }
        if verified_header.flags & FLAG_REPAIR != 0 {
            let SessionState { replay, repair, .. } = &mut *session;
            let Some(repair) = repair.as_mut() else {
                continue;
            };
            let rebuilt = repair
                .decoder
                .accept_repair(&plaintext, Instant::now(), |sequence| {
                    !replay.would_accept(sequence)
                });
            if let Some((sequence, packet)) = rebuilt {
                admit_rebuilt(session, &tun_writer, virtual_ipv4, sequence, packet);
            }
            retry_pending_repairs(session, &tun_writer, virtual_ipv4);
            continue;
        }
        if ipv4_source(&plaintext) != Some(virtual_ipv4) {
            continue;
        }
        if let Err(error) = tun_writer.send(&plaintext) {
            gamepath_engine::log_error!("TUN send failed: {error}");
        }
        if let Some(repair) = session.repair.as_mut() {
            repair
                .decoder
                .remember(verified_header.sequence, &plaintext);
            retry_pending_repairs(session, &tun_writer, virtual_ipv4);
        }
    }
}

/// Largest reply worth protecting for a client. Its tunnel MTU comes from its
/// own link and transports, which can be well under what this relay assumes;
/// a repair of a reply near that size would not fit the client's link.
fn reply_repair_limit(offer: Offer) -> usize {
    usize::from(offer.mtu.min(relay_tun_mtu(LINK_MTU)))
}

/// Applies the group size and MTU a client asked its replies to be protected
/// with, and confirms the size in use on the path the offer came by, like a
/// probe reply, so the client hears back even while its other paths are down.
fn apply_repair_offer(
    session: &mut SessionState,
    socket: &UdpSocket,
    crypto: &SessionCrypto,
    (client_id, session_id): ([u8; 16], u64),
    offer_sequence: u64,
    offer: Offer,
    endpoint: SocketAddr,
) {
    let repair = session.repair.get_or_insert_with(|| {
        gamepath_engine::log_info!(
            "session {session_id:016x} loss repair on, replies in groups of {} up to {} bytes",
            offer.group_size,
            reply_repair_limit(offer)
        );
        RepairState::new(offer)
    });
    let mut closed = None;
    if offer_sequence >= repair.offer_sequence {
        if repair.encoder.group_size() != offer.group_size {
            gamepath_engine::log_info!(
                "session {session_id:016x} loss repair replies now in groups of {}",
                offer.group_size
            );
        }
        repair.offer_sequence = offer_sequence;
        repair.encoder.set_max_packet(reply_repair_limit(offer));
        closed = repair.encoder.set_group_size(offer.group_size);
    }
    let applied = repair.encoder.group_size();
    if let Some(payload) = closed {
        session.fan_out(socket, crypto, client_id, session_id, FLAG_REPAIR, &payload);
    }
    session.outbound_sequence = session.outbound_sequence.wrapping_add(1);
    let header = FrameHeader {
        flags: FLAG_CONTROL | FLAG_SERVER_TO_CLIENT,
        client_id,
        session_id,
        sequence: session.outbound_sequence,
    };
    if let Ok(accept) = crypto.seal_server(header, &fec::accept(applied)) {
        let _ = socket.send_to(&accept, endpoint);
    }
}

/// Forwards a client packet rebuilt from a repair exactly as if it had
/// arrived: the same source check, and its sequence consumed so the original
/// turning up late by a slower path is a duplicate.
fn admit_rebuilt(
    session: &mut SessionState,
    tun: &SyncDevice,
    virtual_ipv4: Ipv4Addr,
    sequence: u64,
    packet: Vec<u8>,
) {
    if ipv4_source(&packet) != Some(virtual_ipv4) || !session.replay.accept(sequence) {
        return;
    }
    if let Err(error) = tun.send(&packet) {
        gamepath_engine::log_error!("TUN send failed: {error}");
    }
    if let Some(repair) = session.repair.as_mut() {
        repair.decoder.remember(sequence, &packet);
        repair.recovered += 1;
    }
}

/// A delivery can complete a repair that was waiting on more than one member.
fn retry_pending_repairs(session: &mut SessionState, tun: &SyncDevice, virtual_ipv4: Ipv4Addr) {
    loop {
        let SessionState { replay, repair, .. } = &mut *session;
        let Some(repair) = repair
            .as_mut()
            .filter(|repair| repair.decoder.has_pending())
        else {
            return;
        };
        let Some((sequence, packet)) = repair
            .decoder
            .retry_pending(Instant::now(), |sequence| !replay.would_accept(sequence))
        else {
            return;
        };
        admit_rebuilt(session, tun, virtual_ipv4, sequence, packet);
    }
}

/// Closes reply groups that stopped growing, so the last reply before a pause
/// is covered within [`fec::GROUP_MAX_AGE`].
fn flush_repairs(
    socket: &UdpSocket,
    clients: &Mutex<HashMap<[u8; 16], RelayClient>>,
    wake: &Condvar,
) {
    let mut guard = clients.lock().unwrap();
    loop {
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        for client in guard.values_mut() {
            let RelayClient {
                client_id,
                key,
                sessions,
                ..
            } = client;
            for (&session_id, session) in sessions.iter_mut() {
                let Some(repair) = session.repair.as_mut() else {
                    continue;
                };
                if let Some(payload) = repair.encoder.flush_due(now) {
                    if let Ok(crypto) = SessionCrypto::new(key, session_id) {
                        session.fan_out(
                            socket,
                            &crypto,
                            *client_id,
                            session_id,
                            FLAG_REPAIR,
                            &payload,
                        );
                    }
                } else if let Some(deadline) = repair.encoder.deadline() {
                    next = Some(next.map_or(deadline, |next| next.min(deadline)));
                }
            }
        }
        let wait = next.map_or(REPAIR_IDLE_WAIT, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        guard = wake.wait_timeout(guard, wait).unwrap().0;
    }
}

fn forward_reply(
    socket: &UdpSocket,
    clients: &Mutex<HashMap<[u8; 16], RelayClient>>,
    repair_wake: &Condvar,
    packet: &[u8],
) {
    let Some(destination) = ipv4_destination(packet) else {
        return;
    };
    let mut clients = clients.lock().unwrap();
    let Some(client) = clients
        .values_mut()
        .find(|client| client.record.virtual_ipv4 == destination)
    else {
        return;
    };
    let Some((&session_id, session)) = client
        .sessions
        .iter_mut()
        .max_by_key(|(_, session)| session.last_seen)
    else {
        return;
    };
    let Ok(crypto) = SessionCrypto::new(&client.key, session_id) else {
        return;
    };
    let Some(sequence) = session.fan_out(socket, &crypto, client.client_id, session_id, 0, packet)
    else {
        return;
    };
    let Some(repair) = session.repair.as_mut() else {
        return;
    };
    let idle = repair.encoder.deadline().is_none();
    let closed = repair.encoder.push(sequence, packet, Instant::now());
    // A flusher already waiting on a deadline rereads every encoder when it
    // wakes, so only one sleeping with nothing open needs telling.
    if idle && repair.encoder.deadline().is_some() {
        repair_wake.notify_one();
    }
    if let Some(payload) = closed {
        session.fan_out(
            socket,
            &crypto,
            client.client_id,
            session_id,
            FLAG_REPAIR,
            &payload,
        );
    }
}

fn read_records(directory: &Path) -> io::Result<Vec<ClientRecord>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let source = fs::read(&path)?;
        let record = serde_json::from_slice(&source).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}", path.display()),
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

fn next_virtual_ip(records: &[ClientRecord]) -> Ipv4Addr {
    let used: std::collections::HashSet<u8> = records
        .iter()
        .map(|record| record.virtual_ipv4.octets()[3])
        .collect();
    let host = (2..=254)
        .find(|host| !used.contains(host))
        .expect("client subnet is full");
    Ipv4Addr::new(10, 203, 0, host)
}

fn ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

fn write_secret_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    write_secret(
        path,
        &serde_json::to_vec_pretty(value).map_err(io::Error::other)?,
    )
}

fn write_secret(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_client() -> RelayClient {
        RelayClient {
            record: ClientRecord {
                name: "test".into(),
                version: 1,
                client_id: "id".into(),
                pre_shared_key: "key".into(),
                virtual_ipv4: Ipv4Addr::new(10, 203, 0, 2),
            },
            client_id: [0; 16],
            key: [0; 32],
            sessions: HashMap::new(),
        }
    }

    #[test]
    fn a_quiet_session_is_expired_rather_than_kept_for_the_life_of_the_process() {
        let mut client = relay_client();
        let start = Instant::now();
        client.admit_session(1, start);
        assert_eq!(client.sessions.len(), 1);
        // A reconnect long after the first session went quiet.
        client.admit_session(2, start + SESSION_TTL + Duration::from_secs(1));
        assert_eq!(client.sessions.len(), 1);
        assert!(client.sessions.contains_key(&2));
    }

    #[test]
    fn an_active_session_survives_a_new_one_being_admitted() {
        let mut client = relay_client();
        let start = Instant::now();
        client.admit_session(1, start).last_seen = start + Duration::from_secs(10);
        client.admit_session(2, start + Duration::from_secs(10));
        assert_eq!(client.sessions.len(), 2);
    }

    #[test]
    fn a_client_cycling_session_ids_cannot_grow_the_map_without_bound() {
        let mut client = relay_client();
        let start = Instant::now();
        for id in 0..MAX_SESSIONS_PER_CLIENT as u64 * 4 {
            // Every session stays fresh, so only the cap can hold this down.
            let session = client.admit_session(id, start);
            session.last_seen = start + Duration::from_millis(id);
        }
        assert_eq!(client.sessions.len(), MAX_SESSIONS_PER_CLIENT);
        // The survivors are the most recent ones.
        assert!(client.sessions.contains_key(
            &(MAX_SESSIONS_PER_CLIENT as u64 * 4 - 1)
        ));
        assert!(!client.sessions.contains_key(&0));
    }

    #[test]
    fn admitting_an_existing_session_does_not_evict_anything() {
        let mut client = relay_client();
        let start = Instant::now();
        for id in 0..MAX_SESSIONS_PER_CLIENT as u64 {
            client.admit_session(id, start).last_seen = start + Duration::from_millis(id);
        }
        client.admit_session(0, start);
        assert_eq!(client.sessions.len(), MAX_SESSIONS_PER_CLIENT);
        assert!(client.sessions.contains_key(&0));
    }

    #[test]
    fn replay_window_accepts_reordering_once() {
        let mut replay = ReplayWindow::default();
        assert!(replay.accept(10));
        assert!(replay.accept(12));
        assert!(replay.accept(11));
        assert!(!replay.accept(11));
        assert!(!replay.accept(10));
    }

    /// Offers travel every path, so an older one arriving after a newer one
    /// must not put the reply group size back, and each is still answered.
    #[test]
    fn a_stale_repair_offer_cannot_undo_a_newer_one() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let endpoint = client.local_addr().unwrap();
        let crypto = SessionCrypto::new(&[5; 32], 9).unwrap();
        let mut session = SessionState::new();
        let offer = |session: &mut SessionState, sequence, group_size| {
            let offer = Offer {
                group_size,
                mtu: 1341,
            };
            apply_repair_offer(
                session,
                &socket,
                &crypto,
                ([1; 16], 9),
                sequence,
                offer,
                endpoint,
            );
            let mut reply = [0_u8; 256];
            let length = client.recv(&mut reply).unwrap();
            let (_, plaintext) = crypto.open_server(&reply[..length]).unwrap();
            fec::accepted_group(&plaintext)
        };
        assert_eq!(offer(&mut session, 10, fec::MULTIPATH_GROUP), Some(4));
        assert_eq!(offer(&mut session, 20, fec::SINGLE_PATH_GROUP), Some(1));
        // The multipath offer sent first, arriving last by a slower path.
        assert_eq!(offer(&mut session, 10, fec::MULTIPATH_GROUP), Some(1));
        assert_eq!(session.repair.as_ref().unwrap().encoder.group_size(), 1);
    }

    /// A client on a narrow link has a smaller tunnel than this relay assumes,
    /// and a reply near that size must not be given a repair it cannot carry.
    #[test]
    fn replies_are_protected_only_up_to_the_clients_own_mtu() {
        let narrow = Offer {
            group_size: fec::MULTIPATH_GROUP,
            mtu: 1200,
        };
        assert_eq!(reply_repair_limit(narrow), 1200);
        let wide = Offer {
            mtu: u16::MAX,
            ..narrow
        };
        assert_eq!(
            reply_repair_limit(wide),
            usize::from(relay_tun_mtu(LINK_MTU))
        );
        let mut repair = RepairState::new(narrow);
        let now = Instant::now();
        assert!(repair.encoder.push(1, &[0x45; 1201], now).is_none());
        assert!(repair.encoder.deadline().is_none());
    }

    fn probe(session_id: u64, payload: &[u8]) -> (SessionCrypto, FrameHeader, Vec<u8>) {
        let crypto = SessionCrypto::new(&[0; 32], session_id).unwrap();
        let header = FrameHeader {
            flags: FLAG_CONTROL,
            client_id: [0; 16],
            session_id,
            sequence: 1,
        };
        (crypto, header, payload.to_vec())
    }

    #[test]
    fn a_probe_from_an_unknown_session_is_answered_without_admitting_it() {
        let mut client = relay_client();
        client.admit_session(1, Instant::now());
        let (crypto, header, payload) = probe(99, b"ping");
        let reply = stateless_probe_reply(&client, &crypto, &header, &payload).unwrap();
        let (reply_header, plaintext) = crypto.open_server(&reply).unwrap();
        assert_eq!(plaintext, b"pong");
        assert_eq!(reply_header.session_id, 99);
        assert_eq!(client.sessions.len(), 1);
    }

    #[test]
    fn a_live_session_and_anything_but_a_probe_go_through_the_session() {
        let mut client = relay_client();
        client.admit_session(1, Instant::now());
        let (crypto, header, payload) = probe(1, b"ping");
        assert!(stateless_probe_reply(&client, &crypto, &header, &payload).is_none());
        // An unknown session's loss-repair offer is a real session coming back.
        let offer = fec::offer(Offer {
            group_size: fec::MULTIPATH_GROUP,
            mtu: 1341,
        });
        let (crypto, header, payload) = probe(2, &offer);
        assert!(stateless_probe_reply(&client, &crypto, &header, &payload).is_none());
        let (crypto, mut header, payload) = probe(3, b"ping");
        header.flags = 0;
        assert!(stateless_probe_reply(&client, &crypto, &header, &payload).is_none());
    }

    #[test]
    fn a_re_created_session_never_repeats_an_earlier_reply_sequence() {
        let mut first = SessionState::new();
        for _ in 0..10_000 {
            first.outbound_sequence = first.outbound_sequence.wrapping_add(1);
        }
        std::thread::sleep(Duration::from_millis(20));
        let second = SessionState::new();
        assert!(second.outbound_sequence > first.outbound_sequence);
    }

    #[test]
    fn packet_addresses_are_extracted() {
        let mut packet = [0_u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&[10, 203, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(ipv4_source(&packet), Some(Ipv4Addr::new(10, 203, 0, 2)));
        assert_eq!(ipv4_destination(&packet), Some(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
