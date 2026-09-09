use clap::{Parser, Subcommand};
use gamepath_engine::auth::{EnrollmentToken, SessionCrypto};
use gamepath_engine::protocol::{FLAG_CONTROL, FLAG_SERVER_TO_CLIENT, FrameHeader, HEADER_LEN};
use gamepath_engine::mtu::{LINK_MTU, relay_tun_mtu};
use gamepath_engine::replay::ReplayWindow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tun_rs::DeviceBuilder;

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
            outbound_sequence: 0,
            last_seen: Instant::now(),
            rejected_frames: 0,
        }
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
                let (sessions, endpoints, rejected) = {
                    let clients = stats_clients.lock().unwrap();
                    clients.values().fold((0, 0, 0), |totals, client| {
                        client.sessions.values().fold(totals, |(s, e, r), session| {
                            (s + 1, e + session.endpoints.len(), r + session.rejected_frames)
                        })
                    })
                };
                // Only speak up when something changed, so an idle relay stays
                // quiet in the journal.
                if rejected != reported || sessions > 0 {
                    gamepath_engine::log_info!(
                        "sessions={sessions} endpoints={endpoints} rejected_frames={rejected} \
                         (+{} since last report)",
                        rejected.saturating_sub(reported)
                    );
                    reported = rejected;
                }
            }
        })?;
    let tun_writer = Arc::clone(&tun);
    let reply_socket = Arc::clone(&socket);
    let reply_clients = Arc::clone(&clients);
    thread::Builder::new()
        .name("gamepath-tun-replies".into())
        .spawn(move || {
            let mut packet = [0_u8; MAX_PACKET];
            loop {
                match tun.recv(&mut packet) {
                    Ok(length) => forward_reply(&reply_socket, &reply_clients, &packet[..length]),
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
        if ipv4_source(&plaintext) != Some(virtual_ipv4) {
            continue;
        }
        if let Err(error) = tun_writer.send(&plaintext) {
            gamepath_engine::log_error!("TUN send failed: {error}");
        }
    }
}

fn forward_reply(
    socket: &UdpSocket,
    clients: &Mutex<HashMap<[u8; 16], RelayClient>>,
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
    let now = Instant::now();
    session
        .endpoints
        .retain(|(_, seen)| now.duration_since(*seen) <= ENDPOINT_TTL);
    if session.endpoints.is_empty() {
        return;
    }
    session.outbound_sequence = session.outbound_sequence.wrapping_add(1);
    let header = FrameHeader {
        flags: FLAG_SERVER_TO_CLIENT,
        client_id: client.client_id,
        session_id,
        sequence: session.outbound_sequence,
    };
    let Ok(crypto) = SessionCrypto::new(&client.key, session_id) else {
        return;
    };
    let Ok(frame) = crypto.seal_server(header, packet) else {
        return;
    };
    for (endpoint, _) in &session.endpoints {
        let _ = socket.send_to(&frame, endpoint);
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
