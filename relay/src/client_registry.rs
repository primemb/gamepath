use super::{ClientRecord, RelayClient};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const RELOAD_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CLIENTS: usize = 253;
const MAX_RECORD_BYTES: u64 = 4096;

pub(super) fn read_records(directory: &Path) -> io::Result<Vec<ClientRecord>> {
    Ok(read_record_files(directory)?
        .into_iter()
        .map(|(_, record)| record)
        .collect())
}

fn read_record_files(directory: &Path) -> io::Result<Vec<(PathBuf, ClientRecord)>> {
    let mut records = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if records.len() >= MAX_CLIENTS {
            return Err(invalid("too many enrolled clients"));
        }
        let mut source = Vec::new();
        fs::File::open(&path)?
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut source)?;
        if source.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("client record is too large"));
        }
        // A serde error can quote a malformed secret field; keep it out of the journal.
        let record =
            serde_json::from_slice(&source).map_err(|_| invalid("invalid client record JSON"))?;
        records.push((path, record));
    }
    Ok(records)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClientAccess {
    pub(super) client_id: String,
    pub(super) name: String,
    pub(super) virtual_ipv4: std::net::Ipv4Addr,
}

pub(super) fn list_access(directory: &Path) -> io::Result<Vec<ClientAccess>> {
    let clients = load_clients(directory)?;
    let mut result = clients
        .into_values()
        .map(|client| ClientAccess {
            client_id: client.record.client_id,
            name: client.record.name,
            virtual_ipv4: client.record.virtual_ipv4,
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.client_id.cmp(&b.client_id))
    });
    Ok(result)
}

pub(super) fn revoke_access(directory: &Path, client_id: &str) -> io::Result<Vec<ClientAccess>> {
    let files = read_record_files(directory)?;
    validate_records(files.iter().map(|(_, record)| record.clone()).collect())?;
    let (path, record) = files
        .iter()
        .find(|(_, record)| record.client_id == client_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "client access no longer exists"))?;
    // Linux conntrack can keep old NAT mappings after revocation. Never hand that
    // source address to a different client, which could receive the old replies.
    let reserved = reserved_addresses(directory)?;
    if !reserved.contains(&record.virtual_ipv4) {
        write_secret(
            &directory.join(format!("{}.revoked", record.virtual_ipv4)),
            &serde_json::to_vec(&record.virtual_ipv4).map_err(io::Error::other)?,
            true,
        )?;
    }
    // Resolve only an exact enrolled ID to its record, never a caller-supplied path or name.
    fs::remove_file(path)?;
    list_access(directory)
}

pub(super) fn reserved_addresses(directory: &Path) -> io::Result<HashSet<std::net::Ipv4Addr>> {
    let mut reserved = HashSet::new();
    let mut count = 0;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("revoked") {
            continue;
        }
        count += 1;
        if count > MAX_CLIENTS {
            return Err(invalid("too many reserved client addresses"));
        }
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(33).read_to_end(&mut bytes)?;
        let address: std::net::Ipv4Addr = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid reserved client address"))?;
        if address.octets()[..3] != [10, 203, 0] || !(2..=254).contains(&address.octets()[3]) {
            return Err(invalid("invalid reserved client address"));
        }
        reserved.insert(address);
    }
    Ok(reserved)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn load_clients(directory: &Path) -> io::Result<HashMap<[u8; 16], RelayClient>> {
    validate_records(read_records(directory)?)
}

fn validate_records(records: Vec<ClientRecord>) -> io::Result<HashMap<[u8; 16], RelayClient>> {
    let mut clients = HashMap::new();
    let mut addresses = HashSet::new();
    for record in records {
        let (client_id, key) = record.token().material().map_err(io::Error::other)?;
        let address = record.virtual_ipv4.octets();
        if address[..3] != [10, 203, 0] || !(2..=254).contains(&address[3]) {
            return Err(invalid("client address must be in 10.203.0.2-254"));
        }
        if clients.contains_key(&client_id) || !addresses.insert(record.virtual_ipv4) {
            return Err(invalid("duplicate client ID or virtual address"));
        }
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
    Ok(clients)
}

fn reconcile_clients(
    active: &mut HashMap<[u8; 16], RelayClient>,
    next: HashMap<[u8; 16], RelayClient>,
) -> bool {
    let mut changed = false;
    active.retain(|id, _| {
        let keep = next.contains_key(id);
        changed |= !keep;
        keep
    });
    for (id, client) in next {
        match active.get_mut(&id) {
            Some(current)
                if current.key == client.key
                    && current.record.virtual_ipv4 == client.record.virtual_ipv4 =>
            {
                // Keep sequence counters, replay windows, endpoints and repair buffers intact.
                current.record = client.record;
            }
            _ => {
                active.insert(id, client);
                changed = true;
            }
        }
    }
    changed
}

fn refresh_clients(
    directory: &Path,
    clients: &Mutex<HashMap<[u8; 16], RelayClient>>,
) -> io::Result<Option<usize>> {
    let next = load_clients(directory)?;
    let mut active = clients.lock().unwrap();
    Ok(reconcile_clients(&mut active, next).then_some(active.len()))
}

pub(super) fn start_reload(
    directory: &Path,
    clients: Arc<Mutex<HashMap<[u8; 16], RelayClient>>>,
) -> io::Result<()> {
    let directory = directory.to_owned();
    thread::Builder::new()
        .name("gamepath-client-reload".into())
        .spawn(move || {
            let mut failed = false;
            loop {
                thread::sleep(RELOAD_INTERVAL);
                // All disk reads, parsing and key validation happen off the packet lock.
                match refresh_clients(&directory, &clients) {
                    Ok(changed) => {
                        if let Some(count) = changed {
                            gamepath_engine::log_info!(
                                "client registry updated: {count} enrolled client(s)"
                            );
                        }
                        if failed {
                            gamepath_engine::log_info!("client registry reload recovered");
                            failed = false;
                        }
                    }
                    Err(error) => {
                        if !failed {
                            gamepath_engine::log_warn!(
                                "client registry reload failed; keeping active clients: {error}"
                            );
                            failed = true;
                        }
                    }
                }
            }
        })?;
    Ok(())
}

pub(super) fn write_secret(path: &Path, contents: &[u8], create_only: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".gamepath-{}-{}.tmp",
        std::process::id(),
        super::fresh_outbound_sequence()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        // Readers see the full record or no record. A duplicate name never replaces a client.
        if create_only {
            fs::hard_link(&temporary, path)
        } else {
            fs::rename(&temporary, path)
        }
    })();
    let _ = fs::remove_file(&temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionState;
    use gamepath_engine::auth::EnrollmentToken;
    use std::net::Ipv4Addr;

    fn record(ip: u8) -> ClientRecord {
        let token = EnrollmentToken::generate(Ipv4Addr::new(10, 203, 0, ip));
        ClientRecord {
            name: format!("client-{ip}"),
            version: token.version,
            client_id: token.client_id,
            pre_shared_key: token.pre_shared_key,
            virtual_ipv4: token.virtual_ipv4,
        }
    }

    #[test]
    fn adding_clients_preserves_active_session_crypto_replay_paths_and_repairs() {
        let owner = record(2);
        let id = owner.token().material().unwrap().0;
        let mut active = validate_records(vec![owner.clone()]).unwrap();
        let session = active
            .get_mut(&id)
            .unwrap()
            .sessions
            .entry(42)
            .or_insert_with(SessionState::new);
        session.outbound_sequence = 555;
        session.replay.accept(123);
        session.observe_endpoint("127.0.0.1:44000".parse().unwrap());
        session.repair = Some(crate::RepairState::new(gamepath_engine::fec::Offer {
            group_size: 4,
            mtu: 1280,
        }));
        assert!(reconcile_clients(
            &mut active,
            validate_records(vec![owner, record(3), record(4)]).unwrap()
        ));
        let session = &mut active.get_mut(&id).unwrap().sessions.get_mut(&42).unwrap();
        assert_eq!(session.outbound_sequence, 555);
        assert!(!session.replay.accept(123));
        assert_eq!(session.endpoints.len(), 1);
        assert!(session.repair.is_some());
        assert_eq!(active.len(), 3);
    }

    #[test]
    fn revocation_and_key_or_address_changes_affect_only_the_changed_client() {
        let a = record(2);
        let b = record(3);
        let a_id = a.token().material().unwrap().0;
        let b_id = b.token().material().unwrap().0;
        let mut active = validate_records(vec![a.clone(), b.clone()]).unwrap();
        for client in active.values_mut() {
            client.sessions.insert(42, SessionState::new());
        }
        let mut changed = a.clone();
        changed.pre_shared_key = record(4).pre_shared_key;
        reconcile_clients(
            &mut active,
            validate_records(vec![changed, b.clone()]).unwrap(),
        );
        assert!(active[&a_id].sessions.is_empty());
        assert_eq!(active[&b_id].sessions.len(), 1);
        active
            .get_mut(&a_id)
            .unwrap()
            .sessions
            .insert(43, SessionState::new());
        let mut moved = a;
        moved.virtual_ipv4 = Ipv4Addr::new(10, 203, 0, 4);
        moved.pre_shared_key = active[&a_id].record.pre_shared_key.clone();
        reconcile_clients(
            &mut active,
            validate_records(vec![moved, b.clone()]).unwrap(),
        );
        assert!(active[&a_id].sessions.is_empty());
        assert_eq!(active[&b_id].sessions.len(), 1);
        reconcile_clients(&mut active, validate_records(vec![b]).unwrap());
        assert!(!active.contains_key(&a_id));
        assert_eq!(active[&b_id].sessions.len(), 1);
    }

    #[test]
    fn a_bad_snapshot_cannot_partially_apply_clients_or_ambiguous_addresses() {
        let a = record(2);
        let mut duplicate_id = record(3);
        duplicate_id.client_id = a.client_id.clone();
        assert!(validate_records(vec![a.clone(), duplicate_id]).is_err());
        assert!(validate_records(vec![a.clone(), record(2)]).is_err());
        let mut bad = record(3);
        bad.pre_shared_key = "invalid".into();
        assert!(validate_records(vec![a, bad]).is_err());
        assert!(validate_records(vec![record(255)]).is_err());
    }

    struct TestDirectory(std::path::PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let record = record(2);
            let dir = std::env::temp_dir().join(format!("gamepath-registry-{}", record.client_id));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn publishing_a_record_is_complete_and_duplicate_names_do_not_overwrite() {
        let dir = TestDirectory::new();
        let path = dir.0.join("friend.json");
        let first = serde_json::to_vec(&record(2)).unwrap();
        write_secret(&path, &first, true).unwrap();
        assert_eq!(load_clients(&dir.0).unwrap().len(), 1);
        assert!(write_secret(&path, &serde_json::to_vec(&record(3)).unwrap(), true).is_err());
        assert_eq!(fs::read(&path).unwrap(), first);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn missing_directory_and_bad_json_are_errors_and_never_log_the_secret() {
        let dir = TestDirectory::new();
        assert!(load_clients(&dir.0.join("missing")).is_err());
        fs::write(dir.0.join("bad.json"), br#"{"version":"private-secret"}"#).unwrap();
        let error = read_records(&dir.0).unwrap_err().to_string();
        assert!(!error.contains("private-secret"));
        assert_eq!(error, "invalid client record JSON");
    }

    #[test]
    fn existing_game_replies_keep_their_session_and_sequence_across_disk_reload() {
        use gamepath_engine::auth::SessionCrypto;
        use std::net::UdpSocket;
        use std::sync::Condvar;

        let dir = TestDirectory::new();
        let owner = record(2);
        write_secret(
            &dir.0.join("owner.json"),
            &serde_json::to_vec(&owner).unwrap(),
            true,
        )
        .unwrap();
        let (id, key) = owner.token().material().unwrap();
        let clients = Mutex::new(load_clients(&dir.0).unwrap());
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let crypto = SessionCrypto::new(&key, 42).unwrap();
        {
            let mut active = clients.lock().unwrap();
            let session = active
                .get_mut(&id)
                .unwrap()
                .admit_session(42, std::time::Instant::now());
            session.observe_endpoint(receiver.local_addr().unwrap());
            session.outbound_sequence = 900;
        }
        let mut packet = [0_u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&owner.virtual_ipv4.octets());
        let reply = || {
            crate::forward_reply(&sender, &clients, &Condvar::new(), &packet);
            let mut bytes = [0_u8; 2048];
            let length = receiver.recv(&mut bytes).unwrap();
            let (header, plaintext) = crypto.open_server(&bytes[..length]).unwrap();
            assert_eq!(header.session_id, 42);
            assert_eq!(plaintext, packet);
            header.sequence
        };
        let first = reply();
        write_secret(
            &dir.0.join("friend.json"),
            &serde_json::to_vec(&record(3)).unwrap(),
            true,
        )
        .unwrap();
        assert_eq!(refresh_clients(&dir.0, &clients).unwrap(), Some(2));
        assert_eq!(reply(), first + 1);
        fs::write(dir.0.join("bad.json"), b"unfinished record").unwrap();
        assert!(refresh_clients(&dir.0, &clients).is_err());
        assert_eq!(reply(), first + 2);
        fs::remove_file(dir.0.join("bad.json")).unwrap();
        let friend_id = list_access(&dir.0)
            .unwrap()
            .into_iter()
            .find(|client| client.virtual_ipv4 == Ipv4Addr::new(10, 203, 0, 3))
            .unwrap()
            .client_id;
        revoke_access(&dir.0, &friend_id).unwrap();
        assert_eq!(refresh_clients(&dir.0, &clients).unwrap(), Some(1));
        assert_eq!(reply(), first + 3);
    }

    #[test]
    fn access_listing_never_contains_client_secrets() {
        let dir = TestDirectory::new();
        let owner = record(2);
        write_secret(
            &dir.0.join("owner.json"),
            &serde_json::to_vec(&owner).unwrap(),
            true,
        )
        .unwrap();
        let listed = serde_json::to_string(&list_access(&dir.0).unwrap()).unwrap();
        assert!(listed.contains(&owner.client_id));
        assert!(!listed.contains(&owner.pre_shared_key));
        assert!(!listed.contains("preSharedKey"));
    }

    #[test]
    fn revoking_an_exact_id_keeps_other_access_and_reserves_the_address() {
        let dir = TestDirectory::new();
        let owner = record(2);
        let friend = record(3);
        for (name, record) in [("owner.json", &owner), ("friend.json", &friend)] {
            write_secret(
                &dir.0.join(name),
                &serde_json::to_vec(record).unwrap(),
                true,
            )
            .unwrap();
        }
        assert!(revoke_access(&dir.0, "../owner.json").is_err());
        assert_eq!(list_access(&dir.0).unwrap().len(), 2);
        let remaining = revoke_access(&dir.0, &friend.client_id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].client_id, owner.client_id);
        assert!(
            reserved_addresses(&dir.0)
                .unwrap()
                .contains(&friend.virtual_ipv4)
        );
        assert_eq!(
            crate::next_virtual_ip(
                &read_records(&dir.0).unwrap(),
                &reserved_addresses(&dir.0).unwrap()
            )
            .unwrap(),
            Ipv4Addr::new(10, 203, 0, 4)
        );
        assert!(revoke_access(&dir.0, &friend.client_id).is_err());
    }
}
