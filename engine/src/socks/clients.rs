//! What each device using the proxy has done this session, keyed by its LAN
//! address: the numbers behind "connected devices" and per-device usage.

use serde::Serialize;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A device with nothing open still counts as connected for this long, so a
/// console between matches does not flicker off the list.
const CONNECTED_GRACE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClientUsage {
    pub(crate) address: String,
    pub(crate) active_tcp: u32,
    pub(crate) active_udp: u32,
    pub(crate) total_connections: u64,
    pub(crate) failed_connections: u64,
    /// From the device towards the Internet.
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) first_seen_at: u64,
    pub(crate) last_active_at: u64,
    pub(crate) connected: bool,
}

#[derive(Default)]
pub(crate) struct ClientBook {
    clients: BTreeMap<Ipv4Addr, ClientUsage>,
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl ClientBook {
    pub(crate) fn entry(&mut self, address: Ipv4Addr) -> &mut ClientUsage {
        let now = unix_millis();
        let client = self.clients.entry(address).or_insert_with(|| ClientUsage {
            address: address.to_string(),
            first_seen_at: now,
            ..ClientUsage::default()
        });
        client.last_active_at = now;
        client
    }

    pub(crate) fn active_tcp(&self, address: Ipv4Addr) -> u32 {
        self.clients
            .get(&address)
            .map_or(0, |client| client.active_tcp)
    }

    pub(crate) fn snapshot(&self) -> Vec<ClientUsage> {
        let cutoff = unix_millis().saturating_sub(CONNECTED_GRACE.as_millis() as u64);
        self.clients
            .values()
            .map(|client| ClientUsage {
                connected: client.active_tcp > 0
                    || client.active_udp > 0
                    || client.last_active_at >= cutoff,
                ..client.clone()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_is_listed_once_and_stays_connected_while_it_has_flows() {
        let mut book = ClientBook::default();
        let console = Ipv4Addr::new(192, 168, 1, 40);
        book.entry(console).total_connections += 1;
        book.entry(console).active_udp += 1;
        book.entry(console).bytes_sent += 100;
        let snapshot = book.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].connected);
        assert_eq!(snapshot[0].bytes_sent, 100);
        assert_eq!(snapshot[0].total_connections, 1);
    }
}
