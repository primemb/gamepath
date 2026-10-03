use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const BYPASS_TTL: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(crate) struct UdpClassifier {
    bypassed: HashMap<(Ipv4Addr, u16), Instant>,
}

impl UdpClassifier {
    pub(crate) fn selected_owner(
        &mut self,
        source: Ipv4Addr,
        port: u16,
        selected_path: impl Fn(u32) -> Option<String>,
    ) -> Option<(u32, String)> {
        let now = Instant::now();
        let key = (source, port);
        if self
            .bypassed
            .get(&key)
            .is_some_and(|at| now.duration_since(*at) < BYPASS_TTL)
        {
            return None;
        }
        let rows = crate::socket_table::udp_rows()?;
        let mut found = false;
        for row in rows {
            let bound = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            if u16::from_be(row.dwLocalPort as u16) != port
                || (!bound.is_unspecified() && bound != source)
            {
                continue;
            }
            found = true;
            if let Some(path) = selected_path(row.dwOwningPid) {
                return Some((row.dwOwningPid, path));
            }
        }
        // Cache only a known unselected owner. A missing inventory or socket
        // is uncertainty, and must not hide a newly created selected socket.
        if found {
            self.bypassed
                .retain(|_, at| now.duration_since(*at) < BYPASS_TTL);
            self.bypassed.insert(key, now);
        }
        None
    }

    pub(crate) fn socket_changed(&mut self, port: u16) {
        self.bypassed.retain(|(_, held), _| *held != port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::net::UdpSocket;

    fn selected_path(pid: u32) -> Option<String> {
        (pid == std::process::id()).then(|| "selected.exe".into())
    }

    #[test]
    fn the_first_datagram_has_an_owner_before_any_socket_notification() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let mut classifier = UdpClassifier::default();
        assert_eq!(
            classifier.selected_owner(
                Ipv4Addr::new(192, 0, 2, 1),
                socket.local_addr().unwrap().port(),
                selected_path,
            ),
            Some((std::process::id(), "selected.exe".into()))
        );
    }

    #[test]
    fn an_unselected_socket_does_not_query_its_owner_for_every_datagram() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let mut classifier = UdpClassifier::default();
        let calls = Cell::new(0);
        for _ in 0..10 {
            assert!(
                classifier
                    .selected_owner(Ipv4Addr::LOCALHOST, port, |_| {
                        calls.set(calls.get() + 1);
                        None
                    })
                    .is_none()
            );
        }
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_socket_event_invalidates_a_cached_bypass_before_port_reuse() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        let mut classifier = UdpClassifier::default();
        assert!(
            classifier
                .selected_owner(Ipv4Addr::LOCALHOST, port, |_| None)
                .is_none()
        );
        classifier.socket_changed(port);
        assert!(
            classifier
                .selected_owner(Ipv4Addr::LOCALHOST, port, selected_path)
                .is_some()
        );
    }

    #[test]
    fn a_socket_on_another_local_address_cannot_select_the_packet() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(
            UdpClassifier::default()
                .selected_owner(
                    Ipv4Addr::new(192, 0, 2, 1),
                    socket.local_addr().unwrap().port(),
                    selected_path,
                )
                .is_none()
        );
    }
}
