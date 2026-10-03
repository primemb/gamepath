//! Recognises the local SOCKS5 proxy's own process, so its name lookups are
//! never redirected into the proxy itself.
//!
//! A proxy client such as Throne (sing-box) resolves its upstream server with
//! the machine's DNS servers, sending the queries from its own process. Remote
//! DNS redirects every lookup to the router into the tunnel, which is the
//! proxy; so the proxy asked itself for its own server's address. With fake IP
//! on it answered with a fake address only it can reach, and everything going
//! through it stopped. Observed: Throne restarted while the VPN was on, looked
//! up `engage.cloudflareclient.com` (its WARP upstream), got `198.18.0.3`, and
//! no connection through it opened again.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_LISTENER;

/// How long a port's owner is trusted before it is looked up again. Ports are
/// reused, so this stays short; lookups are rare enough that it costs little.
const OWNER_TTL: Duration = Duration::from_secs(2);
/// How often the proxy's process is looked for again, since restarting the
/// proxy can change which process listens.
const PROCESS_TTL: Duration = Duration::from_secs(5);
pub(crate) struct ProxyIdentity {
    port: u16,
    /// The process listening on the proxy port, and when that was checked.
    /// Compared by id, so a lookup never has to open a process.
    process: Mutex<(Option<u32>, Option<Instant>)>,
    owners: Mutex<HashMap<u16, (bool, Instant)>>,
}

impl ProxyIdentity {
    /// Only a proxy on this machine has a process to recognise.
    pub(crate) fn for_endpoint(endpoint: SocketAddr) -> Option<Self> {
        endpoint.ip().is_loopback().then(|| Self {
            port: endpoint.port(),
            process: Mutex::new((None, None)),
            owners: Mutex::new(HashMap::new()),
        })
    }

    /// The proxy's process id, looked up again every [`PROCESS_TTL`].
    fn process_id(&self) -> Option<u32> {
        let mut process = self.process.lock().unwrap();
        if process.1.is_none_or(|at| at.elapsed() >= PROCESS_TTL) {
            let found = listener_owner(self.port);
            if let Some(id) = found.filter(|id| Some(*id) != process.0) {
                gamepath_engine::log_info!(
                    "the SOCKS5 proxy on port {} is {} (pid {id}); its own name lookups are never redirected",
                    self.port,
                    crate::split_capture::process_path(id).unwrap_or_default()
                );
            }
            *process = (found, Some(Instant::now()));
        }
        process.0
    }

    /// Whether the UDP socket on `local_port` belongs to the proxy's process.
    pub(crate) fn owns_udp_port(&self, local_port: u16) -> bool {
        if let Some((owned, at)) = self.owners.lock().unwrap().get(&local_port) {
            if at.elapsed() < OWNER_TTL {
                return *owned;
            }
        }
        let owned = self
            .process_id()
            .is_some_and(|proxy| udp_owner(local_port) == Some(proxy));
        let mut owners = self.owners.lock().unwrap();
        owners.retain(|_, (_, at)| at.elapsed() < OWNER_TTL);
        owners.insert(local_port, (owned, Instant::now()));
        owned
    }
}

/// The process listening for TCP on `port`, on loopback or every address.
fn listener_owner(port: u16) -> Option<u32> {
    crate::socket_table::tcp_rows(TCP_TABLE_OWNER_PID_LISTENER)?
        .into_iter()
        .find(|row| crate::split_capture::port_from_dword(row.dwLocalPort) == port)
        .map(|row| row.dwOwningPid)
}

/// The process owning the UDP socket on `port`.
pub(crate) fn udp_owner(port: u16) -> Option<u32> {
    crate::socket_table::udp_rows()?
        .into_iter()
        .find(|row| crate::split_capture::port_from_dword(row.dwLocalPort) == port)
        .map(|row| row.dwOwningPid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    /// This test process plays the proxy: it listens, and owns a UDP socket.
    #[test]
    fn the_proxys_own_sockets_are_recognised_and_others_are_not() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let identity = ProxyIdentity::for_endpoint(listener.local_addr().unwrap()).unwrap();
        let own = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(identity.owns_udp_port(own.local_addr().unwrap().port()));
        // A port nothing has open has no owner to match.
        let unused = {
            let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        assert!(!identity.owns_udp_port(unused));
    }

    #[test]
    fn only_a_proxy_on_this_machine_has_a_process() {
        assert!(ProxyIdentity::for_endpoint("203.0.113.5:1080".parse().unwrap()).is_none());
    }
}
