//! Where the stack's connections leave: through a SOCKS5 proxy, or straight
//! out of another VPN app's adapter.

use crate::vpn_adapter::{Adapter, find, pinned_socket};
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

pub(crate) enum Exit {
    Proxy {
        address: SocketAddr,
        credentials: Option<(String, String)>,
    },
    Adapter(AdapterExit),
}

impl Exit {
    pub(crate) fn is_proxy(&self) -> bool {
        matches!(self, Self::Proxy { .. })
    }

    /// How the loop's own log lines name it.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Proxy { .. } => "SOCKS5",
            Self::Adapter(_) => "adapter",
        }
    }
}

pub(crate) struct AdapterExit {
    wanted: String,
    current: Adapter,
}

impl AdapterExit {
    pub(crate) fn new(wanted: &str, current: Adapter) -> Self {
        Self {
            wanted: wanted.trim().to_owned(),
            current,
        }
    }

    pub(crate) fn adapter(&self) -> &Adapter {
        &self.current
    }

    /// A socket pinned to the adapter, claimed as the stack's own.
    ///
    /// An app that reconnects takes its old address with it, so a bind that
    /// fails looks the adapter up again once before giving up. That keeps the
    /// node working across the app's reconnects without a redial of its own.
    pub(crate) fn socket(
        &mut self,
        kind: socket2::Type,
    ) -> Result<(socket2::Socket, Claim), String> {
        let socket = match pinned_socket(&self.current, kind) {
            Ok(socket) => socket,
            Err(first) => {
                let fresh = find(&self.wanted).map_err(|_| {
                    format!("could not open a socket on {}: {first}", self.current.name)
                })?;
                if fresh != self.current {
                    crate::log_info!(
                        "the adapter for \"{}\" is now {} ({})",
                        self.wanted,
                        fresh.name,
                        fresh.address
                    );
                    self.current = fresh;
                }
                pinned_socket(&self.current, kind).map_err(|error| {
                    format!("could not open a socket on {}: {error}", self.current.name)
                })?
            }
        };
        socket
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let protocol = if kind == socket2::Type::STREAM { 6 } else { 17 };
        let local = socket
            .local_addr()
            .ok()
            .and_then(|address| address.as_socket_ipv4())
            .ok_or("the adapter socket has no IPv4 address")?;
        Ok((socket, Claim::new(protocol, local)))
    }
}

/// Sockets the adapter exit has open, by protocol and local address, with when
/// each was closed.
///
/// Capture sees their packets like any application's, and a website or IP
/// rule naming the destination would select them back into the stack that
/// sent them. Recognised by exact address and port, they are left alone, and
/// nothing else is: Windows hands out each local address and port to one
/// socket at a time. Only a socket given a just-released pair inside the
/// linger can be mistaken for the exit's, and being bound to the adapter, it
/// already leaves through that VPN.
static EXIT_SOCKETS: LazyLock<RwLock<ClaimTable>> = LazyLock::new(|| RwLock::new(HashMap::new()));

/// Protocol and local address, to when the socket was closed (`None` while open).
type ClaimTable = HashMap<(u8, SocketAddrV4), Option<Instant>>;

/// How long a socket still counts as the exit's once it is closed. Its FIN or
/// reset leaves after the socket is gone, and capture sees it on another
/// thread later still; a TIME_WAIT acknowledgement can follow for as long as
/// Windows holds that state, at most 240 s.
const RELEASED_LINGER: Duration = Duration::from_secs(240);
/// Released entries are swept once the table holds this many.
const SWEEP_AT: usize = 1024;
/// Set by the first claim. Capture asks about every packet it sees, and a
/// process with no adapter node (the game engine, always) answers from this
/// alone instead of taking the lock.
static EVER_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Whether a packet from `source` was sent by an adapter exit in this process.
pub fn is_exit_socket(protocol: u8, source: SocketAddrV4) -> bool {
    EVER_CLAIMED.load(Ordering::Relaxed)
        && EXIT_SOCKETS
            .read()
            .unwrap()
            .get(&(protocol, source))
            .is_some_and(|released| still_counts(*released))
}

fn still_counts(released: Option<Instant>) -> bool {
    released.is_none_or(|at| at.elapsed() < RELEASED_LINGER)
}

/// One entry in [`EXIT_SOCKETS`], released when the socket's owner drops it.
pub(crate) struct Claim(u8, SocketAddrV4);

impl Claim {
    fn new(protocol: u8, local: SocketAddrV4) -> Self {
        let mut sockets = EXIT_SOCKETS.write().unwrap();
        if sockets.len() >= SWEEP_AT {
            sockets.retain(|_, released| still_counts(*released));
        }
        sockets.insert((protocol, local), None);
        EVER_CLAIMED.store(true, Ordering::Relaxed);
        Self(protocol, local)
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(released) = EXIT_SOCKETS.write().unwrap().get_mut(&(self.0, self.1)) {
            *released = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_claim_lasts_as_long_as_its_socket_and_its_last_packets() {
        let local = SocketAddrV4::new(Ipv4Addr::new(10, 141, 184, 93), 58_944);
        assert!(!is_exit_socket(17, local));
        let claim = Claim::new(17, local);
        assert!(is_exit_socket(17, local));
        // The same port over the other protocol, or on another address, is
        // somebody else's.
        assert!(!is_exit_socket(6, local));
        assert!(!is_exit_socket(
            17,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 58_944)
        ));
        // The closed socket's FIN can still be on its way to capture.
        drop(claim);
        assert!(is_exit_socket(17, local));
        assert!(still_counts(None));
        if let Some(long_ago) = Instant::now().checked_sub(RELEASED_LINGER) {
            assert!(!still_counts(Some(long_ago)));
        }
    }
}
