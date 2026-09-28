//! A SOCKS5 and HTTP proxy on the local network that carries everything it
//! is given through the running session.
//!
//! This is how a device that cannot run GamePath - a console, a phone, a
//! second PC - uses the tunnel: point its proxy setting at this PC. Its
//! connections, UDP datagrams and name lookups all go through the session,
//! and none of them depend on split-tunnel rules, because they never pass
//! through capture at all. See [`tunnel_egress`] for how.

mod clients;
mod egress;
mod firewall;
mod interface_egress;
mod resolver;
mod server;
mod tunnel_egress;
mod wire;

use crate::session::WireGuardSessionManager;
use gamepath_engine::log_info;
use serde::Deserialize;
use serde_json::{Value, json};
use server::{Server, ServerStatus, WAKER};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub(crate) const DEFAULT_PORT: u16 = 1080;
/// Ports tried after the requested one, so another program holding it moves
/// the proxy rather than failing the feature.
const PORT_ATTEMPTS: u16 = 20;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartRequest {
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    egress: EgressRequest,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

#[derive(Debug, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum EgressRequest {
    /// Through the session this engine runs.
    #[default]
    Session,
    /// Out of a Windows adapter, for native L2TP/IPsec.
    #[serde(rename_all = "camelCase")]
    Interface {
        address: Ipv4Addr,
        interface_index: u32,
    },
}

struct Running {
    stop: Arc<AtomicBool>,
    waker: Arc<mio::Waker>,
    thread: Option<JoinHandle<()>>,
    status: Arc<Mutex<ServerStatus>>,
    port: u16,
    requested_port: u16,
    authenticated: bool,
    egress: &'static str,
    started_at: u64,
}

#[derive(Default)]
pub(crate) struct SocksServerManager {
    active: Option<Running>,
}

impl SocksServerManager {
    /// Starts the proxy, replacing one already running.
    ///
    /// Must not be called with the session manager locked: the tunnel egress
    /// locks it to read the session, and its thread locks it for every packet.
    pub(crate) fn start(
        &mut self,
        payload: Value,
        sessions: &Arc<Mutex<WireGuardSessionManager>>,
    ) -> Result<Value, String> {
        let input: StartRequest = serde_json::from_value(payload)
            .map_err(|error| format!("invalid LAN proxy request: {error}"))?;
        self.stop();
        let credentials = match (input.username, input.password) {
            (Some(user), Some(password)) if !user.is_empty() => Some((user, password)),
            _ => None,
        };
        let poll = mio::Poll::new().map_err(|error| error.to_string())?;
        let waker =
            Arc::new(mio::Waker::new(poll.registry(), WAKER).map_err(|error| error.to_string())?);
        let egress: Box<dyn egress::Egress> = match input.egress {
            EgressRequest::Session => {
                let binding = sessions
                    .lock()
                    .unwrap()
                    .local_stack_binding()
                    .ok_or("start the session before the LAN proxy")?;
                Box::new(tunnel_egress::TunnelEgress::new(
                    binding,
                    Box::new(Arc::clone(sessions)),
                    Arc::clone(&waker),
                ))
            }
            EgressRequest::Interface {
                address,
                interface_index,
            } => Box::new(interface_egress::InterfaceEgress::new(
                poll.registry()
                    .try_clone()
                    .map_err(|error| error.to_string())?,
                address,
                interface_index,
            )),
        };
        let egress_kind = egress.kind();
        let (listener, udp) = bind(input.port)?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(ServerStatus::default()));
        let server = Server::new(
            poll,
            listener,
            udp,
            egress,
            credentials.clone(),
            Arc::clone(&stop),
            Arc::clone(&status),
        )
        .map_err(|error| format!("could not start the LAN proxy: {error}"))?;
        let thread = std::thread::Builder::new()
            .name("gamepath-lan-proxy".into())
            .spawn(move || server.run())
            .map_err(|error| format!("could not start the LAN proxy: {error}"))?;
        firewall::allow_inbound();
        log_info!(
            "LAN proxy listening on port {port} through the {egress_kind}, {}",
            if credentials.is_some() {
                "login required"
            } else {
                "no login"
            }
        );
        self.active = Some(Running {
            stop,
            waker,
            thread: Some(thread),
            status,
            port,
            requested_port: input.port,
            authenticated: credentials.is_some(),
            egress: egress_kind,
            started_at: clients::unix_millis(),
        });
        Ok(self.status())
    }

    pub(crate) fn status(&self) -> Value {
        let Some(running) = &self.active else {
            return json!({ "state": "stopped" });
        };
        let finished = running.thread.as_ref().is_none_or(JoinHandle::is_finished);
        let mut status =
            serde_json::to_value(&*running.status.lock().unwrap()).unwrap_or_else(|_| json!({}));
        status["state"] = json!(if finished { "error" } else { "listening" });
        if finished {
            status["error"] = json!("the LAN proxy stopped unexpectedly");
        }
        status["port"] = json!(running.port);
        status["requestedPort"] = json!(running.requested_port);
        status["authRequired"] = json!(running.authenticated);
        status["egress"] = json!(running.egress);
        status["startedAt"] = json!(running.started_at);
        status["addresses"] = json!(gamepath_engine::netconfig::lan_ipv4_addresses());
        status
    }

    pub(crate) fn stop(&mut self) -> Value {
        if let Some(mut running) = self.active.take() {
            running.stop.store(true, Ordering::Release);
            let _ = running.waker.wake();
            if let Some(thread) = running.thread.take() {
                let _ = thread.join();
            }
        }
        json!({ "state": "stopped" })
    }
}

impl Drop for SocksServerManager {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The TCP listener and UDP relay socket on one port, so a client setting
/// needs a single number and a firewall needs a single rule.
fn bind(requested: u16) -> Result<(mio::net::TcpListener, mio::net::UdpSocket), String> {
    let requested = if requested == 0 {
        DEFAULT_PORT
    } else {
        requested
    };
    let mut last_error = String::new();
    for port in (0..PORT_ATTEMPTS).filter_map(|offset| requested.checked_add(offset)) {
        let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let listener = match std::net::TcpListener::bind(address) {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                continue;
            }
        };
        let udp = match std::net::UdpSocket::bind(address) {
            Ok(udp) => udp,
            Err(error) => {
                last_error = error.to_string();
                continue;
            }
        };
        listener
            .set_nonblocking(true)
            .and_then(|_| udp.set_nonblocking(true))
            .map_err(|error| error.to_string())?;
        return Ok((
            mio::net::TcpListener::from_std(listener),
            mio::net::UdpSocket::from_std(udp),
        ));
    }
    Err(format!(
        "no port from {requested} to {} was free for the LAN proxy: {last_error}",
        requested.saturating_add(PORT_ATTEMPTS - 1)
    ))
}
