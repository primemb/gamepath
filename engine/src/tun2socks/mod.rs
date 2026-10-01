//! A SOCKS5 proxy as the single hop of a direct session.
//!
//! A proxy speaks in connections and datagrams, not packets, so it cannot be
//! handed captured traffic the way a WireGuard or OpenVPN server can. This
//! puts a small TCP/IP stack in front of it: captured packets are answered
//! here and their contents replayed through the proxy, and the proxy's
//! answers are turned back into packets. To the session above, it is one more
//! path that takes and returns IPv4 packets.
//!
//! Only the VPN uses this. Game traffic is UDP that has to reach its server
//! as sent, with its timing intact, which re-originating it would not keep.

mod handshake;
mod packet;
mod stack;

use crate::socks5::{Socks5NodeConfig, negotiate_method, resolve_proxy};
use stack::{Shared, Stack, StackConfig, WAKER};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The address captured packets are rewritten to come from. A private /24 of
/// its own, apart from the relay's `10.203.0.0/24`.
pub const CLIENT_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 207, 0, 2);
const GATEWAY_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 207, 0, 1);
/// Packets waiting for the stack, and waiting for the session. A burst
/// larger than this is dropped and recovered by TCP like any loss.
const QUEUE_LIMIT: usize = 4096;
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);
/// Terminated here, so the stack's MTU is only what the capture side sends.
const STACK_MTU: usize = 1500;

pub struct Socks5Stack {
    shared: Arc<Shared>,
    outbound: mpsc::Receiver<Vec<u8>>,
    worker: Option<JoinHandle<()>>,
    proxy: SocketAddr,
    setup_latency_ms: f64,
}

impl Socks5Stack {
    /// Checks the proxy answers and accepts the login, then starts the stack.
    pub fn open(config: &Socks5NodeConfig, probe_target: Ipv4Addr) -> Result<Self, String> {
        config.validate()?;
        let proxy = resolve_proxy(&config.host, config.port)?;
        let started = Instant::now();
        let mut control = TcpStream::connect_timeout(&proxy, SETUP_TIMEOUT)
            .map_err(|error| format!("could not reach SOCKS5 proxy {proxy}: {error}"))?;
        let _ = control.set_read_timeout(Some(SETUP_TIMEOUT));
        let _ = control.set_write_timeout(Some(SETUP_TIMEOUT));
        negotiate_method(&mut control, config)?;
        let setup_latency_ms = started.elapsed().as_secs_f64() * 1000.0;
        drop(control);

        let poll = mio::Poll::new()
            .map_err(|error| format!("could not start the SOCKS5 stack: {error}"))?;
        let waker = mio::Waker::new(poll.registry(), WAKER)
            .map_err(|error| format!("could not start the SOCKS5 stack: {error}"))?;
        let shared = Arc::new(Shared {
            inbox: Mutex::new(VecDeque::new()),
            waker,
            stop: AtomicBool::new(false),
            counters: Default::default(),
        });
        let (outbound_tx, outbound) = mpsc::sync_channel(QUEUE_LIMIT);
        let credentials = config
            .credentials()
            .map(|(username, password)| (username.to_owned(), password.to_owned()));
        let stack = Stack::new(
            StackConfig {
                client: CLIENT_ADDRESS,
                gateway: GATEWAY_ADDRESS,
                proxy,
                credentials,
                probe_target,
                mtu: STACK_MTU,
            },
            Arc::clone(&shared),
            poll,
            outbound_tx,
        );
        let worker = std::thread::Builder::new()
            .name("gamepath-socks5-stack".into())
            .spawn(move || {
                crate::thread_priority::raise_current_for_data_plane();
                stack.run();
            })
            .map_err(|error| format!("could not start the SOCKS5 stack: {error}"))?;
        crate::log_info!(
            "SOCKS5 VPN path ready through {}, login answered in {:.0} ms",
            crate::log::fingerprint(proxy.to_string().as_bytes()),
            setup_latency_ms
        );
        Ok(Self {
            shared,
            outbound,
            worker: Some(worker),
            proxy,
            setup_latency_ms,
        })
    }

    pub fn address(&self) -> Ipv4Addr {
        CLIENT_ADDRESS
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.proxy
    }

    pub fn bypass_ipv4(&self) -> Option<Ipv4Addr> {
        stack::proxy_bypass(self.proxy)
    }

    pub fn handshake_latency_ms(&self) -> Option<f64> {
        Some(self.setup_latency_ms)
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        let mut inbox = self.shared.inbox.lock().unwrap();
        if inbox.len() >= QUEUE_LIMIT {
            return Err("the SOCKS5 stack is not keeping up".into());
        }
        let was_empty = inbox.is_empty();
        inbox.push_back(packet.to_vec());
        drop(inbox);
        // The loop drains everything once woken, so only the first packet of
        // a burst has to wake it.
        if was_empty {
            let _ = self.shared.waker.wake();
        }
        Ok(())
    }

    pub fn receive_packets(&mut self, timeout: Duration) -> Result<Vec<Vec<u8>>, String> {
        let mut packets = match self.outbound.recv_timeout(timeout) {
            Ok(packet) => vec![packet],
            Err(mpsc::RecvTimeoutError::Timeout) => return Ok(Vec::new()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("the SOCKS5 stack stopped".into());
            }
        };
        packets.extend(self.outbound.try_iter().take(255));
        Ok(packets)
    }
}

/// What a proxy test measured: logging in, then opening a connection through
/// it to the open Internet.
pub struct ProbeResult {
    pub proxy: SocketAddr,
    pub setup_latency_ms: f64,
    pub connect_latency_ms: f64,
}

/// Tests a proxy the way the VPN uses it: a login, then a `CONNECT` to
/// `target`. A proxy that accepts the login but cannot reach out fails here
/// rather than after the user has turned the VPN on.
pub fn probe(
    config: &Socks5NodeConfig,
    target: std::net::SocketAddrV4,
) -> Result<ProbeResult, String> {
    use handshake::{Command, Handshake, Step};
    use std::io::{Read, Write};

    config.validate()?;
    let proxy = resolve_proxy(&config.host, config.port)?;
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&proxy, SETUP_TIMEOUT)
        .map_err(|error| format!("could not reach SOCKS5 proxy {proxy}: {error}"))?;
    let _ = stream.set_read_timeout(Some(SETUP_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SETUP_TIMEOUT));
    let credentials = config
        .credentials()
        .map(|(username, password)| (username.to_owned(), password.to_owned()));
    let (mut handshake, greeting) = Handshake::start(Command::Connect, target, credentials);
    let io = |error: std::io::Error| format!("the SOCKS5 proxy stopped answering: {error}");
    stream.write_all(&greeting).map_err(io)?;
    let mut setup_latency_ms = None;
    let mut connect_started = Instant::now();
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer).map_err(io)?;
        if read == 0 {
            return Err("the SOCKS5 proxy closed the connection".into());
        }
        match handshake.receive(&buffer[..read])? {
            Step::Send(bytes) => {
                // The request is the last thing sent; what follows is the trip out.
                if bytes.first() == Some(&5) {
                    setup_latency_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                    connect_started = Instant::now();
                }
                stream.write_all(&bytes).map_err(io)?;
            }
            Step::Wait => {}
            Step::Done { .. } => {
                return Ok(ProbeResult {
                    proxy,
                    setup_latency_ms: setup_latency_ms.unwrap_or_default(),
                    connect_latency_ms: connect_started.elapsed().as_secs_f64() * 1000.0,
                });
            }
        }
    }
}

impl Drop for Socks5Stack {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        let _ = self.shared.waker.wake();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests;
