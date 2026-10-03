//! End to end through a real proxy on loopback: an application's packets go
//! in one side, the proxy sees connections and datagrams, and the answers come
//! back out as packets.

use super::packet::{build_udp, parse_ipv4, parse_udp};
use super::*;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as StackInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::thread;

const TARGET: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const REFUSED_PORT: u16 = 9;

/// A SOCKS5 proxy that echoes TCP, answers DNS over TCP on port 53, refuses
/// `REFUSED_PORT`, and echoes UDP through an association.
fn spawn_proxy(accept_login: bool) -> SocketAddr {
    spawn_proxy_with_dns_sniff(accept_login, false)
}

fn spawn_proxy_with_dns_sniff(accept_login: bool, sniff_dns: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            thread::spawn(move || serve(stream, accept_login, sniff_dns));
        }
    });
    address
}

fn serve(mut stream: std::net::TcpStream, accept_login: bool, sniff_dns: bool) {
    let mut greeting = [0_u8; 2];
    if stream.read_exact(&mut greeting).is_err() {
        return;
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    let _ = stream.read_exact(&mut methods);
    if !accept_login {
        let _ = stream.write_all(&[5, 0xff]);
        return;
    }
    let _ = stream.write_all(&[5, 0]);
    let mut request = [0_u8; 10];
    if stream.read_exact(&mut request).is_err() {
        return;
    }
    let target = SocketAddrV4::new(
        Ipv4Addr::new(request[4], request[5], request[6], request[7]),
        u16::from_be_bytes([request[8], request[9]]),
    );
    if request[1] == 3 {
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = relay.local_addr().unwrap().port().to_be_bytes();
        let _ = stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]]);
        thread::spawn(move || {
            let mut buffer = [0_u8; 2048];
            while let Ok((length, from)) = relay.recv_from(&mut buffer) {
                // The header names the destination; the reply names it as
                // the source, which is what a real relay does.
                let _ = relay.send_to(&buffer[..length], from);
            }
        });
        let mut hold = [0_u8; 1];
        let _ = stream.read(&mut hold);
        return;
    }
    if target.port() == REFUSED_PORT {
        let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }
    let _ = stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let mut buffer = [0_u8; 4096];
    if target.port() == 53 {
        let recognised = if sniff_dns {
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let recognised = stream.peek(&mut [0_u8; 1]).is_ok_and(|read| read > 0);
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            recognised
        } else {
            true
        };
        loop {
            let mut length = [0_u8; 2];
            if stream.read_exact(&mut length).is_err() {
                return;
            }
            let mut message = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut message).is_err() {
                return;
            }
            // A lookup this proxy never answers, holding up everything sent
            // after it on the same stream, as an in-order resolver does.
            if message.windows(6).any(|label| label == b"\x05stuck") {
                while stream.read(&mut buffer).is_ok_and(|read| read > 0) {}
                return;
            }
            // sing-box closes the stream when a lookup fails.
            if message.windows(7).any(|label| label == b"\x06failed") {
                return;
            }
            message[2] |= 0x80;
            if !recognised {
                message[3] = (message[3] & 0xf0) | 2;
            }
            let _ = stream.write_all(&length);
            let _ = stream.write_all(&message);
            if sniff_dns {
                return;
            }
        }
    }
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 || stream.write_all(&buffer[..read]).is_err() {
            break;
        }
    }
}

struct AppDevice {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push(packet);
        result
    }
}

impl Device for AppDevice {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _now: StackInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _now: StackInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

/// The application side: a TCP/IP stack at the client address whose packets
/// go straight into the SOCKS5 stack, as captured packets would.
struct App {
    iface: Interface,
    device: AppDevice,
    sockets: SocketSet<'static>,
    stack: Socks5Stack,
    /// Packets that came back and were not TCP, for the raw tests.
    other: Vec<Vec<u8>>,
}

impl App {
    fn new(proxy: SocketAddr) -> Self {
        let config = Socks5NodeConfig {
            host: proxy.ip().to_string(),
            port: proxy.port(),
            username: None,
            password: None,
        };
        let stack = Socks5Stack::open(&config, RESOLVER).unwrap();
        let mut device = AppDevice {
            rx: VecDeque::new(),
            tx: Vec::new(),
        };
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            StackInstant::now(),
        );
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(CLIENT_ADDRESS), 24));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(GATEWAY_ADDRESS);
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            stack,
            other: Vec::new(),
        }
    }

    fn step(&mut self) {
        self.iface
            .poll(StackInstant::now(), &mut self.device, &mut self.sockets);
        for packet in self.device.tx.drain(..) {
            self.stack.send_packet(&packet).unwrap();
        }
        for packet in self
            .stack
            .receive_packets(Duration::from_millis(5))
            .unwrap()
        {
            match parse_ipv4(&packet) {
                Some(ip) if ip.protocol == 6 => self.device.rx.push_back(packet),
                _ => self.other.push(packet),
            }
        }
    }

    fn until(&mut self, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 65_536]),
        tcp::SocketBuffer::new(vec![0; 65_536]),
    )
}

#[test]
fn an_applications_connection_is_carried_through_the_proxy() {
    let mut app = App::new(spawn_proxy(true));
    let mut socket = tcp_socket();
    socket
        .connect(app.iface.context(), (IpAddress::Ipv4(TARGET), 80), 40_000)
        .unwrap();
    let handle = app.sockets.add(socket);
    assert!(app.until(|app| app.sockets.get::<tcp::Socket>(handle).may_send()));
    app.sockets
        .get_mut::<tcp::Socket>(handle)
        .send_slice(b"hello through the proxy")
        .unwrap();
    let mut echoed = Vec::new();
    assert!(app.until(|app| {
        let socket = app.sockets.get_mut::<tcp::Socket>(handle);
        let mut buffer = [0_u8; 64];
        while let Ok(read) = socket.recv_slice(&mut buffer) {
            if read == 0 {
                break;
            }
            echoed.extend_from_slice(&buffer[..read]);
        }
        echoed == b"hello through the proxy"
    }));
}

#[test]
fn a_connection_the_proxy_refuses_is_refused_to_the_application() {
    let mut app = App::new(spawn_proxy(true));
    let mut socket = tcp_socket();
    socket
        .connect(
            app.iface.context(),
            (IpAddress::Ipv4(TARGET), REFUSED_PORT),
            40_001,
        )
        .unwrap();
    let handle = app.sockets.add(socket);
    let mut ever_open = false;
    assert!(app.until(|app| {
        let socket = app.sockets.get::<tcp::Socket>(handle);
        ever_open |= socket.state() == tcp::State::Established;
        socket.state() == tcp::State::Closed
    }));
    assert!(
        !ever_open,
        "the connection looked open before the proxy refused it"
    );
}

#[test]
fn cancelling_a_connection_while_the_proxy_is_dialling_closes_its_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = listener.local_addr().unwrap();
    let (dialled_tx, dialled) = mpsc::channel();
    let (closed_tx, closed) = mpsc::channel();
    thread::spawn(move || {
        // The path checks the login before opening its first CONNECT stream.
        let (mut setup, _) = listener.accept().unwrap();
        let mut greeting = [0_u8; 3];
        setup.read_exact(&mut greeting).unwrap();
        setup.write_all(&[5, 0]).unwrap();
        drop(setup);
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.read_exact(&mut greeting).unwrap();
        stream.write_all(&[5, 0]).unwrap();
        let mut request = [0_u8; 10];
        stream.read_exact(&mut request).unwrap();
        dialled_tx.send(()).unwrap();
        let result = stream.read(&mut [0_u8; 1]);
        let _ = closed_tx.send(matches!(result, Ok(0)));
    });
    let mut app = App::new(proxy);
    let mut socket = tcp_socket();
    socket
        .connect(app.iface.context(), (IpAddress::Ipv4(TARGET), 80), 40_004)
        .unwrap();
    app.sockets.add(socket);
    assert!(app.until(|_| dialled.try_recv().is_ok()));
    let reset = super::packet::build_tcp_reset(
        SocketAddrV4::new(CLIENT_ADDRESS, 40_004),
        SocketAddrV4::new(TARGET, 80),
        0,
    );
    app.stack.send_packet(&reset).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        app.step();
        if let Ok(was_closed) = closed.try_recv() {
            assert!(
                was_closed,
                "the abandoned proxy dial stayed open until its read timed out"
            );
            assert_eq!(
                app.stack.shared.counters.tcp_opened.load(Ordering::Relaxed),
                0
            );
            assert_eq!(
                app.stack
                    .shared
                    .counters
                    .tcp_cancelled
                    .load(Ordering::Relaxed),
                1
            );
            return;
        }
    }
    panic!("the proxy stream was never released");
}

#[test]
fn a_datagram_windows_fragmented_is_rebuilt_and_relayed_whole() {
    let mut app = App::new(spawn_proxy(true));
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27_015);
    let client = SocketAddrV4::new(CLIENT_ADDRESS, 41_001);
    let payload = (0..2000).map(|index| index as u8).collect::<Vec<_>>();
    let whole = build_udp(client, server, &payload);
    // Split as Windows would at a 1500-byte MTU: 1480 bytes, then the rest.
    let mut first = whole[..20 + 1480].to_vec();
    let length = first.len() as u16;
    first[2..4].copy_from_slice(&length.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    let mut last = whole[..20].to_vec();
    last.extend_from_slice(&whole[20 + 1480..]);
    let length = last.len() as u16;
    last[2..4].copy_from_slice(&length.to_be_bytes());
    last[6..8].copy_from_slice(&(1480_u16 / 8).to_be_bytes());
    app.stack.send_packet(&last).unwrap();
    app.stack.send_packet(&first).unwrap();
    assert!(app.until(|app| {
        app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            parse_udp(ip.payload)
                .is_some_and(|udp| udp.destination_port == client.port() && udp.payload == payload)
        })
    }));
}

#[test]
fn a_datagram_goes_through_a_udp_association_and_back() {
    let mut app = App::new(spawn_proxy(true));
    let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27_015);
    let client = SocketAddrV4::new(CLIENT_ADDRESS, 41_000);
    app.stack
        .send_packet(&build_udp(client, server, b"ping"))
        .unwrap();
    assert!(app.until(|app| {
        app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            let udp = parse_udp(ip.payload).unwrap();
            ip.source == *server.ip()
                && udp.source_port == server.port()
                && udp.destination_port == client.port()
                && udp.payload == b"ping"
        })
    }));
}

#[test]
fn a_name_lookup_goes_over_tcp_and_keeps_its_own_id() {
    let mut app = App::new(spawn_proxy(true));
    let client = SocketAddrV4::new(CLIENT_ADDRESS, 42_000);
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    app.stack
        .send_packet(&build_udp(client, SocketAddrV4::new(RESOLVER, 53), &query))
        .unwrap();
    assert!(app.until(|app| {
        app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            let udp = parse_udp(ip.payload).unwrap();
            ip.source == RESOLVER
                && udp.destination_port == client.port()
                && udp.payload[..2] == [0x12, 0x34]
                && udp.payload[2] & 0x80 != 0
        })
    }));
}

#[test]
fn a_dns_connection_sends_its_query_before_the_proxy_stops_sniffing() {
    let mut app = App::new(spawn_proxy_with_dns_sniff(true, true));
    let client = SocketAddrV4::new(CLIENT_ADDRESS, 42_010);
    for id in [1_u16, 2] {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        app.stack
            .send_packet(&build_udp(client, SocketAddrV4::new(RESOLVER, 53), &query))
            .unwrap();
        assert!(app.until(|app| {
            app.other.iter().any(|packet| {
                let ip = parse_ipv4(packet).unwrap();
                parse_udp(ip.payload).is_some_and(|udp| {
                    udp.destination_port == client.port() && udp.payload[..2] == id.to_be_bytes()
                })
            })
        }));
        let response = app.other.iter().find_map(|packet| {
            let ip = parse_ipv4(packet)?;
            let udp = parse_udp(ip.payload)?;
            (udp.payload[..2] == id.to_be_bytes()).then_some(udp.payload)
        });
        assert_eq!(
            response.unwrap()[3] & 0x0f,
            0,
            "lookup {id} used a connection that the proxy had already routed without DNS sniffing"
        );
        // The responder closes after its answer. Any empty spare connection
        // has time to fall through the proxy's sniffing deadline before reuse.
        thread::sleep(Duration::from_millis(600));
    }
}

#[test]
fn a_lookup_the_proxy_never_answers_does_not_hold_up_the_next() {
    let mut app = App::new(spawn_proxy(true));
    let lookup = |id: u16, name: &[u8]| {
        let mut query = id.to_be_bytes().to_vec();
        query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(name);
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        query
    };
    let stuck = SocketAddrV4::new(CLIENT_ADDRESS, 42_100);
    let next = SocketAddrV4::new(CLIENT_ADDRESS, 42_101);
    let resolver = SocketAddrV4::new(RESOLVER, 53);
    app.stack
        .send_packet(&build_udp(stuck, resolver, &lookup(1, b"\x05stuck\x03com")))
        .unwrap();
    app.stack
        .send_packet(&build_udp(
            next,
            resolver,
            &lookup(2, b"\x07example\x03com"),
        ))
        .unwrap();
    assert!(app.until(|app| {
        app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            parse_udp(ip.payload).is_some_and(|udp| udp.destination_port == next.port())
        })
    }));
}

#[test]
fn a_lookup_the_proxy_fails_is_answered_with_servfail_at_once() {
    let mut app = App::new(spawn_proxy(true));
    let client = SocketAddrV4::new(CLIENT_ADDRESS, 42_200);
    let mut query = vec![0x56, 0x78, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x06failed\x03com\x00\x00\x01\x00\x01");
    app.stack
        .send_packet(&build_udp(client, SocketAddrV4::new(RESOLVER, 53), &query))
        .unwrap();
    assert!(app.until(|app| {
        app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            parse_udp(ip.payload).is_some_and(|udp| {
                udp.destination_port == client.port()
                    && udp.payload[..2] == [0x56, 0x78]
                    && udp.payload[3] & 0x0f == 2
            })
        })
    }));
}

#[test]
fn a_lookup_that_times_out_is_answered_with_servfail() {
    let mut app = App::new(spawn_proxy(true));
    let client = SocketAddrV4::new(CLIENT_ADDRESS, 42_201);
    let mut query = vec![0x56, 0x79, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x05stuck\x03com\x00\x00\x01\x00\x01");
    app.stack
        .send_packet(&build_udp(client, SocketAddrV4::new(RESOLVER, 53), &query))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(7);
    while Instant::now() < deadline {
        app.step();
        if app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            parse_udp(ip.payload).is_some_and(|udp| {
                ip.source == RESOLVER
                    && udp.destination_port == client.port()
                    && udp.payload[..2] == [0x56, 0x79]
                    && udp.payload[3] & 0x0f == 2
            })
        }) {
            assert_eq!(
                app.stack.shared.counters.dns_failed.load(Ordering::Relaxed),
                1
            );
            return;
        }
    }
    panic!("the timed-out lookup was left unanswered");
}

#[test]
fn the_session_health_probe_is_answered_only_through_the_proxy() {
    let mut app = App::new(spawn_proxy(true));
    let mut message = vec![8, 0, 0, 0, 0xab, 0xcd, 0, 1];
    let checksum = !message
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>() as u16;
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = vec![0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0];
    packet.extend_from_slice(&CLIENT_ADDRESS.octets());
    packet.extend_from_slice(&RESOLVER.octets());
    packet.extend_from_slice(&message);
    app.stack.send_packet(&packet).unwrap();
    assert!(app.until(|app| {
        app.other.iter().any(|packet| {
            let ip = parse_ipv4(packet).unwrap();
            ip.protocol == 1 && ip.source == RESOLVER && ip.payload[0] == 0
        })
    }));
}

#[test]
fn a_proxy_that_refuses_the_login_is_reported_when_the_path_opens() {
    let proxy = spawn_proxy(false);
    let config = Socks5NodeConfig {
        host: proxy.ip().to_string(),
        port: proxy.port(),
        username: None,
        password: None,
    };
    let error = Socks5Stack::open(&config, RESOLVER).err().unwrap();
    assert!(
        error.contains("authentication") || error.contains("method"),
        "{error}"
    );
}

#[test]
fn a_large_transfer_survives_backpressure_in_both_directions() {
    let mut app = App::new(spawn_proxy(true));
    let mut socket = tcp_socket();
    socket
        .connect(app.iface.context(), (IpAddress::Ipv4(TARGET), 80), 40_002)
        .unwrap();
    let handle = app.sockets.add(socket);
    assert!(app.until(|app| app.sockets.get::<tcp::Socket>(handle).may_send()));
    let payload: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let mut sent = 0;
    let mut echoed = Vec::with_capacity(payload.len());
    let deadline = Instant::now() + Duration::from_secs(30);
    while echoed.len() < payload.len() && Instant::now() < deadline {
        let socket = app.sockets.get_mut::<tcp::Socket>(handle);
        if sent < payload.len() && socket.can_send() {
            sent += socket.send_slice(&payload[sent..]).unwrap();
        }
        let mut buffer = [0_u8; 16 * 1024];
        while let Ok(read) = socket.recv_slice(&mut buffer) {
            if read == 0 {
                break;
            }
            echoed.extend_from_slice(&buffer[..read]);
        }
        app.step();
    }
    assert_eq!(echoed.len(), payload.len(), "transfer stalled");
    assert!(echoed == payload, "bytes arrived out of order or damaged");
}

/// A paused video: data keeps arriving for an application that has stopped
/// reading, so its window is shut. The stack must wait, not turn its loop as
/// fast as the CPU allows. Observed live: one core, all the time.
#[test]
fn an_application_that_stops_reading_leaves_the_stack_idle() {
    let mut app = App::new(spawn_proxy(true));
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 256 * 1024]),
    );
    socket
        .connect(app.iface.context(), (IpAddress::Ipv4(TARGET), 80), 40_010)
        .unwrap();
    let handle = app.sockets.add(socket);
    assert!(app.until(|app| app.sockets.get::<tcp::Socket>(handle).may_send()));
    let payload = vec![7_u8; 256 * 1024];
    let settle = Instant::now() + Duration::from_millis(800);
    let mut sent = 0;
    while Instant::now() < settle {
        let socket = app.sockets.get_mut::<tcp::Socket>(handle);
        if sent < payload.len() && socket.can_send() {
            sent += socket.send_slice(&payload[sent..]).unwrap();
        }
        app.step();
    }
    let before = app.stack.shared.counters.turns.load(Ordering::Relaxed);
    let measure = Instant::now() + Duration::from_secs(1);
    while Instant::now() < measure {
        app.step();
    }
    let turns = app.stack.shared.counters.turns.load(Ordering::Relaxed) - before;
    assert!(
        turns < 2_000,
        "the stack turned {turns} times in a second while waiting"
    );
}

#[test]
fn the_proxy_ending_a_connection_ends_it_for_the_application() {
    let mut app = App::new(spawn_proxy(true));
    let mut socket = tcp_socket();
    socket
        .connect(app.iface.context(), (IpAddress::Ipv4(TARGET), 80), 40_003)
        .unwrap();
    let handle = app.sockets.add(socket);
    assert!(app.until(|app| app.sockets.get::<tcp::Socket>(handle).may_send()));
    // Closing our side makes the echo server close its side, which the stack
    // has to pass on as a FIN rather than leave the application waiting.
    app.sockets.get_mut::<tcp::Socket>(handle).close();
    assert!(app.until(|app| {
        matches!(
            app.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::TimeWait | tcp::State::Closed
        )
    }));
}

#[test]
fn a_proxy_test_logs_in_and_reaches_out_through_it() {
    let proxy = spawn_proxy(true);
    let config = Socks5NodeConfig {
        host: proxy.ip().to_string(),
        port: proxy.port(),
        username: None,
        password: None,
    };
    let result = probe(&config, SocketAddrV4::new(TARGET, 80)).unwrap();
    assert_eq!(result.proxy, proxy);
    let error = probe(&config, SocketAddrV4::new(TARGET, REFUSED_PORT))
        .err()
        .unwrap();
    assert!(error.contains("connection refused"), "{error}");
}
