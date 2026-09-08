//! Brings up a real OpenVPN session against a real provider.
//!
//! The protocol has several details that only a live server can settle -- which
//! half of the derived key material each side sends with, where the implicit
//! nonce sits, whether the authentication tag comes before the ciphertext -- so
//! the unit tests cannot stand in for this. It is ignored by default because it
//! needs a provider's configuration and credentials, which cannot live in the
//! repository.
//!
//! Run it with:
//!
//! ```text
//! GAMEPATH_OVPN_CONFIG=<path to .ovpn> \
//! GAMEPATH_OVPN_USER=<username> \
//! GAMEPATH_OVPN_PASS=<password> \
//!   cargo test --manifest-path engine/Cargo.toml --test openvpn_live -- --ignored --nocapture
//! ```

use gamepath_engine::openvpn::{Credentials, UserSpaceOpenVpnPath};
use gamepath_engine::relay_path::NodeSpec;
use gamepath_engine::userspace_wireguard::{ipv4_udp_packet, ipv4_udp_payload};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A public time server, chosen because it answers on a port that is not 53.
///
/// Testing a tunnel with DNS proves very little: proxies and VPN servers
/// routinely answer port 53 from their own resolver whether or not they forward
/// anything else. A reply here means real datagrams are being carried.
const TIME_SERVER: Ipv4Addr = Ipv4Addr::new(162, 159, 200, 1);
const TIME_PORT: u16 = 123;

fn environment() -> Option<(String, Credentials)> {
    let config = std::env::var("GAMEPATH_OVPN_CONFIG").ok()?;
    let source = std::fs::read_to_string(&config)
        .unwrap_or_else(|error| panic!("could not read {config}: {error}"));
    Some((
        source,
        Credentials {
            username: std::env::var("GAMEPATH_OVPN_USER").ok(),
            password: std::env::var("GAMEPATH_OVPN_PASS").ok(),
        },
    ))
}

/// One minimal SNTP request, which any time server answers.
fn time_request() -> Vec<u8> {
    let mut request = vec![0_u8; 48];
    request[0] = 0x23;
    request
}

#[test]
#[ignore = "needs a provider's configuration and credentials"]
fn a_real_session_comes_up_and_carries_a_datagram() {
    let Some((source, credentials)) = environment() else {
        panic!("set GAMEPATH_OVPN_CONFIG, GAMEPATH_OVPN_USER and GAMEPATH_OVPN_PASS");
    };
    let started = Instant::now();
    let mut path = UserSpaceOpenVpnPath::from_config(&source, credentials)
        .unwrap_or_else(|error| panic!("the session did not come up: {error}"));
    println!(
        "session up in {} ms over {}: endpoint {}, tunnel address {}, gateway {:?},          cipher {}, peer id {:?}",
        started.elapsed().as_millis(),
        path.protocol().as_str(),
        path.endpoint(),
        path.address(),
        path.gateway(),
        path.cipher(),
        path.peer_id()
    );
    assert!(
        path.handshake_latency_ms().is_some(),
        "a session that came up has a measured setup time"
    );

    let packet = ipv4_udp_packet(
        path.address(),
        TIME_SERVER,
        41_234,
        TIME_PORT,
        &time_request(),
    )
    .expect("a 48 byte payload fits in one packet");
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut answer = None;
    // Everything that arrives is described, so a failure says what the tunnel
    // did carry rather than only that it did not carry the answer.
    let mut seen = Vec::new();
    while Instant::now() < deadline && answer.is_none() {
        // Resent each time round: this is a datagram over a tunnel that has
        // just come up, and the first one is quite often dropped while the
        // server finishes settling the session.
        path.send_inner(&packet).expect("the request goes out");
        for received in path
            .receive_inner(Duration::from_millis(500))
            .expect("the tunnel keeps reading")
        {
            match ipv4_udp_payload(&received) {
                Some((source_ip, _, source_port, destination_port, payload)) => {
                    seen.push(format!(
                        "udp {source_ip}:{source_port} -> :{destination_port} ({} bytes)",
                        payload.len()
                    ));
                    if source_ip == TIME_SERVER
                        && source_port == TIME_PORT
                        && destination_port == 41_234
                    {
                        answer = Some(payload.len());
                    }
                }
                None => seen.push(format!(
                    "not IPv4: {} bytes starting {}",
                    received.len(),
                    received
                        .iter()
                        .take(8)
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )),
            }
        }
    }
    let length = answer.unwrap_or_else(|| {
        panic!(
            "the time server's answer did not come back. What did arrive: {}",
            if seen.is_empty() {
                "nothing at all".to_owned()
            } else {
                seen.join("; ")
            }
        )
    });
    println!("carried a datagram both ways: {length} byte answer from {TIME_SERVER}");
    assert_eq!(length, 48, "an SNTP answer is 48 bytes");
}

/// The relay a session would actually carry frames to.
///
/// Set `GAMEPATH_RELAY` to `address:port` to check that the node reaches it.
/// The relay ignores anything unauthenticated, so this cannot expect a reply;
/// what it proves is that the tunnel accepts and forwards traffic aimed there.
#[test]
#[ignore = "needs a provider's configuration and a relay to aim at"]
fn a_real_session_can_address_the_relay() {
    let Some((source, credentials)) = environment() else {
        panic!("set GAMEPATH_OVPN_CONFIG, GAMEPATH_OVPN_USER and GAMEPATH_OVPN_PASS");
    };
    let relay = std::env::var("GAMEPATH_RELAY").expect("set GAMEPATH_RELAY to address:port");
    let (host, port) = relay
        .split_once(':')
        .expect("GAMEPATH_RELAY is address:port");
    let address: Ipv4Addr = host.parse().expect("the relay address is IPv4");
    let port: u16 = port.parse().expect("the relay port is a number");

    let mut path = UserSpaceOpenVpnPath::from_config(&source, credentials)
        .unwrap_or_else(|error| panic!("the session did not come up: {error}"));
    let packet = ipv4_udp_packet(path.address(), address, 41_235, port, b"gamepath")
        .expect("a short payload fits in one packet");
    path.send_inner(&packet)
        .expect("the tunnel accepts a packet aimed at the relay");
    // Drained so that an error on the link surfaces here rather than being
    // discovered later by a session.
    path.receive_inner(Duration::from_millis(500))
        .expect("the tunnel stays healthy after addressing the relay");
    println!(
        "addressed {address}:{port} over {} from tunnel address {}",
        path.protocol().as_str(),
        path.address()
    );
}

/// The same server, reached the way a session reaches it.
///
/// The test above exercises the client on its own. This one goes through the
/// node model -- the shape the app stores and the engine is handed -- so that a
/// break in the wiring between them cannot pass unnoticed.
#[test]
#[ignore = "needs a provider's configuration and credentials"]
fn a_node_opens_as_the_single_hop_of_a_direct_session() {
    let Some((source, credentials)) = environment() else {
        panic!("set GAMEPATH_OVPN_CONFIG, GAMEPATH_OVPN_USER and GAMEPATH_OVPN_PASS");
    };
    let node = NodeSpec::OpenVpn {
        config: source,
        username: credentials.username,
        password: credentials.password,
        label: Some("live test".into()),
    };
    node.validate()
        .expect("the configuration and credentials are complete");
    assert!(
        node.supports_direct(),
        "an OpenVPN node routes packets itself"
    );

    let mut path = node
        .open_direct()
        .unwrap_or_else(|error| panic!("the node did not open: {error}"));
    println!(
        "node opened as a {} direct path: tunnel address {}, bypass {:?}, setup {:?} ms",
        path.kind(),
        path.address(),
        path.bypass_ipv4(),
        path.handshake_latency_ms().map(|value| value.round())
    );

    let packet = ipv4_udp_packet(
        path.address(),
        TIME_SERVER,
        41_236,
        TIME_PORT,
        &time_request(),
    )
    .expect("a 48 byte payload fits in one packet");
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut answered = false;
    while Instant::now() < deadline && !answered {
        path.send_packet(&packet).expect("the request goes out");
        for received in path
            .receive_packets(Duration::from_millis(500))
            .expect("the path keeps reading")
        {
            // `receive_packets` already drops anything not addressed to this
            // tunnel, so whatever arrives here is ours.
            if let Some((source_ip, _, source_port, _, _)) = ipv4_udp_payload(&received) {
                answered |= source_ip == TIME_SERVER && source_port == TIME_PORT;
            }
        }
    }
    assert!(answered, "a direct path carries a datagram both ways");
    println!("carried a datagram both ways through the node model");
}

/// One ICMP echo request, built by hand because the engine has no need for one
/// outside this measurement.
fn icmp_echo(source: Ipv4Addr, destination: Ipv4Addr, sequence: u16) -> Vec<u8> {
    let mut icmp = vec![0_u8; 16];
    icmp[0] = 8;
    icmp[4..6].copy_from_slice(&0x4750_u16.to_be_bytes());
    icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
    let checksum = ones_complement(&icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    let total = 20 + icmp.len();
    let mut packet = vec![0_u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = ones_complement(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(&icmp);
    packet
}

fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let value = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(value);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Measures the loss and round trip a node actually delivers.
///
/// Compare the result against the same target reached without the tunnel: loss
/// close to that baseline is the connection, not the client. Set
/// `GAMEPATH_ICMP_TARGET` to something that answers ICMP reliably -- a
/// provider's own tunnel gateway often does not -- and `GAMEPATH_PROBES` to
/// take a sample big enough to mean anything, since one lost packet in twenty
/// already reads as five per cent.
#[test]
#[ignore = "needs a provider's configuration and credentials"]
fn a_real_session_measures_its_own_loss() {
    let Some((source, credentials)) = environment() else {
        panic!("set GAMEPATH_OVPN_CONFIG, GAMEPATH_OVPN_USER and GAMEPATH_OVPN_PASS");
    };
    let mut path = UserSpaceOpenVpnPath::from_config(&source, credentials)
        .unwrap_or_else(|error| panic!("the session did not come up: {error}"));
    // The tunnel's gateway is the shortest path, but plenty of providers do not
    // answer it, so the target can be pointed at something known to reply.
    let target: Ipv4Addr = std::env::var("GAMEPATH_ICMP_TARGET")
        .ok()
        .and_then(|value| value.parse().ok())
        .or_else(|| path.gateway())
        .expect("no target to aim at");

    let probes: u16 = std::env::var("GAMEPATH_PROBES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20);
    let mut answered = 0_u32;
    let mut round_trips = Vec::new();
    // Which probes went missing matters more than how many: a loss always at
    // the start is the session settling, while scattered losses are the link.
    let mut lost_at = Vec::new();
    for sequence in 1..=probes {
        let sent = Instant::now();
        path.send_inner(&icmp_echo(path.address(), target, sequence))
            .expect("the echo goes out");
        // Long enough that a retransmission on a tcp link still arrives inside
        // the window, so a slow reply is not counted as a lost one.
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut seen = false;
        while Instant::now() < deadline && !seen {
            for received in path
                .receive_inner(Duration::from_millis(100))
                .expect("the tunnel keeps reading")
            {
                // Protocol 1 is ICMP; type 0 is an echo reply.
                if received.get(9) == Some(&1) && received.get(20) == Some(&0) {
                    seen = true;
                }
            }
        }
        if seen {
            answered += 1;
            round_trips.push(sent.elapsed().as_secs_f64() * 1000.0);
        } else {
            lost_at.push(sequence);
        }
    }

    let lost = u32::from(probes) - answered;
    let loss = f64::from(lost) / f64::from(probes) * 100.0;
    let best = round_trips.iter().cloned().fold(f64::INFINITY, f64::min);
    let worst = round_trips.iter().cloned().fold(0.0_f64, f64::max);
    let mean = round_trips.iter().sum::<f64>() / round_trips.len().max(1) as f64;
    println!(
        "{answered} of {probes} answered by {target} over {} ({loss:.1}% lost), round trip best          {best:.0} ms, mean {mean:.0} ms, worst {worst:.0} ms",
        path.protocol().as_str()
    );
    println!("lost probe numbers: {lost_at:?}");
    assert!(answered > 0, "{target} answered nothing at all");
}
