use std::net::Ipv4Addr;

/// Public IPv4 address used to measure end-to-end reachability through a
/// tunnel, both as the direct-session ICMP probe target and as the benchmark
/// server reported to the UI.
///
/// It only ever receives echo requests, so the requirement is simply that it
/// answers them from everywhere a user might connect from. Cloudflare's
/// 1.1.1.1 does not meet that: several national filters blackhole or hijack it
/// outright, which made a perfectly healthy tunnel measure as silent.
pub const BENCHMARK_TARGET: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

pub mod adapter;
pub mod auth;
pub mod l2tp;
pub mod log;
pub mod mtu;
/// Native replacements for the `Net*` PowerShell cmdlets. Windows-only, and
/// the relay builds this crate on Linux, so the whole module is gated.
#[cfg(windows)]
pub mod netconfig;
#[cfg(feature = "openvpn")]
pub mod openvpn;
pub mod policy;
pub mod protocol;
pub mod relay_path;
pub mod replay;
pub mod rtt;
pub mod scheduler;
pub mod socks5;
pub mod timer;
pub mod transport;
pub mod uplink;
pub mod userspace_wireguard;
pub mod wfp;
pub mod wireguard_runtime;
