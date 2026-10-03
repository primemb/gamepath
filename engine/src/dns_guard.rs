//! Stops classic DNS using an interface outside the assigned tunnel.

use crate::ipc::PacketCaptureRequest;
use crate::split_capture::{Handle, dll_path, is_application_path, process_path};
use gamepath_engine::dns_policy::{DnsRoute, route};
use gamepath_engine::fragment_router::{Action, FragmentRouter, Route as FragmentRoute};
use gamepath_engine::policy::compile;
use gamepath_engine::role::Role;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Instant;
use windows_sys::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL;

pub(crate) struct DnsGuard {
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    other_active: Arc<AtomicBool>,
    other_app_dns: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DnsGuard {
    /// Without an interface, split capture owns IPv4 and this guards unsupported IPv6 DNS.
    pub(crate) fn start(
        input: &PacketCaptureRequest,
        interface: Option<u32>,
    ) -> Result<Self, String> {
        let plan = compile(&input.traffic_mode, &input.rules)?;
        let filter = guard_filter(interface);
        let handle = Arc::new(Handle::open(
            &dll_path()?,
            &filter,
            0,
            Role::current().capture_priority() - 1,
            0,
        )?);
        handle.set_param(1, 100)?;
        let stop = Arc::new(AtomicBool::new(false));
        let other_active = Arc::new(AtomicBool::new(input.other_session_active));
        let other_app_dns = Arc::new(AtomicBool::new(input.other_session_app_dns));
        let worker_handle = Arc::clone(&handle);
        let worker_stop = Arc::clone(&stop);
        let worker_other = Arc::clone(&other_active);
        let worker_app_dns = Arc::clone(&other_app_dns);
        let all = input.traffic_mode == "all";
        let hostnames: HashSet<_> = input
            .own_hostnames
            .iter()
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        let worker = thread::Builder::new()
            .name("gamepath-dns-guard".into())
            .spawn(move || {
                let mut buffer = vec![0; 65_535];
                let mut fragments = FragmentRouter::default();
                while !worker_stop.load(Ordering::Acquire) {
                    let (length, address) = match worker_handle.recv_into(&mut buffer) {
                        Ok(packet) => packet,
                        Err(error) if matches!(error.raw_os_error(), Some(122 | 232)) => continue,
                        Err(_) => break,
                    };
                    let packet = &buffer[..length];
                    if gamepath_engine::ipv4_fragments::is_later_fragment(packet) {
                        if matches!(
                            fragments.later(packet, address, Instant::now()),
                            Action::Route(FragmentRoute::Bypass)
                        ) {
                            let _ = worker_handle.send(packet, &address);
                        }
                        continue;
                    }
                    let ticket = gamepath_engine::ipv4_fragments::is_first_fragment(packet)
                        .then(|| fragments.begin(packet, Instant::now()));
                    let transport = transport(packet)
                        .filter(|(_, offset)| packet[*offset + 2..*offset + 4] == [0, 53]);
                    let (selected, application, bootstrap, unknown_owner) =
                        transport.map_or((false, false, false, true), |(protocol, offset)| {
                            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
                            // Recheck ownership: a reused port must not inherit a local DNS exemption.
                            let pid = socket_owner(packet[0] >> 4, protocol, port);
                            let path = pid.and_then(process_path);
                            let application = path.as_deref().is_some_and(is_application_path);
                            let selected = path.as_deref().is_some_and(|path| {
                                plan.application_paths.iter().any(|target| path == target)
                                    || plan
                                        .folder_prefixes
                                        .iter()
                                        .any(|target| path.starts_with(target))
                            });
                            let engine_owned = pid == Some(std::process::id());
                            let bootstrap = engine_owned
                                || (protocol == 17
                                    && !application
                                    && packet
                                        .get(offset + 8..)
                                        .and_then(gamepath_engine::dns::question_name)
                                        .is_some_and(|name| hostnames.contains(&name)));
                            (
                                selected || (all && application),
                                application,
                                bootstrap,
                                path.is_none(),
                            )
                        });
                    let other = worker_other.load(Ordering::Relaxed);
                    let decision = if transport.is_none() && ticket.is_some() {
                        DnsRoute::Normal
                    } else if unknown_owner && !bootstrap && Role::current() == Role::Vpn && other {
                        DnsRoute::Remote
                    } else {
                        route(
                            true,
                            Role::current() == Role::Vpn && other,
                            Role::current() == Role::Game
                                && other
                                && worker_app_dns.load(Ordering::Relaxed),
                            selected,
                            application,
                            bootstrap,
                        )
                    };
                    if decision == DnsRoute::Normal {
                        let _ = worker_handle.send(packet, &address);
                    }
                    if let Some(ticket) = ticket {
                        let route = if decision == DnsRoute::Normal {
                            FragmentRoute::Bypass
                        } else {
                            FragmentRoute::Drop
                        };
                        for (packet, address) in fragments.finish(ticket, route, Instant::now()) {
                            let _ = worker_handle.send(&packet, &address);
                        }
                    }
                    // Remote DNS on an unsupported family or a physical interface is deliberately dropped.
                    // Windows can retry on the tunnel adapter; a local answer must never win that race.
                }
            })
            .map_err(|error| format!("could not start DNS leak guard: {error}"))?;
        Ok(Self {
            handle,
            stop,
            other_active,
            other_app_dns,
            worker: Some(worker),
        })
    }

    pub(crate) fn set_other_active(&self, active: bool, can_route_apps: bool) {
        self.other_app_dns.store(can_route_apps, Ordering::Relaxed);
        self.other_active.store(active, Ordering::Relaxed);
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.handle.shutdown_receive();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn guard_filter(interface: Option<u32>) -> String {
    let outside = match interface {
        Some(index) => format!("ifIdx != {index}"),
        None => "ipv6".to_owned(),
    };
    format!(
        "outbound and (udp.DstPort == 53 or tcp.DstPort == 53 or (ip and fragment)) and ({outside})"
    )
}

fn socket_owner(family: u8, protocol: u8, port: u16) -> Option<u32> {
    if family == 6 {
        return crate::socket_table::ipv6_owner(protocol, port);
    }
    if protocol == 17 {
        return crate::proxy_identity::udp_owner(port);
    }
    crate::socket_table::tcp_rows(TCP_TABLE_OWNER_PID_ALL)?
        .into_iter()
        .find(|row| u16::from_be(row.dwLocalPort as u16) == port)
        .map(|row| row.dwOwningPid)
}

fn transport(packet: &[u8]) -> Option<(u8, usize)> {
    let (mut protocol, mut offset) = match packet.first()? >> 4 {
        4 => (*packet.get(9)?, usize::from(packet[0] & 15) * 4),
        6 => (*packet.get(6)?, 40),
        _ => return None,
    };
    for _ in 0..8 {
        match protocol {
            6 | 17 => {
                packet.get(offset..offset + 4)?;
                return Some((protocol, offset));
            }
            0 | 43 | 60 => {
                let header = packet.get(offset..offset + 2)?;
                protocol = header[0];
                offset += (usize::from(header[1]) + 1) * 8;
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_both_dns_transports_on_every_non_tunnel_interface() {
        let filter = guard_filter(Some(42));
        assert!(filter.contains("udp.DstPort == 53") && filter.contains("tcp.DstPort == 53"));
        assert!(filter.contains("ifIdx != 42") && !filter.contains(" and ip "));
        assert!(guard_filter(None).contains("ipv6"));
    }

    #[test]
    fn ipv6_extension_headers_do_not_hide_the_dns_socket() {
        let mut packet = vec![0; 52];
        packet[0] = 0x60;
        packet[6] = 0;
        packet[40] = 17;
        packet[48..52].copy_from_slice(&[1, 2, 0, 53]);
        assert_eq!(transport(&packet), Some((17, 48)));
        assert_eq!(transport(&packet[..49]), None);
    }
}
