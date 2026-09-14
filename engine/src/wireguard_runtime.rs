use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWireGuardConfig {
    pub source: String,
    pub tunnel_address: IpAddr,
    pub endpoint: String,
}

/// Returns the inner MTU explicitly requested by a provider configuration.
/// GamePath owns the runtime adapter, so `parse` intentionally removes this
/// line before bringing the tunnel up; the value is still a useful lower cap
/// when calculating the adapter's safe MTU.
pub fn interface_mtu(input: &str) -> Option<u16> {
    let mut in_interface = false;
    for original_line in input.lines() {
        let line = original_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_interface = line.eq_ignore_ascii_case("[interface]");
            continue;
        }
        if !in_interface {
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        if raw_key.trim().eq_ignore_ascii_case("mtu") {
            return raw_value.trim().parse().ok();
        }
    }
    None
}

/// Rewrites a configuration so the tunnel carries nothing but relay traffic.
pub fn narrow_to_relay(input: &str, relay: IpAddr) -> Result<RuntimeWireGuardConfig, String> {
    parse(input, Some(relay))
}

/// Checks a configuration without changing where it routes.
///
/// A direct session has no relay to narrow towards: the node is the last hop,
/// so it keeps whatever the provider's own AllowedIPs say. Only the shape is
/// verified, using exactly the same rules as the relay path.
pub fn inspect(input: &str) -> Result<RuntimeWireGuardConfig, String> {
    parse(input, None)
}

/// The `AllowedIPs` line to write, or nothing when the configuration's own
/// routes are being kept.
///
/// This returns an iterable rather than taking an `if let` at each of its three
/// call sites: nesting those inside the surrounding condition draws a clippy
/// warning, and collapsing them with a let-chain needs a newer compiler than
/// the Debian `rustc` the relay host builds this crate with.
fn allowed_ips_line(relay_route: &Option<String>) -> Option<String> {
    relay_route
        .as_ref()
        .map(|route| format!("AllowedIPs = {route}"))
}

fn parse(input: &str, relay: Option<IpAddr>) -> Result<RuntimeWireGuardConfig, String> {
    let relay_route = relay.map(|relay| match relay {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    });
    let mut section = "";
    let mut output = Vec::new();
    let mut tunnel_address = None;
    let mut endpoint = None;
    let mut private_key = false;
    let mut public_key = false;
    let mut peer_count = 0_u32;
    let mut peer_allowed_ips_written = false;

    for original_line in input.lines() {
        let line = original_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if section == "peer" && !peer_allowed_ips_written {
                output.extend(allowed_ips_line(&relay_route));
            }
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => "interface",
                "[peer]" => {
                    peer_count += 1;
                    peer_allowed_ips_written = false;
                    "peer"
                }
                _ => "other",
            };
            output.push(original_line.to_owned());
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            output.push(original_line.to_owned());
            continue;
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim();
        if section == "interface" {
            match key.as_str() {
                "address" => {
                    if tunnel_address.is_none() {
                        let first = value.split(',').next().unwrap_or(value).trim();
                        let address = first.split('/').next().unwrap_or(first);
                        tunnel_address = Some(
                            address
                                .parse::<IpAddr>()
                                .map_err(|_| "WireGuard interface has an invalid Address")?,
                        );
                    }
                }
                "privatekey" => private_key = !value.is_empty(),
                "dns" | "mtu" | "table" | "preup" | "postup" | "predown" | "postdown" => continue,
                _ => {}
            }
        }
        if section == "peer" {
            match key.as_str() {
                "publickey" => public_key = !value.is_empty(),
                "endpoint" => endpoint = Some(value.to_owned()),
                "allowedips" => {
                    // A direct session keeps the provider's own routes, so the
                    // line is only replaced when there is a relay to narrow to.
                    let Some(route) = &relay_route else {
                        output.push(original_line.to_owned());
                        continue;
                    };
                    if !peer_allowed_ips_written {
                        output.push(format!("AllowedIPs = {route}"));
                        peer_allowed_ips_written = true;
                    }
                    continue;
                }
                _ => {}
            }
        }
        output.push(original_line.to_owned());
    }
    if section == "peer" && !peer_allowed_ips_written {
        output.extend(allowed_ips_line(&relay_route));
    }
    if !private_key {
        return Err("WireGuard configuration is missing Interface PrivateKey".into());
    }
    if peer_count != 1 {
        return Err("GamePath currently requires exactly one Peer per WireGuard route".into());
    }
    if !public_key {
        return Err("WireGuard configuration is missing Peer PublicKey".into());
    }
    let tunnel_address =
        tunnel_address.ok_or("WireGuard configuration is missing Interface Address")?;
    let endpoint = endpoint.ok_or("WireGuard configuration is missing Peer Endpoint")?;
    output.push(String::new());
    Ok(RuntimeWireGuardConfig {
        source: output.join("\n"),
        tunnel_address,
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"[Interface]
PrivateKey = private-value
Address = 10.88.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = public-value
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example:51820
PersistentKeepalive = 25
"#;

    #[test]
    fn runtime_config_routes_only_relay_and_omits_side_effects() {
        let result = narrow_to_relay(CONFIG, "203.0.113.8".parse().unwrap()).unwrap();
        assert_eq!(
            result.tunnel_address,
            "10.88.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(result.endpoint, "vpn.example:51820");
        assert!(result.source.contains("PrivateKey = private-value"));
        assert!(result.source.contains("AllowedIPs = 203.0.113.8/32"));
        assert!(!result.source.contains("0.0.0.0/0"));
        assert!(!result.source.contains("DNS ="));
        assert!(!result.source.contains("MTU ="));
    }

    #[test]
    fn a_direct_session_keeps_the_providers_own_routes() {
        let result = inspect(CONFIG).unwrap();
        assert_eq!(
            result.tunnel_address,
            "10.88.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(result.endpoint, "vpn.example:51820");
        // The node is the last hop, so its full-tunnel routes have to survive.
        assert!(result.source.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        // Side effects the client applies itself are still dropped.
        assert!(!result.source.contains("DNS ="));
        assert!(!result.source.contains("MTU ="));
    }

    #[test]
    fn a_direct_session_rejects_the_same_broken_configurations() {
        assert!(inspect("[Interface]\nAddress = 10.0.0.2/32\n").is_err());
        assert!(
            inspect(&format!(
                "{CONFIG}\n[Peer]\nPublicKey = another\nEndpoint = other.example:51820\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn reads_an_optional_interface_mtu_without_preserving_it_at_runtime() {
        assert_eq!(interface_mtu(CONFIG), Some(1280));
        assert_eq!(interface_mtu("[Peer]\nMTU = 1400"), None);
        assert_eq!(interface_mtu("[Interface]\nMTU = not-a-number"), None);
    }

    #[test]
    fn multiple_peers_are_rejected_until_peer_selection_exists() {
        let input =
            format!("{CONFIG}\n[Peer]\nPublicKey = another\nEndpoint = other.example:51820\n");
        assert!(narrow_to_relay(&input, "203.0.113.8".parse().unwrap()).is_err());
    }
}
