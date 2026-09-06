use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWireGuardConfig {
    pub source: String,
    pub tunnel_address: IpAddr,
    pub endpoint: String,
}

pub fn narrow_to_relay(input: &str, relay: IpAddr) -> Result<RuntimeWireGuardConfig, String> {
    let relay_route = match relay {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    };
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
                output.push(format!("AllowedIPs = {relay_route}"));
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
                    if !peer_allowed_ips_written {
                        output.push(format!("AllowedIPs = {relay_route}"));
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
        output.push(format!("AllowedIPs = {relay_route}"));
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
    fn multiple_peers_are_rejected_until_peer_selection_exists() {
        let input =
            format!("{CONFIG}\n[Peer]\nPublicKey = another\nEndpoint = other.example:51820\n");
        assert!(narrow_to_relay(&input, "203.0.113.8".parse().unwrap()).is_err());
    }
}
