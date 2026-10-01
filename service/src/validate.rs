//! Checks a session request before anything is opened. Pure: validating one
//! slot never touches the state of a session that is already running.

use crate::slot::SlotId;
use gamepath_engine::relay_path::{NodeSpec, SessionMode};
use gamepath_engine::wireguard_runtime::{inspect, narrow_to_relay};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValidateRequest {
    /// Absent for callers written before direct sessions existed, all of
    /// which meant a relay session.
    #[serde(default)]
    pub(crate) mode: SessionMode,
    /// A direct session has no relay to narrow the tunnels towards.
    #[serde(default)]
    relay_ip: Option<IpAddr>,
    traffic_mode: String,
    #[serde(default)]
    nodes: Vec<NodeSpec>,
    #[serde(default)]
    wireguard_configs: Vec<String>,
}

impl ValidateRequest {
    /// Callers may send the tagged node list or, for WireGuard-only
    /// sessions, the original flat configuration list.
    pub(crate) fn resolved_nodes(&self) -> Vec<NodeSpec> {
        if !self.nodes.is_empty() {
            return self.nodes.clone();
        }
        self.wireguard_configs
            .iter()
            .map(|config| NodeSpec::WireGuard {
                config: config.clone(),
                label: None,
            })
            .collect()
    }
}

/// Whether `node` can carry a direct session in `slot`.
///
/// The VPN slot also takes a SOCKS5 proxy: its engine terminates the captured
/// connections itself and replays them through the proxy. The game slot does
/// not, because game traffic is UDP that must not be re-originated.
pub(crate) fn carries_direct(slot: SlotId, node: &NodeSpec) -> bool {
    node.supports_direct() || (slot == SlotId::Vpn && matches!(node, NodeSpec::Socks5 { .. }))
}

pub(crate) fn validate_runtime(payload: Value, slot: SlotId) -> Result<Value, String> {
    let input: ValidateRequest = serde_json::from_value(payload)
        .map_err(|error| format!("invalid runtime request: {error}"))?;
    if input.traffic_mode != "all" && input.traffic_mode != "split" {
        return Err("traffic mode must be all or split".into());
    }
    let nodes = input.resolved_nodes();
    if nodes.is_empty() {
        return Err(
            "at least one WireGuard, OpenVPN, L2TP/IPsec, or SOCKS5 node is required".into(),
        );
    }
    if slot == SlotId::Vpn && input.mode != SessionMode::Direct {
        return Err("the VPN connects straight to its node and cannot use a relay".into());
    }
    // A direct session has no relay behind the node, so the node itself has
    // to be able to route. Catch that here, before anything is opened.
    if input.mode == SessionMode::Direct {
        if nodes.len() != 1 {
            return Err(format!(
                "direct mode sends traffic through exactly one node, but {} are enabled. \
                 Enable a single WireGuard, OpenVPN, or L2TP/IPsec node, or switch to relay mode to combine them.",
                nodes.len()
            ));
        }
        if !carries_direct(slot, &nodes[0]) {
            return Err(format!(
                "{} cannot carry a direct session on its own. Use a WireGuard, OpenVPN, or L2TP/IPsec node for \
                 direct mode, or set up a relay to reach this proxy through.",
                nodes[0].describe()
            ));
        }
    }
    let mut tunnel_addresses = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        let route = index + 1;
        node.validate()
            .map_err(|error| format!("route {route}: {error}"))?;
        // A proxy on this machine reaches its own upstream over the default
        // route. In all-traffic mode the tunnel owns that route, so the
        // proxy's forwarded traffic would be captured and fed back into it.
        if input.traffic_mode == "all" && node.is_loopback_proxy() {
            return Err(format!(
                "route {route} ({}) runs on this PC and cannot be used in all-traffic mode, \
                 because its own upstream traffic would be captured and looped back. \
                 Use split-tunnel mode for a local proxy, or add a remote SOCKS5 proxy.",
                node.describe()
            ));
        }
        if let NodeSpec::WireGuard { config, .. } = node {
            // A relay session narrows the tunnel to the relay alone; a
            // direct session keeps the routes the provider shipped.
            let runtime = match input.relay_ip.filter(|_| input.mode == SessionMode::Relay) {
                Some(relay_ip) => narrow_to_relay(config, relay_ip),
                None if input.mode == SessionMode::Relay => {
                    Err("a relay session needs the relay address".to_owned())
                }
                None => inspect(config),
            };
            tunnel_addresses.push(
                runtime
                    .map_err(|error| format!("route {route}: {error}"))?
                    .tunnel_address,
            );
        }
    }
    Ok(json!({
        "sessionStatus": "validated",
        "slot": slot.as_str(),
        "mode": input.mode.as_str(),
        "routeCount": nodes.len(),
        "trafficMode": input.traffic_mode,
        "tunnelAddresses": tunnel_addresses,
        "nodeKinds": nodes.iter().map(NodeSpec::kind).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIREGUARD_CONFIG: &str = "[Interface]\nPrivateKey = key\nAddress = 10.88.0.2/32\n\n[Peer]\nPublicKey = peer\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example:51820\n";
    const OPENVPN_CONFIG: &str = "client\ndev tun\nremote vpn.example 1194 udp\nauth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIBIjCByaADAgECAgEBMAoGCCqGSM49BAMCMBIxEDAOBgNVBAMMB1Rlc3QgQ0Ew\n-----END CERTIFICATE-----\n</ca>\n";

    fn validate(traffic_mode: &str, nodes: Value) -> Result<Value, String> {
        validate_runtime(
            json!({
                "relayIp": "203.0.113.8",
                "trafficMode": traffic_mode,
                "nodes": nodes,
            }),
            SlotId::Game,
        )
    }

    fn validate_direct(nodes: Value) -> Result<Value, String> {
        // A direct session sends no relay address at all.
        validate_runtime(
            json!({ "mode": "direct", "trafficMode": "split", "nodes": nodes }),
            SlotId::Game,
        )
    }

    fn validate_vpn(nodes: Value) -> Result<Value, String> {
        validate_runtime(
            json!({ "mode": "direct", "trafficMode": "split", "nodes": nodes }),
            SlotId::Vpn,
        )
    }

    #[test]
    fn a_wireguard_and_socks5_pair_validates_together() {
        let result = validate(
            "split",
            json!([
                { "kind": "wireguard", "config": WIREGUARD_CONFIG },
                { "kind": "socks5", "host": "127.0.0.1", "port": 2080 },
            ]),
        )
        .unwrap();
        assert_eq!(result["routeCount"], 2);
        assert_eq!(result["nodeKinds"][0], "wireguard");
        assert_eq!(result["nodeKinds"][1], "socks5");
        // Only WireGuard routes have a tunnel address to narrow.
        assert_eq!(result["tunnelAddresses"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_local_proxy_is_refused_in_all_traffic_mode() {
        let error = validate(
            "all",
            json!([{ "kind": "socks5", "host": "127.0.0.1", "port": 2080 }]),
        )
        .err()
        .unwrap();
        assert!(error.contains("looped back"), "{error}");
        // The same node is fine when only selected traffic is captured.
        assert!(
            validate(
                "split",
                json!([{ "kind": "socks5", "host": "127.0.0.1", "port": 2080 }]),
            )
            .is_ok()
        );
        // A remote proxy is fine in either mode.
        assert!(
            validate(
                "all",
                json!([{ "kind": "socks5", "host": "203.0.113.9", "port": 1080 }]),
            )
            .is_ok()
        );
    }

    #[test]
    fn a_direct_session_keeps_the_nodes_own_routes() {
        let result =
            validate_direct(json!([{ "kind": "wireguard", "config": WIREGUARD_CONFIG }])).unwrap();
        assert_eq!(result["mode"], "direct");
        assert_eq!(result["routeCount"], 1);
        assert_eq!(result["tunnelAddresses"][0], "10.88.0.2");
        // The default is still a relay session, for callers that send no mode.
        assert_eq!(
            validate(
                "split",
                json!([{ "kind": "wireguard", "config": WIREGUARD_CONFIG }])
            )
            .unwrap()["mode"],
            "relay"
        );

        // OpenVPN is also a tunnelling node: it is valid as the direct
        // session's only hop and needs neither a relay address nor a
        // WireGuard runtime inspection.
        let openvpn = validate_direct(json!([{
            "kind": "openvpn",
            "config": OPENVPN_CONFIG,
            "username": "someone",
            "password": "secret",
        }]))
        .unwrap();
        assert_eq!(openvpn["mode"], "direct");
        assert_eq!(openvpn["routeCount"], 1);
        assert_eq!(openvpn["nodeKinds"][0], "openvpn");

        let l2tp = validate_direct(json!([{
            "kind": "l2tp",
            "server": "vpn.example",
            "username": "someone",
            "password": "secret",
            "preSharedKey": "shared-secret",
        }]))
        .unwrap();
        assert_eq!(l2tp["mode"], "direct");
        assert_eq!(l2tp["routeCount"], 1);
        assert_eq!(l2tp["nodeKinds"][0], "l2tp");
    }

    #[test]
    fn a_direct_session_turns_away_nodes_it_cannot_route_through() {
        let error =
            validate_direct(json!([{ "kind": "socks5", "host": "proxy.example", "port": 1080 }]))
                .err()
                .unwrap();
        assert!(
            error.contains("WireGuard, OpenVPN, or L2TP/IPsec node for direct mode"),
            "{error}"
        );
        assert!(error.contains("relay"), "{error}");

        let error = validate_direct(json!([
            { "kind": "wireguard", "config": WIREGUARD_CONFIG },
            { "kind": "wireguard", "config": WIREGUARD_CONFIG },
        ]))
        .err()
        .unwrap();
        assert!(error.contains("exactly one node"), "{error}");

        // A broken configuration is still caught the same way.
        assert!(
            validate_direct(json!([{ "kind": "wireguard", "config": "[Interface]" }])).is_err()
        );
    }

    #[test]
    fn the_vpn_takes_a_socks5_proxy_that_the_game_refuses() {
        let proxy = json!([{ "kind": "socks5", "host": "proxy.example", "port": 1080 }]);
        assert!(validate_direct(proxy.clone()).is_err());
        let result = validate_vpn(proxy).unwrap();
        assert_eq!(result["slot"], "vpn");
        assert_eq!(result["nodeKinds"][0], "socks5");
    }

    #[test]
    fn the_vpn_never_goes_through_a_relay_and_carries_one_node() {
        let error = validate_runtime(
            json!({
                "relayIp": "203.0.113.8",
                "trafficMode": "split",
                "nodes": [{ "kind": "wireguard", "config": WIREGUARD_CONFIG }],
            }),
            SlotId::Vpn,
        )
        .unwrap_err();
        assert!(error.contains("cannot use a relay"), "{error}");

        let error = validate_vpn(json!([
            { "kind": "wireguard", "config": WIREGUARD_CONFIG },
            { "kind": "socks5", "host": "proxy.example", "port": 1080 },
        ]))
        .unwrap_err();
        assert!(error.contains("exactly one node"), "{error}");
    }

    #[test]
    fn a_relay_session_still_needs_its_relay_address() {
        let error = validate_runtime(
            json!({
                "trafficMode": "split",
                "nodes": [{ "kind": "wireguard", "config": WIREGUARD_CONFIG }],
            }),
            SlotId::Game,
        )
        .err()
        .unwrap();
        assert!(error.contains("relay address"), "{error}");
    }

    #[test]
    fn a_malformed_node_names_its_route() {
        let error = validate(
            "split",
            json!([
                { "kind": "socks5", "host": "proxy.example", "port": 1080 },
                { "kind": "socks5", "host": "proxy.example", "port": 0 },
            ]),
        )
        .err()
        .unwrap();
        assert!(error.starts_with("route 2:"), "{error}");
    }

    #[test]
    fn a_wireguard_only_request_still_validates_without_the_node_list() {
        let result = validate_runtime(
            json!({
                "relayIp": "203.0.113.8",
                "trafficMode": "all",
                "wireguardConfigs": [WIREGUARD_CONFIG],
            }),
            SlotId::Game,
        )
        .unwrap();
        assert_eq!(result["routeCount"], 1);
        assert_eq!(result["tunnelAddresses"][0], "10.88.0.2");
    }
}
