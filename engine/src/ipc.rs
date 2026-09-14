//! The JSON-RPC vocabulary the service speaks to the engine over stdio.
//!
//! Every request the engine accepts is deserialised into one of these, so the
//! shape of the protocol is readable in one place rather than spread across
//! the handlers that act on it.

use gamepath_engine::policy::RuleSpec;
use gamepath_engine::relay_path::{NodeSpec, SessionMode};
use gamepath_engine::scheduler::Strategy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub(crate) struct Request {
    pub(crate) id: u64,
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) payload: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct Response {
    pub(crate) id: u64,
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareRequest {
    pub(crate) route_ids: Vec<String>,
    pub(crate) traffic_mode: String,
    pub(crate) rules: Vec<RuleSpec>,
    /// Absent for callers written before direct sessions existed.
    #[serde(default)]
    pub(crate) mode: SessionMode,
    /// A direct session has no relay, so these three carry nothing there.
    #[serde(default)]
    pub(crate) relay_host: String,
    #[serde(default)]
    pub(crate) relay_port: u16,
    #[serde(default)]
    pub(crate) enrollment_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProbeRequest {
    pub(crate) relay_host: String,
    pub(crate) relay_port: u16,
    pub(crate) enrollment_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireGuardProbeRequest {
    pub(crate) relay_host: String,
    pub(crate) relay_port: u16,
    pub(crate) enrollment_token: String,
    pub(crate) wireguard_configs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionRequest {
    /// Absent for callers written before direct sessions existed, all of which
    /// meant a relay session.
    #[serde(default)]
    pub(crate) mode: SessionMode,
    /// A direct session has no relay, so these three carry nothing there.
    #[serde(default)]
    pub(crate) relay_host: String,
    #[serde(default)]
    pub(crate) relay_port: u16,
    #[serde(default)]
    pub(crate) enrollment_token: String,
    #[serde(default)]
    pub(crate) nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub(crate) wireguard_configs: Vec<String>,
    #[serde(default)]
    pub(crate) route_labels: Vec<String>,
    /// Smart is the safe default; all-paths is an explicit user choice for
    /// sending each packet on every healthy enabled route.
    #[serde(default = "default_relay_strategy")]
    pub(crate) strategy: Strategy,
}

fn default_relay_strategy() -> Strategy {
    Strategy::Adaptive
}

impl SessionRequest {
    /// Callers may send the tagged node list or, for WireGuard-only sessions,
    /// the original flat configuration list.
    pub(crate) fn resolved_nodes(&self) -> Vec<NodeSpec> {
        if !self.nodes.is_empty() {
            return self.nodes.clone();
        }
        self.wireguard_configs
            .iter()
            .enumerate()
            .map(|(index, config)| NodeSpec::WireGuard {
                config: config.clone(),
                label: self.route_labels.get(index).cloned(),
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Socks5ProbeRequest {
    pub(crate) relay_host: String,
    pub(crate) relay_port: u16,
    pub(crate) enrollment_token: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PacketCaptureRequest {
    pub(crate) traffic_mode: String,
    #[serde(default)]
    pub(crate) rules: Vec<RuleSpec>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamepath_engine::relay_path::NodeSpec;
    use serde_json::json;

    fn session_request(payload: Value) -> SessionRequest {
        serde_json::from_value(payload).unwrap()
    }

    #[test]
    fn a_tagged_node_list_keeps_its_order_and_kinds() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "nodes": [
                { "kind": "wireguard", "config": "[Interface]", "label": "Provider A" },
                { "kind": "socks5", "host": "127.0.0.1", "port": 2080, "label": "Local proxy" },
                { "kind": "socks5", "host": "proxy.example", "port": 1080,
                  "username": "player", "password": "secret" },
            ],
        }));
        let nodes = request.resolved_nodes();
        assert_eq!(nodes.len(), 3);
        assert!(matches!(nodes[0], NodeSpec::WireGuard { .. }));
        assert_eq!(nodes[0].label().as_deref(), Some("Provider A"));
        assert_eq!(nodes[1].label().as_deref(), Some("Local proxy"));
        assert_eq!(nodes[1].describe(), "SOCKS5 proxy 127.0.0.1:2080");
        assert_eq!(nodes[2].label(), None);
        assert_eq!(nodes[2].default_label(3), "SOCKS5 route 3");
        assert!(matches!(
            &nodes[2],
            NodeSpec::Socks5 { username, password, .. }
                if username.as_deref() == Some("player") && password.as_deref() == Some("secret")
        ));
    }

    #[test]
    fn a_wireguard_only_request_still_works_without_the_node_list() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "wireguardConfigs": ["[Interface] one", "[Interface] two"],
            "routeLabels": ["Falcon", "  "],
        }));
        let nodes = request.resolved_nodes();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].label().as_deref(), Some("Falcon"));
        // A blank label falls back to the generated route name.
        assert_eq!(nodes[1].label(), None);
        assert_eq!(nodes[1].default_label(2), "WireGuard route 2");
    }

    #[test]
    fn a_request_without_a_mode_still_means_a_relay_session() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "wireguardConfigs": ["[Interface] one"],
        }));
        assert_eq!(request.mode, SessionMode::Relay);
        assert_eq!(request.strategy, Strategy::Adaptive);
    }

    #[test]
    fn a_manual_request_keeps_all_healthy_paths_enabled() {
        let request = session_request(json!({
            "relayHost": "relay.example",
            "relayPort": 51821,
            "enrollmentToken": "gpe1_token",
            "strategy": "all-paths",
            "wireguardConfigs": ["[Interface] one"],
        }));
        assert_eq!(request.strategy, Strategy::AllPaths);
    }

    #[test]
    fn a_direct_request_carries_no_relay_details() {
        let request = session_request(json!({
            "mode": "direct",
            "nodes": [{ "kind": "wireguard", "config": "[Interface]", "label": "Provider A" }],
        }));
        assert_eq!(request.mode, SessionMode::Direct);
        assert_eq!(request.mode.as_str(), "direct");
        assert!(request.relay_host.is_empty());
        assert_eq!(request.relay_port, 0);
        assert!(request.enrollment_token.is_empty());
        assert_eq!(request.resolved_nodes().len(), 1);
    }
}
