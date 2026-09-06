use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSpec {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterceptionPlan {
    pub mode: String,
    pub backend: String,
    pub application_paths: Vec<String>,
    pub folder_prefixes: Vec<String>,
    pub hostnames: Vec<String>,
    pub ip_networks: Vec<String>,
    pub protocols: Vec<String>,
}

pub fn compile(mode: &str, rules: &[RuleSpec]) -> Result<InterceptionPlan, String> {
    if mode == "all" {
        return Ok(InterceptionPlan {
            mode: mode.into(),
            backend: "wintun".into(),
            application_paths: Vec::new(),
            folder_prefixes: Vec::new(),
            hostnames: Vec::new(),
            ip_networks: Vec::new(),
            protocols: vec!["udp".into(), "tcp".into()],
        });
    }
    if mode != "split" {
        return Err("traffic mode must be all or split".into());
    }
    if rules.is_empty() {
        return Err("split mode requires at least one target".into());
    }

    let mut plan = InterceptionPlan {
        mode: mode.into(),
        backend: "wfp".into(),
        application_paths: Vec::new(),
        folder_prefixes: Vec::new(),
        hostnames: Vec::new(),
        ip_networks: Vec::new(),
        protocols: vec!["udp".into(), "tcp".into()],
    };
    for rule in rules {
        let value = rule.value.trim();
        if value.is_empty() {
            return Err(format!("{} target cannot be empty", rule.kind));
        }
        match rule.kind.as_str() {
            "application" => {
                let path = Path::new(value);
                if !path.is_absolute()
                    || !path
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
                {
                    return Err(format!(
                        "application target must be an absolute .exe path: {value}"
                    ));
                }
                plan.application_paths.push(normalize_windows_path(value));
            }
            "folder" => {
                if !Path::new(value).is_absolute() {
                    return Err(format!("folder target must be an absolute path: {value}"));
                }
                plan.folder_prefixes.push(
                    normalize_windows_path(value)
                        .trim_end_matches('\\')
                        .to_owned(),
                );
            }
            "hostname" => plan.hostnames.push(normalize_hostname(value)?),
            "ip" => plan.ip_networks.push(normalize_ip_network(value)?),
            other => return Err(format!("unsupported target type: {other}")),
        }
    }
    Ok(plan)
}

fn normalize_windows_path(value: &str) -> String {
    value.replace('/', "\\").to_lowercase()
}

fn normalize_hostname(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('.').to_lowercase();
    let host = value.strip_prefix("*.").unwrap_or(&value);
    if host.is_empty()
        || host.contains("://")
        || host.contains('/')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return Err(format!("invalid hostname target: {value}"));
    }
    Ok(if value.starts_with("*.") {
        format!("*.{host}")
    } else {
        host.into()
    })
}

fn normalize_ip_network(value: &str) -> Result<String, String> {
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("invalid IP target: {value}"))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid CIDR prefix: {value}"))?,
        None => max_prefix,
    };
    if prefix > max_prefix {
        return Err(format!("CIDR prefix is out of range: {value}"));
    }
    Ok(format!("{address}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_traffic_uses_wintun_without_rules() {
        let plan = compile("all", &[]).unwrap();
        assert_eq!(plan.backend, "wintun");
    }

    #[test]
    fn split_rules_compile_to_wfp_policy() {
        let rules = vec![
            RuleSpec {
                kind: "application".into(),
                value: r"C:\Games\Demo\game.exe".into(),
            },
            RuleSpec {
                kind: "folder".into(),
                value: r"C:\Games\Demo".into(),
            },
            RuleSpec {
                kind: "hostname".into(),
                value: "*.Game.Example.COM".into(),
            },
            RuleSpec {
                kind: "ip".into(),
                value: "203.0.113.0/24".into(),
            },
        ];
        let plan = compile("split", &rules).unwrap();
        assert_eq!(plan.backend, "wfp");
        assert_eq!(plan.hostnames, ["*.game.example.com"]);
        assert_eq!(plan.ip_networks, ["203.0.113.0/24"]);
    }

    #[test]
    fn bad_cidr_is_rejected() {
        let rules = [RuleSpec {
            kind: "ip".into(),
            value: "10.0.0.0/44".into(),
        }];
        assert!(compile("split", &rules).is_err());
    }
}
