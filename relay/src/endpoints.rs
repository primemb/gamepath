use gamepath_engine::path_policy::PathPolicy;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const CAPACITY: usize = 8;
const TTL: Duration = Duration::from_secs(45);

struct Endpoint {
    address: SocketAddr,
    seen: Instant,
    policy: Option<PathPolicy>,
}

pub(crate) struct Endpoints {
    entries: Vec<Endpoint>,
    policy_sequences: [Option<u64>; 64],
    selective: bool,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            policy_sequences: [None; 64],
            selective: false,
        }
    }
}

impl Endpoints {
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|entry| now.duration_since(entry.seen) <= TTL);
    }

    pub(crate) fn observe(&mut self, address: SocketAddr, now: Instant) {
        self.prune(now);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            entry.seen = now;
        } else {
            if self.entries.len() >= CAPACITY {
                self.entries.sort_by_key(|entry| entry.seen);
                self.entries.remove(0);
            }
            self.entries.push(Endpoint {
                address,
                seen: now,
                policy: None,
            });
        }
    }

    pub(crate) fn apply(
        &mut self,
        address: SocketAddr,
        policy: PathPolicy,
        sequence: u64,
        now: Instant,
    ) {
        let previous = &mut self.policy_sequences[usize::from(policy.path)];
        if previous.is_some_and(|previous| sequence <= previous) {
            return;
        }
        *previous = Some(sequence);
        self.selective = true;
        // A NAT rebind or redial replaces this path's endpoint. Its delayed
        // packets must not leave a second return destination alive for 45 s.
        self.entries.retain(|entry| {
            entry.address == address || !entry.policy.is_some_and(|old| old.path == policy.path)
        });
        self.observe(address, now);
        self.entries
            .iter_mut()
            .find(|entry| entry.address == address)
            .unwrap()
            .policy = Some(policy);
    }

    pub(crate) fn targets(&mut self, now: Instant) -> impl Iterator<Item = SocketAddr> + '_ {
        self.prune(now);
        let selected = self
            .entries
            .iter()
            .any(|entry| !self.selective || entry.policy.is_some_and(|policy| policy.selected));
        // Selection messages can be lost or reordered across transports.
        // Keep one recently authenticated route usable through that gap,
        // rather than blackholing replies or multiplying them onto every node.
        let fallback = if selected {
            None
        } else {
            self.entries
                .iter()
                .max_by_key(|entry| entry.seen)
                .map(|entry| entry.address)
        };
        let selective = self.selective;
        self.entries
            .iter()
            .filter(move |entry| {
                if selected {
                    !selective || entry.policy.is_some_and(|policy| policy.selected)
                } else {
                    Some(entry.address) == fallback
                }
            })
            .map(|entry| entry.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(path: u8) -> SocketAddr {
        ([127, 0, 0, 1], 10000 + u16::from(path)).into()
    }

    #[test]
    fn smart_expands_and_returns_to_two_without_probe_fanout() {
        let now = Instant::now();
        let mut endpoints = Endpoints::default();
        for path in 0..5 {
            endpoints.apply(
                address(path),
                PathPolicy {
                    path,
                    selected: path < 2,
                },
                u64::from(path) + 1,
                now,
            );
        }
        assert_eq!(
            endpoints.targets(now).collect::<Vec<_>>(),
            vec![address(0), address(1)]
        );
        endpoints.apply(
            address(2),
            PathPolicy {
                path: 2,
                selected: true,
            },
            6,
            now,
        );
        assert_eq!(endpoints.targets(now).count(), 3);
        endpoints.apply(
            address(2),
            PathPolicy {
                path: 2,
                selected: false,
            },
            7,
            now,
        );
        for path in 0..5 {
            endpoints.observe(address(path), now + Duration::from_secs(1));
        }
        assert_eq!(
            endpoints
                .targets(now + Duration::from_secs(1))
                .collect::<Vec<_>>(),
            vec![address(0), address(1)]
        );
        endpoints.apply(
            address(2),
            PathPolicy {
                path: 2,
                selected: true,
            },
            6,
            now,
        );
        assert_eq!(
            endpoints.targets(now).count(),
            2,
            "late policy undid recovery"
        );
    }

    #[test]
    fn legacy_and_manual_sessions_use_all_live_endpoints() {
        let now = Instant::now();
        let mut legacy = Endpoints::default();
        let mut manual = Endpoints::default();
        for path in 0..5 {
            legacy.observe(address(path), now);
            manual.apply(
                address(path),
                PathPolicy {
                    path,
                    selected: true,
                },
                u64::from(path) + 1,
                now,
            );
        }
        assert_eq!(legacy.targets(now).count(), 5);
        assert_eq!(manual.targets(now).count(), 5);
        assert!(
            legacy
                .targets(now + TTL + Duration::from_secs(1))
                .next()
                .is_none()
        );
    }

    #[test]
    fn rebind_replaces_endpoint_and_ignores_delayed_old_policy() {
        let now = Instant::now();
        let policy = PathPolicy {
            path: 0,
            selected: true,
        };
        let mut endpoints = Endpoints::default();
        endpoints.apply(address(0), policy, 1, now);
        endpoints.apply(address(1), policy, 2, now);
        endpoints.observe(address(0), now);
        endpoints.apply(address(0), policy, 1, now);
        assert_eq!(endpoints.targets(now).collect::<Vec<_>>(), vec![address(1)]);
    }

    #[test]
    fn lost_selection_update_uses_one_fallback_and_recovers() {
        let now = Instant::now();
        let mut endpoints = Endpoints::default();
        for path in 0..5 {
            endpoints.apply(
                address(path),
                PathPolicy {
                    path,
                    selected: false,
                },
                u64::from(path) + 1,
                now,
            );
        }
        assert_eq!(endpoints.targets(now).count(), 1);
        endpoints.apply(
            address(3),
            PathPolicy {
                path: 3,
                selected: true,
            },
            6,
            now,
        );
        assert_eq!(endpoints.targets(now).collect::<Vec<_>>(), vec![address(3)]);
    }

    #[test]
    fn endpoints_remain_bounded() {
        let now = Instant::now();
        let mut endpoints = Endpoints::default();
        for path in 0..64 {
            endpoints.observe(address(path), now + Duration::from_millis(u64::from(path)));
        }
        assert_eq!(endpoints.len(), CAPACITY);
    }
}
