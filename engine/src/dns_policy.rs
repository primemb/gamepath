//! Ownership of classic DNS when the game and VPN coexist.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsRoute {
    Normal,
    Remote,
}

pub fn route(
    remote_enabled: bool,
    own_apps_only: bool,
    yield_foreign_apps: bool,
    rule_selected: bool,
    application_owned: bool,
    bootstrap: bool,
) -> DnsRoute {
    if !remote_enabled || bootstrap {
        return DnsRoute::Normal;
    }
    if rule_selected || (!own_apps_only && !(yield_foreign_apps && application_owned)) {
        DnsRoute::Remote
    } else {
        DnsRoute::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_owns_shared_dns_and_vpn_owns_its_selected_apps() {
        assert_eq!(
            route(true, false, true, false, false, false),
            DnsRoute::Remote
        );
        assert_eq!(
            route(true, false, true, false, true, false),
            DnsRoute::Normal
        );
        assert_eq!(
            route(true, true, false, true, true, false),
            DnsRoute::Remote
        );
        assert_eq!(
            route(true, true, false, false, false, false),
            DnsRoute::Normal
        );
        assert_eq!(
            route(true, true, false, false, true, false),
            DnsRoute::Normal
        );
        // An overlapping game rule always wins before the VPN sees the lookup.
        assert_eq!(
            route(true, false, true, true, true, false),
            DnsRoute::Remote
        );
    }

    #[test]
    fn unknown_ownership_uses_game_and_remote_off_preserves_normal_dns() {
        assert_eq!(
            route(true, false, true, false, false, false),
            DnsRoute::Remote
        );
        for selected in [false, true] {
            assert_eq!(
                route(false, false, false, selected, false, false),
                DnsRoute::Normal
            );
            assert_eq!(
                route(true, false, false, selected, false, true),
                DnsRoute::Normal
            );
        }
    }
}
