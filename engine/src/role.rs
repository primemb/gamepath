//! Which session this engine process carries: the game, or the VPN beside it.
//!
//! The service runs one engine child per session. Everything two children
//! could fight over — the Wintun adapter, the WinDivert priority, the log
//! file — and how hard each competes for the CPU, is decided here, once, from
//! the process's command line. A process without `--role` is the game engine,
//! which is what every caller written before the VPN existed starts.

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Game,
    Vpn,
}

/// A Wintun adapter is identified by its GUID as well as its name, and two
/// processes opening the same one would overwrite each other's addresses,
/// routes and resolvers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    pub name: &'static str,
    pub guid: u128,
}

static CURRENT: OnceLock<Role> = OnceLock::new();

impl Role {
    /// Reads `--role <game|vpn>`. Anything else is refused rather than
    /// guessed, since a VPN engine mistaken for the game would outrank it.
    pub fn from_args<I: IntoIterator<Item = String>>(arguments: I) -> Result<Self, String> {
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            if argument == "--role" {
                return match arguments.next().as_deref() {
                    Some("game") => Ok(Self::Game),
                    Some("vpn") => Ok(Self::Vpn),
                    other => Err(format!("unknown engine role: {}", other.unwrap_or(""))),
                };
            }
        }
        Ok(Self::Game)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Game => "game",
            Self::Vpn => "vpn",
        }
    }

    /// The log file this process writes, so two engines never interleave
    /// lines or race each other's rotation.
    pub fn log_component(self) -> &'static str {
        match self {
            Self::Game => "engine",
            Self::Vpn => "engine-vpn",
        }
    }

    /// WinDivert hands a packet to higher-priority handles first, and a
    /// packet one handle reinjects is only seen by handles of lower priority.
    /// The game keeps the default it always had; the VPN sits below it, so it
    /// only ever sees what the game let through.
    pub fn capture_priority(self) -> i16 {
        match self {
            Self::Game => 0,
            Self::Vpn => -1000,
        }
    }

    pub fn adapter(self) -> AdapterIdentity {
        match self {
            Self::Game => AdapterIdentity {
                name: "GamePath",
                guid: 0x7f0a_9828_52ef_4ddd_913d_c11f_f0d4_a58a,
            },
            Self::Vpn => AdapterIdentity {
                name: "GamePath VPN",
                guid: 0x3c1d_5b7e_8a42_4f6e_b1d9_6e2a_7c90_4f13,
            },
        }
    }

    /// Whether data-plane threads run at `THREAD_PRIORITY_HIGHEST`. The VPN's
    /// run one step lower, so under a busy CPU the game's packets go first.
    pub fn data_plane_highest(self) -> bool {
        self == Self::Game
    }

    /// Fixes this process's role. Called once, before any thread starts.
    pub fn install(self) {
        let _ = CURRENT.set(self);
    }

    pub fn current() -> Self {
        *CURRENT.get().unwrap_or(&Self::Game)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn an_engine_started_without_a_role_is_the_game() {
        assert_eq!(Role::from_args(args(&["engine.exe"])).unwrap(), Role::Game);
        assert_eq!(
            Role::from_args(args(&["engine.exe", "--role", "vpn"])).unwrap(),
            Role::Vpn
        );
        assert!(Role::from_args(args(&["engine.exe", "--role", "relay"])).is_err());
        assert!(Role::from_args(args(&["engine.exe", "--role"])).is_err());
    }

    #[test]
    fn the_game_keeps_everything_it_had_before_roles_existed() {
        let game = Role::Game;
        assert_eq!(game.log_component(), "engine");
        assert_eq!(game.capture_priority(), 0);
        assert_eq!(game.adapter().name, "GamePath");
        assert_eq!(
            game.adapter().guid,
            0x7f0a_9828_52ef_4ddd_913d_c11f_f0d4_a58a
        );
        assert!(game.data_plane_highest());
    }

    #[test]
    fn the_vpn_yields_to_the_game_and_shares_nothing_with_it() {
        let (game, vpn) = (Role::Game, Role::Vpn);
        assert!(vpn.capture_priority() < game.capture_priority());
        assert_ne!(vpn.adapter().guid, game.adapter().guid);
        assert_ne!(vpn.adapter().name, game.adapter().name);
        assert_ne!(vpn.log_component(), game.log_component());
        assert!(!vpn.data_plane_highest());
        // The service's stale-route cleanup matches adapters by this prefix.
        assert!(vpn.adapter().name.starts_with("GamePath"));
    }
}
