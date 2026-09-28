//! Lets devices on the local network reach the proxy through Windows Defender
//! Firewall, which blocks unsolicited inbound connections to a service by
//! default.
//!
//! The rule is scoped to this executable and to `LocalSubnet`, so it opens
//! nothing to the Internet and nothing for any other program. It is replaced
//! rather than added so a reinstall to a different directory does not leave a
//! rule pointing at the old path; the uninstaller removes it.

use gamepath_engine::log_warn;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Once;

pub(crate) const RULE_NAME: &str = "GamePath LAN proxy";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Runs once per engine process, off the calling thread: `netsh` takes a few
/// hundred milliseconds and the proxy is already listening meanwhile.
pub(crate) fn allow_inbound() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("gamepath-firewall".into())
            .spawn(|| {
                if let Err(error) = replace_rule() {
                    log_warn!(
                        "could not open the Windows firewall to the LAN proxy; other devices may \
                         not be able to connect: {error}"
                    );
                }
            });
    });
}

fn netsh(arguments: &[String]) -> Result<std::process::Output, String> {
    let mut command = Command::new("netsh");
    command
        .args(["advfirewall", "firewall"])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    for argument in arguments {
        // netsh wants `name="..."` with the quotes inside the token, which
        // ordinary argument quoting would wrap around the whole thing.
        command.raw_arg(argument);
    }
    command.output().map_err(|error| error.to_string())
}

fn replace_rule() -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let name = format!("name=\"{RULE_NAME}\"");
    let _ = netsh(&["delete".into(), "rule".into(), name.clone()]);
    let output = netsh(&[
        "add".into(),
        "rule".into(),
        name,
        "dir=in".into(),
        "action=allow".into(),
        format!("program=\"{}\"", executable.display()),
        "enable=yes".into(),
        "profile=any".into(),
        "remoteip=localsubnet".into(),
    ])?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}
