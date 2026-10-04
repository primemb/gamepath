//! The privileged engine child each session slot runs its data plane in.

use crate::slot::SlotId;
use serde_json::{Value, json};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long a request may go unanswered. A request reads the engine's reply
/// while holding its slot's lock, so an engine stuck mid-command used to hold
/// the slot forever: observed live, a stop that never returned left both
/// L2TP/IPsec connections up, and Windows could not hang them up either.
fn request_timeout(command: &str) -> Duration {
    match command {
        "hello" | "wireguard-session-status" | "packet-capture-status" | "socks-server-status" => {
            Duration::from_secs(10)
        }
        // The engine's own teardown normally takes a second or two; past this,
        // ending the process is the teardown.
        "stop-wireguard-session" => Duration::from_secs(15),
        // Dials and handshakes: an L2TP/IPsec or OpenVPN start can take most
        // of a minute on a slow node.
        _ => Duration::from_secs(120),
    }
}

pub(crate) struct EngineProcess {
    pub(crate) child: Child,
    job: isize,
    stdin: ChildStdin,
    /// Response lines, read on a thread of their own so a request can give up.
    responses: mpsc::Receiver<String>,
    next_id: u64,
}

impl EngineProcess {
    /// Starts the engine for `slot`. The game slot passes no role, so its
    /// engine runs exactly as it did before slots existed.
    pub(crate) fn start(slot: SlotId) -> Result<Self, String> {
        let executable = env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .ok_or("service executable has no parent directory")?
            .join("gamepath-engine.exe");
        if !executable.is_file() {
            return Err(format!(
                "native engine is missing: {}",
                executable.display()
            ));
        }
        let mut command = Command::new(executable);
        if slot == SlotId::Vpn {
            command.args(["--role", "vpn"]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|error| format!("could not start native engine: {error}"))?;
        let job = match create_kill_on_close_job(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let stdin = child
            .stdin
            .take()
            .ok_or("native engine stdin is unavailable")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("native engine stdout is unavailable")?;
        let (lines, responses) = mpsc::channel();
        thread::Builder::new()
            .name(format!("engine-{}-responses", slot.as_str()))
            .spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if lines.send(line).is_err() {
                        break;
                    }
                }
            })
            .map_err(|error| format!("could not read native engine responses: {error}"))?;
        let mut process = Self {
            child,
            job,
            stdin,
            responses,
            next_id: 1,
        };
        process.request("hello", json!({}))?;
        Ok(process)
    }

    pub(crate) fn request(&mut self, command: &str, payload: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        serde_json::to_writer(
            &mut self.stdin,
            &json!({ "id": id, "command": command, "payload": payload }),
        )
        .map_err(|error| error.to_string())?;
        self.stdin
            .write_all(b"\n")
            .and_then(|_| self.stdin.flush())
            .map_err(|error| format!("native engine request failed: {error}"))?;
        let response = await_response(&self.responses, id, command)?;
        if response["ok"].as_bool() != Some(true) {
            return Err(response["error"]
                .as_str()
                .unwrap_or("native engine request failed")
                .to_owned());
        }
        Ok(response["result"].clone())
    }

    /// Asks the engine to remove what it installed before it is killed. A
    /// bare kill skips the engine's own teardown, which is what removes its
    /// half-default routes; without it they outlive the session.
    pub(crate) fn shut_down(mut self) {
        if let Err(error) = self.request("stop-wireguard-session", json!({})) {
            gamepath_engine::log_warn!("{error}; ending the engine process instead");
        }
    }
}

/// The reply to request `id`, skipping late replies to requests that already
/// gave up, or an error once `command`'s time is up.
fn await_response(
    responses: &mpsc::Receiver<String>,
    id: u64,
    command: &str,
) -> Result<Value, String> {
    let timeout = request_timeout(command);
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = match responses.recv_timeout(remaining) {
            Ok(line) => line,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(format!(
                    "native engine did not answer {command} within {} s",
                    timeout.as_secs()
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("native engine stopped unexpectedly".into());
            }
        };
        let response: Value = serde_json::from_str(&line)
            .map_err(|error| format!("invalid native engine response: {error}"))?;
        match response["id"].as_u64() {
            Some(answered) if answered == id => return Ok(response),
            Some(answered) if answered < id => continue,
            _ => return Err("native engine returned a mismatched response".into()),
        }
    }
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        unsafe {
            CloseHandle(self.job);
        }
    }
}

fn create_kill_on_close_job(child: &Child) -> Result<isize, String> {
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job == 0 {
            return Err(format!(
                "could not create engine job: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        let assigned = if configured != 0 {
            AssignProcessToJobObject(job, child.as_raw_handle() as isize)
        } else {
            0
        };
        if configured == 0 || assigned == 0 {
            let error = std::io::Error::last_os_error();
            CloseHandle(job);
            return Err(format!("could not contain engine process: {error}"));
        }
        Ok(job)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_reply_to_an_abandoned_request_is_skipped() {
        let (lines, responses) = mpsc::channel();
        lines.send(r#"{"id":3,"ok":true}"#.to_owned()).unwrap();
        lines
            .send(r#"{"id":4,"ok":true,"result":1}"#.to_owned())
            .unwrap();
        let response = await_response(&responses, 4, "wireguard-session-status").unwrap();
        assert_eq!(response["result"], 1);
    }

    #[test]
    fn an_engine_that_never_answers_releases_the_caller() {
        let (_lines, responses) = mpsc::channel::<String>();
        let started = Instant::now();
        let error = await_response(&responses, 1, "wireguard-session-status").unwrap_err();
        assert!(error.contains("did not answer"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(12));
    }

    #[test]
    fn an_engine_that_exits_is_reported_at_once() {
        let (lines, responses) = mpsc::channel::<String>();
        drop(lines);
        let error = await_response(&responses, 1, "stop-wireguard-session").unwrap_err();
        assert!(error.contains("stopped unexpectedly"), "{error}");
    }

    #[test]
    fn stopping_is_bounded_and_starting_is_given_time_to_dial() {
        assert_eq!(
            request_timeout("stop-wireguard-session"),
            Duration::from_secs(15)
        );
        assert!(request_timeout("start-wireguard-session") >= Duration::from_secs(60));
    }
}
