//! The privileged engine child each session slot runs its data plane in.

use crate::slot::SlotId;
use serde_json::{Value, json};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) struct EngineProcess {
    pub(crate) child: Child,
    job: isize,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
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
        let mut process = Self {
            child,
            job,
            stdin,
            stdout: BufReader::new(stdout),
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
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .map_err(|error| format!("native engine response failed: {error}"))?;
        if line.is_empty() {
            return Err("native engine stopped unexpectedly".into());
        }
        let response: Value = serde_json::from_str(&line)
            .map_err(|error| format!("invalid native engine response: {error}"))?;
        if response["id"].as_u64() != Some(id) {
            return Err("native engine returned a mismatched response".into());
        }
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
        let _ = self.request("stop-wireguard-session", json!({}));
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
