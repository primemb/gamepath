//! Structured logging shared by the engine, the privileged service and the relay.
//!
//! The bar this has to clear is set by the questions that actually get asked of
//! a running session: which route stopped carrying traffic, when, and what the
//! process did about it. So this logs **transitions and decisions**, plus one
//! periodic summary line for context, and deliberately nothing per packet.
//!
//! Three things keep it from becoming noise:
//!
//! - A level filter, `info` by default, raised with `GAMEPATH_LOG=debug`.
//! - Consecutive identical messages are collapsed into a repeat count, so a
//!   path failing every two seconds costs one line, not eighteen hundred an
//!   hour.
//! - The file is capped and rotated, so a machine left running for a month does
//!   not fill its disk with a log nobody reads.
//!
//! Nothing here should ever be handed a secret. Node configurations, enrollment
//! tokens, pre-shared keys and service tokens stay out of the log entirely;
//! where a value has to be correlated across lines, log [`fingerprint`] of it
//! rather than the value.

use std::fmt::Arguments;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Size at which the log is rotated. One previous file is kept, so a component
/// costs at most twice this on disk.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// A message repeating this long keeps being suppressed, but is re-emitted with
/// its count afterwards so a stuck component still shows a pulse.
const REPEAT_WINDOW: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }

    /// Parses a `GAMEPATH_LOG` value. Anything unrecognised leaves the default
    /// in place rather than silently disabling the log.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "trace" => Some(Self::Debug),
            _ => None,
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static SINK: Mutex<Option<Sink>> = Mutex::new(None);

struct Repeat {
    level: Level,
    message: String,
    count: u64,
    since: Instant,
}

struct Sink {
    component: &'static str,
    path: Option<PathBuf>,
    file: Option<File>,
    written: u64,
    /// Also mirror to stderr. The service captures its child's stderr, and a
    /// developer running a component directly expects to see something.
    stderr: bool,
    repeat: Option<Repeat>,
}

/// Where a Windows component writes its log.
///
/// Everything lands in one directory so a problem report is one folder, and it
/// is the machine-wide one because the service and the engine run elevated and
/// a per-user path would not be writable by them.
#[cfg(windows)]
pub fn log_path(component: &str) -> PathBuf {
    let root = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    root.join("GamePath").join("logs").join(format!("{component}.log"))
}

/// Where a non-Windows component writes its log. The relay is the only one that
/// runs here, and it is a service, so this follows the usual place for one.
#[cfg(not(windows))]
pub fn log_path(component: &str) -> PathBuf {
    PathBuf::from("/var/log/gamepath").join(format!("{component}.log"))
}

/// Starts logging for this process.
///
/// `path` is the log file; `None` logs to stderr only, which is what a test or
/// a one-shot command wants. Calling this again replaces the previous sink.
pub fn init(component: &'static str, path: Option<PathBuf>, stderr: bool) {
    if let Some(level) = std::env::var("GAMEPATH_LOG").ok().and_then(|value| Level::parse(&value)) {
        LEVEL.store(level as u8, Ordering::Relaxed);
    }
    let (file, written) = match &path {
        Some(path) => open_log(path),
        None => (None, 0),
    };
    let mut sink = SINK.lock().unwrap_or_else(|error| error.into_inner());
    *sink = Some(Sink {
        component,
        path,
        file,
        written,
        stderr,
        repeat: None,
    });
}

/// The current level, for callers that want to skip expensive formatting.
pub fn enabled(level: Level) -> bool {
    level as u8 <= LEVEL.load(Ordering::Relaxed)
}

/// Writes one line. Prefer the `log_*` macros, which check the level first.
pub fn write(level: Level, arguments: Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    let message = arguments.to_string();
    let Ok(mut guard) = SINK.lock() else {
        return;
    };
    let Some(sink) = guard.as_mut() else {
        // Logging before init should not lose an error entirely.
        if level <= Level::Warn {
            eprintln!("{} {} {message}", timestamp(), level.label());
        }
        return;
    };
    sink.emit(level, message);
}

/// Emits any suppressed repeat immediately. Worth calling before a process
/// exits so the last line is not lost inside a repeat count.
pub fn flush() {
    let Ok(mut guard) = SINK.lock() else {
        return;
    };
    if let Some(sink) = guard.as_mut() {
        sink.flush_repeat();
    }
}

impl Sink {
    fn emit(&mut self, level: Level, message: String) {
        if let Some(repeat) = &mut self.repeat
            && repeat.level == level
            && repeat.message == message
        {
            repeat.count += 1;
            if repeat.since.elapsed() < REPEAT_WINDOW {
                return;
            }
            let count = repeat.count;
            self.repeat = None;
            self.line(level, &format!("{message} (repeated {count} times)"));
            self.repeat = Some(Repeat {
                level,
                message,
                count: 0,
                since: Instant::now(),
            });
            return;
        }
        self.flush_repeat();
        self.line(level, &message);
        self.repeat = Some(Repeat {
            level,
            message,
            count: 0,
            since: Instant::now(),
        });
    }

    fn flush_repeat(&mut self) {
        let Some(repeat) = self.repeat.take() else {
            return;
        };
        if repeat.count > 0 {
            let Repeat {
                level,
                message,
                count,
                ..
            } = repeat;
            self.line(level, &format!("{message} (repeated {count} times)"));
        }
    }

    fn line(&mut self, level: Level, message: &str) {
        let line = format!(
            "{} {:<5} {} {message}\n",
            timestamp(),
            level.label(),
            self.component
        );
        if self.stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        if self.written + line.len() as u64 > MAX_BYTES {
            self.rotate(&path);
        }
        if let Some(file) = self.file.as_mut()
            && file.write_all(line.as_bytes()).is_ok()
        {
            self.written += line.len() as u64;
        }
    }

    fn rotate(&mut self, path: &Path) {
        self.file = None;
        let previous = path.with_extension("log.1");
        let _ = std::fs::remove_file(&previous);
        let _ = std::fs::rename(path, &previous);
        let (file, written) = open_log(path);
        self.file = file;
        self.written = written;
    }
}

fn open_log(path: &Path) -> (Option<File>, u64) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = OpenOptions::new().create(true).append(true).open(path).ok();
    let written = std::fs::metadata(path).map(|data| data.len()).unwrap_or(0);
    (file, written)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, so lines sort and diff cleanly and a timestamp
/// can be read without converting it first.
fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_timestamp(elapsed.as_secs(), elapsed.subsec_millis())
}

fn format_timestamp(seconds: u64, millis: u32) -> String {
    let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
    let time = seconds % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Days since the Unix epoch to a civil date, by Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_position + 2) / 5 + 1) as u32;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// A short, stable tag for a secret, so the same key or token can be recognised
/// across lines without any of it being written down.
pub fn fingerprint(bytes: &[u8]) -> String {
    // FNV-1a: not a security primitive, and does not need to be. It exists so a
    // log line can say "the same key as before" and nothing more.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{:08x}", hash as u32)
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Error) {
            $crate::log::write($crate::log::Level::Error, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Warn) {
            $crate::log::write($crate::log::Level::Warn, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Info) {
            $crate::log::write($crate::log::Level::Info, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Debug) {
            $crate::log::write($crate::log::Level::Debug, format_args!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_a_known_date_format_correctly() {
        assert_eq!(format_timestamp(0, 0), "1970-01-01T00:00:00.000Z");
        // A real session start from the service log. That file records local
        // time; this formats UTC, which is the point of moving to it.
        assert_eq!(
            format_timestamp(1_788_936_975, 42),
            "2026-09-09T06:56:15.042Z"
        );
    }

    #[test]
    fn a_leap_day_is_not_off_by_one() {
        // 2024-02-29T00:00:00Z
        assert_eq!(format_timestamp(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert_eq!(format_timestamp(1_709_251_200, 0), "2024-03-01T00:00:00.000Z");
    }

    #[test]
    fn levels_order_from_most_to_least_severe() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
    }

    #[test]
    fn the_level_filter_is_parsed_leniently_and_never_silently_disables() {
        assert_eq!(Level::parse("Debug"), Some(Level::Debug));
        assert_eq!(Level::parse("  WARN "), Some(Level::Warn));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        // Unrecognised leaves the caller to keep its default.
        assert_eq!(Level::parse("verbose"), None);
        assert_eq!(Level::parse(""), None);
    }

    #[test]
    fn a_fingerprint_is_stable_short_and_not_the_secret() {
        let secret = b"an enrollment token that must never be logged";
        let tag = fingerprint(secret);
        assert_eq!(tag.len(), 8);
        assert_eq!(tag, fingerprint(secret));
        assert_ne!(tag, fingerprint(b"a different secret"));
        assert!(!String::from_utf8_lossy(secret).contains(&tag));
    }

    fn sink(component: &'static str) -> Sink {
        Sink {
            component,
            path: None,
            file: None,
            written: 0,
            stderr: false,
            repeat: None,
        }
    }

    #[test]
    fn a_repeated_message_is_collapsed_instead_of_written_each_time() {
        let mut sink = sink("test");
        for _ in 0..1000 {
            sink.emit(Level::Warn, "path health check timed out".into());
        }
        // Only the first went out; the rest are held as a count.
        let repeat = sink.repeat.as_ref().expect("the repeat should be pending");
        assert_eq!(repeat.count, 999);
        assert_eq!(repeat.message, "path health check timed out");
    }

    #[test]
    fn a_different_message_releases_the_pending_repeat() {
        let mut sink = sink("test");
        sink.emit(Level::Warn, "same".into());
        sink.emit(Level::Warn, "same".into());
        sink.emit(Level::Info, "something else".into());
        let repeat = sink.repeat.as_ref().unwrap();
        assert_eq!(repeat.message, "something else");
        assert_eq!(repeat.count, 0);
    }

    #[test]
    fn the_same_message_at_a_different_level_is_not_collapsed() {
        let mut sink = sink("test");
        sink.emit(Level::Info, "route 2 is unreachable".into());
        sink.emit(Level::Error, "route 2 is unreachable".into());
        assert_eq!(sink.repeat.as_ref().unwrap().level, Level::Error);
        assert_eq!(sink.repeat.as_ref().unwrap().count, 0);
    }

    #[test]
    fn rotation_keeps_one_previous_file_and_starts_a_new_one() {
        let directory = std::env::temp_dir().join(format!("gamepath-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let path = directory.join("test.log");
        let (file, written) = open_log(&path);
        let mut sink = Sink {
            component: "test",
            path: Some(path.clone()),
            file,
            written,
            stderr: false,
            repeat: None,
        };
        // Every line is a distinct message, so nothing is collapsed away.
        let padding = "x".repeat(1000);
        for index in 0..(MAX_BYTES / 1000 + 500) {
            sink.emit(Level::Info, format!("line {index} {padding}"));
        }
        sink.flush_repeat();
        drop(sink);
        let current = std::fs::metadata(&path).unwrap().len();
        let previous = path.with_extension("log.1");
        assert!(previous.is_file(), "the previous log should be kept");
        assert!(current <= MAX_BYTES, "the live log outgrew its cap");
        assert!(std::fs::metadata(&previous).unwrap().len() <= MAX_BYTES);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
