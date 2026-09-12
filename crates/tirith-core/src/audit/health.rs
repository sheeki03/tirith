//! Failure observations only. Absence is unknown, never inferred audit success.
use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub(crate) const APPEND_LOCK_TIMEOUT: Duration = Duration::from_millis(250);
const PROCESS_NOTICE_LIMIT: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendFailureNotice {
    pub schema_version: u32,
    pub observation_id: String,
    pub observed_unix_ms: u64,
}

impl AppendFailureNotice {
    pub fn validate(&self, now_unix_ms: u64) -> bool {
        self.schema_version == 1
            && self.observed_unix_ms > 0
            && self.observed_unix_ms <= now_unix_ms
            && uuid::Uuid::parse_str(&self.observation_id)
                .is_ok_and(|id| id.to_string() == self.observation_id)
    }
}

/// The sink receives an observed destination for routing only. No destination,
/// command, reason, policy text or secret is included in a notice or its DTO.
pub type FailureNoticeSink = fn(&Path, &AppendFailureNotice) -> bool;
static NOTICE_SINK: OnceLock<FailureNoticeSink> = OnceLock::new();

pub fn install_failure_notice_sink(sink: FailureNoticeSink) -> bool {
    NOTICE_SINK.set(sink).is_ok()
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessFailureObservation {
    pub notice: AppendFailureNotice,
    pub durable_notice_recorded: bool,
}

#[derive(Default)]
struct ProcessNotices(VecDeque<(PathBuf, ProcessFailureObservation)>);

impl ProcessNotices {
    fn record(&mut self, path: &Path, observation: ProcessFailureObservation) {
        if path.as_os_str().as_encoded_bytes().len() > 64 * 1024 {
            return;
        }
        self.0.retain(|(existing, _)| existing != path);
        self.0.push_back((path.to_owned(), observation));
        while self.0.len() > PROCESS_NOTICE_LIMIT {
            self.0.pop_front();
        }
    }
    fn latest(&self, path: &Path) -> Option<ProcessFailureObservation> {
        self.0
            .iter()
            .find(|(existing, _)| existing == path)
            .map(|(_, value)| value.clone())
    }
}

static PROCESS_NOTICES: OnceLock<Mutex<ProcessNotices>> = OnceLock::new();
static WARNING_PRINTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn latest_process_failure(path: &Path) -> Option<ProcessFailureObservation> {
    PROCESS_NOTICES.get()?.lock().ok()?.latest(path)
}

pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub(crate) fn record_append_failure(path: &Path) {
    let notice = AppendFailureNotice {
        schema_version: 1,
        observation_id: uuid::Uuid::new_v4().to_string(),
        observed_unix_ms: now_unix_ms(),
    };
    let durable_notice_recorded = NOTICE_SINK.get().is_some_and(|sink| sink(path, &notice));
    if let Ok(mut notices) = PROCESS_NOTICES.get_or_init(Default::default).lock() {
        notices.record(
            path,
            ProcessFailureObservation {
                notice,
                durable_notice_recorded,
            },
        );
    }
    if !WARNING_PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "tirith: audit append failed; recorded history may be incomplete."
        );
    }
}

/// The OS lock remains the ordinary audit lock; only its waiting is bounded.
/// No coordination file, alternate inode, or successful-append shortcut exists.
pub(crate) fn lock_append_for(file: &File, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match fs2::FileExt::try_lock_exclusive(file) {
            Ok(()) => return Ok(()),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error().is_some_and(|code| {
                        Some(code) == fs2::lock_contended_error().raw_os_error()
                    }) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "audit append lock deadline reached",
            ));
        }
        std::thread::sleep(Duration::from_millis(5).min(remaining));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(time: u64) -> AppendFailureNotice {
        AppendFailureNotice {
            schema_version: 1,
            observation_id: uuid::Uuid::new_v4().to_string(),
            observed_unix_ms: time,
        }
    }

    #[test]
    fn held_native_append_lock_returns_within_its_deadline() {
        let held = tempfile::NamedTempFile::new().unwrap();
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(held.path())
            .unwrap();
        fs2::FileExt::lock_exclusive(held.as_file()).unwrap();
        let start = Instant::now();
        let error = lock_append_for(&contender, Duration::from_millis(20)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        fs2::FileExt::unlock(held.as_file()).unwrap();
        lock_append_for(&contender, Duration::ZERO).unwrap();
        fs2::FileExt::unlock(&contender).unwrap();
    }

    #[test]
    fn observations_are_bounded_and_do_not_mix_destinations() {
        let mut notices = ProcessNotices::default();
        assert!(notices.latest(Path::new("absent")).is_none());
        for index in 0..PROCESS_NOTICE_LIMIT + 1 {
            notices.record(
                Path::new(&index.to_string()),
                ProcessFailureObservation {
                    notice: notice(100),
                    durable_notice_recorded: false,
                },
            );
        }
        assert_eq!(notices.0.len(), PROCESS_NOTICE_LIMIT);
        assert!(notices.latest(Path::new("0")).is_none());
        assert!(notices.latest(Path::new("1")).is_some());
        let replacement = notice(101);
        notices.record(
            Path::new("1"),
            ProcessFailureObservation {
                notice: replacement.clone(),
                durable_notice_recorded: true,
            },
        );
        assert_eq!(notices.latest(Path::new("1")).unwrap().notice, replacement);
    }

    #[test]
    fn stored_notice_rejects_future_clock_and_unrecognized_content() {
        assert!(notice(100).validate(100));
        assert!(!notice(101).validate(100));
        assert!(!notice(0).validate(100));
        let mut invalid = notice(100);
        invalid.observation_id = "untrusted text".into();
        assert!(!invalid.validate(100));
        assert!(serde_json::from_str::<AppendFailureNotice>(
            r#"{"schema_version":1,"observation_id":"raw","observed_unix_ms":100,"command":"private"}"#
        ).is_err());
    }
}
