//! Read-only health projection plus the fixed private default-log failure sink.
//! A notice proves only that an instrumented writer observed a failed append.
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tirith_core::audit::health::{self, AppendFailureNotice};

const NOTICE_BYTES: usize = 1024;
const NOTICE_LOCK_WAIT: Duration = Duration::from_millis(25);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateNotice {
    schema_version: u32,
    // This comparison stays in the private file and is never publicly projected.
    destination_binding: String,
    notice: AppendFailureNotice,
}

struct Locations {
    log: PathBuf,
    notice: PathBuf,
    scope: PathBuf,
}

fn locations() -> Result<Locations, String> {
    let log = tirith_core::audit::audit_log_path().ok_or("audit destination unavailable")?;
    let state = tirith_core::policy::state_dir().ok_or("audit health state unavailable")?;
    let (home, operator_uid) = super::shell_target::operator_home()?;
    #[cfg(unix)]
    if operator_uid != Some(unsafe { libc::geteuid() }) {
        return Err("audit health cannot create another operator's personal files".into());
    }
    #[cfg(not(unix))]
    let _ = operator_uid;
    if !log.is_absolute() || !state.is_absolute() {
        return Err("audit health requires absolute configured destinations".into());
    }
    let notice = state.join("audit-append-failure-v1.json");
    let scope = if notice.starts_with(&home) {
        home
    } else {
        state
    };
    Ok(Locations { log, notice, scope })
}

fn destination_binding(path: &Path) -> String {
    let mut hash = Sha256::new();
    hash.update(b"tirith-private-audit-notice-destination-v1\0");
    hash.update(path.as_os_str().as_encoded_bytes());
    format!("{:x}", hash.finalize())
}

pub(crate) fn install_sink() {
    let _ = health::install_failure_notice_sink(record_default_failure);
}

fn record_default_failure(log: &Path, notice: &AppendFailureNotice) -> bool {
    save_notice(log, notice).is_ok()
}

fn save_notice(log: &Path, notice: &AppendFailureNotice) -> Result<(), String> {
    save_notice_with_timeout(log, notice, NOTICE_LOCK_WAIT)
}

fn save_notice_with_timeout(
    log: &Path,
    notice: &AppendFailureNotice,
    lock_timeout: Duration,
) -> Result<(), String> {
    let paths = locations()?;
    if paths.log != log || !notice.validate(health::now_unix_ms()) {
        return Err("audit health destination or observation is unavailable".into());
    }
    let stored = PrivateNotice {
        schema_version: 1,
        destination_binding: destination_binding(log),
        notice: notice.clone(),
    };
    let bytes = serde_json::to_string(&stored).map_err(|_| "cannot encode audit health notice")?;
    let result = super::setup::write_private_notice_bounded(
        &paths.notice,
        &paths.scope,
        bytes,
        NOTICE_BYTES,
        lock_timeout,
        |bytes| valid_stored_notice(bytes, &paths.log),
    )?;
    match result {
        super::setup::TransactionOutcome::Written | super::setup::TransactionOutcome::Unchanged => {
            Ok(())
        }
        _ => Err("audit health notice publication requires recovery".into()),
    }
}

// The durable slot retains the first valid observation until deliberately
// removed. Invalid, wrong-destination and future observations are left intact;
// a failure-reporting side effect never replaces or repairs private user data.
fn valid_stored_notice(bytes: &[u8], log: &Path) -> bool {
    serde_json::from_slice::<PrivateNotice>(bytes).is_ok_and(|stored| {
        stored.schema_version == 1
            && stored.notice.validate(health::now_unix_ms())
            && stored.destination_binding == destination_binding(log)
    })
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HealthState {
    FailureObserved,
    Unknown,
    Disabled,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NoticeAvailability {
    NotInspected,
    Available,
    Absent,
    Unreadable,
    Invalid,
    DestinationChanged,
}

#[derive(Serialize)]
pub(crate) struct AuditHealth {
    schema_version: u32,
    state: HealthState,
    source: &'static str,
    notice_availability: NoticeAvailability,
    failure_observation: Option<AppendFailureNotice>,
    coverage: &'static str,
    detects_all_losses: bool,
    claims_current_success: bool,
}

impl AuditHealth {
    pub(crate) fn summary(&self) -> &'static str {
        match self.state {
            HealthState::FailureObserved => "A writer reported an earlier append failure; recorded history may be incomplete. This observation does not establish the current recording state.",
            HealthState::Disabled => "Logging is disabled; new checks are not being recorded by this process.",
            HealthState::Unknown => "No valid append-failure observation is available. Complete recording has not been established.",
        }
    }

    pub(crate) fn projection(&self) -> serde_json::Value {
        let mut value =
            serde_json::to_value(self).expect("audit health contains only JSON primitives");
        value["detail"] = self.summary().into();
        value
    }
}

pub(crate) fn read() -> AuditHealth {
    let mut result = AuditHealth {
        schema_version: 1,
        state: HealthState::Unknown,
        source: "no_observation",
        notice_availability: NoticeAvailability::NotInspected,
        failure_observation: None,
        coverage: "instrumented_default_log_writers_only",
        detects_all_losses: false,
        claims_current_success: false,
    };
    if std::env::var("TIRITH_LOG").as_deref() == Ok("0") {
        result.state = HealthState::Disabled;
        return result;
    }
    let Ok(paths) = locations() else {
        return result;
    };
    if let Some(process) = health::latest_process_failure(&paths.log) {
        if process.notice.validate(health::now_unix_ms()) {
            result.state = HealthState::FailureObserved;
            result.source = "current_process";
            result.failure_observation = Some(process.notice);
        }
    }
    result.notice_availability = NoticeAvailability::Unreadable;
    let Ok(snapshot) = super::setup::fs_helpers::read_snapshot_scoped_capped(
        &paths.notice,
        &paths.scope,
        NOTICE_BYTES,
    ) else {
        return result;
    };
    if snapshot.require_private().is_err() {
        return result;
    }
    let Some(bytes) = snapshot.bytes else {
        result.notice_availability = NoticeAvailability::Absent;
        return result;
    };
    let Ok(stored) = serde_json::from_slice::<PrivateNotice>(&bytes) else {
        result.notice_availability = NoticeAvailability::Invalid;
        return result;
    };
    if stored.schema_version != 1 || !stored.notice.validate(health::now_unix_ms()) {
        result.notice_availability = NoticeAvailability::Invalid;
        return result;
    }
    if stored.destination_binding != destination_binding(&paths.log) {
        result.notice_availability = NoticeAvailability::DestinationChanged;
        return result;
    }
    result.notice_availability = NoticeAvailability::Available;
    if result
        .failure_observation
        .as_ref()
        .is_none_or(|current| current.observed_unix_ms < stored.notice.observed_unix_ms)
    {
        result.state = HealthState::FailureObserved;
        result.source = "private_failure_notice";
        result.failure_observation = Some(stored.notice);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Positive persistence fixtures may overlap unrelated setup tests, whose
    // Unix writer lock uses the same filesystem-root inode. Exercise the real
    // writer with its ordinary test budget; production remains best-effort at
    // 25 ms and the transaction suite pins refusal under deliberate contention.
    fn save_test_notice(log: &Path, notice: &AppendFailureNotice) -> Result<(), String> {
        save_notice_with_timeout(log, notice, Duration::from_secs(30))
    }

    #[test]
    fn disabled_logging_does_not_inspect_or_create_a_notice() {
        let mut environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        let paths = locations().unwrap();
        assert!(!paths.notice.exists());
        environment.set_env("TIRITH_LOG", "0");
        let report = read().projection();
        assert_eq!(report["state"], "disabled");
        assert_eq!(report["notice_availability"], "not_inspected");
        assert_eq!(report["source"], "no_observation");
        assert!(report["failure_observation"].is_null());
        assert_eq!(report["claims_current_success"], false);
        assert!(!paths.notice.exists());
    }

    fn observation() -> AppendFailureNotice {
        AppendFailureNotice {
            schema_version: 1,
            observation_id: uuid::Uuid::new_v4().to_string(),
            observed_unix_ms: health::now_unix_ms(),
        }
    }

    #[test]
    fn absent_notice_is_unknown_and_saved_failure_survives_process_memory_absence() {
        let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        let paths = locations().unwrap();
        assert!(!paths.notice.exists());
        let before = serde_json::to_value(read()).unwrap();
        assert_eq!(before["state"], "unknown");
        assert!(
            !paths.notice.exists(),
            "reading health must not create state"
        );
        save_test_notice(&paths.log, &observation()).unwrap();
        let first = std::fs::read(&paths.notice).unwrap();
        save_test_notice(&paths.log, &observation()).unwrap();
        assert_eq!(std::fs::read(&paths.notice).unwrap(), first);
        let after = serde_json::to_value(read()).unwrap();
        assert_eq!(after["state"], "failure_observed");
        assert_eq!(after["source"], "private_failure_notice");
        assert_eq!(after["claims_current_success"], false);
        assert!(!after.to_string().contains("destination_binding"));
    }

    #[test]
    fn corrupt_oversized_and_destination_changed_notices_are_not_success() {
        let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        let paths = locations().unwrap();
        save_test_notice(&paths.log, &observation()).unwrap();
        std::fs::write(&paths.notice, vec![b'x'; NOTICE_BYTES + 1]).unwrap();
        assert_eq!(serde_json::to_value(read()).unwrap()["state"], "unknown");
        std::fs::write(&paths.notice, b"invalid").unwrap();
        assert_eq!(
            serde_json::to_value(read()).unwrap()["notice_availability"],
            "invalid"
        );
        let other = PrivateNotice {
            schema_version: 1,
            destination_binding: destination_binding(Path::new("other")),
            notice: observation(),
        };
        std::fs::write(&paths.notice, serde_json::to_vec(&other).unwrap()).unwrap();
        let report = serde_json::to_value(read()).unwrap();
        assert_eq!(report["notice_availability"], "destination_changed");
        assert_eq!(report["state"], "unknown");
    }

    #[cfg(unix)]
    #[test]
    fn privacy_drift_is_refused_before_replacement_or_projection() {
        use std::os::unix::fs::PermissionsExt as _;
        let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        let paths = locations().unwrap();
        save_test_notice(&paths.log, &observation()).unwrap();
        std::fs::set_permissions(&paths.notice, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::read(&paths.notice).unwrap();
        assert!(save_notice(&paths.log, &observation()).is_err());
        assert_eq!(std::fs::read(&paths.notice).unwrap(), before);
        assert_eq!(serde_json::to_value(read()).unwrap()["state"], "unknown");
    }
}
