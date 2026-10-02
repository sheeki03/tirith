//! Helpers shared by the `tirith policy team` connection, enrollment and
//! rollout commands.
use tirith_core::policy_team::Id;

pub(super) fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Parse a team record identifier: a canonical, lowercase, non-nil UUID.
pub(super) fn id(value: &str) -> Result<Id, String> {
    Id::parse(value).map_err(|_| "a canonical nonzero UUID is required".into())
}

pub(super) fn now_ms() -> Result<u64, String> {
    tirith_core::util::now_ms().ok_or_else(|| "local clock is unavailable".into())
}

/// Offline mode forbids every contact with the team authority.
pub(super) fn network_allowed() -> Result<(), String> {
    if super::offline_env_active() {
        Err("team authority contact is disabled by offline mode".into())
    } else {
        Ok(())
    }
}
