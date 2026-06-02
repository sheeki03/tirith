//! Sudo-session helpers (M8 ch4).
//!
//! A session file at `state_dir()/sudo-session.json` stores `{started_at, ttl,
//! reason}` for the operator's claimed sudo window. The M8 ch4 rule consults it
//! (when `policy.sudo_require_reason` is on) so a tagged session can suppress an
//! otherwise-blocking finding.
//!
//! Clock-skew tolerance: TTL checks compare `now()` to `started_at`, tolerating
//! ≤60s skew (NTP/container drift); a wildly-future timestamp expires the session
//! and never panics. The on-disk `mtime` is NEVER used to rewrite `started_at` —
//! a `touch`/`cp -p` must not reactivate an expired session.
//!
//! Lifecycle: `start` writes the file `0o600` (overwriting any prior); `end`
//! removes it; `status` computes `remaining_secs`. Failures are non-fatal — an
//! unreadable file means "no session", which the rules treat as a hard Block.
//!
//! Honest scope: the file is user-writable, so this is operator-trust (catch "I
//! forgot a sudo window is open"), not adversary-resistant. Same shape as the M8
//! ch1-3 labels-file model.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Max tolerated clock skew between `started_at` and `now()`. Wider than typical
/// NTP drift, tight enough that a pathologically-wrong clock still expires.
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 60;

/// Default TTL for `tirith sudo session start` without `--ttl`.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 30 * 60;

/// Path the session file lives at, when `state_dir()` is resolvable.
pub fn sudo_session_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|s| s.join("sudo-session.json"))
}

/// On-disk shape of the sudo-session file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SudoSession {
    /// Unix epoch seconds when the operator started the session.
    pub started_at: u64,
    /// Lifetime in seconds before the session expires.
    pub ttl_secs: u64,
    /// Operator-supplied reason string. Stored verbatim, no parsing.
    #[serde(default)]
    pub reason: String,
}

impl SudoSession {
    /// Construct a fresh session anchored at `SystemTime::now()`.
    pub fn now(ttl_secs: u64, reason: impl Into<String>) -> Self {
        Self {
            started_at: unix_now(),
            ttl_secs,
            reason: reason.into(),
        }
    }

    /// `true` when still within the TTL window. Tolerates clock-skew within
    /// [`CLOCK_SKEW_TOLERANCE_SECS`].
    pub fn is_active(&self) -> bool {
        let now = unix_now();
        let started = self.started_at;
        // `started_at` may be slightly future after a clock-correction; don't
        // reject those, but a wildly-past clock fails closed (safer default).
        let effective_now = if now >= started {
            now
        } else if started - now <= CLOCK_SKEW_TOLERANCE_SECS {
            started
        } else {
            return false;
        };
        let age = effective_now.saturating_sub(started);
        age <= self.ttl_secs
    }

    /// Seconds remaining in the session. `0` once expired.
    pub fn remaining_secs(&self) -> u64 {
        let now = unix_now();
        if now < self.started_at {
            return self.ttl_secs; // negative age → full TTL
        }
        let age = now - self.started_at;
        self.ttl_secs.saturating_sub(age)
    }
}

/// Read the current session, or `None` when the file is missing OR expired
/// (caller needn't re-check the TTL). NEVER overwrites `started_at` from disk
/// mtime — a `touch`/backup-tool mtime refresh must not reactivate an expired
/// session.
pub fn read_active_session() -> Option<SudoSession> {
    let path = sudo_session_path()?;
    let bytes = std::fs::read(&path).ok()?;
    let session: SudoSession = serde_json::from_slice(&bytes).ok()?;

    if session.is_active() {
        Some(session)
    } else {
        None
    }
}

/// Write a new session file, overwriting any prior session. Returns the
/// final on-disk path.
pub fn write_session(session: &SudoSession) -> Result<PathBuf, String> {
    let path =
        sudo_session_path().ok_or_else(|| "could not resolve tirith state dir".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let body =
        serde_json::to_vec_pretty(session).map_err(|e| format!("serialize sudo session: {e}"))?;
    write_file_0600(&path, &body).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

/// Remove the session file. Idempotent — missing-file is success.
pub fn remove_session() -> Result<(), String> {
    let path = match sudo_session_path() {
        Some(p) => p,
        None => return Ok(()),
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

fn write_file_0600(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(body)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a `--ttl` string (`30m` / `2h` / `90s` / bare seconds) to seconds.
/// Empty → `None`. The suffix must be a single ASCII byte; a multi-byte suffix
/// (e.g. `5m€`) is rejected so the `split_at` below can't panic mid-codepoint.
pub fn parse_ttl(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bare integer → seconds.
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    // Suffix must be a single ASCII byte (rejected up-front so the split is safe).
    let last_byte = s.as_bytes().last().copied()?;
    if !last_byte.is_ascii() {
        return None;
    }
    let (num_part, suffix) = s.split_at(s.len() - 1);
    if num_part.is_empty() {
        return None;
    }
    let n: u64 = num_part.parse().ok()?;
    match suffix {
        "s" | "S" => Some(n),
        "m" | "M" => Some(n.saturating_mul(60)),
        "h" | "H" => Some(n.saturating_mul(60 * 60)),
        "d" | "D" => Some(n.saturating_mul(24 * 60 * 60)),
        _ => None,
    }
}

/// Format the duration as a short human string (`30m`, `2h`, `1d`).
pub fn format_ttl(secs: u64) -> String {
    if secs % (24 * 60 * 60) == 0 && secs >= 24 * 60 * 60 {
        return format!("{}d", secs / (24 * 60 * 60));
    }
    if secs % (60 * 60) == 0 && secs >= 60 * 60 {
        return format!("{}h", secs / (60 * 60));
    }
    if secs % 60 == 0 && secs >= 60 {
        return format!("{}m", secs / 60);
    }
    format!("{secs}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_handles_units() {
        assert_eq!(parse_ttl("30s"), Some(30));
        assert_eq!(parse_ttl("5m"), Some(300));
        assert_eq!(parse_ttl("2h"), Some(7200));
        assert_eq!(parse_ttl("1d"), Some(86400));
        assert_eq!(parse_ttl("90"), Some(90));
    }

    #[test]
    fn parse_ttl_rejects_garbage() {
        assert_eq!(parse_ttl(""), None);
        assert_eq!(parse_ttl("xyz"), None);
        assert_eq!(parse_ttl("3w"), None);
    }

    #[test]
    fn parse_ttl_does_not_panic_on_multibyte_suffix() {
        // Regression: `split_at(len - 1)` panicked mid-codepoint on a multi-byte
        // last char (the CLI passes the raw `--ttl` arg here).
        assert_eq!(parse_ttl("5m€"), None);
        assert_eq!(parse_ttl("30s😀"), None);
        assert_eq!(parse_ttl("€"), None);
        assert_eq!(parse_ttl("m"), None); // unit only, no number
    }

    #[test]
    fn format_ttl_picks_largest_clean_unit() {
        assert_eq!(format_ttl(30), "30s");
        assert_eq!(format_ttl(300), "5m");
        assert_eq!(format_ttl(7200), "2h");
        assert_eq!(format_ttl(86400), "1d");
        assert_eq!(format_ttl(86461), "86461s");
    }

    #[test]
    fn fresh_session_is_active() {
        let s = SudoSession::now(60, "demo");
        assert!(s.is_active());
        assert!(s.remaining_secs() > 0);
    }

    #[test]
    fn expired_session_is_inactive() {
        let now = unix_now();
        let s = SudoSession {
            started_at: now.saturating_sub(120),
            ttl_secs: 30,
            reason: "stale".to_string(),
        };
        assert!(!s.is_active());
        assert_eq!(s.remaining_secs(), 0);
    }

    #[test]
    fn small_future_clock_skew_tolerated() {
        let now = unix_now();
        let s = SudoSession {
            started_at: now + 10, // 10s in the future — well under tolerance
            ttl_secs: 60,
            reason: "skew".to_string(),
        };
        assert!(s.is_active());
    }

    #[test]
    fn large_future_clock_skew_rejected() {
        let now = unix_now();
        let s = SudoSession {
            started_at: now + 10 * CLOCK_SKEW_TOLERANCE_SECS,
            ttl_secs: 60,
            reason: "wild_skew".to_string(),
        };
        assert!(!s.is_active());
    }
}
