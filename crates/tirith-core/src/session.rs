use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Global session ID for the current tirith process lifetime.
static SESSION_ID: OnceLock<String> = OnceLock::new();

/// Get or generate the session ID.
///
/// Priority:
/// 1. `TIRITH_SESSION_ID` env var (set by shell hooks for cross-command sessions)
/// 2. Auto-generated UUID for this process
///
/// Existing callers should continue using this. New code that needs
/// file-based fallback for agent hooks should prefer `resolve_session_id()`.
pub fn session_id() -> &'static str {
    SESSION_ID.get_or_init(|| {
        std::env::var("TIRITH_SESSION_ID").unwrap_or_else(|_| generate_session_id())
    })
}

/// Generate a new session ID using UUID v4.
fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a fresh session ID suitable for `tirith init` to export.
pub fn new_session_id() -> String {
    generate_session_id()
}

// ---------------------------------------------------------------------------
// Split API — env + file-based fallback
// ---------------------------------------------------------------------------

/// Immutable env-var session (returns `&'static str`, cached in `OnceLock`).
///
/// Returns `Some` if `TIRITH_SESSION_ID` is set and non-empty, `None` otherwise.
/// The value is cached for the process lifetime.
pub fn env_session_id() -> Option<&'static str> {
    static CACHED: OnceLock<Option<String>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            std::env::var("TIRITH_SESSION_ID")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .as_deref()
}

/// Cache entry for a file-based fallback session ID.
struct FallbackEntry {
    session_id: String,
    cached_at: Instant,
}

/// In-process cache for fallback session IDs, keyed by scope string.
static FALLBACK_CACHE: OnceLock<Mutex<HashMap<String, FallbackEntry>>> = OnceLock::new();

/// Max age for a file-based fallback ID on disk before regenerating (4 hours).
const FALLBACK_FILE_MAX_AGE_SECS: u64 = 4 * 3600;

/// Per-entry in-process cache refresh interval (5 minutes).
const FALLBACK_CACHE_REFRESH_SECS: u64 = 300;

/// Refreshable file-based fallback session ID.
///
/// Cache is keyed by scope (`{integration}-{cwd_hash_8chars}`).
/// File lives at `state_dir()/sessions/fallback-{scope}.id`.
/// If the file exists and its mtime is less than 4 hours, its content is used.
/// Otherwise a new ID is generated and written.
///
/// An in-process `Mutex<HashMap>` caches resolved IDs with a 5-minute refresh.
pub fn fallback_session_id() -> String {
    let scope = compute_scope();
    let cache = FALLBACK_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // Check in-process cache first
    if let Ok(map) = cache.lock() {
        if let Some(entry) = map.get(&scope) {
            if entry.cached_at.elapsed().as_secs() < FALLBACK_CACHE_REFRESH_SECS {
                return entry.session_id.clone();
            }
        }
    }

    // Try to load from file, or generate fresh
    let id = load_or_create_fallback_file(&scope);

    // Update in-process cache
    if let Ok(mut map) = cache.lock() {
        map.insert(
            scope,
            FallbackEntry {
                session_id: id.clone(),
                cached_at: Instant::now(),
            },
        );
    }

    id
}

/// Unified session ID resolver.
///
/// Priority:
/// 1. `TIRITH_SESSION_ID` env var (immutable, process-lifetime cache)
/// 2. File-based fallback (refreshable, scoped by integration + cwd)
///
/// Returns an owned `String`. New code should prefer this over `session_id()`
/// when the caller might run outside a shell hook (e.g. agent integrations).
pub fn resolve_session_id() -> String {
    if let Some(env_id) = env_session_id() {
        return env_id.to_string();
    }
    fallback_session_id()
}

/// Compute a scope key from the current integration name and working directory.
///
/// Format: `{integration}-{cwd_hash_8chars}` where integration comes from
/// `TIRITH_INTEGRATION` env var (default "unknown") and cwd_hash is the
/// first 8 hex chars of the SHA-256 of the current directory.
fn compute_scope() -> String {
    let integration = std::env::var("TIRITH_INTEGRATION")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    // Sanitize integration name: only [a-zA-Z0-9_-]
    let integration: String = integration
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();

    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let cwd_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(cwd.as_bytes());
        let digest = hasher.finalize();
        hex_encode_8(&digest)
    };

    format!("{integration}-{cwd_hash}")
}

/// Encode the first 4 bytes (8 hex chars) of a digest.
fn hex_encode_8(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Path for a fallback session file.
fn fallback_file_path(scope: &str) -> Option<PathBuf> {
    let state = crate::policy::state_dir()?;
    Some(state.join("sessions").join(format!("fallback-{scope}.id")))
}

/// Load an existing fallback file if fresh, or create a new one.
fn load_or_create_fallback_file(scope: &str) -> String {
    let path = match fallback_file_path(scope) {
        Some(p) => p,
        None => return generate_session_id(),
    };

    // Try to read existing file
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(age) = std::time::SystemTime::now().duration_since(modified) {
                if age.as_secs() < FALLBACK_FILE_MAX_AGE_SECS {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let id = content.trim().to_string();
                        if !id.is_empty() && id.len() <= 128 {
                            return id;
                        }
                    }
                }
            }
        }
    }

    // Generate new ID and write
    let new_id = generate_session_id();
    write_fallback_file(&path, &new_id);
    new_id
}

/// Write a fallback session ID to file with secure permissions.
fn write_fallback_file(path: &PathBuf, session_id: &str) {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot create dir {}: {e}",
                parent.display()
            ));
            return;
        }
    }

    // Refuse to follow symlinks (matches audit.rs / session_warnings.rs pattern)
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                crate::audit::audit_diagnostic(format!(
                    "tirith: session: refusing to follow symlink at {}",
                    path.display()
                ));
                return;
            }
            _ => {}
        }
    }

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
        open_opts.custom_flags(libc::O_NOFOLLOW);
    }

    let file = match open_opts.open(path) {
        Ok(f) => f,
        Err(e) => {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot write fallback {}: {e} — session ID may be unstable",
                path.display()
            ));
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    use std::io::Write;
    let mut writer = std::io::BufWriter::new(&file);
    let write_ok = writer
        .write_all(session_id.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .is_ok();
    drop(writer);
    if !write_ok {
        // Remove partial/corrupt file so next read regenerates instead of
        // reading a truncated session ID.
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_stable_within_process() {
        let id1 = session_id();
        let id2 = session_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_generate_session_id_unique() {
        let a = generate_session_id();
        // Small sleep to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = generate_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_session_id_format() {
        let id = generate_session_id();
        // UUID v4 format: 8-4-4-4-12 hex chars = 36 chars
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_resolve_session_id_returns_non_empty() {
        // Whether env var is set or not, resolve should return something
        let id = resolve_session_id();
        assert!(!id.is_empty());
        // Should be a valid-looking identifier (UUID or env value)
        assert!(id.len() <= 128);
    }

    #[test]
    fn test_resolve_session_id_stable_on_repeated_calls() {
        let id1 = resolve_session_id();
        let id2 = resolve_session_id();
        // Within the same process, should be the same (from cache or env)
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_scope_format() {
        let scope = compute_scope();
        // Should be "{integration}-{8_hex_chars}"
        assert!(scope.contains('-'));
        // The hash part after the last hyphen should be 8 hex chars
        let parts: Vec<&str> = scope.rsplitn(2, '-').collect();
        assert_eq!(parts[0].len(), 8);
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hex_encode_8() {
        let bytes = [0xAB, 0xCD, 0xEF, 0x12, 0x34];
        assert_eq!(hex_encode_8(&bytes), "abcdef12");
    }

    #[test]
    fn test_hex_encode_8_short_input() {
        let bytes = [0x01, 0x02];
        assert_eq!(hex_encode_8(&bytes), "0102");
    }

    #[cfg(unix)]
    #[test]
    fn test_fallback_file_roundtrip() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };

        let scope = "test-integration-abcd1234";
        let id = load_or_create_fallback_file(scope);
        assert!(!id.is_empty());
        assert!(uuid::Uuid::parse_str(&id).is_ok());

        // Loading again should return the same ID
        let id2 = load_or_create_fallback_file(scope);
        assert_eq!(id, id2);

        // Verify file permissions
        if let Some(path) = fallback_file_path(scope) {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[cfg(unix)]
    #[test]
    fn test_env_session_id_priority() {
        // Note: env_session_id uses OnceLock so we can only test the concept.
        // The actual env check is cached for the process lifetime, so we verify
        // the resolve logic indirectly.
        let resolved = resolve_session_id();
        assert!(!resolved.is_empty());
    }
}
