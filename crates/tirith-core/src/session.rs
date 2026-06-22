use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Global session ID for the current tirith process lifetime.
static SESSION_ID: OnceLock<String> = OnceLock::new();

/// Get or generate the session ID: `TIRITH_SESSION_ID` env var, else an
/// auto-generated per-process UUID. New code that needs the file-based fallback
/// for agent hooks should prefer [`resolve_session_id`].
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

/// `TIRITH_SESSION_ID` if set and non-empty, else `None`. Cached for the process
/// lifetime.
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

/// Read cap for the fallback file: it holds a single UUID line, so 256 bytes is
/// generous while still bounding a hostile oversized file.
const FALLBACK_FILE_READ_CAP: u64 = 256;

/// Per-entry in-process cache refresh interval (5 minutes).
const FALLBACK_CACHE_REFRESH_SECS: u64 = 300;

/// Refreshable file-based fallback session ID. Keyed by scope
/// (`{integration}-{cwd_hash_8chars}`); the file lives at
/// `state_dir()/sessions/fallback-{scope}.id` and is reused while its mtime is
/// under 4 hours. An in-process `Mutex<HashMap>` caches with a 5-minute refresh.
pub fn fallback_session_id() -> String {
    let scope = compute_scope();
    let cache = FALLBACK_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    if let Ok(map) = cache.lock() {
        if let Some(entry) = map.get(&scope) {
            if entry.cached_at.elapsed().as_secs() < FALLBACK_CACHE_REFRESH_SECS {
                return entry.session_id.clone();
            }
        }
    }

    let id = load_or_create_fallback_file(&scope);

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

/// Unified session ID resolver: `TIRITH_SESSION_ID` env var, else the file-based
/// fallback (scoped by integration + cwd). Prefer this over [`session_id`] when
/// the caller might run outside a shell hook (e.g. agent integrations).
pub fn resolve_session_id() -> String {
    if let Some(env_id) = env_session_id() {
        return env_id.to_string();
    }
    fallback_session_id()
}

/// Scope key `{integration}-{cwd_hash_8chars}`: integration from
/// `TIRITH_INTEGRATION` (default "unknown"), cwd_hash the first 8 hex chars of
/// SHA-256(cwd).
fn compute_scope() -> String {
    let integration = std::env::var("TIRITH_INTEGRATION")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    // Sanitize: only [a-zA-Z0-9_-].
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
    hex::encode(&bytes[..bytes.len().min(4)])
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

    // Open with O_NOFOLLOW so a symlink planted at the fallback path cannot
    // redirect this read onto another file, and take BOTH the freshness mtime and
    // the content from the SAME open handle: one inode for the stat and the read
    // closes the freshness-vs-read race a separate `symlink_metadata` +
    // `read_to_string` left open (a swap between the two could read a different
    // file than the one whose mtime we checked).
    if let Ok(file) = crate::util::open_read_no_follow_capped(&path, FALLBACK_FILE_READ_CAP) {
        if let Ok(modified) = file.metadata().and_then(|m| m.modified()) {
            if let Ok(age) = std::time::SystemTime::now().duration_since(modified) {
                if age.as_secs() < FALLBACK_FILE_MAX_AGE_SECS {
                    // Read from the SAME handle, overflow-safe: take(cap + 1) so a
                    // TOCTOU grow past the cap is rejected rather than buffered
                    // (mirrors util::read_text_no_follow_capped).
                    use std::io::Read as _;
                    let mut buf = Vec::new();
                    if (&file)
                        .take(FALLBACK_FILE_READ_CAP.saturating_add(1))
                        .read_to_end(&mut buf)
                        .is_ok()
                        && buf.len() as u64 <= FALLBACK_FILE_READ_CAP
                    {
                        if let Ok(content) = String::from_utf8(buf) {
                            let id = content.trim().to_string();
                            if !id.is_empty() && id.len() <= 128 {
                                return id;
                            }
                        }
                    }
                }
            }
        }
    }
    // NotFound and any other error (symlink refusal, oversized, I/O) all fall
    // through to regenerate: fail-safe, since a stable ID is best-effort.

    let new_id = generate_session_id();
    write_fallback_file(&path, &new_id);
    new_id
}

/// Write a fallback session ID to file with secure permissions.
fn write_fallback_file(path: &Path, session_id: &str) {
    if let Some(parent) = path.parent() {
        // Create sessions/ and, only if THIS call created it, fsync the grandparent
        // so a first-time-created dir entry survives a crash. The helper keys off
        // create_dir's own result, so there is no exists()-then-create TOCTOU.
        if let Err(e) = crate::util::create_dir_durable(parent) {
            crate::audit::audit_diagnostic(format!(
                "tirith: session: cannot create dir {}: {e}",
                parent.display()
            ));
            return;
        }
    }

    // Crash-atomic, 0600, symlink-safe in one call: a random temp sibling plus a
    // rename means no predictable temp and no symlink-follow at `path`, and the
    // reader never sees a torn file. Replaces the prior in-place O_NOFOLLOW write
    // plus manual partial-file cleanup.
    if let Err(e) = crate::util::write_file_atomic_0600(path, format!("{session_id}\n").as_bytes())
    {
        crate::audit::audit_diagnostic(format!(
            "tirith: session: cannot write fallback {}: {e}; session ID may be unstable",
            path.display()
        ));
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
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = generate_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_session_id_format() {
        let id = generate_session_id();
        // UUID v4: 8-4-4-4-12 hex = 36 chars.
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

    /// A symlink planted at the fallback path must NOT be followed: the no-follow
    /// open refuses it, so the loader regenerates a fresh UUID instead of returning
    /// the link target's contents.
    #[cfg(unix)]
    #[test]
    fn test_load_fallback_refuses_symlink_and_regenerates() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };

        let scope = "symlink-test-abcd1234";
        let path = fallback_file_path(scope).expect("a fallback path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // Plant a sentinel and a symlink at the fallback path pointing to it.
        let sentinel = dir.path().join("sentinel.txt");
        let sentinel_id = "11111111-2222-3333-4444-555555555555";
        std::fs::write(&sentinel, format!("{sentinel_id}\n")).unwrap();
        std::os::unix::fs::symlink(&sentinel, &path).unwrap();

        let id = load_or_create_fallback_file(scope);
        // Must be a fresh valid UUID, NOT the sentinel's contents.
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert_ne!(
            id, sentinel_id,
            "a symlinked fallback path must not leak the link target's id"
        );
        // The sentinel must be untouched (the rename replaced the link, not it).
        assert_eq!(
            std::fs::read_to_string(&sentinel).unwrap(),
            format!("{sentinel_id}\n"),
            "the symlink target must be byte-for-byte unchanged"
        );
        // The fallback path itself must now be a REGULAR file (the atomic rename
        // replaced the symlink), holding exactly the regenerated id. Without this
        // the test could pass even if the best-effort write had failed and left
        // the planted symlink in place.
        let meta = std::fs::symlink_metadata(&path).expect("fallback path exists");
        assert!(
            !meta.file_type().is_symlink(),
            "the planted symlink must be replaced by a regular file"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{id}\n"),
            "the fallback file must contain the regenerated id"
        );

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    /// `write_fallback_file` publishes the id atomically: the file holds exactly
    /// the id, no temp sibling remains, and a pre-existing file is replaced
    /// wholesale (not appended).
    #[cfg(unix)]
    #[test]
    fn test_write_fallback_atomic_replaces_and_leaves_no_temp() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };

        let scope = "atomic-write-test-abcd1234";
        let path = fallback_file_path(scope).expect("a fallback path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A stale pre-existing file must be replaced wholesale.
        std::fs::write(&path, "STALE PARTIAL CONTENT to be replaced wholesale").unwrap();

        let new_id = "abcdef01-2345-6789-abcd-ef0123456789";
        write_fallback_file(&path, new_id);

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{new_id}\n"),
            "the fallback file must hold exactly the new id plus newline"
        );

        // No temp sibling may remain after the atomic publish.
        let leftovers: Vec<String> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != path.file_name().unwrap().to_string_lossy().as_ref())
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file must remain after an atomic publish, found: {leftovers:?}"
        );

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
