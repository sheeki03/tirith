use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Global session ID for the current tirith process lifetime.
static SESSION_ID: OnceLock<String> = OnceLock::new();

/// The privacy-safe session-ID contract shared by every resolver and the
/// state-store path validation (repo-0339). An env/fallback ID outside the
/// bounded filename alphabet, or one that mandatory durable projection
/// recognizes as secret material, would either disable warning recording or
/// become a secret-bearing filename. Reject it at the shared predicate so every
/// resolved ID remains storable without exposing raw secret bytes.
pub(crate) fn is_valid_session_id(id: &str) -> bool {
    let has_safe_alphabet = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    has_safe_alphabet && crate::redact::privacy_project_durable_text(id) == id
}

fn select_process_session_id(env_id: Option<String>) -> String {
    env_id
        .filter(|id| is_valid_session_id(id))
        .unwrap_or_else(generate_session_id)
}

/// Get or generate the session ID: `TIRITH_SESSION_ID` env var, else an
/// auto-generated per-process UUID. New code that needs the file-based fallback
/// for agent hooks should prefer [`resolve_session_id`].
pub fn session_id() -> &'static str {
    SESSION_ID.get_or_init(|| {
        // repo-0339: an invalid or privacy-unsafe env ID must not propagate (it
        // would silently disable every state write or become a secret-bearing
        // filename); fall back to a fresh valid ID.
        select_process_session_id(std::env::var("TIRITH_SESSION_ID").ok())
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

/// Privacy-safe `TIRITH_SESSION_ID` if set, else `None`. Values that cannot be
/// used as non-secret state filenames are treated as absent. Cached for the
/// process lifetime.
pub fn env_session_id() -> Option<&'static str> {
    static CACHED: OnceLock<Option<String>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            std::env::var("TIRITH_SESSION_ID")
                .ok()
                .filter(|s| is_valid_session_id(s))
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
    // Keep the cache lock across a miss's load/create/insert. Releasing it
    // between lookup and publication lets concurrent first callers both miss,
    // generate different UUIDs, and overwrite the same cache entry in turn; a
    // caller can then observe a different ID on its immediately following call.
    // This path is non-reentrant (its best-effort diagnostics only project and
    // print text), so serializing the infrequent fallback I/O is safe.
    let mut map = cache.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(entry) = map.get(&scope) {
        if entry.cached_at.elapsed().as_secs() < FALLBACK_CACHE_REFRESH_SECS {
            return entry.session_id.clone();
        }
    }

    let id = load_or_create_fallback_file(&scope);
    map.insert(
        scope,
        FallbackEntry {
            session_id: id.clone(),
            cached_at: Instant::now(),
        },
    );

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

const FALLBACK_SCOPE_UNKNOWN_INTEGRATION: &str = "unknown";
const FALLBACK_SCOPE_REDACTED_INTEGRATION: &str = "redacted";
const FALLBACK_SCOPE_REDACTED_CWD: &str = "privacy-redacted-cwd";
const FALLBACK_SCOPE_UNAVAILABLE_CWD: &str = "cwd-unavailable";

/// Scope key `{integration}-{cwd_hash_8chars}`. Both caller-controlled inputs
/// cross the mandatory durable-privacy boundary before they can influence a
/// filename or a stable digest. A secret-bearing integration/cwd collapses to
/// a fixed category; no raw secret, prefix, or secret-derived digest enters the
/// fallback path, atomic temp names, diagnostics, or cache key.
fn compute_scope() -> String {
    let integration = std::env::var("TIRITH_INTEGRATION").ok();
    let cwd = std::env::current_dir().ok();
    compute_scope_from(integration.as_deref(), cwd.as_deref())
}

fn compute_scope_from(integration: Option<&str>, cwd: Option<&Path>) -> String {
    let integration = privacy_safe_integration_scope(integration);
    let cwd_material = privacy_safe_cwd_scope_material(cwd);
    format!("{integration}-{}", scope_hash_8(&cwd_material))
}

fn privacy_safe_integration_scope(integration: Option<&str>) -> String {
    let raw = integration
        .filter(|value| !value.is_empty())
        .unwrap_or(FALLBACK_SCOPE_UNKNOWN_INTEGRATION);
    if crate::redact::privacy_project_durable_text(raw) != raw {
        return FALLBACK_SCOPE_REDACTED_INTEGRATION.to_string();
    }

    // Preserve the historical filename alphabet, but project again after
    // filtering: removing punctuation must not synthesize a credential-shaped
    // component that bypassed projection in the original representation.
    let sanitized: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if sanitized.is_empty() {
        return FALLBACK_SCOPE_UNKNOWN_INTEGRATION.to_string();
    }
    if crate::redact::privacy_project_durable_text(&sanitized) != sanitized {
        return FALLBACK_SCOPE_REDACTED_INTEGRATION.to_string();
    }

    sanitized.chars().take(32).collect()
}

fn privacy_safe_cwd_scope_material(cwd: Option<&Path>) -> String {
    let Some(cwd) = cwd else {
        return FALLBACK_SCOPE_UNAVAILABLE_CWD.to_string();
    };
    let raw = cwd.display().to_string();
    if crate::redact::privacy_project_durable_text(&raw) == raw {
        raw
    } else {
        FALLBACK_SCOPE_REDACTED_CWD.to_string()
    }
}

fn scope_hash_8(material: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(material.as_bytes());
    hex_encode_8(&hasher.finalize())
}

/// Encode the first 4 bytes (8 hex chars) of a digest.
fn hex_encode_8(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(4)])
}

/// Path for a fallback session file.
fn fallback_file_path(scope: &str) -> Option<PathBuf> {
    let state = crate::policy::state_dir()?;
    Some(fallback_file_path_in(&state, scope))
}

fn fallback_file_path_in(state: &Path, scope: &str) -> PathBuf {
    state.join("sessions").join(format!("fallback-{scope}.id"))
}

/// Load an existing fallback file if fresh, or create a new one.
fn load_or_create_fallback_file(scope: &str) -> String {
    let path = match fallback_file_path(scope) {
        Some(p) => p,
        None => return generate_session_id(),
    };
    load_or_create_fallback_path(&path)
}

fn load_or_create_fallback_path(path: &Path) -> String {
    // Open with O_NOFOLLOW so a symlink planted at the fallback path cannot
    // redirect this read onto another file, and take BOTH the freshness mtime and
    // the content from the SAME open handle: one inode for the stat and the read
    // closes the freshness-vs-read race a separate `symlink_metadata` +
    // `read_to_string` left open (a swap between the two could read a different
    // file than the one whose mtime we checked).
    if let Ok(file) = crate::util::open_read_no_follow_capped(path, FALLBACK_FILE_READ_CAP) {
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
                            if is_valid_session_id(&id) {
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
    write_fallback_file(path, &new_id);
    // repo-0342: a concurrent process may already have published. Re-read and
    // adopt the value currently visible on disk, narrowing the cross-process
    // race window. The cache mutex above is the convergence guarantee for
    // callers in this process; this reread does not serialize other processes.
    if let Ok(file) = crate::util::open_read_no_follow_capped(path, FALLBACK_FILE_READ_CAP) {
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
                if is_valid_session_id(&id) {
                    return id;
                }
            }
        }
    }
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
    fn privacy_unsafe_env_ids_fall_back_to_storable_uuid() {
        let canary = format!("ghp_canary_{}", "S".repeat(30));
        let private_scalar = format!("0x{}1", "0".repeat(63));
        for unsafe_id in [&canary, &private_scalar] {
            assert!(unsafe_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')));
            assert!(!is_valid_session_id(unsafe_id));
            assert!(crate::session_warnings::session_state_path(unsafe_id).is_none());

            let selected = select_process_session_id(Some(unsafe_id.to_string()));
            assert_ne!(selected.as_str(), unsafe_id.as_str());
            assert!(is_valid_session_id(&selected));
            assert!(uuid::Uuid::parse_str(&selected).is_ok());
            assert!(crate::session_warnings::session_state_path(&selected).is_some());
        }
    }

    #[test]
    fn resolver_and_state_path_share_one_session_id_predicate() {
        for valid in [generate_session_id(), "operator-session_1".to_string()] {
            assert!(is_valid_session_id(&valid));
            assert!(crate::session_warnings::session_state_path(&valid).is_some());
        }
        for invalid in [
            "../escape".to_string(),
            format!("ghp_canary_{}", "T".repeat(30)),
            format!("0x{}1", "0".repeat(63)),
        ] {
            assert!(!is_valid_session_id(&invalid));
            assert!(crate::session_warnings::session_state_path(&invalid).is_none());
        }
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
    fn benign_fallback_scope_remains_deterministic_and_partitioned() {
        let cwd_a = Path::new("/workspace/operator-project-a");
        let cwd_b = Path::new("/workspace/operator-project-b");
        let first = compute_scope_from(Some("claude-code"), Some(cwd_a));
        let repeated = compute_scope_from(Some("claude-code"), Some(cwd_a));
        let other_cwd = compute_scope_from(Some("claude-code"), Some(cwd_b));

        assert_eq!(first, repeated, "a benign scope must remain deterministic");
        assert_ne!(first, other_cwd, "benign cwd partitioning must remain");
        assert!(first.starts_with("claude-code-"));
        let hash = first.rsplit('-').next().unwrap();
        assert_eq!(hash.len(), 8);
        assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));

        // Projection must also run after filename sanitization: punctuation
        // removal cannot synthesize a canary-shaped durable component.
        let split_canary = format!("ghp_!canary_{}", "A".repeat(30));
        assert_eq!(
            privacy_safe_integration_scope(Some(&split_canary)),
            FALLBACK_SCOPE_REDACTED_INTEGRATION
        );

        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("tirith");
        let benign_cwd = dir.path().join("operator-project");
        std::fs::create_dir_all(&benign_cwd).unwrap();
        let benign_scope = compute_scope_from(Some("claude-code"), Some(&benign_cwd));
        let benign_path = fallback_file_path_in(&state_dir, &benign_scope);
        let first_id = load_or_create_fallback_path(&benign_path);
        assert_eq!(
            first_id,
            load_or_create_fallback_path(&benign_path),
            "the same benign integration/cwd/state must resolve to one UUID"
        );
    }

    #[test]
    fn fallback_filename_categorizes_secret_bearing_integration_and_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("tirith");
        let integration_canary = format!("ghp_canary_{}", "I".repeat(30));
        let cwd_canary = "AKIA00CANARYABCDEFGH";
        let secret_cwd = dir.path().join(format!("repo-{cwd_canary}"));
        std::fs::create_dir_all(&secret_cwd).unwrap();

        let raw_cwd = secret_cwd.display().to_string();
        let legacy_integration_fragment: String = integration_canary.chars().take(32).collect();
        let raw_integration_digest = scope_hash_8(&integration_canary);
        let raw_cwd_digest = scope_hash_8(&raw_cwd);

        let scope = compute_scope_from(Some(&integration_canary), Some(&secret_cwd));
        assert_eq!(
            scope,
            compute_scope_from(Some(&integration_canary), Some(&secret_cwd)),
            "safe categorical scope is stable"
        );
        assert!(scope.starts_with("redacted-"), "scope was {scope}");
        assert_eq!(
            privacy_safe_cwd_scope_material(Some(&secret_cwd)),
            FALLBACK_SCOPE_REDACTED_CWD
        );

        let path = fallback_file_path_in(&state_dir, &scope);
        let id = load_or_create_fallback_path(&path);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert_eq!(
            id,
            load_or_create_fallback_path(&path),
            "a secret-categorized path must resolve to one stable UUID"
        );

        let sessions_dir = state_dir.join("sessions");
        let names: Vec<String> = std::fs::read_dir(&sessions_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("fallback-{scope}.id")]);

        let rendered_path = format!("{:?}", sessions_dir.join(&names[0]));
        for forbidden in [
            integration_canary.as_str(),
            legacy_integration_fragment.as_str(),
            raw_integration_digest.as_str(),
            cwd_canary,
            raw_cwd_digest.as_str(),
        ] {
            assert!(
                !rendered_path.contains(forbidden),
                "fallback path retained raw or stable secret material: {rendered_path}"
            );
        }
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
        let _global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global session state");

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
    }

    /// A symlink planted at the fallback path must NOT be followed: the no-follow
    /// open refuses it, so the loader regenerates a fresh UUID instead of returning
    /// the link target's contents.
    #[cfg(unix)]
    #[test]
    fn test_load_fallback_refuses_symlink_and_regenerates() {
        let global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global session state");

        let scope = "symlink-test-abcd1234";
        let path = fallback_file_path(scope).expect("a fallback path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        // Plant a sentinel and a symlink at the fallback path pointing to it.
        let sentinel = global.roots().root.join("sentinel.txt");
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
    }

    /// `write_fallback_file` publishes the id atomically: the file holds exactly
    /// the id, no temp sibling remains, and a pre-existing file is replaced
    /// wholesale (not appended).
    #[cfg(unix)]
    #[test]
    fn test_write_fallback_atomic_replaces_and_leaves_no_temp() {
        let _global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global session state");

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
