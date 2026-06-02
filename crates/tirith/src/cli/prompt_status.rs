//! `tirith prompt-status` — M8 ch6. A fast one-line status emitter for shell
//! prompts: protection posture plus cloud/k8s contexts and sudo/SSH state.
//!
//! Output shapes: short (`[tirith:guarded][aws:prod][kube:payments-prod]`),
//! long (`tirith: guarded; aws: prod; …`), and a stable `--json` envelope.
//!
//! Two caches keep it prompt-fast: the 5s process-global cache in
//! [`tirith_core::context_detect`] and a 30s per-user on-disk cache at
//! `$XDG_RUNTIME_DIR/tirith/prompt-<uid>.cache`. On a cold cache we read
//! kubeconfig + AWS env/files only and deliberately SKIP the gcloud/az
//! shell-outs `detect_all()` does (100ms-1.5s each, over the latency budget);
//! the richer set is available via `tirith context status`.
//!
//! No colour codes by default, so command substitution into `$PS1` / `$PROMPT`
//! never injects an unmatched ANSI escape that clobbers cursor accounting.
//!
//! Cache file format:
//!
//! ```json
//! {
//!   "captured_at": 1717000000,
//!   "protection_mode": "guarded",
//!   "contexts": {"aws": "prod", "kube": "payments-prod"},
//!   "ssh_remote": false,
//!   "sudo_active": false
//! }
//! ```
//!
//! The 30s TTL is a staleness tradeoff (a `kubectx` may lag up to 30s);
//! documented in `docs/prompt-integration.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tirith_core::context_detect::{self, Provider};
use tirith_core::sudo_session;

/// Per-user prompt-status cache TTL — longer than the 5s in-process cache
/// because prompt-status runs on every prompt redraw.
const CACHE_TTL_SECS: u64 = 30;

/// On-disk cache shape. Versioned for additive field changes.
#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    captured_at: u64,
    protection_mode: String,
    contexts: BTreeMap<String, String>,
    ssh_remote: bool,
    sudo_active: bool,
}

fn default_schema_version() -> u32 {
    1
}

/// Public JSON envelope written to stdout — like [`CacheEnvelope`] but without
/// the cache timestamp.
#[derive(Debug, Serialize)]
struct PublicEnvelope<'a> {
    schema_version: u32,
    protection_mode: &'a str,
    contexts: &'a BTreeMap<String, String>,
    ssh_remote: bool,
    sudo_active: bool,
}

/// Status snapshot — the in-memory view of what we're about to render.
struct Status {
    protection_mode: String,
    contexts: BTreeMap<String, String>,
    ssh_remote: bool,
    sudo_active: bool,
}

/// Entry point. Flag precedence: `--json` wins, then `--short`, else long form.
/// `--short` and `--json` are not mutually exclusive in clap; both → JSON.
pub fn run(short: bool, json: bool) -> i32 {
    let status = match load_or_refresh() {
        Ok(s) => s,
        Err(_) => {
            // Never fail the prompt — emit a minimal off line on any error.
            Status {
                protection_mode: "off".into(),
                contexts: BTreeMap::new(),
                ssh_remote: false,
                sudo_active: false,
            }
        }
    };

    if json {
        let env = PublicEnvelope {
            schema_version: 1,
            protection_mode: &status.protection_mode,
            contexts: &status.contexts,
            ssh_remote: status.ssh_remote,
            sudo_active: status.sudo_active,
        };
        match serde_json::to_string(&env) {
            Ok(s) => {
                println!("{s}");
                0
            }
            // The JSON path must not abort the prompt either — return 0 with an
            // empty envelope rather than a raw error.
            Err(_) => {
                println!(
                    "{{\"schema_version\":1,\"protection_mode\":\"off\",\"contexts\":{{}},\"ssh_remote\":false,\"sudo_active\":false}}"
                );
                0
            }
        }
    } else if short {
        println!("{}", format_short(&status));
        0
    } else {
        println!("{}", format_long(&status));
        0
    }
}

/// Render the bracketed short form: `[tirith:guarded][aws:prod][kube:…]`.
///
/// Starts with `[tirith:<mode>]` for downstream parsers; provider segments are
/// BTreeMap-sorted; ssh/sudo segments appended only when active.
fn format_short(s: &Status) -> String {
    let mut out = format!("[tirith:{}]", s.protection_mode);
    for (k, v) in &s.contexts {
        // A malformed cache entry shouldn't render `[kube:]`.
        if v.is_empty() {
            continue;
        }
        out.push_str(&format!("[{k}:{v}]"));
    }
    if s.ssh_remote {
        out.push_str("[ssh:remote]");
    }
    if s.sudo_active {
        out.push_str("[sudo:active]");
    }
    out
}

/// Render the semicolon-separated long form.
fn format_long(s: &Status) -> String {
    let mut parts = vec![format!("tirith: {}", s.protection_mode)];
    for (k, v) in &s.contexts {
        if v.is_empty() {
            continue;
        }
        parts.push(format!("{k}: {v}"));
    }
    if s.ssh_remote {
        parts.push("ssh: remote".into());
    }
    if s.sudo_active {
        parts.push("sudo: session active".into());
    }
    parts.join("; ")
}

/// Resolve a fresh [`Status`], using the on-disk cache when <30s old and
/// refreshing otherwise. Cache failures fall through to a refresh.
fn load_or_refresh() -> Result<Status, String> {
    let cache_path = resolve_cache_path();

    // Cache hit path: read, parse, check TTL. Any error → refresh.
    if let Some(path) = &cache_path {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(env) = serde_json::from_slice::<CacheEnvelope>(&bytes) {
                let now = unix_now();
                if env.captured_at <= now
                    && now - env.captured_at < CACHE_TTL_SECS
                    && env.schema_version == 1
                {
                    return Ok(Status {
                        protection_mode: env.protection_mode,
                        contexts: env.contexts,
                        ssh_remote: env.ssh_remote,
                        sudo_active: env.sudo_active,
                    });
                }
            }
        }
    }

    let status = refresh_status();
    // Best-effort cache write; a failure just means the next call refreshes again.
    if let Some(path) = &cache_path {
        let _ = write_cache(path, &status);
    }
    Ok(status)
}

/// Refresh from fast inputs only (`TIRITH_STATUS`, `TIRITH_SSH_REMOTE`, the
/// sudo-session file, kubeconfig, AWS env/config). Deliberately does NOT call
/// `context_detect::detect_all()` — its `gcloud`/`az` shell-outs blow the
/// per-prompt latency budget; the full set is at `tirith context status`.
fn refresh_status() -> Status {
    let protection_mode = detect_protection_mode();
    let ssh_remote = std::env::var("TIRITH_SSH_REMOTE")
        .map(|v| {
            let trimmed = v.trim();
            !trimmed.is_empty() && trimmed != "0" && !trimmed.eq_ignore_ascii_case("false")
        })
        .unwrap_or(false);
    let sudo_active = sudo_session::read_active_session().is_some();

    let mut contexts = BTreeMap::new();
    if let Ok(ctx) = context_detect::detect_single(Provider::Kube) {
        contexts.insert(Provider::Kube.as_str().to_string(), ctx.context);
    }
    if let Ok(ctx) = context_detect::detect_single(Provider::Aws) {
        contexts.insert(Provider::Aws.as_str().to_string(), ctx.context);
    }
    // gcp/az skipped for the latency budget (see doc comment).

    Status {
        protection_mode,
        contexts,
        ssh_remote,
        sudo_active,
    }
}

/// Read `TIRITH_STATUS` and map it via [`protection_mode_from_status`] (env
/// wrapper; the pure mapping is shared with `tirith doctor --quick`).
fn detect_protection_mode() -> String {
    protection_mode_from_status(std::env::var("TIRITH_STATUS").ok().as_deref())
}

/// Single source of truth mapping a hook-exported `TIRITH_STATUS` value to the
/// cross-codebase `protection_mode` vocabulary, shared by `prompt-status` and
/// `doctor --quick` so they can't drift. Documented in `docs/prompt-integration.md`.
///
/// | shell hook value | prompt label  |
/// |------------------|---------------|
/// | `blocks`         | `guarded`     |
/// | `warn-only`      | `warn-only`   |
/// | `degraded`       | `degraded`    |
/// | `off` / `""` / absent | `off`    |
/// | (other)          | (verbatim)    |
pub(crate) fn protection_mode_from_status(status: Option<&str>) -> String {
    match status {
        Some("blocks") => "guarded".into(),
        Some("warn-only") => "warn-only".into(),
        Some("degraded") => "degraded".into(),
        Some("off") | Some("") | None => "off".into(),
        Some(other) => other.to_string(),
    }
}

/// Test-only `pub(crate)` shim exposing the real env-reading
/// `detect_protection_mode` to `cli::doctor`'s cross-module agreement test.
/// Caller sets `TIRITH_STATUS` under the shared env lock.
#[cfg(test)]
pub(crate) fn protection_mode_for_test() -> String {
    detect_protection_mode()
}

/// Resolve the cache file path: `$XDG_RUNTIME_DIR/tirith/prompt-<uid>.cache`
/// first, else `state_dir()/prompt-<uid>.cache`. Both use restrictive perms
/// (0700 parent, 0600 file) so a multi-user box can't read another user's
/// protection state. `None` (→ skip caching) only when neither dir resolves.
fn resolve_cache_path() -> Option<PathBuf> {
    let uid = current_uid();
    let file_name = format!("prompt-{uid}.cache");

    if let Ok(rt_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let trimmed = rt_dir.trim();
        if !trimmed.is_empty() {
            let parent = PathBuf::from(trimmed).join("tirith");
            if ensure_dir_0700(&parent).is_ok() {
                return Some(parent.join(file_name));
            }
        }
    }

    if let Some(state) = tirith_core::policy::state_dir() {
        if ensure_dir_0700(&state).is_ok() {
            return Some(state.join(file_name));
        }
    }
    None
}

/// Best-effort uid, only to namespace the cache file. `0` on non-Unix (the
/// path is already user-scoped, so no collision).
fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `getuid()` is a thread-safe libc call that always
        // succeeds and returns the current real uid.
        unsafe { libc::getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Ensure `dir` exists with `0700` perms on Unix. Errors propagate so the
/// caller can skip caching gracefully.
fn ensure_dir_0700(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        // Ignore failures — the dir may already be 0700, or be one we don't own;
        // never abort the prompt on a perms issue.
        let _ = fs::set_permissions(dir, perms);
    }
    Ok(())
}

/// Write the cache file with `0600` perms on Unix, atomically (tempfile +
/// rename) so a concurrent reader never sees a half-written envelope. Falls
/// back to a direct write if the tempfile can't be created.
fn write_cache(path: &std::path::Path, status: &Status) -> std::io::Result<()> {
    let envelope = CacheEnvelope {
        schema_version: 1,
        captured_at: unix_now(),
        protection_mode: status.protection_mode.clone(),
        contexts: status.contexts.clone(),
        ssh_remote: status.ssh_remote,
        sudo_active: status.sudo_active,
    };
    let body = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;

    let parent = match path.parent() {
        Some(p) => p,
        None => return write_direct(path, &body),
    };
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return write_direct(path, &body),
    };
    let tmp_name = format!(".{file_name}.{}.tmp", std::process::id());
    let tmp_path = parent.join(tmp_name);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = match opts.open(&tmp_path) {
        Ok(f) => f,
        Err(_) => {
            return write_direct(path, &body);
        }
    };
    use std::io::Write as _;
    if let Err(e) = f.write_all(&body) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(f);
    match fs::rename(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

fn write_direct(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    let mut opts = fs::OpenOptions::new();
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

/// Test-only: render `format_short` from a synthesized status, independent of
/// the host's real kubeconfig / AWS state.
#[cfg(test)]
fn render_short_for_test(
    protection_mode: &str,
    contexts: &[(&str, &str)],
    ssh_remote: bool,
    sudo_active: bool,
) -> String {
    let mut map = BTreeMap::new();
    for (k, v) in contexts {
        map.insert((*k).to_string(), (*v).to_string());
    }
    format_short(&Status {
        protection_mode: protection_mode.into(),
        contexts: map,
        ssh_remote,
        sudo_active,
    })
}

#[cfg(test)]
fn render_long_for_test(
    protection_mode: &str,
    contexts: &[(&str, &str)],
    ssh_remote: bool,
    sudo_active: bool,
) -> String {
    let mut map = BTreeMap::new();
    for (k, v) in contexts {
        map.insert((*k).to_string(), (*v).to_string());
    }
    format_long(&Status {
        protection_mode: protection_mode.into(),
        contexts: map,
        ssh_remote,
        sudo_active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Local serialization lock for env-var-mutating tests here (touch only
    /// `TIRITH_STATUS`; `tirith_core::TEST_ENV_LOCK` isn't reachable).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn short_form_matches_spec_example() {
        let line = render_short_for_test(
            "guarded",
            &[("aws", "prod"), ("kube", "payments-prod")],
            false,
            false,
        );
        assert_eq!(line, "[tirith:guarded][aws:prod][kube:payments-prod]");
    }

    #[test]
    fn short_form_includes_ssh_and_sudo_when_active() {
        let line = render_short_for_test("guarded", &[("aws", "prod")], true, true);
        assert_eq!(line, "[tirith:guarded][aws:prod][ssh:remote][sudo:active]");
    }

    #[test]
    fn short_form_no_contexts_is_just_tirith_segment() {
        let line = render_short_for_test("off", &[], false, false);
        assert_eq!(line, "[tirith:off]");
    }

    #[test]
    fn short_form_skips_empty_context_values() {
        // A corrupt cache must not render `[kube:]`.
        let line = render_short_for_test("guarded", &[("kube", "")], false, false);
        assert_eq!(line, "[tirith:guarded]");
    }

    #[test]
    fn long_form_matches_spec_example() {
        let line = render_long_for_test(
            "guarded",
            &[("aws", "prod"), ("kube", "payments-prod")],
            false,
            true,
        );
        assert_eq!(
            line,
            "tirith: guarded; aws: prod; kube: payments-prod; sudo: session active",
        );
    }

    #[test]
    fn long_form_no_contexts_only_tirith() {
        let line = render_long_for_test("off", &[], false, false);
        assert_eq!(line, "tirith: off");
    }

    #[test]
    fn protection_mode_maps_known_values() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for (input, expected) in [
            ("blocks", "guarded"),
            ("warn-only", "warn-only"),
            ("degraded", "degraded"),
            ("off", "off"),
        ] {
            // SAFETY: serialized via ENV_LOCK above.
            unsafe {
                std::env::set_var("TIRITH_STATUS", input);
            }
            assert_eq!(detect_protection_mode(), expected);
        }
        unsafe {
            std::env::remove_var("TIRITH_STATUS");
        }
        assert_eq!(detect_protection_mode(), "off");
    }

    #[test]
    fn protection_mode_unknown_value_passes_through() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized via ENV_LOCK above.
        unsafe {
            std::env::set_var("TIRITH_STATUS", "futureValue");
        }
        assert_eq!(detect_protection_mode(), "futureValue");
        unsafe {
            std::env::remove_var("TIRITH_STATUS");
        }
    }

    #[test]
    fn cache_envelope_round_trips_via_serde() {
        let env = CacheEnvelope {
            schema_version: 1,
            captured_at: 1_700_000_000,
            protection_mode: "guarded".into(),
            contexts: BTreeMap::from([
                ("aws".to_string(), "prod".to_string()),
                ("kube".to_string(), "payments-prod".to_string()),
            ]),
            ssh_remote: true,
            sudo_active: false,
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let back: CacheEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.protection_mode, "guarded");
        assert_eq!(back.contexts.len(), 2);
        assert!(back.ssh_remote);
        assert!(!back.sudo_active);
    }
}
