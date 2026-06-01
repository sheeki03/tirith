//! `tirith prompt-status` — M8 ch6.
//!
//! A *fast* status emitter designed to be called from a shell prompt on every
//! redraw. Outputs one line summarising the operator's current protection
//! posture plus the cloud / k8s contexts and sudo / SSH state.
//!
//! ## Output shapes
//!
//! - **Short** (`--short`, the default form used in PS1 hooks):
//!   `[tirith:guarded][aws:prod][kube:payments-prod]`
//! - **Long** (no `--short`, no `--json`):
//!   `tirith: guarded; aws: prod; kube: payments-prod; sudo: session active`
//! - **JSON** (`--json`): a stable envelope keyed on `protection_mode`,
//!   `contexts`, `ssh_remote`, `sudo_active`.
//!
//! ## Latency model
//!
//! Two layers of caching:
//!
//! 1. **Process-global cache** in [`tirith_core::context_detect`] (5s TTL —
//!    a small file read + minimal YAML parse for kubeconfig).
//! 2. **Per-user on-disk cache** in `$XDG_RUNTIME_DIR/tirith/prompt-<uid>.cache`
//!    (30s TTL — used by *this* command to avoid re-running detection on
//!    every prompt redraw, even within a fresh process).
//!
//! On a cold-cache invocation we read kubeconfig + AWS env/files only. We
//! deliberately **skip the gcloud / az shell-outs** that `detect_all()`
//! does — those add 100ms-1.5s each in the worst case and would blow the
//! prompt-status latency budget. The richer detection still runs from
//! `tirith context status` and the engine hot path (which is gated on a
//! cloud-CLI leader anyway).
//!
//! No colour codes are emitted by default. A future `--color` opt-in could
//! lift them in; for now we keep the output prompt-safe so command
//! substitution into `$PS1` / `$PROMPT` never injects an unmatched ANSI
//! escape that would clobber line-editor cursor accounting.
//!
//! ## Cache file format
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
//! 30-second TTL is the staleness tradeoff: if the operator runs `kubectx`
//! the prompt may lag for up to 30s before re-detecting. We accept that
//! over re-reading kubeconfig on every prompt redraw. Operators can force
//! a refresh by invoking `tirith context status` or by waiting 30s. The
//! tradeoff is documented in `docs/prompt-integration.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tirith_core::context_detect::{self, Provider};
use tirith_core::sudo_session;

/// Per-user prompt-status cache TTL. Longer than the in-process detection
/// cache (5s) because prompt-status is invoked on EVERY prompt redraw —
/// the file cache is the difference between a single kubeconfig read per
/// prompt and one read per 30s.
const CACHE_TTL_SECS: u64 = 30;

/// On-disk cache shape. Versioned (`schema_version`) so a future field
/// addition can be done as an additive change without breaking
/// already-cached files.
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

/// Public JSON envelope written to stdout. Distinct from
/// [`CacheEnvelope`] only because the public envelope omits the cache
/// timestamp (callers shouldn't have to care about caching).
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

/// Entry point. Precedence when multiple format flags are passed:
/// `--json` always wins (JSON envelope), then `--short` (bracketed PS1
/// line), and the long human form is the default. `--short` and `--json`
/// are NOT enforced as mutually exclusive in clap — passing both is
/// legal and produces JSON (PR-127 review #23, comment-analyzer #4).
pub fn run(short: bool, json: bool) -> i32 {
    let status = match load_or_refresh() {
        Ok(s) => s,
        Err(_) => {
            // Never fail the prompt. On any error, emit a minimal off line
            // so the shell prompt still draws cleanly.
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
            // Even the JSON path must not abort the prompt — return 0 with
            // an empty envelope rather than letting the shell display a
            // raw error.
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
/// Always starts with the `[tirith:<mode>]` segment so a downstream parser
/// can quickly recognise the line. Provider segments are sorted by
/// provider name (BTreeMap iteration order) for deterministic output.
///
/// SSH-remote and sudo-active state are appended as their own segments
/// only when active — keeps the bare-prompt case ([tirith:guarded]) tight.
fn format_short(s: &Status) -> String {
    let mut out = format!("[tirith:{}]", s.protection_mode);
    for (k, v) in &s.contexts {
        // Skip silently if a value is empty — shouldn't happen, but a
        // malformed cache entry shouldn't produce `[kube:]`.
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

/// Resolve a fresh [`Status`], using the on-disk cache when it's <30s
/// old and refreshing otherwise. Cache failures are non-fatal — we
/// silently fall through to a refresh.
fn load_or_refresh() -> Result<Status, String> {
    let cache_path = resolve_cache_path();

    // Cache hit path. Read, parse, check TTL. Any error → refresh.
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
    // Best-effort cache write. A write failure is silent — the next call
    // will refresh again, which is correct behavior.
    if let Some(path) = &cache_path {
        let _ = write_cache(path, &status);
    }
    Ok(status)
}

/// Refresh from authoritative sources. Reads only fast inputs:
/// - `TIRITH_STATUS` env var (shell-hook-exported protection level).
/// - `TIRITH_SSH_REMOTE` env var.
/// - Sudo-session file via [`tirith_core::sudo_session`].
/// - kubeconfig (file read + small YAML parse).
/// - AWS env / config file (file existence check, no parsing).
///
/// Crucially this does **NOT** call `context_detect::detect_all()` because
/// that shell-outs to `gcloud` / `az` — the per-prompt latency budget
/// can't afford it. The user's full provider set is available via
/// `tirith context status`.
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
    // Kube: fast — reads `~/.kube/config` and parses YAML. The 5s
    // process-local cache in `context_detect` coalesces repeat reads.
    if let Ok(ctx) = context_detect::detect_single(Provider::Kube) {
        contexts.insert(Provider::Kube.as_str().to_string(), ctx.context);
    }
    // AWS: fast — env precedence, then a stat() on `~/.aws/config`.
    if let Ok(ctx) = context_detect::detect_single(Provider::Aws) {
        contexts.insert(Provider::Aws.as_str().to_string(), ctx.context);
    }
    // Skip gcp/az for latency budget. They're available from
    // `tirith context status` when the operator wants them.

    Status {
        protection_mode,
        contexts,
        ssh_remote,
        sudo_active,
    }
}

/// Read `TIRITH_STATUS` and map shell-hook values to prompt-status terms.
///
/// Thin env-reading wrapper over [`protection_mode_from_status`] — the pure
/// mapping lives there so `tirith doctor --quick` can share it (see
/// `cli::doctor::gather_quick_info`) and the two surfaces can never drift.
fn detect_protection_mode() -> String {
    protection_mode_from_status(std::env::var("TIRITH_STATUS").ok().as_deref())
}

/// Map a hook-exported `TIRITH_STATUS` value to the cross-codebase
/// `protection_mode` vocabulary. The single source of truth for this mapping,
/// shared by `tirith prompt-status` (via [`detect_protection_mode`]) and
/// `tirith doctor --quick` (via `cli::doctor`) so both report the same mode
/// for the same status. Documented in `docs/prompt-integration.md`.
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

/// Test-only: exercise the real env-reading `detect_protection_mode` so the
/// cross-module agreement test in `cli::doctor` compares the genuine
/// `prompt-status` entry point (not just the shared pure mapping) against
/// `doctor --quick`. Reachable across the `cli` module because it is
/// `pub(crate)`. The caller is responsible for setting `TIRITH_STATUS` under
/// the shared env lock.
#[cfg(test)]
pub(crate) fn protection_mode_for_test() -> String {
    detect_protection_mode()
}

/// Resolve the cache file path. Preference order:
/// 1. `$XDG_RUNTIME_DIR/tirith/prompt-<uid>.cache` (Linux runtime dir —
///    tmpfs, per-user, cleared on logout).
/// 2. `state_dir()/prompt-<uid>.cache` (macOS / no-XDG fallback).
///
/// Both branches set restrictive perms (`0700` on the parent, `0600` on
/// the file itself) so a multi-user box can't read another user's
/// cached protection state.
///
/// Returns `None` only when neither dir is resolvable — degenerate (no
/// HOME, no XDG_RUNTIME_DIR). In that case we just skip caching.
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

/// Best-effort uid lookup. Used only to namespace the cache file path so
/// a multi-user system doesn't collide. Returns `0` as a sentinel on
/// non-Unix or lookup failure (the file name still ends up unique
/// per-OS-user because either the `state_dir()` or `XDG_RUNTIME_DIR`
/// path is already user-scoped).
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

/// Ensure `dir` exists with `0700` perms on Unix. No-op on other OSes
/// beyond create_dir_all. Errors propagate so the caller can skip
/// caching gracefully.
fn ensure_dir_0700(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        // Ignore failures here — the dir may already be 0700 from a
        // previous run, and a perms-set on an existing dir we don't own
        // would surface as PermissionDenied. We never want to abort the
        // prompt on a perms issue.
        let _ = fs::set_permissions(dir, perms);
    }
    Ok(())
}

/// Write the cache file with `0600` perms on Unix. Atomic via
/// write-tempfile-then-rename, so a concurrent reader (split-pane terminal,
/// another shell instance) never observes a half-written envelope.
///
/// If the tempfile path can't be created (e.g. read-only directory) we
/// fall back to a direct write — the worst case there is the documented
/// "parse failure → refresh" path, which is operationally fine.
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
            // Tempfile creation failed — fall back to the direct write.
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

/// Test-only helper — render `format_short` from a synthesized status so
/// the shape doesn't depend on the host's real kubeconfig / AWS state.
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

    /// Local serialization lock for env-var-mutating tests in this
    /// module. `tirith_core::TEST_ENV_LOCK` is `pub(crate)` to its own
    /// crate and isn't reachable from here; tests in this module touch
    /// `TIRITH_STATUS` only, so a per-module lock is sufficient.
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
        // Empty value should never appear, even if a corrupt cache slips
        // one in — guard against `[kube:]` rendering.
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
