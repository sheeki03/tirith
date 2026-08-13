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
    /// repo-0228: fingerprint of the environment the status was computed from.
    /// A warm cache from a DIFFERENT shell (other TIRITH_STATUS / AWS_PROFILE /
    /// KUBECONFIG) must not leak its context into this shell's prompt.
    #[serde(default)]
    env_fingerprint: String,
}

fn default_schema_version() -> u32 {
    1
}

/// repo-0228: hash the environment inputs the status is derived from.
fn current_env_fingerprint() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for name in [
        "TIRITH_STATUS",
        "TIRITH_SSH_REMOTE",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "KUBECONFIG",
    ] {
        h.update(name.as_bytes());
        h.update([0]);
        if let Ok(value) = std::env::var(name) {
            h.update(value.as_bytes());
        }
        h.update([0]);
    }
    format!("{:x}", h.finalize())
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
    // repo-0411: every interpolated value is env/config-derived and lands in
    // the prompt unescaped — sanitize terminal controls/bidi/newlines first.
    let mut out = format!(
        "[tirith:{}]",
        super::sanitize_for_human_output(&s.protection_mode, false)
    );
    for (k, v) in &s.contexts {
        // A malformed cache entry shouldn't render `[kube:]`.
        if v.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "[{}:{}]",
            super::sanitize_for_human_output(k, false),
            super::sanitize_for_human_output(v, false)
        ));
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
    let mut parts = vec![format!(
        "tirith: {}",
        super::sanitize_for_human_output(&s.protection_mode, false)
    )];
    for (k, v) in &s.contexts {
        if v.is_empty() {
            continue;
        }
        parts.push(format!(
            "{}: {}",
            super::sanitize_for_human_output(k, false),
            super::sanitize_for_human_output(v, false)
        ));
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
                    && env.env_fingerprint == current_env_fingerprint()
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

/// Protection posture classified for an exit-code contract. Built from the
/// `protection_mode` string [`protection_mode_from_status`] emits plus whether a
/// shell hook is configured. A manually-run `tirith status` is an EXTERNAL process
/// that sees only EXPORTED env: a protected shell's live mode lives in the
/// deliberately-non-exported `TIRITH_STATUS`, and only bash re-exports it (as
/// `TIRITH_BASH_EFFECTIVE_PROTECTION`). So a missing live signal does NOT prove
/// "unprotected": `"off"` with a configured hook is [`ConfiguredUnknown`] (live
/// mode unverifiable here, exit 0), and only `"off"` with NO hook is
/// [`HookMissing`] (a real failure). Drives the new `tirith status` exit code;
/// `prompt-status` stays always-0.
///
/// [`HookMissing`]: ProtectionHealth::HookMissing
/// [`ConfiguredUnknown`]: ProtectionHealth::ConfiguredUnknown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectionHealth {
    Guarded,
    WarnOnly,
    Degraded,
    /// Hook configured, but this external process can't see the live per-shell
    /// mode (it's non-exported; only bash re-exports it). Not provably off.
    ConfiguredUnknown,
    HookMissing,
    Unknown,
}

impl ProtectionHealth {
    /// Map a `protection_mode` string (same vocabulary as
    /// [`protection_mode_from_status`]) plus `hook_configured` to a health.
    /// `"off"` resolves to [`HookMissing`](Self::HookMissing) when no hook is
    /// configured, otherwise [`ConfiguredUnknown`](Self::ConfiguredUnknown).
    /// Anything outside the known
    /// vocabulary (including values passed through verbatim) is
    /// [`Unknown`](Self::Unknown).
    pub(crate) fn classify(protection_mode: &str, hook_configured: bool) -> Self {
        match protection_mode {
            // repo-0436: the env-exported mode string is only meaningful when a
            // hook actually exists — otherwise a wrapper or project environment
            // can forge "guarded" and claim protection that is not installed.
            "guarded" if hook_configured => Self::Guarded,
            "guarded" => Self::HookMissing,
            "warn-only" => Self::WarnOnly,
            "degraded" => Self::Degraded,
            // No live mode signal. A protected shell's TIRITH_STATUS is
            // non-exported, so an external `tirith status` legitimately sees "off"
            // even when protected — a CONFIGURED hook is not provably off (exit 0);
            // only a MISSING hook is a real failure.
            "off" if hook_configured => Self::ConfiguredUnknown,
            "off" => Self::HookMissing,
            _ => Self::Unknown,
        }
    }

    /// Exit-code contract: `0` when actively blocking ([`Guarded`]) OR when the
    /// hook is configured but the live mode is unverifiable from this external
    /// process ([`ConfiguredUnknown`] — not provably off). Every PROVABLY-reduced
    /// posture (warn-only, degraded, hook-missing, unknown) is `1`.
    ///
    /// [`Guarded`]: Self::Guarded
    /// [`ConfiguredUnknown`]: Self::ConfiguredUnknown
    pub(crate) fn exit_code(self) -> i32 {
        match self {
            Self::Guarded | Self::ConfiguredUnknown => 0,
            _ => 1,
        }
    }

    /// Stable lowercase label for human/JSON output.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Guarded => "guarded",
            Self::WarnOnly => "warn-only",
            Self::Degraded => "degraded",
            Self::ConfiguredUnknown => "configured",
            Self::HookMissing => "hook-missing",
            Self::Unknown => "unknown",
        }
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
        env_fingerprint: current_env_fingerprint(),
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
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};

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
        let _isolate = EnvGuard::remove("TIRITH_STATUS");
        for (input, expected) in [
            ("blocks", "guarded"),
            ("warn-only", "warn-only"),
            ("degraded", "degraded"),
            ("off", "off"),
        ] {
            let _value = EnvGuard::set("TIRITH_STATUS", std::path::Path::new(input));
            assert_eq!(detect_protection_mode(), expected);
        }
        assert_eq!(detect_protection_mode(), "off");
    }

    #[test]
    fn protection_mode_unknown_value_passes_through() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _isolate = EnvGuard::remove("TIRITH_STATUS");
        let _value = EnvGuard::set("TIRITH_STATUS", std::path::Path::new("futureValue"));
        assert_eq!(detect_protection_mode(), "futureValue");
    }

    #[test]
    fn protection_health_classify_and_exit_codes() {
        // Guarded exits 0 (actively blocking); ConfiguredUnknown also exits 0 (see below).
        let guarded = ProtectionHealth::classify("guarded", true);
        assert_eq!(guarded, ProtectionHealth::Guarded);
        assert_eq!(guarded.exit_code(), 0);
        assert_eq!(guarded.label(), "guarded");

        // Provably-reduced postures (warn-only, degraded, hook-missing, unknown) exit 1.
        let warn_only = ProtectionHealth::classify("warn-only", true);
        assert_eq!(warn_only, ProtectionHealth::WarnOnly);
        assert_eq!(warn_only.exit_code(), 1);

        // "off" splits on hook_configured. With NO hook it is a real failure.
        let hook_missing = ProtectionHealth::classify("off", false);
        assert_eq!(hook_missing, ProtectionHealth::HookMissing);
        assert_eq!(hook_missing.exit_code(), 1);
        assert_eq!(hook_missing.label(), "hook-missing");

        // With a CONFIGURED hook, "off" only means the live mode is invisible to
        // this external process (TIRITH_STATUS is non-exported) — not provably off,
        // so it does NOT fail the exit code.
        let configured = ProtectionHealth::classify("off", true);
        assert_eq!(configured, ProtectionHealth::ConfiguredUnknown);
        assert_eq!(configured.exit_code(), 0);
        assert_eq!(configured.label(), "configured");

        let degraded = ProtectionHealth::classify("degraded", true);
        assert_eq!(degraded, ProtectionHealth::Degraded);
        assert_eq!(degraded.exit_code(), 1);

        // Anything outside the known vocabulary is Unknown (hook flag irrelevant).
        let unknown = ProtectionHealth::classify("futureValue", true);
        assert_eq!(unknown, ProtectionHealth::Unknown);
        assert_eq!(unknown.exit_code(), 1);
        assert_eq!(unknown.label(), "unknown");
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
            env_fingerprint: String::new(),
        };
        let bytes = serde_json::to_vec(&env).unwrap();
        let back: CacheEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.protection_mode, "guarded");
        assert_eq!(back.contexts.len(), 2);
        assert!(back.ssh_remote);
        assert!(!back.sudo_active);
    }
}
