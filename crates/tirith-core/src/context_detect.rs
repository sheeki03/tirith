//! Operational-context detection — M8 ch1.
//!
//! Reads the currently-selected context for each supported cloud / k8s provider
//! so `rules::context` can decide whether a command's target is labeled
//! production. Four readers: **kube** (`~/.kube/config` `current-context`,
//! honoring the first `$KUBECONFIG` entry); **aws** (`$AWS_PROFILE` then
//! `$AWS_DEFAULT_PROFILE`, falling back to `~/.aws` `default` — only the profile
//! *name*, never credentials); **gcloud** (`gcloud config list --format=json`,
//! context `<account>@<project>`); **az** (`az account show -o json`,
//! subscription `name`). The gcloud/az shell-outs have a hard 1.5s timeout.
//!
//! Every external command goes through [`run_with_timeout`], which drains stdout
//! on a helper thread (no pipe-buffer deadlock) and `kill()`s on timeout. The hot
//! path never blocks: callers gate detection on the parsed leader being a cloud
//! CLI, and a 5s per-process cache keeps repeats cheap.
//!
//! ## Cache semantics
//!
//! [`detect_all`] caches results in a process-global `OnceLock`/`Mutex` for
//! [`CACHE_TTL_SECS`] (5s). Failures are cached too (negative caching keeps a
//! permanently-broken `gcloud` from being re-invoked every second).
//!
//! ## Honest scope
//!
//! These signals are operator-trust, not adversary-resistant: the strings read
//! are caller-controlled (user-writable config files). The labels file
//! (`~/.config/tirith/context-labels.yaml`) is the security boundary — an
//! attacker who can mutate it can already run anything. We trust it to declare
//! which contexts are critical, then lift the current-context string into a
//! finding when a destructive command targets a labeled context.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hard per-call wall-clock cap for any shell-out; the child is killed past it.
const SHELL_OUT_TIMEOUT: Duration = Duration::from_millis(1500);
const SHELL_OUT_CAP: usize = 1024 * 1024;

/// Per-process cache TTL — keeps the hot path responsive during a burst of
/// cloud-CLI commands.
pub const CACHE_TTL_SECS: u64 = 5;

/// Provider identifier. The string form matches the `provider:context` label
/// keys (e.g. `kube:prod-us-east`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Provider {
    Kube,
    Aws,
    Gcp,
    Azure,
}

impl Provider {
    /// Label-key prefix (`kube`, `aws`, `gcp`, `azure`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kube => "kube",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
        }
    }

    /// Parse from the `provider:context` label-key prefix.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "kube" | "k8s" | "kubernetes" => Some(Self::Kube),
            "aws" => Some(Self::Aws),
            "gcp" | "gcloud" | "google" => Some(Self::Gcp),
            "azure" | "az" => Some(Self::Azure),
            _ => None,
        }
    }

    /// Map a parsed command leader (lowercased basename) to the provider it
    /// targets, if any.
    pub fn from_leader(leader: &str) -> Option<Self> {
        match leader {
            "kubectl" | "kustomize" | "helm" | "argocd" => Some(Self::Kube),
            "aws" | "aws-vault" => Some(Self::Aws),
            "gcloud" => Some(Self::Gcp),
            "az" => Some(Self::Azure),
            _ => None,
        }
    }
}

/// Failure reason returned by a single-provider reader. `NotConfigured` is
/// absence of signal (no config / no CLI on PATH), not an error; the others are
/// operational failures that get logged and negative-cached for
/// [`CACHE_TTL_SECS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextDetectFailure {
    /// The provider isn't configured on this machine — absence of signal.
    NotConfigured,
    /// The shell-out exceeded [`SHELL_OUT_TIMEOUT`]. The child was killed.
    Timeout,
    /// The shell-out exited with a non-zero status code.
    Exited(i32),
    /// An I/O failure (spawn / read / JSON parse). Carries a short reason string.
    Io(String),
}

impl std::fmt::Display for ContextDetectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "not configured"),
            Self::Timeout => write!(f, "timeout after {}ms", SHELL_OUT_TIMEOUT.as_millis()),
            Self::Exited(c) => write!(f, "exited with status {c}"),
            Self::Io(reason) => write!(f, "io error: {reason}"),
        }
    }
}

/// Resolved active context for a single provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderContext {
    pub provider: Provider,
    /// The operator-facing context name (kube `current-context`, aws profile
    /// name, gcp `<account>@<project>`, azure subscription name).
    pub context: String,
}

impl ProviderContext {
    /// The `provider:context` label-key form.
    pub fn label_key(&self) -> String {
        format!("{}:{}", self.provider.as_str(), self.context)
    }
}

/// Combined result of detecting every provider; failures are exposed for the
/// audit log.
#[derive(Debug, Clone, Default)]
pub struct DetectionResult {
    pub contexts: BTreeMap<Provider, ProviderContext>,
    pub failures: BTreeMap<Provider, ContextDetectFailure>,
}

impl DetectionResult {
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }
}

/// Process-global cache (`OnceLock`-deferred init, fine-grained inner `Mutex`).
static CACHE: OnceLock<Mutex<CacheEntry>> = OnceLock::new();
type ProviderDetection = Result<ProviderContext, ContextDetectFailure>;
type ProviderCache = BTreeMap<Provider, (Instant, ContextFingerprint, ProviderDetection)>;
static PROVIDER_CACHE: OnceLock<Mutex<ProviderCache>> = OnceLock::new();

#[derive(Default)]
struct CacheEntry {
    captured_at: Option<Instant>,
    result: DetectionResult,
    fingerprint: ContextFingerprint,
}

/// repo-0266: a 5-second blind TTL let a long-lived process evaluate a
/// destructive command against a context that had already changed underneath
/// it (`kubectl config use-context prod` seconds after a dev-context call).
/// The cache is only honored while the fingerprint of the provider inputs
/// (relevant env vars + config-file mtimes) is unchanged; any change forces a
/// fresh detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ContextFingerprint {
    kubeconfig_env: Option<String>,
    kubeconfig_mtime: Option<std::time::SystemTime>,
    kube_default_mtime: Option<std::time::SystemTime>,
    aws_profile: Option<String>,
    aws_default_profile: Option<String>,
    aws_config_mtime: Option<std::time::SystemTime>,
    aws_credentials_mtime: Option<std::time::SystemTime>,
    azure_profile: Option<String>,
    gcloud_config: Option<String>,
}

fn file_mtime(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn current_fingerprint() -> ContextFingerprint {
    let home = home::home_dir();
    let kube_default = home.as_ref().map(|h| h.join(".kube").join("config"));
    let aws_config = home.as_ref().map(|h| h.join(".aws").join("config"));
    let aws_credentials = home.as_ref().map(|h| h.join(".aws").join("credentials"));
    ContextFingerprint {
        kubeconfig_env: std::env::var("KUBECONFIG").ok(),
        kubeconfig_mtime: std::env::var("KUBECONFIG")
            .ok()
            .and_then(|v| {
                let separator = if cfg!(windows) { ';' } else { ':' };
                v.split(separator).next().map(str::trim).map(String::from)
            })
            .as_deref()
            .map(std::path::Path::new)
            .and_then(file_mtime),
        kube_default_mtime: kube_default.as_deref().and_then(file_mtime),
        aws_profile: std::env::var("AWS_PROFILE").ok(),
        aws_default_profile: std::env::var("AWS_DEFAULT_PROFILE").ok(),
        aws_config_mtime: aws_config.as_deref().and_then(file_mtime),
        aws_credentials_mtime: aws_credentials.as_deref().and_then(file_mtime),
        azure_profile: std::env::var("AZURE_CONFIG_DIR").ok(),
        gcloud_config: std::env::var("CLOUDSDK_CONFIG").ok(),
    }
}

fn cache() -> &'static Mutex<CacheEntry> {
    CACHE.get_or_init(|| Mutex::new(CacheEntry::default()))
}

fn provider_cache() -> &'static Mutex<ProviderCache> {
    PROVIDER_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Detect the active context for every configured provider, with a per-process
/// cache. Hot-path-safe: never blocks longer than [`SHELL_OUT_TIMEOUT`] per
/// provider when cold, instant on a cache hit.
///
/// Test-only: `TIRITH_CONTEXT_DETECT_DISABLE=1` returns an empty result with no
/// filesystem / shell-out access, so integration tests don't pick up the
/// developer's real cloud config. repo-0265: honored ONLY in debug builds — a
/// production (release) binary ignores the variable entirely, so an
/// attacker-controlled environment cannot silence context detection.
pub(crate) fn context_detect_disabled() -> bool {
    cfg!(debug_assertions)
        && std::env::var("TIRITH_CONTEXT_DETECT_DISABLE")
            .ok()
            .as_deref()
            == Some("1")
}

pub fn detect_all() -> DetectionResult {
    if context_detect_disabled() {
        return DetectionResult::default();
    }

    let now = Instant::now();
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(captured_at) = guard.captured_at {
        if now.duration_since(captured_at) < Duration::from_secs(CACHE_TTL_SECS) {
            // repo-0266: the TTL only applies while the provider inputs are
            // byte-identical; a config rewrite or env change invalidates early.
            if guard.fingerprint == current_fingerprint() {
                return guard.result.clone();
            }
        }
    }

    // Snapshot the provider inputs BEFORE detection runs. Sampling afterwards
    // would record an input that changed mid-detection as fresh, serving the
    // stale result for the whole TTL — the exact staleness repo-0266's
    // fingerprint check exists to prevent. (`detect_provider` below already
    // samples first.)
    let fingerprint = current_fingerprint();
    let fresh = refresh_all();
    guard.captured_at = Some(now);
    guard.fingerprint = fingerprint;
    guard.result = fresh.clone();
    fresh
}

/// Detect the active context for a single provider (used by `tirith context
/// status` for per-provider failure detail). Not cached — `detect_all` coalesces.
pub fn detect_single(provider: Provider) -> Result<ProviderContext, ContextDetectFailure> {
    match provider {
        Provider::Kube => detect_kube(),
        Provider::Aws => detect_aws(),
        Provider::Gcp => detect_gcloud(),
        Provider::Azure => detect_azure(),
    }
}

/// Detect only the command's provider and cache that result. This keeps the
/// analysis hot path from executing unrelated provider CLIs.
pub fn detect_provider(provider: Provider) -> Result<ProviderContext, ContextDetectFailure> {
    if context_detect_disabled() {
        return Err(ContextDetectFailure::NotConfigured);
    }
    let now = Instant::now();
    let fingerprint = current_fingerprint();
    {
        let guard = match provider_cache().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some((captured_at, cached_fingerprint, result)) = guard.get(&provider) {
            if now.duration_since(*captured_at) < Duration::from_secs(CACHE_TTL_SECS)
                && *cached_fingerprint == fingerprint
            {
                return result.clone();
            }
        }
    }
    // The lock is NOT held across `detect_single`: it spawns a cloud CLI and can
    // block for the whole SHELL_OUT_TIMEOUT, and this runs on the
    // command-analysis path. Holding it would stall every other caller,
    // including callers for a different provider, for that entire interval.
    // Two threads racing a cold entry both shell out and store the same answer,
    // which is harmless.
    let result = detect_single(provider);
    let mut guard = match provider_cache().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.insert(provider, (Instant::now(), fingerprint, result.clone()));
    result
}

/// Evict the per-process detection cache.
///
/// Production calls this when a command is about to CHANGE provider
/// configuration, so the next command cannot reuse a stale context during the
/// five-second TTL; tests call it between scenarios for the same reason.
pub fn invalidate_cache() {
    if let Some(lock) = CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = CacheEntry::default();
        }
    }
    if let Some(lock) = PROVIDER_CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            guard.clear();
        }
    }
}

fn refresh_all() -> DetectionResult {
    let mut contexts = BTreeMap::new();
    let mut failures = BTreeMap::new();

    for provider in [
        Provider::Kube,
        Provider::Aws,
        Provider::Gcp,
        Provider::Azure,
    ] {
        match detect_single(provider) {
            Ok(ctx) => {
                contexts.insert(provider, ctx);
            }
            Err(ContextDetectFailure::NotConfigured) => {
                // Absence of signal — don't record as a failure.
            }
            Err(other) => {
                failures.insert(provider, other);
            }
        }
    }

    DetectionResult { contexts, failures }
}

// ────────────────────────────────────────────────────────────────────── kube

fn detect_kube() -> Result<ProviderContext, ContextDetectFailure> {
    let path = match resolve_kubeconfig_path() {
        Some(p) => p,
        None => return Err(ContextDetectFailure::NotConfigured),
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| ContextDetectFailure::Io(format!("read {}: {e}", path.display())))?;

    let value: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| ContextDetectFailure::Io(format!("yaml parse: {e}")))?;

    let current = value
        .get("current-context")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or(ContextDetectFailure::NotConfigured)?;

    Ok(ProviderContext {
        provider: Provider::Kube,
        context: current,
    })
}

/// Resolve the active kubeconfig path: the first `$KUBECONFIG` entry (mirroring
/// kubectl's `current-context` resolution), falling back to `~/.kube/config`.
fn resolve_kubeconfig_path() -> Option<PathBuf> {
    if let Ok(env_val) = std::env::var("KUBECONFIG") {
        let env_val = env_val.trim();
        if !env_val.is_empty() {
            let separator = if cfg!(windows) { ';' } else { ':' };
            let first = env_val.split(separator).next().unwrap_or(env_val).trim();
            if !first.is_empty() {
                let path = PathBuf::from(first);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    let home = home::home_dir()?;
    let path = home.join(".kube").join("config");
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────── aws

fn detect_aws() -> Result<ProviderContext, ContextDetectFailure> {
    // Env precedence per `aws --help`: `AWS_PROFILE` then `AWS_DEFAULT_PROFILE`.
    for name in ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"] {
        if let Ok(val) = std::env::var(name) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Ok(ProviderContext {
                    provider: Provider::Aws,
                    context: trimmed.to_string(),
                });
            }
        }
    }

    // Fall back to a file under `~/.aws/` for *some* signal when `AWS_PROFILE`
    // is unset. We only need the profile NAME, never the credential value.
    let home = home::home_dir().ok_or(ContextDetectFailure::NotConfigured)?;
    let config_path = home.join(".aws").join("config");
    let credentials_path = home.join(".aws").join("credentials");

    if !config_path.is_file() && !credentials_path.is_file() {
        return Err(ContextDetectFailure::NotConfigured);
    }

    // Return `default` (what `aws` itself would use) when either file exists.
    Ok(ProviderContext {
        provider: Provider::Aws,
        context: "default".to_string(),
    })
}

// ──────────────────────────────────────────────────────────────────── gcloud

fn detect_gcloud() -> Result<ProviderContext, ContextDetectFailure> {
    let out = run_with_timeout("gcloud", &["config", "list", "--format=json"])?;
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| ContextDetectFailure::Io(format!("json parse: {e}")))?;

    let core = value
        .get("core")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let account = core
        .get("account")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let project = core
        .get("project")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let context = match (account, project) {
        (Some(a), Some(p)) => format!("{a}@{p}"),
        (None, Some(p)) => p.to_string(),
        (Some(a), None) => a.to_string(),
        (None, None) => return Err(ContextDetectFailure::NotConfigured),
    };

    Ok(ProviderContext {
        provider: Provider::Gcp,
        context,
    })
}

// ───────────────────────────────────────────────────────────────────── azure

fn detect_azure() -> Result<ProviderContext, ContextDetectFailure> {
    let out = run_with_timeout("az", &["account", "show", "-o", "json"])?;
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| ContextDetectFailure::Io(format!("json parse: {e}")))?;

    // Prefer the operator-facing `name` (what `az account list -o table` prints),
    // falling back to the subscription `id` UUID.
    let context = value
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("id").and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(ContextDetectFailure::NotConfigured)?
        .to_string();

    Ok(ProviderContext {
        provider: Provider::Azure,
        context,
    })
}

// ─────────────────────────────────────────────────────────────── shell-out

/// A simple `Output`-shaped result that's `Clone`-able for our caller.
#[derive(Debug, Clone)]
struct ShellOutOutput {
    #[allow(dead_code)] // reserved for future error reporting
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
}

/// Run a binary with a hard wall-clock timeout, mapping the shared helper's
/// outcome onto [`ContextDetectFailure`]. A missing binary at trusted resolution
/// becomes `NotConfigured` ("no signal"); an untrusted first PATH hit is a real
/// provenance I/O error and is never executed.
fn run_with_timeout(program: &str, args: &[&str]) -> Result<ShellOutOutput, ContextDetectFailure> {
    use crate::trusted_child::TrustedExecutableError;
    use crate::util::{run_trusted_with_timeout, ShellTimeoutOutcome};
    let executable = match crate::trusted_child::resolve_system_helper(program) {
        Ok(executable) => executable,
        Err(TrustedExecutableError::NotFound(_)) => {
            return Err(ContextDetectFailure::NotConfigured)
        }
        Err(error) => return Err(ContextDetectFailure::Io(error.to_string())),
    };
    let outcome = run_trusted_with_timeout(
        &executable,
        args,
        SHELL_OUT_TIMEOUT,
        SHELL_OUT_CAP,
        &[
            "HOME",
            "USERPROFILE",
            "XDG_CONFIG_HOME",
            "CLOUDSDK_CONFIG",
            "AZURE_CONFIG_DIR",
            "APPDATA",
            "LOCALAPPDATA",
        ],
    );
    match outcome {
        ShellTimeoutOutcome::Completed { status, stdout } => {
            if status.success() {
                Ok(ShellOutOutput {
                    status: status.code(),
                    stdout,
                })
            } else {
                Err(ContextDetectFailure::Exited(status.code().unwrap_or(-1)))
            }
        }
        ShellTimeoutOutcome::NotFound => Err(ContextDetectFailure::NotConfigured),
        ShellTimeoutOutcome::SpawnError(reason) => Err(ContextDetectFailure::Io(reason)),
        ShellTimeoutOutcome::WaitError(reason) => Err(ContextDetectFailure::Io(reason)),
        ShellTimeoutOutcome::CleanupError(reason) => Err(ContextDetectFailure::Io(reason)),
        ShellTimeoutOutcome::Timeout {
            cleanup_succeeded: true,
        } => Err(ContextDetectFailure::Timeout),
        ShellTimeoutOutcome::Timeout {
            cleanup_succeeded: false,
        } => Err(ContextDetectFailure::Io(
            "context helper timed out and process-tree cleanup failed".to_string(),
        )),
        ShellTimeoutOutcome::OutputLimitExceeded {
            cleanup_succeeded: true,
        } => Err(ContextDetectFailure::Io(
            "context helper output exceeded the capture limit".to_string(),
        )),
        ShellTimeoutOutcome::OutputLimitExceeded {
            cleanup_succeeded: false,
        } => Err(ContextDetectFailure::Io(
            "context helper exceeded the capture limit and process-tree cleanup failed".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn write_marker_executable(path: &std::path::Path, marker: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;

        let marker = marker.display().to_string().replace('\'', "'\"'\"'");
        std::fs::write(path, format!("#!/bin/sh\n: > '{marker}'\nexit 97\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn provider_parse_round_trips() {
        for p in [
            Provider::Kube,
            Provider::Aws,
            Provider::Gcp,
            Provider::Azure,
        ] {
            assert_eq!(Provider::parse(p.as_str()), Some(p));
        }
    }

    #[cfg(unix)]
    #[test]
    fn cloud_context_callers_reject_path_shadowed_helpers() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        let temporary = tempfile::Builder::new()
            .prefix("tirith-context-shadow-")
            .tempdir_in(&global.roots().home)
            .unwrap();
        let shadow_bin = temporary.path().join("shadow-bin");
        std::fs::create_dir(&shadow_bin).unwrap();
        let marker = temporary.path().join("cloud-helper-executed");
        for helper in ["gcloud", "az"] {
            write_marker_executable(&shadow_bin.join(helper), &marker);
        }

        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let mut path_entries = vec![shadow_bin.clone()];
        path_entries.extend(std::env::split_paths(&inherited));
        global.set_env("PATH", std::env::join_paths(path_entries).unwrap());

        for (helper, args) in [
            ("gcloud", &["config", "list", "--format=json"][..]),
            ("az", &["account", "show", "-o", "json"][..]),
        ] {
            let error = run_with_timeout(helper, args)
                .expect_err("a first-hit helper under a same-UID home directory must be refused");
            assert!(
                matches!(error, ContextDetectFailure::Io(_)),
                "untrusted {helper} should surface as a provenance I/O failure: {error:?}"
            );
        }
        assert!(
            !marker.exists(),
            "context detection must not execute PATH-shadowed gcloud or az"
        );
    }

    #[test]
    fn provider_parse_aliases() {
        assert_eq!(Provider::parse("k8s"), Some(Provider::Kube));
        assert_eq!(Provider::parse("kubernetes"), Some(Provider::Kube));
        assert_eq!(Provider::parse("gcloud"), Some(Provider::Gcp));
        assert_eq!(Provider::parse("az"), Some(Provider::Azure));
        assert_eq!(Provider::parse("unknown"), None);
    }

    #[test]
    fn provider_from_leader() {
        assert_eq!(Provider::from_leader("kubectl"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("helm"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("argocd"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("kustomize"), Some(Provider::Kube));
        assert_eq!(Provider::from_leader("aws"), Some(Provider::Aws));
        assert_eq!(Provider::from_leader("aws-vault"), Some(Provider::Aws));
        assert_eq!(Provider::from_leader("gcloud"), Some(Provider::Gcp));
        assert_eq!(Provider::from_leader("az"), Some(Provider::Azure));
        assert_eq!(Provider::from_leader("curl"), None);
    }

    #[test]
    fn label_key_format() {
        let ctx = ProviderContext {
            provider: Provider::Kube,
            context: "prod-us-east".into(),
        };
        assert_eq!(ctx.label_key(), "kube:prod-us-east");
    }

    #[test]
    fn timeout_disables_detection_via_env() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        global.set_env("TIRITH_CONTEXT_DETECT_DISABLE", "1");
        global.after_restore(invalidate_cache);
        invalidate_cache();
        let r = detect_all();
        assert!(r.is_empty(), "disable env must produce empty result");
    }

    #[test]
    fn aws_env_precedence_aws_profile_wins() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        global.set_env("AWS_PROFILE", "prod");
        global.set_env("AWS_DEFAULT_PROFILE", "dev");
        let ctx = detect_aws().expect("aws detection");
        assert_eq!(ctx.context, "prod");
    }

    #[test]
    fn aws_falls_back_to_default_profile_name() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        global.remove_env("AWS_PROFILE");
        global.remove_env("AWS_DEFAULT_PROFILE");
        // Result is non-deterministic (depends on whether ~/.aws exists); just
        // check it doesn't panic.
        let _ = detect_aws();
    }

    #[cfg(unix)]
    #[test]
    fn timeout_triggers_on_slow_binary() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        let path = std::env::join_paths([
            std::path::Path::new("/usr/bin"),
            std::path::Path::new("/bin"),
        ])
        .unwrap();
        global.set_env("PATH", path);
        let result = run_with_timeout("sleep", &["10"]);
        assert!(
            matches!(result, Err(ContextDetectFailure::Timeout)),
            "expected Timeout, got {result:?}",
        );
    }

    #[test]
    fn missing_binary_reports_not_configured() {
        let result = run_with_timeout("this-binary-definitely-does-not-exist-xyzzy", &[]);
        assert!(
            matches!(result, Err(ContextDetectFailure::NotConfigured)),
            "expected NotConfigured, got {result:?}",
        );
    }

    #[test]
    fn kube_parses_current_context_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let kube_path = dir.path().join("config");
        std::fs::write(
            &kube_path,
            "apiVersion: v1\nkind: Config\ncurrent-context: my-cluster\ncontexts:\n  - name: my-cluster\n",
        )
        .unwrap();
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        global.set_env("KUBECONFIG", &kube_path);
        let ctx = detect_kube().expect("kube detection");
        assert_eq!(ctx.context, "my-cluster");
    }

    #[test]
    fn kube_kubeconfig_multi_file_takes_first() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a.yaml");
        let second = dir.path().join("b.yaml");
        std::fs::write(
            &first,
            "apiVersion: v1\nkind: Config\ncurrent-context: first-ctx\n",
        )
        .unwrap();
        std::fs::write(
            &second,
            "apiVersion: v1\nkind: Config\ncurrent-context: second-ctx\n",
        )
        .unwrap();
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global context detection state");
        let sep = if cfg!(windows) { ";" } else { ":" };
        let joined = format!("{}{sep}{}", first.display(), second.display());
        global.set_env("KUBECONFIG", joined);
        let ctx = detect_kube().expect("kube detection");
        assert_eq!(ctx.context, "first-ctx");
    }
}
