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
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hard per-call wall-clock cap for any shell-out; the child is killed past it.
const SHELL_OUT_TIMEOUT: Duration = Duration::from_millis(1500);

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

#[derive(Default)]
struct CacheEntry {
    captured_at: Option<Instant>,
    result: DetectionResult,
}

fn cache() -> &'static Mutex<CacheEntry> {
    CACHE.get_or_init(|| Mutex::new(CacheEntry::default()))
}

/// Detect the active context for every configured provider, with a per-process
/// cache. Hot-path-safe: never blocks longer than [`SHELL_OUT_TIMEOUT`] per
/// provider when cold, instant on a cache hit.
///
/// Test-only: `TIRITH_CONTEXT_DETECT_DISABLE=1` returns an empty result with no
/// filesystem / shell-out access, so integration tests don't pick up the
/// developer's real cloud config.
pub fn detect_all() -> DetectionResult {
    if std::env::var("TIRITH_CONTEXT_DETECT_DISABLE")
        .ok()
        .as_deref()
        == Some("1")
    {
        return DetectionResult::default();
    }

    let now = Instant::now();
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(captured_at) = guard.captured_at {
        if now.duration_since(captured_at) < Duration::from_secs(CACHE_TTL_SECS) {
            return guard.result.clone();
        }
    }

    let fresh = refresh_all();
    guard.captured_at = Some(now);
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

/// Clear the per-process cache. Tests call this between scenarios.
pub fn clear_cache_for_tests() {
    if let Some(lock) = CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = CacheEntry::default();
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
/// outcome onto [`ContextDetectFailure`]. A missing binary (`spawn` `NotFound`)
/// becomes `NotConfigured` ("no signal"), distinct from a real I/O error.
fn run_with_timeout(program: &str, args: &[&str]) -> Result<ShellOutOutput, ContextDetectFailure> {
    use crate::util::{run_shell_with_timeout, ShellTimeoutOutcome};
    let outcome = run_shell_with_timeout(
        program,
        args,
        SHELL_OUT_TIMEOUT,
        Duration::from_millis(25),
        Stdio::null(),
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
        ShellTimeoutOutcome::Timeout => Err(ContextDetectFailure::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // SAFETY: tests in this crate serialize env mutation via TEST_ENV_LOCK.
        unsafe {
            std::env::set_var("TIRITH_CONTEXT_DETECT_DISABLE", "1");
        }
        clear_cache_for_tests();
        let r = detect_all();
        assert!(r.is_empty(), "disable env must produce empty result");
        unsafe {
            std::env::remove_var("TIRITH_CONTEXT_DETECT_DISABLE");
        }
        clear_cache_for_tests();
    }

    #[test]
    fn aws_env_precedence_aws_profile_wins() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::set_var("AWS_PROFILE", "prod");
            std::env::set_var("AWS_DEFAULT_PROFILE", "dev");
        }
        let ctx = detect_aws().expect("aws detection");
        assert_eq!(ctx.context, "prod");
        unsafe {
            std::env::remove_var("AWS_PROFILE");
            std::env::remove_var("AWS_DEFAULT_PROFILE");
        }
    }

    #[test]
    fn aws_falls_back_to_default_profile_name() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::remove_var("AWS_PROFILE");
            std::env::remove_var("AWS_DEFAULT_PROFILE");
        }
        // Result is non-deterministic (depends on whether ~/.aws exists); just
        // check it doesn't panic.
        let _ = detect_aws();
    }

    #[test]
    fn timeout_triggers_on_slow_binary() {
        // `sleep` is POSIX-only; skip on Windows (same watchdog path anyway).
        if cfg!(windows) {
            return;
        }
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
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        unsafe {
            std::env::set_var("KUBECONFIG", kube_path.display().to_string());
        }
        let ctx = detect_kube().expect("kube detection");
        assert_eq!(ctx.context, "my-cluster");
        unsafe {
            std::env::remove_var("KUBECONFIG");
        }
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
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let sep = if cfg!(windows) { ";" } else { ":" };
        let joined = format!("{}{sep}{}", first.display(), second.display());
        unsafe {
            std::env::set_var("KUBECONFIG", joined);
        }
        let ctx = detect_kube().expect("kube detection");
        assert_eq!(ctx.context, "first-ctx");
        unsafe {
            std::env::remove_var("KUBECONFIG");
        }
    }
}
