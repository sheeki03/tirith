//! `tirith context status|guard|label` (M8 ch1).
//!
//! - `status` — print the active context + label per provider (stable JSON).
//! - `guard on|off` — flip `context_guard_enabled` by appending/rewriting that
//!   one key in `policy.yaml` (never round-tripping the whole file).
//! - `label <provider:context> <criticality> [--scope user|repo]` — write one
//!   entry into the flat-YAML labels file, preserving existing entries.
//!
//! We never round-trip the hand-edited `policy.yaml` through serde (to keep
//! comments / ordering intact).

use std::io::Write;
use std::path::PathBuf;

use tirith_core::context_detect::{self, ContextDetectFailure, Provider, ProviderContext};
use tirith_core::policy::{self as policy_mod, Policy};

/// Allowed criticality values (case-insensitive synonyms of
/// `rules::context::is_critical_label`); we persist exactly what the operator typed.
const ALLOWED_CRITICALITIES: &[&str] = &[
    "critical",
    "production",
    "prod",
    "live",
    "p0",
    "p1",
    "p2",
    "staging",
    "dev",
    "test",
];

/// Scope for `tirith context label` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelScope {
    User,
    Repo,
}

impl LabelScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Repo => "repo",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "user" => Some(Self::User),
            "repo" | "project" | "workspace" => Some(Self::Repo),
            _ => None,
        }
    }
}

/// `tirith context status` — list active contexts and labels.
pub fn status(json: bool) -> i32 {
    let mut policy = Policy::discover_partial(None);
    policy.load_context_labels(None);

    let detection = context_detect::detect_all();

    if json {
        return emit_status_json(&detection, &policy);
    }

    if detection.contexts.is_empty() && detection.failures.is_empty() {
        eprintln!("tirith context status: no cloud / k8s context detected");
        eprintln!("  (configure ~/.kube/config, AWS_PROFILE, gcloud or az to populate)");
        return 0;
    }

    eprintln!("tirith context status:");
    for provider in [
        Provider::Kube,
        Provider::Aws,
        Provider::Gcp,
        Provider::Azure,
    ] {
        match (
            detection.contexts.get(&provider),
            detection.failures.get(&provider),
        ) {
            (Some(ctx), _) => {
                let label = policy
                    .context_labels
                    .get(&ctx.label_key())
                    .map(String::as_str)
                    .unwrap_or("(unlabeled)");
                eprintln!(
                    "  {:<6} {}  [label: {label}]",
                    provider.as_str(),
                    ctx.context,
                );
            }
            (None, Some(failure)) => {
                eprintln!("  {:<6} <error: {failure}>", provider.as_str());
            }
            (None, None) => {
                eprintln!("  {:<6} (not configured)", provider.as_str());
            }
        }
    }
    eprintln!(
        "  guard: {}  label-file (user): {}",
        if policy.context_guard_enabled {
            "ON"
        } else {
            "OFF"
        },
        policy_mod::user_context_labels_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<unknown>".into()),
    );
    0
}

fn emit_status_json(detection: &context_detect::DetectionResult, policy: &Policy) -> i32 {
    #[derive(serde::Serialize)]
    struct ProviderEntry {
        provider: &'static str,
        context: Option<String>,
        label: Option<String>,
        error: Option<String>,
    }
    #[derive(serde::Serialize)]
    struct Out {
        schema_version: u32,
        guard_enabled: bool,
        user_label_file: Option<String>,
        repo_label_file: Option<String>,
        providers: Vec<ProviderEntry>,
    }

    let mut providers = Vec::new();
    for provider in [
        Provider::Kube,
        Provider::Aws,
        Provider::Gcp,
        Provider::Azure,
    ] {
        let (context, label, error) = match (
            detection.contexts.get(&provider),
            detection.failures.get(&provider),
        ) {
            (Some(ctx), _) => (
                Some(ctx.context.clone()),
                policy.context_labels.get(&ctx.label_key()).cloned(),
                None,
            ),
            (None, Some(f)) => (None, None, Some(f.to_string())),
            (None, None) => (None, None, None),
        };
        providers.push(ProviderEntry {
            provider: provider.as_str(),
            context,
            label,
            error,
        });
    }

    let out = Out {
        schema_version: 1,
        guard_enabled: policy.context_guard_enabled,
        user_label_file: policy_mod::user_context_labels_path().map(|p| p.display().to_string()),
        repo_label_file: policy_mod::repo_context_labels_path(None)
            .map(|p| p.display().to_string()),
        providers,
    };

    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        eprintln!("tirith context status: failed to write JSON output");
        return 1;
    }
    0
}

/// `tirith context guard on|off` — flip the operator switch by appending or
/// rewriting the single `context_guard_enabled` line in `policy.yaml` (never
/// round-tripping it through serde). Creates a user-config policy if none exists.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith context guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        eprintln!(
            "tirith context guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith context guard: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn guard_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "guard_enabled": policy.context_guard_enabled,
            "policy_path": policy.path,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith context guard: {}",
            if policy.context_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

fn resolve_policy_path_for_guard() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    // No existing policy — create one in the user config dir.
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith context guard: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotently append-or-rewrite the `context_guard_enabled` line in a policy
/// YAML file, never touching other lines.
fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let new_line = format!("context_guard_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("context_guard_enabled:") {
            out.push_str(&new_line);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&new_line);
        out.push('\n');
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(out.as_bytes())
}

/// `tirith context label <provider:context> <criticality> [--scope user|repo]`.
pub fn label(label_key: &str, criticality: &str, scope: LabelScope, json: bool) -> i32 {
    if !label_key.contains(':') {
        eprintln!(
            "tirith context label: '{label_key}' is not a valid 'provider:context' key (e.g. kube:prod-us-east)"
        );
        return 2;
    }
    let (provider_str, ctx_part) = match label_key.split_once(':') {
        Some(parts) => parts,
        None => unreachable!("contains ':' checked above"),
    };
    if Provider::parse(provider_str).is_none() {
        eprintln!(
            "tirith context label: unknown provider '{provider_str}' (expected one of: kube, aws, gcp, azure)"
        );
        return 2;
    }
    if ctx_part.is_empty() {
        eprintln!("tirith context label: context name is empty after the colon");
        return 2;
    }

    let criticality_norm = criticality.trim().to_lowercase();
    if !ALLOWED_CRITICALITIES.iter().any(|c| *c == criticality_norm) {
        eprintln!(
            "tirith context label: '{criticality}' is not a known criticality (expected one of: {}; case-insensitive)",
            ALLOWED_CRITICALITIES.join(", "),
        );
        return 2;
    }

    let target_path = match scope {
        LabelScope::User => match policy_mod::user_context_labels_path() {
            Some(p) => p,
            None => {
                eprintln!("tirith context label: could not resolve user config dir");
                return 1;
            }
        },
        LabelScope::Repo => match policy_mod::repo_context_labels_path(None) {
            Some(p) => p,
            None => {
                eprintln!("tirith context label: --scope repo requires running inside a git repo");
                return 1;
            }
        },
    };

    if let Err(e) = policy_mod::write_context_label(&target_path, label_key, criticality) {
        eprintln!(
            "tirith context label: failed to write {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "scope": scope.as_str(),
            "path": target_path.display().to_string(),
            "label_key": label_key,
            "criticality": criticality,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith context label: {label_key} -> {criticality} (scope={}, file={})",
            scope.as_str(),
            target_path.display(),
        );
    }
    0
}

// Silence unused-import warnings under cfg combinations.
#[allow(dead_code)]
fn _silence_unused(_pc: &ProviderContext, _f: &ContextDetectFailure) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn label_scope_parse() {
        assert_eq!(LabelScope::parse("user"), Some(LabelScope::User));
        assert_eq!(LabelScope::parse("USER"), Some(LabelScope::User));
        assert_eq!(LabelScope::parse("repo"), Some(LabelScope::Repo));
        assert_eq!(LabelScope::parse("workspace"), Some(LabelScope::Repo));
        assert_eq!(LabelScope::parse("invalid"), None);
    }

    #[test]
    fn update_policy_guard_key_creates_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        update_policy_guard_key(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: true"));
    }

    #[test]
    fn update_policy_guard_key_replaces_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "paranoia: 2\ncontext_guard_enabled: true\nfail_mode: open\n",
        )
        .unwrap();
        update_policy_guard_key(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: false"));
        assert!(content.contains("paranoia: 2"));
        assert!(content.contains("fail_mode: open"));
        assert!(!content.contains("context_guard_enabled: true"));
    }

    #[test]
    fn update_policy_guard_key_appends_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "paranoia: 2\n").unwrap();
        update_policy_guard_key(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("paranoia: 2"));
        assert!(content.contains("context_guard_enabled: true"));
    }
}
