//! `tirith onboard` — M13 ch1 onboarding wizard.
//!
//! Detects the developer's environment (shell, IDE configs, AI-config files,
//! package managers, lockfiles, CI, MCP configs, and tirith's own install
//! state), prints a detection report, and RECOMMENDS one of the shipping policy
//! templates (`individual` / `ci-strict` / `ai-agent-heavy`) plus a short list
//! of next actions.
//!
//! Detection is read-only and reuses the existing helpers — `init::detect_shell`
//! for the shell, `init::find_hook_dir_readonly` + `doctor::check_shell_profile`
//! for tirith's install state, `policy::discover_local_policy_path` for the
//! policy, and `path_audit::which_all` for PATH-based package-manager detection
//! — rather than reinventing any of it.
//!
//! `--apply` (off by default) performs the recommended SAFE actions
//! (`policy init --template <rec>`, `init` hook) with per-step confirmation on
//! stdin. It refuses to act non-interactively (stdin/stderr not a TTY): it
//! prints what it WOULD do and requires an interactive run, so a piped or CI
//! invocation never silently mutates the working tree. No new RuleId, no
//! tier-1 changes.

use std::path::{Path, PathBuf};

use crate::cli::policy::PolicyTemplate;

/// Repo-local MCP config files `onboard` probes for. Mirrors the discovery
/// surface in `tirith-core`'s `mcp_lock::MCP_CONFIG_RELATIVE_PATHS` (which is
/// crate-private to core) plus the home-relative Windsurf path the task calls
/// out. Kept as an explicit list so discovery stays bounded and never strays
/// outside the known MCP config surface.
const MCP_CONFIG_RELATIVE_PATHS: &[&str] = &[
    // Bare repo-root MCP configs.
    "mcp.json",
    ".mcp.json",
    "mcp_settings.json",
    // IDE host-directory variants.
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".windsurf/mcp.json",
    ".cline/mcp_settings.json",
    ".amazonq/mcp.json",
    ".continue/mcp.json",
    ".kiro/settings/mcp.json",
];

/// Package managers `onboard` looks for on `PATH`. `(binary, label)`.
const PACKAGE_MANAGERS: &[(&str, &str)] = &[
    ("npm", "npm"),
    ("pnpm", "pnpm"),
    ("yarn", "yarn"),
    ("cargo", "cargo"),
    ("pip", "pip"),
    ("uv", "uv"),
    ("go", "go"),
];

/// Lockfiles `onboard` looks for in the repo root. `(relative_path, label)`.
const LOCKFILES: &[(&str, &str)] = &[
    ("package-lock.json", "package-lock.json"),
    ("pnpm-lock.yaml", "pnpm-lock.yaml"),
    ("yarn.lock", "yarn.lock"),
    ("Cargo.lock", "Cargo.lock"),
    ("requirements.txt", "requirements.txt"),
    ("uv.lock", "uv.lock"),
    ("go.sum", "go.sum"),
];

/// Schema version of the `onboard --json` envelope (both the success report and
/// the error envelope carry it). Stable; bump on breaking changes.
const ONBOARD_SCHEMA_VERSION: u32 = 1;

/// The detection report `onboard` builds and (optionally) serializes to JSON.
///
/// Field naming and casing mirror the other `--json` surfaces (snake_case,
/// `serde::Serialize` derive): see `doctor.rs`'s `DoctorInfo` / `incident.rs`'s
/// `StatusOut`. `recommended_template` carries the canonical template NAME
/// (`"individual"` / `"ci-strict"` / `"ai-agent-heavy"`) so a machine consumer
/// can feed it straight back into `tirith policy init --template <name>`.
#[derive(Debug, Clone, serde::Serialize)]
struct OnboardReport {
    /// Schema version of this envelope (stable; bump on breaking changes).
    schema_version: u32,
    /// The directory detection ran in.
    cwd: String,
    /// The repo root walked up to (the `.git` boundary), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_root: Option<String>,
    /// The requested mode bias (`repo` / `team` / `ai-agent-heavy`), or `auto`.
    requested_mode: String,
    /// Detected interactive shell (`zsh` / `bash` / `fish` / `pwsh` / ...).
    detected_shell: String,
    /// IDE config directories present at the repo root.
    ide_configs: Vec<String>,
    /// AI-config files / directories present at the repo root.
    ai_config_files: Vec<String>,
    /// Package managers found on `PATH` (PATH-dependent — not asserted in tests).
    package_managers: Vec<String>,
    /// Lockfiles present at the repo root.
    lockfiles: Vec<String>,
    /// `true` when `.github/workflows/` holds at least one `*.yml` / `*.yaml`.
    ci_detected: bool,
    /// MCP config files present (repo-local plus the home Windsurf config).
    mcp_configs: Vec<String>,
    /// tirith install state.
    tirith: TirithState,
    /// The recommended policy template NAME.
    recommended_template: String,
    /// Why that template was recommended (human-readable).
    recommendation_reason: String,
    /// Short, ordered list of recommended next actions.
    next_actions: Vec<String>,
}

/// tirith's own install state, surfaced read-only (never materializes hooks).
#[derive(Debug, Clone, serde::Serialize)]
struct TirithState {
    /// The shell hook is wired into the detected shell's profile.
    hook_installed: bool,
    /// A `.tirith/policy.yaml` (or `.yml`) is discoverable from `cwd`.
    policy_present: bool,
    /// The discovered policy path, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

/// `tirith onboard` entry point.
///
/// * `mode` — `Some("repo"|"team"|"ai-agent-heavy")` biases the recommendation;
///   `None` = auto-detect. (Modeled as mutually-exclusive `--repo|--team|
///   --ai-agent-heavy` flags in `main.rs`, collapsed to this string.)
/// * `apply` — `false` (default) reports only; `true` performs the recommended
///   SAFE actions with per-step stdin confirmation (refuses non-interactively).
/// * `json` — emit the detection + recommendation as a JSON object.
pub fn run(mode: Option<&str>, apply: bool, json: bool) -> i32 {
    // `--json` and `--apply` are mutually exclusive: `apply_actions` prints
    // interactive prompts and may invoke `tirith init`, whose output would
    // corrupt the JSON document. Reject the combination up front (M13 PR #132
    // finding L) rather than emitting valid JSON followed by non-JSON noise.
    //
    // The caller asked for `--json`, so the rejection itself must be
    // machine-readable: emit the same `{schema_version, error}` envelope the
    // other `--json` surfaces use (CodeRabbit M13 round-5 D5-4) rather than raw
    // stderr text automation can't parse. A failed write exits non-zero (2),
    // matching the success path's broken-pipe contract.
    if json && apply {
        let err = serde_json::json!({
            "schema_version": ONBOARD_SCHEMA_VERSION,
            "error": "--json and --apply cannot be combined \
                      (--apply prints interactive prompts that would corrupt the JSON output)",
        });
        if !crate::cli::write_json_stdout(&err, "tirith onboard: failed to write JSON output") {
            return 2;
        }
        return 1;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_str = cwd.display().to_string();

    // Repo root: walk up to the `.git` boundary. Fall back to cwd so detection
    // still works outside a git repo (mirrors `policy::init`'s fallback).
    let repo_root = tirith_core::policy::find_repo_root(Some(&cwd_str));
    let detect_root = repo_root.clone().unwrap_or_else(|| cwd.clone());

    let report = gather_report(&cwd, &detect_root, repo_root.as_deref(), mode);

    if json {
        // Match the broken-pipe-safe JSON contract the other `--json` surfaces
        // use: a failed write exits non-zero rather than pairing truncated JSON
        // with a success code.
        if !crate::cli::write_json_stdout(&report, "tirith onboard: failed to write JSON output") {
            return 2;
        }
        // `--json` is never combined with `--apply` (rejected up front), so the
        // JSON document is the entire output — no interactive apply follows.
        return 0;
    }

    print_human(&report);

    if apply {
        return apply_actions(&report);
    }
    0
}

/// Build the full detection report for `detect_root` (the repo root, or cwd as a
/// fallback), biased by the requested `mode`.
fn gather_report(
    cwd: &Path,
    detect_root: &Path,
    repo_root: Option<&Path>,
    mode: Option<&str>,
) -> OnboardReport {
    let detected_shell = crate::cli::init::detect_shell().to_string();

    let ide_configs = detect_dirs(detect_root, &[".cursor", ".vscode"]);
    let ai_config_files = detect_ai_config(detect_root);
    let package_managers = detect_package_managers();
    let lockfiles = detect_lockfiles(detect_root);
    let ci_detected = detect_ci(detect_root);
    let mcp_configs = detect_mcp_configs(detect_root);
    let tirith = detect_tirith_state(cwd, &detected_shell);

    let requested_mode = mode.unwrap_or("auto").to_string();

    let signals = RecommendationSignals {
        mode,
        ai_config_count: ai_config_files.len(),
        mcp_config_count: mcp_configs.len(),
        ci_detected,
    };
    let (recommended_template, recommendation_reason) = recommend_template(&signals);
    let next_actions = build_next_actions(&tirith, recommended_template);

    OnboardReport {
        schema_version: ONBOARD_SCHEMA_VERSION,
        cwd: cwd.display().to_string(),
        repo_root: repo_root.map(|p| p.display().to_string()),
        requested_mode,
        detected_shell,
        ide_configs,
        ai_config_files,
        package_managers,
        lockfiles,
        ci_detected,
        mcp_configs,
        tirith,
        recommended_template: recommended_template.canonical_name().to_string(),
        recommendation_reason,
        next_actions,
    }
}

/// Return the subset of `names` that exist as directories directly under `root`.
fn detect_dirs(root: &Path, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|name| root.join(name).is_dir())
        .map(|name| (*name).to_string())
        .collect()
}

/// Root-level AI agent-instruction basenames `onboard` probes for. This mirrors
/// the AI-config surface the product actually acts on — `tirith ai` and the
/// `aifile` rules treat exactly this set (the agent-instruction files) as AI
/// config — so the recommendation isn't undercounted relative to the rest of the
/// tool. Each entry is verified against the canonical classifier
/// ([`tirith_core::rules::aifile::is_ai_config_file`]) at construction time by
/// `detect_ai_config`, and `ai_config_basenames_are_canonical` pins that
/// agreement so this list can't drift from the product's notion.
///
/// MCP server configs (`.mcp.json` / `mcp.json` / `mcp_settings.json`) are
/// DELIBERATELY excluded here — they are counted separately as MCP configs
/// (`detect_mcp_configs`) and feed the recommendation through `mcp_config_count`,
/// so listing them here too would double-count.
const AI_CONFIG_BASENAMES: &[&str] = &[
    // Anthropic / Claude.
    "CLAUDE.md",
    // OpenAI / generic agents.
    "AGENTS.md",
    "AGENTS.override.md",
    // Cursor.
    ".cursorrules",
    ".cursorignore",
    // Cline / Roo.
    ".clinerules",
    ".roorules",
    // Windsurf / Goose.
    ".windsurfrules",
    ".goosehints",
    // GitHub Copilot.
    "copilot-instructions.md",
    // Gemini / Qwen.
    "GEMINI.md",
    "QWEN.md",
    // llms.txt convention.
    "llms.txt",
    "llms-full.txt",
];

/// Detect AI-config files / directories. Covers the same agent-instruction
/// surface `tirith ai` / the `aifile` rules treat as AI config — not just the
/// original `CLAUDE.md` / `.cursorrules` / `AGENTS.md` trio — so a repo using
/// `copilot-instructions.md`, `.clinerules` (incl. themed `.clinerules-*` /
/// `.roorules-*`), `llms.txt`, `.cursorignore`, etc. is not undercounted and the
/// auto recommendation doesn't wrongly drop below `ai-agent-heavy`:
///
///  - the [`AI_CONFIG_BASENAMES`] root-level files (each gated through the
///    canonical [`tirith_core::rules::aifile::is_ai_config_file`] so the set
///    stays anchored to what the product acts on);
///  - `.github/copilot-instructions.md` (Copilot's repo-scoped location);
///  - themed `.clinerules-<theme>` / `.roorules-<mode>` variants at the root
///    (discovered via `read_dir`, same as the product's themed-rules match);
///  - the `.claude/` dir, and any entry under `.cursor/rules/`.
fn detect_ai_config(root: &Path) -> Vec<String> {
    use tirith_core::rules::aifile;

    let mut found = Vec::new();

    // Root-level agent-instruction files, anchored to the canonical classifier.
    for name in AI_CONFIG_BASENAMES {
        let path = root.join(name);
        // `is_ai_config_file` is the product's canonical AI-config predicate;
        // gating on it keeps this detector from drifting from what the rest of
        // the tool treats as AI config.
        if path.is_file() && aifile::is_ai_config_file(&path) {
            found.push((*name).to_string());
        }
    }

    // Copilot's repo-scoped instructions live under `.github/`.
    let gh_copilot = root.join(".github").join("copilot-instructions.md");
    if gh_copilot.is_file() {
        found.push(".github/copilot-instructions.md".to_string());
    }

    // Themed Cline / Roo rules: `.clinerules-<theme>` / `.roorules-<mode>` at the
    // repo root. The product recognises these as agent-instruction files too, so
    // glob them via `read_dir` rather than enumerating themes.
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let lower = name.to_ascii_lowercase();
            if (lower.starts_with(".clinerules-") || lower.starts_with(".roorules-"))
                && entry.path().is_file()
                && aifile::is_ai_config_file(&entry.path())
            {
                found.push(name.into_owned());
            }
        }
    }

    if root.join(".claude").is_dir() {
        found.push(".claude/".to_string());
    }
    // `.cursor/rules/*` — any entry (file or nested rule) counts as a signal.
    let cursor_rules = root.join(".cursor").join("rules");
    if cursor_rules.is_dir() {
        let has_entry = std::fs::read_dir(&cursor_rules)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        if has_entry {
            found.push(".cursor/rules/".to_string());
        }
    }
    found
}

/// Detect which package managers are on `PATH`, using the same PATH resolution
/// (`path_audit::which_all`) the rest of the codebase uses — no shelling out to
/// `which`. PATH-dependent, so tests do NOT assert on this list.
fn detect_package_managers() -> Vec<String> {
    let path_value = std::env::var("PATH").unwrap_or_default();
    PACKAGE_MANAGERS
        .iter()
        .filter(|(binary, _)| !tirith_core::path_audit::which_all(binary, &path_value).is_empty())
        .map(|(_, label)| (*label).to_string())
        .collect()
}

/// Detect lockfiles present at the repo root.
fn detect_lockfiles(root: &Path) -> Vec<String> {
    LOCKFILES
        .iter()
        .filter(|(rel, _)| root.join(rel).is_file())
        .map(|(_, label)| (*label).to_string())
        .collect()
}

/// `true` when `.github/workflows/` holds at least one `*.yml` / `*.yaml` file.
fn detect_ci(root: &Path) -> bool {
    let workflows = root.join(".github").join("workflows");
    let entries = match std::fs::read_dir(&workflows) {
        Ok(e) => e,
        Err(_) => return false,
    };
    entries.flatten().any(|entry| {
        entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false)
    })
}

/// Detect MCP config files: the repo-local surface joined onto `root`, plus the
/// home-relative Windsurf config (`~/.codeium/windsurf/mcp_config.json`).
fn detect_mcp_configs(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = MCP_CONFIG_RELATIVE_PATHS
        .iter()
        .filter(|rel| root.join(rel).is_file())
        .map(|rel| (*rel).to_string())
        .collect();

    if let Some(home) = home::home_dir() {
        let windsurf = home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json");
        if windsurf.is_file() {
            found.push(windsurf.display().to_string());
        }
    }
    found
}

/// Surface tirith's install state read-only: whether the shell hook is wired
/// into the detected shell's profile (reusing `doctor::check_shell_profile`),
/// and whether a policy is discoverable from `cwd` (reusing the engine's local
/// discovery). Never materializes hooks.
fn detect_tirith_state(cwd: &Path, detected_shell: &str) -> TirithState {
    let (_profile, hook_installed) = crate::cli::doctor::check_shell_profile(detected_shell);
    let cwd_str = cwd.display().to_string();
    let policy_path = tirith_core::policy::discover_local_policy_path(Some(&cwd_str));
    TirithState {
        hook_installed,
        policy_present: policy_path.is_some(),
        policy_path: policy_path.map(|p| p.display().to_string()),
    }
}

/// Inputs to the template recommendation. Kept as a struct so the mapping is
/// unit-testable without a filesystem.
struct RecommendationSignals<'a> {
    mode: Option<&'a str>,
    ai_config_count: usize,
    mcp_config_count: usize,
    ci_detected: bool,
}

/// Map detections → a shipping template, biased by `mode`.
///
/// Priority:
///   1. An explicit `--repo|--team|--ai-agent-heavy` mode wins outright.
///   2. Heavy AI-config / MCP presence → `ai-agent-heavy`.
///   3. A CI repo (`.github/workflows`) → `ci-strict`.
///   4. Otherwise → `individual`.
fn recommend_template(signals: &RecommendationSignals) -> (PolicyTemplate, String) {
    // 1. Explicit mode bias.
    match signals.mode {
        Some("ai-agent-heavy") => {
            return (
                PolicyTemplate::AiAgentHeavy,
                "requested --ai-agent-heavy".to_string(),
            );
        }
        Some("team") => {
            return (
                PolicyTemplate::Startup,
                "requested --team (balanced shared defaults for a human team)".to_string(),
            );
        }
        Some("repo") => {
            // A "repo" bias still respects a CI signal — a repo with CI wants the
            // stricter ci-strict baseline; otherwise the individual defaults.
            if signals.ci_detected {
                return (
                    PolicyTemplate::CiStrict,
                    "requested --repo and a .github/workflows CI pipeline is present".to_string(),
                );
            }
            return (
                PolicyTemplate::Individual,
                "requested --repo with no CI pipeline detected".to_string(),
            );
        }
        _ => {}
    }

    // 2. Auto: heavy AI-agent surface.
    if signals.ai_config_count >= 2 || signals.mcp_config_count >= 1 {
        return (
            PolicyTemplate::AiAgentHeavy,
            format!(
                "{} AI-config file(s) and {} MCP config(s) detected — an AI-agent-heavy environment",
                signals.ai_config_count, signals.mcp_config_count
            ),
        );
    }

    // 3. Auto: CI repo.
    if signals.ci_detected {
        return (
            PolicyTemplate::CiStrict,
            "a .github/workflows CI pipeline is present".to_string(),
        );
    }

    // 4. Auto: default.
    (
        PolicyTemplate::Individual,
        "no CI or heavy AI-agent signals — sensible single-developer defaults".to_string(),
    )
}

/// Build the ordered list of recommended next actions from tirith's state and
/// the recommended template.
fn build_next_actions(tirith: &TirithState, template: PolicyTemplate) -> Vec<String> {
    let mut actions = Vec::new();
    if !tirith.hook_installed {
        actions.push(
            "run `tirith init` and add the printed line to your shell profile to install the hook"
                .to_string(),
        );
    }
    if !tirith.policy_present {
        actions.push(format!(
            "run `tirith policy init --template {}`",
            template.canonical_name()
        ));
    }
    if actions.is_empty() {
        actions.push(
            "tirith is already set up here — run `tirith doctor` to confirm protection status"
                .to_string(),
        );
    }
    actions
}

/// Print the human-readable detection report.
fn print_human(report: &OnboardReport) {
    println!("tirith onboard — environment detection");
    println!("  directory:   {}", report.cwd);
    if let Some(root) = &report.repo_root {
        println!("  repo root:   {root}");
    }
    if report.requested_mode != "auto" {
        println!("  mode bias:   --{}", report.requested_mode);
    }
    println!("  shell:       {}", report.detected_shell);
    println!("  IDE configs: {}", fmt_list(&report.ide_configs));
    println!("  AI configs:  {}", fmt_list(&report.ai_config_files));
    println!("  pkg mgrs:    {}", fmt_list(&report.package_managers));
    println!("  lockfiles:   {}", fmt_list(&report.lockfiles));
    println!(
        "  CI:          {}",
        if report.ci_detected {
            ".github/workflows present"
        } else {
            "none"
        }
    );
    println!("  MCP configs: {}", fmt_list(&report.mcp_configs));
    println!();

    println!("tirith status");
    println!(
        "  shell hook:  {}",
        if report.tirith.hook_installed {
            "installed"
        } else {
            "not installed"
        }
    );
    match &report.tirith.policy_path {
        Some(p) => println!("  policy:      {p}"),
        None => println!("  policy:      none"),
    }
    println!();

    println!(
        "Recommended policy template: {}",
        report.recommended_template
    );
    println!("  why: {}", report.recommendation_reason);
    println!();
    println!("Next steps:");
    for (i, action) in report.next_actions.iter().enumerate() {
        println!("  {}. {action}", i + 1);
    }
}

/// Render a string list for the human report, or `(none)` when empty.
fn fmt_list(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

/// `--apply`: perform the recommended SAFE actions with per-step stdin
/// confirmation. Refuses to act when stdin/stderr are not a TTY (a piped or CI
/// invocation): it prints what it WOULD do and returns exit code 1 without
/// mutating anything (a non-interactive `--apply` must not look like a success).
/// Only invokes existing safe operations (`policy init`, `init`); it never
/// overwrites an existing `.tirith/policy.yaml` without confirmation.
fn apply_actions(report: &OnboardReport) -> i32 {
    println!();
    if !is_tty_pair() {
        // Non-interactive: do NOT silently perform destructive actions. This is a
        // refusal to do the requested work, so it exits NON-ZERO (M13 PR #132
        // finding N) — a CI / piped `--apply` should not look like a success.
        eprintln!("tirith onboard --apply: not an interactive terminal — refusing to act.");
        eprintln!("  Re-run interactively to apply, or perform these steps yourself:");
        for action in &report.next_actions {
            eprintln!("    - {action}");
        }
        return 1;
    }

    let mut performed = 0;
    // Set when any attempted step failed, so the overall exit code propagates the
    // failure instead of masking it as a success (finding N).
    let mut failed = false;

    // 1. Install the shell hook (idempotent; `init` only prints the eval line
    //    and materializes hook assets — it does not edit the profile).
    if !report.tirith.hook_installed
        && confirm_stdin("Show the `tirith init` shell-hook line to install?")
    {
        let rc = crate::cli::init::run(None, false);
        if rc == 0 {
            println!(
                "  Add the line above to your shell profile, then restart your shell or `source` it."
            );
            performed += 1;
        } else {
            eprintln!("  `tirith init` failed (exit code {rc}).");
            failed = true;
        }
    }

    // 2. Create the recommended policy — only when none exists (never clobber).
    if report.tirith.policy_present {
        println!(
            "  A policy already exists at {} — leaving it untouched.",
            report.tirith.policy_path.as_deref().unwrap_or("<unknown>")
        );
    } else if confirm_stdin(&format!(
        "Run `tirith policy init --template {}`?",
        report.recommended_template
    )) {
        // `policy::init` is no-clobber without --force, so this is safe even if a
        // policy raced into existence after detection.
        let rc = crate::cli::policy::init(false, false, Some(&report.recommended_template));
        if rc == 0 {
            performed += 1;
        } else {
            eprintln!("  `tirith policy init` failed (exit code {rc}).");
            failed = true;
        }
    }

    if performed == 0 {
        println!("tirith onboard: no actions applied.");
    } else {
        println!("tirith onboard: applied {performed} action(s).");
    }
    // Propagate any step failure as a non-zero exit.
    if failed {
        1
    } else {
        0
    }
}

/// Interactive `[y/N]` prompt that reads a line from stdin. The prompt goes to
/// STDERR — the same stream [`is_tty_pair`] gates on — so it stays visible even
/// when stdout is redirected (e.g. `tirith onboard plan --apply > out`); a
/// non-`y`/`yes` answer (or a read error) declines. Callers gate on
/// [`is_tty_pair`] before invoking this. (CodeRabbit M13 round-2 R8: previously
/// printed to stdout, so a redirected stdout left `--apply` blocking on input
/// behind an invisible prompt.)
fn confirm_stdin(prompt: &str) -> bool {
    use std::io::Write;
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => matches!(input.trim(), "y" | "Y" | "yes" | "Yes"),
        Err(e) => {
            eprintln!("tirith onboard: could not read confirmation input: {e}");
            false
        }
    }
}

/// `--apply` needs BOTH stdin (to read the answer) and stderr (so the prompt is
/// visible) to be a TTY — the same pair `tirith fix` gates its interactive
/// rewrite on.
fn is_tty_pair() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommend_explicit_modes_win() {
        let ai = recommend_template(&RecommendationSignals {
            mode: Some("ai-agent-heavy"),
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(ai.0, PolicyTemplate::AiAgentHeavy);

        // `--team` maps to the balanced human-team preset (`startup`), not the CI
        // profile. (M13 PR #132 finding M.)
        let team = recommend_template(&RecommendationSignals {
            mode: Some("team"),
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(team.0, PolicyTemplate::Startup);

        // `--repo` respects a CI signal but otherwise picks individual.
        let repo_ci = recommend_template(&RecommendationSignals {
            mode: Some("repo"),
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: true,
        });
        assert_eq!(repo_ci.0, PolicyTemplate::CiStrict);
        let repo_plain = recommend_template(&RecommendationSignals {
            mode: Some("repo"),
            ai_config_count: 5,
            mcp_config_count: 5,
            ci_detected: false,
        });
        assert_eq!(
            repo_plain.0,
            PolicyTemplate::Individual,
            "an explicit --repo bias must not be overridden by auto AI-agent signals"
        );
    }

    #[test]
    fn recommend_auto_prioritizes_ai_then_ci_then_individual() {
        // Heavy AI surface (2+ AI configs) → ai-agent-heavy, even with CI.
        let ai = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 2,
            mcp_config_count: 0,
            ci_detected: true,
        });
        assert_eq!(ai.0, PolicyTemplate::AiAgentHeavy);

        // A single MCP config alone is enough for ai-agent-heavy.
        let mcp = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 0,
            mcp_config_count: 1,
            ci_detected: false,
        });
        assert_eq!(mcp.0, PolicyTemplate::AiAgentHeavy);

        // CI without a heavy AI surface → ci-strict.
        let ci = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 1,
            mcp_config_count: 0,
            ci_detected: true,
        });
        assert_eq!(ci.0, PolicyTemplate::CiStrict);

        // Nothing notable → individual.
        let individual = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(individual.0, PolicyTemplate::Individual);
    }

    #[test]
    fn next_actions_reflect_install_state() {
        // Fresh machine: both hook and policy actions appear.
        let fresh = build_next_actions(
            &TirithState {
                hook_installed: false,
                policy_present: false,
                policy_path: None,
            },
            PolicyTemplate::Individual,
        );
        assert!(fresh.iter().any(|a| a.contains("tirith init")));
        assert!(fresh
            .iter()
            .any(|a| a.contains("tirith policy init --template individual")));

        // Fully set up: a single "already set up" line, no destructive actions.
        let done = build_next_actions(
            &TirithState {
                hook_installed: true,
                policy_present: true,
                policy_path: Some("/repo/.tirith/policy.yaml".to_string()),
            },
            PolicyTemplate::CiStrict,
        );
        assert_eq!(done.len(), 1);
        assert!(done[0].contains("already set up"));
    }

    /// R7-5: every basename in [`AI_CONFIG_BASENAMES`] must be recognised by the
    /// product's canonical AI-config classifier. This pins the onboard detector's
    /// list to what the rest of the tool (`tirith ai` / the `aifile` rules)
    /// actually treats as AI config, so the two can't silently diverge.
    #[test]
    fn ai_config_basenames_are_canonical() {
        use tirith_core::rules::aifile;
        for name in AI_CONFIG_BASENAMES {
            assert!(
                aifile::is_ai_config_file(Path::new(name)),
                "{name:?} is in AI_CONFIG_BASENAMES but is NOT recognised by the canonical \
                 is_ai_config_file — the onboard detector has drifted from the product's set"
            );
        }
    }

    /// R7-5: the AI-config detector must cover the broader supported surface, not
    /// just `CLAUDE.md` / `.cursorrules` / `AGENTS.md`. A repo using
    /// `copilot-instructions.md` + `.clinerules` (incl. a themed `.clinerules-*`)
    /// must be detected as AI config and, with 2+ such files, push the AUTO
    /// recommendation to `ai-agent-heavy` (previously these were undercounted and
    /// the recommendation wrongly dropped below `ai-agent-heavy`).
    #[test]
    fn detect_ai_config_recognizes_broader_signals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // None of these three is in the original CLAUDE.md/.cursorrules/AGENTS.md
        // trio, so the pre-R7-5 detector would have counted ZERO of them.
        std::fs::write(root.join("copilot-instructions.md"), "# copilot\n").unwrap();
        std::fs::write(root.join(".clinerules"), "rules\n").unwrap();
        std::fs::write(root.join(".clinerules-security"), "themed\n").unwrap();

        let found = detect_ai_config(root);
        assert!(
            found.iter().any(|f| f == "copilot-instructions.md"),
            "copilot-instructions.md must be detected as AI config, got: {found:?}"
        );
        assert!(
            found.iter().any(|f| f == ".clinerules"),
            ".clinerules must be detected as AI config, got: {found:?}"
        );
        assert!(
            found.iter().any(|f| f == ".clinerules-security"),
            "themed .clinerules-* must be detected as AI config, got: {found:?}"
        );

        // The broadened count (>= 2) drives the AUTO recommendation to
        // ai-agent-heavy — the behavioural payoff of the fix.
        let (template, _why) = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: found.len(),
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(
            template,
            PolicyTemplate::AiAgentHeavy,
            "a repo with multiple broader AI-config signals must recommend ai-agent-heavy"
        );
    }

    /// R7-5: `.github/copilot-instructions.md` (Copilot's repo-scoped location) is
    /// also a recognised AI-config signal.
    #[test]
    fn detect_ai_config_finds_github_copilot_instructions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join(".github")).unwrap();
        std::fs::write(
            root.join(".github").join("copilot-instructions.md"),
            "# copilot\n",
        )
        .unwrap();

        let found = detect_ai_config(root);
        assert!(
            found.iter().any(|f| f == ".github/copilot-instructions.md"),
            ".github/copilot-instructions.md must be detected, got: {found:?}"
        );
    }
}
