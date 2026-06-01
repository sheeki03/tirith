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
    // `--json` and `--apply` are mutually exclusive — they're declared
    // `conflicts_with` each other on the `Onboard` clap variant, so the
    // combination is rejected at parse time with a usage error (exit 2) and never
    // reaches this function. (The earlier runtime `if json && apply` rejection was
    // removed as unreachable — CodeRabbit M13 PR #132 R12-7.)

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
    // Sort for a STABLE order (R19-N1): the themed `.clinerules-*` / `.roorules-*`
    // glob above is driven by `std::fs::read_dir`, whose iteration order is
    // OS-/filesystem-dependent and non-deterministic. Without this sort the
    // `onboard --json` report's `ai_config_files` array could reorder run-to-run
    // on the same tree. Sorting makes the serialized output deterministic.
    found.sort();
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
        // Only a REGULAR FILE counts as a workflow — a DIRECTORY whose name ends
        // in `.yml`/`.yaml` (e.g. a dir literally named `pipeline.yaml`) is not a
        // CI pipeline and must not flip detection (CodeRabbit M13 PR #132
        // round-22). `file_type()` avoids an extra `stat` and, like the rest of
        // this function, treats any IO error conservatively as non-CI.
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            return false;
        }
        entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false)
    })
}

/// Resolve the user's home directory in an ENV-RESOLVABLE way, preferring the
/// `$HOME` / `%USERPROFILE%` env over `home::home_dir()`.
///
/// `home::home_dir()` on Unix (notably macOS) can fall back to `getpwuid_r`,
/// which ignores an unset/empty `$HOME` and returns the REAL passwd home. That
/// makes the home-relative MCP scan ([`detect_mcp_configs`]) impossible to
/// isolate in tests on macOS — a runner with a real
/// `~/.codeium/windsurf/mcp_config.json` would leak in and flip an
/// `mcp_config_count`-driven recommendation. Reading the env first (the same
/// way `tirith_core::policy::state_dir` / `cli::checkpoint::home_dir` resolve
/// user paths) keeps production behaviour identical for real users — `$HOME`
/// (`%USERPROFILE%` on Windows) is set in every normal session — while letting
/// tests point the scan at an isolated temp home on every OS. We still fall back
/// to `home::home_dir()` when the env var is absent so a stripped environment
/// behaves exactly as before.
fn home_base() -> Option<PathBuf> {
    #[cfg(unix)]
    let env_home = std::env::var_os("HOME");
    #[cfg(not(unix))]
    let env_home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));

    env_home
        // A RELATIVE `$HOME` / `%USERPROFILE%` (e.g. `HOME=.`) would make the
        // home-relative MCP scan probe a cwd-relative `.codeium/...`, fabricating
        // an MCP signal that biases the recommendation. Only honor an ABSOLUTE
        // override; anything relative falls back to `home::home_dir()` (CodeRabbit
        // M13 PR #132 R12-5).
        .filter(|h| !h.is_empty() && Path::new(h).is_absolute())
        .map(PathBuf::from)
        .or_else(home::home_dir)
        // The env branch already requires non-empty + absolute, but
        // `home::home_dir()` can ALSO yield a non-absolute path: on some
        // runners an empty `$HOME` makes it return `Some("")` (MSRV CI: Rust 1.83
        // / Linux), and on Unix it reads `$HOME` directly, so a RELATIVE override
        // like `HOME=.` comes back verbatim instead of being skipped. Either case
        // would make `detect_mcp_configs` probe a cwd-relative `.codeium/...` and
        // fabricate an MCP signal. A single final guard — the home base must be
        // ABSOLUTE (which also rules out the empty path) — closes BOTH the R12-5
        // relative-home hole and the MSRV empty-path failure, regardless of which
        // source (env or `home_dir()`) produced the value.
        .filter(|p| p.is_absolute())
}

/// Detect MCP config files: the repo-local surface joined onto `root`, plus the
/// home-relative Windsurf config (`~/.codeium/windsurf/mcp_config.json`).
///
/// The home base is resolved via [`home_base`] (env-first), NOT `home::home_dir`
/// directly, so the home-relative scan is isolatable in tests on every OS
/// (CodeRabbit M13 PR #132 R11-3).
fn detect_mcp_configs(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = MCP_CONFIG_RELATIVE_PATHS
        .iter()
        .filter(|rel| root.join(rel).is_file())
        .map(|rel| (*rel).to_string())
        .collect();

    if let Some(home) = home_base() {
        let windsurf = home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json");
        if windsurf.is_file() {
            found.push(windsurf.display().to_string());
        }
    }
    // Sort for a STABLE order (R19-N1). The repo-local matches are already produced
    // in a fixed order from `MCP_CONFIG_RELATIVE_PATHS`, but sorting keeps the
    // serialized `mcp_configs` array deterministic regardless of how the home
    // windsurf path interleaves, matching `detect_ai_config`'s contract.
    found.sort();
    found
}

/// Surface tirith's install state read-only: whether the shell hook is wired
/// into the detected shell's profile (reusing `doctor::check_shell_profile`),
/// and whether a policy is discoverable from `cwd` (reusing the engine's local
/// discovery). Never materializes hooks.
fn detect_tirith_state(cwd: &Path, detected_shell: &str) -> TirithState {
    let (_profile, hook_installed) =
        crate::cli::doctor::check_shell_profile(detected_shell, "tirith: onboard:");
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
    apply_actions_with_interactivity(report, is_tty_pair())
}

/// The body of [`apply_actions`], with the interactivity decision INJECTED rather
/// than read from the ambient TTY. Split out (R15-onboard.rs:650) so the
/// non-interactive refusal path is unit-testable deterministically: a PTY-backed
/// test runner can make `is_tty_pair()` return `true`, which would otherwise send
/// the refusal test down the interactive branch and block on `read_line`. Tests
/// call this directly with `interactive: false`; production calls
/// [`apply_actions`], which passes the real `is_tty_pair()`.
fn apply_actions_with_interactivity(report: &OnboardReport, interactive: bool) -> i32 {
    println!();

    // Idempotency: if the hook AND policy are already present there is no
    // mutating step to perform, so `--apply` is a no-op REGARDLESS of TTY. Report
    // success and return BEFORE the non-interactive refusal — otherwise a piped /
    // CI `tirith onboard --apply` on an already-configured repo would exit 1 and
    // masquerade as a failure even though it had nothing to do (CodeRabbit M13
    // PR #132 R12-6). The refusal (return 1, below) then only fires when there is
    // actually work to do non-interactively.
    let needs_hook = !report.tirith.hook_installed;
    let needs_policy = !report.tirith.policy_present;
    if !needs_hook && !needs_policy {
        println!("tirith onboard: no actions applied.");
        return 0;
    }

    if !interactive {
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

    /// Build a minimal [`OnboardReport`] for `apply_actions` tests, varying only
    /// the install state that drives the idempotency / refusal decision.
    fn report_with_state(hook_installed: bool, policy_present: bool) -> OnboardReport {
        OnboardReport {
            schema_version: ONBOARD_SCHEMA_VERSION,
            cwd: ".".to_string(),
            repo_root: None,
            requested_mode: "auto".to_string(),
            detected_shell: "bash".to_string(),
            ide_configs: vec![],
            ai_config_files: vec![],
            package_managers: vec![],
            lockfiles: vec![],
            ci_detected: false,
            mcp_configs: vec![],
            tirith: TirithState {
                hook_installed,
                policy_present,
                policy_path: policy_present.then(|| "/repo/.tirith/policy.yaml".to_string()),
            },
            recommended_template: "individual".to_string(),
            recommendation_reason: "test".to_string(),
            next_actions: vec!["do a thing".to_string()],
        }
    }

    /// R12-6: a non-interactive `--apply` on an already-configured repo (hook AND
    /// policy present) is a NO-OP, so `apply_actions_with_interactivity` returns 0
    /// — it must NOT hit the non-interactive refusal (exit 1) when there is
    /// nothing to do. R15-onboard.rs:650: injecting `interactive = false` makes
    /// this deterministic regardless of the runner's ambient TTY (a PTY runner
    /// would otherwise take the interactive branch). This is exactly the piped/CI
    /// path the finding is about: idempotent `--apply` must look like a success.
    #[test]
    fn apply_actions_noop_when_already_configured_returns_zero() {
        let report = report_with_state(true, true);
        assert_eq!(
            apply_actions_with_interactivity(&report, false),
            0,
            "an already-configured repo has nothing to apply — must exit 0 even non-interactively"
        );
    }

    /// R12-6 (the converse): when there IS a mutating step to perform (hook
    /// missing), a non-interactive `apply_actions_with_interactivity` still
    /// refuses and returns 1. R15-onboard.rs:650: `interactive = false` is
    /// injected so the refusal path is exercised deterministically — a PTY runner
    /// can no longer divert this into the interactive branch and block on
    /// `read_line`. Pairs with the no-op test to prove the no-op short-circuit
    /// fires ONLY when nothing is needed.
    #[test]
    fn apply_actions_noninteractive_with_work_returns_one() {
        // Policy present but hook missing → a real step remains, so the
        // non-interactive refusal must fire (exit 1).
        let report = report_with_state(false, true);
        assert_eq!(
            apply_actions_with_interactivity(&report, false),
            1,
            "a non-interactive --apply with work to do must refuse (exit 1)"
        );
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

    /// R19-N1: the detected `ai_config_files` list must be SORTED so the
    /// `onboard --json` report is deterministic. `detect_ai_config` globs themed
    /// `.clinerules-*` / `.roorules-*` via `read_dir`, whose iteration order is
    /// OS-/filesystem-dependent — without the sort, planting several such files
    /// (plus the deterministic basename + `.claude/` / `.cursor/rules/` entries)
    /// could yield a different array order from one run to the next. Plant a
    /// multi-file tree spanning all three code paths and assert the result is in
    /// sorted order.
    #[test]
    fn detect_ai_config_is_sorted_for_stable_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // Basename-loop entries (deterministic source order in AI_CONFIG_BASENAMES,
        // chosen here so their natural order differs from sorted order).
        std::fs::write(root.join("CLAUDE.md"), "x\n").unwrap();
        std::fs::write(root.join(".cursorrules"), "x\n").unwrap();
        std::fs::write(root.join("AGENTS.md"), "x\n").unwrap();
        // read_dir-driven themed rules — the non-deterministic source.
        std::fs::write(root.join(".clinerules-security"), "x\n").unwrap();
        std::fs::write(root.join(".clinerules-perf"), "x\n").unwrap();
        std::fs::write(root.join(".roorules-review"), "x\n").unwrap();
        // Directory-signal entries appended after the loops.
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::fs::create_dir_all(root.join(".cursor").join("rules")).unwrap();
        std::fs::write(root.join(".cursor").join("rules").join("a.mdc"), "rule\n").unwrap();

        let found = detect_ai_config(root);
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(
            found, sorted,
            "ai_config_files must be returned in sorted order for deterministic JSON, got: {found:?}"
        );
        // Sanity: the multi-source tree really did populate all three paths.
        assert!(found.iter().any(|f| f == "CLAUDE.md"));
        assert!(found.iter().any(|f| f == ".clinerules-security"));
        assert!(found.iter().any(|f| f == ".claude/"));
        assert!(found.iter().any(|f| f == ".cursor/rules/"));
    }

    /// R19-N1: the `mcp_configs` list is likewise returned sorted, so the
    /// `onboard --json` report's `mcp_configs` array is deterministic. Plant
    /// several repo-local MCP configs (whose un-sorted order follows the
    /// `MCP_CONFIG_RELATIVE_PATHS` table) and assert the result is sorted.
    #[test]
    fn detect_mcp_configs_is_sorted_for_stable_json() {
        let repo = tempfile::tempdir().expect("repo");
        let root = repo.path();
        // Plant a few repo-local MCP configs whose table order is NOT sorted order
        // (`.vscode/mcp.json` precedes `.cursor/mcp.json` in the table but sorts
        // after it lexically).
        std::fs::write(root.join("mcp.json"), "{}\n").unwrap();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(root.join(".vscode").join("mcp.json"), "{}\n").unwrap();
        std::fs::create_dir_all(root.join(".cursor")).unwrap();
        std::fs::write(root.join(".cursor").join("mcp.json"), "{}\n").unwrap();

        // Isolate the home base so a runner's real ~/.codeium can't leak in.
        let home = tempfile::tempdir().expect("home");
        let _guard = HomeGuard::set(home.path());

        let found = detect_mcp_configs(root);
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(
            found, sorted,
            "mcp_configs must be returned in sorted order for deterministic JSON, got: {found:?}"
        );
        assert!(
            found.len() >= 3,
            "expected the three planted repo-local MCP configs, got: {found:?}"
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

    /// CodeRabbit M13 PR #132 round-22 F3: `detect_ci` must count only REGULAR
    /// FILES under `.github/workflows/` — a DIRECTORY whose name ends in
    /// `.yml`/`.yaml` (e.g. a dir literally named `pipeline.yaml`) is NOT a CI
    /// pipeline and must not flip detection. Cover both halves: a real `*.yml`
    /// FILE → CI detected; a workflows dir containing ONLY a `*.yaml`-named
    /// SUBDIRECTORY (no real workflow file) → CI NOT detected.
    #[test]
    fn detect_ci_requires_regular_file_not_directory() {
        // Half 1: a real workflow FILE → CI detected.
        let with_file = tempfile::tempdir().expect("tempdir");
        let wf = with_file.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("ci.yml"), "on: push\n").unwrap();
        assert!(
            detect_ci(with_file.path()),
            "a real *.yml workflow FILE must be detected as CI"
        );

        // Half 2: the workflows dir holds ONLY a directory named like a workflow
        // (`pipeline.yaml/`), no regular workflow file → NOT CI.
        let dir_only = tempfile::tempdir().expect("tempdir");
        let wf2 = dir_only.path().join(".github").join("workflows");
        std::fs::create_dir_all(wf2.join("pipeline.yaml")).unwrap();
        assert!(
            !detect_ci(dir_only.path()),
            "a DIRECTORY named *.yaml under workflows must NOT be counted as CI"
        );
    }

    /// F3 (no-regression): a missing `.github/workflows/` directory still reads as
    /// non-CI (the IO-error branch), so the file-type guard didn't change the
    /// conservative no-workflows-dir behaviour.
    #[test]
    fn detect_ci_absent_workflows_dir_is_not_ci() {
        let empty = tempfile::tempdir().expect("tempdir");
        assert!(
            !detect_ci(empty.path()),
            "no .github/workflows dir must read as non-CI"
        );
    }

    // `HOME` / `USERPROFILE` are process-global and cargo runs unit tests in
    // parallel. The R11-3 tests that point the home base at a temp dir must not
    // interleave with each other OR with any OTHER env-mutating test in the
    // crate. Rather than duplicate the crate-wide lock/guard, reuse
    // `test_harness::{ENV_LOCK, EnvGuard}` — the SINGLE crate-wide HOME/env lock
    // every other env-mutating test (`doctor`, `setup::tools`, ...) already
    // serialises on. `HomeGuard` is now a thin RAII wrapper that holds the
    // crate-wide lock plus two `EnvGuard`s (one each for `HOME` / `USERPROFILE`)
    // so it still points BOTH vars at `dir` on every OS and restores them on
    // Drop even if the test panics — identical behaviour, no duplicate locking.
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};

    struct HomeGuard {
        // Teardown order is enforced EXPLICITLY by the `Drop` impl below
        // (env guards dropped before the lock), NOT by field-declaration
        // order — so a future reorder of these fields can't silently let
        // another test observe a restored-but-still-locked or
        // unlocked-but-not-yet-restored env. Each field is an `Option` so
        // `drop` can `.take()` and drop them one at a time in the order it
        // chooses; `home`/`userprofile` are always `Some` for a live guard.
        home: Option<EnvGuard>,
        userprofile: Option<EnvGuard>,
        lock: Option<std::sync::MutexGuard<'static, ()>>,
    }

    impl HomeGuard {
        /// Point BOTH `HOME` (Unix) and `USERPROFILE` (Windows) at `dir` so
        /// [`home_base`] resolves there on every OS, isolated from the real home.
        /// Acquires the crate-wide `ENV_LOCK` so no other env-mutating test can
        /// race; the two `EnvGuard`s restore the prior values on Drop.
        fn set(dir: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let home = EnvGuard::set("HOME", dir);
            let userprofile = EnvGuard::set("USERPROFILE", dir);
            Self {
                home: Some(home),
                userprofile: Some(userprofile),
                lock: Some(lock),
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            // ORDER: restore the env vars FIRST (drop both `EnvGuard`s), THEN
            // release the crate-wide lock. Dropping each `.take()`n value at
            // the end of its `let` statement makes the sequence explicit and
            // refactor-proof — it no longer depends on field-declaration order.
            // Any field left `None` (already taken) is simply a no-op drop.
            drop(self.home.take());
            drop(self.userprofile.take());
            // Lock released LAST so no other env-mutating test can acquire it
            // and observe HOME/USERPROFILE before they've been restored above.
            drop(self.lock.take());
        }
    }

    /// R11-3: [`home_base`] must resolve from the `$HOME` / `%USERPROFILE%` env,
    /// NOT the OS passwd entry, so the home-relative MCP scan is isolatable on
    /// every OS (incl. macOS, where `home::home_dir()` can prefer `getpwuid_r`).
    /// This also covers the ABSOLUTE half of R12-5: an absolute temp `HOME` is
    /// honored and returned verbatim.
    #[test]
    fn home_base_resolves_from_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = HomeGuard::set(dir.path());
        assert_eq!(
            home_base(),
            Some(dir.path().to_path_buf()),
            "home_base must honor the HOME/USERPROFILE env override"
        );
    }

    /// R12-5: a RELATIVE `$HOME` / `%USERPROFILE%` (e.g. `HOME=.`) must NOT be
    /// returned — it would make the home-relative MCP scan probe a cwd-relative
    /// `.codeium/...` and fabricate an MCP signal. `home_base` falls back to
    /// `home::home_dir()` instead, and never echoes back the relative path.
    #[test]
    fn home_base_rejects_relative_home() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        // A clearly-relative override on every OS.
        std::env::set_var("HOME", "relative-home");
        std::env::set_var("USERPROFILE", "relative-home");

        let base = home_base();

        // Restore before asserting so a failure can't leak the relative env.
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_userprofile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }

        // It must not echo back the relative override...
        assert_ne!(
            base.as_deref(),
            Some(Path::new("relative-home")),
            "home_base must not return a relative HOME/USERPROFILE override"
        );
        // ...and whatever it falls back to must be absolute (or absent).
        if let Some(p) = &base {
            assert!(
                p.is_absolute(),
                "home_base fallback must be absolute, got {p:?}"
            );
        }
    }

    /// R11-3: an EMPTY `HOME`/`USERPROFILE` must be treated as unset (mirroring
    /// `policy::state_dir`'s empty-`XDG_STATE_HOME` handling), so `home_base`
    /// never returns an empty/relative base. This is the behaviour unique to the
    /// env-first helper — a naive `var_os("HOME")` would return `Some("")` and
    /// silently anchor the windsurf scan at a bogus relative path. With both vars
    /// empty, `home_base` falls back to `home::home_dir()` (a non-empty absolute
    /// path) or `None`, never `Some("")`.
    #[test]
    fn home_base_treats_empty_env_as_unset() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var_os("HOME");
        let prev_userprofile = std::env::var_os("USERPROFILE");
        std::env::set_var("HOME", "");
        std::env::set_var("USERPROFILE", "");

        let base = home_base();
        // Restore before asserting so a failure can't leak empty env into siblings.
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_userprofile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }

        assert_ne!(
            base.as_deref(),
            Some(Path::new("")),
            "home_base must not return an empty path for an empty HOME/USERPROFILE"
        );
        if let Some(p) = &base {
            assert!(
                !p.as_os_str().is_empty(),
                "home_base fallback must be a non-empty path, got {p:?}"
            );
        }
    }

    /// R11-3 (the core fix): the home-relative Windsurf MCP config is detected
    /// when it lives under the ENV-resolved home, and a repo that plants no MCP
    /// config yields ZERO — regardless of the host's real `~/.codeium`. Because
    /// the scan resolves the home base from `HOME`/`USERPROFILE` (which the guard
    /// repoints at a temp dir), the runner's real `~/.codeium/windsurf/...` can
    /// never leak in, so the `onboard_json_ci_repo_recommends_ci_strict`
    /// integration test stays deterministic on macOS.
    #[test]
    fn detect_mcp_configs_uses_env_home_for_windsurf() {
        // An empty repo root (no repo-local MCP configs planted).
        let repo = tempfile::tempdir().expect("repo");

        // Case 1: isolated home WITHOUT a windsurf config → zero MCP configs,
        // even if the real host home has one.
        let home_absent = tempfile::tempdir().expect("home_absent");
        {
            let _guard = HomeGuard::set(home_absent.path());
            let found = detect_mcp_configs(repo.path());
            assert!(
                found.is_empty(),
                "an isolated home with no windsurf config must yield 0 MCP configs \
                 (host's real ~/.codeium must not leak in), got: {found:?}"
            );
        }

        // Case 2: plant the windsurf config UNDER the isolated home → it IS
        // detected, proving the env-resolution path actually reads HOME.
        let home_present = tempfile::tempdir().expect("home_present");
        let windsurf_dir = home_present.path().join(".codeium").join("windsurf");
        std::fs::create_dir_all(&windsurf_dir).unwrap();
        let windsurf_cfg = windsurf_dir.join("mcp_config.json");
        std::fs::write(&windsurf_cfg, "{}\n").unwrap();
        {
            let _guard = HomeGuard::set(home_present.path());
            let found = detect_mcp_configs(repo.path());
            assert!(
                found
                    .iter()
                    .any(|f| f == &windsurf_cfg.display().to_string()),
                "a windsurf MCP config under the isolated home must be detected, got: {found:?}"
            );
        }
    }
}
