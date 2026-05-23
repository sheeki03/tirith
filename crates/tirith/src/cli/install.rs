//! `tirith install` — the safe-install transaction.
//!
//! `tirith install <npm|pip|cargo|url> <args...>` wraps a real package install
//! with **pre-execution install-risk analysis** and records the transaction.
//! It is the *assembly chunk* of M3 (Supply-Chain Firewall): it composes
//! existing tirith building blocks rather than adding new detection —
//!
//!  * the install-command rules, URL rules, and threat-DB package rules, via
//!    [`tirith_core::engine`];
//!  * the deterministic package-risk scorer
//!    ([`tirith_core::package_risk`]) and its opt-in registry-API provenance
//!    signals;
//!  * [`tirith_core::checkpoint`] for a before/after file record;
//!  * [`tirith_core::receipt`] / [`tirith_core::runner`] for the safe
//!    download-and-run path of the `url` form;
//!  * [`tirith_core::audit`] for the transaction record.
//!
//! The flow is **analyze → inform → record → run**:
//!  1. *Analyze* — score the package(s) and the would-be install command
//!     *before* anything is installed, producing one explainable verdict.
//!  2. *Inform* — present the verdict. A **block** refuses (bypass per
//!     policy); a **warn** requires an interactive acknowledgement, exactly as
//!     `tirith check` does; an **allow** proceeds.
//!  3. *Record* — take a checkpoint of the working directory and audit-log
//!     the verdict so there is a before/after record of the transaction.
//!  4. *Run* — only now invoke the real `npm install` / `pip install` /
//!     `cargo install` (directly, never through a shell), or the downloaded
//!     script for the `url` form.
//!
//! ## What this is NOT
//!
//! This is install-risk **analysis** plus a recorded transaction. It does
//! **not** sandbox, isolate, or contain the install — runtime sandboxing is an
//! explicit tirith non-goal (see `docs/threat-model.md`). The real install
//! runs with the user's full privileges. tirith's contribution is that the
//! install is analyzed, surfaced, and recorded *first* — nothing here, in
//! `--help`, or in the docs, claims otherwise.

#[cfg(unix)]
use tirith_core::runner::{self, RunOptions};

use std::process::Command;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::install_txn::{self, InstallPlan, OnlineMode, PackageManager, PlanRequest};
use tirith_core::policy::Policy;
use tirith_core::registry_api::{self, HttpRegistryClient};
use tirith_core::style::Stream;
use tirith_core::threatdb::{Ecosystem, ThreatDb};
use tirith_core::verdict::{Action, Verdict};

/// Which install source the `<npm|pip|cargo|url>` positional selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallSource {
    /// `npm install <pkg...>`
    Npm,
    /// `pip install <pkg...>`
    Pip,
    /// `cargo install <pkg...>`
    Cargo,
    /// Download and run an install script from a URL (delegates to the
    /// existing `tirith run` safe download-and-run machinery).
    Url,
}

impl InstallSource {
    /// The package-manager mapping, or `None` for [`InstallSource::Url`]
    /// (which is not a package-manager transaction).
    fn package_manager(self) -> Option<PackageManager> {
        match self {
            InstallSource::Npm => Some(PackageManager::Npm),
            InstallSource::Pip => Some(PackageManager::Pip),
            InstallSource::Cargo => Some(PackageManager::Cargo),
            InstallSource::Url => None,
        }
    }
}

/// Abstraction over actually running the real package-manager install.
///
/// The production implementation ([`ProcessInstallRunner`]) spawns the real
/// process; tests inject a fake so a test **never** installs anything and
/// **never** touches the network. The trait takes the resolved argv — the
/// program and its arguments — and runs it *directly*, never via a shell.
pub trait InstallRunner {
    /// Run the install command `program args...` and return its exit code.
    ///
    /// `Ok(Some(code))` is the process's exit code; `Ok(None)` means the
    /// process was terminated by a signal and so has no exit code. A failure
    /// to *spawn* the process at all is an `Err` (the production
    /// implementation's `?`), not `Ok(None)`. The caller treats both `Ok(None)`
    /// and `Err` as a non-success.
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<Option<i32>>;
}

/// Production [`InstallRunner`] — spawns the real package manager with
/// inherited stdio so its output streams straight to the user's terminal.
pub struct ProcessInstallRunner;

impl InstallRunner for ProcessInstallRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<Option<i32>> {
        // Direct spawn — `program` is a fixed package-manager name and `args`
        // are passed through argv, so there is no shell and no word-splitting.
        let status = Command::new(program).args(args).status()?;
        Ok(status.code())
    }
}

/// Entry point for `tirith install`.
///
/// `source` selects the install kind; `args` are the user's arguments after
/// the source (the package list / flags, or the URL for the `url` form).
#[allow(clippy::too_many_arguments)]
pub fn run(
    source: InstallSource,
    args: &[String],
    online: bool,
    offline: bool,
    json: bool,
    yes: bool,
    no_exec: bool,
    sha256: Option<String>,
) -> i32 {
    // A tirith-owned flag placed AFTER <source> lands in the package-manager
    // args (trailing_var_arg), not parsed by tirith. For a tirith flag that is
    // a safety footgun: `tirith install npm pkg --no-exec` would forward
    // `--no-exec` to npm and STILL run the real install, despite the user
    // asking to analyze only. The guarded flags are the tirith-owned options
    // that no package manager interprets as an install flag, so finding one in
    // the trailing args is unambiguously a misplaced tirith flag — a hard
    // error, not a silent no-op. `--offline` is deliberately NOT guarded
    // (`cargo install --offline` is legitimate), nor `--format` / `--json`
    // (`npm install --json` is legitimate).
    const MISPLACED_TIRITH_FLAGS: &[&str] = &["--no-exec", "--online", "--yes"];
    if let Some(flag) = args
        .iter()
        .find(|a| MISPLACED_TIRITH_FLAGS.contains(&a.as_str()))
    {
        eprintln!(
            "tirith install: `{flag}` is a tirith option and must come before \
             the <source> argument (e.g. `tirith install {flag} npm \
             <package>`). After <source>, arguments go to the package manager \
             — a misplaced `{flag}` would not affect tirith."
        );
        return 2;
    }
    match source.package_manager() {
        Some(manager) => run_package_manager(manager, args, online, offline, json, yes, no_exec),
        None => run_url(args, online, offline, json, no_exec, sha256),
    }
}

// ===========================================================================
// package-manager form: npm / pip / cargo
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn run_package_manager(
    manager: PackageManager,
    args: &[String],
    online: bool,
    offline: bool,
    json: bool,
    yes: bool,
    no_exec: bool,
) -> i32 {
    if args.is_empty() {
        eprintln!(
            "tirith install: no packages or arguments given for {}.",
            manager.label()
        );
        eprintln!(
            "  try: tirith install {} <package>   (e.g. tirith install {} {})",
            manager.label(),
            manager.label(),
            example_package(manager),
        );
        return 2;
    }

    let interactive = is_terminal::is_terminal(std::io::stderr());
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = Policy::discover(cwd.as_deref());

    // --- ANALYZE --------------------------------------------------------
    // Resolve the registry-API path. Offline by default; `--online` opts in,
    // and `--offline` / `TIRITH_OFFLINE` overrides `--online`. The resolver is
    // offline-safe — it degrades any registry failure to `Unavailable`.
    let use_online = online && !offline && !super::offline_env_active();
    let http_client = HttpRegistryClient::new();
    let resolver =
        |eco: Ecosystem, name: &str| registry_api::gather_api_signals(&http_client, eco, name);
    let online_mode = if use_online {
        OnlineMode::Resolver(&resolver)
    } else {
        OnlineMode::Off
    };

    let db = ThreatDb::cached();
    let plan_request = PlanRequest {
        manager,
        user_args: args,
        db: db.as_deref(),
        policy: &policy,
        cwd: cwd.clone(),
        interactive,
        online: online_mode,
    };
    let mut plan = install_txn::plan_install(&plan_request);

    // M4 item 8 chunk 3 follow-up — stamp the resolved caller origin on the
    // plan's verdict BEFORE the audit-log write below. The engine that built
    // the plan does not know the caller's identity by design; the CLI does.
    // Without this stamp, `tirith install` audit lines would land in the
    // `tirith agent sessions` "unknown" bucket.
    plan.verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` on the
    // install path. `tirith install` does not route through
    // `post_process_verdict`, so without this call an operator who writes
    // a `deny` matcher to block an untrusted agent would see deny enforce
    // on `tirith check` but silently fail on `tirith install npm
    // evil-pkg` (a package-management hostile surface). The helper is a
    // no-op on `Allowed`/`Unspecified`.
    tirith_core::escalation::apply_agent_rules(&mut plan.verdict, &policy);

    // --- INFORM ---------------------------------------------------------
    if json {
        // A JSON-write failure means the consumer never received the analysis
        // — do not then run the install behind a verdict it cannot read. Exit
        // non-zero, consistent with `tirith version`'s JSON-failure handling.
        if !print_plan_json(&plan, use_online) {
            return 1;
        }
    } else {
        print_plan_human(&plan, use_online);
    }

    // The gate must be decided *before* the audit is written: a BLOCK that is
    // bypassed via `TIRITH=0` has to be recorded as bypassed. `--no-exec`
    // never installs, so there is no bypass and no gate — its audit reflects
    // the verdict as-is. The exit code on `--no-exec` still mirrors the
    // verdict so a script can branch on it: 0 allow, 1 block, 2 warn.
    let decision = if no_exec {
        if !json {
            eprintln!(
                "tirith install: --no-exec — analysis only, '{}' was NOT run.",
                plan.analysis_command
            );
        }
        match plan.verdict.action {
            Action::Allow => ProceedDecision::Stop(0),
            Action::Block => ProceedDecision::Stop(1),
            Action::Warn | Action::WarnAck => ProceedDecision::Stop(2),
        }
    } else {
        // A block refuses; a warn needs acknowledgement; an allow proceeds.
        decide_proceed(&plan.verdict, &policy, interactive, yes, json)
    };

    // If the gate bypassed a BLOCK via `TIRITH=0`, stamp the verdict so the
    // audit entry records what actually happened — without this, a bypassed
    // block would be logged as `bypass_honored: false`.
    if matches!(decision, ProceedDecision::Go) && plan.verdict.action == Action::Block {
        plan.verdict.bypass_requested = true;
        plan.verdict.bypass_honored = true;
    }

    // Audit the verdict regardless of the decision — the analysis happened.
    // A failed audit write does not abort the transaction (it is a record, not
    // a gate), but it must not be silent: the transaction claims to be
    // recorded. Surface it as a non-fatal notice, mirroring the checkpoint
    // path's "skipped (non-fatal)" pattern.
    if let Err(e) = tirith_core::audit::log_verdict(
        &plan.verdict,
        &format!("install {}", plan.analysis_command),
        None,
        None,
        &policy.dlp_custom_patterns,
    ) {
        if !json {
            eprintln!("tirith install: audit log not written (non-fatal): {e}");
        }
    }

    match decision {
        ProceedDecision::Stop(code) => code,
        // --- RECORD then RUN --------------------------------------------
        ProceedDecision::Go => run_and_record(&plan, cwd.as_deref(), json, &ProcessInstallRunner),
    }
}

/// Outcome of the verdict gate.
enum ProceedDecision {
    /// Proceed with the install.
    Go,
    /// Do not install; exit with this code.
    Stop(i32),
}

/// Apply the verdict gate, consistent with `tirith check`:
///
///  * **Block** — refuse. If the policy allows the environment bypass and
///    `TIRITH=0` is set, the block is bypassed (and audited as such by the
///    caller). Otherwise exit `1`.
///  * **Warn / WarnAck** — require acknowledgement. With `--yes`, or an
///    interactive `y` at the prompt, proceed; otherwise exit `2`.
///  * **Allow** — proceed.
fn decide_proceed(
    verdict: &Verdict,
    policy: &Policy,
    interactive: bool,
    yes: bool,
    json: bool,
) -> ProceedDecision {
    match verdict.action {
        Action::Allow => ProceedDecision::Go,

        Action::Block => {
            // Policy-gated environment bypass — the same `TIRITH=0` escape
            // hatch `tirith check` honors. A non-interactive session may only
            // bypass when policy additionally opts that in.
            let bypass_set = std::env::var("TIRITH").ok().as_deref() == Some("0");
            let bypass_allowed =
                policy.allow_bypass_env && (interactive || policy.allow_bypass_env_noninteractive);
            if bypass_set && bypass_allowed {
                if !json {
                    eprintln!(
                        "tirith install: BLOCK bypassed via TIRITH=0 (policy permits) — \
                         proceeding against advice."
                    );
                }
                ProceedDecision::Go
            } else {
                if !json {
                    eprintln!(
                        "tirith install: refusing to install — the analysis BLOCKED \
                         this transaction (see findings above)."
                    );
                    if policy.allow_bypass_env {
                        eprintln!("  to override against advice: TIRITH=0 tirith install ...");
                    }
                }
                ProceedDecision::Stop(1)
            }
        }

        Action::Warn | Action::WarnAck => {
            if yes {
                if !json {
                    eprintln!(
                        "tirith install: proceeding past {} warning(s) (--yes).",
                        verdict.findings.len()
                    );
                }
                return ProceedDecision::Go;
            }
            if !interactive {
                if !json {
                    eprintln!(
                        "tirith install: {} warning(s) — not installing in a \
                         non-interactive session. Re-run with --yes to proceed.",
                        verdict.findings.len()
                    );
                }
                return ProceedDecision::Stop(2);
            }
            // Interactive acknowledgement, mirroring `tirith check`'s prompt.
            eprint!(
                "tirith install: proceed with {} warning(s) and install? [y/N] ",
                verdict.findings.len()
            );
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() {
                eprintln!("tirith install: could not read confirmation — not installing.");
                return ProceedDecision::Stop(2);
            }
            if matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
                ProceedDecision::Go
            } else {
                eprintln!("tirith install: cancelled — nothing was installed.");
                ProceedDecision::Stop(2)
            }
        }
    }
}

/// Take a before-install checkpoint, run the real install via `runner`, then
/// report — the *record* and *run* steps of the transaction.
///
/// The checkpoint is best-effort: it snapshots the working directory so the
/// user has a before/after record (`tirith checkpoint diff <id>`). It is **not**
/// a sandbox and **not** an automatic rollback — a failed install is not undone
/// for the user; the checkpoint simply makes the change inspectable.
fn run_and_record(
    plan: &InstallPlan,
    cwd: Option<&str>,
    json: bool,
    runner: &dyn InstallRunner,
) -> i32 {
    // --- RECORD: before-install checkpoint ------------------------------
    let checkpoint_id = match cwd {
        Some(dir) => {
            let trigger = format!("install {}", plan.analysis_command);
            match tirith_core::checkpoint::create(&[dir], Some(&trigger)) {
                Ok(meta) => {
                    if !json {
                        eprintln!(
                            "tirith install: checkpoint {} taken ({} file(s)) — \
                             before/after record only, not a sandbox.",
                            meta.id, meta.file_count
                        );
                    }
                    Some(meta.id)
                }
                Err(e) => {
                    // A checkpoint failure must not abort the install — it is
                    // a record, not a gate. Report and continue.
                    if !json {
                        eprintln!("tirith install: checkpoint skipped (non-fatal): {e}");
                    }
                    None
                }
            }
        }
        None => None,
    };

    // --- RUN: the real install -----------------------------------------
    if !json {
        eprintln!("tirith install: running '{}' ...", plan.analysis_command);
    }
    let exit_code = match runner.run(&plan.argv.program, &plan.argv.args) {
        Ok(Some(code)) => code,
        Ok(None) => {
            if !json {
                eprintln!(
                    "tirith install: '{}' did not return an exit code \
                     (terminated by signal).",
                    plan.argv.program
                );
            }
            1
        }
        Err(e) => {
            if !json {
                eprintln!("tirith install: failed to run '{}': {e}", plan.argv.program);
            }
            return 1;
        }
    };

    if json {
        // The install already ran; the outcome JSON is how the consumer learns
        // the result. If that write fails, a `0` install exit must not be
        // reported as overall success — surface the output failure as exit 1.
        // (A non-zero install exit already propagates and is kept.)
        if !print_outcome_json(plan, checkpoint_id.as_deref(), exit_code) && exit_code == 0 {
            return 1;
        }
    } else {
        let after = if exit_code == 0 {
            "completed".to_string()
        } else {
            format!("exited {exit_code}")
        };
        eprintln!("tirith install: '{}' {after}.", plan.analysis_command);
        if let Some(id) = &checkpoint_id {
            eprintln!("  before/after record: tirith checkpoint diff {id}");
        }
    }

    exit_code
}

// ===========================================================================
// url form — delegates to the existing `tirith run` machinery
// ===========================================================================

/// The `url` form: download-and-run an install script.
///
/// Per the assembly principle, this does **not** re-implement download or
/// execution — it delegates wholly to [`tirith_core::runner`], the existing
/// `tirith run` safe download-and-run path. `runner::run` already downloads
/// with a size cap and timeout, computes a SHA-256, statically analyzes the
/// script body, enforces an interpreter allowlist, writes a [`Receipt`], and
/// asks for confirmation on the controlling terminal before executing.
///
/// `tirith install` adds a *preflight risk verdict* on top: the URL is
/// analyzed first (download-shaped, not pipe-to-shell, so a legitimate
/// installer URL is not auto-blocked), and a BLOCK refuses before any
/// download. A non-blocking preflight then hands off to `runner::run`, whose
/// own `Execute this script? [y/N]` prompt is the go-ahead for execution.
#[cfg(unix)]
fn run_url(
    args: &[String],
    _online: bool,
    _offline: bool,
    json: bool,
    no_exec: bool,
    sha256: Option<String>,
) -> i32 {
    let url = match args {
        [single] => single.as_str(),
        [] => {
            eprintln!("tirith install: no URL given.");
            eprintln!("  try: tirith install url https://get.example-tool.sh");
            return 2;
        }
        _ => {
            eprintln!(
                "tirith install: the url form takes exactly one URL \
                 (got {} arguments).",
                args.len()
            );
            return 2;
        }
    };

    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = Policy::discover(cwd.as_deref());
    let interactive = is_terminal::is_terminal(std::io::stderr());

    // --- ANALYZE: URL preflight ----------------------------------------
    // Analyze the URL as a *download* (`curl -fsSL <url>`), NOT as a
    // pipe-to-shell. Analyzing `curl <url> | sh` would make CurlPipeShell fire
    // on every URL and turn every URL install into a block. The real script
    // body is analyzed separately by `runner::run` after download.
    let mut preflight = preflight_url(url, cwd.as_deref(), interactive);

    // M4 item 8 chunk 3 follow-up — stamp the resolved caller origin on the
    // preflight verdict BEFORE the audit-log write below. The engine that
    // built the preflight does not know the caller's identity by design; the
    // CLI does. Without this stamp, `tirith install url` audit lines would
    // land in the `tirith agent sessions` "unknown" bucket.
    preflight.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` on the URL
    // install path. `tirith install url` does not route through
    // `post_process_verdict`, so without this call deny would stamp but
    // not enforce on the URL-download hostile surface. The helper is a
    // no-op on `Allowed`/`Unspecified`. Runs BEFORE the bypass-decision
    // block below so a deny-forced Block can still be bypassed by
    // `TIRITH=0` (consistent with how the regular pipeline behaves —
    // finding A in the M4 PR #120 wave-end review tracks the
    // bypass-skips-agent-rules gap).
    tirith_core::escalation::apply_agent_rules(&mut preflight, &policy);

    if json {
        // A JSON-write failure means the consumer never received the preflight
        // verdict — do not then proceed to download. Exit non-zero.
        if !print_url_preflight_json(url, &preflight) {
            return 1;
        }
    } else {
        print_url_preflight_human(url, &preflight);
    }

    // Decide the block/bypass *before* auditing so a `TIRITH=0`-bypassed BLOCK
    // is recorded as bypassed rather than logged as `bypass_honored: false`.
    let blocked_and_refused = if preflight.action == Action::Block {
        let bypass_set = std::env::var("TIRITH").ok().as_deref() == Some("0");
        let bypass_allowed =
            policy.allow_bypass_env && (interactive || policy.allow_bypass_env_noninteractive);
        if bypass_set && bypass_allowed {
            // Bypassed — stamp the verdict so the audit entry is honest.
            preflight.bypass_requested = true;
            preflight.bypass_honored = true;
            false
        } else {
            true
        }
    } else {
        false
    };

    // A failed audit write does not abort the transaction, but the URL form
    // also claims to be recorded — surface a non-fatal notice on failure.
    if let Err(e) = tirith_core::audit::log_verdict(
        &preflight,
        &format!("install url {url}"),
        None,
        None,
        &policy.dlp_custom_patterns,
    ) {
        if !json {
            eprintln!("tirith install: audit log not written (non-fatal): {e}");
        }
    }

    // A blocking preflight that was not bypassed refuses before any download.
    if blocked_and_refused {
        if !json {
            eprintln!(
                "tirith install: refusing to download — the URL preflight \
                 BLOCKED this transaction (see findings above)."
            );
        }
        return 1;
    }
    if preflight.action == Action::Block && !json {
        eprintln!(
            "tirith install: URL preflight BLOCK bypassed via TIRITH=0 \
             (policy permits) — proceeding against advice."
        );
    }

    // A warning preflight is surfaced; `runner::run`'s own confirmation prompt
    // is the acknowledgement, so there is no second prompt here.
    if preflight.action != Action::Allow && !json {
        eprintln!(
            "tirith install: URL preflight raised {} finding(s) — the script \
             body will be analyzed and you will be asked to confirm before it runs.",
            preflight.findings.len()
        );
    }

    // --- RECORD + RUN: delegate to the existing safe runner -------------
    // `runner::run` re-analyzes the *downloaded script*, writes a Receipt, and
    // (unless --no-exec) prompts on /dev/tty before executing.
    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256: sha256,
    };
    match runner::run(opts) {
        Ok(result) => {
            let json_ok = if json {
                print_url_outcome_json(&result)
            } else {
                if result.executed {
                    eprintln!(
                        "tirith install: install script executed (receipt {}).",
                        tirith_core::receipt::short_hash(&result.receipt.sha256)
                    );
                } else {
                    eprintln!(
                        "tirith install: install script downloaded and recorded, \
                         not executed (receipt {}).",
                        tirith_core::receipt::short_hash(&result.receipt.sha256)
                    );
                }
                true
            };
            let outcome_code = if result.executed {
                result.exit_code.unwrap_or(1)
            } else {
                0
            };
            // A JSON-write failure must not be reported as a `0` success — if
            // the outcome JSON did not reach the consumer, surface exit 1.
            // (A non-zero script exit already propagates and is kept.)
            if !json_ok && outcome_code == 0 {
                1
            } else {
                outcome_code
            }
        }
        Err(e) => {
            if json {
                // Route through `write_json_stdout` so the trailing newline is
                // a fallible write (no broken-pipe panic). The command is
                // already failing, so a write failure does not change the
                // exit code.
                let _ = write_json_stdout(&serde_json::json!({ "error": e }));
            } else {
                eprintln!("tirith install: {e}");
            }
            1
        }
    }
}

/// On non-Unix the `url` form is unavailable — `tirith run` (and thus the
/// safe runner) is Unix-only. npm/pip/cargo still work.
#[cfg(not(unix))]
fn run_url(
    _args: &[String],
    _online: bool,
    _offline: bool,
    _json: bool,
    _no_exec: bool,
    _sha256: Option<String>,
) -> i32 {
    eprintln!(
        "tirith install: the url form is only available on Unix. \
         Use `tirith install npm|pip|cargo` instead."
    );
    2
}

/// Single-quote a value for a synthesized POSIX shell command, so it is
/// analyzed as one argument. Any embedded single quote is closed, escaped, and
/// reopened (`'\''`) — without this a URL containing `&`, `;`, a backtick, a
/// space, or a quote would tokenize as shell syntax and produce spurious
/// findings.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Analyze a URL as a download (not a pipe-to-shell) and return the verdict.
///
/// Separated so it is unit-testable without touching the network — it only
/// runs the offline `engine::analyze`, no fetch.
fn preflight_url(url: &str, cwd: Option<&str>, interactive: bool) -> Verdict {
    let ctx = AnalysisContext {
        // A download shape: a legitimate installer URL must not trip the
        // pipe-to-shell rule here. The script body is analyzed for real by
        // the runner after it is fetched. The URL is single-quoted so a URL
        // containing shell metacharacters (`&`, `;`, backticks, spaces) is
        // analyzed as a single argument, not as shell syntax.
        input: format!("curl -fsSL {}", shell_single_quote(url)),
        shell: tirith_core::tokenize::ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive,
        cwd: cwd.map(|s| s.to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
    };
    engine::analyze(&ctx)
}

// ===========================================================================
// output
// ===========================================================================

/// A short, well-known example package per manager, for the usage hint.
fn example_package(manager: PackageManager) -> &'static str {
    match manager {
        PackageManager::Npm => "left-pad",
        PackageManager::Pip => "requests",
        PackageManager::Cargo => "ripgrep",
    }
}

/// Render the analysis verdict for a package-manager install (human form).
fn print_plan_human(plan: &InstallPlan, online: bool) {
    let s = Stream::Stderr;
    eprintln!(
        "tirith install: analyzing '{}' before running it",
        plan.analysis_command
    );
    eprintln!("  (pre-execution install-risk analysis — not a sandbox)");
    eprintln!();

    // Per-package risk scores.
    if plan.packages.is_empty() {
        eprintln!("  packages: none on the command line (command-shape analysis only)");
    } else {
        eprintln!("  packages:");
        for pkg in &plan.packages {
            eprintln!(
                "    - {} {} — risk {}/100 ({})",
                pkg.reference.ecosystem, pkg.reference.name, pkg.risk.score, pkg.risk.risk_level,
            );
        }
    }
    eprintln!();

    // The verdict.
    match plan.verdict.action {
        Action::Allow => {
            eprintln!(
                "  {}",
                tirith_core::style::green("verdict: ALLOW — no supply-chain risks found", s)
            );
        }
        Action::Warn | Action::WarnAck => {
            eprintln!(
                "  {}",
                tirith_core::style::yellow(
                    &format!(
                        "verdict: WARN — {} finding(s), acknowledgement required",
                        plan.verdict.findings.len()
                    ),
                    s,
                )
            );
        }
        Action::Block => {
            eprintln!(
                "  {}",
                tirith_core::style::bold_red(
                    &format!(
                        "verdict: BLOCK — {} finding(s), install refused",
                        plan.verdict.findings.len()
                    ),
                    s,
                )
            );
        }
    }
    for finding in &plan.verdict.findings {
        let sev = tirith_core::style::severity_label(&finding.severity, s);
        eprintln!("    {} {} — {}", sev, finding.rule_id, finding.title);
        eprintln!("      {}", finding.description);
    }

    if !plan.notes.is_empty() {
        eprintln!();
        eprintln!("  notes:");
        for note in &plan.notes {
            eprintln!("    - {note}");
        }
    }
    if !online && !plan.packages.is_empty() {
        eprintln!();
        eprintln!(
            "  (offline analysis — re-run with --online to add registry-API \
             provenance signals)"
        );
    }
    eprintln!();
}

/// Write `value` as pretty JSON to stdout. Returns `false` on a write failure
/// (a broken pipe, a full disk) so the caller can exit non-zero — a piped
/// consumer must not see truncated JSON paired with a success exit code.
///
/// Thin wrapper over [`super::write_json_stdout`] carrying the `tirith
/// install` error prefix; the shared helper writes the body and the trailing
/// newline through one locked handle with fallible ops (no broken-pipe panic).
fn write_json_stdout<T: serde::Serialize>(value: &T) -> bool {
    super::write_json_stdout(value, "tirith install: failed to write JSON output")
}

/// Render the analysis verdict for a package-manager install (JSON form).
/// Returns `false` on a JSON-write failure.
fn print_plan_json(plan: &InstallPlan, online: bool) -> bool {
    #[derive(serde::Serialize)]
    struct PackageOut<'a> {
        ecosystem: String,
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<&'a str>,
        risk_score: u32,
        risk_level: &'a str,
    }
    #[derive(serde::Serialize)]
    struct PlanOut<'a> {
        schema_version: u32,
        kind: &'a str,
        manager: &'a str,
        command: &'a str,
        sandboxed: bool,
        online: bool,
        packages: Vec<PackageOut<'a>>,
        verdict: &'a Verdict,
        notes: &'a [String],
    }
    let packages = plan
        .packages
        .iter()
        .map(|p| PackageOut {
            ecosystem: p.reference.ecosystem.to_string(),
            name: &p.reference.name,
            version: p.reference.version.as_deref(),
            risk_score: p.risk.score,
            risk_level: p.risk.risk_level,
        })
        .collect();
    let out = PlanOut {
        schema_version: 1,
        kind: "install_analysis",
        manager: plan.manager.label(),
        command: &plan.analysis_command,
        // Explicit and always false: this transaction is analyzed, not
        // sandboxed. A consumer can assert on it.
        sandboxed: false,
        online,
        packages,
        verdict: &plan.verdict,
        notes: &plan.notes,
    };
    write_json_stdout(&out)
}

/// JSON record of the completed package-manager transaction. Returns `false`
/// on a JSON-write failure.
fn print_outcome_json(plan: &InstallPlan, checkpoint_id: Option<&str>, exit_code: i32) -> bool {
    let out = serde_json::json!({
        "schema_version": 1,
        "kind": "install_outcome",
        "manager": plan.manager.label(),
        "command": plan.analysis_command,
        "sandboxed": false,
        "ran": true,
        "exit_code": exit_code,
        "checkpoint_id": checkpoint_id,
        "verdict_action": format!("{:?}", plan.verdict.action),
    });
    write_json_stdout(&out)
}

/// Render the URL-form preflight verdict (human form).
fn print_url_preflight_human(url: &str, verdict: &Verdict) {
    let s = Stream::Stderr;
    eprintln!("tirith install: preflight analysis of install URL");
    eprintln!("  url: {url}");
    eprintln!("  (pre-execution URL-risk analysis — the script body is analyzed after download; not a sandbox)");
    match verdict.action {
        Action::Allow => {
            eprintln!("  {}", tirith_core::style::green("preflight: ALLOW", s));
        }
        Action::Warn | Action::WarnAck => {
            eprintln!(
                "  {}",
                tirith_core::style::yellow(
                    &format!("preflight: WARN — {} finding(s)", verdict.findings.len()),
                    s,
                )
            );
        }
        Action::Block => {
            eprintln!(
                "  {}",
                tirith_core::style::bold_red(
                    &format!("preflight: BLOCK — {} finding(s)", verdict.findings.len()),
                    s,
                )
            );
        }
    }
    for finding in &verdict.findings {
        let sev = tirith_core::style::severity_label(&finding.severity, s);
        eprintln!("    {} {} — {}", sev, finding.rule_id, finding.title);
        eprintln!("      {}", finding.description);
    }
}

/// Render the URL-form preflight verdict (JSON form). Returns `false` on a
/// JSON-write failure.
fn print_url_preflight_json(url: &str, verdict: &Verdict) -> bool {
    let out = serde_json::json!({
        "schema_version": 1,
        "kind": "install_url_preflight",
        "url": url,
        "sandboxed": false,
        "verdict": verdict,
    });
    write_json_stdout(&out)
}

/// JSON record of the completed URL transaction (the `runner` result).
/// Returns `false` on a JSON-write failure.
#[cfg(unix)]
fn print_url_outcome_json(result: &runner::RunResult) -> bool {
    let out = serde_json::json!({
        "schema_version": 1,
        "kind": "install_url_outcome",
        "sandboxed": false,
        "receipt": &result.receipt,
        "executed": result.executed,
        "exit_code": result.exit_code,
    });
    write_json_stdout(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tirith_core::verdict::{Finding, RuleId, Severity};

    /// A fake [`InstallRunner`] — records the argv it was asked to run and
    /// returns a canned exit code. It NEVER spawns a process, so a test using
    /// it installs nothing and touches no network.
    struct FakeRunner {
        exit_code: Option<i32>,
        seen: Mutex<Vec<(String, Vec<String>)>>,
    }
    impl FakeRunner {
        fn new(exit_code: Option<i32>) -> Self {
            Self {
                exit_code,
                seen: Mutex::new(Vec::new()),
            }
        }
    }
    impl InstallRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<Option<i32>> {
            self.seen
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            Ok(self.exit_code)
        }
    }

    fn allow_verdict() -> Verdict {
        Verdict::from_findings(vec![], 3, Default::default())
    }

    fn warn_verdict() -> Verdict {
        Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::ThreatSuspiciousPackage,
                severity: Severity::Medium,
                title: "t".to_string(),
                description: "d".to_string(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Default::default(),
        )
    }

    fn block_verdict() -> Verdict {
        Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::ThreatMaliciousPackage,
                severity: Severity::Critical,
                title: "t".to_string(),
                description: "d".to_string(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Default::default(),
        )
    }

    #[test]
    fn install_source_package_manager_mapping() {
        assert_eq!(
            InstallSource::Npm.package_manager(),
            Some(PackageManager::Npm)
        );
        assert_eq!(
            InstallSource::Pip.package_manager(),
            Some(PackageManager::Pip)
        );
        assert_eq!(
            InstallSource::Cargo.package_manager(),
            Some(PackageManager::Cargo)
        );
        assert_eq!(InstallSource::Url.package_manager(), None);
    }

    #[test]
    fn decide_proceed_allow_goes() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&allow_verdict(), &policy, false, false, true),
            ProceedDecision::Go
        ));
    }

    #[test]
    fn decide_proceed_block_stops_with_exit_1() {
        let policy = Policy::default();
        // No TIRITH=0 in env for this test path.
        assert!(matches!(
            decide_proceed(&block_verdict(), &policy, true, false, true),
            ProceedDecision::Stop(1)
        ));
    }

    #[test]
    fn decide_proceed_warn_noninteractive_stops_without_yes() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&warn_verdict(), &policy, false, false, true),
            ProceedDecision::Stop(2)
        ));
    }

    #[test]
    fn decide_proceed_warn_with_yes_goes() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&warn_verdict(), &policy, false, true, true),
            ProceedDecision::Go
        ));
    }

    #[test]
    fn fake_runner_records_argv_and_never_spawns() {
        // run_and_record with a fake runner: nothing is installed, the argv is
        // recorded, and the fake's exit code is returned.
        let req_args = vec!["my-pkg".to_string()];
        let argv = install_txn::build_argv(PackageManager::Npm, &req_args);
        let plan = InstallPlan {
            manager: PackageManager::Npm,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
        };
        let runner = FakeRunner::new(Some(0));
        // cwd = None so no checkpoint is attempted (keeps the test hermetic —
        // no filesystem writes outside tempdirs).
        let code = run_and_record(&plan, None, true, &runner);
        assert_eq!(code, 0);
        let seen = runner.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the runner must be called exactly once");
        assert_eq!(seen[0].0, "npm");
        assert_eq!(seen[0].1, vec!["install", "my-pkg"]);
    }

    #[test]
    fn fake_runner_propagates_nonzero_exit() {
        let req_args = vec!["my-pkg".to_string()];
        let argv = install_txn::build_argv(PackageManager::Cargo, &req_args);
        let plan = InstallPlan {
            manager: PackageManager::Cargo,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
        };
        let runner = FakeRunner::new(Some(17));
        let code = run_and_record(&plan, None, true, &runner);
        assert_eq!(code, 17, "the install's own exit code must propagate");
    }

    #[test]
    fn fake_runner_signal_termination_is_failure() {
        let argv = install_txn::build_argv(PackageManager::Pip, &["x".to_string()]);
        let plan = InstallPlan {
            manager: PackageManager::Pip,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
        };
        let runner = FakeRunner::new(None); // signal-terminated → no code
        let code = run_and_record(&plan, None, true, &runner);
        assert_eq!(code, 1);
    }

    #[test]
    fn preflight_url_plain_installer_does_not_block() {
        // A plain https installer URL, analyzed as a *download*, must not be
        // blocked — analyzing it as a pipe-to-shell would. Offline, no network.
        let verdict = preflight_url("https://get.example-tool.sh/install.sh", None, false);
        assert_ne!(
            verdict.action,
            Action::Block,
            "a download-shaped preflight must not block a plain installer URL: {:?}",
            verdict.findings,
        );
    }

    #[test]
    fn preflight_url_raw_ip_is_flagged() {
        // A raw-IP URL is suspicious and the preflight should surface it
        // (raw_ip_url rule) — still offline, no fetch.
        let verdict = preflight_url("http://203.0.113.5/install.sh", None, false);
        assert!(
            verdict.action != Action::Allow,
            "a raw-IP install URL should raise at least one finding"
        );
    }

    #[test]
    fn shell_single_quote_escapes_metacharacters() {
        // CR10: a URL with shell metacharacters must become one quoted token.
        assert_eq!(
            shell_single_quote("https://x.example/a?b=1&c=2"),
            "'https://x.example/a?b=1&c=2'"
        );
        // An embedded single quote is closed/escaped/reopened.
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn preflight_url_with_shell_metacharacters_no_spurious_findings() {
        // CR10: a benign https installer URL carrying `&`, `;`, and a space
        // must not produce findings from the URL tokenizing as shell syntax.
        // Quoting it makes `curl -fsSL '<url>'` analyze the URL as one arg.
        let url = "https://get.example-tool.sh/install.sh?ref=a&v=1;x y";
        let verdict = preflight_url(url, None, false);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "a quoted benign installer URL must not raise shell-syntax findings: {:?}",
            verdict.findings,
        );
    }

    #[test]
    fn preflight_url_quoting_preserves_real_detection() {
        // The quoting must not hide a genuinely suspicious URL — a raw-IP URL
        // is still flagged when it also contains shell metacharacters.
        let verdict = preflight_url("http://203.0.113.5/install.sh?a=1&b=2", None, false);
        assert!(
            verdict.action != Action::Allow,
            "quoting must not suppress a raw-IP finding"
        );
    }
}
