//! `tirith install` — the safe-install transaction.
//!
//! `tirith install <npm|pip|cargo|url> <args...>` wraps a real package install
//! with pre-execution install-risk analysis and records the transaction. The
//! M3 assembly chunk: composes existing building blocks (engine rules,
//! `package_risk` scorer, `checkpoint`, `receipt`/`runner`, `audit`), no new
//! detection.
//!
//! Flow is **analyze → inform → record → run**: score before installing
//! (block refuses, warn needs ack, allow proceeds), checkpoint + audit, then
//! invoke the real install directly (never via a shell).
//!
//! ## What this is NOT
//!
//! This is analysis + a recorded transaction. It does NOT sandbox, isolate, or
//! contain the install — runtime sandboxing is an explicit tirith non-goal (see
//! `docs/threat-model.md`); the real install runs with the user's full
//! privileges.

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

/// Which install source the `<source>` positional selects.
///
/// M6 ch1 added eight distro/docker/go backends. These have no registry adapter,
/// so `--online` provenance signals degrade to `Unavailable` ("no registry
/// adapter for <eco>"); the CLI prints a banner (and embeds it in JSON) so weak
/// coverage is never silent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallSource {
    /// `npm install <pkg...>`
    Npm,
    /// `pip install <pkg...>`
    Pip,
    /// `cargo install <pkg...>`
    Cargo,
    /// `apt-get install <pkg...>` — Debian/Ubuntu.
    Apt,
    /// `brew install <pkg...>` — Homebrew.
    Brew,
    /// `dnf install <pkg...>` — Fedora / RHEL 8+.
    Dnf,
    /// `yum install <pkg...>` — RHEL 7 and earlier.
    Yum,
    /// `pacman -S <pkg...>` — Arch / Manjaro.
    Pacman,
    /// `scoop install <pkg...>` — Windows-only at the real-run step; `--no-exec`
    /// dry-run works on every OS.
    Scoop,
    /// `docker pull <image>[:<tag>|@<digest>]` — parsed with the engine's Docker parser.
    Docker,
    /// `go install <module>[@<version>]` — version defaults to `latest`.
    Go,
    /// Download and run an install script from a URL (delegates to `tirith run`).
    Url,
}

impl InstallSource {
    /// The package-manager mapping, or `None` for [`InstallSource::Url`].
    fn package_manager(self) -> Option<PackageManager> {
        match self {
            InstallSource::Npm => Some(PackageManager::Npm),
            InstallSource::Pip => Some(PackageManager::Pip),
            InstallSource::Cargo => Some(PackageManager::Cargo),
            InstallSource::Apt => Some(PackageManager::Apt),
            InstallSource::Brew => Some(PackageManager::Brew),
            InstallSource::Dnf => Some(PackageManager::Dnf),
            InstallSource::Yum => Some(PackageManager::Yum),
            InstallSource::Pacman => Some(PackageManager::Pacman),
            InstallSource::Scoop => Some(PackageManager::Scoop),
            InstallSource::Docker => Some(PackageManager::Docker),
            InstallSource::Go => Some(PackageManager::Go),
            InstallSource::Url => None,
        }
    }
}

/// One completed install. Streaming (human) mode populates only `exit_code`;
/// capture (JSON) mode buffers `stdout`/`stderr` so the JSON envelope can embed
/// them rather than let them interleave on stdout.
#[derive(Debug, Clone, Default)]
pub struct InstallRunOutput {
    /// Process exit code (`None` on signal-termination).
    pub exit_code: Option<i32>,
    /// Captured stdout, only in capture mode.
    pub stdout: Option<String>,
    /// Captured stderr, only in capture mode.
    pub stderr: Option<String>,
}

/// Abstraction over running the real package-manager install. The production
/// impl ([`ProcessInstallRunner`]) spawns the real process; tests inject a fake
/// that never installs and never touches the network. Runs the resolved argv
/// directly, never via a shell.
///
/// Streaming inherits the terminal (live progress; captured fields `None`);
/// capture buffers stdout/stderr for `--format json`.
pub trait InstallRunner {
    /// Run `program args...`. `capture` selects streaming vs capture. A spawn
    /// failure is `Err`; the caller treats both `Err` and a `None` exit as
    /// non-success.
    fn run(
        &self,
        program: &str,
        args: &[String],
        capture: bool,
    ) -> std::io::Result<InstallRunOutput>;
}

/// Production [`InstallRunner`] — spawns the real package manager.
pub struct ProcessInstallRunner;

impl InstallRunner for ProcessInstallRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        capture: bool,
    ) -> std::io::Result<InstallRunOutput> {
        // Direct spawn — `program` is a fixed name and `args` go through argv,
        // so there is no shell and no word-splitting.
        if capture {
            // PR #121 fix-list item 3 — capture mode for `--format json` buffers
            // child stdout/stderr so they don't interleave between JSON objects
            // (which previously made the output unparseable).
            let output = Command::new(program).args(args).output()?;
            Ok(InstallRunOutput {
                exit_code: output.status.code(),
                stdout: Some(String::from_utf8_lossy(&output.stdout).into_owned()),
                stderr: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
            })
        } else {
            // Streaming (human) mode — child stdio inherits the terminal.
            let status = Command::new(program).args(args).status()?;
            Ok(InstallRunOutput {
                exit_code: status.code(),
                stdout: None,
                stderr: None,
            })
        }
    }
}

/// Entry point for `tirith install`. `source` selects the install kind; `args`
/// are the package list / flags (or the URL for the `url` form).
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
    // A tirith-owned flag placed AFTER <source> lands in the package-manager args
    // (trailing_var_arg), not parsed by tirith — a safety footgun (e.g. a
    // misplaced `--no-exec` would STILL run the real install). Guarded flags are
    // tirith-owned options no package manager interprets, so finding one trailing
    // is a hard error. `--offline`/`--format`/`--json` are NOT guarded (legitimate
    // package-manager flags).
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

// package-manager form: npm / pip / cargo

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

    // --- ANALYZE ---
    // Offline by default; `--online` opts in, `--offline` / `TIRITH_OFFLINE`
    // overrides it. The resolver degrades any registry failure to `Unavailable`.
    let use_online = online && !offline && !super::offline_env_active();
    let http_client = HttpRegistryClient::new();
    // M6 ch6 — fold `PackageExistence` into the provenance so the
    // `PackageNotFoundInRegistry` gate can read it; an `Unavailable` with a
    // positive 404 is upgraded to `Available` carrying only existence.
    let resolver = |eco: Ecosystem, name: &str| {
        let (mut signals, existence) = registry_api::gather_api_signals(&http_client, eco, name);
        use tirith_core::package_risk::{ApiProvenance, PackageExistence};
        match &mut signals {
            tirith_core::package_risk::ApiSignals::Available { provenance } => {
                provenance.package_existence = existence;
                let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
                if dc.risk {
                    provenance.dep_confusion = Some(dc);
                }
            }
            tirith_core::package_risk::ApiSignals::Unavailable { .. }
                if matches!(existence, PackageExistence::NotFound) =>
            {
                let mut prov = ApiProvenance {
                    source: eco.to_string(),
                    package_existence: PackageExistence::NotFound,
                    ..Default::default()
                };
                let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
                if dc.risk {
                    prov.dep_confusion = Some(dc);
                }
                signals = tirith_core::package_risk::ApiSignals::Available { provenance: prov };
            }
            _ => {}
        }
        signals
    };
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

    // M4 item 8 chunk 3 — stamp the caller origin before the audit write (the
    // engine doesn't know the caller's identity; the CLI does), else audit lines
    // land in the "unknown" bucket.
    plan.verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 — enforce `agent_rules.deny` on the install path, which
    // doesn't route through `post_process_verdict` (no-op on Allowed/Unspecified).
    // M4 PR #120 fix-6 (Greptile P1): mirror the bypass-skip — under `TIRITH=0`
    // the raw verdict wins and we must NOT re-Block. Pinned by
    // `install_agent_rules_deny_skipped_under_tirith_bypass_today`.
    if !plan.verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut plan.verdict, &policy);
    }

    // --- INFORM ---
    // PR #121 fix-list item 3 — JSON analysis is NOT written here; it's held so
    // analysis + outcome ship as ONE envelope `{"analysis":..,"outcome":..}`.
    // Writing it here let the child's stdout interleave between two JSON objects.
    if !json {
        print_plan_human(&plan, use_online);
    }

    // Decide the gate BEFORE the audit write so a `TIRITH=0`-bypassed BLOCK is
    // recorded as bypassed. `--no-exec` never installs (no gate); its exit still
    // mirrors the verdict (0 allow, 1 block, 2 warn) so a script can branch.
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
        decide_proceed(&plan.verdict, &policy, interactive, yes, json)
    };

    // If the gate bypassed a BLOCK via `TIRITH=0`, stamp the verdict so the audit
    // records what happened (else it logs `bypass_honored: false`).
    if matches!(decision, ProceedDecision::Go) && plan.verdict.action == Action::Block {
        plan.verdict.bypass_requested = true;
        plan.verdict.bypass_honored = true;
    }

    // Audit regardless of the decision — the analysis happened. A failed write
    // is a non-fatal notice (a record, not a gate), not silent.
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
        ProceedDecision::Stop(code) => {
            // JSON Stop path (Block refused, Warn declined, --no-exec): emit the
            // combined envelope with a no-outcome marker so it stays parseable.
            if json && !emit_combined_json(&plan, use_online, /* outcome = */ None) {
                return 1;
            }
            code
        }
        // --- RECORD then RUN ---
        ProceedDecision::Go => {
            // M6 ch1 — Scoop is Windows-only at the real-run step; refuse to
            // invoke it elsewhere (the dry-run path above runs on every OS).
            if plan.manager.is_windows_only_runtime() && !cfg!(target_os = "windows") {
                if !json {
                    eprintln!(
                        "tirith install: refusing to run '{}' — {} is Windows-only \
                         at the real-run step. Use `--no-exec` to analyze on this OS, \
                         or run the command from a Windows host.",
                        plan.analysis_command,
                        plan.manager.label(),
                    );
                } else {
                    let _ = emit_combined_json(
                        &plan,
                        use_online,
                        Some(OutcomeRecord {
                            ran: false,
                            exit_code: None,
                            checkpoint_id: None,
                            stdout: None,
                            stderr: None,
                            spawn_error: Some(format!(
                                "{} is Windows-only at the real-run step",
                                plan.manager.label()
                            )),
                        }),
                    );
                }
                return 2;
            }
            run_and_record(
                &plan,
                cwd.as_deref(),
                json,
                use_online,
                &ProcessInstallRunner,
            )
        }
    }
}

/// Outcome of the verdict gate.
enum ProceedDecision {
    /// Proceed with the install.
    Go,
    /// Do not install; exit with this code.
    Stop(i32),
}

/// Apply the verdict gate, consistent with `tirith check`: Block refuses (unless
/// policy + `TIRITH=0` bypass), Warn/WarnAck need `--yes` or an interactive `y`,
/// Allow proceeds.
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
            // Policy-gated `TIRITH=0` bypass (same as `tirith check`); a
            // non-interactive session needs the extra policy opt-in.
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
            // Interactive acknowledgement, mirroring `tirith check`.
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
/// report — the *record* and *run* steps.
///
/// The checkpoint is best-effort and NOT a sandbox / rollback — it only makes
/// the change inspectable (`tirith checkpoint diff <id>`).
fn run_and_record(
    plan: &InstallPlan,
    cwd: Option<&str>,
    json: bool,
    online: bool,
    runner: &dyn InstallRunner,
) -> i32 {
    // --- RECORD: before-install checkpoint ---
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
                    // A record, not a gate — report and continue.
                    if !json {
                        eprintln!("tirith install: checkpoint skipped (non-fatal): {e}");
                    }
                    None
                }
            }
        }
        None => None,
    };

    // --- RUN: the real install ---
    if !json {
        eprintln!("tirith install: running '{}' ...", plan.analysis_command);
    }
    // PR #121 fix-list item 3 — JSON mode CAPTURES child stdout/stderr into the
    // outcome envelope, else its progress lines break single-document parsing.
    let run_output = match runner.run(
        &plan.argv.program,
        &plan.argv.args,
        /* capture = */ json,
    ) {
        Ok(out) => out,
        Err(e) => {
            if !json {
                eprintln!("tirith install: failed to run '{}': {e}", plan.argv.program);
            } else {
                // Spawn failure still gets a single parseable envelope.
                let _ = emit_combined_json(
                    plan,
                    online,
                    Some(OutcomeRecord {
                        ran: false,
                        exit_code: None,
                        checkpoint_id: checkpoint_id.as_deref(),
                        stdout: None,
                        stderr: None,
                        spawn_error: Some(e.to_string()),
                    }),
                );
            }
            return 1;
        }
    };
    let exit_code = match run_output.exit_code {
        Some(code) => code,
        None => {
            if !json {
                eprintln!(
                    "tirith install: '{}' did not return an exit code \
                     (terminated by signal).",
                    plan.argv.program
                );
            }
            1
        }
    };

    if json {
        // PR #121 fix-list item 3 — emit ONE envelope holding analysis + outcome
        // (with captured child output embedded), so a consumer parses one document.
        let outcome = OutcomeRecord {
            ran: true,
            exit_code: Some(exit_code),
            checkpoint_id: checkpoint_id.as_deref(),
            stdout: run_output.stdout.as_deref(),
            stderr: run_output.stderr.as_deref(),
            spawn_error: None,
        };
        // A JSON-write failure must not report `0` success — surface exit 1 if the
        // envelope didn't reach the consumer (a non-zero install exit is kept).
        if !emit_combined_json(plan, online, Some(outcome)) && exit_code == 0 {
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

/// One install transaction's outcome record, for the JSON envelope (borrowed
/// fields).
struct OutcomeRecord<'a> {
    /// `true` if the runner spawned (even on non-zero/signal exit); `false` on a
    /// spawn failure (`spawn_error` set, `exit_code` `None`).
    ran: bool,
    exit_code: Option<i32>,
    checkpoint_id: Option<&'a str>,
    stdout: Option<&'a str>,
    stderr: Option<&'a str>,
    spawn_error: Option<String>,
}

/// Emit the single `{"analysis":..,"outcome":..}` JSON envelope (PR #121
/// fix-list item 3). Returns `false` on a write failure. `outcome` is `None`
/// when the install never ran (the field is still present as `null` for a
/// stable shape).
fn emit_combined_json(plan: &InstallPlan, online: bool, outcome: Option<OutcomeRecord>) -> bool {
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
    struct AnalysisEnvelope<'a> {
        kind: &'a str,
        manager: &'a str,
        command: &'a str,
        sandboxed: bool,
        online: bool,
        packages: Vec<PackageOut<'a>>,
        verdict: &'a Verdict,
        notes: &'a [String],
        // M6 ch1 — for backends with no registry adapter, embed the same banner
        // the human output shows so a JSON consumer can detect weak coverage.
        #[serde(skip_serializing_if = "Option::is_none")]
        signals_note: Option<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct OutcomeEnvelope<'a> {
        kind: &'a str,
        manager: &'a str,
        command: &'a str,
        sandboxed: bool,
        ran: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        checkpoint_id: Option<&'a str>,
        verdict_action: String,
        // Child output captured in JSON mode.
        #[serde(skip_serializing_if = "Option::is_none")]
        stdout: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stderr: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        spawn_error: Option<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct CombinedEnvelope<'a> {
        schema_version: u32,
        kind: &'a str,
        analysis: AnalysisEnvelope<'a>,
        // `null` when the install did not run; key always present for a stable shape.
        outcome: Option<OutcomeEnvelope<'a>>,
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

    // Own the banner at this scope so its borrow outlives the move into the envelope.
    let signals_banner_owned: Option<String> = if plan.manager.lacks_registry_adapter() {
        Some(plan.manager.no_registry_adapter_banner())
    } else {
        None
    };
    let analysis = AnalysisEnvelope {
        kind: "install_analysis",
        manager: plan.manager.label(),
        command: &plan.analysis_command,
        sandboxed: false,
        online,
        packages,
        verdict: &plan.verdict,
        notes: &plan.notes,
        signals_note: signals_banner_owned.as_deref(),
    };

    // Own `spawn_error` at this scope so its borrow outlives the closure below.
    let spawn_error_owned: Option<String> = outcome.as_ref().and_then(|o| o.spawn_error.clone());
    let outcome_env = outcome.map(|o| OutcomeEnvelope {
        kind: "install_outcome",
        manager: plan.manager.label(),
        command: &plan.analysis_command,
        sandboxed: false,
        ran: o.ran,
        exit_code: o.exit_code,
        checkpoint_id: o.checkpoint_id,
        verdict_action: format!("{:?}", plan.verdict.action),
        stdout: o.stdout,
        stderr: o.stderr,
        spawn_error: spawn_error_owned.as_deref(),
    });

    let combined = CombinedEnvelope {
        schema_version: 2,
        kind: "install",
        analysis,
        outcome: outcome_env,
    };

    write_json_stdout(&combined)
}

// url form — delegates to the existing `tirith run` machinery

/// The `url` form: download-and-run an install script. Does NOT re-implement
/// download/execution — delegates to [`tirith_core::runner`] (size cap, timeout,
/// SHA-256, static analysis, interpreter allowlist, [`Receipt`], confirm prompt).
/// `tirith install` adds a download-shaped preflight verdict on top (a BLOCK
/// refuses before any download); `runner::run`'s own prompt gates execution.
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
    let interactive = is_terminal::is_terminal(std::io::stderr());

    // --- ANALYZE: URL preflight ---
    // Analyze the URL as a *download* (`curl -fsSL <url>`), NOT a pipe-to-shell
    // (which would make CurlPipeShell fire on every URL). The real script body is
    // analyzed by `runner::run` after download.
    //
    // M4 PR #120 fix-6 (CodeRabbit Major TOCTOU): `preflight_url` returns BOTH the
    // verdict AND the policy snapshot it discovered, so the bypass/agent-rules/
    // audit calls below all run against the SAME snapshot (a second
    // `Policy::discover` opened a TOCTOU window).
    let (mut preflight, policy) = preflight_url(url, cwd.as_deref(), interactive);

    // M4 item 8 chunk 3 — stamp the caller origin before the audit write, else
    // audit lines land in the "unknown" bucket.
    preflight.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 — enforce `agent_rules.deny` on the URL path (no-op on
    // Allowed/Unspecified). Runs BEFORE the bypass block so a deny-forced Block
    // can still be `TIRITH=0`-bypassed. M4 PR #120 fix-6 (Greptile P1): mirror the
    // bypass-skip — under `TIRITH=0` the raw verdict wins, no re-Block. Pins:
    // `install_agent_rules_deny_skipped_under_tirith_bypass_today` (pkg) /
    // `install_url_agent_rules_deny_skipped_under_tirith_bypass_today` (url).
    if !preflight.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut preflight, &policy);
    }

    if json {
        // A JSON-write failure means the consumer never got the verdict — do not
        // then download. Exit non-zero.
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
            // Bypassed — stamp so the audit entry is honest.
            preflight.bypass_requested = true;
            preflight.bypass_honored = true;
            false
        } else {
            true
        }
    } else {
        false
    };

    // A failed audit write is a non-fatal notice (the transaction proceeds).
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

    // `runner::run`'s own confirmation prompt is the acknowledgement; no second
    // prompt here.
    if preflight.action != Action::Allow && !json {
        eprintln!(
            "tirith install: URL preflight raised {} finding(s) — the script \
             body will be analyzed and you will be asked to confirm before it runs.",
            preflight.findings.len()
        );
    }

    // --- RECORD + RUN: delegate to the safe runner ---
    // `runner::run` re-analyzes the downloaded script, writes a Receipt, and
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
            // A JSON-write failure must not report `0` success — surface exit 1 if
            // the outcome didn't reach the consumer (a non-zero script exit is kept).
            if !json_ok && outcome_code == 0 {
                1
            } else {
                outcome_code
            }
        }
        Err(e) => {
            if json {
                // Via `write_json_stdout` so the trailing newline is a fallible
                // write (no broken-pipe panic).
                let _ = write_json_stdout(&serde_json::json!({ "error": e }));
            } else {
                eprintln!("tirith install: {e}");
            }
            1
        }
    }
}

/// On non-Unix the `url` form is unavailable (the safe runner is Unix-only);
/// npm/pip/cargo still work.
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

/// Single-quote a value for a synthesized POSIX shell command so it is analyzed
/// as one argument (embedded `'` → `'\''`); else a URL with `&`/`;`/backtick/
/// space would tokenize as shell syntax and produce spurious findings.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Analyze a URL as a download (not a pipe-to-shell) and return the verdict.
/// Unit-testable without the network — offline `engine::analyze`, no fetch.
fn preflight_url(url: &str, cwd: Option<&str>, interactive: bool) -> (Verdict, Policy) {
    let ctx = AnalysisContext {
        // Download shape so a legitimate installer URL doesn't trip the
        // pipe-to-shell rule; single-quoted so shell metacharacters in the URL
        // are one argument, not syntax. The body is analyzed by the runner later.
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
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    // M4 PR #120 fix-6 (CodeRabbit Major TOCTOU): return the engine-discovered
    // policy so the caller's bypass/agent-rules/audit calls share one snapshot.
    engine::analyze_returning_policy(&ctx)
}

// output

/// A short, well-known example package per manager, for the usage hint.
fn example_package(manager: PackageManager) -> &'static str {
    match manager {
        PackageManager::Npm => "left-pad",
        PackageManager::Pip => "requests",
        PackageManager::Cargo => "ripgrep",
        PackageManager::Apt => "nginx",
        PackageManager::Brew => "ripgrep",
        PackageManager::Dnf => "httpd",
        PackageManager::Yum => "httpd",
        PackageManager::Pacman => "firefox",
        PackageManager::Scoop => "neovim",
        PackageManager::Docker => "alpine:latest",
        PackageManager::Go => "github.com/spf13/cobra@latest",
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
    // M6 ch1 — surface the weak-signals banner up front for adapter-less backends
    // (same string the JSON envelope embeds).
    if plan.manager.lacks_registry_adapter() {
        eprintln!("  {}", plan.manager.no_registry_adapter_banner());
    }
    eprintln!();

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

/// Write `value` as pretty JSON to stdout, returning `false` on a write failure
/// so the caller can exit non-zero. Thin wrapper over [`super::write_json_stdout`]
/// with the `tirith install` error prefix.
fn write_json_stdout<T: serde::Serialize>(value: &T) -> bool {
    super::write_json_stdout(value, "tirith install: failed to write JSON output")
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

/// Render the URL-form preflight verdict (JSON). `false` on a write failure.
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

/// JSON record of the completed URL transaction. `false` on a write failure.
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

    /// A fake [`InstallRunner`] — records the argv and returns a canned exit code,
    /// never spawning a process (installs nothing, no network).
    struct FakeRunner {
        exit_code: Option<i32>,
        /// Canned stdout/stderr for capture-mode tests.
        stdout: Option<String>,
        stderr: Option<String>,
        seen: Mutex<Vec<(String, Vec<String>, bool)>>,
    }
    impl FakeRunner {
        fn new(exit_code: Option<i32>) -> Self {
            Self {
                exit_code,
                stdout: None,
                stderr: None,
                seen: Mutex::new(Vec::new()),
            }
        }
        fn with_capture(mut self, stdout: &str, stderr: &str) -> Self {
            self.stdout = Some(stdout.to_string());
            self.stderr = Some(stderr.to_string());
            self
        }
    }
    impl InstallRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            capture: bool,
        ) -> std::io::Result<InstallRunOutput> {
            self.seen
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec(), capture));
            Ok(InstallRunOutput {
                exit_code: self.exit_code,
                stdout: if capture { self.stdout.clone() } else { None },
                stderr: if capture { self.stderr.clone() } else { None },
            })
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
        // M6 ch1 — the 8 new backends map one-to-one onto `PackageManager`.
        assert_eq!(
            InstallSource::Apt.package_manager(),
            Some(PackageManager::Apt)
        );
        assert_eq!(
            InstallSource::Brew.package_manager(),
            Some(PackageManager::Brew)
        );
        assert_eq!(
            InstallSource::Dnf.package_manager(),
            Some(PackageManager::Dnf)
        );
        assert_eq!(
            InstallSource::Yum.package_manager(),
            Some(PackageManager::Yum)
        );
        assert_eq!(
            InstallSource::Pacman.package_manager(),
            Some(PackageManager::Pacman)
        );
        assert_eq!(
            InstallSource::Scoop.package_manager(),
            Some(PackageManager::Scoop)
        );
        assert_eq!(
            InstallSource::Docker.package_manager(),
            Some(PackageManager::Docker)
        );
        assert_eq!(
            InstallSource::Go.package_manager(),
            Some(PackageManager::Go)
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
        // cwd=None so no checkpoint (hermetic); json=true exercises the capture path.
        let code = run_and_record(&plan, None, true, false, &runner);
        assert_eq!(code, 0);
        let seen = runner.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the runner must be called exactly once");
        assert_eq!(seen[0].0, "npm");
        assert_eq!(seen[0].1, vec!["install", "my-pkg"]);
        assert!(
            seen[0].2,
            "JSON mode must request capture so child output is embedded"
        );
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
        let code = run_and_record(&plan, None, true, false, &runner);
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
        let code = run_and_record(&plan, None, true, false, &runner);
        assert_eq!(code, 1);
    }

    #[test]
    fn json_mode_emits_single_parseable_envelope() {
        // PR #121 fix-list item 3 regression pin — JSON mode must request capture
        // so child output lands INSIDE the single envelope. We can't observe
        // stdout cleanly here, so we assert the runner is called with capture=true.
        let req_args = vec!["clean-pkg".to_string()];
        let argv = install_txn::build_argv(PackageManager::Pip, &req_args);
        let plan = InstallPlan {
            manager: PackageManager::Pip,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
        };
        let runner = FakeRunner::new(Some(0))
            .with_capture("installing clean-pkg\nDone.\n", "warning: deprecated\n");
        let _code = run_and_record(&plan, None, /* json = */ true, false, &runner);
        let seen = runner.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].2,
            "JSON mode must request capture; saw capture={}",
            seen[0].2,
        );
    }

    #[test]
    fn detect_manifest_flag_helper_is_internal() {
        // CLI-side smoke that the core's manifest detector fires through
        // `plan_install`; real coverage lives in `tirith-core::install_txn::tests`.
        let req = tirith_core::install_txn::PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["-r".to_string(), "requirements.txt".to_string()],
            db: None,
            policy: &Policy::default(),
            cwd: None,
            interactive: false,
            online: tirith_core::install_txn::OnlineMode::Off,
        };
        let plan = tirith_core::install_txn::plan_install(&req);
        assert!(
            plan.verdict
                .findings
                .iter()
                .any(|f| f.title.contains("manifest install")),
            "the manifest-bypass finding must surface from the CLI's plan_install \
             call too: {:?}",
            plan.verdict.findings,
        );
    }

    #[test]
    fn preflight_url_plain_installer_does_not_block() {
        // A plain https installer URL, analyzed as a download, must not block.
        let (verdict, _policy) =
            preflight_url("https://get.example-tool.sh/install.sh", None, false);
        assert_ne!(
            verdict.action,
            Action::Block,
            "a download-shaped preflight must not block a plain installer URL: {:?}",
            verdict.findings,
        );
    }

    #[test]
    fn preflight_url_raw_ip_is_flagged() {
        // A raw-IP URL is suspicious; the preflight should surface it (raw_ip_url).
        let (verdict, _policy) = preflight_url("http://203.0.113.5/install.sh", None, false);
        assert!(
            verdict.action != Action::Allow,
            "a raw-IP install URL should raise at least one finding"
        );
    }

    #[test]
    fn shell_single_quote_escapes_metacharacters() {
        // CR10: a URL with shell metacharacters becomes one quoted token.
        assert_eq!(
            shell_single_quote("https://x.example/a?b=1&c=2"),
            "'https://x.example/a?b=1&c=2'"
        );
        // An embedded single quote is closed/escaped/reopened.
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn preflight_url_with_shell_metacharacters_no_spurious_findings() {
        // CR10: a benign URL with `&`/`;`/space must not produce shell-syntax
        // findings once quoted into `curl -fsSL '<url>'`.
        let url = "https://get.example-tool.sh/install.sh?ref=a&v=1;x y";
        let (verdict, _policy) = preflight_url(url, None, false);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "a quoted benign installer URL must not raise shell-syntax findings: {:?}",
            verdict.findings,
        );
    }

    #[test]
    fn preflight_url_quoting_preserves_real_detection() {
        // Quoting must not hide a raw-IP URL that also carries shell metacharacters.
        let (verdict, _policy) =
            preflight_url("http://203.0.113.5/install.sh?a=1&b=2", None, false);
        assert!(
            verdict.action != Action::Allow,
            "quoting must not suppress a raw-IP finding"
        );
    }
}
