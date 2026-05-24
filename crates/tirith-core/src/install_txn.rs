//! Safe-install transaction analysis — the engine behind `tirith install`.
//!
//! `tirith install` is the *assembly* of existing tirith building blocks into
//! one recorded install transaction. This module is its core: it composes a
//! single explainable [`Verdict`] for a package-manager install (`npm` / `pip`
//! / `cargo`) from two already-existing engines —
//!
//!  1. the command-shape analysis ([`crate::engine::analyze`], which itself
//!     runs the install-command rules from [`crate::rules::install`], the URL
//!     rules, and the local-threat-DB package rules); and
//!  2. the deterministic package-risk scorer ([`crate::package_risk`], chunks
//!     2–3, plus the opt-in registry-API provenance signals of chunk 6).
//!
//! It does **not** re-implement either engine, and it does **not** parse the
//! command line itself — package extraction reuses
//! [`crate::rules::threatintel::extract_packages`].
//!
//! ## Honest framing
//!
//! This is **pre-execution install-risk analysis plus a recorded transaction**.
//! It is *not* a sandbox and it does not isolate or contain the install —
//! runtime sandboxing is an explicit tirith non-goal (`docs/threat-model.md`).
//! Nothing in this module — code, output, or docs — may imply otherwise. The
//! real install still runs with the user's full privileges; tirith's value is
//! that it is analyzed, surfaced, and recorded *first*.
//!
//! The URL form of `tirith install` is handled separately by the CLI: it
//! delegates wholly to [`crate::runner`], the existing safe download-and-run
//! machinery, rather than going through this module.

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::package_risk::{self, ApiSignals, ContentSignals, PackageSignals, RiskBreakdown};
use crate::policy::{FailMode, Policy};
use crate::rules::threatintel::{self, PackageRef};
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::tokenize::{self, ShellType};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Verdict};

/// Which package manager an install transaction drives.
///
/// The `url` form of `tirith install` is intentionally absent here: it is not
/// a package-manager transaction and is handled by the CLI through
/// [`crate::runner`] directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    /// `npm install <pkg...>`
    Npm,
    /// `pip install <pkg...>`
    Pip,
    /// `cargo install <pkg...>`
    Cargo,
}

impl PackageManager {
    /// The program name to invoke (argv[0] of the real install).
    pub fn program(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pip => "pip",
            PackageManager::Cargo => "cargo",
        }
    }

    /// The install subcommand for this manager (`npm install`, `pip install`,
    /// `cargo install`).
    pub fn install_subcommand(self) -> &'static str {
        // All three happen to use `install`; kept as a method so a future
        // manager with a different verb (e.g. a hypothetical `add`) is a
        // one-line change, not a scattered edit.
        "install"
    }

    /// The registry [`Ecosystem`] this manager installs from — the ecosystem
    /// the package-risk scorer is keyed on.
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            PackageManager::Npm => Ecosystem::Npm,
            PackageManager::Pip => Ecosystem::PyPI,
            PackageManager::Cargo => Ecosystem::Crates,
        }
    }

    /// Human label for output.
    pub fn label(self) -> &'static str {
        self.program()
    }
}

/// The argv of the real install command, e.g.
/// `["npm", "install", "left-pad", "--save-dev"]`.
///
/// This is what the CLI actually executes — directly via
/// `std::process::Command`, never through a shell. The same tokens, joined
/// with spaces, form the [`InstallPlan::analysis_command`] string used purely
/// for analysis and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallArgv {
    /// argv[0] — the package-manager program.
    pub program: String,
    /// argv[1..] — the install subcommand followed by the user's arguments.
    pub args: Vec<String>,
}

impl InstallArgv {
    /// The command as a single human-readable string, for display and audit.
    /// This string is **never** handed to a shell.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

/// A fully-analyzed, ready-to-run install transaction.
///
/// Produced by [`plan_install`]. The CLI inspects [`InstallPlan::verdict`] to
/// decide whether to proceed (and how), then runs [`InstallPlan::argv`].
#[derive(Debug, Clone)]
pub struct InstallPlan {
    /// The package manager being driven.
    pub manager: PackageManager,
    /// The exact argv of the real install command.
    pub argv: InstallArgv,
    /// The argv joined into a string — used for analysis and the audit log
    /// only, never executed through a shell.
    pub analysis_command: String,
    /// The packages the transaction will install, as extracted from the
    /// arguments. Empty when the user passed only flags (e.g. a bare
    /// `pip install -r requirements.txt`, where there is no package on the
    /// command line to score). Each [`PlannedPackage`] carries its own
    /// [`RiskBreakdown`] — see [`InstallPlan::risk_breakdowns`].
    pub packages: Vec<PlannedPackage>,
    /// The composed verdict: command-shape findings merged with
    /// package-risk findings, de-duplicated, action derived from the strongest.
    pub verdict: Verdict,
    /// Notes about analysis coverage (a missing threat DB, an unrecognized
    /// package spec). Surfaced so the transaction is honest about its limits.
    pub notes: Vec<String>,
}

impl InstallPlan {
    /// The per-package [`RiskBreakdown`]s, in [`InstallPlan::packages`] order.
    ///
    /// A derived view over `packages` — the breakdown is stored once, on each
    /// [`PlannedPackage`], so there is no separate `risk_breakdowns` field that
    /// could drift out of agreement with it.
    pub fn risk_breakdowns(&self) -> impl Iterator<Item = &RiskBreakdown> {
        self.packages.iter().map(|p| &p.risk)
    }
}

/// One package the install transaction will install, plus its risk breakdown.
#[derive(Debug, Clone)]
pub struct PlannedPackage {
    /// The package as extracted from the install arguments.
    pub reference: PackageRef,
    /// Its deterministic [`package_risk`] breakdown.
    pub risk: RiskBreakdown,
}

/// How the registry-API (`--online`) package signals are resolved.
///
/// Mirrors [`crate::ecosystem_scan::OnlineMode`]: the CLI supplies this so the
/// core never reaches the network or reads an environment variable itself.
pub enum OnlineMode<'a> {
    /// Offline analysis — every package's API signals are
    /// [`ApiSignals::NotComputed`].
    Off,
    /// `--online` analysis — the closure resolves each `(ecosystem, name)` to
    /// its [`ApiSignals`]. The closure must be offline-safe (degrading any
    /// failure to [`ApiSignals::Unavailable`]); it is called at most once per
    /// distinct package.
    Resolver(&'a dyn Fn(Ecosystem, &str) -> ApiSignals),
}

/// Inputs to [`plan_install`], kept in a struct so the signature stays stable.
pub struct PlanRequest<'a> {
    /// Which package manager is being driven.
    pub manager: PackageManager,
    /// The user's arguments *after* the `npm|pip|cargo` source — e.g.
    /// `["left-pad", "--save-dev"]`. The install subcommand is prepended by
    /// the planner, so a caller passes the package list and flags only.
    pub user_args: &'a [String],
    /// The loaded threat DB, or `None` when one is not installed (analysis
    /// still runs; name signals fall back to "unknown" and a note is added).
    pub db: Option<&'a ThreatDb>,
    /// The active policy — drives severity overrides and the bypass decision.
    pub policy: &'a Policy,
    /// The current working directory, for the engine's command analysis.
    pub cwd: Option<String>,
    /// Whether the run is interactive (affects only the verdict's
    /// `interactive_detected` flag — the gate is the CLI's job).
    pub interactive: bool,
    /// Registry-API resolution mode.
    pub online: OnlineMode<'a>,
}

/// The aggregate-risk score at or above which a package, on its *own risk
/// score alone* (no DB typosquat, no slopsquat shape — those are already
/// findings in their own right), warrants a blocking finding.
///
/// `package_risk::risk_level` calls 76–100 `"critical"`; a critical aggregate
/// score means several independent provenance red flags stacked up, which is a
/// block-worthy signal even without a confirmed name match.
const AGGREGATE_BLOCK_SCORE: u32 = 76;

/// The aggregate-risk score at or above which a package warrants an advisory
/// (warn) finding on its score alone. `risk_level` calls 51–75 `"high"`.
const AGGREGATE_WARN_SCORE: u32 = 51;

/// Analyze a package-manager install and produce a ready-to-run [`InstallPlan`].
///
/// This is the single entry point. It:
///  1. builds the real install argv and the analysis command string;
///  2. runs [`engine::analyze`] over that command string (command-shape,
///     URL, and local-threat-DB package findings — for free);
///  3. extracts the packages and scores each with [`package_risk`];
///  4. merges the package-risk findings into the command findings,
///     de-duplicating against the threat-DB findings the engine already
///     produced; and
///  5. derives the final [`Action`] from the strongest merged finding.
///
/// It performs **no** network I/O itself — the only networked path is the
/// caller-supplied [`OnlineMode::Resolver`] closure. It never panics.
pub fn plan_install(request: &PlanRequest) -> InstallPlan {
    let manager = request.manager;
    let argv = build_argv(manager, request.user_args);
    let analysis_command = argv.display();

    let mut notes: Vec<String> = Vec::new();
    if request.db.is_none() {
        notes.push(
            "the local threat database is not installed — popular-package and \
             typosquat signals are unavailable, so package scoring is weaker. \
             Run `tirith threat-db update` to install it."
                .to_string(),
        );
    }

    // --- (1) command-shape analysis -------------------------------------
    // Analyze the synthesized real command exactly as `tirith check` would.
    // This yields the install-command rules (unsigned repo, remote manifest,
    // ...), URL rules, and local-threat-DB package rules in one pass — we do
    // NOT call `rules::install::check` or `rules::threatintel::check`
    // directly; the engine already wires them.
    let ctx = AnalysisContext {
        input: analysis_command.clone(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: request.interactive,
        cwd: request.cwd.clone(),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
    };
    let command_verdict = engine::analyze(&ctx);
    let mut findings: Vec<Finding> = command_verdict.findings;

    // --- (2) + (3) package extraction and package-risk scoring ----------
    // Reuse the existing extractor rather than re-parsing the command line.
    let segments = tokenize::tokenize(&analysis_command, ShellType::Posix);
    let extracted = threatintel::extract_packages(&segments);

    // Keep only packages for this manager's ecosystem. `extract_packages`
    // recognizes every install command it sees; the synthesized command only
    // ever contains one, so this is belt-and-suspenders.
    let eco = manager.ecosystem();
    let mut planned: Vec<PlannedPackage> = Vec::new();

    for pkg in extracted.into_iter().filter(|p| p.ecosystem == eco) {
        let signals = gather_package_signals(request, eco, &pkg, &mut notes);
        // `score_package` itself asserts the factor-sum invariant.
        let breakdown = package_risk::score_package(&signals);

        // (4) Turn the breakdown into findings, de-duplicated against the
        // threat-DB findings the engine already produced for this package.
        for finding in risk_findings_for(&pkg, &breakdown, &findings) {
            findings.push(finding);
        }

        planned.push(PlannedPackage {
            reference: pkg,
            risk: breakdown,
        });
    }

    if planned.is_empty() {
        notes.push(format!(
            "no installable package name found on the command line for {} — \
             scoring covered the command shape only. A manifest-driven install \
             (e.g. a lockfile or requirements file) has no package argument to \
             score; run `tirith ecosystem scan` to assess a project's manifests.",
            manager.label()
        ));

        // PR #121 fix-list item 1 — close the manifest-form install bypass.
        // Previously, when `planned.is_empty()` AND the user invoked a
        // manifest-driven form (`pip install -r requirements.txt`,
        // `npm install` with no args, `cargo install --path .`, ...), the
        // analysis was complete with ZERO package-risk scoring contribution
        // and frequently exited ALLOW. Operators saw "verdict: ALLOW — no
        // supply-chain risks found" and believed tirith had analyzed their
        // manifest. It had not — `extract_packages` cannot extract names from
        // a manifest path; the manifest body would have to be parsed.
        //
        // The fix: when a manifest flag is present, emit a finding so the
        // operator sees the unanalyzed surface as an explicit gap, with a
        // pointer to `tirith ecosystem scan` (the path that DOES parse
        // manifests). Severity escalates under `fail_mode: closed` so a
        // strict-mode policy hard-blocks instead of just warning.
        if let Some(manifest_arg) = detect_manifest_flag(request.user_args) {
            let strict = matches!(request.policy.fail_mode, FailMode::Closed);
            let severity = if strict {
                Severity::High
            } else {
                Severity::Medium
            };
            let mode_note = if strict {
                "Under `fail_mode: closed` the manifest path must be analyzed before \
                 the install is allowed to proceed."
            } else {
                "Re-run `tirith ecosystem scan` against the manifest to score every \
                 declared dependency before proceeding."
            };
            let manifest_label = match &manifest_arg {
                ManifestFlag::PathArg { flag, value } => format!("{flag} {value}"),
                ManifestFlag::JoinedPath { token } => token.clone(),
                ManifestFlag::Bareword { token } => token.clone(),
                ManifestFlag::NoArgs => "(no package argument)".to_string(),
            };
            let scan_target: &str = match &manifest_arg {
                ManifestFlag::PathArg { value, .. } => value,
                ManifestFlag::JoinedPath { token } => {
                    token.split_once('=').map(|(_k, v)| v).unwrap_or(".")
                }
                ManifestFlag::Bareword { token } => token,
                ManifestFlag::NoArgs => ".",
            };
            findings.push(Finding {
                rule_id: RuleId::ThreatSuspiciousPackage,
                severity,
                title: format!(
                    "{} manifest install — package names could not be extracted \
                     from {}",
                    manager.label(),
                    manifest_label,
                ),
                description: format!(
                    "`{}` is a manifest-driven install ({}): package names could \
                     not be extracted from the manifest {}, so per-package risk \
                     scoring did NOT run. Without scoring, a malicious or \
                     typosquatted dependency declared in the manifest would not \
                     surface in this verdict. {} Run `tirith ecosystem scan {}`.",
                    analysis_command,
                    manifest_arg.describe(),
                    manifest_label,
                    mode_note,
                    scan_target,
                ),
                evidence: vec![Evidence::Text {
                    detail: format!(
                        "manager={} manifest_form={} manifest_arg={} \
                         fail_mode={}",
                        manager.label(),
                        manifest_arg.describe(),
                        manifest_label,
                        if strict { "closed" } else { "open" },
                    ),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // --- (5) compose the verdict ----------------------------------------
    // Apply policy severity overrides to the merged findings, then derive the
    // action from the strongest. `from_findings` is the same max-severity →
    // action mapping the rest of tirith uses.
    for finding in &mut findings {
        if let Some(sev) = request.policy.severity_override(&finding.rule_id) {
            finding.severity = sev;
        }
    }
    let mut verdict = Verdict::from_findings(
        findings,
        command_verdict.tier_reached,
        command_verdict.timings_ms,
    );
    verdict.interactive_detected = request.interactive;
    verdict.urls_extracted_count = command_verdict.urls_extracted_count;

    InstallPlan {
        manager,
        argv,
        analysis_command,
        packages: planned,
        verdict,
        notes,
    }
}

/// The kind of manifest-driven install flag detected on a `planned.is_empty()`
/// install command. Surfaces enough structure that a finding can carry the
/// exact manifest path / form back to the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestFlag {
    /// A flag that takes a separate-token path: `pip install -r requirements.txt`,
    /// `pip install --requirement requirements.txt`, `pip install -e .`,
    /// `cargo install --path .`, etc.
    PathArg { flag: String, value: String },
    /// A `flag=value` joined form: `pip install --requirement=requirements.txt`,
    /// `cargo install --path=.`.
    JoinedPath { token: String },
    /// A bareword that is itself a manifest reference: `pip install .`,
    /// `pip install ./subdir`, `pip install /abs/path` (pip uses a path
    /// positional to install from `pyproject.toml`).
    Bareword { token: String },
    /// `npm install` with NO user arguments (npm uses the local
    /// `package-lock.json` / `package.json` implicitly).
    NoArgs,
}

impl ManifestFlag {
    /// One-line description used in finding bodies.
    fn describe(&self) -> &'static str {
        match self {
            ManifestFlag::PathArg { .. } | ManifestFlag::JoinedPath { .. } => {
                "explicit manifest flag"
            }
            ManifestFlag::Bareword { .. } => "manifest path positional",
            ManifestFlag::NoArgs => "implicit local manifest (no args)",
        }
    }
}

/// Detect whether `user_args` represents a manifest-driven install.
///
/// The detection is conservative: only the well-known manifest forms across
/// pip / npm / cargo are recognized. A future package manager (or a flag this
/// list does not cover) returns `None` and falls through to the existing
/// "no package on the command line" note without escalating to a finding.
///
/// Forms recognized today:
///
/// * pip — `-r FILE`, `--requirement FILE`, `--requirements FILE`, `-c FILE`,
///   `--constraint FILE`, `-e PATH` (editable), `--editable PATH`,
///   `--requirement=FILE` / `--constraint=FILE` / `--editable=PATH` joined,
///   and a bareword path (`.`, `./x`, `/abs/path`).
/// * npm — install with NO user args (the default reads
///   `package.json`/`package-lock.json`).
/// * cargo — `--path PATH`, `--path=PATH`, `--git URL`, `--git=URL`.
///
/// The check runs *before* the verdict is composed — `user_args` here is the
/// caller's arguments after the `<source>` positional, i.e. exactly what the
/// install subcommand will see.
fn detect_manifest_flag(user_args: &[String]) -> Option<ManifestFlag> {
    // npm install with NO args — implicit local manifest. The same is *not*
    // true for pip / cargo: a bare `pip install` or `cargo install` is a
    // usage error (no target), so we only treat the empty-args form as
    // manifest-driven when SOME flag-or-positional is present. Empty
    // `user_args` therefore returns `NoArgs` only when the engine analyzed
    // an actual `<manager> install` invocation with no further args; the
    // CLI rejects empty args before `plan_install` is called for pip/cargo,
    // so in practice NoArgs surfaces for npm.
    if user_args.is_empty() {
        return Some(ManifestFlag::NoArgs);
    }

    // Separate-token flags (`-r FILE` / `--path PATH` / etc.).
    const SEPARATE_FLAGS: &[&str] = &[
        // pip
        "-r",
        "--requirement",
        "--requirements",
        "-c",
        "--constraint",
        "-e",
        "--editable",
        // cargo
        "--path",
        "--git",
    ];
    let mut i = 0;
    while i < user_args.len() {
        let arg = user_args[i].as_str();
        if SEPARATE_FLAGS.contains(&arg) {
            // Need a following value token. If the user wrote `pip install -r`
            // with nothing after it, that's a usage error pip itself catches;
            // we still surface the manifest-form finding with an empty value.
            let value = user_args.get(i + 1).cloned().unwrap_or_default();
            return Some(ManifestFlag::PathArg {
                flag: arg.to_string(),
                value,
            });
        }
        // Joined `flag=value` forms.
        if let Some((flag_part, _value_part)) = arg.split_once('=') {
            const JOINED_FLAGS: &[&str] = &[
                // pip
                "--requirement",
                "--requirements",
                "--constraint",
                "--editable",
                // cargo
                "--path",
                "--git",
            ];
            if JOINED_FLAGS.contains(&flag_part) {
                return Some(ManifestFlag::JoinedPath {
                    token: arg.to_string(),
                });
            }
        }
        // Bareword path positional (pip's `pip install .` form). We treat a
        // bareword as a manifest reference when it *looks* like a path
        // (starts with `.`, `/`, or `~`). A normal package name like
        // `requests` is not a manifest reference — pip parses it as a name.
        //
        // We deliberately ignore arguments that start with `-` (they're
        // flags), and we only consider a token a path-positional when it
        // STARTS with one of those characters (a bare `.` is the canonical
        // "install from this directory" pip form; `requirements.txt` alone
        // without `-r` is NOT a manifest install per pip's CLI, so we do
        // NOT treat a `.txt` suffix as a signal).
        if !arg.starts_with('-')
            && (arg == "."
                || arg == ".."
                || arg.starts_with("./")
                || arg.starts_with("../")
                || arg.starts_with('/')
                || arg.starts_with('~'))
        {
            return Some(ManifestFlag::Bareword {
                token: arg.to_string(),
            });
        }
        i += 1;
    }
    None
}

/// Build the real install argv for `manager` from the user's arguments.
///
/// The install subcommand is inserted right after argv[0]; the user's
/// arguments follow verbatim. No argument is interpreted or rewritten — they
/// are passed straight through to the package manager.
pub fn build_argv(manager: PackageManager, user_args: &[String]) -> InstallArgv {
    let mut args = Vec::with_capacity(user_args.len() + 1);
    args.push(manager.install_subcommand().to_string());
    args.extend(user_args.iter().cloned());
    InstallArgv {
        program: manager.program().to_string(),
        args,
    }
}

/// Gather the [`PackageSignals`] for one package: name signals from the threat
/// DB, content signals left un-inspected (a pre-install transaction has no
/// local package directory — tirith never downloads the package to inspect
/// it), and registry-API signals per the request's [`OnlineMode`].
fn gather_package_signals(
    request: &PlanRequest,
    eco: Ecosystem,
    pkg: &PackageRef,
    notes: &mut Vec<String>,
) -> PackageSignals {
    let db = request.db;
    let name_vs_popular = package_risk::classify_name(db, eco, &pkg.name);
    let malicious_typosquat_of = db
        .and_then(|db| db.check_typosquat(eco, &pkg.name))
        .map(|ts| ts.target_name);

    let api = match &request.online {
        OnlineMode::Off => ApiSignals::offline(),
        OnlineMode::Resolver(resolve) => {
            let signals = resolve(eco, &pkg.name);
            if let ApiSignals::Unavailable { reason } = &signals {
                notes.push(format!(
                    "registry-API provenance for '{}' was unavailable: {reason}",
                    pkg.name
                ));
            }
            signals
        }
    };

    PackageSignals {
        ecosystem: eco,
        name: pkg.name.clone(),
        threat_db_missing: db.is_none(),
        name_vs_popular,
        malicious_typosquat_of,
        // A pre-install transaction never has the package on disk yet, and
        // tirith never downloads it to peek — content signals are simply not
        // evaluated. This is not a failure and not a fetch.
        content_signals: ContentSignals::NotInspected,
        api,
    }
}

/// Turn a package's [`RiskBreakdown`] into the [`Finding`]s it warrants for the
/// install verdict — de-duplicated against `existing` (the findings the engine
/// already produced, which include the local-threat-DB package rules).
///
/// The engine's `threatintel` rules already emit
/// [`RuleId::ThreatMaliciousPackage`] / [`RuleId::ThreatPackageTyposquat`] /
/// [`RuleId::ThreatPackageSimilarName`] for a package the threat DB knows. To
/// avoid a doubled finding for the same package + rule, this function skips
/// any `(rule_id, package)` pair already present in `existing`. What it adds
/// that the engine cannot:
///
///  * a *confirmed-typosquat* finding when the package-risk DB lookup found
///    one but the engine's `threatintel` pass did not (different DB tables);
///  * an **aggregate-score** finding — when a package's deterministic risk
///    score is high/critical from *provenance* signals (package age,
///    ownership, version spike, missing source repo, yanked status — the
///    chunk-6 `--online` additions) rather than from a name match. The engine
///    has no equivalent: it does not score provenance.
fn risk_findings_for(
    pkg: &PackageRef,
    breakdown: &RiskBreakdown,
    existing: &[Finding],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let eco = pkg.ecosystem;

    // Does `existing` already carry a finding of `rule` that names this
    // package? The threatintel findings put the package name in the title and
    // description; an exact word match on the name is a safe, conservative
    // dedupe key.
    let already_has = |rule: RuleId| -> bool {
        existing
            .iter()
            .any(|f| f.rule_id == rule && finding_mentions_package(f, &pkg.name))
    };

    // --- confirmed typosquat from the package-risk DB lookup ------------
    if let Some(target) = &breakdown.malicious_typosquat_of {
        if !already_has(RuleId::ThreatPackageTyposquat)
            && !already_has(RuleId::ThreatMaliciousPackage)
        {
            out.push(Finding {
                rule_id: RuleId::ThreatPackageTyposquat,
                severity: Severity::High,
                title: format!("Confirmed typosquat: {} → {}", pkg.name, target),
                description: format!(
                    "The {eco} package '{}' is a confirmed typosquat of the popular \
                     package '{target}' (source: local threat database). Package-risk \
                     score {}/100 ({}). Installing it is high-risk.",
                    pkg.name, breakdown.score, breakdown.risk_level,
                ),
                evidence: vec![Evidence::Text {
                    detail: format!(
                        "package={} ecosystem={eco} typosquat_of={target} \
                         risk_score={}",
                        pkg.name, breakdown.score
                    ),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
        // A confirmed typosquat is the dominant signal — do not also pile on
        // an aggregate-score finding for the same package.
        return out;
    }

    // --- aggregate provenance / maintainer risk -------------------------
    // Only when the score is high/critical AND it is not already explained by
    // a name-match finding the engine produced. This is the chunk-6 value:
    // a package that is dangerous on provenance grounds, with no name tell.
    let name_match_present = already_has(RuleId::ThreatMaliciousPackage)
        || already_has(RuleId::ThreatPackageTyposquat)
        || already_has(RuleId::ThreatPackageSimilarName);

    if !name_match_present && breakdown.score >= AGGREGATE_WARN_SCORE {
        let severity = if breakdown.score >= AGGREGATE_BLOCK_SCORE {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity,
            title: format!(
                "Elevated supply-chain risk: {} package '{}' scores {}/100 ({})",
                eco, pkg.name, breakdown.score, breakdown.risk_level,
            ),
            description: format!(
                "The {eco} package '{}' has a deterministic package-risk score of \
                 {}/100 ({}), driven by provenance and maintainer signals rather \
                 than a known-bad name. Review the factor breakdown before \
                 installing — run `tirith package explain {eco} {}`.",
                pkg.name, breakdown.score, breakdown.risk_level, pkg.name,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "package={} ecosystem={eco} risk_score={} risk_level={}",
                    pkg.name, breakdown.score, breakdown.risk_level,
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    out
}

/// Whether `finding`'s title or description mentions `name` as a whole word.
///
/// Used as a conservative de-duplication key: the `threatintel` package
/// findings always embed the package name in both fields, so a whole-word
/// match reliably identifies "this finding is about this package" without the
/// false positives a substring match would give (`react` inside `react-dom`).
fn finding_mentions_package(finding: &Finding, name: &str) -> bool {
    mentions_word(&finding.title, name) || mentions_word(&finding.description, name)
}

/// Whole-package-name containment check: does `haystack` contain `word`
/// bounded, on both sides, by a character that cannot be part of a package
/// name (or by a string end)?
///
/// A package name can contain ASCII alphanumerics plus `-`, `.`, `/`, `_`,
/// `@` (npm scopes, paths). Those characters are therefore treated as
/// *name characters*: `react` must NOT match inside `react-dom` or
/// `@scope/react`. The boundary characters are everything else — whitespace,
/// quotes, parentheses, the `≈` in a similar-name title, etc.
fn mentions_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    // Characters that can legitimately be part of a package name. A match
    // flanked by one of these is a substring of a *longer* name, not a
    // reference to `word` itself.
    let is_name_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '/' | '_' | '@');
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(word) {
        let abs = start + pos;
        let before_ok = abs == 0
            || !haystack[..abs]
                .chars()
                .next_back()
                .is_some_and(is_name_char);
        let after = abs + word.len();
        let after_ok =
            after >= haystack.len() || !haystack[after..].chars().next().is_some_and(is_name_char);
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

/// Whether `verdict` permits the install to proceed without an interactive
/// acknowledgement: only an [`Action::Allow`] does.
pub fn is_clear_to_proceed(verdict: &Verdict) -> bool {
    verdict.action == Action::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_api::{FetchError, RegistryClient, RegistryMetadata};

    fn empty_policy() -> Policy {
        Policy::default()
    }

    /// A fixture-fed [`RegistryClient`] — tests never touch a real registry.
    struct FakeClient {
        result: Result<RegistryMetadata, FetchError>,
    }
    impl RegistryClient for FakeClient {
        fn fetch(&self, _eco: Ecosystem, _name: &str) -> Result<RegistryMetadata, FetchError> {
            self.result.clone()
        }
    }

    #[test]
    fn build_argv_npm_prepends_install_subcommand() {
        let argv = build_argv(
            PackageManager::Npm,
            &["left-pad".to_string(), "--save-dev".to_string()],
        );
        assert_eq!(argv.program, "npm");
        assert_eq!(argv.args, vec!["install", "left-pad", "--save-dev"]);
        assert_eq!(argv.display(), "npm install left-pad --save-dev");
    }

    #[test]
    fn build_argv_cargo_and_pip() {
        assert_eq!(
            build_argv(PackageManager::Cargo, &["ripgrep".to_string()]).display(),
            "cargo install ripgrep"
        );
        assert_eq!(
            build_argv(PackageManager::Pip, &["requests".to_string()]).display(),
            "pip install requests"
        );
    }

    #[test]
    fn package_manager_ecosystem_mapping() {
        assert_eq!(PackageManager::Npm.ecosystem(), Ecosystem::Npm);
        assert_eq!(PackageManager::Pip.ecosystem(), Ecosystem::PyPI);
        assert_eq!(PackageManager::Cargo.ecosystem(), Ecosystem::Crates);
    }

    #[test]
    fn mentions_word_is_whole_word() {
        assert!(mentions_word("Package 'react' is bad", "react"));
        assert!(!mentions_word("Package 'react-dom' is bad", "react"));
        assert!(mentions_word("install react-dom now", "react-dom"));
        assert!(!mentions_word("", "react"));
        assert!(!mentions_word("nothing here", ""));
    }

    #[test]
    fn plan_install_clean_package_allows() {
        // A package with no name tell and no threat DB → score 0 → Allow.
        let req = PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["my-unique-internal-pkg-xyzzy".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert_eq!(
            plan.argv.display(),
            "npm install my-unique-internal-pkg-xyzzy"
        );
        assert_eq!(
            plan.verdict.action,
            Action::Allow,
            "a clean offline install must Allow: {:?}",
            plan.verdict.findings
        );
        assert!(is_clear_to_proceed(&plan.verdict));
        assert_eq!(plan.packages.len(), 1);
        // No threat DB → a note must say so.
        assert!(plan.notes.iter().any(|n| n.contains("threat database")));
    }

    #[test]
    fn plan_install_no_package_argument_notes_command_only() {
        // `pip install -r requirements.txt` has no package on the command
        // line — the plan must note it scored the command shape only.
        let req = PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["-r".to_string(), "requirements.txt".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert!(plan.packages.is_empty());
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("no installable package")),
            "notes: {:?}",
            plan.notes
        );
    }

    #[test]
    fn plan_install_pip_dash_r_manifest_bypass_emits_finding() {
        // PR #121 fix-list item 1 regression pin — a `pip install -r
        // requirements.txt` invocation used to fall through to a clean ALLOW
        // because no package name could be extracted from the command line.
        // Now the manifest-form path emits a Medium finding under the default
        // `fail_mode: open` so the unanalyzed surface is visible.
        let req = PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["-r".to_string(), "requirements.txt".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert!(
            plan.packages.is_empty(),
            "no per-package scoring on a manifest install"
        );
        assert_ne!(
            plan.verdict.action,
            Action::Allow,
            "manifest-form install must NOT silently allow — verdict: {:?} \
             findings: {:?}",
            plan.verdict.action,
            plan.verdict.findings,
        );
        let manifest_findings: Vec<_> = plan
            .verdict
            .findings
            .iter()
            .filter(|f| {
                f.rule_id == RuleId::ThreatSuspiciousPackage && f.title.contains("manifest install")
            })
            .collect();
        assert_eq!(
            manifest_findings.len(),
            1,
            "expected exactly one manifest-install finding, got: {:?}",
            plan.verdict.findings,
        );
        assert_eq!(manifest_findings[0].severity, Severity::Medium);
        assert!(
            manifest_findings[0]
                .description
                .contains("tirith ecosystem scan"),
            "the manifest finding must point at ecosystem scan: {}",
            manifest_findings[0].description,
        );
    }

    #[test]
    fn plan_install_pip_dash_r_under_fail_closed_escalates_to_high() {
        // Same manifest-form bypass, but with `fail_mode: closed` — the
        // severity escalates from Medium to High so a strict-mode policy
        // hard-blocks. Action goes Warn → Block.
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let req = PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["-r".to_string(), "requirements.txt".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        let manifest_finding = plan
            .verdict
            .findings
            .iter()
            .find(|f| {
                f.rule_id == RuleId::ThreatSuspiciousPackage && f.title.contains("manifest install")
            })
            .expect("manifest-install finding must be present under fail_mode: closed");
        assert_eq!(manifest_finding.severity, Severity::High);
        assert_eq!(plan.verdict.action, Action::Block);
    }

    #[test]
    fn plan_install_pip_editable_dot_emits_finding() {
        // `pip install -e .` and `pip install .` are pip's "install from this
        // directory's pyproject.toml" forms. Same manifest-bypass surface.
        for args in [
            vec!["-e".to_string(), ".".to_string()],
            vec![".".to_string()],
            vec!["./subproject".to_string()],
            vec!["--editable=.".to_string()],
        ] {
            let req = PlanRequest {
                manager: PackageManager::Pip,
                user_args: &args,
                db: None,
                policy: &empty_policy(),
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            };
            let plan = plan_install(&req);
            assert!(
                plan.verdict
                    .findings
                    .iter()
                    .any(|f| f.title.contains("manifest install")),
                "expected manifest-install finding for `pip install {}` — got: {:?}",
                args.join(" "),
                plan.verdict.findings,
            );
        }
    }

    #[test]
    fn plan_install_npm_no_args_emits_manifest_finding() {
        // `npm install` with no further args reads the local
        // package-lock.json / package.json — a manifest-driven install with
        // no package on the command line. (The tirith CLI rejects empty args
        // for pip/cargo before this function is called, so this exercises the
        // npm-specific path.)
        let req = PlanRequest {
            manager: PackageManager::Npm,
            user_args: &[],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert!(
            plan.verdict
                .findings
                .iter()
                .any(|f| f.title.contains("manifest install")),
            "expected manifest-install finding for `npm install` with no args: {:?}",
            plan.verdict.findings,
        );
    }

    #[test]
    fn plan_install_cargo_path_manifest_emits_finding() {
        // `cargo install --path .` builds the crate at `.` rather than a
        // published name — no name extractable from the command line.
        for args in [
            vec!["--path".to_string(), ".".to_string()],
            vec!["--path=.".to_string()],
            vec![
                "--git".to_string(),
                "https://github.com/example/repo".to_string(),
            ],
        ] {
            let req = PlanRequest {
                manager: PackageManager::Cargo,
                user_args: &args,
                db: None,
                policy: &empty_policy(),
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            };
            let plan = plan_install(&req);
            assert!(
                plan.verdict
                    .findings
                    .iter()
                    .any(|f| f.title.contains("manifest install")),
                "expected manifest-install finding for `cargo install {}`: {:?}",
                args.join(" "),
                plan.verdict.findings,
            );
        }
    }

    #[test]
    fn plan_install_detect_manifest_flag_recognizes_known_forms() {
        // Direct unit test on the detector — narrow coverage so adding a new
        // flag is a one-line diff with a clear pin.
        assert!(detect_manifest_flag(&[]).is_some());
        assert!(detect_manifest_flag(&["-r".to_string(), "req.txt".to_string()]).is_some());
        assert!(detect_manifest_flag(&["--requirement=r.txt".to_string()]).is_some());
        assert!(detect_manifest_flag(&["-e".to_string(), ".".to_string()]).is_some());
        assert!(detect_manifest_flag(&[".".to_string()]).is_some());
        assert!(detect_manifest_flag(&["./foo".to_string()]).is_some());
        assert!(detect_manifest_flag(&["--path".to_string(), ".".to_string()]).is_some());
        // Normal package names are NOT manifest references.
        assert!(detect_manifest_flag(&["requests".to_string()]).is_none());
        assert!(
            detect_manifest_flag(&["left-pad".to_string(), "--save-dev".to_string()]).is_none(),
            "a package name plus an npm flag must not be a manifest install"
        );
    }

    #[test]
    fn plan_install_online_resolver_high_provenance_risk_warns() {
        // A package the (absent) threat DB does not know, but whose registry
        // provenance is alarming: brand-new, ownerless, version-spiked, no
        // source repo, yanked. That stacks to a high aggregate score with no
        // name tell — exactly the chunk-6 value the engine alone misses.
        use crate::package_risk::ApiProvenance;
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_age_days: Some(1),
            latest_version_age_days: Some(0),
            ownership_transferred: Some(true),
            version_spike: Some(true),
            recent_downloads: Some(3),
            has_source_repo: Some(false),
            yanked_or_deprecated: true,
            latest_version: Some("9.9.9".to_string()),
        };
        let resolver = |_eco: Ecosystem, _name: &str| ApiSignals::Available {
            provenance: provenance.clone(),
        };
        let req = PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["totally-unknown-pkg".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver(&resolver),
        };
        let plan = plan_install(&req);
        // The aggregate-risk finding must be present and at least Warn.
        assert!(
            plan.verdict.action == Action::Warn || plan.verdict.action == Action::Block,
            "alarming provenance must not Allow: action={:?} score={:?}",
            plan.verdict.action,
            plan.risk_breakdowns().next().map(|b| b.score),
        );
        assert!(
            plan.verdict
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::ThreatSuspiciousPackage),
            "expected an aggregate-risk finding: {:?}",
            plan.verdict.findings
        );
    }

    #[test]
    fn plan_install_online_resolver_unavailable_is_noted_and_degrades() {
        // An `--online` run whose registry call fails must degrade to the
        // offline score and add an honest note — never panic, never block on
        // the failure alone.
        let resolver = |_eco: Ecosystem, _name: &str| ApiSignals::unavailable("connection refused");
        let req = PlanRequest {
            manager: PackageManager::Cargo,
            user_args: &["some-crate".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver(&resolver),
        };
        let plan = plan_install(&req);
        assert_eq!(
            plan.verdict.action,
            Action::Allow,
            "a registry failure alone must not change the verdict"
        );
        assert!(
            plan.notes.iter().any(|n| n.contains("unavailable")),
            "notes: {:?}",
            plan.notes
        );
    }

    #[test]
    fn risk_findings_dedupe_against_existing_threatintel_finding() {
        // If the engine already emitted a ThreatPackageSimilarName for a
        // package, an aggregate-score finding for the SAME package must be
        // suppressed — no doubled finding.
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "raect".to_string(),
            version: None,
        };
        let existing = vec![Finding {
            rule_id: RuleId::ThreatPackageSimilarName,
            severity: Severity::Medium,
            title: "Package name similar to popular package: raect ≈ react".to_string(),
            description: "Package 'raect' in npm is within edit distance 1.".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        // A breakdown with a high score but NO malicious_typosquat_of.
        use crate::package_risk::NameVsPopular;
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "raect".to_string(),
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        let produced = risk_findings_for(&pkg, &breakdown, &existing);
        assert!(
            produced.is_empty(),
            "a name-match already present must suppress the aggregate finding: {produced:?}"
        );
    }

    #[test]
    fn risk_findings_typosquat_emitted_when_engine_missed_it() {
        // The package-risk DB lookup found a confirmed typosquat the engine's
        // threatintel pass did not (different tables) → emit it once.
        let pkg = PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: "reqeusts".to_string(),
            version: None,
        };
        use crate::package_risk::NameVsPopular;
        let signals = PackageSignals {
            ecosystem: Ecosystem::PyPI,
            name: "reqeusts".to_string(),
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::Unknown,
            malicious_typosquat_of: Some("requests".to_string()),
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        let produced = risk_findings_for(&pkg, &breakdown, &[]);
        assert_eq!(produced.len(), 1);
        assert_eq!(produced[0].rule_id, RuleId::ThreatPackageTyposquat);
        assert_eq!(produced[0].severity, Severity::High);
    }

    #[test]
    fn fake_registry_client_drives_resolver_without_network() {
        // Proves the resolver seam works with a fixture client — no network.
        let client = FakeClient {
            result: Ok(RegistryMetadata {
                source: "npm".to_string(),
                latest_version: Some("1.0.0".to_string()),
                ..Default::default()
            }),
        };
        let signals = crate::registry_api::gather_api_signals(&client, Ecosystem::Npm, "x");
        assert!(matches!(signals, ApiSignals::Available { .. }));
    }
}
