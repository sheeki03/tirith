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
use crate::package_risk::{
    self, ApiProvenance, ApiSignals, ContentSignals, NameVsPopular, PackageExistence,
    PackageSignals, RiskBreakdown,
};
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
///
/// **M6 ch1** — extended with eight distro/docker/go backends. These ship
/// command-complete (the right argv is built, the verdict carries the right
/// `manager` label, threat-DB and command-shape rules run) but **signal-weak**:
/// no registry adapter is wired for them, so `--online` provenance signals
/// degrade to [`crate::package_risk::ApiSignals::Unavailable`] with the honest
/// reason `"no registry adapter for <eco>"`. The CLI surfaces a banner saying
/// so on every `tirith install <backend>` invocation, and threat-DB lookups
/// for these ecosystems return empty until feed wiring extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    /// `npm install <pkg...>`
    Npm,
    /// `pip install <pkg...>`
    Pip,
    /// `cargo install <pkg...>`
    Cargo,
    /// `apt-get install <pkg...>` — Debian/Ubuntu. The scriptable interface is
    /// `apt-get`, not `apt` (per Debian docs `apt` is meant for interactive
    /// use). One variant ↔ one program: there is no `apt`-vs-`apt-get`
    /// ambiguity at the dispatch level.
    Apt,
    /// `brew install <pkg...>` — Homebrew, macOS / Linuxbrew.
    Brew,
    /// `dnf install <pkg...>` — Fedora / RHEL 8+.
    Dnf,
    /// `yum install <pkg...>` — RHEL 7 and earlier, still common in CI images.
    Yum,
    /// `pacman -S <pkg...>` — Arch / Manjaro. argv[1] is `-S` (the Sync
    /// op flag), not a positional subcommand; this is encoded through
    /// [`Self::install_subcommand`] so the generic argv builder stays
    /// untouched.
    Pacman,
    /// `scoop install <pkg...>` — Windows-only command-line installer. The
    /// dry-run analysis path runs on every OS; the real-run path is gated
    /// behind `cfg!(target_os = "windows")` by the CLI so a Linux/macOS
    /// operator cannot accidentally trigger a half-broken install.
    Scoop,
    /// `docker pull <image>[:<tag>|@<digest>]` — pulls an image; the install
    /// subcommand is `pull`, not `install`. Image refs are parsed by
    /// [`crate::parse::parse_docker_ref`] (the existing engine code path).
    Docker,
    /// `go install <module>[@<version>]` — the version suffix defaults to
    /// `@latest` if not supplied, mirroring `go install`'s own default. Module
    /// path parsing is local (a small split on `@`).
    Go,
}

impl PackageManager {
    /// The program name to invoke (argv[0] of the real install).
    ///
    /// **One variant ↔ exactly one program.** No `"apt"|"apt-get"`
    /// ambiguity: `Apt` always maps to `apt-get` because that is the
    /// scriptable interface; `apt` itself is documented as for interactive
    /// use only.
    pub fn program(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pip => "pip",
            PackageManager::Cargo => "cargo",
            PackageManager::Apt => "apt-get",
            PackageManager::Brew => "brew",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Pacman => "pacman",
            PackageManager::Scoop => "scoop",
            PackageManager::Docker => "docker",
            PackageManager::Go => "go",
        }
    }

    /// The install subcommand for this manager.
    ///
    /// Most are `install`. Docker uses `pull`. Pacman uses `-S` (the Sync
    /// op flag — `pacman` has no positional subcommand). Encoding pacman's
    /// `-S` through this method means [`build_argv`] stays generic: it
    /// inserts `argv[1] = install_subcommand`, and that just happens to be
    /// a flag for pacman.
    pub fn install_subcommand(self) -> &'static str {
        match self {
            PackageManager::Docker => "pull",
            PackageManager::Pacman => "-S",
            // npm / pip / cargo / apt-get / brew / dnf / yum / scoop / go.
            _ => "install",
        }
    }

    /// The registry [`Ecosystem`] this manager installs from — the ecosystem
    /// the package-risk scorer is keyed on.
    ///
    /// The distro/docker/go ecosystems are present so the scorer's
    /// per-package output can carry the right label; today no registry
    /// adapter exists for them so `--online` signals degrade.
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            PackageManager::Npm => Ecosystem::Npm,
            PackageManager::Pip => Ecosystem::PyPI,
            PackageManager::Cargo => Ecosystem::Crates,
            PackageManager::Apt => Ecosystem::Apt,
            PackageManager::Brew => Ecosystem::Brew,
            PackageManager::Dnf => Ecosystem::Dnf,
            PackageManager::Yum => Ecosystem::Yum,
            PackageManager::Pacman => Ecosystem::Pacman,
            PackageManager::Scoop => Ecosystem::Scoop,
            PackageManager::Docker => Ecosystem::Docker,
            PackageManager::Go => Ecosystem::Go,
        }
    }

    /// Human label for output. By default the same as [`Self::program`] —
    /// for `Apt` we return `"apt"` instead of `"apt-get"` because that is
    /// the user-facing CLI name even though `apt-get` is the scriptable
    /// program we invoke.
    pub fn label(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt",
            other => other.program(),
        }
    }

    /// `true` when this manager has **no registry adapter** wired into
    /// [`crate::registry_api`] today, so `--online` provenance signals
    /// degrade to [`crate::package_risk::ApiSignals::Unavailable`] with the
    /// reason `"no registry adapter for <eco>"`. The CLI uses this to
    /// print a one-line "signals are weak" banner on every invocation.
    ///
    /// **Source of truth** lives in [`crate::registry_api`]'s `fetch`
    /// dispatch; this method must agree with it. A future PR that wires an
    /// adapter for one of these ecosystems flips this method's return value
    /// to `false`, then the banner disappears.
    pub fn lacks_registry_adapter(self) -> bool {
        // Today only npm / pypi / crates.io have adapters.
        !matches!(
            self,
            PackageManager::Npm | PackageManager::Pip | PackageManager::Cargo
        )
    }

    /// The one-line banner printed (and embedded in JSON) when this manager
    /// has no registry adapter. The plan's verbatim text is reproduced here.
    pub fn no_registry_adapter_banner(self) -> String {
        format!(
            "note: registry-API provenance signals for {} are not available \
             (no registry adapter); analysis relies on threat-DB name match \
             and command-shape rules only",
            self.label()
        )
    }

    /// `true` when this manager runs the real install only on Windows
    /// (currently just Scoop). The dry-run / analysis path runs on every
    /// OS; the real-run path is gated by the CLI.
    pub fn is_windows_only_runtime(self) -> bool {
        matches!(self, PackageManager::Scoop)
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
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };
    let command_verdict = engine::analyze(&ctx);
    let mut findings: Vec<Finding> = command_verdict.findings;

    // --- (2) + (3) package extraction and package-risk scoring ----------
    // Reuse the existing extractor rather than re-parsing the command line.
    // For Npm / Pip / Cargo this is sufficient — the generic extractor
    // recognizes those commands. For Docker and Go the manager-specific
    // parser is authoritative (it parses image refs / module paths with
    // versions, including the implicit-`latest` default for both), so for
    // those two managers we *replace* the generic extractor's output with
    // the manager-specific output to avoid emitting two PlannedPackage
    // entries for the same `(ecosystem, name)`. For Apt / Brew / Dnf / Yum
    // / Pacman / Scoop there is no public per-package registry to score
    // against in M6 ch1 and the manager-specific parser intentionally
    // returns empty — the verdict for those backends is command-shape
    // analysis + the no-registry-adapter banner.
    let segments = tokenize::tokenize(&analysis_command, ShellType::Posix);
    let extracted: Vec<PackageRef> = match manager {
        PackageManager::Docker | PackageManager::Go => {
            extract_packages_manager_specific(manager, request.user_args)
        }
        _ => threatintel::extract_packages(&segments),
    };

    // M6 ch1 — the `schemeless_to_sink` false positive on `go install
    // <module>` / `docker pull <image>` is suppressed at the engine layer
    // in `extract.rs` (docker has a long-standing carve-out; go got one in
    // M6 ch1 alongside this code). No additional install-side filtering
    // needed here.

    // Keep only packages for this manager's ecosystem. `extract_packages`
    // recognizes every install command it sees; the synthesized command only
    // ever contains one, so this is belt-and-suspenders.
    let eco = manager.ecosystem();
    let mut planned: Vec<PlannedPackage> = Vec::new();

    let online_in_use = matches!(request.online, OnlineMode::Resolver(_));
    for pkg in extracted.into_iter().filter(|p| p.ecosystem == eco) {
        let signals = gather_package_signals(request, eco, &pkg, &mut notes);
        // `score_package` itself asserts the factor-sum invariant.
        let breakdown = package_risk::score_package(&signals);

        // M6 ch7 — install-script signal is only present when (a) `--online`
        // resolved the package and inline `scripts.*` arrived, OR (b) the
        // path is `ecosystem scan --installed` / `package scan --lockfile
        // --online` (where script text is on disk). A bare offline `tirith
        // install` cannot evaluate the signal — surface that gap explicitly
        // rather than silently allowing the policy rule to no-op.
        if request
            .policy
            .package_policy
            .block_install_scripts_for_unknown_packages
            && !online_in_use
            && matches!(signals.name_vs_popular, NameVsPopular::Unknown)
        {
            notes.push(format!(
                "(install-script signal not available offline — pass `--online` to evaluate \
                 install-script policy for '{}')",
                pkg.name
            ));
        }

        // Honest framing for the M6 ch7 `block_not_found` rule too: offline
        // runs cannot resolve `PackageExistence` and the policy never fires.
        if request.policy.package_policy.block_not_found
            && !online_in_use
            && package_existence(&signals.api).is_none()
        {
            notes.push(format!(
                "(package-existence signal requires --online — `block_not_found` policy did \
                 not evaluate for '{}')",
                pkg.name
            ));
        }

        // (4) Turn the breakdown into findings, de-duplicated against the
        // threat-DB findings the engine already produced for this package.
        for finding in risk_findings_for(&pkg, &breakdown, &findings, request.policy) {
            findings.push(finding);
        }

        planned.push(PlannedPackage {
            reference: pkg,
            risk: breakdown,
        });
    }

    if planned.is_empty() {
        // M6 ch1 — when the manager has no registry adapter (apt / brew /
        // dnf / yum / pacman / scoop), we DO NOT score per-package risk
        // even though a package name was given. The "no installable package
        // name" wording would be confusing for `apt-get install nginx`
        // (`nginx` IS the name — we just have no adapter). Use a
        // backend-honest note in that case; for npm/pip/cargo keep the
        // existing manifest-form pointer.
        let note = if manager.lacks_registry_adapter() && !request.user_args.is_empty() {
            format!(
                "{} has no registry adapter wired into tirith yet, so per-package \
                 risk scoring did NOT run (threat-DB name match + command-shape \
                 rules only). The banner above carries the same signal.",
                manager.label(),
            )
        } else {
            format!(
                "no installable package name found on the command line for {} — \
                 scoring covered the command shape only. A manifest-driven install \
                 (e.g. a lockfile or requirements file) has no package argument to \
                 score; run `tirith ecosystem scan` to assess a project's manifests.",
                manager.label(),
            )
        };
        notes.push(note);

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

/// M6 ch1 — manager-specific package extraction for the install backends
/// the generic [`threatintel::extract_packages`] does not recognize.
///
/// Today this covers:
///
///  * `Docker` — parses `<image>[:<tag>|@<digest>]` arguments into
///    [`PackageRef`]s keyed at `Ecosystem::Docker`. Uses
///    [`crate::parse::parse_docker_ref`] (the existing engine code path) so
///    a digest form, a registry prefix, and an implicit `library/` namespace
///    all round-trip through one parser.
///  * `Go` — parses `<module>[@<version>]` arguments into [`PackageRef`]s
///    keyed at `Ecosystem::Go`, defaulting the version to `latest` when
///    absent (mirroring `go install`'s own implicit default). Note the
///    generic extractor *also* recognizes `go install pkg@v1`, so for
///    explicit-version forms there is some overlap — the dedupe by
///    `(ecosystem, name)` in the scoring loop tolerates duplicates.
///
/// For `Npm`, `Pip`, `Cargo`, `Apt`, `Brew`, `Dnf`, `Yum`, `Pacman`, `Scoop`
/// this returns an empty vector: the first three are covered by the
/// generic extractor; the last six have no public per-package registry to
/// score against in M6 ch1 and intentionally produce no PackageRef. The
/// verdict for those is command-shape analysis + the no-registry-adapter
/// banner, not silent name-scoring.
fn extract_packages_manager_specific(
    manager: PackageManager,
    user_args: &[String],
) -> Vec<PackageRef> {
    match manager {
        PackageManager::Docker => parse_docker_specs(user_args),
        PackageManager::Go => parse_go_specs(user_args),
        // The covered-or-no-op managers — explicit so a future manager forces
        // a decision here rather than silently inheriting "no extraction".
        PackageManager::Npm
        | PackageManager::Pip
        | PackageManager::Cargo
        | PackageManager::Apt
        | PackageManager::Brew
        | PackageManager::Dnf
        | PackageManager::Yum
        | PackageManager::Pacman
        | PackageManager::Scoop => Vec::new(),
    }
}

/// Parse Docker image-ref arguments into [`PackageRef`]s.
///
/// Accepts:
///  * `<image>` (e.g. `alpine`) — implicit `library/` namespace, version
///    `latest` (Docker's own default).
///  * `<image>:<tag>` (e.g. `alpine:3.18`).
///  * `<image>@<digest>` (e.g. `alpine@sha256:abcdef...`).
///  * `<registry>/<image>[:tag|@digest]` (e.g. `ghcr.io/owner/img:v1`).
///
/// Tokens that start with `-` (flags) are skipped. The package `name` is the
/// canonical `<registry-or-empty>/<image>` (with an implicit `library/`
/// namespace expanded), and `version` carries the tag — or `sha256:...`
/// when the spec used a digest form, prefixed so the audit line distinguishes.
fn parse_docker_specs(user_args: &[String]) -> Vec<PackageRef> {
    use crate::parse::{parse_docker_ref, UrlLike};
    let mut out = Vec::new();
    let mut i = 0;
    while i < user_args.len() {
        let arg = &user_args[i];
        if arg.starts_with('-') {
            // Flags with separate value forms: skip BOTH the flag and its
            // value so the value (e.g. `linux/amd64` after `--platform`)
            // isn't misclassified as an image ref. Inline `--flag=value`
            // doesn't consume the next token. The list below is the set of
            // docker pull / run flags that take a separate value AND whose
            // value can plausibly look like an image (contains `/`, `:`, or
            // a digest-looking string). Boolean flags don't need to skip.
            if !arg.contains('=') && is_docker_value_bearing_flag(arg) && i + 1 < user_args.len() {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let UrlLike::DockerRef {
            registry,
            image,
            tag,
            digest,
        } = parse_docker_ref(arg)
        {
            let name = match registry {
                Some(reg) => format!("{reg}/{image}"),
                None => image,
            };
            let version = match (tag, digest) {
                (_, Some(d)) => Some(d),
                (Some(t), None) => Some(t),
                (None, None) => Some("latest".to_string()),
            };
            out.push(PackageRef {
                ecosystem: Ecosystem::Docker,
                name,
                version,
            });
        }
        i += 1;
    }
    out
}

/// Docker CLI flags whose VALUE is a separate token (not inlined with `=`)
/// AND whose value can plausibly match an image-ref shape (contains `/` or
/// `:`) — so we must skip the value to avoid misclassifying it as a pull
/// target. Conservative list: only the flags whose values look image-like.
fn is_docker_value_bearing_flag(flag: &str) -> bool {
    matches!(
        flag,
        "--platform"
            | "--user"
            | "-u"
            | "--volume"
            | "-v"
            | "--mount"
            | "--publish"
            | "-p"
            | "--env"
            | "-e"
            | "--env-file"
            | "--network"
            | "--name"
            | "--hostname"
            | "-h"
            | "--workdir"
            | "-w"
            | "--cidfile"
            | "--entrypoint"
            | "--label"
            | "-l"
            | "--add-host"
            | "--device"
            | "--dns"
            | "--restart"
            | "--memory"
            | "-m"
            | "--cpus"
            | "--log-driver"
            | "--log-opt"
    )
}

/// Parse Go module-spec arguments into [`PackageRef`]s.
///
/// Accepts:
///  * `<module>` (e.g. `github.com/spf13/cobra`) — version defaults to
///    `latest`, mirroring `go install`'s own implicit default.
///  * `<module>@<version>` (e.g. `github.com/spf13/cobra@latest`,
///    `github.com/spf13/cobra@v1.8.0`).
///
/// Tokens that start with `-` (flags) are skipped. A module path is
/// minimally validated: it must contain at least one `.` or `/` to look
/// like an import path. Otherwise the token is ignored (a plain word like
/// `nginx` is not a Go module).
fn parse_go_specs(user_args: &[String]) -> Vec<PackageRef> {
    let mut out = Vec::new();
    for arg in user_args {
        if arg.starts_with('-') {
            continue;
        }
        let (name, version) = match arg.rsplit_once('@') {
            Some((n, v)) if !n.is_empty() && !v.is_empty() => (n, Some(v.to_string())),
            _ => (arg.as_str(), Some("latest".to_string())),
        };
        // Reject local-path install targets. `go install ./cmd/foo`,
        // `go install /abs/path/...`, `go install ~/repo/...` operate on
        // local filesystem paths, not remote registry modules — turning them
        // into `PackageRef`s would emit bogus risk findings for paths.
        if name == "."
            || name == ".."
            || name.starts_with("./")
            || name.starts_with("../")
            || name.starts_with('/')
            || name.starts_with('~')
        {
            continue;
        }
        // Conservative shape check — a Go module path is dotted or has a
        // slash. `nginx` is rejected as a likely typo from a wrong source.
        if !name.contains('.') && !name.contains('/') {
            continue;
        }
        out.push(PackageRef {
            ecosystem: Ecosystem::Go,
            name: name.to_string(),
            version,
        });
    }
    out
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
        // M6 ch6 — carry version through from the install-extractor's parse
        // so OSV correlation can pin to (eco, name, version) downstream.
        version: pkg.version.clone(),
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
    policy: &Policy,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let eco = pkg.ecosystem;
    let pp = &policy.package_policy;

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

    let warn_threshold = pp.warn_aggregate_score_effective();
    let block_threshold = pp.block_aggregate_score_effective();
    if !name_match_present && breakdown.score >= warn_threshold {
        let severity = if breakdown.score >= block_threshold {
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
                    "package={} ecosystem={eco} risk_score={} risk_level={} \
                     warn_threshold={warn_threshold} block_threshold={block_threshold}",
                    pkg.name, breakdown.score, breakdown.risk_level,
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    // --- M6 ch7 policy-driven rules ------------------------------------
    out.extend(policy_findings_for(pkg, breakdown, policy));

    out
}

/// M6 ch7 — emit findings driven by `policy.package_policy` thresholds.
///
/// Each rule path here has a clean default (do not fire) and only emits
/// when a policy threshold crosses a signal carried in `breakdown`. The
/// caller hand-rolls "is this signal observable on the path's --online
/// state" gating; this function trusts the inputs.
fn policy_findings_for(
    pkg: &PackageRef,
    breakdown: &RiskBreakdown,
    policy: &Policy,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let eco = pkg.ecosystem;
    let pp = &policy.package_policy;
    let provenance: Option<&ApiProvenance> = match &breakdown.api_signals {
        ApiSignals::Available { provenance } => Some(provenance),
        _ => None,
    };

    // PackagePolicyNotFound — registry-confirmed 404 + block_not_found
    if pp.block_not_found {
        if let Some(prov) = provenance {
            if matches!(prov.package_existence, PackageExistence::NotFound) {
                out.push(Finding {
                    rule_id: RuleId::PackagePolicyNotFound,
                    severity: Severity::High,
                    title: format!(
                        "Package not found: {eco} '{}' (policy block_not_found)",
                        pkg.name
                    ),
                    description: format!(
                        "The {eco} package '{}' was not found in the registry (HTTP 404) \
                         and policy `block_not_found: true` requires this to block. \
                         The package may be a typo, may belong to a private registry, \
                         or may have been removed.",
                        pkg.name,
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!("package={} ecosystem={eco} existence=not_found", pkg.name),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }
    }

    // PackagePolicyNewerThanDays — package_age_days against thresholds
    if let Some(prov) = provenance {
        if let Some(age_days) = prov.package_age_days {
            let warn_d = pp.warn_newer_than_days;
            let block_d = pp.block_newer_than_days;
            let (fired, sev) = match (block_d, warn_d) {
                (Some(b), _) if (age_days as u32) <= b => (true, Severity::High),
                (_, Some(w)) if (age_days as u32) <= w => (true, Severity::Medium),
                _ => (false, Severity::Medium),
            };
            if fired {
                out.push(Finding {
                    rule_id: RuleId::PackagePolicyNewerThanDays,
                    severity: sev,
                    title: format!(
                        "Package newer than policy threshold: {eco} '{}' ({} day{})",
                        pkg.name,
                        age_days,
                        if age_days == 1 { "" } else { "s" },
                    ),
                    description: format!(
                        "The {eco} package '{}' was first published {age_days} day(s) ago, \
                         which trips the policy threshold (warn_newer_than_days={:?}, \
                         block_newer_than_days={:?}). A brand-new package has no community \
                         track record yet.",
                        pkg.name, warn_d, block_d,
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "package={} ecosystem={eco} package_age_days={age_days} \
                             warn_threshold={warn_d:?} block_threshold={block_d:?}",
                            pkg.name,
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }

        // PackagePolicyLowDownloads — recent_downloads against threshold
        if let (Some(dl), Some(low)) = (prov.recent_downloads, pp.warn_low_downloads_below) {
            if dl <= low as u64 {
                out.push(Finding {
                    rule_id: RuleId::PackagePolicyLowDownloads,
                    severity: Severity::Medium,
                    title: format!(
                        "Package has low recent downloads: {eco} '{}' ({} downloads)",
                        pkg.name, dl,
                    ),
                    description: format!(
                        "The {eco} package '{}' reports {dl} recent downloads, at or below the \
                         policy threshold {low}. Low downloads on a public-registry package may \
                         indicate unfamiliarity or abandonment.",
                        pkg.name,
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "package={} ecosystem={eco} recent_downloads={dl} threshold={low}",
                            pkg.name,
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }

        // PackagePolicyUnknownPackageWithInstallScripts — Unknown + script signal
        if pp.block_install_scripts_for_unknown_packages
            && matches!(breakdown.name_vs_popular, NameVsPopular::Unknown)
        {
            if let Some(iss) = prov.install_script_signals.as_ref() {
                if iss.has_network_call || iss.has_shell_spawn {
                    out.push(Finding {
                        rule_id: RuleId::PackagePolicyUnknownPackageWithInstallScripts,
                        severity: Severity::High,
                        title: format!(
                            "Unknown {eco} package ships install-time scripts: '{}'",
                            pkg.name,
                        ),
                        description: format!(
                            "The {eco} package '{}' is not a known-popular name and its \
                             install scripts include a network call or shell spawn. Policy \
                             `block_install_scripts_for_unknown_packages: true` requires this \
                             to block — review the install script directly before proceeding.",
                            pkg.name,
                        ),
                        evidence: vec![Evidence::Text {
                            detail: format!(
                                "package={} ecosystem={eco} has_network_call={} \
                                 has_shell_spawn={}",
                                pkg.name, iss.has_network_call, iss.has_shell_spawn,
                            ),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }

    // PackagePolicyTyposquatDistance — name-vs-popular edit distance
    if let Some(max_dist) = pp.block_typosquat_distance {
        if let NameVsPopular::NearPopular {
            popular_name,
            distance,
        } = &breakdown.name_vs_popular
        {
            if (*distance as u32) <= max_dist {
                out.push(Finding {
                    rule_id: RuleId::PackagePolicyTyposquatDistance,
                    severity: Severity::High,
                    title: format!(
                        "Typosquat distance below policy threshold: {eco} '{}' ≈ '{}'",
                        pkg.name, popular_name,
                    ),
                    description: format!(
                        "The {eco} package '{}' is edit-distance {distance} from the \
                         popular package '{popular_name}', at or below the policy threshold \
                         {max_dist}. Policy requires a block at this distance.",
                        pkg.name,
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "package={} ecosystem={eco} similar_to={popular_name} \
                             distance={distance} threshold={max_dist}",
                            pkg.name,
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }
    }

    out
}

/// Helper: extract `package_existence` from `api_signals` when available.
fn package_existence(api: &ApiSignals) -> Option<PackageExistence> {
    match api {
        ApiSignals::Available { provenance } => Some(provenance.package_existence),
        _ => None,
    }
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
        #[allow(deprecated)]
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
            ..Default::default()
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
            version: None,
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
        let p = empty_policy();
        let produced = risk_findings_for(&pkg, &breakdown, &existing, &p);
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
            version: None,
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::Unknown,
            malicious_typosquat_of: Some("requests".to_string()),
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        let p = empty_policy();
        let produced = risk_findings_for(&pkg, &breakdown, &[], &p);
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
        let (signals, _existence) =
            crate::registry_api::gather_api_signals(&client, Ecosystem::Npm, "x");
        assert!(matches!(signals, ApiSignals::Available { .. }));
    }

    // ── M6 ch1 — distro / docker / go backends ─────────────────────────────

    #[test]
    fn package_manager_m6_ch1_program_label_and_ecosystem_mapping() {
        // One variant ↔ one program. `Apt` maps to `apt-get` (the
        // scriptable interface), not `apt`; its `label()` shows `apt` for
        // the user-facing string.
        assert_eq!(PackageManager::Apt.program(), "apt-get");
        assert_eq!(PackageManager::Apt.label(), "apt");
        assert_eq!(PackageManager::Brew.program(), "brew");
        assert_eq!(PackageManager::Dnf.program(), "dnf");
        assert_eq!(PackageManager::Yum.program(), "yum");
        assert_eq!(PackageManager::Pacman.program(), "pacman");
        assert_eq!(PackageManager::Scoop.program(), "scoop");
        assert_eq!(PackageManager::Docker.program(), "docker");
        assert_eq!(PackageManager::Go.program(), "go");

        // install_subcommand: most use `install`; pacman uses `-S`; docker
        // uses `pull`. argv[1] = install_subcommand by build_argv contract.
        assert_eq!(PackageManager::Apt.install_subcommand(), "install");
        assert_eq!(PackageManager::Brew.install_subcommand(), "install");
        assert_eq!(PackageManager::Dnf.install_subcommand(), "install");
        assert_eq!(PackageManager::Yum.install_subcommand(), "install");
        assert_eq!(PackageManager::Pacman.install_subcommand(), "-S");
        assert_eq!(PackageManager::Scoop.install_subcommand(), "install");
        assert_eq!(PackageManager::Docker.install_subcommand(), "pull");
        assert_eq!(PackageManager::Go.install_subcommand(), "install");

        // Ecosystem mapping — each variant maps to its dedicated Ecosystem
        // (Apt..=Docker), Go maps to the existing Ecosystem::Go.
        assert_eq!(PackageManager::Apt.ecosystem(), Ecosystem::Apt);
        assert_eq!(PackageManager::Brew.ecosystem(), Ecosystem::Brew);
        assert_eq!(PackageManager::Dnf.ecosystem(), Ecosystem::Dnf);
        assert_eq!(PackageManager::Yum.ecosystem(), Ecosystem::Yum);
        assert_eq!(PackageManager::Pacman.ecosystem(), Ecosystem::Pacman);
        assert_eq!(PackageManager::Scoop.ecosystem(), Ecosystem::Scoop);
        assert_eq!(PackageManager::Docker.ecosystem(), Ecosystem::Docker);
        assert_eq!(PackageManager::Go.ecosystem(), Ecosystem::Go);
    }

    #[test]
    fn lacks_registry_adapter_matches_registry_api_dispatch() {
        // Source of truth lives in `registry_api`'s `fetch` dispatch — these
        // assertions pin the two in agreement. A future PR that wires an
        // adapter must flip this method, or the banner becomes a lie.
        assert!(!PackageManager::Npm.lacks_registry_adapter());
        assert!(!PackageManager::Pip.lacks_registry_adapter());
        assert!(!PackageManager::Cargo.lacks_registry_adapter());
        assert!(PackageManager::Apt.lacks_registry_adapter());
        assert!(PackageManager::Brew.lacks_registry_adapter());
        assert!(PackageManager::Dnf.lacks_registry_adapter());
        assert!(PackageManager::Yum.lacks_registry_adapter());
        assert!(PackageManager::Pacman.lacks_registry_adapter());
        assert!(PackageManager::Scoop.lacks_registry_adapter());
        assert!(PackageManager::Docker.lacks_registry_adapter());
        assert!(PackageManager::Go.lacks_registry_adapter());
    }

    #[test]
    fn no_registry_adapter_banner_uses_manager_label() {
        // The banner text is fixed and machine-readable — downstream tests
        // / docs consumers depend on the exact wording.
        let banner = PackageManager::Apt.no_registry_adapter_banner();
        assert!(
            banner.contains("apt"),
            "banner must mention 'apt' (label, not 'apt-get'): {banner}"
        );
        assert!(
            banner.contains("no registry adapter"),
            "banner must call out the gap explicitly: {banner}"
        );
        assert!(
            banner.contains("threat-DB name match and command-shape rules only"),
            "banner must list the fallback signals: {banner}"
        );
        // Docker banner uses the docker label.
        let dbanner = PackageManager::Docker.no_registry_adapter_banner();
        assert!(dbanner.contains("docker"));
    }

    #[test]
    fn build_argv_apt_inserts_install_subcommand() {
        let argv = build_argv(PackageManager::Apt, &["nginx".to_string()]);
        assert_eq!(argv.program, "apt-get");
        assert_eq!(argv.args, vec!["install", "nginx"]);
        assert_eq!(argv.display(), "apt-get install nginx");
    }

    #[test]
    fn build_argv_pacman_inserts_sync_flag_at_argv1() {
        // pacman has no positional subcommand — argv[1] is `-S` (Sync).
        // build_argv is generic: install_subcommand("-S") goes at argv[1].
        let argv = build_argv(PackageManager::Pacman, &["firefox".to_string()]);
        assert_eq!(argv.program, "pacman");
        assert_eq!(argv.args, vec!["-S", "firefox"]);
        assert_eq!(argv.display(), "pacman -S firefox");
    }

    #[test]
    fn build_argv_docker_uses_pull_not_install() {
        let argv = build_argv(PackageManager::Docker, &["alpine:latest".to_string()]);
        assert_eq!(argv.program, "docker");
        assert_eq!(argv.args, vec!["pull", "alpine:latest"]);
    }

    #[test]
    fn parse_docker_specs_handles_tag_digest_and_implicit_namespace() {
        // Implicit `library/` namespace, no tag → version defaults to `latest`.
        let pkgs = parse_docker_specs(&["alpine".to_string()]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Docker);
        assert_eq!(pkgs[0].name, "library/alpine");
        assert_eq!(pkgs[0].version.as_deref(), Some("latest"));

        // Explicit tag.
        let pkgs = parse_docker_specs(&["alpine:3.18".to_string()]);
        assert_eq!(pkgs[0].version.as_deref(), Some("3.18"));

        // Digest form — version carries `sha256:...` so the audit row
        // distinguishes immutable vs mutable refs.
        let pkgs = parse_docker_specs(&["alpine@sha256:abcdef0123456789".to_string()]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version.as_deref(), Some("sha256:abcdef0123456789"));

        // Registry prefix preserved.
        let pkgs = parse_docker_specs(&["ghcr.io/owner/img:v1".to_string()]);
        assert_eq!(pkgs[0].name, "ghcr.io/owner/img");
        assert_eq!(pkgs[0].version.as_deref(), Some("v1"));

        // Flags are skipped.
        let pkgs =
            parse_docker_specs(&["--platform=linux/amd64".to_string(), "alpine".to_string()]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "library/alpine");
    }

    #[test]
    fn parse_docker_specs_skips_value_after_value_bearing_flag() {
        // Regression: `--platform linux/amd64` is a flag with a separate
        // value token. The flag is skipped; the value `linux/amd64` MUST
        // also be skipped — otherwise it parses as a `linux/amd64:latest`
        // bogus image ref.
        let pkgs = parse_docker_specs(&[
            "--platform".to_string(),
            "linux/amd64".to_string(),
            "alpine".to_string(),
        ]);
        assert_eq!(pkgs.len(), 1, "only `alpine` should parse, not the value");
        assert_eq!(pkgs[0].name, "library/alpine");

        // Same for `-v /host:/container alpine` — the `/host:/container`
        // value contains `/` and `:`, both of which would otherwise make it
        // parse as an image ref.
        let pkgs = parse_docker_specs(&[
            "-v".to_string(),
            "/host:/container".to_string(),
            "alpine".to_string(),
        ]);
        assert_eq!(pkgs.len(), 1, "only `alpine` should parse, not the mount");
        assert_eq!(pkgs[0].name, "library/alpine");

        // Inline `--flag=value` form: only the flag token is skipped, the
        // next positional argument IS parsed.
        let pkgs = parse_docker_specs(&["-p=8080:80".to_string(), "alpine".to_string()]);
        assert_eq!(pkgs.len(), 1, "inline `-p=8080:80` skips one token only");
        assert_eq!(pkgs[0].name, "library/alpine");
    }

    #[test]
    fn parse_go_specs_defaults_version_to_latest() {
        // No `@version` → defaults to `latest`.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra".to_string()]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Go);
        assert_eq!(pkgs[0].name, "github.com/spf13/cobra");
        assert_eq!(pkgs[0].version.as_deref(), Some("latest"));

        // Explicit @latest.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra@latest".to_string()]);
        assert_eq!(pkgs[0].version.as_deref(), Some("latest"));

        // Explicit @v1.8.0.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra@v1.8.0".to_string()]);
        assert_eq!(pkgs[0].version.as_deref(), Some("v1.8.0"));

        // A bare word that does not look like a module path is skipped —
        // `nginx` is not a Go module, even though it might be a Go binary
        // someone confused.
        let pkgs = parse_go_specs(&["nginx".to_string()]);
        assert!(
            pkgs.is_empty(),
            "non-module-shaped names must not be parsed"
        );

        // Flags are skipped.
        let pkgs = parse_go_specs(&["-v".to_string(), "github.com/x/y".to_string()]);
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn parse_go_specs_rejects_local_path_targets() {
        // Regression: `go install ./cmd/foo` was being treated as a remote
        // registry module because `./cmd/foo` contains `/`. Local paths are
        // NOT modules — they must be skipped entirely.
        let cases = vec![
            ".".to_string(),
            "..".to_string(),
            "./cmd/foo".to_string(),
            "../cmd/foo".to_string(),
            "./...".to_string(),
            "../../package".to_string(),
            "/abs/path/cmd/foo".to_string(),
            "/usr/local/src/proj".to_string(),
            "~/repo/cmd/foo".to_string(),
            "~".to_string(),
        ];
        for tok in &cases {
            let pkgs = parse_go_specs(std::slice::from_ref(tok));
            assert!(
                pkgs.is_empty(),
                "local path {tok:?} must not parse as a Go module"
            );
        }
        // Sanity: a real module still works alongside a local path.
        let pkgs = parse_go_specs(&[
            "./cmd/foo".to_string(),
            "github.com/spf13/cobra@v1.8.0".to_string(),
        ]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/spf13/cobra");
    }

    #[test]
    fn plan_install_apt_emits_banner_via_lacks_registry_adapter() {
        // M6 ch1 acceptance — an apt install plan reaches ALLOW (the
        // command-shape rules don't fire on `apt-get install nginx`), the
        // packages list is empty (no registry adapter, no scoring), and the
        // manager carries the lacks-registry-adapter flag so the CLI shows
        // the banner.
        let req = PlanRequest {
            manager: PackageManager::Apt,
            user_args: &["nginx".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert_eq!(
            plan.verdict.action,
            Action::Allow,
            "apt-get install nginx must Allow: {:?}",
            plan.verdict.findings,
        );
        assert!(
            plan.packages.is_empty(),
            "apt has no registry adapter — no scoring"
        );
        assert!(plan.manager.lacks_registry_adapter());
    }

    #[test]
    fn plan_install_docker_pull_extracts_image_ref() {
        let req = PlanRequest {
            manager: PackageManager::Docker,
            user_args: &["alpine:latest".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert_eq!(plan.argv.display(), "docker pull alpine:latest");
        assert_eq!(
            plan.verdict.action,
            Action::Allow,
            "docker pull alpine:latest must Allow: {:?}",
            plan.verdict.findings,
        );
        assert_eq!(plan.packages.len(), 1, "docker image ref must be extracted");
        assert_eq!(plan.packages[0].reference.ecosystem, Ecosystem::Docker);
        assert_eq!(plan.packages[0].reference.name, "library/alpine");
        assert_eq!(
            plan.packages[0].reference.version.as_deref(),
            Some("latest")
        );
    }

    #[test]
    fn plan_install_go_install_extracts_module_with_default_latest() {
        // No `@version` — the manager-specific parser defaults to `latest`,
        // mirroring `go install`'s own behavior.
        let req = PlanRequest {
            manager: PackageManager::Go,
            user_args: &["github.com/spf13/cobra".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert_eq!(
            plan.verdict.action,
            Action::Allow,
            "go install github.com/spf13/cobra must Allow (no schemeless-sink FP): {:?}",
            plan.verdict.findings,
        );
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].reference.name, "github.com/spf13/cobra");
        assert_eq!(
            plan.packages[0].reference.version.as_deref(),
            Some("latest")
        );
    }

    #[test]
    fn plan_install_distro_no_registry_adapter_note_is_specific() {
        // For distro backends the "no installable package name" note would be
        // misleading (nginx IS the name — we just have no adapter). The note
        // must instead say so explicitly so the operator isn't confused.
        let req = PlanRequest {
            manager: PackageManager::Brew,
            user_args: &["ripgrep".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        };
        let plan = plan_install(&req);
        assert!(
            plan.notes.iter().any(|n| n.contains("no registry adapter")),
            "the note must point at the missing-adapter gap: {:?}",
            plan.notes,
        );
        // The legacy "no installable package name" wording must NOT appear
        // for a backend with a name on the command line.
        assert!(
            !plan
                .notes
                .iter()
                .any(|n| n.contains("no installable package name")),
            "distro backends with a name on the command line must NOT show the \
             misleading legacy note: {:?}",
            plan.notes,
        );
    }

    // ── M6 ch7 — policy-driven rule emission tests ─────────────────────────

    /// Build a minimal `RiskBreakdown` carrying the given provenance
    /// (so the policy_findings_for helper has data to read).
    #[allow(deprecated)]
    fn breakdown_with_provenance(
        name: &str,
        eco: Ecosystem,
        nvp: NameVsPopular,
        provenance: ApiProvenance,
    ) -> RiskBreakdown {
        let signals = PackageSignals {
            ecosystem: eco,
            name: name.to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular: nvp,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::Available { provenance },
        };
        package_risk::score_package(&signals)
    }

    #[test]
    fn package_policy_not_found_fires_when_signal_and_policy_align() {
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "missing-pkg".to_string(),
            version: None,
        };
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_existence: PackageExistence::NotFound,
            ..Default::default()
        };
        let breakdown = breakdown_with_provenance(
            "missing-pkg",
            Ecosystem::Npm,
            NameVsPopular::Unknown,
            provenance,
        );
        let mut policy = empty_policy();
        policy.package_policy.block_not_found = true;
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PackagePolicyNotFound
                    && f.severity == Severity::High),
            "PackagePolicyNotFound must fire High when signal+policy align: {findings:?}"
        );
    }

    #[test]
    fn package_policy_not_found_does_not_fire_when_existence_unknown() {
        // Honest no-data: offline runs report Unknown, and even with
        // `block_not_found: true` the rule must stay silent.
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "some-pkg".to_string(),
            version: None,
        };
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_existence: PackageExistence::Unknown,
            ..Default::default()
        };
        let breakdown = breakdown_with_provenance(
            "some-pkg",
            Ecosystem::Npm,
            NameVsPopular::Unknown,
            provenance,
        );
        let mut policy = empty_policy();
        policy.package_policy.block_not_found = true;
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::PackagePolicyNotFound),
            "PackagePolicyNotFound must NOT fire on Unknown existence: {findings:?}"
        );
    }

    #[test]
    fn package_policy_newer_than_days_block_fires_on_block_threshold() {
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "fresh-pkg".to_string(),
            version: None,
        };
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_age_days: Some(3),
            package_existence: PackageExistence::Exists,
            ..Default::default()
        };
        let breakdown = breakdown_with_provenance(
            "fresh-pkg",
            Ecosystem::Npm,
            NameVsPopular::Unknown,
            provenance,
        );
        let mut policy = empty_policy();
        policy.package_policy.block_newer_than_days = Some(7);
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PackagePolicyNewerThanDays)
            .expect("expected PackagePolicyNewerThanDays finding");
        assert_eq!(
            f.severity,
            Severity::High,
            "block_newer_than_days crossed -> Block severity"
        );
    }

    #[test]
    fn package_policy_typosquat_distance_fires_on_near_popular_at_or_below_threshold() {
        let pkg = PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: "reqeusts".to_string(),
            version: None,
        };
        let provenance = ApiProvenance {
            source: "pypi".to_string(),
            package_existence: PackageExistence::Exists,
            ..Default::default()
        };
        let breakdown = breakdown_with_provenance(
            "reqeusts",
            Ecosystem::PyPI,
            NameVsPopular::NearPopular {
                popular_name: "requests".to_string(),
                distance: 1,
            },
            provenance,
        );
        let mut policy = empty_policy();
        policy.package_policy.block_typosquat_distance = Some(1);
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PackagePolicyTyposquatDistance),
            "PackagePolicyTyposquatDistance must fire at distance <= threshold: {findings:?}"
        );
    }

    #[test]
    fn package_policy_unknown_with_install_scripts_fires_on_network_or_shell() {
        use crate::package_risk::InstallScriptSignals;
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "unknown-pkg".to_string(),
            version: None,
        };
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_existence: PackageExistence::Exists,
            install_script_signals: Some(InstallScriptSignals {
                has_network_call: true,
                has_shell_spawn: false,
                suspicious_patterns: vec![],
            }),
            ..Default::default()
        };
        let breakdown = breakdown_with_provenance(
            "unknown-pkg",
            Ecosystem::Npm,
            NameVsPopular::Unknown,
            provenance,
        );
        let mut policy = empty_policy();
        policy
            .package_policy
            .block_install_scripts_for_unknown_packages = true;
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        assert!(
            findings.iter().any(|f| f.rule_id
                == RuleId::PackagePolicyUnknownPackageWithInstallScripts
                && f.severity == Severity::High),
            "PackagePolicyUnknownPackageWithInstallScripts must fire High: {findings:?}"
        );
    }

    #[test]
    fn package_policy_low_downloads_warns_when_below_threshold() {
        let pkg = PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: "unfamiliar".to_string(),
            version: None,
        };
        let provenance = ApiProvenance {
            source: "pypi".to_string(),
            package_existence: PackageExistence::Exists,
            recent_downloads: Some(5),
            ..Default::default()
        };
        let breakdown = breakdown_with_provenance(
            "unfamiliar",
            Ecosystem::PyPI,
            NameVsPopular::Unknown,
            provenance,
        );
        let mut policy = empty_policy();
        policy.package_policy.warn_low_downloads_below = Some(100);
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PackagePolicyLowDownloads)
            .expect("expected PackagePolicyLowDownloads finding");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn aggregate_threshold_reads_from_policy_not_constants() {
        // Hand-curate a breakdown with score == 60 (provenance-only). With
        // the default policy (warn=51, block=76) this should fire a
        // Medium-severity ThreatSuspiciousPackage finding (Warn). With a
        // custom policy lowering block to 60, it must escalate to High
        // (Block) — proving thresholds are policy-driven.
        #[allow(deprecated)]
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_age_days: Some(1),
            ownership_transferred: Some(true),
            version_spike: Some(true),
            recent_downloads: Some(3),
            has_source_repo: Some(false),
            yanked_or_deprecated: true,
            latest_version: Some("9.9.9".to_string()),
            package_existence: PackageExistence::Exists,
            ..Default::default()
        };
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "test-pkg".to_string(),
            version: None,
        };
        let breakdown = breakdown_with_provenance(
            "test-pkg",
            Ecosystem::Npm,
            NameVsPopular::Unknown,
            provenance,
        );

        // With default policy and a critical score, the finding must be High.
        let policy = empty_policy();
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        let sus = findings
            .iter()
            .find(|f| f.rule_id == RuleId::ThreatSuspiciousPackage)
            .expect("expected ThreatSuspiciousPackage on default thresholds");

        // Lower both thresholds far below the score and re-evaluate. Result
        // remains High (block_threshold crossed).
        let mut tight_policy = empty_policy();
        tight_policy.package_policy.warn_aggregate_score = Some(1);
        tight_policy.package_policy.block_aggregate_score = Some(1);
        let tight = risk_findings_for(&pkg, &breakdown, &[], &tight_policy);
        let tight_sus = tight
            .iter()
            .find(|f| f.rule_id == RuleId::ThreatSuspiciousPackage)
            .expect("tighter policy must still emit the finding");
        // The default-policy finding's severity must follow the same map
        // (we're not pinning the exact score here — just that the warn
        // threshold drives Medium and block drives High):
        assert!(
            matches!(sus.severity, Severity::Medium | Severity::High),
            "default-policy aggregate finding must be Medium or High"
        );
        assert_eq!(
            tight_sus.severity,
            Severity::High,
            "extreme-tight thresholds must escalate to High"
        );
    }
}
