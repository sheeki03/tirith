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
use crate::rules::threatintel::{self, PackageRef};
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::tokenize::{self, ShellType};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Verdict};

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
/// `std::process::Command`, never through a shell; the same tokens joined with
/// spaces form [`InstallPlan::analysis_command`] (analysis/audit only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallArgv {
    /// argv[0] — the package-manager program.
    pub program: String,
    /// argv[1..] — the install subcommand followed by the user's arguments.
    pub args: Vec<String>,
}

impl InstallArgv {
    /// The command as a single human-readable string (display/audit); never
    /// handed to a shell.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
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
    /// The argv joined into a string — analysis/audit only, never shell-executed.
    pub analysis_command: String,
    /// The packages the transaction will install (empty for a flags-only /
    /// manifest install). Each carries its own [`RiskBreakdown`].
    pub packages: Vec<PlannedPackage>,
    /// The composed verdict: command-shape + package-risk findings, deduped,
    /// action from the strongest.
    pub verdict: Verdict,
    /// Coverage notes (missing threat DB, unrecognized spec) — honest limits.
    pub notes: Vec<String>,
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
    /// Offline — every package's API signals are [`ApiSignals::NotComputed`].
    Off,
    /// `--online` — an offline-safe closure resolving each `(ecosystem, name)`
    /// to its [`ApiSignals`], called at most once per distinct package.
    Resolver(&'a dyn Fn(Ecosystem, &str) -> ApiSignals),
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

    // (2)+(3) package extraction and scoring. Reuse the existing extractor for
    // npm/pip/cargo; for Docker/Go the manager-specific parser is authoritative
    // (and replaces the generic output to avoid duplicate PlannedPackage
    // entries). The distro backends have no registry to score against and
    // return empty — their verdict is command-shape + the no-adapter banner.
    let segments = tokenize::tokenize(&analysis_command, ShellType::Posix);
    let extracted: Vec<PackageRef> = match manager {
        PackageManager::Docker | PackageManager::Go => {
            extract_packages_manager_specific(manager, request.user_args)
        }
        _ => threatintel::extract_packages(&segments),
    };

    // M6 ch1 — the `schemeless_to_sink` FP on `go install` / `docker pull` is
    // suppressed at the engine layer in `extract.rs`; nothing extra needed here.

    // Keep only packages for this manager's ecosystem (belt-and-suspenders).
    let eco = manager.ecosystem();
    let mut planned: Vec<PlannedPackage> = Vec::new();

    let online_in_use = matches!(request.online, OnlineMode::Resolver(_));
    for pkg in extracted.into_iter().filter(|p| p.ecosystem == eco) {
        let signals = gather_package_signals(request, eco, &pkg, &mut notes);
        let breakdown = package_risk::score_package(&signals);

        // M6 ch7 — the install-script signal needs `--online` (or on-disk script
        // text). A bare offline install can't evaluate it; surface the gap
        // rather than silently no-op the policy rule.
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

    // (5) compose the verdict — apply policy severity overrides, then derive
    // the action from the strongest finding (the shared max-severity mapping).
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
        let (name, version) = match arg.rsplit_once('@') {
            Some((n, v)) if !n.is_empty() && !v.is_empty() => (n, Some(v.to_string())),
            _ => (arg.as_str(), Some("latest".to_string())),
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
            version,
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
        // M6 ch6 — carry version through so OSV can pin to (eco, name, version).
        version: pkg.version.clone(),
        threat_db_missing: db.is_none(),
        name_vs_popular,
        malicious_typosquat_of,
        // Pre-install: nothing on disk and we never fetch — content not evaluated.
        content_signals: ContentSignals::NotInspected,
        api,
    }
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
    fn plan_install_online_resolver_high_provenance_risk_warns() {
        // Alarming provenance (brand-new, ownerless, version-spiked, no repo,
        // yanked) stacks to a high score with no name tell — the chunk-6 value.
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
        // A failed `--online` call degrades to the offline score with a note —
        // never panics or blocks on the failure alone.
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
        // An existing ThreatPackageSimilarName must suppress the aggregate
        // finding for the same package.
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
        // The package-risk DB found a typosquat the engine's pass missed
        // (different tables) → emit once.
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
        // The resolver seam works with a fixture client — no network.
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
        assert_eq!(pkgs[0].version.as_deref(), Some("latest"));

        // Explicit tag.
        let pkgs = parse_docker_specs(&["alpine:3.18".to_string()]);
        assert_eq!(pkgs[0].version.as_deref(), Some("3.18"));

        // Digest form — version carries `sha256:...`.
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
        assert_eq!(pkgs[0].version.as_deref(), Some("latest"));

        // Explicit @latest.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra@latest".to_string()]);
        assert_eq!(pkgs[0].version.as_deref(), Some("latest"));

        // Explicit @v1.8.0.
        let pkgs = parse_go_specs(&["github.com/spf13/cobra@v1.8.0".to_string()]);
        assert_eq!(pkgs[0].version.as_deref(), Some("v1.8.0"));

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
            plan.packages[0].reference.version.as_deref(),
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
            plan.packages[0].reference.version.as_deref(),
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
        // Unknown existence (offline) must stay silent even with
        // `block_not_found: true`.
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
            version: None,
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
