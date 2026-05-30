//! `tirith intend` — intent-vs-command heuristic (M10 ch4).
//!
//! ## What this is
//!
//! A **pure-Rust, no-LLM** heuristic that flags when a *stated intent* ("install
//! a formatter") doesn't justify what the command *actually does* (pipe a remote
//! script straight into a shell). It computes an [`IntentBehaviorReport`] with
//! three parts:
//!
//! - `intent_signals`  — which intent keyword groups the stated intent matched
//!   (e.g. `install`, `test`, `build`). One natural-language sentence can match
//!   several.
//! - `command_signals` — the high-impact behaviors the command exhibits, derived
//!   from the SHIPPING engine rules. `intend` runs [`crate::engine::analyze`] on
//!   the command and maps each [`RuleId`](crate::verdict::RuleId) that fired to a
//!   named [`CommandSignal`]. This keeps the signals consistent with the rest of
//!   tirith rather than re-implementing detection.
//! - `mismatches`      — every command signal that is HIGH-IMPACT *and* not
//!   justified by any matched intent. A mismatch is the heuristic's output.
//!
//! ## What this is NOT
//!
//! - It is **advisory and Info-level only**. It NEVER blocks. The command's real
//!   security verdict comes from `tirith check`; `intend` only answers "does the
//!   thing you said you wanted match the thing this command does?".
//! - It is a HEURISTIC. Natural-language intent classification by keyword is
//!   necessarily incomplete — a phrasing it doesn't recognize yields no intent
//!   signals, so EVERY high-impact command signal then reads as unjustified. The
//!   caller renders this honestly.
//! - There is NO LLM call here and none is wired. A future `--llm-explain` wave
//!   may add one; M10 is pure heuristic.

use serde::Serialize;

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::tokenize::ShellType;
use crate::verdict::RuleId;

/// A high-impact behavior the analyzed command exhibits, derived from the
/// engine rule that fired. The mapping from [`RuleId`] to `CommandSignal` is in
/// [`CommandSignal::from_rule`]. Signals that share an intuitive meaning
/// (every "pipe a download into an interpreter" rule) collapse to one variant
/// so the user-facing report stays readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandSignal {
    /// A remote download is piped straight into a shell / interpreter
    /// (`curl … | bash`, `iwr … | iex`, `wget -O- | sh`).
    DownloadPipe,
    /// The command escalates privileges with `sudo` (any of the M8 ch4 sudo
    /// rules fired).
    Sudo,
    /// The command reads/sweeps credential files or exfiltrates data over the
    /// network (`DataExfiltration`, `CredentialFileSweep`, sensitive-env export
    /// into a sink).
    EnvOrCredentialExfil,
    /// The command writes to a shell rc / profile (a persistence foothold).
    ShellRcWrite,
    /// The command runs a package-manager install (`pip install`, `npm install`,
    /// remote `pip`/`npm` URL install, untrusted Docker registry, etc.).
    PackageInstall,
    /// The command decodes a base64 blob and executes it.
    Base64Execute,
    /// The command opens an interactive root shell (`sudo bash`).
    RootShell,
}

impl CommandSignal {
    /// Stable lowercase token used in human + JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            CommandSignal::DownloadPipe => "download_pipe",
            CommandSignal::Sudo => "sudo",
            CommandSignal::EnvOrCredentialExfil => "env_or_credential_exfil",
            CommandSignal::ShellRcWrite => "shell_rc_write",
            CommandSignal::PackageInstall => "package_install",
            CommandSignal::Base64Execute => "base64_execute",
            CommandSignal::RootShell => "root_shell",
        }
    }

    /// One-line human label for the signal.
    pub fn label(self) -> &'static str {
        match self {
            CommandSignal::DownloadPipe => "pipes a remote download into a shell",
            CommandSignal::Sudo => "escalates privileges with sudo",
            CommandSignal::EnvOrCredentialExfil => "reads credentials or sends data off-host",
            CommandSignal::ShellRcWrite => "writes a shell rc/profile (persistence)",
            CommandSignal::PackageInstall => "installs a package from a package manager",
            CommandSignal::Base64Execute => "decodes and executes a base64 blob",
            CommandSignal::RootShell => "opens an interactive root shell",
        }
    }

    /// Whether this signal is "high impact" — i.e. worth flagging when the
    /// stated intent does not justify it. `PackageInstall` is intentionally NOT
    /// high-impact: installing a package is exactly what most build/test/install
    /// intents are FOR, and flagging it would drown the signal. The high-impact
    /// set is the surprising, persistence-/exfil-/privilege-shaped behaviors.
    pub fn is_high_impact(self) -> bool {
        match self {
            CommandSignal::DownloadPipe
            | CommandSignal::Sudo
            | CommandSignal::EnvOrCredentialExfil
            | CommandSignal::ShellRcWrite
            | CommandSignal::Base64Execute
            | CommandSignal::RootShell => true,
            CommandSignal::PackageInstall => false,
        }
    }

    /// Map an engine [`RuleId`] to a `CommandSignal`, or `None` when the rule
    /// is not one of the behaviors `intend` reasons about (homograph hostnames,
    /// terminal-deception bytes, file-scan findings, etc. are out of scope —
    /// `intend` is about *what the command does to the machine*, which the
    /// command-shape / ecosystem / sudo rules capture).
    pub fn from_rule(rule: RuleId) -> Option<CommandSignal> {
        match rule {
            // Download-pipe family.
            RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            | RuleId::PsInlineDownloadExecute => Some(CommandSignal::DownloadPipe),

            // Base64 decode-and-execute.
            RuleId::Base64DecodeExecute => Some(CommandSignal::Base64Execute),

            // Credential sweep / data exfiltration / sensitive-env into a sink.
            RuleId::CredentialFileSweep
            | RuleId::DataExfiltration
            | RuleId::SensitiveEnvExport
            | RuleId::ProcMemAccess => Some(CommandSignal::EnvOrCredentialExfil),

            // Sudo escalation family (M8 ch4).
            RuleId::SudoShellSpawn => Some(CommandSignal::RootShell),
            RuleId::SudoEnvPreserveSensitive
            | RuleId::SudoTeeSystemFile
            | RuleId::SudoDownloadInstall
            | RuleId::SudoRecursivePermsBroadPath => Some(CommandSignal::Sudo),

            // Package-manager install family.
            RuleId::PipUrlInstall
            | RuleId::NpmUrlInstall
            | RuleId::DockerUntrustedRegistry
            | RuleId::DockerRemotePrivEsc
            | RuleId::BrewUntrustedTap
            | RuleId::HelmUntrustedRepo
            | RuleId::RepoAddFromPipe => Some(CommandSignal::PackageInstall),

            _ => None,
        }
    }
}

/// A coarse classification of the stated intent, derived from keyword groups.
/// One sentence can match several (so `IntentBehaviorReport::intent_signals` is
/// a set). Each class declares which [`CommandSignal`]s it *justifies* via
/// [`IntentClass::justifies`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentClass {
    /// "install", "add a dependency", "set up", "bootstrap".
    Install,
    /// "download", "fetch", "pull", "curl", "get … from the internet".
    Download,
    /// "run", "execute", "launch" an installer/script.
    RunScript,
    /// "test", "check", "run the tests".
    Test,
    /// "build", "compile", "bundle".
    Build,
    /// "format", "lint", "fmt", "tidy".
    Format,
    /// "clean", "remove build artifacts", "purge".
    Clean,
    /// "deploy", "release", "publish", "ship".
    Deploy,
    /// "configure", "set up config", "edit settings".
    Configure,
}

impl IntentClass {
    /// Stable lowercase token used in human + JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            IntentClass::Install => "install",
            IntentClass::Download => "download",
            IntentClass::RunScript => "run_script",
            IntentClass::Test => "test",
            IntentClass::Build => "build",
            IntentClass::Format => "format",
            IntentClass::Clean => "clean",
            IntentClass::Deploy => "deploy",
            IntentClass::Configure => "configure",
        }
    }

    /// The keyword stems that, when present as a whole word in the stated
    /// intent, classify it into this group. Matching is whole-word and
    /// case-insensitive (see [`classify_intent`]).
    fn keywords(self) -> &'static [&'static str] {
        match self {
            IntentClass::Install => &[
                "install",
                "installer",
                "installing",
                "setup",
                "bootstrap",
                "provision",
                "add",
                "dependency",
                "dependencies",
            ],
            IntentClass::Download => &[
                "download",
                "downloading",
                "fetch",
                "fetching",
                "pull",
                "curl",
                "wget",
                "retrieve",
                "grab",
            ],
            IntentClass::RunScript => &[
                "run", "running", "execute", "exec", "launch", "invoke", "script",
            ],
            IntentClass::Test => &[
                "test", "tests", "testing", "check", "verify", "spec", "specs",
            ],
            IntentClass::Build => &[
                "build",
                "building",
                "compile",
                "compiling",
                "bundle",
                "package",
            ],
            IntentClass::Format => &[
                "format",
                "formatter",
                "formatting",
                "fmt",
                "lint",
                "linter",
                "linting",
                "tidy",
                "prettier",
                "reformat",
            ],
            IntentClass::Clean => &[
                "clean", "cleaning", "remove", "purge", "delete", "clear", "wipe", "prune",
            ],
            IntentClass::Deploy => &[
                "deploy",
                "deploying",
                "release",
                "publish",
                "ship",
                "rollout",
                "promote",
            ],
            IntentClass::Configure => &[
                "configure",
                "config",
                "configuration",
                "settings",
                "set",
                "edit",
                "customize",
            ],
        }
    }

    /// The command signals this intent class JUSTIFIES — i.e. signals that, when
    /// they fire, are an expected consequence of doing the stated thing and so do
    /// NOT count as a mismatch.
    ///
    /// The discipline is narrow on purpose (per the project's "narrow carveouts"
    /// rule): a class justifies only what its name plainly implies. "install" /
    /// "download" / "run a script" justify the download-pipe shape (that IS how
    /// many installers work); "deploy" additionally justifies privilege use.
    /// "format" / "test" / "build" / "clean" justify a package install (a
    /// formatter is a package) but NOT piping a remote script to a shell, NOT
    /// sudo, NOT exfil.
    fn justifies(self) -> &'static [CommandSignal] {
        match self {
            // Explicitly download-and-run intents justify the pipe-to-shell shape
            // and the package install that usually follows.
            IntentClass::Install => &[CommandSignal::PackageInstall],
            IntentClass::Download => &[CommandSignal::DownloadPipe],
            IntentClass::RunScript => &[CommandSignal::DownloadPipe, CommandSignal::Base64Execute],

            // Deploy/release commonly need privilege and may push artifacts.
            IntentClass::Deploy => &[
                CommandSignal::Sudo,
                CommandSignal::PackageInstall,
                CommandSignal::ShellRcWrite,
            ],

            // Configure justifies writing config (incl. a shell rc).
            IntentClass::Configure => &[CommandSignal::ShellRcWrite],

            // Build/test/format/clean justify installing a package (the tool is a
            // package) but nothing surprising.
            IntentClass::Test | IntentClass::Build | IntentClass::Format | IntentClass::Clean => {
                &[CommandSignal::PackageInstall]
            }
        }
    }

    /// All classes, for iteration during classification.
    const ALL: [IntentClass; 9] = [
        IntentClass::Install,
        IntentClass::Download,
        IntentClass::RunScript,
        IntentClass::Test,
        IntentClass::Build,
        IntentClass::Format,
        IntentClass::Clean,
        IntentClass::Deploy,
        IntentClass::Configure,
    ];
}

/// A single intent-class match, recording which class fired and which keyword
/// triggered it (for `--explain` derivation).
#[derive(Debug, Clone, Serialize)]
pub struct IntentSignal {
    pub class: IntentClass,
    /// The keyword from the stated intent that matched this class.
    pub matched_keyword: String,
}

/// A flagged mismatch: a high-impact command signal that no matched intent
/// justified.
#[derive(Debug, Clone, Serialize)]
pub struct Mismatch {
    pub signal: CommandSignal,
    /// Human-readable reason — what the command does vs what the intent implied.
    pub reason: String,
}

/// One derivation step for `--explain`: why a command signal was or was not a
/// mismatch, naming the intent class (if any) that justified it.
#[derive(Debug, Clone, Serialize)]
pub struct Derivation {
    pub signal: CommandSignal,
    /// `true` when this signal was flagged as a mismatch.
    pub mismatch: bool,
    /// The intent class that justified this signal, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justified_by: Option<IntentClass>,
    pub detail: String,
}

/// The full report `tirith intend` produces.
#[derive(Debug, Clone, Serialize)]
pub struct IntentBehaviorReport {
    /// The intent classes the stated intent matched.
    pub intent_signals: Vec<IntentSignal>,
    /// The high-impact behaviors the command exhibits (deduped, sorted).
    pub command_signals: Vec<CommandSignal>,
    /// Every high-impact command signal not justified by a matched intent.
    pub mismatches: Vec<Mismatch>,
    /// Per-signal derivation, populated only when `--explain` is requested.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub derivation: Vec<Derivation>,
}

impl IntentBehaviorReport {
    /// `true` when at least one mismatch was found.
    pub fn has_mismatch(&self) -> bool {
        !self.mismatches.is_empty()
    }
}

/// Split the stated intent into lowercase ASCII alphanumeric words. Punctuation
/// becomes a separator so `"format,lint"` yields two words. Hyphens split too,
/// so `"set-up"` matches the `set` / `up` stems.
fn intent_words(intent: &str) -> Vec<String> {
    intent
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

/// Classify the stated intent into a set of [`IntentSignal`]s by whole-word
/// keyword match. Deterministic order: classes in [`IntentClass::ALL`] order,
/// first matching keyword per class.
pub fn classify_intent(intent: &str) -> Vec<IntentSignal> {
    let words = intent_words(intent);
    let mut signals = Vec::new();
    for class in IntentClass::ALL {
        if let Some(kw) = class
            .keywords()
            .iter()
            .find(|kw| words.iter().any(|w| w == **kw))
        {
            signals.push(IntentSignal {
                class,
                matched_keyword: (*kw).to_string(),
            });
        }
    }
    signals
}

/// Derive the deduped, sorted set of [`CommandSignal`]s for `command` by running
/// the shipping engine and mapping each fired rule. This reuses
/// [`crate::engine::analyze`] so the signals stay consistent with `tirith
/// check` rather than re-implementing detection.
pub fn command_signals(command: &str, shell: ShellType) -> Vec<CommandSignal> {
    let ctx = AnalysisContext {
        input: command.to_string(),
        shell,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: None,
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: None,
    };
    let verdict = engine::analyze(&ctx);

    let mut signals: Vec<CommandSignal> = verdict
        .findings
        .iter()
        .filter_map(|f| CommandSignal::from_rule(f.rule_id))
        .collect();
    signals.sort();
    signals.dedup();
    signals
}

/// Compute the full intent-vs-command report. When `explain` is true, the
/// `derivation` field is populated with a per-signal trace.
pub fn analyze_intent(
    intent: &str,
    command: &str,
    shell: ShellType,
    explain: bool,
) -> IntentBehaviorReport {
    let intent_signals = classify_intent(intent);
    let command_signals = command_signals(command, shell);

    // A signal is justified when ANY matched intent class justifies it.
    let justified_by = |signal: CommandSignal| -> Option<IntentClass> {
        intent_signals
            .iter()
            .find(|s| s.class.justifies().contains(&signal))
            .map(|s| s.class)
    };

    let mut mismatches = Vec::new();
    let mut derivation = Vec::new();

    for &signal in &command_signals {
        let justifier = justified_by(signal);
        let high_impact = signal.is_high_impact();
        let is_mismatch = high_impact && justifier.is_none();

        if is_mismatch {
            mismatches.push(Mismatch {
                signal,
                reason: format!(
                    "the command {} but the stated intent does not justify that",
                    signal.label()
                ),
            });
        }

        if explain {
            let detail = if !high_impact {
                format!(
                    "command {} — not a high-impact behavior, never a mismatch",
                    signal.label()
                )
            } else if let Some(class) = justifier {
                format!(
                    "command {} — justified by intent '{}'",
                    signal.label(),
                    class.as_str()
                )
            } else {
                format!(
                    "command {} — NOT justified by any matched intent → mismatch",
                    signal.label()
                )
            };
            derivation.push(Derivation {
                signal,
                mismatch: is_mismatch,
                justified_by: justifier,
                detail,
            });
        }
    }

    IntentBehaviorReport {
        intent_signals,
        command_signals,
        mismatches,
        derivation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_install_a_formatter() {
        let sigs = classify_intent("install a formatter");
        let classes: Vec<_> = sigs.iter().map(|s| s.class).collect();
        assert!(classes.contains(&IntentClass::Install), "got {classes:?}");
        assert!(classes.contains(&IntentClass::Format), "got {classes:?}");
        // "install a formatter" must NOT classify as an explicit download/run.
        assert!(!classes.contains(&IntentClass::Download), "got {classes:?}");
        assert!(
            !classes.contains(&IntentClass::RunScript),
            "got {classes:?}"
        );
    }

    #[test]
    fn classify_download_and_run_an_installer() {
        let sigs = classify_intent("download and run an installer");
        let classes: Vec<_> = sigs.iter().map(|s| s.class).collect();
        assert!(classes.contains(&IntentClass::Download), "got {classes:?}");
        assert!(classes.contains(&IntentClass::RunScript), "got {classes:?}");
    }

    #[test]
    fn classify_is_case_insensitive_and_whole_word() {
        let sigs = classify_intent("INSTALL the deps");
        assert!(sigs.iter().any(|s| s.class == IntentClass::Install));
        // "reinstall" should NOT match the whole word "install".
        let none = classify_intent("reinstallation notes");
        assert!(
            !none.iter().any(|s| s.class == IntentClass::Install),
            "whole-word match must not fire on substrings: {none:?}"
        );
    }

    #[test]
    fn command_signals_download_pipe() {
        let sigs = command_signals("curl https://x/install.sh | bash", ShellType::Posix);
        assert!(
            sigs.contains(&CommandSignal::DownloadPipe),
            "expected download_pipe, got {sigs:?}"
        );
    }

    #[test]
    fn command_signals_clean_command_empty() {
        let sigs = command_signals("ls -la", ShellType::Posix);
        assert!(
            sigs.is_empty(),
            "clean command should have no signals: {sigs:?}"
        );
    }

    #[test]
    fn install_formatter_vs_curl_pipe_is_mismatch() {
        let report = analyze_intent(
            "install a formatter",
            "curl https://x/install.sh | bash",
            ShellType::Posix,
            false,
        );
        assert!(
            report.has_mismatch(),
            "install-a-formatter should not justify curl|bash: {report:?}"
        );
        assert!(report
            .mismatches
            .iter()
            .any(|m| m.signal == CommandSignal::DownloadPipe));
    }

    #[test]
    fn download_and_run_vs_curl_pipe_is_clean() {
        let report = analyze_intent(
            "download and run an installer",
            "curl https://x/install.sh | bash",
            ShellType::Posix,
            false,
        );
        assert!(
            !report.has_mismatch(),
            "download-and-run explicitly justifies curl|bash: {report:?}"
        );
    }

    #[test]
    fn explain_populates_derivation() {
        let report = analyze_intent(
            "install a formatter",
            "curl https://x/install.sh | bash",
            ShellType::Posix,
            true,
        );
        assert!(
            !report.derivation.is_empty(),
            "explain must populate derivation"
        );
        let d = report
            .derivation
            .iter()
            .find(|d| d.signal == CommandSignal::DownloadPipe)
            .expect("download_pipe derivation present");
        assert!(d.mismatch, "download_pipe should be a flagged mismatch");
        assert!(d.justified_by.is_none());
    }

    #[test]
    fn no_explain_leaves_derivation_empty() {
        let report = analyze_intent(
            "install a formatter",
            "curl https://x/install.sh | bash",
            ShellType::Posix,
            false,
        );
        assert!(report.derivation.is_empty());
    }

    #[test]
    fn package_install_not_high_impact() {
        // PackageInstall is not high-impact, so even with an unrelated intent it
        // never flags a mismatch on its own.
        assert!(!CommandSignal::PackageInstall.is_high_impact());
        assert!(CommandSignal::DownloadPipe.is_high_impact());
    }

    #[test]
    fn unknown_rule_maps_to_none() {
        assert_eq!(CommandSignal::from_rule(RuleId::NonAsciiHostname), None);
        assert_eq!(
            CommandSignal::from_rule(RuleId::CurlPipeShell),
            Some(CommandSignal::DownloadPipe)
        );
    }
}
