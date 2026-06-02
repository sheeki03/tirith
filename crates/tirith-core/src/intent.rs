//! `tirith intend` — intent-vs-command heuristic (M10 ch4).
//!
//! A pure-Rust, no-LLM heuristic that flags when a stated intent ("install a
//! formatter") doesn't justify what the command does (pipe a remote script into
//! a shell). [`IntentBehaviorReport`] has three parts: `intent_signals` (which
//! keyword groups the intent matched), `command_signals` (high-impact behaviors,
//! derived by running [`crate::engine::analyze`] and mapping each fired
//! [`RuleId`](crate::verdict::RuleId)), and `mismatches` (high-impact signals no
//! matched intent justifies — the output).
//!
//! Advisory / Info-only — NEVER blocks; the real verdict comes from `tirith
//! check`. It is a heuristic: an unrecognized phrasing yields no intent signals,
//! so every high-impact signal then reads as unjustified.

use serde::Serialize;

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::tokenize::ShellType;
use crate::verdict::RuleId;

/// A high-impact behavior the command exhibits, derived from the fired engine
/// rule (mapping in [`CommandSignal::from_rule`]). Related rules collapse to one
/// variant so the report stays readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandSignal {
    /// A remote download piped into a shell (`curl … | bash`, `iwr … | iex`).
    DownloadPipe,
    /// Privilege escalation with `sudo` (any M8 ch4 sudo rule).
    Sudo,
    /// Reads credential files or exfiltrates data over the network.
    EnvOrCredentialExfil,
    /// Writes to a shell rc/profile (a persistence foothold).
    ShellRcWrite,
    /// Runs a package-manager install (`pip`/`npm`/Docker/etc.).
    PackageInstall,
    /// Decodes a base64 blob and executes it.
    Base64Execute,
    /// Opens an interactive root shell (`sudo bash`).
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

    /// Whether this signal is worth flagging when the intent does not justify it.
    /// `PackageInstall` is NOT high-impact (it's what most install/build intents
    /// are FOR); the high-impact set is the surprising persistence/exfil/privilege
    /// behaviors.
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

    /// Map an engine [`RuleId`] to a `CommandSignal`, or `None` for rules outside
    /// `intend`'s scope (homograph hostnames, terminal bytes, file-scan findings —
    /// `intend` reasons only about what the command does to the machine).
    pub fn from_rule(rule: RuleId) -> Option<CommandSignal> {
        match rule {
            RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            | RuleId::PsInlineDownloadExecute => Some(CommandSignal::DownloadPipe),

            RuleId::Base64DecodeExecute => Some(CommandSignal::Base64Execute),

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

/// A coarse classification of the stated intent from keyword groups (one
/// sentence can match several). Each class declares which [`CommandSignal`]s it
/// justifies via [`IntentClass::justifies`].
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

    /// The keyword stems that classify an intent into this group (whole-word,
    /// case-insensitive — see [`classify_intent`]).
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

    /// The command signals this intent class JUSTIFIES (an expected consequence,
    /// so not a mismatch). Deliberately narrow: a class justifies only what its
    /// name implies. "install"/"download"/"run a script" justify the download-pipe
    /// shape; "deploy" also privilege; "format"/"test"/"build"/"clean" justify a
    /// package install but NOT a remote pipe-to-shell / sudo / exfil.
    fn justifies(self) -> &'static [CommandSignal] {
        match self {
            IntentClass::Install => &[CommandSignal::PackageInstall],
            IntentClass::Download => &[CommandSignal::DownloadPipe],
            IntentClass::RunScript => &[CommandSignal::DownloadPipe, CommandSignal::Base64Execute],

            // Deploy/release commonly need privilege and may push artifacts.
            IntentClass::Deploy => &[
                CommandSignal::Sudo,
                CommandSignal::PackageInstall,
                CommandSignal::ShellRcWrite,
            ],

            IntentClass::Configure => &[CommandSignal::ShellRcWrite],

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

/// Split the intent into lowercase ASCII-alphanumeric words (punctuation and
/// hyphens are separators, so `"format,lint"` → two words, `"set-up"` → `set`/`up`).
fn intent_words(intent: &str) -> Vec<String> {
    intent
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

/// Classify the intent into [`IntentSignal`]s by whole-word keyword match, in
/// [`IntentClass::ALL`] order (first matching keyword per class).
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

/// The deduped, sorted [`CommandSignal`]s for `command`, derived by running
/// [`crate::engine::analyze`] and mapping each fired rule (so signals stay
/// consistent with `tirith check`).
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
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
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
