//! Typed shell preparation shared by the CLI and local controls. The caller
//! chooses a shell and action; this module derives every path and payload.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::trusted_child::TrustedExecutable;

use super::change_plan::{Edit, MutationService, OperationKind, OperationStatus, RequestedChange};
use super::shell_profile::{
    has_executable_tirith_init, is_managed_begin_marker, shell_quote, validate_marker_pairing,
};
use crate::cli::control::identity::BinaryIdentity;
use crate::cli::shell_target::{self, ProfileTarget, ShellTarget};

const BEGIN: &str = "# BEGIN tirith-hook v1";
const END: &str = "# END tirith-hook";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ShellKind {
    Bash,
    Zsh,
    Fish,
    Nushell,
    Powershell,
    Pwsh,
}

impl ShellKind {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            "nu" | "nushell" => Ok(Self::Nushell),
            "powershell" => Ok(Self::Powershell),
            "pwsh" => Ok(Self::Pwsh),
            _ => Err("shell must be bash, zsh, fish, nushell, powershell, or pwsh".into()),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Nushell => "nushell",
            Self::Powershell => "powershell",
            Self::Pwsh => "pwsh",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ShellChange {
    Install {
        shell: ShellKind,
        #[serde(default)]
        force: bool,
    },
    Remove {
        shell: ShellKind,
    },
}

impl ShellChange {
    fn shell(&self) -> ShellKind {
        match self {
            Self::Install { shell, .. } | Self::Remove { shell } => *shell,
        }
    }

    fn kind(&self) -> OperationKind {
        match self {
            Self::Install { .. } => OperationKind::SetupShell,
            Self::Remove { .. } => OperationKind::RemoveIntegration,
        }
    }
}

#[derive(Serialize)]
struct ShellIntent {
    scope: &'static str,
    cwd: Option<String>,
    change: ShellChange,
}

fn intent(change: ShellChange, cwd: Option<&str>) -> Result<ShellIntent, String> {
    let cwd = cwd.map(str::to_owned).or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|path| path.to_str().map(str::to_owned))
    });
    if cwd
        .as_deref()
        .is_some_and(|value| !Path::new(value).is_absolute())
    {
        return Err("shell operation policy scope must be absolute".into());
    }
    Ok(ShellIntent {
        scope: "user",
        cwd,
        change,
    })
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedProfile {
    path: PathBuf,
    scope: PathBuf,
    startup: String,
}

impl ExpectedProfile {
    fn matches(&self, target: &ProfileTarget) -> bool {
        self.path == target.path && self.scope == target.scope && self.startup == target.startup
    }
}

/// Private replay input, never included in browser projections. Exact digest
/// binding prevents a same-version binary or external hook update from turning
/// an already reviewed startup plan into a different activation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PinnedFile {
    invocation: PathBuf,
    canonical: PathBuf,
    digest: String,
    executable: bool,
}

/// A live identity is tied to an open native handle, never a metadata-only
/// digest cache. Reacquisition hashes the current bytes against the journal.
struct HeldShellInput {
    expected: PinnedFile,
    executable: Option<TrustedExecutable>,
    identity: BinaryIdentity,
}

impl HeldShellInput {
    fn capture(path: &Path, executable: bool) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("shell activation input must have an absolute path".into());
        }
        let canonical = path
            .canonicalize()
            .map_err(|_| "shell activation input is unavailable")?;
        let executable = executable
            .then(|| TrustedExecutable::from_absolute(path, &[]))
            .transpose()
            .map_err(|_| "shell activation executable is untrusted")?;
        let identity = if executable.is_some() {
            BinaryIdentity::capture(&canonical)?
        } else {
            // A previously accepted empty external hook remains a valid input.
            // It still retains a native handle and exact empty-content digest.
            BinaryIdentity::capture_input(&canonical)?
        };
        let expected = PinnedFile {
            invocation: path.into(),
            canonical,
            digest: identity.sha256().into(),
            executable: executable.is_some(),
        };
        let held = Self {
            expected,
            executable,
            identity,
        };
        held.revalidate()?;
        Ok(held)
    }

    fn revalidate(&self) -> Result<(), String> {
        self.identity
            .revalidate()
            .map_err(|_| "shell activation executable or hook changed; refresh the plan")?;
        if self.expected.invocation.canonicalize().ok().as_ref() != Some(&self.expected.canonical) {
            return Err("shell activation invocation changed; refresh the plan".into());
        }
        if let Some(executable) = &self.executable {
            executable
                .revalidate()
                .map_err(|_| "shell activation executable is no longer trusted")?;
        }
        Ok(())
    }
}

/// Retained by the operation journal and checked at each protected publication.
/// It captures selected startup destinations, not an environment claim that a
/// browser's parent shell is active or can block a command.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ShellPrecondition {
    shell: ShellKind,
    home: PathBuf,
    uid: Option<u32>,
    profiles: Vec<ExpectedProfile>,
    inputs: Vec<PinnedFile>,
}

impl ShellPrecondition {
    pub(super) fn selected_shell(&self) -> ShellKind {
        self.shell
    }

    fn capture(target: &ShellTarget) -> Result<Self, String> {
        Ok(Self {
            shell: ShellKind::parse(&target.shell)?,
            home: target.operator_home.clone(),
            uid: target.operator_uid,
            profiles: target
                .profiles
                .iter()
                .map(|profile| ExpectedProfile {
                    path: profile.path.clone(),
                    scope: profile.scope.clone(),
                    startup: profile.startup.clone(),
                })
                .collect(),
            inputs: Vec::new(),
        })
    }

    fn validate_selection(&self) -> Result<(), String> {
        let current = shell_target::resolve_for_shell(self.shell.name())?;
        shell_target::require_personal_writer(&current)?;
        if current.operator_home != self.home
            || current.operator_uid != self.uid
            || current.profiles.len() != self.profiles.len()
            || !self
                .profiles
                .iter()
                .zip(&current.profiles)
                .all(|(expected, current)| expected.matches(current))
        {
            return Err("shell profile selection or operator changed; refresh the plan".into());
        }
        Ok(())
    }

    pub(crate) fn retain(&self) -> Result<RetainedShellInputs, String> {
        self.validate_selection()?;
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for expected in &self.inputs {
            let held = HeldShellInput::capture(&expected.invocation, expected.executable)?;
            if &held.expected != expected {
                return Err(
                    "shell activation input bytes or selection changed; refresh the plan".into(),
                );
            }
            inputs.push(held);
        }
        let retained = RetainedShellInputs {
            expected: self.clone(),
            inputs,
        };
        retained.revalidate()?;
        Ok(retained)
    }

    pub(crate) fn validate_undo(&self) -> Result<(), String> {
        let current = shell_target::resolve_for_shell(self.shell.name())?;
        shell_target::require_personal_writer(&current)?;
        if current.operator_home != self.home || current.operator_uid != self.uid {
            return Err("shell operation operator changed; refresh the undo decision".into());
        }
        // Compensation restores captured bytes in the original held scopes.
        // An executable upgrade or newly selected startup file does not grant
        // authority over other paths; each old owned postimage is still checked.
        Ok(())
    }
}

/// Retain exact activation input handles throughout one preparation or apply.
/// Deserializing a journal never restores this lease: retry must hash again.
pub(crate) struct RetainedShellInputs {
    expected: ShellPrecondition,
    inputs: Vec<HeldShellInput>,
}

impl RetainedShellInputs {
    fn capture(target: &ShellTarget) -> Result<Self, String> {
        Ok(Self {
            expected: ShellPrecondition::capture(target)?,
            inputs: Vec::new(),
        })
    }

    fn capture_input(&mut self, path: &Path, executable: bool) -> Result<(), String> {
        let input = HeldShellInput::capture(path, executable)?;
        self.expected.inputs.push(input.expected.clone());
        self.inputs.push(input);
        Ok(())
    }

    pub(crate) fn revalidate_for(&self, expected: &ShellPrecondition) -> Result<(), String> {
        if expected != &self.expected {
            return Err("retained shell inputs do not belong to this immutable operation".into());
        }
        self.revalidate()
    }

    fn revalidate(&self) -> Result<(), String> {
        self.expected.validate_selection()?;
        for input in &self.inputs {
            input.revalidate()?;
        }
        Ok(())
    }
}

enum PreparedEdit {
    Hook(Option<String>),
    Whole(String),
}

struct PreparedStep {
    target: PathBuf,
    scope: PathBuf,
    before: Option<String>,
    edit: PreparedEdit,
    activation: bool,
    description: &'static str,
}

impl PreparedStep {
    fn request(&self) -> RequestedChange {
        RequestedChange {
            target: self.target.clone(),
            scope_root: self.scope.clone(),
            edit: match &self.edit {
                PreparedEdit::Hook(block) => Edit::ShellHook {
                    block: block.clone(),
                },
                PreparedEdit::Whole(text) => Edit::WholeFile(text.clone()),
            },
            activation: self.activation,
            description: self.description.into(),
        }
    }
}

#[derive(Serialize)]
struct ProfilePreview {
    target: PathBuf,
    startup: String,
    action: &'static str,
    ownership: &'static str,
}

pub(crate) struct PreparedShell {
    pub snapshot: EffectivePolicySnapshot,
    pub compiled: tirith_core::redact::CompiledCustomPatterns,
    target: ShellTarget,
    intent: ShellIntent,
    retained: RetainedShellInputs,
    steps: Vec<PreparedStep>,
    profiles: Vec<ProfilePreview>,
    verification_profile_inputs: Vec<super::change_plan::SetupVerificationDocument>,
    changed: bool,
}

pub(crate) type PreparedShellParts = (
    Vec<RequestedChange>,
    BTreeMap<PathBuf, Option<String>>,
    ShellPrecondition,
);

impl PreparedShell {
    pub(crate) fn capture(change: ShellChange, cwd: Option<&str>) -> Result<Self, String> {
        let binary = if matches!(&change, ShellChange::Install { .. }) {
            Some(super::run_impl::resolve_tirith_bin(false)?)
        } else {
            None
        };
        Self::capture_with_binary(change, cwd, binary.as_deref())
    }

    pub(super) fn capture_with_binary(
        change: ShellChange,
        cwd: Option<&str>,
        binary: Option<&str>,
    ) -> Result<Self, String> {
        let intent = intent(change, cwd)?;
        let target = shell_target::resolve_for_shell(intent.change.shell().name())?;
        shell_target::require_personal_writer(&target)?;
        if let Some(reason) = &target.unsupported_reason {
            return Err(reason.clone());
        }
        let snapshot =
            EffectivePolicySnapshot::resolve(intent.cwd.as_deref(), ResolutionMode::Runtime);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ),
        );
        let mut prepared = Self {
            retained: RetainedShellInputs::capture(&target)?,
            target,
            intent,
            snapshot,
            compiled,
            steps: Vec::new(),
            profiles: Vec::new(),
            verification_profile_inputs: Vec::new(),
            changed: false,
        };
        let desired = match &prepared.intent.change {
            ShellChange::Install { shell, .. } => {
                let binary =
                    binary.ok_or("shell setup requires the validated running executable")?;
                prepared.retained.capture_input(Path::new(binary), true)?;
                let line = if *shell == ShellKind::Nushell {
                    prepared.prepare_nushell_source()?
                } else {
                    init_line(*shell, binary)
                };
                Some(format!("{BEGIN}\n{line}\n{END}\n"))
            }
            ShellChange::Remove { .. } => None,
        };
        let profiles = removal_candidates(
            &prepared.target,
            matches!(prepared.intent.change, ShellChange::Remove { .. }),
        );
        // Read and validate every target before planning any destination write.
        for profile in profiles {
            let before = super::fs_helpers::read_to_string_scoped(&profile.path, &profile.scope)?;
            prepared.prepare_profile(profile, before, desired.as_deref())?;
        }
        if !prepared.profiles.is_empty()
            && prepared
                .profiles
                .iter()
                .all(|profile| profile.ownership == "manual")
        {
            prepared.steps.clear();
            prepared.changed = false;
        }
        prepared.retained.revalidate()?;
        Ok(prepared)
    }

    fn prepare_profile(
        &mut self,
        profile: ProfileTarget,
        before: Option<String>,
        desired: Option<&str>,
    ) -> Result<(), String> {
        if matches!(&self.intent.change, ShellChange::Install { .. }) {
            self.verification_profile_inputs.push(
                super::change_plan::SetupVerificationDocument::observed(
                    &profile.path,
                    &profile.scope,
                    before.as_deref(),
                )?,
            );
        }
        let original = before.as_deref().unwrap_or_default();
        validate_marker_pairing(original)?;
        let blocks = block_ranges(original);
        let manual = blocks.is_empty() && has_executable_tirith_init(original);
        let action;
        let edit;
        match &self.intent.change {
            ShellChange::Install { force, .. } => {
                let desired = desired.expect("install has a derived block");
                if manual {
                    action = "preserve-manual";
                    edit = None;
                } else if blocks.len() == 1 && &original[blocks[0].0..blocks[0].1] == desired {
                    action = "unchanged";
                    edit = Some(PreparedEdit::Hook(Some(desired.into())));
                } else {
                    if !blocks.is_empty() && !force {
                        return Err("shell hook has different content or duplicate blocks; review a force repair plan".into());
                    }
                    action = if blocks.is_empty() {
                        "install"
                    } else {
                        "repair"
                    };
                    self.changed = true;
                    edit = Some(
                        if blocks.len() <= 1
                            && blocks.iter().all(|&(start, end)| {
                                original[start..end].lines().next() == Some(BEGIN)
                            })
                        {
                            PreparedEdit::Hook(Some(desired.into()))
                        } else {
                            // Duplicate/future-version blocks have ambiguous relative
                            // placement. Bind the whole original for conservative
                            // repair/undo while preserving every unowned byte.
                            let mut output = without_blocks(original, &blocks);
                            if !output.is_empty() && !output.ends_with('\n') {
                                output.push('\n');
                            }
                            output.push_str(desired);
                            PreparedEdit::Whole(output)
                        },
                    );
                }
            }
            ShellChange::Remove { .. } => {
                if blocks.is_empty() {
                    action = if manual {
                        "preserve-manual"
                    } else {
                        "unchanged"
                    };
                    edit = None;
                } else {
                    action = "remove";
                    self.changed = true;
                    edit = Some(
                        if blocks.len() == 1
                            && original[blocks[0].0..blocks[0].1].lines().next() == Some(BEGIN)
                        {
                            PreparedEdit::Hook(None)
                        } else {
                            PreparedEdit::Whole(without_blocks(original, &blocks))
                        },
                    );
                }
            }
        }
        self.profiles.push(ProfilePreview {
            target: profile.path.clone(),
            startup: profile.startup,
            action,
            ownership: if manual {
                "manual"
            } else if blocks.is_empty() {
                "absent"
            } else {
                "managed-marker"
            },
        });
        if let Some(edit) = edit {
            self.steps.push(PreparedStep {
                target: profile.path,
                scope: profile.scope,
                before,
                edit,
                activation: true,
                description: match self.intent.change {
                    ShellChange::Install { .. } => {
                        "Configure the selected personal shell startup file"
                    }
                    ShellChange::Remove { .. } => "Remove only the managed Tirith startup block",
                },
            });
        }
        Ok(())
    }

    fn prepare_nushell_source(&mut self) -> Result<String, String> {
        if let Some(directory) = crate::cli::init::find_hook_dir_readonly() {
            let directory = directory
                .canonicalize()
                .map_err(|_| "Nushell hook directory is unavailable")?;
            let hook = directory.join("lib/nushell-hook.nu");
            self.retained.capture_input(&hook, false)?;
            return Ok(format!(
                "{}\nsource {}\n{}",
                crate::cli::init::integration_stamp("nushell", &directory),
                shell_quote(path_text(&hook)?, "nushell"),
                crate::cli::init::integration_handoff_cleanup("nushell")
            ));
        }
        let data = tirith_core::policy::data_dir().ok_or("cannot locate personal hook storage")?;
        let directory = data.join("shell");
        let version = format!("{}\n", env!("CARGO_PKG_VERSION"));
        for (name, contents) in [
            ("lib/bash-hook.bash", crate::assets::BASH_HOOK),
            ("lib/zsh-hook.zsh", crate::assets::ZSH_HOOK),
            ("lib/fish-hook.fish", crate::assets::FISH_HOOK),
            ("lib/powershell-hook.ps1", crate::assets::POWERSHELL_HOOK),
            ("lib/nushell-hook.nu", crate::assets::NUSHELL_HOOK),
            (".hooks-version", version.as_str()),
        ] {
            let target = directory.join(name);
            let before = super::fs_helpers::read_to_string_scoped(&target, &data)?;
            self.changed |= before.as_deref() != Some(contents);
            // Retain already-current assets too, so activation cannot silently
            // source a different generation during a multi-file repair.
            self.steps.push(PreparedStep {
                target,
                scope: data.clone(),
                before,
                edit: PreparedEdit::Whole(contents.into()),
                activation: false,
                description: "Stage the embedded shell hook before startup activation",
            });
        }
        Ok(format!(
            "{}\nsource {}\n{}",
            crate::cli::init::integration_handoff("nushell", env!("CARGO_PKG_VERSION")),
            shell_quote(
                path_text(&directory.join("lib/nushell-hook.nu"))?,
                "nushell"
            ),
            crate::cli::init::integration_handoff_cleanup("nushell")
        ))
    }

    pub(crate) fn projection(&self) -> Value {
        let mut value = serde_json::json!({"schema_version":1,"kind":"shell_preview","applied":false,
            "shell":self.target,"profiles":self.profiles,"change":self.intent.change,
            "policy_identity":self.snapshot.identity,"step_count":self.steps.len(),
            "activation_required":matches!(self.intent.change, ShellChange::Install {..}),
            "verified_blocking":false,"verification_source":"startup-configuration-only"});
        redact_shell_projection(&mut value, &self.compiled);
        tirith_core::verdict::bound_json_value_for_output(value)
    }

    pub(crate) fn setup_parts(&self) -> Result<PreparedShellParts, String> {
        self.retained.revalidate()?;
        self.snapshot
            .revalidate_inputs()
            .map_err(|e| e.to_string())?;
        if !self.changed {
            return Ok((Vec::new(), BTreeMap::new(), self.retained.expected.clone()));
        }
        Ok((
            self.steps.iter().map(PreparedStep::request).collect(),
            self.steps
                .iter()
                .map(|step| (step.target.clone(), step.before.clone()))
                .collect(),
            self.retained.expected.clone(),
        ))
    }

    pub(crate) fn verification_intent(
        &self,
    ) -> Result<super::change_plan::SetupVerificationIntent, String> {
        if !matches!(&self.intent.change, ShellChange::Install { .. }) {
            return Err("removal cannot request fresh-shell activation".into());
        }
        self.retained.revalidate()?;
        let unchanged = self
            .verification_profile_inputs
            .iter()
            .filter(|input| {
                !self.changed || !self.steps.iter().any(|step| input.is_path(&step.target))
            })
            .cloned()
            .collect();
        super::change_plan::SetupVerificationIntent::for_shell(
            self.intent.change.shell(),
            unchanged,
        )
    }

    pub(crate) fn plan(&self, id: &str) -> Result<Option<OperationStatus>, String> {
        let service = MutationService::current()?;
        if let Some(status) =
            service.status_for_intent(id, self.intent.change.kind(), &self.intent)?
        {
            return Ok(Some(status));
        }
        if !self.changed {
            return service
                .complete_noop_with_intent(
                    id,
                    self.intent.change.kind(),
                    &self.snapshot,
                    &self.intent,
                )
                .map(Some);
        }
        self.retained.revalidate()?;
        let expected: BTreeMap<_, _> = self
            .steps
            .iter()
            .map(|step| (step.target.clone(), step.before.clone()))
            .collect();
        service
            .plan_shell_change_with_intent(
                id,
                self.intent.change.kind(),
                super::change_plan::PlanChanges {
                    requests: self.steps.iter().map(PreparedStep::request).collect(),
                    preimages: &expected,
                },
                &self.snapshot,
                &self.intent,
                self.retained.expected.clone(),
            )
            .map(Some)
    }
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| "shell activation path is not valid UTF-8".into())
}

fn init_line(shell: ShellKind, binary: &str) -> String {
    let name = shell.name();
    let executable = shell_quote(binary, name);
    match shell {
        ShellKind::Fish => format!("{executable} init --shell fish | source"),
        ShellKind::Powershell | ShellKind::Pwsh => {
            format!("Invoke-Expression (& {executable} init --shell {name})")
        }
        _ => format!("eval \"$({executable} init --shell {name})\""),
    }
}

fn removal_candidates(target: &ShellTarget, remove: bool) -> Vec<ProfileTarget> {
    let mut profiles = target.profiles.clone();
    if remove && target.shell == "bash" {
        for name in [".bash_profile", ".bash_login", ".profile"] {
            let path = target.operator_home.join(name);
            if !profiles.iter().any(|profile| profile.path == path) {
                profiles.push(ProfileTarget {
                    path,
                    scope: target.operator_home.clone(),
                    startup: "interactive-login".into(),
                });
            }
        }
    }
    profiles
}

fn block_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let marker = line.trim_end_matches(['\r', '\n']);
        if is_managed_begin_marker(marker) {
            start = Some(offset);
        } else if marker == END {
            if let Some(start) = start.take() {
                ranges.push((start, offset + line.len()));
            }
        }
        offset += line.len();
    }
    ranges
}

fn without_blocks(text: &str, blocks: &[(usize, usize)]) -> String {
    let mut output = String::new();
    let mut offset = 0;
    for &(start, end) in blocks {
        output.push_str(&text[offset..start]);
        offset = end;
    }
    output.push_str(&text[offset..]);
    output
}

/// CLI adapter over the same derived plan used by browser controls.
pub(crate) fn run_cli(shell: Option<&str>, remove: bool, force: bool, dry_run: bool) -> i32 {
    let outcome = (|| {
        let shell = match shell {
            Some(shell) => ShellKind::parse(shell)?,
            None => {
                let target = shell_target::inspect_current()?;
                shell_target::require_personal_writer(&target)?;
                if let Some(reason) = target.unsupported_reason {
                    return Err(reason);
                }
                ShellKind::parse(&target.shell)?
            }
        };
        if remove {
            return super::shell_profile::remove_shell_hook(shell.name(), dry_run);
        }
        let prepared = PreparedShell::capture(ShellChange::Install { shell, force }, None)?;
        super::shell_profile::apply_prepared_shell(prepared, dry_run)?;
        if !dry_run {
            eprintln!("tirith: open a fresh {} session to activate the configuration; current interception remains unverified", shell.name());
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            eprintln!(
                "tirith setup: {}",
                tirith_core::output::sanitize_human_field(&error, &[])
            );
            1
        }
    }
}

fn redact_target(value: &mut Value, compiled: &tirith_core::redact::CompiledCustomPatterns) {
    // These fields may contain native paths, process output or display text.
    // Shell/startup/source names are protocol values generated by our resolver.
    for key in [
        "operator_home",
        "executable",
        "version",
        "unsupported_reason",
    ] {
        if let Some(field) = value.get_mut(key) {
            tirith_core::redact::redact_json_strings(field, compiled);
        }
    }
    if let Some(profiles) = value.get_mut("profiles").and_then(Value::as_array_mut) {
        for profile in profiles {
            for key in ["path", "scope"] {
                if let Some(field) = profile.get_mut(key) {
                    tirith_core::redact::redact_json_strings(field, compiled);
                }
            }
        }
    }
}

fn redact_shell_projection(
    value: &mut Value,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    for key in ["shell", "target"] {
        if let Some(target) = value.get_mut(key).filter(|target| target.is_object()) {
            redact_target(target, compiled);
        }
    }
    if let Some(profiles) = value.get_mut("profiles").and_then(Value::as_array_mut) {
        for profile in profiles {
            for key in ["path", "target"] {
                if let Some(field) = profile.get_mut(key) {
                    tirith_core::redact::redact_json_strings(field, compiled);
                }
            }
        }
    }
}

/// A repeated request looks up the immutable high-level intent before target
/// resolution or asset preparation, so a lost response cannot create a new plan.
pub(crate) fn prepare(id: &str, change: ShellChange, cwd: Option<&str>) -> Result<Value, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "operation ID must be a UUID")?;
    let intent = intent(change.clone(), cwd)?;
    let service = MutationService::current()?;
    if let Some(status) = service.status_for_intent(id, change.kind(), &intent)? {
        let snapshot =
            EffectivePolicySnapshot::resolve(intent.cwd.as_deref(), ResolutionMode::Runtime);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ),
        );
        return Ok(
            serde_json::json!({"schema_version":1,"kind":"shell_plan","reused":true,"unchanged":status.no_op,
            "operation":crate::cli::profile::status_projection(&status,&compiled)?}),
        );
    }
    let prepared = PreparedShell::capture(change, cwd)?;
    let operation = prepared
        .plan(id)?
        .as_ref()
        .map(|status| crate::cli::profile::status_projection(status, &prepared.compiled))
        .transpose()?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"shell_plan","applied":false,
        "preview":prepared.projection(),"unchanged":operation.as_ref().is_some_and(|status| status["no_op"] == true),"operation":operation}),
    )
}

/// Read startup configuration only. This never spawns a shell, asks a host to
/// run a command, or promotes inherited flags to current verified protection.
pub(crate) fn inspect(shell: ShellKind, cwd: Option<&str>) -> Result<Value, String> {
    let target = shell_target::resolve_for_shell(shell.name())?;
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
        &tirith_core::policy::captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns),
    );
    let profiles: Vec<Value> = target
        .profiles
        .iter()
        .map(|profile| {
            let result = super::fs_helpers::read_to_string_scoped(&profile.path, &profile.scope);
            let state = match result {
                Ok(Some(text)) if validate_marker_pairing(&text).is_err() => {
                    "malformed-managed-markers"
                }
                Ok(Some(text)) if !block_ranges(&text).is_empty() => {
                    "managed-block-present-unverified"
                }
                Ok(Some(text)) if has_executable_tirith_init(&text) => {
                    "manual-activation-present-unverified"
                }
                Ok(_) => "absent",
                Err(_) => "unreadable-or-unsafe",
            };
            serde_json::json!({"path":profile.path,"startup":profile.startup,"state":state})
        })
        .collect();
    let mut value = serde_json::json!({"schema_version":1,"kind":"shell_configuration","target":target,
        "profiles":profiles,"policy_identity":snapshot.identity,"verified_blocking":false,"fresh":false,
        "source":"startup-configuration-only","next_step":"Activate the configured shell and verify interception in that shell; configuration inspection does not execute a blocking probe."});
    redact_shell_projection(&mut value, &compiled);
    Ok(tirith_core::verdict::bound_json_value_for_output(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn shell_plan_is_read_only_until_apply_and_preserves_unrelated_profile_edits() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let prepared = PreparedShell::capture(
                ShellChange::Install {
                    shell: ShellKind::Bash,
                    force: false,
                },
                None,
            )
            .unwrap();
            assert!(!home.join(".bashrc").exists());
            assert!(!home.join(".bash_profile").exists());
            assert_eq!(prepared.projection()["verified_blocking"], false);
            let id = uuid::Uuid::new_v4().to_string();
            prepared.plan(&id).unwrap().unwrap();
            assert!(!home.join(".bashrc").exists());
            std::fs::write(home.join(".bashrc"), "# unrelated local edit\n").unwrap();
            let service = MutationService::current().unwrap();
            assert_eq!(
                service.apply(&id, &prepared.snapshot).unwrap().state,
                super::super::change_plan::JobState::Completed
            );
            let text = std::fs::read_to_string(home.join(".bashrc")).unwrap();
            assert!(text.starts_with("# unrelated local edit\n"));
            assert_eq!(text.matches(BEGIN).count(), 1);
            assert!(std::fs::read_to_string(home.join(".bash_profile"))
                .unwrap()
                .contains("init --shell bash"));
            assert_eq!(
                service
                    .undo(&id, &prepared.snapshot.refresh_runtime())
                    .unwrap()
                    .state,
                super::super::change_plan::JobState::Undone
            );
            assert_eq!(
                std::fs::read_to_string(home.join(".bashrc")).unwrap(),
                "# unrelated local edit\n"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn planned_shell_selection_drift_refuses_before_any_profile_write() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            std::fs::write(home.join(".profile"), "# existing login profile\n").unwrap();
            let prepared = PreparedShell::capture(
                ShellChange::Install {
                    shell: ShellKind::Bash,
                    force: false,
                },
                None,
            )
            .unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            prepared.plan(&id).unwrap().unwrap();
            std::fs::write(home.join(".bash_profile"), "# now selected\n").unwrap();
            let status = MutationService::current()
                .unwrap()
                .apply(&id, &prepared.snapshot)
                .unwrap();
            assert_eq!(
                status.state,
                super::super::change_plan::JobState::RefreshRequired
            );
            assert!(!home.join(".bashrc").exists());
            assert_eq!(
                std::fs::read_to_string(home.join(".profile")).unwrap(),
                "# existing login profile\n"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn manual_activation_is_preserved_without_a_mutation_plan() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let manual = "eval \"$(tirith init --shell zsh)\"\n# keep my settings";
            std::fs::write(home.join(".zshrc"), manual).unwrap();
            let prepared = PreparedShell::capture(
                ShellChange::Install {
                    shell: ShellKind::Zsh,
                    force: true,
                },
                None,
            )
            .unwrap();
            assert!(
                prepared
                    .plan(&uuid::Uuid::new_v4().to_string())
                    .unwrap()
                    .unwrap()
                    .no_op
            );
            assert_eq!(
                std::fs::read_to_string(home.join(".zshrc")).unwrap(),
                manual
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn repair_of_future_blocks_preserves_bytes_and_refuses_a_stale_whole_document() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let path = home.join(".zshrc");
            let original = "# personal\r\n# BEGIN tirith-hook v27\nold\n# END tirith-hook\n# final without newline";
            std::fs::write(&path, original).unwrap();
            assert!(PreparedShell::capture(
                ShellChange::Install {
                    shell: ShellKind::Zsh,
                    force: false
                },
                None
            )
            .is_err());
            let prepared = PreparedShell::capture(
                ShellChange::Install {
                    shell: ShellKind::Zsh,
                    force: true,
                },
                None,
            )
            .unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            prepared.plan(&id).unwrap().unwrap();
            let changed = format!("{original}\n# intervening edit");
            std::fs::write(&path, &changed).unwrap();
            let status = MutationService::current()
                .unwrap()
                .apply(&id, &prepared.snapshot)
                .unwrap();
            assert_eq!(
                status.state,
                super::super::change_plan::JobState::RefreshRequired
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), changed);
        });
    }

    #[test]
    fn broad_dlp_preserves_protocol_fields_and_redacts_only_display_values() {
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[".+".into()]);
        let mut value = serde_json::json!({"kind":"shell_preview", "policy_identity":"opaque-uuid",
            "change":{"action":"install","shell":"bash","force":false},
            "shell":{"shell":"bash","operator_home":"/private/home","executable":"/private/bash",
                "version":"private process output", "identity_source":"requested-shell-family",
                "profiles":[{"path":"/private/home/.bashrc","scope":"/private/home","startup":"interactive-nonlogin"}]},
            "profiles":[{"target":"/private/home/.bashrc","action":"install","ownership":"managed","state":"absent"}],
            "verification_source":"startup-configuration-only"});
        redact_shell_projection(&mut value, &compiled);
        assert_eq!(value["kind"], "shell_preview");
        assert_eq!(value["change"]["action"], "install");
        assert_eq!(value["change"]["shell"], "bash");
        assert_eq!(value["profiles"][0]["action"], "install");
        assert_eq!(value["profiles"][0]["state"], "absent");
        assert_eq!(value["policy_identity"], "opaque-uuid");
        assert!(!value.to_string().contains("/private"));
        assert!(!value.to_string().contains("private process output"));
    }

    #[test]
    fn typed_input_rejects_arbitrary_paths_commands_and_unknown_shells() {
        assert!(serde_json::from_value::<ShellChange>(
            serde_json::json!({"action":"install","shell":"bash","path":"/tmp/profile"})
        )
        .is_err());
        assert!(serde_json::from_value::<ShellChange>(
            serde_json::json!({"action":"install","shell":"bash","command":"echo unsafe"})
        )
        .is_err());
        assert!(serde_json::from_value::<ShellChange>(
            serde_json::json!({"action":"remove","shell":"cmd"})
        )
        .is_err());
    }

    #[test]
    fn removal_preserves_all_unowned_bytes_and_future_marker_versions() {
        let input = "before\r\n# BEGIN tirith-hook v27\r\nold hook\r\n# END tirith-hook\r\nbetween\n# BEGIN tirith-hook v1\ncurrent hook\n# END tirith-hook\nafter without final newline";
        validate_marker_pairing(input).unwrap();
        assert_eq!(
            without_blocks(input, &block_ranges(input)),
            "before\r\nbetween\nafter without final newline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn precondition_rejects_new_higher_priority_bash_login_target() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            std::fs::write(home.join(".profile"), "personal\n").unwrap();
            let target = shell_target::resolve_for_shell("bash").unwrap();
            let guard = ShellPrecondition::capture(&target).unwrap();
            let held = guard.retain().unwrap();
            held.revalidate().unwrap();
            std::fs::write(home.join(".bash_profile"), "new higher priority\n").unwrap();
            assert!(held.revalidate().is_err());
            assert!(guard.retain().is_err());
        });
    }

    #[test]
    fn retained_empty_hook_preserves_empty_input_compatibility() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("empty-hook");
        std::fs::write(&path, b"").unwrap();
        let held = HeldShellInput::capture(&path, false).unwrap();
        held.revalidate().unwrap();
        assert_eq!(
            held.expected.digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(
            BinaryIdentity::capture(&path).is_err(),
            "empty executable admission stays unchanged"
        );
    }

    #[test]
    fn retained_hook_rejects_identical_replacement_while_original_handle_is_live() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hook");
        let replacement = root.path().join("replacement");
        std::fs::write(&path, b"same hook bytes").unwrap();
        let held = HeldShellInput::capture(&path, false).unwrap();
        std::fs::write(&replacement, b"same hook bytes").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(held.revalidate().is_err());
    }

    #[test]
    fn retained_hook_detects_or_excludes_in_place_changes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hook");
        std::fs::write(&path, b"before").unwrap();
        let held = HeldShellInput::capture(&path, false).unwrap();
        let write = std::fs::write(&path, b"after!");
        #[cfg(windows)]
        {
            assert!(
                write.is_err(),
                "the retained Windows handle excludes writers"
            );
            held.revalidate().unwrap();
        }
        #[cfg(not(windows))]
        {
            write.unwrap();
            assert!(held.revalidate().is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_invocation_alias_and_executable_permission_changes_refuse() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        let alias = root.path().join("alias");
        for path in [&first, &second] {
            std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        symlink(&first, &alias).unwrap();
        let held = HeldShellInput::capture(&alias, true).unwrap();
        std::fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        assert!(
            held.revalidate().is_err(),
            "identical bytes through another alias are not the reviewed selection"
        );
        let held = HeldShellInput::capture(&first, true).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            held.revalidate().is_err(),
            "retention does not bypass executable trust"
        );
    }

    #[cfg(unix)]
    #[test]
    fn journal_resume_reacquires_and_hashes_inputs_after_old_handles_close() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let target = shell_target::resolve_for_shell("bash").unwrap();
            let path = home.join("resume-hook");
            std::fs::write(&path, b"before").unwrap();
            let mut held = RetainedShellInputs::capture(&target).unwrap();
            held.capture_input(&path, false).unwrap();
            let saved = serde_json::to_string(&held.expected).unwrap();
            drop(held);
            let expected: ShellPrecondition = serde_json::from_str(&saved).unwrap();
            std::fs::write(&path, b"after!").unwrap();
            assert!(
                expected.retain().is_err(),
                "durable metadata cannot reuse a closed-handle digest"
            );
            std::fs::write(&path, b"before").unwrap();
            expected.retain().unwrap().revalidate().unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn retained_shell_lease_is_bound_to_the_exact_immutable_precondition() {
        crate::cli::test_harness::with_fake_env(true, |home, _| {
            let target = shell_target::resolve_for_shell("bash").unwrap();
            let path = home.join("bound-hook");
            std::fs::write(&path, b"original").unwrap();
            let mut held = RetainedShellInputs::capture(&target).unwrap();
            held.capture_input(&path, false).unwrap();
            held.revalidate_for(&held.expected).unwrap();
            let mut other = held.expected.clone();
            other.profiles[0].startup.push_str("-changed");
            assert!(held.revalidate_for(&other).is_err());
            let mut other = held.expected.clone();
            other.inputs[0].digest = "0".repeat(64);
            assert!(held.revalidate_for(&other).is_err());
            let mut other = held.expected.clone();
            other.inputs[0].executable = true;
            assert!(held.revalidate_for(&other).is_err());
        });
    }

    #[cfg(unix)]
    #[test]
    fn resumed_shell_apply_refuses_changed_input_but_undo_keeps_owned_compensation() {
        use super::super::change_plan::JobState;
        use std::os::unix::fs::PermissionsExt;
        for apply_before_change in [false, true] {
            crate::cli::test_harness::with_fake_env(true, |home, _| {
                let binary = home.join("retained-shell-executable");
                std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
                std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
                let prepared = PreparedShell::capture_with_binary(
                    ShellChange::Install {
                        shell: ShellKind::Bash,
                        force: false,
                    },
                    None,
                    binary.to_str(),
                )
                .unwrap();
                let id = uuid::Uuid::new_v4().to_string();
                prepared.plan(&id).unwrap().unwrap();
                let policy = prepared.snapshot.clone();
                if apply_before_change {
                    assert_eq!(
                        MutationService::current()
                            .unwrap()
                            .apply(&id, &policy)
                            .unwrap()
                            .state,
                        JobState::Completed
                    );
                }
                drop(prepared);
                // A later caller owns no earlier native input handle.
                std::fs::write(&binary, "#!/bin/sh\nexit 1\n").unwrap();
                let service = MutationService::current().unwrap();
                if apply_before_change {
                    assert_eq!(
                        service.undo(&id, &policy.refresh_runtime()).unwrap().state,
                        JobState::Undone
                    );
                    assert!(!std::fs::read_to_string(home.join(".bashrc"))
                        .unwrap()
                        .contains(BEGIN));
                } else {
                    assert_eq!(
                        service.apply(&id, &policy).unwrap().state,
                        JobState::RefreshRequired
                    );
                    assert!(!home.join(".bashrc").exists());
                    assert!(!home.join(".bash_profile").exists());
                }
            });
        }
    }
}
