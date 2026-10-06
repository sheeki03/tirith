//! Static npm evidence over already validated, bounded archive members.
//!
//! JavaScript support is a bounded lexical capability pass, not a JavaScript
//! evaluator or proof of data flow. It removes comments and distinguishes string
//! contents from call tokens. Templates, escaped/dynamic loading, regex literals
//! and exhausted token budgets have explicit incomplete coverage. Signals are
//! observations or requests for review; neither minification nor a script/native
//! module alone is a malicious-package finding.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{bounded_text, Member, NpmFileKind, NpmInspection, NpmIssueKind};
use crate::tokenize::ShellType;

#[path = "npm_inert_heredoc.rs"]
mod inert_heredoc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmMetadata {
    pub name: String,
    pub version: String,
    pub scripts: BTreeMap<String, String>,
    pub bin: BTreeMap<String, String>,
    pub main: Option<String>,
    pub dependencies: BTreeMap<String, String>,
    pub bundled_dependencies: Vec<String>,
    pub implicit_node_gyp_install: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmCapability {
    LifecycleExecution,
    ProcessSpawn,
    NetworkAccess,
    DynamicEvaluation,
    SensitiveFileAccess,
    NativeModule,
    NativeInitialization,
    NativeBuild,
    CommandLineEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmSignalKind {
    LifecycleScript,
    ImplicitNativeBuild,
    CommandLineEntry,
    CodeCapabilities,
    DownloadToShell,
    EncodedDynamicExecution,
    SensitiveReadWithNetwork,
    NativeArtifact,
    NativeExecutionCombination,
    BundledDependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmSignalLevel {
    Observation,
    Review,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmSignal {
    pub kind: NpmSignalKind,
    pub level: NpmSignalLevel,
    pub member: String,
    pub capabilities: Vec<NpmCapability>,
    /// Declared script events that directly name this file. This does not imply
    /// that every event runs for a registry installation or that a branch runs.
    pub lifecycle_events: Vec<String>,
    pub evidence: String,
}

fn push(inspection: &mut NpmInspection, signal: NpmSignal) {
    if inspection.signals.len() >= inspection.limits.signals {
        inspection.issue(
            NpmIssueKind::SignalLimit,
            None,
            "Signal output reached its configured limit; additional evidence was omitted.",
        );
        return;
    }
    inspection.signals.push(signal);
}

fn signal(
    kind: NpmSignalKind,
    level: NpmSignalLevel,
    member: &str,
    capabilities: Vec<NpmCapability>,
    events: &[String],
    evidence: &str,
) -> NpmSignal {
    NpmSignal {
        kind,
        level,
        member: member.to_owned(),
        capabilities,
        lifecycle_events: events.to_vec(),
        evidence: bounded_text(evidence, 1024),
    }
}

pub(super) fn inspect_members(members: &[Member<'_>], inspection: &mut NpmInspection) {
    let Some(root) = members
        .iter()
        .find(|member| member.path == "package/package.json")
    else {
        inspection.issue(
            NpmIssueKind::MissingMetadata,
            None,
            "The required package/package.json member is absent.",
        );
        return;
    };
    if root.bytes.len() > inspection.limits.metadata_bytes {
        inspection.issue(
            NpmIssueKind::MetadataLimit,
            Some(&root.path),
            "Root package metadata exceeds the configured limit.",
        );
        return;
    }
    let document = std::str::from_utf8(root.bytes)
        .ok()
        .and_then(|text| crate::mcp_lock::parse_json_no_duplicates(text).ok());
    let metadata = document.as_ref().and_then(parse_metadata);
    let Some(mut metadata) = metadata else {
        inspection.issue(NpmIssueKind::InvalidMetadata, Some(&root.path), "Package metadata requires unique JSON keys, a valid name/version and bounded correctly typed scripts, bins and dependencies.");
        return;
    };
    let has_binding_gyp = members.iter().any(|member| {
        member.path == "package/binding.gyp" && member.kind != NpmFileKind::Directory
    });
    metadata.implicit_node_gyp_install = has_binding_gyp
        && !metadata.scripts.contains_key("install")
        && !metadata.scripts.contains_key("preinstall");
    inspection.artifact.name = Some(metadata.name.clone());
    inspection.artifact.version = Some(metadata.version.clone());
    inspection.coverage.metadata_complete = true;
    // npm's _id is supplemental metadata, not an independent authority. When it
    // contradicts name/version, preserve exact bytes and report the contradiction.
    if document
        .as_ref()
        .and_then(|v| v.get("_id"))
        .is_some_and(|id| {
            id.as_str() != Some(format!("{}@{}", metadata.name, metadata.version).as_str())
        })
    {
        inspection.coverage.metadata_complete = false;
        inspection.issue(
            NpmIssueKind::ContradictoryIdentity,
            Some(&root.path),
            "Supplemental package _id contradicts the declared name and version.",
        );
    }
    let by_path: BTreeMap<&str, &Member<'_>> =
        members.iter().map(|m| (m.path.as_str(), m)).collect();
    let mut event_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut explicit_code = BTreeSet::new();
    for (event, command) in &metadata.scripts {
        if !lifecycle_event(event) {
            continue;
        }
        push(inspection, signal(NpmSignalKind::LifecycleScript, NpmSignalLevel::Observation,
            &root.path, vec![NpmCapability::LifecycleExecution], std::slice::from_ref(event),
            &format!("Declared {event} script: {}. Event execution depends on the npm operation and script policy.", bounded_text(command, 512))));
        let events = std::slice::from_ref(event);
        inspect_shell(command, &root.path, events, inspection);
        match literal_script_target(command) {
            Some(target) => {
                if by_path
                    .get(target.as_str())
                    .is_some_and(|member| member.kind != NpmFileKind::Directory)
                {
                    explicit_code.insert(target.clone());
                    event_files.entry(target).or_default().push(event.clone());
                } else {
                    inspection.issue(
                        NpmIssueKind::UnresolvedLifecycle,
                        Some(&root.path),
                        "A lifecycle script directly references a file absent from this artifact.",
                    );
                }
            }
            None => {
                // Shell commands and dependency-provided tools have effects that
                // this offline artifact cannot fully resolve. A harmless-looking
                // build command is still explicitly unresolved, not malware.
                inspection.issue(NpmIssueKind::UnresolvedLifecycle, Some(&root.path), "A lifecycle script depends on shell interpretation, external tools or dynamically selected code.");
            }
        }
    }
    if metadata.implicit_node_gyp_install {
        push(inspection, signal(NpmSignalKind::ImplicitNativeBuild, NpmSignalLevel::Observation,
            "package/binding.gyp", vec![NpmCapability::LifecycleExecution, NpmCapability::NativeBuild],
            &["install".to_owned()], "binding.gyp with no preinstall/install override enables npm's implicit node-gyp rebuild; build effects are unresolved offline."));
        inspection.issue(
            NpmIssueKind::UnresolvedLifecycle,
            Some("package/binding.gyp"),
            "Native build configuration can invoke external tools and is not executed or resolved.",
        );
    }
    for (name, target) in &metadata.bin {
        let Some(path) = package_relative(target) else {
            inspection.coverage.metadata_complete = false;
            inspection.issue(
                NpmIssueKind::InvalidMetadata,
                Some(&root.path),
                "A declared bin target is outside the package or has an ambiguous path.",
            );
            continue;
        };
        push(
            inspection,
            signal(
                NpmSignalKind::CommandLineEntry,
                NpmSignalLevel::Observation,
                &path,
                vec![NpmCapability::CommandLineEntry],
                &[],
                &format!(
                    "Declared command-line entry {name}; execution requires a caller to invoke it."
                ),
            ),
        );
        if !by_path
            .get(path.as_str())
            .is_some_and(|member| member.kind != NpmFileKind::Directory)
        {
            inspection.coverage.metadata_complete = false;
            inspection.issue(
                NpmIssueKind::InvalidMetadata,
                Some(&root.path),
                "A declared bin target is absent from the artifact.",
            );
        }
        explicit_code.insert(path);
    }
    if let Some(main) = &metadata.main {
        if let Some(path) = package_relative(main) {
            if by_path.contains_key(path.as_str()) {
                explicit_code.insert(path);
            } else {
                inspection.issue(
                    NpmIssueKind::UnsupportedCode,
                    Some(&root.path),
                    "The declared main entry requires unresolved extension or directory selection.",
                );
            }
        } else {
            inspection.coverage.metadata_complete = false;
            inspection.issue(
                NpmIssueKind::InvalidMetadata,
                Some(&root.path),
                "The declared main entry has an ambiguous or external path.",
            );
        }
    }
    if document
        .as_ref()
        .is_some_and(|value| value.get("exports").is_some() || value.get("imports").is_some())
    {
        inspection.issue(NpmIssueKind::UnsupportedCode, Some(&root.path), "Conditional exports/imports resolution is not proven by local lexical inspection; recognized code members are still analyzed.");
    }
    for name in &metadata.bundled_dependencies {
        push(inspection, signal(NpmSignalKind::BundledDependency, NpmSignalLevel::Observation,
            &root.path, vec![], &[], &format!("Declared bundled dependency {name}; bundled bytes are inspected as archive members, not resolved from a registry.")));
    }
    inspection.metadata = Some(metadata);
    let mut native_files = 0usize;
    for member in members {
        let kind = if member.kind == NpmFileKind::Resource && explicit_code.contains(&member.path) {
            NpmFileKind::JavaScript
        } else {
            member.kind
        };
        if matches!(kind, NpmFileKind::Directory | NpmFileKind::Resource) {
            continue;
        }
        if member.path == root.path {
            continue;
        }
        if member.kind == NpmFileKind::Metadata {
            // Nested package manifests can declare bundled dependency hooks.
            // Their resolution and install ordering are outside this local pass.
            inspection.issue(NpmIssueKind::UnresolvedLifecycle, Some(&member.path), "Nested package metadata is retained as an exact member; dependency lifecycle resolution is not performed.");
            continue;
        }
        if member.kind == NpmFileKind::NestedArchive {
            inspection.issue(
                NpmIssueKind::NestedArchive,
                Some(&member.path),
                "Nested archive content is not recursively inspected.",
            );
            continue;
        }
        if matches!(
            member.kind,
            NpmFileKind::OtherCode | NpmFileKind::WebAssembly
        ) {
            inspection.issue(NpmIssueKind::UnsupportedCode, Some(&member.path), "This executable or source format has no complete static analyzer in this inspection version.");
            continue;
        }
        if member.bytes.len() > inspection.limits.code_member_bytes
            || inspection.coverage.inspected_code_files >= inspection.limits.code_files
            || member.bytes.len() as u64
                > (inspection.limits.total_code_bytes as u64)
                    .saturating_sub(inspection.coverage.inspected_code_bytes)
        {
            inspection.issue(NpmIssueKind::CodeLimit, Some(&member.path), "Code analysis exceeds a member, aggregate byte or file-count limit; whole-member identity is retained.");
            continue;
        }
        let events = event_files
            .get(&member.path)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if member.kind == NpmFileKind::Native {
            if native_files >= inspection.limits.native_files {
                inspection.issue(
                    NpmIssueKind::CodeLimit,
                    Some(&member.path),
                    "Native analyzer count reached its configured limit.",
                );
                continue;
            }
            native_files += 1;
            inspect_native(member, events, inspection);
        } else if let Ok(text) = std::str::from_utf8(member.bytes) {
            if kind == NpmFileKind::JavaScript {
                inspect_js(text, &member.path, events, inspection);
            } else {
                inspect_shell(text, &member.path, events, inspection);
                inspection.issue(NpmIssueKind::UnsupportedCode, Some(&member.path), "Shell code receives a bounded command-pattern pass; full shell effects are not resolved.");
            }
        } else {
            inspection.issue(
                NpmIssueKind::UnsupportedCode,
                Some(&member.path),
                "Source bytes are not valid UTF-8; no lossy source interpretation is used.",
            );
        }
        inspection.coverage.inspected_code_files += 1;
        inspection.coverage.inspected_code_bytes += member.bytes.len() as u64;
    }
}

fn parse_metadata(document: &Value) -> Option<NpmMetadata> {
    let object = document.as_object()?;
    let name = object.get("name")?.as_str()?;
    let version = object.get("version")?.as_str()?;
    if !valid_name(name)
        || version.is_empty()
        || version.len() > 256
        || version.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let scripts = string_map(object.get("scripts"), 128, 128, 8192)?;
    let main = match object.get("main") {
        None => None,
        Some(Value::String(path)) if !path.is_empty() && path.len() <= 4096 => Some(path.clone()),
        _ => return None,
    };
    let dependencies = string_map(object.get("dependencies"), 2048, 214, 2048)?;
    if dependencies.keys().any(|name| !valid_name(name)) {
        return None;
    }
    let bin = match object.get("bin") {
        Some(Value::String(path)) if path.len() <= 4096 => {
            BTreeMap::from([(name.rsplit('/').next()?.to_owned(), path.clone())])
        }
        value => string_map(value, 128, 214, 4096)?,
    };
    let bundled = match (
        object.get("bundledDependencies"),
        object.get("bundleDependencies"),
    ) {
        (Some(a), Some(b)) if a != b => return None,
        (Some(a), _) | (_, Some(a)) => Some(a),
        _ => None,
    };
    let bundled_dependencies = match bundled {
        None | Some(Value::Bool(false)) => Vec::new(),
        Some(Value::Bool(true)) => dependencies.keys().cloned().collect(),
        Some(Value::Array(values)) if values.len() <= 2048 => {
            let mut names = BTreeSet::new();
            for value in values {
                let name = value.as_str()?;
                if !valid_name(name) || !names.insert(name.to_owned()) {
                    return None;
                }
            }
            names.into_iter().collect()
        }
        _ => return None,
    };
    Some(NpmMetadata {
        name: name.to_owned(),
        version: version.to_owned(),
        scripts,
        bin,
        main,
        dependencies,
        bundled_dependencies,
        implicit_node_gyp_install: false,
    })
}

fn string_map(
    value: Option<&Value>,
    count: usize,
    key_bytes: usize,
    value_bytes: usize,
) -> Option<BTreeMap<String, String>> {
    let Some(value) = value else {
        return Some(BTreeMap::new());
    };
    let values = value.as_object()?;
    if values.len() > count {
        return None;
    }
    values
        .iter()
        .map(|(key, value)| {
            let value = value.as_str()?;
            if key.is_empty()
                || key.len() > key_bytes
                || value.len() > value_bytes
                || key.chars().any(char::is_control)
                || value.contains('\0')
            {
                return None;
            }
            Some((key.clone(), value.to_owned()))
        })
        .collect()
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    let component = |part: &str| {
        !part.is_empty()
            && !part.starts_with(['.', '_'])
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
    };
    match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, package)| component(scope) && component(package)),
        None => component(name),
    }
}

fn lifecycle_event(event: &str) -> bool {
    matches!(
        event,
        "preinstall"
            | "install"
            | "postinstall"
            | "prepublish"
            | "preprepare"
            | "prepare"
            | "postprepare"
            | "prepublishOnly"
            | "prepack"
            | "postpack"
            | "publish"
            | "postpublish"
            | "dependencies"
    )
}

fn package_relative(path: &str) -> Option<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
    let limits = super::NpmLimits::default();
    super::normalize_path(&format!("package/{path}"), false, &limits).ok()
}

/// Only literal node/sh file invocations have a direct member edge. Flags,
/// substitutions, chains, redirections and npm-provided executable resolution
/// remain explicit unknowns. This narrow edge never controls whether other code
/// files are read.
fn literal_script_target(command: &str) -> Option<String> {
    use crate::rules::command::{command_word_is_statically_bound, normalize_shell_token};
    let shell = ShellType::Posix;
    // Anything that can expand, redirect, group or start a comment keeps the
    // edge unknown, even inside quotes.
    if command.contains(['$', '`', '\\', '(', ')', '<', '>'])
        || command.split_whitespace().any(|word| word.starts_with('#'))
    {
        return None;
    }
    let segments = crate::tokenize::tokenize(command, shell);
    let [segment] = segments.as_slice() else {
        return None;
    };
    let (Some(program), [target]) = (segment.command.as_deref(), segment.args.as_slice()) else {
        return None;
    };
    if !command_word_is_statically_bound(program, shell)
        || !command_word_is_statically_bound(target, shell)
    {
        return None;
    }
    let target = normalize_shell_token(target, shell);
    if !matches!(
        normalize_shell_token(program, shell).as_str(),
        "node" | "nodejs" | "sh" | "bash" | "zsh"
    ) || target.starts_with('-')
    {
        return None;
    }
    package_relative(&target)
}

/// Nesting depth and body count for the brace/function/subshell and
/// substitution descent in [`fetch_feeds_shell`] (each pass of [`descend`]
/// has its own count). Package scripts are bounded text, so this only keeps
/// adversarial nesting from turning one file into unbounded work. Hitting
/// either bound is incomplete coverage, never "no pipeline".
const SHELL_BODY_DEPTH: usize = 8;
const SHELL_BODY_BUDGET: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShellFetch {
    Found,
    NotFound,
    /// The descent stopped at its depth or body bound before finishing.
    Bounded,
}

/// A download command piped straight into a shell. Uses the core tokenizer and
/// the pipe-to-interpreter resolution, so variables (`curl $U | bash`),
/// wrappers (`| sudo bash`) and redirections (`| sh >/dev/null`) are handled.
/// Only a literal downloader as the pipe source qualifies: `echo curl … | sh` is
/// not a download claim.
fn feeds_shell(text: &str) -> bool {
    crate::rules::command::fetch_piped_interpreters(text, ShellType::Posix)
        .iter()
        .any(|interpreter| {
            matches!(
                interpreter.as_str(),
                "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "ash"
            )
        })
}

/// The core tokenizer splits neither `|` nor newlines inside `{ ... }`,
/// `( ... )` or a substitution, so a pipeline inside a brace group, function
/// body, subshell, command substitution (`$(...)`, backticks) or process
/// substitution is only visible after descending into that body.
/// `substitutions` is the text to read substitutions from (heredoc bodies
/// blanked, see [`without_heredoc_bodies`]); it is `None` for a group body,
/// whose substitutions were already read from the text around it, and in the
/// group-only pass of [`descend`].
fn fetch_feeds_shell(
    text: &str,
    substitutions: Option<&str>,
    depth: usize,
    budget: &mut usize,
) -> ShellFetch {
    if feeds_shell(text) {
        return ShellFetch::Found;
    }
    let mut bounded = false;
    for mut segment in crate::tokenize::tokenize(text, ShellType::Posix) {
        // The tokenizer does not split words at newlines, so a `{` followed by
        // a newline comes back inside a longer command word ("{\n",
        // "{\n{\n", "{\ncurl"). A segment that starts with `{` and blank
        // space is a brace group whatever that word looks like.
        let raw = segment.raw.trim_start();
        if raw.starts_with('{') && raw[1..].starts_with(char::is_whitespace) {
            segment.command = Some("{".to_string());
        }
        let body = crate::extract::literal_posix_brace_group_body(&segment)
            .ok()
            .flatten()
            .or_else(|| {
                crate::extract::literal_posix_function_definition(&segment)
                    .ok()
                    .flatten()
                    .map(|(_, body)| body)
            })
            .or_else(|| {
                crate::extract::literal_posix_subshell_group_body(&segment)
                    .ok()
                    .flatten()
            })
            // A trailing redirection (`{ ...; } >log`) does not change what
            // runs inside the group.
            .or_else(|| crate::extract::posix_compound_body_any_suffix(&segment.raw));
        let Some(body) = body else {
            continue;
        };
        if *budget == 0 {
            return ShellFetch::Bounded;
        }
        if depth >= SHELL_BODY_DEPTH {
            bounded = true;
            continue;
        }
        *budget -= 1;
        match fetch_feeds_shell(&body, None, depth + 1, budget) {
            ShellFetch::Found => return ShellFetch::Found,
            ShellFetch::Bounded => bounded = true,
            ShellFetch::NotFound => {}
        }
    }
    let bodies = substitutions.map(substitution_bodies).unwrap_or_default();
    match substitutions_feed_shell(&bodies, depth, budget) {
        ShellFetch::NotFound if bounded => ShellFetch::Bounded,
        outcome => outcome,
    }
}

/// Descends into each substitution body that holds a `|` (a pipeline needs
/// one, so a body without one uses no budget).
fn substitutions_feed_shell(bodies: &[String], depth: usize, budget: &mut usize) -> ShellFetch {
    let mut bounded = false;
    for body in bodies {
        if !body.contains('|') {
            continue;
        }
        if *budget == 0 {
            return ShellFetch::Bounded;
        }
        if depth >= SHELL_BODY_DEPTH {
            bounded = true;
            continue;
        }
        *budget -= 1;
        match fetch_feeds_shell(body, Some(body), depth + 1, budget) {
            ShellFetch::Found => return ShellFetch::Found,
            ShellFetch::Bounded => bounded = true,
            ShellFetch::NotFound => {}
        }
    }
    if bounded {
        ShellFetch::Bounded
    } else {
        ShellFetch::NotFound
    }
}

/// How one shell reads the spots where the shells read quotes differently.
#[derive(Clone, Copy)]
struct Dialect {
    /// `$'...'` is one ANSI-C string (bash, zsh, ksh). dash has no `$'...'`:
    /// it reads a `$` and then an ordinary single-quoted string, which a `\'`
    /// closes.
    ansi_c: bool,
    /// Which `'` inside a `${...}` that sits in double quotes pairs with the
    /// next `'` while the shell looks for the closing `}`. The text between
    /// still expands (`"${x:-'$(cmd)'}"` runs `cmd` in every shell).
    parameter_quotes: ParameterQuotes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParameterQuotes {
    /// bash: every one.
    Always,
    /// dash and ksh: one in the operand of a `#`, `%` or `/` pattern operator
    /// (`"${x#'"'}"`); elsewhere a `'` is a plain byte (`"${x:-'"'}"`).
    PatternOperand,
    /// zsh: none.
    Never,
}

/// bash first: every other reading only adds the bodies it alone finds.
const DIALECTS: [Dialect; 4] = [
    Dialect {
        ansi_c: true,
        parameter_quotes: ParameterQuotes::Always,
    },
    Dialect {
        ansi_c: false,
        parameter_quotes: ParameterQuotes::PatternOperand,
    },
    Dialect {
        ansi_c: true,
        parameter_quotes: ParameterQuotes::PatternOperand,
    },
    Dialect {
        ansi_c: true,
        parameter_quotes: ParameterQuotes::Never,
    },
];

/// The bodies of the command substitutions (`$(...)`, backticks) and process
/// substitutions (`<(...)`, `>(...)`) in `text`, outermost only, read as the
/// shell reads them: none inside single quotes, `$'...'` or a comment, and
/// inside double quotes only `$(...)` and backticks. An unclosed one takes the
/// rest of the text, so more is read, never less.
///
/// Where the shells read quotes differently (a `$'`, which dash does not
/// know, and a `'` inside a double-quoted `${...}`), the text is read the way
/// each of bash, dash, ksh and zsh reads it, and every body any reading finds
/// is kept, once.
fn substitution_bodies(text: &str) -> Vec<String> {
    let mut bodies = read_substitution_bodies(text, DIALECTS[0]);
    // The readings can differ only at a `$'` or at a `'` inside a `${...}`.
    let others = if text.contains("${") && text.contains('\'') {
        &DIALECTS[1..]
    } else if text.contains("$'") {
        &DIALECTS[1..2]
    } else {
        &[]
    };
    if !others.is_empty() {
        let mut seen: std::collections::HashSet<String> = bodies.iter().cloned().collect();
        for dialect in others {
            for body in read_substitution_bodies(text, *dialect) {
                if seen.insert(body.clone()) {
                    bodies.push(body);
                }
            }
        }
    }
    bodies
}

/// What the reader of [`read_substitution_bodies`] is inside of.
#[derive(Clone, Copy)]
enum Frame {
    /// Double quotes.
    Double,
    /// A `${...}`. `in_double`: the `${` sits in double quotes, where nested
    /// double quotes pair (`"${x:-"'"}"` is one string in bash, dash and zsh)
    /// and `quotes_pair` says whether a `'` pairs with the next one.
    Parameter { in_double: bool, quotes_pair: bool },
}

/// [`substitution_bodies`] under one shell's reading.
fn read_substitution_bodies(text: &str, dialect: Dialect) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut bodies = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut word_start = true;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        let in_double = matches!(
            frames.last(),
            Some(
                Frame::Double
                    | Frame::Parameter {
                        in_double: true,
                        ..
                    }
            )
        );
        if byte == b'`' {
            let end = crate::extract::posix_backtick_close(text, index).unwrap_or(bytes.len());
            bodies.push(unescape_backticks(&text[index + 1..end]));
            index = end + 1;
            word_start = false;
            continue;
        }
        if next == Some(b'(') && (byte == b'$' || (!in_double && matches!(byte, b'<' | b'>'))) {
            let end = crate::extract::posix_delimiter_close(text, index + 1).unwrap_or(bytes.len());
            bodies.push(text[index + 2..end].to_owned());
            index = end + 1;
            word_start = false;
            continue;
        }
        if byte == b'$' && next == Some(b'{') {
            let quotes_pair = match dialect.parameter_quotes {
                ParameterQuotes::Always => true,
                ParameterQuotes::PatternOperand => pattern_operator_follows(&bytes[index + 2..]),
                ParameterQuotes::Never => false,
            };
            frames.push(Frame::Parameter {
                in_double,
                quotes_pair,
            });
            index += 2;
            word_start = false;
            continue;
        }
        match frames.last().copied() {
            Some(Frame::Double) => {
                match byte {
                    b'\\' => index += 1,
                    b'"' => {
                        frames.pop();
                    }
                    _ => {}
                }
                index += 1;
                continue;
            }
            Some(Frame::Parameter {
                in_double: true,
                quotes_pair,
            }) => {
                let quoted_from = match byte {
                    b'\'' if quotes_pair => Some((index + 1, false)),
                    // bash reads a `$'...'` there with its escapes.
                    b'$' if quotes_pair && dialect.ansi_c && next == Some(b'\'') => {
                        Some((index + 2, true))
                    }
                    _ => None,
                };
                if let Some((from, escapes)) = quoted_from {
                    let close = closing_quote(bytes, from, escapes);
                    expanded_substitution_bodies(text, from..close, &mut bodies);
                    index = close + 1;
                    continue;
                }
                match byte {
                    b'\\' => index += 1,
                    b'"' => frames.push(Frame::Double),
                    b'}' => {
                        frames.pop();
                    }
                    _ => {}
                }
                index += 1;
                continue;
            }
            Some(Frame::Parameter {
                in_double: false, ..
            })
            | None => {}
        }
        // Unquoted: at the top level, or inside a `${...}` outside double
        // quotes, where quotes pair as at the top level but no comment starts
        // (`echo ${x:- #} $(cmd)` runs `cmd`).
        let in_parameter = !frames.is_empty();
        if dialect.ansi_c && byte == b'$' && next == Some(b'\'') {
            // `$'...'`: a backslash escapes the next byte, `\'` included.
            index = closing_quote(bytes, index + 2, true) + 1;
            word_start = false;
            continue;
        }
        match byte {
            b'\\' => {
                // The shells remove a backslash-newline before they split the
                // line into words, so it leaves the word state alone: the `#`
                // in `echo hi \` + `#note` starts a comment.
                if next != Some(b'\n') {
                    word_start = false;
                }
                index += 2;
                continue;
            }
            b'\'' => {
                index = closing_quote(bytes, index + 1, false) + 1;
                word_start = false;
                continue;
            }
            b'"' => {
                frames.push(Frame::Double);
                index += 1;
                word_start = false;
                continue;
            }
            b'}' if in_parameter => {
                frames.pop();
                index += 1;
                word_start = false;
                continue;
            }
            // Only where a comment certainly starts: reading a comment as
            // code over-reads, reading code as a comment would hide it.
            b'#' if word_start && !in_parameter => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                continue;
            }
            _ => {}
        }
        // A carriage return is an ordinary word byte in every shell, so a
        // `#` right after one starts no comment.
        word_start = matches!(
            byte,
            b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')'
        );
        index += 1;
    }
    bodies
}

/// The index of the `'` that closes a single-quoted string whose text starts
/// at `from`, or the end of the input. With `escapes` (`$'...'`) a backslash
/// escapes the next byte.
fn closing_quote(bytes: &[u8], from: usize, escapes: bool) -> usize {
    let mut index = from;
    while index < bytes.len() && bytes[index] != b'\'' {
        index += if escapes && bytes[index] == b'\\' {
            2
        } else {
            1
        };
    }
    index.min(bytes.len())
}

/// The text after a `${` names a parameter followed by a `#`, `%` or `/`
/// pattern operator (`${x#'*'}`, `${1%%.*}`, `${x/a/b}`). `${#x}` is a length.
fn pattern_operator_follows(rest: &[u8]) -> bool {
    let mut index = usize::from(rest.first() == Some(&b'#') && rest.get(1) != Some(&b'}'));
    match rest.get(index) {
        Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_' => {
            while rest
                .get(index)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                index += 1;
            }
        }
        Some(byte) if byte.is_ascii_digit() => {
            while rest.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        }
        Some(b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!') => index += 1,
        _ => return false,
    }
    matches!(rest.get(index), Some(b'#' | b'%' | b'/'))
}

/// The substitution bodies in `text[range]` read as expanded text, the way
/// the shells read an unquoted heredoc body: only a backslash quotes there,
/// and `'`, `"` and `#` are plain bytes, so every unescaped `$(...)` and
/// backtick runs. A body may run past the range end (more is read, never
/// less).
fn expanded_substitution_bodies(
    text: &str,
    range: std::ops::Range<usize>,
    bodies: &mut Vec<String>,
) {
    let bytes = text.as_bytes();
    let mut index = range.start;
    while index < range.end.min(bytes.len()) {
        match bytes[index] {
            b'\\' => index += 2,
            b'`' => {
                let end = crate::extract::posix_backtick_close(text, index).unwrap_or(bytes.len());
                bodies.push(unescape_backticks(&text[index + 1..end]));
                index = end + 1;
            }
            b'$' if bytes.get(index + 1) == Some(&b'(') => {
                let end =
                    crate::extract::posix_delimiter_close(text, index + 1).unwrap_or(bytes.len());
                bodies.push(text[index + 2..end].to_owned());
                index = end + 1;
            }
            _ => index += 1,
        }
    }
}

/// Inside backticks a backslash quotes only `$`, `` ` `` and `\`.
fn unescape_backticks(body: &str) -> String {
    let mut unescaped = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            unescaped.push(character);
            continue;
        }
        match chars.next() {
            Some(next @ ('$' | '`' | '\\')) => unescaped.push(next),
            Some(next) => {
                unescaped.push('\\');
                unescaped.push(next);
            }
            None => unescaped.push('\\'),
        }
    }
    unescaped
}

/// `text` with every heredoc body and terminator blanked (newlines kept), for
/// reading substitutions: heredoc text is data there (an apostrophe in it is
/// no quote), and each body that may run is scanned on its own. Unchanged
/// when the heredocs cannot be delimited.
fn without_heredoc_bodies(text: &str) -> std::borrow::Cow<'_, str> {
    let spans = if text.contains("<<") {
        crate::extract::posix_heredoc_spans(text).unwrap_or_default()
    } else {
        Vec::new()
    };
    if spans.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut bytes = text.as_bytes().to_vec();
    for span in spans {
        for byte in bytes.get_mut(span.through_terminator).into_iter().flatten() {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).map_or(std::borrow::Cow::Borrowed(text), std::borrow::Cow::Owned)
}

/// Fallback once the descent hit a bound, or where the heredocs are
/// ambiguous: each line on its own, with group openers and closers around it
/// removed, and the substitutions in it. With `expanded` (ambiguous
/// heredocs), a line may be an unquoted heredoc body line, so its
/// substitutions are also read the way such a body expands.
fn any_line_feeds_shell(text: &str, expanded: bool) -> bool {
    text.lines().any(|line| {
        let line = line
            .trim_start_matches(|c: char| c == '{' || c == '(' || c.is_whitespace())
            .trim_end_matches(|c: char| c == '}' || c == ')' || c == ';' || c.is_whitespace());
        if line.is_empty() {
            return false;
        }
        let mut budget = SHELL_BODY_BUDGET;
        if feeds_shell(line) || substitution_feeds_shell(&substitution_bodies(line), 0, &mut budget)
        {
            return true;
        }
        let mut bodies = Vec::new();
        if expanded {
            expanded_substitution_bodies(line, 0..line.len(), &mut bodies);
        }
        substitution_feeds_shell(&bodies, 0, &mut budget)
    })
}

/// The line pass reads inside a line's substitutions too, within `budget`
/// piped bodies per line. Running out counts as found: the line pass is the
/// fallback, which fails toward the signal.
fn substitution_feeds_shell(bodies: &[String], depth: usize, budget: &mut usize) -> bool {
    depth < SHELL_BODY_DEPTH
        && bodies.iter().filter(|body| body.contains('|')).any(|body| {
            if *budget == 0 {
                return true;
            }
            *budget -= 1;
            feeds_shell(body)
                || substitution_feeds_shell(&substitution_bodies(body), depth + 1, budget)
        })
}

/// One bounded descent over the file, then over each live heredoc body.
/// Without `read_substitutions` it enters brace-group, function and subshell
/// bodies only; with it, substitution bodies too.
fn descend(
    text: &str,
    heredocs: &inert_heredoc::HeredocView,
    read_substitutions: bool,
) -> ShellFetch {
    let substitutions = read_substitutions.then(|| without_heredoc_bodies(text));
    let mut budget = SHELL_BODY_BUDGET;
    let mut outcome = fetch_feeds_shell(
        heredocs.masked.as_deref().unwrap_or(text),
        substitutions.as_deref(),
        0,
        &mut budget,
    );
    // A live heredoc body stays in the text read above, where the tokenizer
    // reads it as code: the apostrophe of `it's` (or a `"`, or `$(`) opens a
    // quote that hides every later line, and a `curl … | sh` after the
    // heredoc was missed. So the group pass also reads the file with every
    // heredoc body blanked (heredoc text is data there, and each live body is
    // scanned on its own below), on its own budget, and keeps any finding.
    // Substitutions are already read from that blanked text.
    if !read_substitutions && outcome != ShellFetch::Found && !heredocs.live_bodies.is_empty() {
        let blanked = without_heredoc_bodies(text);
        let mut blanked_budget = SHELL_BODY_BUDGET;
        match fetch_feeds_shell(&blanked, None, 0, &mut blanked_budget) {
            ShellFetch::NotFound => {}
            other => outcome = other,
        }
    }
    // The live bodies were already counted by the whole-file pass, so their
    // own pass gets a fresh (shared) budget: at most twice the work.
    let mut body_budget = SHELL_BODY_BUDGET;
    for live in &heredocs.live_bodies {
        if outcome == ShellFetch::Found {
            break;
        }
        let body = &text[live.range.clone()];
        let substitutions = read_substitutions.then(|| without_heredoc_bodies(body));
        match fetch_feeds_shell(body, substitutions.as_deref(), 0, &mut body_budget) {
            ShellFetch::NotFound => {}
            other => outcome = other,
        }
        if outcome == ShellFetch::Found || live.quoted {
            continue;
        }
        // An unquoted body is also expanded when the heredoc is read, as
        // data: only a backslash quotes there, so its substitutions run
        // whatever `'`, `"` or `#` it holds (`it's $(cmd)`). The reading as
        // code above is still needed where the body is fed to a shell.
        if let Some(substitutions) = substitutions.as_deref() {
            let read_as_code: std::collections::HashSet<String> =
                substitution_bodies(substitutions).into_iter().collect();
            let mut expanded = Vec::new();
            expanded_substitution_bodies(body, 0..body.len(), &mut expanded);
            expanded.retain(|body| !read_as_code.contains(body));
            match substitutions_feed_shell(&expanded, 0, &mut body_budget) {
                ShellFetch::NotFound => {}
                other => outcome = other,
            }
        }
    }
    outcome
}

fn inspect_shell(text: &str, member: &str, events: &[String], inspection: &mut NpmInspection) {
    // Heredoc text this file provably only prints is data, like a comment.
    // Every other heredoc body is also scanned on its own, and ambiguous
    // heredocs add the line-by-line pass. The bounded fallback below keeps
    // reading the raw text (fails toward the signal).
    let heredocs = inert_heredoc::analyze(text);
    // The group descent runs alone first, on its own budget, so substitution
    // bodies (each piped one costs a body) can never use up the budget a
    // later brace group, function or subshell needs, as in a live heredoc
    // body full of `$(... | ...)` before one holding `f() { curl … | sh; }`.
    // The descent that also reads substitutions then gets a fresh budget.
    let grouped = descend(text, &heredocs, false);
    let substituted = if grouped == ShellFetch::Found {
        ShellFetch::NotFound
    } else {
        descend(text, &heredocs, true)
    };
    let bounded = grouped == ShellFetch::Bounded || substituted == ShellFetch::Bounded;
    if bounded {
        inspection.issue(NpmIssueKind::CodeLimit, Some(member),
            "Shell brace-group, function, subshell or substitution nesting exceeds the bounded descent; a line-by-line download-to-shell pass was used for the rest.");
    }
    // The line pass reads the file as code. The body of an unquoted live
    // heredoc is also expanded as data, where `'`, `"` and `#` are plain
    // text, so once the descent is bounded its lines are read that way too.
    // It also runs where the shells read the text differently (a `$${` or
    // `$$(`, or a backslash-newline inside `$(`/`${`), since the descent
    // follows one reading only.
    let reads_differently = crate::extract::posix_text_reads_differently_across_shells(text);
    let found = grouped == ShellFetch::Found
        || substituted == ShellFetch::Found
        || ((bounded || heredocs.ambiguous || reads_differently)
            && any_line_feeds_shell(text, heredocs.ambiguous))
        || (bounded
            && heredocs
                .live_bodies
                .iter()
                .any(|live| !live.quoted && any_line_feeds_shell(&text[live.range.clone()], true)));
    if found {
        push(inspection, signal(NpmSignalKind::DownloadToShell, NpmSignalLevel::Review, member,
            vec![NpmCapability::NetworkAccess, NpmCapability::ProcessSpawn], events,
            "A literal curl/wget pipeline feeds a shell interpreter. Review the downloaded code; no network request or script was executed."));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Word,
    String,
    Punct,
}
#[derive(Clone, Copy)]
struct Token<'a> {
    kind: TokenKind,
    value: &'a str,
}

fn js_tokens(text: &str) -> (Vec<Token<'_>>, bool, bool) {
    let bytes = text.as_bytes();
    let mut offset = usize::from(bytes.starts_with(b"\xef\xbb\xbf")) * 3;
    if bytes.get(offset..).is_some_and(|b| b.starts_with(b"#!")) {
        offset = bytes
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(bytes.len());
    }
    let mut tokens = Vec::new();
    let mut complete = true;
    let mut limited = false;
    while offset < bytes.len() {
        if tokens.len() >= 65_536 {
            limited = true;
            break;
        }
        let byte = bytes[offset];
        if byte.is_ascii_whitespace() {
            offset += 1;
            continue;
        }
        if bytes.get(offset..offset + 2) == Some(b"//") {
            offset += 2;
            while offset < bytes.len() && bytes[offset] != b'\n' {
                offset += 1;
            }
            continue;
        }
        if bytes.get(offset..offset + 2) == Some(b"/*") {
            offset += 2;
            let Some(end) = bytes[offset..].windows(2).position(|pair| pair == b"*/") else {
                complete = false;
                break;
            };
            offset += end + 2;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            let quote = byte;
            let start = offset + 1;
            offset = start;
            let mut escaped = false;
            while offset < bytes.len() && bytes[offset] != quote {
                if bytes[offset] == b'\\' {
                    escaped = true;
                    offset += 1;
                }
                offset = offset.saturating_add(1);
            }
            if offset >= bytes.len() {
                complete = false;
                break;
            }
            if escaped || quote == b'`' {
                complete = false;
            }
            if offset - start > 8192 {
                limited = true;
            } else if !escaped && quote != b'`' {
                tokens.push(Token {
                    kind: TokenKind::String,
                    value: &text[start..offset],
                });
            }
            offset += 1;
            continue;
        }
        if byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$') {
            let start = offset;
            offset += 1;
            while offset < bytes.len()
                && (bytes[offset].is_ascii_alphanumeric() || matches!(bytes[offset], b'_' | b'$'))
            {
                offset += 1;
            }
            if offset - start > 8192 {
                limited = true;
            } else {
                tokens.push(Token {
                    kind: TokenKind::Word,
                    value: &text[start..offset],
                });
            }
            continue;
        }
        if byte >= 128 {
            complete = false;
            offset += text[offset..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        }
        if matches!(byte, b'/' | b'\\') {
            complete = false;
        }
        tokens.push(Token {
            kind: TokenKind::Punct,
            value: &text[offset..offset + 1],
        });
        offset += 1;
    }
    (tokens, complete && !limited, limited)
}

fn inspect_js(text: &str, member: &str, events: &[String], inspection: &mut NpmInspection) {
    let (tokens, complete, limited) = js_tokens(text);
    if !complete {
        inspection.issue(if limited { NpmIssueKind::CodeLimit } else { NpmIssueKind::UnsupportedCode }, Some(member),
            "JavaScript contains unsupported lexical shapes or exceeds token/string limits; static capability coverage is partial.");
    }
    let call = |index: usize, name: &str| {
        tokens
            .get(index)
            .is_some_and(|t| t.kind == TokenKind::Word && t.value == name)
            && tokens.get(index + 1).is_some_and(|t| t.value == "(")
    };
    let imported = |module: &str| {
        tokens.iter().enumerate().any(|(index, token)| {
            token.kind == TokenKind::String
                && token.value.strip_prefix("node:").unwrap_or(token.value) == module
                && ((index >= 2 && call(index - 2, "require"))
                    || (index >= 1
                        && tokens[index - 1].kind == TokenKind::Word
                        && tokens[index - 1].value == "from"))
        })
    };
    let has_call = |names: &[&str]| {
        tokens
            .iter()
            .enumerate()
            .any(|(index, _)| names.iter().any(|name| call(index, name)))
    };
    let spawn = imported("child_process")
        && has_call(&[
            "exec",
            "execSync",
            "execFile",
            "execFileSync",
            "spawn",
            "spawnSync",
            "fork",
        ]);
    let network = has_call(&["fetch"])
        || ((imported("http") || imported("https") || imported("net") || imported("tls"))
            && has_call(&["get", "request", "connect", "createConnection"]));
    let dynamic = has_call(&["eval", "Function"])
        || (imported("vm")
            && has_call(&[
                "runInContext",
                "runInNewContext",
                "runInThisContext",
                "compileFunction",
            ]));
    let sensitive_literal = tokens.iter().any(|token| {
        token.kind == TokenKind::String
            && [
                ".npmrc",
                ".ssh/",
                ".aws/",
                "credentials",
                "id_rsa",
                "Login Data",
                "Cookies",
            ]
            .iter()
            .any(|needle| token.value.contains(needle))
    });
    let sensitive_read = imported("fs")
        && has_call(&["readFile", "readFileSync", "createReadStream"])
        && sensitive_literal;
    let mut capabilities = Vec::new();
    if spawn {
        capabilities.push(NpmCapability::ProcessSpawn);
    }
    if network {
        capabilities.push(NpmCapability::NetworkAccess);
    }
    if dynamic {
        capabilities.push(NpmCapability::DynamicEvaluation);
    }
    if sensitive_read {
        capabilities.push(NpmCapability::SensitiveFileAccess);
    }
    if !capabilities.is_empty() {
        push(inspection, signal(NpmSignalKind::CodeCapabilities, NpmSignalLevel::Observation, member, capabilities, events,
            "Recognized static module/call patterns indicate capabilities in this file. Binding, reachability and data flow are not proven."));
    }
    if dynamic
        || tokens.iter().enumerate().any(|(index, _)| {
            (call(index, "require") || call(index, "import"))
                && tokens
                    .get(index + 2)
                    .is_none_or(|t| t.kind != TokenKind::String)
        })
    {
        inspection.issue(
            NpmIssueKind::DynamicCode,
            Some(member),
            "Dynamic evaluation or module selection prevents complete local behavior analysis.",
        );
    }
    if tokens
        .iter()
        .enumerate()
        .any(|(index, _)| call(index, "require") || call(index, "import"))
    {
        inspection.issue(NpmIssueKind::UnsupportedCode, Some(member), "Module calls are recognized as lexical evidence; transitive resolution, dependency bytes and binding behavior are not proven.");
    }
    let encoded_eval = tokens.iter().enumerate().any(|(index, _)| {
        (call(index, "eval") || call(index, "Function"))
            && tokens[index + 2..]
                .iter()
                .take(40)
                .any(|token| token.kind == TokenKind::String && token.value == "base64")
            && tokens[index + 2..].windows(3).take(40).any(|window| {
                window[0].value == "Buffer" && window[1].value == "." && window[2].value == "from"
            })
    });
    if encoded_eval {
        push(inspection, signal(NpmSignalKind::EncodedDynamicExecution, NpmSignalLevel::Review, member,
            vec![NpmCapability::DynamicEvaluation], events,
            "Dynamic evaluation appears with nearby Buffer.from/base64 decoding tokens. Review the encoded execution path; no decoded code was executed."));
    }
    if sensitive_read && network {
        push(inspection, signal(NpmSignalKind::SensitiveReadWithNetwork, NpmSignalLevel::Review, member,
            vec![NpmCapability::SensitiveFileAccess, NpmCapability::NetworkAccess], events,
            "Credential-like path literals and filesystem-read calls coexist with network-call patterns. Review possible data transfer; static co-occurrence does not prove exfiltration."));
    }
}

fn inspect_native(member: &Member<'_>, events: &[String], inspection: &mut NpmInspection) {
    use crate::artifact::archive::NativeMemberHandoff;
    use crate::artifact::native::{triage_native, NativeCoverage};

    let handoff = NativeMemberHandoff::Buffered {
        location: crate::location::SubjectLocation::member(
            &inspection.artifact.filename,
            &member.path,
        ),
        bytes: member.bytes.to_vec(),
        sha256: crate::util::sha256_hex(member.bytes),
    };
    let triage = triage_native(&handoff, false, false);
    let facts = triage.facts;
    let mut capabilities = vec![NpmCapability::NativeModule];
    let initializer =
        facts.has_elf_constructor || facts.has_macho_mod_init || facts.has_pe_tls_or_dllmain;
    if initializer {
        capabilities.push(NpmCapability::NativeInitialization);
    }
    if !facts.spawn_imports.is_empty() {
        capabilities.push(NpmCapability::ProcessSpawn);
    }
    push(inspection, signal(NpmSignalKind::NativeArtifact, NpmSignalLevel::Observation, &member.path,
        capabilities, events, "Native object bytes are present. Native modules and initialization entries are ordinary package capabilities, not sufficient evidence of malicious behavior."));
    if facts.coverage != NativeCoverage::Full {
        inspection.issue(
            NpmIssueKind::NativeIncomplete,
            Some(&member.path),
            "Native format parsing or a bounded native extraction stage was incomplete.",
        );
    }
    if initializer
        && !facts.spawn_imports.is_empty()
        && (facts.has_runtime_launch
            || facts.has_spawn_with_sibling
            || !facts.sensitive_paths.is_empty())
    {
        push(inspection, signal(NpmSignalKind::NativeExecutionCombination, NpmSignalLevel::Review, &member.path,
            vec![NpmCapability::NativeModule, NpmCapability::NativeInitialization, NpmCapability::ProcessSpawn], events,
            "Native initialization, imported process-spawn capability and runtime/payload or sensitive-path evidence coexist. Review the initialization path; actual execution and data flow are not proven."));
    }
}
