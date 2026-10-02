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
/// substitutions, chains and npm-provided executable resolution remain explicit
/// unknowns. This narrow edge never controls whether other code files are read.
fn literal_script_target(command: &str) -> Option<String> {
    let (tokens, complete) = shell_words(command);
    if !complete || tokens.len() != 2 || tokens.iter().any(|word| word.operator) {
        return None;
    }
    if !matches!(
        tokens[0].value.as_str(),
        "node" | "nodejs" | "sh" | "bash" | "zsh"
    ) || tokens[1].value.starts_with('-')
    {
        return None;
    }
    package_relative(&tokens[1].value)
}

fn inspect_shell(text: &str, member: &str, events: &[String], inspection: &mut NpmInspection) {
    let (words, complete) = shell_words(text);
    if !complete {
        return;
    }
    // Only a literal downloader at the beginning of a pipeline and a shell at
    // its next stage qualifies. "echo curl ... | sh" is not a download claim.
    let mut start = 0usize;
    for (index, word) in words.iter().enumerate() {
        if word.operator && matches!(word.value.as_str(), ";" | "&&" | "||" | "\n") {
            start = index + 1;
            continue;
        }
        if word.operator
            && word.value == "|"
            && words
                .get(start)
                .is_some_and(|w| !w.operator && matches!(w.value.as_str(), "curl" | "wget"))
            && words
                .get(index + 1)
                .is_some_and(|w| !w.operator && matches!(w.value.as_str(), "sh" | "bash" | "zsh"))
        {
            push(inspection, signal(NpmSignalKind::DownloadToShell, NpmSignalLevel::Review, member,
                vec![NpmCapability::NetworkAccess, NpmCapability::ProcessSpawn], events,
                "A literal curl/wget pipeline feeds a shell interpreter. Review the downloaded code; no network request or script was executed."));
            break;
        }
        if word.operator && word.value == "|" {
            start = index + 1;
        }
    }
}

struct ShellWord {
    value: String,
    operator: bool,
}

fn shell_words(text: &str) -> (Vec<ShellWord>, bool) {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut word_started = false;
    let mut quote = None;
    let mut complete = true;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if words.len() >= 4096 || current.len() > 8192 {
            complete = false;
            break;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                if q == '"' && matches!(ch, '$' | '`' | '\\') {
                    complete = false;
                }
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                word_started = true;
            }
            '$' | '`' | '\\' | '(' | ')' | '<' | '>' => {
                complete = false;
                current.push(ch);
                word_started = true;
            }
            '#' if !word_started => {
                for ch in chars.by_ref() {
                    if ch == '\n' {
                        break;
                    }
                }
                words.push(ShellWord {
                    value: "\n".to_owned(),
                    operator: true,
                });
            }
            '|' | '&' | ';' | '\n' => {
                if word_started {
                    words.push(ShellWord {
                        value: std::mem::take(&mut current),
                        operator: false,
                    });
                    word_started = false;
                }
                let mut op = ch.to_string();
                if matches!(ch, '|' | '&') && chars.peek() == Some(&ch) {
                    chars.next();
                    op.push(ch);
                }
                words.push(ShellWord {
                    value: op,
                    operator: true,
                });
            }
            ch if ch.is_whitespace() => {
                if word_started {
                    words.push(ShellWord {
                        value: std::mem::take(&mut current),
                        operator: false,
                    });
                    word_started = false;
                }
            }
            _ => {
                current.push(ch);
                word_started = true;
            }
        }
    }
    if word_started {
        words.push(ShellWord {
            value: current,
            operator: false,
        });
    }
    (words, complete && quote.is_none())
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
    use sha2::{Digest, Sha256};

    let handoff = NativeMemberHandoff::Buffered {
        location: crate::location::SubjectLocation::member(
            &inspection.artifact.filename,
            &member.path,
        ),
        bytes: member.bytes.to_vec(),
        sha256: hex::encode(Sha256::digest(member.bytes)),
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
