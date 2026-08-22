//! Shared idempotent writer for `.devcontainer/devcontainer.json` (M8 ch5):
//! adds an independent, structurally exact Tirith `postCreateCommand` plus
//! `TIRITH_DEVCONTAINER=1` in `containerEnv`.
//!
//! Existing JSONC is edited by byte span: line/block comments, trailing commas,
//! line endings, and unrelated formatting survive unchanged. The effective
//! document is still validated as strict JSON after masking JSONC extensions,
//! and ambiguous duplicate managed keys are rejected instead of guessed at.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::util::{ContainedAtomicFile, OpenRegularError};

/// Human-readable marker retained for CLI output compatibility.
pub const TIRITH_HOOK_MARKER: &str = "tirith init";
/// Reserved lifecycle-command key owned by Tirith.
pub const TIRITH_HOOK_KEY: &str = "tirith-init";

const TIRITH_HOOK_ARGV: [&str; 4] = ["tirith", "init", "--shell", "auto"];

/// devcontainer.json and .gitignore are small configuration files; cap reads
/// so a hostile or broken file cannot force an unbounded allocation.
const CONFIG_READ_CAP: u64 = 1024 * 1024;

/// True only when `path` exists as a REGULAR file reached without following a
/// final symlink, and every component of its parent directory is likewise not
/// a symlink (repo-0271). `is_file()` follows links and would accept a
/// repository-planted redirect outside the project.
fn regular_file_no_follow(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {}
        _ => return false,
    }
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            matches!(
                std::fs::symlink_metadata(parent),
                Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink()
            )
        }
        _ => true,
    }
}

/// Outcome of an inject / setup operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectOutcome {
    /// File did not exist; created a minimal one (only when `create_if_missing`).
    Created(PathBuf),
    /// File existed and was modified to add the tirith hook + env flag.
    Updated(PathBuf),
    /// File already contained the tirith hook — no-op.
    AlreadyInjected(PathBuf),
    /// File did not exist and `create_if_missing` was false.
    NotFound(PathBuf),
    /// File existed but could not be parsed as JSONC.
    ParseError(PathBuf, String),
}

/// Find devcontainer.json under `cwd`: nested `.devcontainer/` first, then the
/// flat `.devcontainer.json` Codespaces also accepts. `None` if neither exists.
///
/// Both the file AND its parent must be reached without following a
/// repository-controlled symlink (repo-0271); a symlinked candidate is skipped
/// so the writer below never resolves a redirect outside the project.
pub fn find_devcontainer_json(cwd: &Path) -> Option<PathBuf> {
    let nested = cwd.join(".devcontainer").join("devcontainer.json");
    if regular_file_no_follow(&nested) {
        return Some(nested);
    }
    let flat = cwd.join(".devcontainer.json");
    if regular_file_no_follow(&flat) {
        return Some(flat);
    }
    None
}

/// Default path when none exists: always the nested variant (matches the
/// layout Codespaces scaffolds).
pub fn default_devcontainer_json(cwd: &Path) -> PathBuf {
    cwd.join(".devcontainer").join("devcontainer.json")
}

/// Compatibility-only devcontainer publisher for external library callers.
/// Tirith-owned CLI paths render and publish through their typed ConfigWrite
/// boundary and must not call this legacy publisher.
///
/// `root` is the selected repository root: every read and write is confined
/// beneath it through a retained, no-follow parent capability, refuses a
/// symlinked destination, and publishes atomically via a same-directory
/// temporary file (repo-0271). A repository-planted symlink at
/// `.devcontainer/`, `devcontainer.json`, or `.devcontainer.json` is rejected
/// instead of rewriting an external target.
///
/// Existing string and argv lifecycle forms become a multi-command object so
/// an untrusted setup command cannot prevent Tirith from being launched. A
/// re-run is a no-op only when the reserved entry contains the exact argv.
#[doc(hidden)]
#[deprecated(
    since = "0.1.0",
    note = "outside Tirith-owned CLI boundaries; use an authorized ConfigWrite integration"
)]
pub fn inject_tirith_hook(path: &Path, root: &Path, create_if_missing: bool) -> InjectOutcome {
    let prepared = match ContainedAtomicFile::prepare(root, path, create_if_missing) {
        Ok(prepared) => prepared,
        Err(e) => {
            return InjectOutcome::ParseError(
                path.to_path_buf(),
                format!("refusing unsafe devcontainer destination: {e}"),
            )
        }
    };
    if let Err(error) = prepared.lock_parent_for_mutation() {
        return InjectOutcome::ParseError(
            path.to_path_buf(),
            format!("cannot serialize devcontainer mutation: {error}"),
        );
    }
    let content_str = match prepared.read_capped(CONFIG_READ_CAP) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return InjectOutcome::ParseError(
                    path.to_path_buf(),
                    "devcontainer.json is not UTF-8".to_string(),
                )
            }
        },
        Err(OpenRegularError::NotFound) => {
            if !create_if_missing {
                return InjectOutcome::NotFound(path.to_path_buf());
            }
            // Minimal seed kept narrow — operators re-edit image/features/name.
            let value = json!({
                "name": "tirith-protected devcontainer",
                "postCreateCommand": {
                    TIRITH_HOOK_KEY: TIRITH_HOOK_ARGV,
                },
                "containerEnv": { "TIRITH_DEVCONTAINER": "1" },
            });
            match write_pretty(&prepared, &value) {
                Ok(()) => return InjectOutcome::Created(path.to_path_buf()),
                Err(e) => return InjectOutcome::ParseError(path.to_path_buf(), e),
            }
        }
        Err(e) => {
            return InjectOutcome::ParseError(
                path.to_path_buf(),
                format!("refusing unsafe devcontainer source: {e:?}"),
            );
        }
    };

    let rendered = match render_tirith_hook_jsonc(&content_str) {
        Ok(Some(rendered)) => rendered,
        Ok(None) => return InjectOutcome::AlreadyInjected(path.to_path_buf()),
        Err(error) => return InjectOutcome::ParseError(path.to_path_buf(), error),
    };

    match prepared
        .write_atomic_if_observed(rendered.as_bytes(), true)
        .map_err(|error| format!("atomic write: {error}"))
    {
        Ok(()) => InjectOutcome::Updated(path.to_path_buf()),
        Err(e) => InjectOutcome::ParseError(path.to_path_buf(), e),
    }
}

/// Compatibility-only `.gitignore` publisher for external library callers.
/// Tirith-owned CLI paths use their typed ConfigWrite boundary.
///
/// The existing file is read through a no-follow, size-capped contained
/// reader and republished atomically beneath `cwd` (repo-0271). A symlinked
/// `.gitignore` is an error, and an UNREADABLE file is no longer silently
/// treated as empty (which would have truncated a non-UTF-8 symlink target
/// down to just the Tirith stanza).
#[doc(hidden)]
#[deprecated(
    since = "0.1.0",
    note = "outside Tirith-owned CLI boundaries; use an authorized ConfigWrite integration"
)]
pub fn ensure_gitignore_entry(cwd: &Path) -> std::io::Result<bool> {
    let path = cwd.join(".gitignore");
    let prepared = ContainedAtomicFile::prepare(cwd, &path, false)?;
    prepared.lock_parent_for_mutation()?;
    let existing = match prepared.read_capped(CONFIG_READ_CAP) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ".gitignore is not UTF-8; refusing to rewrite it",
            )
        })?,
        Err(OpenRegularError::NotFound) => String::new(),
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to read unsafe .gitignore: {e:?}"),
            ))
        }
    };
    for line in existing.lines() {
        let t = line.trim();
        if t == ".tirith" || t == ".tirith/" || t == "/.tirith" || t == "/.tirith/" {
            return Ok(false);
        }
    }
    let mut new_content = existing;
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str("# tirith state directory (devcontainer / codespaces)\n");
    new_content.push_str(".tirith/\n");
    prepared.write_atomic_if_observed(new_content.as_bytes(), true)?;
    Ok(true)
}

fn tirith_hook_value() -> Value {
    json!(TIRITH_HOOK_ARGV)
}

#[derive(Debug, Clone)]
struct JsoncMember {
    key: String,
    key_start: usize,
    key_end: usize,
    value_start: usize,
    value_end: usize,
}

#[derive(Debug, Clone)]
struct JsoncObject {
    close: usize,
    members: Vec<JsoncMember>,
    trailing_comma: bool,
}

#[derive(Debug)]
struct JsoncDocument {
    masked: Vec<u8>,
    strict: Vec<u8>,
    root: JsoncObject,
}

impl JsoncDocument {
    fn parse(input: &str) -> Result<Self, String> {
        let masked = mask_jsonc_comments(input)?;
        let mut strict = masked.clone();
        mask_jsonc_trailing_commas(&mut strict);
        let strict_text = std::str::from_utf8(&strict)
            .map_err(|_| "devcontainer.json is not valid UTF-8".to_string())?;
        let value: Value =
            serde_json::from_str(strict_text).map_err(|error| format!("parse error: {error}"))?;
        if !value.is_object() {
            return Err("devcontainer.json root must be an object".to_string());
        }

        let root_start = skip_jsonc_whitespace(&masked, 0);
        if masked.get(root_start) != Some(&b'{') {
            return Err("devcontainer.json root must be an object".to_string());
        }
        let root = parse_jsonc_object(&masked, root_start)?;
        if skip_jsonc_whitespace(&masked, root.close + 1) != masked.len() {
            return Err("devcontainer.json has content after the root object".to_string());
        }
        Ok(Self {
            masked,
            strict,
            root,
        })
    }

    fn unique_member<'a>(
        &'a self,
        object: &'a JsoncObject,
        key: &str,
    ) -> Result<Option<&'a JsoncMember>, String> {
        let mut matches = object.members.iter().filter(|member| member.key == key);
        let first = matches.next();
        if matches.next().is_some() {
            return Err(format!(
                "devcontainer.json contains duplicate managed key `{key}`"
            ));
        }
        Ok(first)
    }

    fn value(&self, member: &JsoncMember) -> Result<Value, String> {
        serde_json::from_slice(&self.strict[member.value_start..member.value_end])
            .map_err(|error| format!("parse `{}`: {error}", member.key))
    }

    fn object_value(&self, member: &JsoncMember) -> Result<JsoncObject, String> {
        let object = parse_jsonc_object(&self.masked, member.value_start)?;
        if object.close + 1 != member.value_end {
            return Err(format!("`{}` must be a JSON object", member.key));
        }
        Ok(object)
    }
}

/// Render the Tirith lifecycle hook into an existing JSONC document while
/// preserving every byte outside the managed key/value spans. `Ok(None)` means
/// the effective exact hook and environment marker were already installed.
pub fn render_tirith_hook_jsonc(input: &str) -> Result<Option<String>, String> {
    let mut rendered = input.to_string();
    let mut changed = false;

    if let Some(updated) = render_post_create_command(&rendered)? {
        rendered = updated;
        changed = true;
    }
    if let Some(updated) = render_container_env(&rendered)? {
        rendered = updated;
        changed = true;
    }

    let effective = JsoncDocument::parse(&rendered)?;
    let root: Value = serde_json::from_slice(&effective.strict)
        .map_err(|error| format!("parse generated devcontainer.json: {error}"))?;
    if root
        .get("postCreateCommand")
        .and_then(Value::as_object)
        .and_then(|commands| commands.get(TIRITH_HOOK_KEY))
        != Some(&tirith_hook_value())
        || !root
            .get("containerEnv")
            .and_then(Value::as_object)
            .and_then(|environment| environment.get("TIRITH_DEVCONTAINER"))
            .and_then(Value::as_str)
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    {
        return Err("generated devcontainer.json failed Tirith hook validation".to_string());
    }

    Ok(changed.then_some(rendered))
}

fn render_post_create_command(input: &str) -> Result<Option<String>, String> {
    let document = JsoncDocument::parse(input)?;
    let Some(member) = document.unique_member(&document.root, "postCreateCommand")? else {
        return Ok(Some(insert_jsonc_object_member(
            input,
            &document.root,
            "postCreateCommand",
            &managed_post_create_object(),
        )));
    };
    let value = document.value(member)?;
    match value {
        Value::Object(_) => {
            let commands = document.object_value(member)?;
            let existing = document.unique_member(&commands, TIRITH_HOOK_KEY)?;
            if let Some(existing) = existing {
                if document.value(existing)? == tirith_hook_value() {
                    return Ok(None);
                }

                let keys: std::collections::HashSet<&str> = commands
                    .members
                    .iter()
                    .map(|entry| entry.key.as_str())
                    .collect();
                let mut suffix = 0usize;
                let preserved_key = loop {
                    let candidate = if suffix == 0 {
                        format!("{TIRITH_HOOK_KEY}-existing")
                    } else {
                        format!("{TIRITH_HOOK_KEY}-existing-{suffix}")
                    };
                    if !keys.contains(candidate.as_str()) {
                        break candidate;
                    }
                    suffix = suffix.saturating_add(1);
                };
                let mut renamed = input.to_string();
                renamed.replace_range(
                    existing.key_start..existing.key_end,
                    &serde_json::to_string(&preserved_key)
                        .map_err(|error| format!("serialize preserved hook key: {error}"))?,
                );
                return render_post_create_command(&renamed)
                    .map(|next| Some(next.unwrap_or(renamed)));
            }

            Ok(Some(insert_jsonc_object_member(
                input,
                &commands,
                TIRITH_HOOK_KEY,
                r#"["tirith", "init", "--shell", "auto"]"#,
            )))
        }
        Value::String(_) | Value::Array(_) => {
            let raw_existing = &input[member.value_start..member.value_end];
            let property_indent = line_indent(input, member.key_start);
            let child_indent = format!("{property_indent}  ");
            let newline = preferred_newline(input);
            let replacement = format!(
                "{{{newline}{child_indent}\"existing\": {raw_existing},{newline}{child_indent}\"{TIRITH_HOOK_KEY}\": [\"tirith\", \"init\", \"--shell\", \"auto\"]{newline}{property_indent}}}"
            );
            let mut output = input.to_string();
            output.replace_range(member.value_start..member.value_end, &replacement);
            Ok(Some(output))
        }
        Value::Null => {
            let mut output = input.to_string();
            output.replace_range(
                member.value_start..member.value_end,
                &managed_post_create_object(),
            );
            Ok(Some(output))
        }
        _ => Err("postCreateCommand must be a string, array, object, or null".to_string()),
    }
}

fn render_container_env(input: &str) -> Result<Option<String>, String> {
    let document = JsoncDocument::parse(input)?;
    let Some(member) = document.unique_member(&document.root, "containerEnv")? else {
        return Ok(Some(insert_jsonc_object_member(
            input,
            &document.root,
            "containerEnv",
            r#"{"TIRITH_DEVCONTAINER": "1"}"#,
        )));
    };
    match document.value(member)? {
        Value::Object(_) => {
            let environment = document.object_value(member)?;
            match document.unique_member(&environment, "TIRITH_DEVCONTAINER")? {
                Some(flag)
                    if document.value(flag)?.as_str().is_some_and(|value| {
                        value == "1" || value.eq_ignore_ascii_case("true")
                    }) =>
                {
                    Ok(None)
                }
                Some(flag) => {
                    let mut output = input.to_string();
                    output.replace_range(flag.value_start..flag.value_end, r#""1""#);
                    Ok(Some(output))
                }
                None => Ok(Some(insert_jsonc_object_member(
                    input,
                    &environment,
                    "TIRITH_DEVCONTAINER",
                    r#""1""#,
                ))),
            }
        }
        Value::Null => {
            let mut output = input.to_string();
            output.replace_range(
                member.value_start..member.value_end,
                r#"{"TIRITH_DEVCONTAINER": "1"}"#,
            );
            Ok(Some(output))
        }
        _ => Err("containerEnv must be an object or null".to_string()),
    }
}

fn managed_post_create_object() -> String {
    format!(r#"{{"{TIRITH_HOOK_KEY}": ["tirith", "init", "--shell", "auto"]}}"#)
}

fn insert_jsonc_object_member(input: &str, object: &JsoncObject, key: &str, value: &str) -> String {
    let newline = preferred_newline(input);
    let close_indent = line_indent(input, object.close);
    let member_indent = object
        .members
        .first()
        .map(|member| line_indent(input, member.key_start))
        .filter(|indent| indent.len() > close_indent.len())
        .unwrap_or_else(|| format!("{close_indent}  "));

    let mut output = input.to_string();
    let mut close = object.close;
    if !object.members.is_empty() && !object.trailing_comma {
        let comma_at = object.members.last().expect("non-empty members").value_end;
        output.insert(comma_at, ',');
        if comma_at <= close {
            close += 1;
        }
    }

    let begins_new_line = output[..close].ends_with('\n');
    let mut insertion = String::new();
    if !begins_new_line {
        insertion.push_str(newline);
    }
    insertion.push_str(&member_indent);
    insertion.push_str(&serde_json::to_string(key).expect("JSON object key serialization"));
    insertion.push_str(": ");
    insertion.push_str(value);
    insertion.push_str(newline);
    insertion.push_str(&close_indent);
    output.insert_str(close, &insertion);
    output
}

fn preferred_newline(input: &str) -> &'static str {
    if input.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn line_indent(input: &str, position: usize) -> String {
    let line_start = input[..position]
        .rfind('\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    input[line_start..position]
        .chars()
        .take_while(|character| matches!(character, ' ' | '\t' | '\r'))
        .collect()
}

fn mask_jsonc_comments(input: &str) -> Result<Vec<u8>, String> {
    let bytes = input.as_bytes();
    let mut masked = bytes.to_vec();
    if masked.starts_with(&[0xEF, 0xBB, 0xBF]) {
        masked[..3].fill(b' ');
    }
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index = json_string_end(bytes, index)?;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let start = index;
                index += 2;
                while bytes.get(index).is_some_and(|byte| *byte != b'\n') {
                    index += 1;
                }
                for byte in &mut masked[start..index] {
                    if *byte != b'\r' {
                        *byte = b' ';
                    }
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start = index;
                index += 2;
                while bytes.get(index..index + 2) != Some(b"*/") {
                    if index >= bytes.len() {
                        return Err("unterminated block comment in devcontainer.json".to_string());
                    }
                    index += 1;
                }
                index += 2;
                for byte in &mut masked[start..index] {
                    if !matches!(*byte, b'\n' | b'\r') {
                        *byte = b' ';
                    }
                }
            }
            _ => index += 1,
        }
    }
    Ok(masked)
}

fn mask_jsonc_trailing_commas(bytes: &mut [u8]) {
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index = json_string_end(bytes, index).unwrap_or(bytes.len());
            }
            b',' => {
                let after = skip_jsonc_whitespace(bytes, index + 1);
                if bytes
                    .get(after)
                    .is_some_and(|byte| matches!(*byte, b'}' | b']'))
                {
                    bytes[index] = b' ';
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
}

fn parse_jsonc_object(bytes: &[u8], start: usize) -> Result<JsoncObject, String> {
    if bytes.get(start) != Some(&b'{') {
        return Err("expected JSON object".to_string());
    }
    let mut members = Vec::new();
    let mut index = skip_jsonc_whitespace(bytes, start + 1);
    let mut trailing_comma = false;
    loop {
        if bytes.get(index) == Some(&b'}') {
            return Ok(JsoncObject {
                close: index,
                members,
                trailing_comma,
            });
        }
        if bytes.get(index) != Some(&b'"') {
            return Err("JSONC object keys must be double-quoted strings".to_string());
        }
        let key_start = index;
        let key_end = json_string_end(bytes, key_start)?;
        let key: String = serde_json::from_slice(&bytes[key_start..key_end])
            .map_err(|error| format!("invalid JSONC object key: {error}"))?;
        index = skip_jsonc_whitespace(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return Err(format!("missing colon after JSONC key `{key}`"));
        }
        let value_start = skip_jsonc_whitespace(bytes, index + 1);
        let value_end = skip_jsonc_value(bytes, value_start)?;
        members.push(JsoncMember {
            key,
            key_start,
            key_end,
            value_start,
            value_end,
        });
        index = skip_jsonc_whitespace(bytes, value_end);
        match bytes.get(index) {
            Some(b',') => {
                index = skip_jsonc_whitespace(bytes, index + 1);
                trailing_comma = bytes.get(index) == Some(&b'}');
            }
            Some(b'}') => {
                trailing_comma = false;
            }
            _ => return Err("expected comma or object close in JSONC".to_string()),
        }
    }
}

fn skip_jsonc_value(bytes: &[u8], start: usize) -> Result<usize, String> {
    match bytes.get(start) {
        Some(b'"') => json_string_end(bytes, start),
        Some(b'{') => Ok(parse_jsonc_object(bytes, start)?.close + 1),
        Some(b'[') => {
            let mut index = skip_jsonc_whitespace(bytes, start + 1);
            if bytes.get(index) == Some(&b']') {
                return Ok(index + 1);
            }
            loop {
                index = skip_jsonc_value(bytes, index)?;
                index = skip_jsonc_whitespace(bytes, index);
                match bytes.get(index) {
                    Some(b',') => {
                        index = skip_jsonc_whitespace(bytes, index + 1);
                        if bytes.get(index) == Some(&b']') {
                            return Ok(index + 1);
                        }
                    }
                    Some(b']') => return Ok(index + 1),
                    _ => return Err("expected comma or array close in JSONC".to_string()),
                }
            }
        }
        Some(_) => {
            let mut index = start;
            while bytes.get(index).is_some_and(|byte| {
                !byte.is_ascii_whitespace() && !matches!(*byte, b',' | b'}' | b']')
            }) {
                index += 1;
            }
            if index == start {
                Err("missing JSONC value".to_string())
            } else {
                Ok(index)
            }
        }
        None => Err("missing JSONC value".to_string()),
    }
}

fn json_string_end(bytes: &[u8], start: usize) -> Result<usize, String> {
    if bytes.get(start) != Some(&b'"') {
        return Err("expected JSON string".to_string());
    }
    let mut index = start + 1;
    let mut escaped = false;
    while let Some(byte) = bytes.get(index).copied() {
        index += 1;
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(index);
        }
    }
    Err("unterminated string in devcontainer.json".to_string())
}

fn skip_jsonc_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn write_pretty(prepared: &ContainedAtomicFile, value: &Value) -> Result<(), String> {
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| format!("serialize devcontainer.json: {e}"))?;
    let mut content = pretty;
    content.push('\n');
    prepared
        .write_atomic_if_observed(content.as_bytes(), true)
        .map_err(|e| format!("atomic write: {e}"))
}

/// Strip JSONC line/block comments and trailing commas (before `]`/`}`),
/// returning valid JSON. String-aware: `"..."` literals are preserved verbatim.
pub fn strip_jsonc_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if escape {
                escape = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escape = true;
                i += 1;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push(b);
            i += 1;
            continue;
        }
        // Line comment: skip to newline (keep the newline).
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment: skip until `*/`.
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                i = bytes.len();
            }
            continue;
        }
        out.push(b);
        i += 1;
    }

    // Trailing-comma cleanup: drop a `,` followed only by whitespace then `}`/`]`.
    let mut clean: Vec<u8> = Vec::with_capacity(out.len());
    let mut j = 0;
    let mut in_str = false;
    let mut esc = false;
    while j < out.len() {
        let b = out[j];
        if in_str {
            clean.push(b);
            if esc {
                esc = false;
                j += 1;
                continue;
            }
            if b == b'\\' {
                esc = true;
                j += 1;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            j += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
            clean.push(b);
            j += 1;
            continue;
        }
        if b == b',' {
            // Peek ahead skipping whitespace.
            let mut k = j + 1;
            while k < out.len() && (out[k] as char).is_whitespace() {
                k += 1;
            }
            if k < out.len() && (out[k] == b'}' || out[k] == b']') {
                // Skip the comma; keep whitespace so error line numbers stay stable.
                j += 1;
                continue;
            }
        }
        clean.push(b);
        j += 1;
    }
    String::from_utf8(clean).unwrap_or(input.to_string())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn strip_jsonc_comments_handles_line_and_block_and_trailing() {
        let input = r#"{
            // a line comment
            "name": "demo", /* block comment */
            "args": [
                "a",
                "b", // inline
            ],
        }"#;
        let out = strip_jsonc_comments(input);
        let v: Value = serde_json::from_str(&out).expect("strip output should parse");
        assert_eq!(v.get("name").and_then(Value::as_str), Some("demo"));
        assert_eq!(
            v.get("args").and_then(Value::as_array).map(|a| a.len()),
            Some(2)
        );
    }

    #[test]
    fn strip_jsonc_comments_preserves_string_literals_with_slashes() {
        // Hostnames inside string values must NOT be treated as comments.
        let input = r#"{ "url": "https://example.com/path // not a comment" }"#;
        let out = strip_jsonc_comments(input);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v.get("url").and_then(Value::as_str),
            Some("https://example.com/path // not a comment")
        );
    }

    #[test]
    fn inject_creates_minimal_file_when_missing_and_flagged() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".devcontainer/devcontainer.json");
        let outcome = inject_tirith_hook(&path, dir.path(), true);
        assert!(matches!(outcome, InjectOutcome::Created(_)));
        let value = read_devcontainer(&path);
        assert_exact_tirith_lifecycle_entry(&value);
        assert_eq!(value["containerEnv"]["TIRITH_DEVCONTAINER"], "1");
    }

    #[test]
    fn inject_idempotent_second_run_is_no_op() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".devcontainer/devcontainer.json");
        let first = inject_tirith_hook(&path, dir.path(), true);
        assert!(matches!(first, InjectOutcome::Created(_)));
        let second = inject_tirith_hook(&path, dir.path(), true);
        assert!(
            matches!(second, InjectOutcome::AlreadyInjected(_)),
            "expected AlreadyInjected, got {second:?}"
        );
    }

    #[test]
    fn inject_appends_to_existing_post_create_string() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devcontainer.json");
        std::fs::write(
            &path,
            r#"{
                // comment ok
                "name": "demo",
                "postCreateCommand": "npm ci",
            }"#,
        )
        .unwrap();
        let outcome = inject_tirith_hook(&path, dir.path(), false);
        assert!(matches!(outcome, InjectOutcome::Updated(_)));
        let value = read_devcontainer(&path);
        assert_eq!(value["postCreateCommand"]["existing"], "npm ci");
        assert_exact_tirith_lifecycle_entry(&value);
    }

    #[test]
    fn inject_appends_to_existing_post_create_array() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devcontainer.json");
        std::fs::write(
            &path,
            r#"{ "name": "demo", "postCreateCommand": ["npm", "ci"] }"#,
        )
        .unwrap();
        let outcome = inject_tirith_hook(&path, dir.path(), false);
        assert!(matches!(outcome, InjectOutcome::Updated(_)));
        let value = read_devcontainer(&path);
        assert_eq!(value["postCreateCommand"]["existing"], json!(["npm", "ci"]));
        assert_exact_tirith_lifecycle_entry(&value);
    }

    fn read_devcontainer(path: &Path) -> Value {
        let body = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&strip_jsonc_comments(&body)).unwrap()
    }

    fn assert_exact_tirith_lifecycle_entry(value: &Value) {
        let commands = value
            .get("postCreateCommand")
            .and_then(Value::as_object)
            .expect("lifecycle command must be a multi-command object");
        assert_eq!(
            commands.get("tirith-init"),
            Some(&json!(["tirith", "init", "--shell", "auto"])),
            "the managed entry must be an exact argv invocation"
        );
    }

    #[test]
    fn inject_does_not_trust_a_tirith_substring() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devcontainer.json");
        std::fs::write(
            &path,
            r#"{
                "postCreateCommand": "echo 'tirith init --shell auto'",
                "containerEnv": { "TIRITH_DEVCONTAINER": "1" }
            }"#,
        )
        .unwrap();

        let outcome = inject_tirith_hook(&path, dir.path(), false);
        assert!(matches!(outcome, InjectOutcome::Updated(_)));
        let value = read_devcontainer(&path);
        assert_exact_tirith_lifecycle_entry(&value);
        assert_eq!(
            value["postCreateCommand"]["existing"], "echo 'tirith init --shell auto'",
            "the original command must be preserved without being trusted as the hook"
        );
    }

    #[test]
    fn inject_converts_string_to_independent_lifecycle_commands() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devcontainer.json");
        std::fs::write(&path, r#"{ "postCreateCommand": "exit 1" }"#).unwrap();

        assert!(matches!(
            inject_tirith_hook(&path, dir.path(), false),
            InjectOutcome::Updated(_)
        ));
        let value = read_devcontainer(&path);
        assert_exact_tirith_lifecycle_entry(&value);
        assert_eq!(value["postCreateCommand"]["existing"], "exit 1");
    }

    #[test]
    fn inject_preserves_argv_array_as_one_independent_command() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devcontainer.json");
        std::fs::write(
            &path,
            r#"{ "postCreateCommand": ["npm", "ci", "--ignore-scripts"] }"#,
        )
        .unwrap();

        assert!(matches!(
            inject_tirith_hook(&path, dir.path(), false),
            InjectOutcome::Updated(_)
        ));
        let value = read_devcontainer(&path);
        assert_exact_tirith_lifecycle_entry(&value);
        assert_eq!(
            value["postCreateCommand"]["existing"],
            json!(["npm", "ci", "--ignore-scripts"])
        );
    }

    #[test]
    fn inject_preserves_existing_multi_command_object() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("devcontainer.json");
        std::fs::write(
            &path,
            r#"{
                "postCreateCommand": {
                    "dependencies": ["npm", "ci"],
                    "notice": "echo ready"
                }
            }"#,
        )
        .unwrap();

        assert!(matches!(
            inject_tirith_hook(&path, dir.path(), false),
            InjectOutcome::Updated(_)
        ));
        let value = read_devcontainer(&path);
        assert_exact_tirith_lifecycle_entry(&value);
        assert_eq!(
            value["postCreateCommand"]["dependencies"],
            json!(["npm", "ci"])
        );
        assert_eq!(value["postCreateCommand"]["notice"], "echo ready");
    }

    #[test]
    fn jsonc_render_preserves_comments_trailing_commas_crlf_and_urls() {
        let input = concat!(
            "{\r\n",
            "  // root comment\r\n",
            "  \"url\": \"https://example.test/a//b\", // URL comment\r\n",
            "  \"postCreateCommand\": [\r\n",
            "    \"npm\", /* array comment */\r\n",
            "    \"ci\",\r\n",
            "  ],\r\n",
            "  \"containerEnv\": {\r\n",
            "    // environment comment\r\n",
            "    \"EXISTING\": \"yes\",\r\n",
            "  },\r\n",
            "  // closing comment\r\n",
            "}\r\n",
        );

        let rendered = render_tirith_hook_jsonc(input)
            .expect("valid JSONC")
            .expect("hook is missing");
        for preserved in [
            "// root comment",
            "https://example.test/a//b",
            "// URL comment",
            "/* array comment */",
            "// environment comment",
            "// closing comment",
        ] {
            assert!(rendered.contains(preserved), "lost `{preserved}`");
        }
        assert!(rendered.contains("\r\n"));
        assert!(!rendered.replace("\r\n", "").contains('\n'));

        let effective: Value = serde_json::from_str(&strip_jsonc_comments(&rendered)).unwrap();
        assert_eq!(
            effective["postCreateCommand"]["existing"],
            json!(["npm", "ci"])
        );
        assert_exact_tirith_lifecycle_entry(&effective);
        assert_eq!(effective["containerEnv"]["EXISTING"], "yes");
        assert_eq!(effective["containerEnv"]["TIRITH_DEVCONTAINER"], "1");
        assert_eq!(
            render_tirith_hook_jsonc(&rendered).unwrap(),
            None,
            "second render must be byte-preserving"
        );
    }

    #[test]
    fn jsonc_render_preserves_conflicting_managed_entry_under_unique_key() {
        let input = r#"{
  "postCreateCommand": {
    // keep the user command and its comment
    "tirith-init": ["echo", "not tirith"],
    "tirith-init-existing": "occupied",
  },
  "containerEnv": null,
}"#;
        let rendered = render_tirith_hook_jsonc(input).unwrap().unwrap();
        assert!(rendered.contains("// keep the user command and its comment"));
        let effective: Value = serde_json::from_str(&strip_jsonc_comments(&rendered)).unwrap();
        assert_eq!(
            effective["postCreateCommand"]["tirith-init-existing-1"],
            json!(["echo", "not tirith"])
        );
        assert_eq!(
            effective["postCreateCommand"]["tirith-init-existing"],
            "occupied"
        );
        assert_exact_tirith_lifecycle_entry(&effective);
        assert_eq!(effective["containerEnv"]["TIRITH_DEVCONTAINER"], "1");
    }

    #[test]
    fn jsonc_render_rejects_ambiguous_or_incompatible_managed_fields() {
        for input in [
            r#"{"postCreateCommand": null, "postCreate\u0043ommand": null}"#,
            r#"{"postCreateCommand": 42}"#,
            r#"{"containerEnv": ["not", "an", "object"]}"#,
            r#"{/* unterminated"#,
        ] {
            assert!(
                render_tirith_hook_jsonc(input).is_err(),
                "unsafe document unexpectedly accepted: {input}"
            );
        }
    }

    #[test]
    fn inject_returns_not_found_when_create_disabled() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let outcome = inject_tirith_hook(&path, dir.path(), false);
        assert!(matches!(outcome, InjectOutcome::NotFound(_)));
    }

    #[test]
    fn find_devcontainer_json_prefers_nested() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join(".devcontainer/devcontainer.json");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        std::fs::write(&nested, "{}").unwrap();
        let flat = dir.path().join(".devcontainer.json");
        std::fs::write(&flat, "{}").unwrap();
        let found = find_devcontainer_json(dir.path()).unwrap();
        assert_eq!(found, nested);
    }

    #[test]
    fn ensure_gitignore_appends_when_missing() {
        let dir = tempdir().unwrap();
        let added = ensure_gitignore_entry(dir.path()).unwrap();
        assert!(added);
        let body = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(body.contains(".tirith/"));
    }

    #[test]
    fn ensure_gitignore_idempotent() {
        let dir = tempdir().unwrap();
        ensure_gitignore_entry(dir.path()).unwrap();
        let added_again = ensure_gitignore_entry(dir.path()).unwrap();
        assert!(!added_again, "second call must report nothing was added");
    }

    #[cfg(unix)]
    #[test]
    fn inject_refuses_symlinked_devcontainer_json() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let external = outside.path().join("external.json");
        std::fs::write(&external, r#"{ "name": "victim" }"#).unwrap();
        let link = dir.path().join(".devcontainer.json");
        std::os::unix::fs::symlink(&external, &link).unwrap();

        // Discovery must skip the planted link...
        assert!(find_devcontainer_json(dir.path()).is_none());
        // ...and a direct inject must refuse rather than rewrite the target.
        let outcome = inject_tirith_hook(&link, dir.path(), false);
        assert!(
            matches!(outcome, InjectOutcome::ParseError(_, _)),
            "expected refusal, got {outcome:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&external).unwrap(),
            r#"{ "name": "victim" }"#,
            "the external symlink target must remain byte-identical"
        );
    }

    #[cfg(unix)]
    #[test]
    fn inject_refuses_symlinked_devcontainer_parent() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::write(
            outside.path().join("devcontainer.json"),
            r#"{ "name": "victim" }"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".devcontainer")).unwrap();

        assert!(find_devcontainer_json(dir.path()).is_none());
        let nested = dir.path().join(".devcontainer/devcontainer.json");
        let outcome = inject_tirith_hook(&nested, dir.path(), true);
        assert!(
            matches!(outcome, InjectOutcome::ParseError(_, _)),
            "expected refusal through a symlinked parent, got {outcome:?}"
        );
        assert_eq!(
            std::fs::read_to_string(outside.path().join("devcontainer.json")).unwrap(),
            r#"{ "name": "victim" }"#
        );
    }

    #[cfg(unix)]
    #[test]
    fn gitignore_entry_refuses_symlink_and_unreadable_content() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let external = outside.path().join("notes.txt");
        std::fs::write(&external, "do not append here\n").unwrap();
        std::os::unix::fs::symlink(&external, dir.path().join(".gitignore")).unwrap();

        assert!(ensure_gitignore_entry(dir.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(&external).unwrap(),
            "do not append here\n",
            "the symlink target must not receive the Tirith stanza"
        );
    }
}
