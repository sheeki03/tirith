//! Shared idempotent writer for `.devcontainer/devcontainer.json` (M8 ch5):
//! adds an independent, structurally exact Tirith `postCreateCommand` plus
//! `TIRITH_DEVCONTAINER=1` in `containerEnv`.
//!
//! JSONC support is best-effort, not complete (no single-quoted strings,
//! unquoted keys, or Unicode-escape edge cases): we strip line/block comments
//! and trailing commas string-aware, then parse with `serde_json`. Comments
//! inside the file do NOT survive the rewrite (we re-emit via
//! `to_string_pretty`); untouched fields keep their values but lose formatting.

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

    let stripped = strip_jsonc_comments(&content_str);
    let mut value: Value = match serde_json::from_str(&stripped) {
        Ok(v) => v,
        Err(e) => {
            return InjectOutcome::ParseError(path.to_path_buf(), format!("parse error: {e}"));
        }
    };

    if has_tirith_marker(&value) && has_env_flag(&value) {
        return InjectOutcome::AlreadyInjected(path.to_path_buf());
    }

    if let Err(message) = upsert_post_create(&mut value) {
        return InjectOutcome::ParseError(path.to_path_buf(), message.to_string());
    }
    upsert_container_env_flag(&mut value);

    match write_pretty(&prepared, &value) {
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

fn has_tirith_marker(value: &Value) -> bool {
    value
        .get("postCreateCommand")
        .and_then(Value::as_object)
        .and_then(|commands| commands.get(TIRITH_HOOK_KEY))
        == Some(&tirith_hook_value())
}

fn has_env_flag(value: &Value) -> bool {
    value
        .get("containerEnv")
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("TIRITH_DEVCONTAINER"))
        .and_then(|v| v.as_str())
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn tirith_hook_value() -> Value {
    json!(TIRITH_HOOK_ARGV)
}

fn preserve_managed_key_collision(commands: &mut serde_json::Map<String, Value>) {
    let Some(existing) = commands.remove(TIRITH_HOOK_KEY) else {
        return;
    };
    let mut suffix = 0usize;
    loop {
        let candidate = if suffix == 0 {
            format!("{TIRITH_HOOK_KEY}-existing")
        } else {
            format!("{TIRITH_HOOK_KEY}-existing-{suffix}")
        };
        if !commands.contains_key(&candidate) {
            commands.insert(candidate, existing);
            return;
        }
        suffix = suffix.saturating_add(1);
    }
}

fn upsert_post_create(value: &mut Value) -> Result<(), &'static str> {
    let obj = value
        .as_object_mut()
        .ok_or("devcontainer.json root must be an object")?;
    let existing = obj.remove("postCreateCommand");
    let mut commands = match existing {
        Some(Value::Object(commands)) => commands,
        Some(existing @ (Value::String(_) | Value::Array(_))) => {
            let mut commands = serde_json::Map::new();
            commands.insert("existing".to_string(), existing);
            commands
        }
        Some(Value::Null) | None => serde_json::Map::new(),
        Some(_) => return Err("postCreateCommand must be a string, array, or object"),
    };

    if commands.get(TIRITH_HOOK_KEY) != Some(&tirith_hook_value()) {
        preserve_managed_key_collision(&mut commands);
        commands.insert(TIRITH_HOOK_KEY.to_string(), tirith_hook_value());
    }
    obj.insert("postCreateCommand".to_string(), Value::Object(commands));
    Ok(())
}

fn upsert_container_env_flag(value: &mut Value) {
    let obj = match value.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    let env = obj
        .entry("containerEnv".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(env_obj) = env.as_object_mut() {
        env_obj.insert(
            "TIRITH_DEVCONTAINER".to_string(),
            Value::String("1".to_string()),
        );
    }
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
        serde_json::from_str(&body).unwrap()
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
