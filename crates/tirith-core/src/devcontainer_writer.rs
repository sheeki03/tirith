//! Shared writer for `.devcontainer/devcontainer.json` (M8 ch5).
//!
//! Both `tirith devcontainer inject` and `tirith codespaces setup` /
//! `inject` need to (a) parse an existing `devcontainer.json` (JSONC —
//! comments and trailing commas are allowed), (b) append a tirith
//! `postCreateCommand` line, and (c) set `TIRITH_DEVCONTAINER=1` in
//! `containerEnv`. All three steps must be **idempotent** — re-running
//! the inject must be a no-op.
//!
//! ## JSONC parser decision
//!
//! `serde_jsonc` is NOT a workspace dep (and the published crate has
//! limited test coverage). Instead this module strips line comments
//! (`// …`), block comments (`/* … */`), and trailing commas itself,
//! then parses with `serde_json::Value`. The strip step is
//! string-aware so a `//` or `/*` inside a JSON string literal is
//! preserved verbatim.
//!
//! The strip-then-parse approach loses original formatting on rewrite,
//! but that is acceptable here — the writer reconstructs a minimal
//! pretty-printed file with the tirith additions. The injection is
//! idempotent (a re-run with the tirith hook already present is a
//! no-op), so operators do not lose hand-edits to fields tirith does
//! not touch (`name`, `image`, `features`, `customizations`, etc.).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Sentinel string we embed in the `postCreateCommand` so the next
/// inject run can detect that tirith has already wired itself.
pub const TIRITH_HOOK_MARKER: &str = "tirith init";

/// Outcome of an inject / setup operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectOutcome {
    /// File did not exist — `setup` created a minimal one with the
    /// tirith hook. `inject` returns this only when called with
    /// `create_if_missing = true`.
    Created(PathBuf),
    /// File existed and was modified to add the tirith hook /
    /// `TIRITH_DEVCONTAINER=1`.
    Updated(PathBuf),
    /// File already contained the tirith hook — no-op.
    AlreadyInjected(PathBuf),
    /// File did not exist and `create_if_missing` was false. `inject`
    /// reports this as an error to the caller.
    NotFound(PathBuf),
    /// File existed but could not be parsed as JSONC. The caller
    /// should surface the message to the operator.
    ParseError(PathBuf, String),
}

/// Find the devcontainer.json file under `cwd`. Searches:
///   1. `cwd/.devcontainer/devcontainer.json`
///   2. `cwd/.devcontainer.json` (Codespaces also accepts this)
///
/// Returns the first existing one, or `None` when neither exists.
pub fn find_devcontainer_json(cwd: &Path) -> Option<PathBuf> {
    let nested = cwd.join(".devcontainer").join("devcontainer.json");
    if nested.is_file() {
        return Some(nested);
    }
    let flat = cwd.join(".devcontainer.json");
    if flat.is_file() {
        return Some(flat);
    }
    None
}

/// Default devcontainer.json path used when `find_devcontainer_json`
/// returns `None`. Always the nested variant — Codespaces' UI defaults
/// to the same layout when scaffolding a new container.
pub fn default_devcontainer_json(cwd: &Path) -> PathBuf {
    cwd.join(".devcontainer").join("devcontainer.json")
}

/// Append the tirith `postCreateCommand` + `TIRITH_DEVCONTAINER=1`
/// `containerEnv` entry to an existing devcontainer.json, OR (when
/// `create_if_missing = true`) write a minimal one with just the
/// tirith hook.
///
/// **Idempotent.** Re-running with the marker already present
/// returns [`InjectOutcome::AlreadyInjected`] and does not touch the
/// file.
pub fn inject_tirith_hook(path: &Path, create_if_missing: bool) -> InjectOutcome {
    let content_str = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create_if_missing {
                return InjectOutcome::NotFound(path.to_path_buf());
            }
            // Write a minimal devcontainer.json with the tirith hook
            // wired in. Operators routinely re-edit this file with
            // their image / features / name, so we keep the seed
            // narrow.
            let value = json!({
                "name": "tirith-protected devcontainer",
                "postCreateCommand": format!("{TIRITH_HOOK_MARKER} --shell auto || true"),
                "containerEnv": { "TIRITH_DEVCONTAINER": "1" },
            });
            match write_pretty(path, &value) {
                Ok(()) => return InjectOutcome::Created(path.to_path_buf()),
                Err(e) => return InjectOutcome::ParseError(path.to_path_buf(), e),
            }
        }
        Err(e) => {
            return InjectOutcome::ParseError(path.to_path_buf(), format!("read error: {e}"));
        }
    };

    // Parse the JSONC.
    let stripped = strip_jsonc_comments(&content_str);
    let mut value: Value = match serde_json::from_str(&stripped) {
        Ok(v) => v,
        Err(e) => {
            return InjectOutcome::ParseError(path.to_path_buf(), format!("parse error: {e}"));
        }
    };

    // Already injected? Check whether `postCreateCommand` contains the
    // marker `tirith init`. Two shapes: a string or an array of strings.
    if has_tirith_marker(&value) && has_env_flag(&value) {
        return InjectOutcome::AlreadyInjected(path.to_path_buf());
    }

    // Merge in the hook + env. The merge is order-preserving where we
    // can, but the strip-and-rewrite step always reformats the file,
    // so we don't try to preserve original whitespace.
    upsert_post_create(&mut value);
    upsert_container_env_flag(&mut value);

    match write_pretty(path, &value) {
        Ok(()) => InjectOutcome::Updated(path.to_path_buf()),
        Err(e) => InjectOutcome::ParseError(path.to_path_buf(), e),
    }
}

/// Helper for the codespaces setup path: ensures `<cwd>/.gitignore`
/// has a `.tirith/` entry so per-codespace state directories never
/// leak into the operator's repo. Idempotent.
pub fn ensure_gitignore_entry(cwd: &Path) -> std::io::Result<bool> {
    let path = cwd.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    // Match the bare `.tirith/` or `.tirith` line (with optional
    // leading whitespace / trailing slash variants). Word-anchored
    // comparison would be overkill; line-trimmed prefix is enough.
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
    std::fs::write(&path, new_content)?;
    Ok(true)
}

// ─── internals ─────────────────────────────────────────────────────

fn has_tirith_marker(value: &Value) -> bool {
    match value.get("postCreateCommand") {
        Some(Value::String(s)) => s.contains(TIRITH_HOOK_MARKER),
        Some(Value::Array(items)) => items.iter().any(|v| {
            v.as_str()
                .map(|s| s.contains(TIRITH_HOOK_MARKER))
                .unwrap_or(false)
        }),
        _ => false,
    }
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

fn upsert_post_create(value: &mut Value) {
    let obj = match value.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    let existing = obj.remove("postCreateCommand");
    let tirith_cmd = format!("{TIRITH_HOOK_MARKER} --shell auto || true");
    match existing {
        Some(Value::String(s)) => {
            if s.contains(TIRITH_HOOK_MARKER) {
                obj.insert("postCreateCommand".to_string(), Value::String(s));
            } else {
                // Join with `&&` so the user's command still runs
                // before tirith installs the hook.
                let joined = format!("{s} && {tirith_cmd}");
                obj.insert("postCreateCommand".to_string(), Value::String(joined));
            }
        }
        Some(Value::Array(mut items)) => {
            let already = items.iter().any(|v| {
                v.as_str()
                    .map(|s| s.contains(TIRITH_HOOK_MARKER))
                    .unwrap_or(false)
            });
            if !already {
                items.push(Value::String(tirith_cmd));
            }
            obj.insert("postCreateCommand".to_string(), Value::Array(items));
        }
        Some(other) => {
            // Unknown shape — replace with our string form rather than
            // silently corrupting the file.
            obj.insert("postCreateCommand".to_string(), other);
        }
        None => {
            obj.insert("postCreateCommand".to_string(), Value::String(tirith_cmd));
        }
    }
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

fn write_pretty(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err(format!("create dir {}: {e}", parent.display()));
        }
    }
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| format!("serialize devcontainer.json: {e}"))?;
    let mut content = pretty;
    content.push('\n');
    std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Strip JSONC-style comments and trailing commas from `input`,
/// returning a valid JSON string.
///
/// Handles:
///  * `// line comments`
///  * `/* block comments */`
///  * Trailing commas before `]` and `}` (legal in JSONC).
///
/// String-aware: `"..."` literals (with `\"` escapes) are preserved
/// verbatim.
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
        // Line comment: skip until newline (preserve the newline).
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

    // Trailing-comma cleanup pass. Walk byte-by-byte, drop a `,` that
    // is followed by optional whitespace and then `}` or `]`.
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
                // Skip the comma entirely (keep the whitespace so
                // line numbers stay roughly stable in errors).
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
        // Must parse cleanly as serde_json.
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
        let outcome = inject_tirith_hook(&path, true);
        assert!(matches!(outcome, InjectOutcome::Created(_)));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("tirith init"));
        assert!(body.contains("TIRITH_DEVCONTAINER"));
    }

    #[test]
    fn inject_idempotent_second_run_is_no_op() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".devcontainer/devcontainer.json");
        let first = inject_tirith_hook(&path, true);
        assert!(matches!(first, InjectOutcome::Created(_)));
        let second = inject_tirith_hook(&path, true);
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
        let outcome = inject_tirith_hook(&path, false);
        assert!(matches!(outcome, InjectOutcome::Updated(_)));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("npm ci"), "expected user's command preserved");
        assert!(
            body.contains("tirith init"),
            "expected tirith hook appended"
        );
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
        let outcome = inject_tirith_hook(&path, false);
        assert!(matches!(outcome, InjectOutcome::Updated(_)));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("tirith init"));
    }

    #[test]
    fn inject_returns_not_found_when_create_disabled() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let outcome = inject_tirith_hook(&path, false);
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
}
