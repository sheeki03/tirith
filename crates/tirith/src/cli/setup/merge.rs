use std::fmt;
use std::path::Path;

use serde::de::{Deserialize, IgnoredAny, MapAccess, Visitor};
use serde_json::{json, Value};

/// Merge a server entry into an MCP JSON config file under `"mcpServers"`.
/// Skips identical config; errors on drift unless `force`.
pub fn merge_mcp_json(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_mcp_json_with_key(
        path,
        scope_root,
        server_name,
        server_config,
        "mcpServers",
        force,
        dry_run,
    )
}

/// Like `merge_mcp_json` but with a custom top-level key (e.g. `"servers"` for VS Code).
pub fn merge_mcp_json_with_key(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = super::fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let mut config: Value = if let Some(raw) = snapshot.text(path)? {
            serde_json::from_str(raw).map_err(|e| format!("parse {}: {e}", path.display()))?
        } else {
            json!({})
        };
        let servers = config
            .as_object_mut()
            .ok_or_else(|| format!("{} is not a JSON object", path.display()))?
            .entry(server_key)
            .or_insert_with(|| json!({}));
        let servers_obj = servers
            .as_object_mut()
            .ok_or_else(|| format!("{server_key} in {} is not an object", path.display()))?;

        let mut backup = false;
        if let Some(existing) = servers_obj.get(server_name) {
            if !force {
                if existing == &server_config {
                    eprintln!(
                        "tirith: {server_name} already in {}, up to date",
                        path.display()
                    );
                    return Ok(super::fs_helpers::FileUpdate::unchanged());
                }
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: {server_name} in {} has different config — use --force to update",
                        path.display()
                    );
                    return Ok(super::fs_helpers::FileUpdate::unchanged());
                }
                return Err(format!(
                    "tirith: {server_name} in {} has different config than expected — use --force to update",
                    path.display()
                ));
            }
            backup = true;
        }
        servers_obj.insert(server_name.to_string(), server_config.clone());
        let content =
            serde_json::to_string_pretty(&config).map_err(|error| format!("serialize: {error}"))?;
        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                content.len()
            );
        }
        Ok(super::fs_helpers::FileUpdate::write_text(content, 0o644).with_backup(backup))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

/// Merge one MCP server into a JSON or JSONC configuration while preserving
/// every unrelated byte. This is used by clients whose supported config may
/// contain comments (notably OpenCode), so parsing and re-serializing the whole
/// document would be an unnecessarily destructive setup operation.
// The explicit scope root and output mode are security boundaries and must not
// be inferred from the destination path.
#[allow(clippy::too_many_arguments)]
pub fn merge_mcp_jsonc_with_key(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    mode: u32,
    exact_mode: bool,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_mcp_jsonc_with_key_inner(
        path,
        scope_root,
        server_name,
        server_config,
        server_key,
        None,
        false,
        StrictJsonEmptyPolicy::Reject,
        mode,
        exact_mode,
        force,
        dry_run,
    )
}

/// Merge one MCP server into a strict-JSON configuration while preserving
/// unrelated bytes. Unlike [`merge_mcp_jsonc_with_key`], this rejects comments,
/// trailing commas, and every other extension that the target host's
/// `JSON.parse` loader would reject.
#[allow(clippy::too_many_arguments)]
pub fn merge_mcp_strict_json_with_key(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    mode: u32,
    exact_mode: bool,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_mcp_jsonc_with_key_inner(
        path,
        scope_root,
        server_name,
        server_config,
        server_key,
        None,
        true,
        StrictJsonEmptyPolicy::Reject,
        mode,
        exact_mode,
        force,
        dry_run,
    )
}

/// Strict-JSON merge for hosts that define an existing zero-byte settings file
/// as their initial `{}` state. This exception is deliberately separate from
/// [`merge_mcp_strict_json_with_key`] so strict hosts without that documented
/// bootstrap behavior continue to reject empty input.
#[allow(clippy::too_many_arguments)]
pub fn merge_mcp_strict_json_with_key_allow_empty(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    mode: u32,
    exact_mode: bool,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_mcp_jsonc_with_key_inner(
        path,
        scope_root,
        server_name,
        server_config,
        server_key,
        None,
        true,
        StrictJsonEmptyPolicy::ExactEmpty,
        mode,
        exact_mode,
        force,
        dry_run,
    )
}

/// Strict-JSON merge for hosts that trim an existing settings file before
/// treating empty content as their initial `{}` state.
#[allow(clippy::too_many_arguments)]
pub fn merge_mcp_strict_json_with_key_allow_blank(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    mode: u32,
    exact_mode: bool,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_mcp_jsonc_with_key_inner(
        path,
        scope_root,
        server_name,
        server_config,
        server_key,
        None,
        true,
        StrictJsonEmptyPolicy::WhitespaceOnly,
        mode,
        exact_mode,
        force,
        dry_run,
    )
}

/// Merge an MCP server and remove its name from a top-level disable list in
/// one strict-JSON transaction. OMP's `disabledServers` has higher precedence
/// than every server-level `enabled` value, so these changes must publish as a
/// single unit.
#[allow(clippy::too_many_arguments)]
pub fn merge_mcp_strict_json_with_key_and_enable(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    disabled_key: &str,
    mode: u32,
    exact_mode: bool,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_mcp_jsonc_with_key_inner(
        path,
        scope_root,
        server_name,
        server_config,
        server_key,
        Some(disabled_key),
        true,
        StrictJsonEmptyPolicy::Reject,
        mode,
        exact_mode,
        force,
        dry_run,
    )
}

#[derive(Clone, Copy)]
enum StrictJsonEmptyPolicy {
    Reject,
    ExactEmpty,
    WhitespaceOnly,
}

#[allow(clippy::too_many_arguments)]
fn merge_mcp_jsonc_with_key_inner(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    server_key: &str,
    disabled_key: Option<&str>,
    strict_json: bool,
    empty_policy: StrictJsonEmptyPolicy,
    mode: u32,
    exact_mode: bool,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = super::fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let snapshot_raw = snapshot.text(path)?;
        let raw = snapshot_raw.unwrap_or("{\n}\n");
        let raw = match empty_policy {
            StrictJsonEmptyPolicy::ExactEmpty if snapshot_raw.is_some() && raw.is_empty() => {
                "{\n}\n"
            }
            StrictJsonEmptyPolicy::WhitespaceOnly
                if snapshot_raw.is_some() && raw.trim().is_empty() =>
            {
                "{\n}\n"
            }
            _ => raw,
        };
        if strict_json {
            let parsed: Value = serde_json::from_str(raw).map_err(|error| {
                format!("tirith: {} is not strict JSON: {error}", path.display())
            })?;
            if !parsed.is_object() {
                return Err(format!("tirith: {} is not a JSON object", path.display()));
            }
        }
        let root = parse_jsonc_root(raw)
            .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
        let lex = lex_jsonc(raw)
            .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
        let root_span = scan_jsonc_object(&lex.without_comments, 0, path)?;
        if root_span.close != root.close {
            return Err(format!(
                "tirith: {} has content outside its root JSON object",
                path.display()
            ));
        }

        let server_key_entries: Vec<&JsoncObjectEntry> = root_span
            .entries
            .iter()
            .filter(|entry| entry.key == server_key)
            .collect();
        if server_key_entries.len() > 1 {
            return Err(format!(
                "tirith: {} contains duplicate {server_key:?} keys; fix it manually before setup",
                path.display()
            ));
        }
        let disabled_needs_update = disabled_key
            .map(|key| jsonc_top_level_string_array_contains(path, &root, key, server_name))
            .transpose()?
            .unwrap_or(false);

        let desired_map = json!({server_name: server_config.clone()});
        let mut rendered = if let Some(server_map_entry) = server_key_entries.first() {
            let server_map_value = root
                .value
                .get(server_key)
                .ok_or_else(|| format!("{server_key} missing in {}", path.display()))?;
            if !server_map_value.is_object() {
                return Err(format!(
                    "tirith: {server_key} in {} is not an object",
                    path.display()
                ));
            }
            let map_open = skip_jsonc_ws(&lex.without_comments, server_map_entry.value_start);
            if lex.without_comments.get(map_open) != Some(&b'{') {
                return Err(format!(
                    "tirith: {server_key} in {} is not an object",
                    path.display()
                ));
            }
            let server_map_span = scan_jsonc_object(&lex.without_comments, map_open, path)?;
            if server_map_span.close + 1 != server_map_entry.value_end {
                return Err(format!(
                    "tirith: {server_key} in {} is not a standalone object",
                    path.display()
                ));
            }
            let matching: Vec<&JsoncObjectEntry> = server_map_span
                .entries
                .iter()
                .filter(|entry| entry.key == server_name)
                .collect();
            if matching.len() > 1 {
                return Err(format!(
                    "tirith: {server_key} in {} contains duplicate {server_name:?} entries; fix it manually before setup",
                    path.display()
                ));
            }

            if let Some(existing_entry) = matching.first() {
                let existing = server_map_value
                    .get(server_name)
                    .ok_or_else(|| format!("{server_name} missing in {}", path.display()))?;
                if existing == &server_config && !disabled_needs_update {
                    #[cfg(unix)]
                    if exact_mode && snapshot.mode().unwrap_or(0) & 0o777 != mode {
                        if dry_run {
                            eprintln!(
                                "[dry-run] would correct {} permissions to mode {mode:04o}",
                                path.display()
                            );
                        }
                        return Ok(super::fs_helpers::FileUpdate::write_text(
                            raw.to_string(),
                            mode,
                        )
                        .with_exact_mode());
                    }
                    eprintln!(
                        "tirith: {server_name} already in {}, up to date",
                        path.display()
                    );
                    return Ok(super::fs_helpers::FileUpdate::unchanged());
                }
                if existing != &server_config && !force {
                    if dry_run {
                        eprintln!(
                            "[dry-run] would error: {server_name} in {} has different config — use --force to update",
                            path.display()
                        );
                        return Ok(super::fs_helpers::FileUpdate::unchanged());
                    }
                    return Err(format!(
                        "tirith: {server_name} in {} has different config than expected — use --force to update",
                        path.display()
                    ));
                }
                if existing == &server_config {
                    raw.to_string()
                } else {
                    replace_jsonc_value(raw, existing_entry, &server_config)?
                }
            } else {
                insert_jsonc_entry(raw, &server_map_span, server_name, &server_config, 4)?
            }
        } else {
            insert_jsonc_entry(raw, &root_span, server_key, &desired_map, 2)?
        };

        if let Some(key) = disabled_key {
            rendered = remove_jsonc_top_level_array_string(path, &rendered, key, server_name)?;
        }
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        if strict_json {
            let parsed: Value = serde_json::from_str(&rendered).map_err(|error| {
                format!(
                    "tirith: generated {} is not strict JSON: {error}",
                    path.display()
                )
            })?;
            if !parsed.is_object() {
                return Err(format!(
                    "tirith: generated {} is not a JSON object",
                    path.display()
                ));
            }
        }
        verify_jsonc_server(path, &rendered, server_key, server_name, &server_config)?;
        if let Some(key) = disabled_key {
            let root = parse_jsonc_root(&rendered)
                .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
            if jsonc_top_level_string_array_contains(path, &root, key, server_name)? {
                return Err(format!(
                    "tirith: generated {} still disables {server_name:?} in {key}",
                    path.display()
                ));
            }
        }
        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                rendered.len()
            );
        }

        let update = super::fs_helpers::FileUpdate::write_text(rendered, mode)
            .with_backup(snapshot.exists());
        #[cfg(unix)]
        let update = if exact_mode {
            update.with_exact_mode()
        } else {
            update
        };
        #[cfg(not(unix))]
        let update = {
            let _ = exact_mode;
            update
        };
        Ok(update)
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

#[derive(Debug)]
struct JsoncObjectEntry {
    key: String,
    value_start: usize,
    value_end: usize,
}

#[derive(Debug)]
struct JsoncObjectSpan {
    close: usize,
    entries: Vec<JsoncObjectEntry>,
    trailing_comma: bool,
}

fn skip_jsonc_ws(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn json_string_end(bytes: &[u8], start: usize, path: &Path) -> Result<usize, String> {
    if bytes.get(start) != Some(&b'"') {
        return Err(format!(
            "tirith: expected a JSON string in {}",
            path.display()
        ));
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
    Err(format!(
        "tirith: unterminated JSON string in {}",
        path.display()
    ))
}

fn json_value_end(bytes: &[u8], start: usize, path: &Path) -> Result<usize, String> {
    let start = skip_jsonc_ws(bytes, start);
    match bytes.get(start).copied() {
        Some(b'"') => json_string_end(bytes, start, path),
        Some(b'{') | Some(b'[') => {
            let mut stack = Vec::new();
            let mut index = start;
            while let Some(byte) = bytes.get(index).copied() {
                match byte {
                    b'"' => index = json_string_end(bytes, index, path)?,
                    b'{' => {
                        stack.push(b'}');
                        index += 1;
                    }
                    b'[' => {
                        stack.push(b']');
                        index += 1;
                    }
                    b'}' | b']' => {
                        if stack.pop() != Some(byte) {
                            return Err(format!(
                                "tirith: unbalanced JSON value in {}",
                                path.display()
                            ));
                        }
                        index += 1;
                        if stack.is_empty() {
                            return Ok(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            Err(format!(
                "tirith: unterminated JSON value in {}",
                path.display()
            ))
        }
        Some(_) => {
            let mut end = start;
            while bytes
                .get(end)
                .is_some_and(|byte| !matches!(*byte, b',' | b'}'))
            {
                end += 1;
            }
            while end > start && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            if end == start {
                Err(format!("tirith: empty JSON value in {}", path.display()))
            } else {
                Ok(end)
            }
        }
        None => Err(format!("tirith: missing JSON value in {}", path.display())),
    }
}

fn scan_jsonc_object(bytes: &[u8], start: usize, path: &Path) -> Result<JsoncObjectSpan, String> {
    let start = skip_jsonc_ws(bytes, start);
    if bytes.get(start) != Some(&b'{') {
        return Err(format!(
            "tirith: {} root must be a JSON object",
            path.display()
        ));
    }
    let mut entries = Vec::new();
    let mut index = start + 1;
    let mut trailing_comma = false;
    loop {
        index = skip_jsonc_ws(bytes, index);
        match bytes.get(index).copied() {
            Some(b'}') => {
                return Ok(JsoncObjectSpan {
                    close: index,
                    entries,
                    trailing_comma,
                });
            }
            Some(b'"') => {}
            _ => {
                return Err(format!(
                    "tirith: expected a JSON object key in {}",
                    path.display()
                ));
            }
        }

        let key_start = index;
        let key_end = json_string_end(bytes, key_start, path)?;
        let key: String = serde_json::from_slice(&bytes[key_start..key_end])
            .map_err(|error| format!("parse JSON key in {}: {error}", path.display()))?;
        index = skip_jsonc_ws(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return Err(format!(
                "tirith: expected ':' after JSON key in {}",
                path.display()
            ));
        }
        let value_start = skip_jsonc_ws(bytes, index + 1);
        let value_end = json_value_end(bytes, value_start, path)?;
        entries.push(JsoncObjectEntry {
            key,
            value_start,
            value_end,
        });
        index = skip_jsonc_ws(bytes, value_end);
        match bytes.get(index).copied() {
            Some(b',') => {
                index += 1;
                let next = skip_jsonc_ws(bytes, index);
                trailing_comma = bytes.get(next) == Some(&b'}');
            }
            Some(b'}') => trailing_comma = false,
            _ => {
                return Err(format!(
                    "tirith: expected ',' or '}}' in {}",
                    path.display()
                ));
            }
        }
    }
}

fn replace_jsonc_value(
    raw: &str,
    entry: &JsoncObjectEntry,
    value: &Value,
) -> Result<String, String> {
    let replacement = serde_json::to_string(value)
        .map_err(|error| format!("serialize MCP server config: {error}"))?;
    let mut result = String::with_capacity(raw.len() + replacement.len());
    result.push_str(&raw[..entry.value_start]);
    result.push_str(&replacement);
    result.push_str(&raw[entry.value_end..]);
    Ok(result)
}

fn jsonc_top_level_string_array_contains(
    path: &Path,
    root: &JsoncRoot,
    key: &str,
    target: &str,
) -> Result<bool, String> {
    if root.key_count(key) > 1 {
        return Err(format!(
            "tirith: {} contains duplicate {key:?} keys; fix it manually before setup",
            path.display()
        ));
    }
    let Some(value) = root.value.get(key) else {
        return Ok(false);
    };
    let values = value
        .as_array()
        .ok_or_else(|| format!("tirith: {key} in {} is not an array", path.display()))?;
    if values.iter().any(|value| !value.is_string()) {
        return Err(format!(
            "tirith: {key} in {} must contain only strings",
            path.display()
        ));
    }
    Ok(values.iter().any(|value| value.as_str() == Some(target)))
}

fn remove_jsonc_top_level_array_string(
    path: &Path,
    raw: &str,
    key: &str,
    target: &str,
) -> Result<String, String> {
    let root = parse_jsonc_root(raw)
        .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
    if !jsonc_top_level_string_array_contains(path, &root, key, target)? {
        return Ok(raw.to_string());
    }
    let lex = lex_jsonc(raw)
        .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
    let span = scan_jsonc_object(&lex.without_comments, 0, path)?;
    let entry = span
        .entries
        .iter()
        .find(|entry| entry.key == key)
        .ok_or_else(|| format!("{key} missing in {}", path.display()))?;
    let filtered = root
        .value
        .get(key)
        .and_then(Value::as_array)
        .expect("validated string array")
        .iter()
        .filter(|value| value.as_str() != Some(target))
        .cloned()
        .collect();
    replace_jsonc_value(raw, entry, &Value::Array(filtered))
}

/// Read one MCP server from JSON/JSONC while rejecting ambiguous duplicate
/// keys. Used to preflight later-precedence client config before any write.
pub(super) fn jsonc_mcp_server(
    path: &Path,
    raw: &str,
    server_key: &str,
    server_name: &str,
) -> Result<Option<Value>, String> {
    let root = parse_jsonc_root(raw)
        .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
    if root.key_count(server_key) > 1 {
        return Err(format!(
            "tirith: {} contains duplicate {server_key:?} keys; fix it manually before setup",
            path.display()
        ));
    }
    let Some(servers) = root.value.get(server_key) else {
        return Ok(None);
    };
    if !servers.is_object() {
        return Err(format!(
            "tirith: {server_key} in {} is not an object",
            path.display()
        ));
    }

    let lex = lex_jsonc(raw)
        .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
    let root_span = scan_jsonc_object(&lex.without_comments, 0, path)?;
    let map_entry = root_span
        .entries
        .iter()
        .find(|entry| entry.key == server_key)
        .ok_or_else(|| format!("{server_key} missing in {}", path.display()))?;
    let map_open = skip_jsonc_ws(&lex.without_comments, map_entry.value_start);
    let map_span = scan_jsonc_object(&lex.without_comments, map_open, path)?;
    let matching = map_span
        .entries
        .iter()
        .filter(|entry| entry.key == server_name)
        .count();
    if matching > 1 {
        return Err(format!(
            "tirith: {server_key} in {} contains duplicate {server_name:?} entries; fix it manually before setup",
            path.display()
        ));
    }
    Ok(servers.get(server_name).cloned())
}

fn insert_jsonc_entry(
    raw: &str,
    object: &JsoncObjectSpan,
    key: &str,
    value: &Value,
    indent: usize,
) -> Result<String, String> {
    let key = serde_json::to_string(key).map_err(|error| format!("serialize key: {error}"))?;
    let value = serde_json::to_string(value)
        .map_err(|error| format!("serialize MCP server config: {error}"))?;
    let mut prefix = raw[..object.close].to_string();
    if !object.entries.is_empty() && !object.trailing_comma {
        let insert_at = object
            .entries
            .last()
            .expect("non-empty JSON object has a final entry")
            .value_end;
        prefix.insert(insert_at, ',');
    }
    if !prefix.ends_with('\n') {
        prefix.push('\n');
    }
    prefix.push_str(&" ".repeat(indent));
    prefix.push_str(&key);
    prefix.push_str(": ");
    prefix.push_str(&value);
    prefix.push('\n');
    prefix.push_str(&" ".repeat(indent.saturating_sub(2)));
    prefix.push_str(&raw[object.close..]);
    Ok(prefix)
}

fn verify_jsonc_server(
    path: &Path,
    raw: &str,
    server_key: &str,
    server_name: &str,
    expected: &Value,
) -> Result<(), String> {
    let root = parse_jsonc_root(raw)
        .map_err(|error| error.replace("VS Code settings", &path.display().to_string()))?;
    if root.key_count(server_key) != 1
        || root
            .value
            .get(server_key)
            .and_then(Value::as_object)
            .and_then(|servers| servers.get(server_name))
            != Some(expected)
    {
        return Err(format!(
            "tirith: generated {} does not expose the exact expected {server_key}.{server_name} entry",
            path.display()
        ));
    }
    Ok(())
}

/// Merge a hook entry into a hooks.json file (Cursor/Windsurf format).
/// Detects existing tirith hooks by the `marker` substring in each `command`.
// The explicit scope root is a security boundary and must not be inferred from
// the destination path, so retain it even though this makes eight parameters.
#[allow(clippy::too_many_arguments)]
pub fn merge_hooks_json(
    path: &Path,
    scope_root: &Path,
    event_name: &str,
    hook_entry: Value,
    marker: &str,
    force: bool,
    dry_run: bool,
    require_version: bool,
) -> Result<(), String> {
    let outcome = super::fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let mut config: Value = if let Some(raw) = snapshot.text(path)? {
            serde_json::from_str(raw).map_err(|e| format!("parse {}: {e}", path.display()))?
        } else if require_version {
            json!({"version": 1, "hooks": {}})
        } else {
            json!({"hooks": {}})
        };
        // repo-0429: when the consumer REQUIRES `version: 1` (Cursor), an
        // existing project-controlled hooks.json without it must not be
        // silently extended — Cursor would ignore the whole document and the
        // hook would never run. Fail loudly instead of reporting success.
        if require_version && config.get("version") != Some(&json!(1)) {
            return Err(format!(
                "tirith: {} exists without a `\"version\": 1` field; Cursor requires it, so no hook was added — fix or remove the file and re-run setup",
                path.display()
            ));
        }
        let hooks = config
            .as_object_mut()
            .ok_or_else(|| format!("{} is not a JSON object", path.display()))?
            .entry("hooks")
            .or_insert_with(|| json!({}));
        let hooks_obj = hooks
            .as_object_mut()
            .ok_or_else(|| format!("hooks in {} is not an object", path.display()))?;
        let event_arr = hooks_obj
            .entry(event_name)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| format!("hooks.{event_name} in {} is not an array", path.display()))?;
        let matching_indices: Vec<usize> = event_arr
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry
                    .get("command")
                    .and_then(|value| value.as_str())
                    .is_some_and(|command| command.contains(marker))
            })
            .map(|(index, _)| index)
            .collect();

        let backup = match matching_indices.len() {
            0 => {
                event_arr.push(hook_entry.clone());
                false
            }
            1 => {
                let index = matching_indices[0];
                if !force {
                    if event_arr[index] == hook_entry {
                        eprintln!("tirith: hook in {}, up to date", path.display());
                        return Ok(super::fs_helpers::FileUpdate::unchanged());
                    }
                    if dry_run {
                        eprintln!(
                            "[dry-run] would error: hook entry in {} has different config — use --force to update",
                            path.display()
                        );
                        return Ok(super::fs_helpers::FileUpdate::unchanged());
                    }
                    return Err(format!(
                        "tirith: hook entry in {} has different config than expected — use --force to update",
                        path.display()
                    ));
                }
                event_arr[index] = hook_entry.clone();
                true
            }
            _ => {
                if !force {
                    if dry_run {
                        eprintln!(
                            "[dry-run] would error: multiple tirith hook entries found in {} — use --force to deduplicate",
                            path.display()
                        );
                        return Ok(super::fs_helpers::FileUpdate::unchanged());
                    }
                    return Err(format!(
                        "tirith: multiple tirith hook entries found in {} — use --force to deduplicate",
                        path.display()
                    ));
                }
                for &index in matching_indices.iter().rev() {
                    event_arr.remove(index);
                }
                event_arr.push(hook_entry.clone());
                true
            }
        };
        let content =
            serde_json::to_string_pretty(&config).map_err(|error| format!("serialize: {error}"))?;
        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                content.len()
            );
        }
        Ok(super::fs_helpers::FileUpdate::write_text(content, 0o644).with_backup(backup))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

/// Merge a tirith MCP server into Claude Code's settings.json `mcpServers`.
/// Used for user-scope `--with-mcp` instead of `claude mcp add`, which deadlocks
/// inside an active Claude Code session. Same drift semantics as `merge_mcp_json`.
pub fn merge_claude_mcp_server(
    path: &Path,
    scope_root: &Path,
    server_name: &str,
    server_config: Value,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = super::fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let mut config: Value = if let Some(raw) = snapshot.text(path)? {
            serde_json::from_str(raw).map_err(|e| format!("parse {}: {e}", path.display()))?
        } else {
            json!({})
        };
        let servers = config
            .as_object_mut()
            .ok_or_else(|| format!("{} is not a JSON object", path.display()))?
            .entry("mcpServers")
            .or_insert_with(|| json!({}));
        let servers_obj = servers
            .as_object_mut()
            .ok_or_else(|| format!("mcpServers in {} is not an object", path.display()))?;
        let mut backup = false;
        if let Some(existing) = servers_obj.get(server_name) {
            if !force {
                if existing == &server_config {
                    eprintln!(
                        "tirith: {server_name} MCP server already in {}, up to date",
                        path.display()
                    );
                    return Ok(super::fs_helpers::FileUpdate::unchanged());
                }
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: {server_name} MCP server in {} has different config — use --force to update",
                        path.display()
                    );
                    return Ok(super::fs_helpers::FileUpdate::unchanged());
                }
                return Err(format!(
                    "{server_name} MCP server in {} has different config than expected — use --force to update",
                    path.display()
                ));
            }
            backup = true;
        }
        servers_obj.insert(server_name.to_string(), server_config.clone());
        let content =
            serde_json::to_string_pretty(&config).map_err(|error| format!("serialize: {error}"))?;
        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                content.len()
            );
        }
        Ok(super::fs_helpers::FileUpdate::write_text(content, 0o644).with_backup(backup))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!(
            "tirith: registered {server_name} MCP server in {}{annotation}",
            path.display(),
        );
    }
    Ok(())
}

/// Merge a tirith hook into a Claude Code / Gemini CLI settings.json
/// (`hooks.{event_name}[]` matcher entries, each with an inner `hooks[]`).
///
/// Operates at the individual hook-command level, preserving other hooks and
/// matchers. `marker` is a tool-specific filename substring used to detect the
/// existing tirith hook entry.
// Keep the trusted root explicit at this internal boundary for the same reason
// as merge_hooks_json.
#[allow(clippy::too_many_arguments)]
fn merge_hook_settings_inner(
    path: &Path,
    scope_root: &Path,
    event_name: &str,
    matcher_name: &str,
    hook_command: &str,
    marker: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = super::fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let mut config: Value = if let Some(raw) = snapshot.text(path)? {
            serde_json::from_str(raw).map_err(|e| format!("parse {}: {e}", path.display()))?
        } else {
            json!({})
        };

        let root = config
            .as_object_mut()
            .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;

        let hooks = root.entry("hooks").or_insert_with(|| json!({}));
        let hooks_obj = hooks
            .as_object_mut()
            .ok_or_else(|| format!("hooks in {} is not an object", path.display()))?;

        let event_arr = hooks_obj.entry(event_name).or_insert_with(|| json!([]));
        let arr = event_arr
            .as_array_mut()
            .ok_or_else(|| format!("hooks.{event_name} in {} is not an array", path.display()))?;

        let new_hook_entry = json!({
            "type": "command",
            "command": hook_command
        });
        let mut backup = false;

        let has_marker = |h: &Value| -> bool {
            h.get("command")
                .and_then(|v| v.as_str())
                .map(|cmd| cmd.contains(marker))
                .unwrap_or(false)
        };

        // All matcher indices matching matcher_name.
        let matcher_indices: Vec<usize> = arr
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry
                    .get("matcher")
                    .and_then(|v| v.as_str())
                    .map(|m| m == matcher_name)
                    .unwrap_or(false)
            })
            .map(|(i, _)| i)
            .collect();

        match matcher_indices.len() {
            0 => {
                arr.push(json!({
                    "matcher": matcher_name,
                    "hooks": [new_hook_entry]
                }));
            }
            1 => {
                let idx = matcher_indices[0];

                // Marker-matching hook index within the matcher's inner hooks.
                let marker_hook_idx = arr[idx]
                    .get("hooks")
                    .and_then(|v| v.as_array())
                    .and_then(|inner| inner.iter().position(&has_marker));

                match marker_hook_idx {
                    Some(hi) => {
                        let existing = &arr[idx]["hooks"][hi];
                        if *existing == new_hook_entry {
                            eprintln!(
                                "tirith: {event_name} hook in {}, up to date",
                                path.display()
                            );
                            return Ok(super::fs_helpers::FileUpdate::unchanged());
                        }
                        if !force {
                            if dry_run {
                                eprintln!(
                                "[dry-run] would error: {event_name} hook in {} has different config — use --force to update",
                                path.display()
                            );
                                return Ok(super::fs_helpers::FileUpdate::unchanged());
                            }
                            return Err(format!(
                            "{event_name} hook in {} has different config than expected — use --force to update",
                            path.display()
                        ));
                        }
                        backup = true;
                        arr[idx]["hooks"][hi] = new_hook_entry;
                    }
                    None => {
                        // Matcher exists but has no tirith hook: append to inner
                        // hooks[], replacing it if missing or non-array (e.g. null).
                        let obj = arr[idx]
                            .as_object_mut()
                            .ok_or_else(|| "matcher entry is not an object".to_string())?;
                        if !obj.get("hooks").is_some_and(|v| v.is_array()) {
                            obj.insert("hooks".to_string(), json!([]));
                        }
                        let inner_arr = obj["hooks"]
                            .as_array_mut()
                            .expect("just ensured hooks is an array");
                        inner_arr.push(new_hook_entry);
                    }
                }
            }
            _ => {
                if !force {
                    if dry_run {
                        eprintln!(
                        "[dry-run] would error: multiple {matcher_name} matcher entries in {} — use --force to deduplicate",
                        path.display()
                    );
                        return Ok(super::fs_helpers::FileUpdate::unchanged());
                    }
                    return Err(format!(
                    "multiple {matcher_name} matcher entries in {} — use --force to deduplicate",
                    path.display()
                ));
                }
                backup = true;

                // Remove marker-matching hooks from all matchers; collect the
                // non-marker hooks from duplicates into the first matcher rather
                // than silently dropping them.
                let mut orphan_hooks: Vec<Value> = Vec::new();
                for (pos, &idx) in matcher_indices.iter().enumerate() {
                    if let Some(inner) = arr[idx]["hooks"].as_array_mut() {
                        inner.retain(|h| !has_marker(h));
                        if pos > 0 {
                            orphan_hooks.append(inner);
                        }
                    }
                }

                // Replace `hooks` if missing or non-array (e.g. null).
                let first = arr[matcher_indices[0]]
                    .as_object_mut()
                    .ok_or_else(|| "matcher entry is not an object".to_string())?;
                if !first.get("hooks").is_some_and(|v| v.is_array()) {
                    first.insert("hooks".to_string(), json!([]));
                }
                let inner_arr = first["hooks"]
                    .as_array_mut()
                    .expect("just ensured hooks is an array");

                inner_arr.extend(orphan_hooks);
                inner_arr.push(new_hook_entry);

                for &idx in matcher_indices[1..].iter().rev() {
                    arr.remove(idx);
                }
            }
        }

        let content =
            serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;

        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                content.len()
            );
        }

        Ok(super::fs_helpers::FileUpdate::write_text(content, 0o644).with_backup(backup))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

/// Merge a tirith PreToolUse hook into Claude Code's settings.json.
pub fn merge_claude_settings(
    path: &Path,
    scope_root: &Path,
    hook_command: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_hook_settings_inner(
        path,
        scope_root,
        "PreToolUse",
        "Bash",
        hook_command,
        "tirith-check.py",
        force,
        dry_run,
    )
}

/// Merge a tirith BeforeTool hook into Gemini CLI's settings.json.
pub fn merge_gemini_settings(
    path: &Path,
    scope_root: &Path,
    hook_command: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    merge_hook_settings_inner(
        path,
        scope_root,
        "BeforeTool",
        "run_shell_command",
        hook_command,
        "tirith-security-guard-gemini.py",
        force,
        dry_run,
    )
}

/// Merge a tirith hook into VS Code's settings.json using a JSONC managed block.
/// Preserves all content outside the block byte-for-byte; errors (with manual
/// instructions) if a `"hooks"` key already exists outside the block.
fn vscode_managed_block(begin_marker: &str, end_marker: &str, hook_command: &str) -> String {
    format!(
        "\x20\x20{begin_marker}\n\
         \x20\x20\"hooks\": {{\n\
         \x20\x20\x20\x20\"PreToolUse\": [\n\
         \x20\x20\x20\x20\x20\x20{{\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\"type\": \"command\",\n\
         \x20\x20\x20\x20\x20\x20\x20\x20\"command\": \"{hook_command}\"\n\
         \x20\x20\x20\x20\x20\x20}}\n\
         \x20\x20\x20\x20]\n\
         \x20\x20}},\n\
         \x20\x20{end_marker}"
    )
}

pub fn merge_vscode_settings(
    path: &Path,
    scope_root: &Path,
    hook_command: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = super::fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let path_existed = snapshot.exists();
        let raw = snapshot.text(path)?.unwrap_or("{\n}\n").to_string();

        let begin_marker = "// BEGIN tirith-hooks";
        let end_marker = "// END tirith-hooks";
        let managed_block = vscode_managed_block(begin_marker, end_marker, hook_command);

        let existing_blocks = collect_managed_blocks(&raw, begin_marker, end_marker)?;
        if !force {
            match existing_blocks.as_slice() {
                [] => {}
                [existing] if existing.content == managed_block => {}
                [_] => {
                    return Err(format!(
                        "tirith: managed VS Code hooks in {} differ from the expected PreToolUse configuration — use --force to repair",
                        path.display()
                    ));
                }
                _ => {
                    return Err(format!(
                        "tirith: multiple managed VS Code hook blocks found in {} — use --force to repair",
                        path.display()
                    ));
                }
            }
        }

        let working_text = if !existing_blocks.is_empty() {
            remove_managed_block(&raw, begin_marker, end_marker)?
        } else {
            raw.clone()
        };

        // Parse the complete JSONC document outside our root-level managed
        // block. This both rejects malformed settings and detects escaped or
        // duplicate effective keys without mistaking comments/values for
        // configuration.
        let outside_root = parse_jsonc_root(&working_text)?;
        if outside_root.key_count("hooks") != 0 {
            println!(
                "Add the following to your hooks.PreToolUse array in {}:\n\
             {{\n\
             \x20\x20\"type\": \"command\",\n\
             \x20\x20\"command\": \"{hook_command}\"\n\
             }}",
                path.display()
            );
            return Err(format!(
                "tirith: {} already has a \"hooks\" key — cannot safely merge. \
             Add the hook entry shown above manually.",
                path.display()
            ));
        }

        // Only report success after the full generated block and absence of a
        // competing effective `hooks` key have both been checked. The semantic
        // check prevents an exact-looking block in a comment or nested object
        // from being accepted as an installed root hook.
        if !force && existing_blocks.len() == 1 {
            verify_vscode_managed_document(
                &raw,
                begin_marker,
                end_marker,
                &managed_block,
                hook_command,
            )?;
            eprintln!("tirith: VS Code hooks in {}, up to date", path.display());
            return Ok(super::fs_helpers::FileUpdate::unchanged());
        }

        // The parser records the actual root closing token and the root's
        // trailing-comma state, so braces and commas inside comments/strings
        // cannot redirect or corrupt insertion.
        let insert_pos = outside_root.close;
        let mut result = working_text[..insert_pos].to_string();
        if !outside_root.keys.is_empty() && !outside_root.trailing_comma {
            result.push(',');
        }
        if !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&managed_block);
        result.push('\n');
        result.push_str(&working_text[insert_pos..]);

        if !result.ends_with('\n') {
            result.push('\n');
        }

        verify_vscode_managed_document(
            &result,
            begin_marker,
            end_marker,
            &managed_block,
            hook_command,
        )?;

        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                result.len()
            );
        }

        // VS Code settings are high-value user content: every modification of
        // an existing file gets one snapshot-consistent transaction backup.
        Ok(super::fs_helpers::FileUpdate::write_text(result, 0o644).with_backup(path_existed))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

#[derive(Debug)]
struct ManagedBlock {
    start: usize,
    end: usize,
    content: String,
}

#[derive(Debug)]
struct JsoncLineComment {
    line_start: usize,
    line_end: usize,
    remove_end: usize,
    at_root_object: bool,
}

#[derive(Debug)]
struct JsoncLex {
    without_comments: Vec<u8>,
    line_comments: Vec<JsoncLineComment>,
}

#[derive(Debug)]
struct JsoncRoot {
    value: Value,
    keys: Vec<String>,
    close: usize,
    trailing_comma: bool,
}

impl JsoncRoot {
    fn key_count(&self, wanted: &str) -> usize {
        self.keys
            .iter()
            .filter(|key| key.as_str() == wanted)
            .count()
    }
}

struct RootKeys(Vec<String>);

impl<'de> Deserialize<'de> for RootKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(RootKeysVisitor)
    }
}

struct RootKeysVisitor;

impl<'de> Visitor<'de> for RootKeysVisitor {
    type Value = RootKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            keys.push(key);
            map.next_value::<IgnoredAny>()?;
        }
        Ok(RootKeys(keys))
    }
}

/// Remove all effective root-object blocks between the paired marker comments.
fn remove_managed_block(
    text: &str,
    begin_marker: &str,
    end_marker: &str,
) -> Result<String, String> {
    let blocks = collect_managed_blocks(text, begin_marker, end_marker)?;
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for block in blocks {
        out.push_str(&text[cursor..block.start]);
        cursor = block.end;
    }
    out.push_str(&text[cursor..]);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Return each exactly delimited root-object managed block after validating
/// pairing. Marker-looking text in a string, block comment, nested object, or
/// after the root is not an effective delimiter.
fn collect_managed_blocks(
    text: &str,
    begin_marker: &str,
    end_marker: &str,
) -> Result<Vec<ManagedBlock>, String> {
    let lex = lex_jsonc(text)?;
    let mut blocks = Vec::new();
    let mut current: Option<&JsoncLineComment> = None;

    for comment in lex
        .line_comments
        .iter()
        .filter(|comment| comment.at_root_object)
    {
        let line = &text[comment.line_start..comment.line_end];
        if line.trim() == begin_marker {
            if current.is_some() {
                return Err(
                    "tirith: corrupted tirith-hooks block — nested BEGIN marker, fix manually"
                        .to_string(),
                );
            }
            current = Some(comment);
            continue;
        }
        if line.trim() == end_marker {
            let Some(begin) = current.take() else {
                return Err("tirith: found END marker without BEGIN in managed block".to_string());
            };
            blocks.push(ManagedBlock {
                start: begin.line_start,
                end: comment.remove_end,
                content: text[begin.line_start..comment.line_end].replace("\r\n", "\n"),
            });
            continue;
        }
    }

    if current.is_some() {
        return Err(
            "tirith: corrupted tirith-hooks block — missing END marker, fix manually".to_string(),
        );
    }
    Ok(blocks)
}

/// Tokenize comments and structural context while preserving byte offsets.
fn lex_jsonc(text: &str) -> Result<JsoncLex, String> {
    let bytes = text.as_bytes();
    let mut without_comments = bytes.to_vec();
    if without_comments.starts_with(&[0xEF, 0xBB, 0xBF]) {
        without_comments[..3].fill(b' ');
    }
    let mut line_comments = Vec::new();
    let mut containers = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                let mut escaped = false;
                let mut closed = false;
                while let Some(current) = bytes.get(index).copied() {
                    index += 1;
                    if escaped {
                        escaped = false;
                    } else if current == b'\\' {
                        escaped = true;
                    } else if current == b'"' {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err("tirith: unterminated string in VS Code settings".into());
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let comment_start = index;
                let at_root_object = containers.as_slice() == b"{";
                index += 2;
                while bytes.get(index).is_some_and(|byte| *byte != b'\n') {
                    index += 1;
                }
                let mut line_end = index;
                if bytes.get(line_end.wrapping_sub(1)) == Some(&b'\r') {
                    line_end -= 1;
                }
                let line_start = text[..comment_start]
                    .rfind('\n')
                    .map(|position| position + 1)
                    .unwrap_or(0);
                line_comments.push(JsoncLineComment {
                    line_start,
                    line_end,
                    remove_end: if bytes.get(index) == Some(&b'\n') {
                        index + 1
                    } else {
                        index
                    },
                    at_root_object,
                });
                without_comments[comment_start..index].fill(b' ');
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let comment_start = index;
                index += 2;
                while bytes.get(index..index + 2) != Some(b"*/") {
                    if index >= bytes.len() {
                        return Err("tirith: unterminated block comment in VS Code settings".into());
                    }
                    index += 1;
                }
                index += 2;
                for byte in &mut without_comments[comment_start..index] {
                    if *byte != b'\n' && *byte != b'\r' {
                        *byte = b' ';
                    }
                }
            }
            b'{' => {
                containers.push(b'{');
                index += 1;
            }
            b'}' => {
                if containers.pop() != Some(b'{') {
                    return Err("tirith: unmatched closing brace in VS Code settings".into());
                }
                index += 1;
            }
            b'[' => {
                containers.push(b'[');
                index += 1;
            }
            b']' => {
                if containers.pop() != Some(b'[') {
                    return Err("tirith: unmatched closing bracket in VS Code settings".into());
                }
                index += 1;
            }
            _ => index += 1,
        }
    }
    if !containers.is_empty() {
        return Err("tirith: unbalanced JSONC structure in VS Code settings".into());
    }
    Ok(JsoncLex {
        without_comments,
        line_comments,
    })
}

fn parse_jsonc_root(text: &str) -> Result<JsoncRoot, String> {
    let mut lex = lex_jsonc(text)?;
    let close = lex
        .without_comments
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| "tirith: VS Code settings are empty".to_string())?;
    if lex.without_comments[close] != b'}' {
        return Err("tirith: VS Code settings root must be a JSON object".into());
    }
    let trailing_comma = lex.without_comments[..close]
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|position| lex.without_comments[position] == b',');

    // JSONC permits a comma immediately before an object/array close. Replace
    // only those commas with whitespace so serde_json can validate the full
    // effective document while all original byte offsets remain stable.
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < lex.without_comments.len() {
        let byte = lex.without_comments[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b',' {
            let mut after = index + 1;
            while lex
                .without_comments
                .get(after)
                .is_some_and(u8::is_ascii_whitespace)
            {
                after += 1;
            }
            if lex
                .without_comments
                .get(after)
                .is_some_and(|byte| matches!(*byte, b'}' | b']'))
            {
                lex.without_comments[index] = b' ';
            }
        }
        index += 1;
    }

    let strict = String::from_utf8(lex.without_comments)
        .map_err(|_| "tirith: VS Code settings are not valid UTF-8".to_string())?;
    let value: Value = serde_json::from_str(&strict)
        .map_err(|error| format!("tirith: invalid VS Code settings JSONC: {error}"))?;
    if !value.is_object() {
        return Err("tirith: VS Code settings root must be a JSON object".into());
    }
    let RootKeys(keys): RootKeys = serde_json::from_str(&strict)
        .map_err(|error| format!("tirith: invalid VS Code settings JSONC: {error}"))?;
    Ok(JsoncRoot {
        value,
        keys,
        close,
        trailing_comma,
    })
}

#[cfg(test)]
pub(super) fn parse_jsonc_test_value(text: &str) -> Result<Value, String> {
    Ok(parse_jsonc_root(text)?.value)
}

fn verify_vscode_managed_document(
    text: &str,
    begin_marker: &str,
    end_marker: &str,
    expected_block: &str,
    hook_command: &str,
) -> Result<(), String> {
    let blocks = collect_managed_blocks(text, begin_marker, end_marker)?;
    if blocks.len() != 1 || blocks[0].content != expected_block {
        return Err(
            "tirith: generated VS Code settings do not contain exactly one effective managed hook block"
                .into(),
        );
    }
    let root = parse_jsonc_root(text)?;
    let expected_hooks = json!({
        "PreToolUse": [{
            "type": "command",
            "command": hook_command
        }]
    });
    if root.key_count("hooks") != 1 || root.value.get("hooks") != Some(&expected_hooks) {
        return Err(
            "tirith: VS Code settings do not expose the exact expected effective PreToolUse hook"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn merge_mcp_json(
        path: &Path,
        server_name: &str,
        server_config: Value,
        force: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        super::merge_mcp_json(
            path,
            path.parent().expect("test path has parent"),
            server_name,
            server_config,
            force,
            dry_run,
        )
    }

    fn merge_mcp_json_with_key(
        path: &Path,
        server_name: &str,
        server_config: Value,
        server_key: &str,
        force: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        super::merge_mcp_json_with_key(
            path,
            path.parent().expect("test path has parent"),
            server_name,
            server_config,
            server_key,
            force,
            dry_run,
        )
    }

    fn merge_mcp_jsonc_with_key(
        path: &Path,
        server_name: &str,
        server_config: Value,
        server_key: &str,
        force: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        super::merge_mcp_jsonc_with_key(
            path,
            path.parent().expect("test path has parent"),
            server_name,
            server_config,
            server_key,
            0o644,
            false,
            force,
            dry_run,
        )
    }

    fn merge_hooks_json(
        path: &Path,
        event_name: &str,
        hook_entry: Value,
        marker: &str,
        force: bool,
        dry_run: bool,
        require_version: bool,
    ) -> Result<(), String> {
        super::merge_hooks_json(
            path,
            path.parent().expect("test path has parent"),
            event_name,
            hook_entry,
            marker,
            force,
            dry_run,
            require_version,
        )
    }

    fn merge_claude_settings(
        path: &Path,
        hook_command: &str,
        force: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        super::merge_claude_settings(
            path,
            path.parent().expect("test path has parent"),
            hook_command,
            force,
            dry_run,
        )
    }

    fn merge_gemini_settings(
        path: &Path,
        hook_command: &str,
        force: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        super::merge_gemini_settings(
            path,
            path.parent().expect("test path has parent"),
            hook_command,
            force,
            dry_run,
        )
    }

    fn merge_vscode_settings(
        path: &Path,
        hook_command: &str,
        force: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        super::merge_vscode_settings(
            path,
            path.parent().expect("test path has parent"),
            hook_command,
            force,
            dry_run,
        )
    }

    #[cfg(unix)]
    #[test]
    fn merge_up_to_date_and_dry_run_refuse_symlinked_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked = root.path().join("nested");
        std::os::unix::fs::symlink(outside.path(), &linked).unwrap();
        let path = linked.join("mcp.json");
        let expected = json!({"command": "tirith", "args": ["mcp"]});
        fs::write(
            outside.path().join("mcp.json"),
            serde_json::to_string(&json!({"mcpServers": {"tirith": expected}})).unwrap(),
        )
        .unwrap();

        for dry_run in [false, true] {
            let result = super::merge_mcp_json(
                &path,
                root.path(),
                "tirith",
                expected.clone(),
                false,
                dry_run,
            );
            assert!(
                result.is_err(),
                "dry_run={dry_run} bypassed parent validation"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn merge_force_never_backs_up_or_cleans_through_symlinked_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked = root.path().join("nested");
        std::os::unix::fs::symlink(outside.path(), &linked).unwrap();
        let path = linked.join("mcp.json");
        fs::write(
            outside.path().join("mcp.json"),
            r#"{"mcpServers":{"tirith":{"command":"old"}}}"#,
        )
        .unwrap();
        for i in 0..7 {
            fs::write(
                outside
                    .path()
                    .join(format!("mcp.json.tirith-backup-20260101-00000{i}")),
                "outside-backup",
            )
            .unwrap();
        }

        let result = super::merge_mcp_json(
            &path,
            root.path(),
            "tirith",
            json!({"command": "new"}),
            true,
            false,
        );

        assert!(result.is_err());
        let backups = fs::read_dir(outside.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(backups, 7);
    }

    #[test]
    fn mcp_json_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json(&path, "tirith", json!({"command": "tirith"}), false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcpServers"]["tirith"]["command"], "tirith");
    }

    #[test]
    fn mcp_json_preserves_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        fs::write(&path, r#"{"mcpServers":{"other":{"command":"other"}}}"#).unwrap();

        merge_mcp_json(&path, "tirith", json!({"command": "tirith"}), false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcpServers"]["other"]["command"], "other");
        assert_eq!(content["mcpServers"]["tirith"]["command"], "tirith");
    }

    #[test]
    fn mcp_json_skip_if_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        let config = json!({"command": "tirith"});
        merge_mcp_json(&path, "tirith", config.clone(), false, false).unwrap();

        merge_mcp_json(&path, "tirith", config, false, false).unwrap();
    }

    #[test]
    fn mcp_json_drift_error_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json(&path, "tirith", json!({"command": "old"}), false, false).unwrap();

        let result = merge_mcp_json(&path, "tirith", json!({"command": "new"}), false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("different config"));
    }

    #[test]
    fn mcp_json_drift_warning_in_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json(&path, "tirith", json!({"command": "old"}), false, false).unwrap();

        // dry_run + drift must not error.
        let result = merge_mcp_json(&path, "tirith", json!({"command": "new"}), false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn mcp_json_force_replaces_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json(&path, "tirith", json!({"command": "old"}), false, false).unwrap();

        merge_mcp_json(&path, "tirith", json!({"command": "new"}), true, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcpServers"]["tirith"]["command"], "new");
    }

    #[test]
    fn mcp_json_dry_run_no_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        merge_mcp_json(&path, "tirith", json!({"command": "tirith"}), false, true).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn mcp_json_dry_run_force_no_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json(&path, "tirith", json!({"command": "old"}), false, false).unwrap();

        // dry-run + force must not create backup files.
        merge_mcp_json(&path, "tirith", json!({"command": "new"}), true, true).unwrap();

        let backup_count = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(backup_count, 0);
    }

    #[test]
    fn mcp_json_vscode_servers_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json_with_key(
            &path,
            "tirith-gateway",
            json!({"type": "stdio", "command": "tirith", "args": ["mcp-server"]}),
            "servers",
            false,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["servers"]["tirith-gateway"]["type"], "stdio");
        assert_eq!(content["servers"]["tirith-gateway"]["command"], "tirith");
        // Must NOT have "mcpServers" key
        assert!(content.get("mcpServers").is_none());
    }

    #[test]
    fn mcp_json_vscode_preserves_existing_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        fs::write(
            &path,
            r#"{"servers":{"other":{"type":"stdio","command":"other"}}}"#,
        )
        .unwrap();

        merge_mcp_json_with_key(
            &path,
            "tirith-gateway",
            json!({"type": "stdio", "command": "tirith"}),
            "servers",
            false,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["servers"]["other"]["command"], "other");
        assert_eq!(content["servers"]["tirith-gateway"]["command"], "tirith");
    }

    #[test]
    fn mcp_jsonc_preserves_comments_and_unrelated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.jsonc");
        let original = r#"{
  // keep this comment byte-for-byte
  "model": "provider/model",
  "mcp": {
    "other": { "type": "remote", "url": "https://example.test/mcp" },
  },
}
"#;
        fs::write(&path, original).unwrap();

        merge_mcp_jsonc_with_key(
            &path,
            "tirith",
            json!({"type": "local", "command": ["/opt/tirith", "mcp-server"]}),
            "mcp",
            false,
            false,
        )
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("// keep this comment byte-for-byte"));
        assert!(content.contains(r#""model": "provider/model""#));
        let parsed = parse_jsonc_root(&content).unwrap();
        assert_eq!(parsed.value["mcp"]["other"]["type"], "remote");
        assert_eq!(
            parsed.value["mcp"]["tirith"]["command"],
            json!(["/opt/tirith", "mcp-server"])
        );
    }

    #[test]
    fn mcp_jsonc_force_replaces_only_managed_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.jsonc");
        fs::write(
            &path,
            r#"{
  "mcp": {
    // an unrelated server remains untouched
    "other": { "command": ["other"] },
    "tirith": { "command": ["/old/tirith", "mcp-server"] }
  }
}
"#,
        )
        .unwrap();
        let desired = json!({"command": ["/new/tirith", "mcp-server"]});

        let drift = merge_mcp_jsonc_with_key(&path, "tirith", desired.clone(), "mcp", false, false);
        assert!(drift.is_err());

        merge_mcp_jsonc_with_key(&path, "tirith", desired, "mcp", true, false).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("// an unrelated server remains untouched"));
        assert!(content.contains(r#""other": { "command": ["other"] }"#));
        let parsed = parse_jsonc_root(&content).unwrap();
        assert_eq!(
            parsed.value["mcp"]["tirith"]["command"],
            json!(["/new/tirith", "mcp-server"])
        );
    }

    #[test]
    fn mcp_jsonc_rejects_duplicate_effective_server_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.jsonc");
        fs::write(&path, r#"{"mcp": {}, "m\u0063p": {}}"#).unwrap();

        let error = merge_mcp_jsonc_with_key(
            &path,
            "tirith",
            json!({"command": ["/opt/tirith", "mcp-server"]}),
            "mcp",
            false,
            false,
        )
        .unwrap_err();
        assert!(error.contains("duplicate"));
    }

    #[test]
    fn mcp_jsonc_rejects_duplicate_escaped_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.jsonc");
        fs::write(&path, r#"{"mcp": {"tirith": {}, "t\u0069rith": {}}}"#).unwrap();

        let error = merge_mcp_jsonc_with_key(
            &path,
            "tirith",
            json!({"command": ["/opt/tirith", "mcp-server"]}),
            "mcp",
            false,
            false,
        )
        .unwrap_err();
        assert!(error.contains("duplicate"), "{error}");
    }

    #[test]
    fn mcp_jsonc_dry_run_does_not_create_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("mcp.jsonc");

        super::merge_mcp_jsonc_with_key(
            &path,
            dir.path(),
            "tirith",
            json!({"command": ["/opt/tirith", "mcp-server"]}),
            "mcp",
            0o644,
            false,
            false,
            true,
        )
        .unwrap();

        assert!(!path.exists());
        assert!(!path.parent().unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn mcp_jsonc_repairs_private_mode_when_content_is_current() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        let desired = json!({"command": "/opt/tirith", "args": ["mcp-server"]});
        super::merge_mcp_jsonc_with_key(
            &path,
            dir.path(),
            "tirith",
            desired.clone(),
            "mcpServers",
            0o600,
            true,
            false,
            false,
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        super::merge_mcp_jsonc_with_key(
            &path,
            dir.path(),
            "tirith",
            desired,
            "mcpServers",
            0o600,
            true,
            false,
            false,
        )
        .unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn hooks_json_creates_new_file_with_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        let entry = json!({"command": "hooks/tirith-hook.sh", "type": "command"});

        merge_hooks_json(
            &path,
            "beforeShellExecution",
            entry,
            "tirith-hook",
            false,
            false,
            true,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["version"], 1);
        assert!(content["hooks"]["beforeShellExecution"].is_array());
    }

    #[test]
    fn hooks_json_skip_if_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        let entry = json!({"command": "hooks/tirith-hook.sh"});

        merge_hooks_json(
            &path,
            "pre_run_command",
            entry.clone(),
            "tirith-hook",
            false,
            false,
            false,
        )
        .unwrap();
        // Idempotent
        merge_hooks_json(
            &path,
            "pre_run_command",
            entry,
            "tirith-hook",
            false,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn hooks_json_drift_error_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        merge_hooks_json(
            &path,
            "beforeShellExecution",
            json!({"command": "hooks/tirith-hook.sh", "timeout": 10}),
            "tirith-hook",
            false,
            false,
            true,
        )
        .unwrap();

        let result = merge_hooks_json(
            &path,
            "beforeShellExecution",
            json!({"command": "hooks/tirith-hook.sh", "timeout": 15}),
            "tirith-hook",
            false,
            false,
            true,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("different config"));
    }

    #[test]
    fn hooks_json_preserves_other_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(
            &path,
            r#"{"hooks":{"beforeShellExecution":[{"command":"other.sh"}]}}"#,
        )
        .unwrap();

        merge_hooks_json(
            &path,
            "beforeShellExecution",
            json!({"command": "hooks/tirith-hook.sh"}),
            "tirith-hook",
            false,
            false,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn claude_settings_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        merge_claude_settings(&path, "python3 hook.py", false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Bash");
    }

    #[test]
    fn claude_settings_preserves_other_matchers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[]}]}}"#,
        )
        .unwrap();

        merge_claude_settings(&path, "python3 tirith.py", false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn vscode_settings_creates_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("// BEGIN tirith-hooks"));
        assert!(content.contains("// END tirith-hooks"));
        assert!(content.contains("tirith-hook.sh"));
    }

    #[test]
    fn vscode_settings_skip_if_block_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

        // Second call should skip
        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();
    }

    #[test]
    fn vscode_settings_does_not_trust_marker_substring() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            "{\n  // attacker mentions // BEGIN tirith-hooks but installs nothing\n}\n",
        )
        .unwrap();

        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content
                .lines()
                .filter(|line| line.trim() == "// BEGIN tirith-hooks")
                .count(),
            1
        );
        assert!(content.contains("\"PreToolUse\""));
        assert!(content.contains("\"command\": \"hooks/tirith-hook.sh\""));
    }

    #[test]
    fn vscode_settings_does_not_trust_exact_block_in_ineffective_context() {
        let managed = vscode_managed_block(
            "// BEGIN tirith-hooks",
            "// END tirith-hooks",
            "hooks/tirith-hook.sh",
        );
        for poisoned in [
            format!("{{\n  /*\n{managed}\n  */\n}}\n"),
            format!("{{\n  \"decoy\": {{\n{managed}\n  }}\n}}\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("settings.json");
            fs::write(&path, poisoned).unwrap();

            merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

            let content = fs::read_to_string(&path).unwrap();
            let root = parse_jsonc_root(&content).unwrap();
            assert_eq!(root.key_count("hooks"), 1);
            assert_eq!(
                root.value["hooks"]["PreToolUse"][0]["command"],
                "hooks/tirith-hook.sh"
            );
            assert_eq!(
                collect_managed_blocks(&content, "// BEGIN tirith-hooks", "// END tirith-hooks")
                    .unwrap()
                    .len(),
                1,
                "only the effective root block counts as managed"
            );
        }
    }

    #[test]
    fn vscode_settings_rejects_unpaired_or_drifted_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "{\n  // BEGIN tirith-hooks\n}\n").unwrap();
        assert!(
            merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false)
                .unwrap_err()
                .contains("missing END marker")
        );

        fs::write(
            &path,
            "{\n  // BEGIN tirith-hooks\n  \"hooks\": {},\n  // END tirith-hooks\n}\n",
        )
        .unwrap();
        assert!(
            merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false)
                .unwrap_err()
                .contains("differ from the expected")
        );
    }

    #[test]
    fn vscode_settings_rejects_competing_hooks_key_beside_exact_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let poisoned = content.replacen("{\n", "{\n  \"hooks\": {},\n", 1);
        fs::write(&path, poisoned).unwrap();

        assert!(
            merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false)
                .unwrap_err()
                .contains("already has a \"hooks\" key")
        );
    }

    #[test]
    fn vscode_settings_detects_inline_and_escaped_effective_hooks_keys() {
        for original in [
            "{ \"hooks\": {} }\n",
            "{ \"ho\\u006fks\": {} }\n",
            "{/* comment */ \"hooks\" /* gap */ : {}}\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("settings.json");
            fs::write(&path, original).unwrap();
            assert!(
                merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false)
                    .unwrap_err()
                    .contains("already has a \"hooks\" key"),
                "effective hooks key was missed in {original:?}"
            );
        }
    }

    #[test]
    fn vscode_settings_ignores_hooks_text_inside_comments_and_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            "{\n  // \"hooks\": {}\n  \"note\": \"\\\"hooks\\\": is documentation\"\n}\n",
        )
        .unwrap();
        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();
        assert!(fs::read_to_string(path).unwrap().contains("\"PreToolUse\""));
    }

    #[test]
    fn vscode_settings_hard_error_on_existing_hooks_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "{\n  \"hooks\": {\n    \"PreToolUse\": []\n  }\n}\n").unwrap();

        let result = merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already has a \"hooks\" key"));
    }

    #[test]
    fn vscode_settings_preserves_content_outside_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n  \"editor.fontSize\": 14\n}\n";
        fs::write(&path, original).unwrap();

        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"editor.fontSize\": 14"));
        assert!(content.contains("// BEGIN tirith-hooks"));
    }

    #[test]
    fn vscode_settings_preserves_jsonc_features() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // JSONC content: comments, trailing comma, URL string with "https://"
        let original = "\
{\n\
  // Editor configuration\n\
  \"editor.fontSize\": 14,\n\
  \"editor.tabSize\": 2,\n\
  // API endpoint (do not change)\n\
  \"myExtension.url\": \"https://x.com/api/v1\",\n\
}\n";
        fs::write(&path, original).unwrap();

        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        // All original content preserved
        assert!(
            content.contains("// Editor configuration"),
            "comment preserved"
        );
        assert!(
            content.contains("\"editor.fontSize\": 14"),
            "fontSize preserved"
        );
        assert!(
            content.contains("\"editor.tabSize\": 2"),
            "tabSize preserved"
        );
        assert!(
            content.contains("// API endpoint (do not change)"),
            "second comment preserved"
        );
        assert!(
            content.contains("\"myExtension.url\": \"https://x.com/api/v1\""),
            "URL value preserved"
        );
        // Managed block inserted
        assert!(content.contains("// BEGIN tirith-hooks"));
        assert!(content.contains("// END tirith-hooks"));
        assert!(content.contains("tirith-hook.sh"));
    }

    #[test]
    fn vscode_settings_inserts_after_trailing_block_comment_without_double_comma() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n  \"editor.fontSize\": 14,\n  /* keep this trailing comment */\n}\n";
        fs::write(&path, original).unwrap();

        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let root = parse_jsonc_root(&content).unwrap();
        assert_eq!(root.value["editor.fontSize"], 14);
        assert_eq!(
            root.value["hooks"]["PreToolUse"][0]["command"],
            "hooks/tirith-hook.sh"
        );
        assert!(content.contains("/* keep this trailing comment */"));
    }

    #[test]
    fn vscode_settings_uses_root_close_not_brace_in_trailing_comment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n  \"editor.fontSize\": 14\n}\n// trailing documentation: }\n";
        fs::write(&path, original).unwrap();

        merge_vscode_settings(&path, "hooks/tirith-hook.sh", false, false).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let root = parse_jsonc_root(&content).unwrap();
        assert_eq!(root.value["editor.fontSize"], 14);
        assert_eq!(
            root.value["hooks"]["PreToolUse"][0]["command"],
            "hooks/tirith-hook.sh"
        );
        assert!(content.ends_with("}\n// trailing documentation: }\n"));
    }

    #[test]
    fn vscode_settings_force_preserves_jsonc_outside_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        // First setup
        merge_vscode_settings(&path, "hooks/old-hook.sh", false, false).unwrap();

        // Manually add JSONC content outside the managed block
        let content = fs::read_to_string(&path).unwrap();
        let augmented = content.replace(
            "{\n",
            "{\n  // My custom comment\n  \"custom.setting\": true,\n",
        );
        fs::write(&path, &augmented).unwrap();

        // Force update should preserve content outside managed block
        merge_vscode_settings(&path, "hooks/new-hook.sh", true, false).unwrap();

        let result = fs::read_to_string(&path).unwrap();
        assert!(
            result.contains("// My custom comment"),
            "custom comment preserved after force"
        );
        assert!(
            result.contains("\"custom.setting\": true"),
            "custom setting preserved after force"
        );
        assert!(result.contains("new-hook.sh"), "new hook command present");
        assert!(!result.contains("old-hook.sh"), "old hook command removed");
    }

    #[test]
    fn remove_managed_block_removes_block() {
        let text = "{\n  // BEGIN x\n  \"managed\": true,\n  // END x\n}\n";
        let result = remove_managed_block(text, "// BEGIN x", "// END x").unwrap();
        assert_eq!(result, "{\n}\n");
    }

    #[test]
    fn remove_managed_block_errors_on_missing_end() {
        let text = "{\n  // BEGIN x\n}\n";
        let result = remove_managed_block(text, "// BEGIN x", "// END x");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing END"));
    }

    #[test]
    fn remove_managed_block_errors_on_orphan_end() {
        let text = "{\n  // END x\n}\n";
        let result = remove_managed_block(text, "// BEGIN x", "// END x");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("END marker without BEGIN"));
    }

    #[test]
    fn gemini_settings_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        merge_gemini_settings(
            &path,
            "python3 tirith-security-guard-gemini.py",
            false,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "run_shell_command");
        let inner = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(
            inner[0]["command"],
            "python3 tirith-security-guard-gemini.py"
        );
    }

    #[test]
    fn gemini_settings_preserves_other_matchers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"other_tool","hooks":[]}]}}"#,
        )
        .unwrap();

        merge_gemini_settings(
            &path,
            "python3 tirith-security-guard-gemini.py",
            false,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn gemini_settings_preserves_other_hooks_in_same_matcher() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Existing run_shell_command matcher with a non-tirith hook
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"other-hook.py"}]}]}}"#,
        )
        .unwrap();

        merge_gemini_settings(
            &path,
            "python3 tirith-security-guard-gemini.py",
            false,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "should still be one matcher entry");
        let inner = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 2, "should have both hooks");
        assert_eq!(inner[0]["command"], "other-hook.py");
        assert_eq!(
            inner[1]["command"],
            "python3 tirith-security-guard-gemini.py"
        );
    }

    #[test]
    fn gemini_settings_skip_if_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        let cmd = "python3 tirith-security-guard-gemini.py";
        merge_gemini_settings(&path, cmd, false, false).unwrap();
        // Second call should be idempotent
        merge_gemini_settings(&path, cmd, false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let inner = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 1, "no duplicate hooks");
    }

    #[test]
    fn gemini_settings_drift_error_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        merge_gemini_settings(
            &path,
            "python3 tirith-security-guard-gemini.py",
            false,
            false,
        )
        .unwrap();

        let result = merge_gemini_settings(
            &path,
            "python3 /new/tirith-security-guard-gemini.py",
            false,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("different config"));
    }

    #[test]
    fn gemini_settings_force_replaces_only_tirith_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Matcher with tirith hook + another hook
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"other-hook.py"},{"type":"command","command":"python3 tirith-security-guard-gemini.py"}]}]}}"#,
        )
        .unwrap();

        merge_gemini_settings(
            &path,
            "python3 /new/path/tirith-security-guard-gemini.py",
            true,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let inner = content["hooks"]["BeforeTool"][0]["hooks"]
            .as_array()
            .unwrap();
        assert_eq!(inner.len(), 2, "both hooks present");
        assert_eq!(inner[0]["command"], "other-hook.py", "other hook preserved");
        assert_eq!(
            inner[1]["command"], "python3 /new/path/tirith-security-guard-gemini.py",
            "tirith hook updated"
        );
    }

    #[test]
    fn gemini_settings_multiple_matchers_error_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Two run_shell_command matcher entries
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"a.py"}]},{"matcher":"run_shell_command","hooks":[{"type":"command","command":"b.py"}]}]}}"#,
        )
        .unwrap();

        let result = merge_gemini_settings(
            &path,
            "python3 tirith-security-guard-gemini.py",
            false,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("multiple"));
    }

    #[test]
    fn gemini_settings_multiple_matchers_force_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Two run_shell_command matchers, both with a tirith hook
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"python3 tirith-security-guard-gemini.py"}]},{"matcher":"run_shell_command","hooks":[{"type":"command","command":"python3 /old/tirith-security-guard-gemini.py"}]}]}}"#,
        )
        .unwrap();

        merge_gemini_settings(
            &path,
            "python3 /new/tirith-security-guard-gemini.py",
            true,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        // All duplicates removed, consolidated into one
        assert_eq!(arr.len(), 1, "deduplicated to one matcher");
        let inner = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(
            inner[0]["command"],
            "python3 /new/tirith-security-guard-gemini.py"
        );
    }

    #[test]
    fn gemini_settings_force_consolidates_mixed_hooks_from_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Two run_shell_command matchers: first has tirith + other hook, second has another hook
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"python3 tirith-security-guard-gemini.py"},{"type":"command","command":"other-a.py"}]},{"matcher":"run_shell_command","hooks":[{"type":"command","command":"other-b.py"}]}]}}"#,
        )
        .unwrap();

        merge_gemini_settings(
            &path,
            "python3 /new/tirith-security-guard-gemini.py",
            true,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "consolidated to one matcher");
        let inner = arr[0]["hooks"].as_array().unwrap();
        // other-a from first, other-b from second (consolidated), then new tirith hook
        assert_eq!(inner.len(), 3, "all hooks consolidated");
        assert_eq!(inner[0]["command"], "other-a.py");
        assert_eq!(inner[1]["command"], "other-b.py");
        assert_eq!(
            inner[2]["command"],
            "python3 /new/tirith-security-guard-gemini.py"
        );

        // Running again without --force should succeed (convergent)
        merge_gemini_settings(
            &path,
            "python3 /new/tirith-security-guard-gemini.py",
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn gemini_settings_force_handles_malformed_matcher_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Two matchers: first has hooks=null (malformed), second has a tirith hook
        fs::write(
            &path,
            r#"{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":null},{"matcher":"run_shell_command","hooks":[{"type":"command","command":"python3 tirith-security-guard-gemini.py"}]}]}}"#,
        )
        .unwrap();

        merge_gemini_settings(
            &path,
            "python3 /new/tirith-security-guard-gemini.py",
            true,
            false,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "consolidated to one matcher");
        let inner = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(
            inner[0]["command"], "python3 /new/tirith-security-guard-gemini.py",
            "tirith hook must be present after force"
        );
    }

    #[test]
    fn gemini_settings_dry_run_no_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        merge_gemini_settings(
            &path,
            "python3 tirith-security-guard-gemini.py",
            false,
            true,
        )
        .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn claude_inner_preserves_other_hooks_in_bash_matcher() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Bash matcher with a non-tirith hook
        fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other-hook.py"}]}]}}"#,
        )
        .unwrap();

        merge_claude_settings(&path, "python3 tirith-check.py", false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let arr = content["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "single Bash matcher");
        let inner = arr[0]["hooks"].as_array().unwrap();
        assert_eq!(inner.len(), 2, "both hooks preserved");
        assert_eq!(inner[0]["command"], "other-hook.py");
        assert_eq!(inner[1]["command"], "python3 tirith-check.py");
    }

    #[test]
    fn claude_inner_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        let cmd = "python3 tirith-check.py";
        merge_claude_settings(&path, cmd, false, false).unwrap();
        merge_claude_settings(&path, cmd, false, false).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let inner = content["hooks"]["PreToolUse"][0]["hooks"]
            .as_array()
            .unwrap();
        assert_eq!(inner.len(), 1, "no duplicate");
    }
}
