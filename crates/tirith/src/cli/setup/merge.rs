use std::fs;
use std::path::Path;

use serde_json::{json, Value};

/// Merge a server entry into an MCP JSON config file.
///
/// Creates `mcpServers` object if missing. Drift detection: if the server
/// exists with different config and `!force`, returns an error. Same config
/// is silently skipped.
pub fn merge_mcp_json(
    path: &Path,
    server_name: &str,
    server_config: Value,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let mut config: Value = if path.exists() {
        let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?
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

    if let Some(existing) = servers_obj.get(server_name) {
        if !force {
            if existing == &server_config {
                eprintln!(
                    "tirith: {server_name} already in {}, up to date",
                    path.display()
                );
                return Ok(());
            }
            if dry_run {
                eprintln!(
                    "[dry-run] would error: {server_name} in {} has different config — use --force to update",
                    path.display()
                );
                return Ok(());
            }
            return Err(format!(
                "tirith: {server_name} in {} has different config than expected — use --force to update",
                path.display()
            ));
        }
        // force: create backup before overwriting user config (not in dry-run)
        if !dry_run {
            super::fs_helpers::create_backup(path, true)?;
        }
    }

    servers_obj.insert(server_name.to_string(), server_config);

    let content = serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    super::fs_helpers::atomic_write(path, &content, 0o644)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

/// Merge a hook entry into a hooks.json file (Cursor/Windsurf format).
///
/// Shared by Cursor (`beforeShellExecution`) and Windsurf (`pre_run_command`).
/// Detects existing tirith hooks by scanning for `marker` substring in each
/// entry's `command` field.
pub fn merge_hooks_json(
    path: &Path,
    event_name: &str,
    hook_entry: Value,
    marker: &str,
    force: bool,
    dry_run: bool,
    require_version: bool,
) -> Result<(), String> {
    let mut config: Value = if path.exists() {
        let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?
    } else if require_version {
        json!({"version": 1, "hooks": {}})
    } else {
        json!({"hooks": {}})
    };

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

    // Find all entries whose "command" field contains the marker
    let matching_indices: Vec<usize> = event_arr
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry
                .get("command")
                .and_then(|v| v.as_str())
                .map(|cmd| cmd.contains(marker))
                .unwrap_or(false)
        })
        .map(|(i, _)| i)
        .collect();

    match matching_indices.len() {
        0 => {
            // No existing entry — append
            event_arr.push(hook_entry);
        }
        1 => {
            let idx = matching_indices[0];
            if !force {
                if event_arr[idx] == hook_entry {
                    eprintln!("tirith: hook in {}, up to date", path.display());
                    return Ok(());
                }
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: hook entry in {} has different config — use --force to update",
                        path.display()
                    );
                    return Ok(());
                }
                return Err(format!(
                    "tirith: hook entry in {} has different config than expected — use --force to update",
                    path.display()
                ));
            }
            // force: replace (backup only when not dry-run)
            if !dry_run {
                super::fs_helpers::create_backup(path, true)?;
            }
            event_arr[idx] = hook_entry;
        }
        _ => {
            if !force {
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: multiple tirith hook entries found in {} — use --force to deduplicate",
                        path.display()
                    );
                    return Ok(());
                }
                return Err(format!(
                    "tirith: multiple tirith hook entries found in {} — use --force to deduplicate",
                    path.display()
                ));
            }
            // force: remove all matching, insert one (backup only when not dry-run)
            if !dry_run {
                super::fs_helpers::create_backup(path, true)?;
            }
            // Remove in reverse order to preserve indices
            for &idx in matching_indices.iter().rev() {
                event_arr.remove(idx);
            }
            event_arr.push(hook_entry);
        }
    }

    let content = serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    super::fs_helpers::atomic_write(path, &content, 0o644)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

/// Merge a tirith PreToolUse hook into Claude Code's settings.json.
///
/// Navigates to `hooks.PreToolUse` array, looks for an existing entry with
/// `matcher == "Bash"` that contains "tirith" in its command. Preserves all
/// other keys and entries.
pub fn merge_claude_settings(
    path: &Path,
    hook_command: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let mut config: Value = if path.exists() {
        let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?
    } else {
        json!({})
    };

    let root = config
        .as_object_mut()
        .ok_or_else(|| format!("{} is not a JSON object", path.display()))?;

    // Ensure hooks object exists
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| format!("hooks in {} is not an object", path.display()))?;

    // Ensure PreToolUse array exists
    let pre_tool_use = hooks_obj.entry("PreToolUse").or_insert_with(|| json!([]));
    let arr = pre_tool_use
        .as_array_mut()
        .ok_or_else(|| format!("hooks.PreToolUse in {} is not an array", path.display()))?;

    let new_entry = json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": hook_command
            }
        ]
    });

    // Find existing Bash matcher with tirith in command
    let existing_idx = arr.iter().position(|entry| {
        let is_bash = entry
            .get("matcher")
            .and_then(|v| v.as_str())
            .map(|m| m == "Bash")
            .unwrap_or(false);
        if !is_bash {
            return false;
        }
        entry
            .get("hooks")
            .and_then(|v| v.as_array())
            .map(|hooks| {
                hooks.iter().any(|h| {
                    h.get("command")
                        .and_then(|v| v.as_str())
                        .map(|cmd| cmd.contains("tirith"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });

    match existing_idx {
        Some(idx) => {
            if !force {
                if arr[idx] == new_entry {
                    eprintln!("tirith: PreToolUse hook in {}, up to date", path.display());
                    return Ok(());
                }
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: PreToolUse hook in {} has different config — use --force to update",
                        path.display()
                    );
                    return Ok(());
                }
                return Err(format!(
                    "PreToolUse hook in {} has different config than expected — use --force to update",
                    path.display()
                ));
            }
            // force: replace (backup only when not dry-run)
            if !dry_run {
                super::fs_helpers::create_backup(path, true)?;
            }
            arr[idx] = new_entry;
        }
        None => {
            arr.push(new_entry);
        }
    }

    let content = serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }

    super::fs_helpers::atomic_write(path, &content, 0o644)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

/// Merge a tirith hook into VS Code's settings.json using JSONC comment markers.
///
/// Uses `// BEGIN tirith-hooks` / `// END tirith-hooks` managed block markers.
/// Preserves all content outside the managed block byte-for-byte. If an existing
/// `"hooks"` key is found outside the managed block, returns a hard error with
/// manual merge instructions.
pub fn merge_vscode_settings(
    path: &Path,
    hook_command: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let raw = if path.exists() {
        fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?
    } else {
        "{\n}\n".to_string()
    };

    let begin_marker = "// BEGIN tirith-hooks";
    let end_marker = "// END tirith-hooks";

    let has_begin = raw.contains(begin_marker);

    if has_begin && !force {
        eprintln!("tirith: VS Code hooks in {}, up to date", path.display());
        return Ok(());
    }

    // If force and block exists, remove the old block first
    let already_backed_up;
    let working_text = if has_begin && force {
        if !dry_run {
            super::fs_helpers::create_backup(path, true)?;
            already_backed_up = true;
        } else {
            already_backed_up = false;
        }
        remove_managed_block(&raw, begin_marker, end_marker)?
    } else {
        already_backed_up = false;
        raw.clone()
    };

    // Build the managed block
    let managed_block = format!(
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
    );

    // Check for existing "hooks" key outside managed block (line-by-line scan)
    let hooks_key_re =
        regex::Regex::new(r#"^\s*"hooks"\s*:"#).map_err(|e| format!("regex compile: {e}"))?;

    let mut in_managed_block = false;
    for line in working_text.lines() {
        if line.contains(begin_marker) {
            in_managed_block = true;
            continue;
        }
        if line.contains(end_marker) {
            in_managed_block = false;
            continue;
        }
        if !in_managed_block && hooks_key_re.is_match(line) {
            // Print manual instructions to stdout
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
    }

    // Insert managed block before the last `}` in the file
    let insert_pos = working_text.rfind('}').ok_or_else(|| {
        // Print manual instructions to stdout
        println!(
            "Add the following to {}:\n{}",
            path.display(),
            managed_block
        );
        format!(
            "tirith: could not locate insertion point in {} — add hook manually",
            path.display()
        )
    })?;

    // Find the preceding non-empty, non-comment line and add trailing comma if needed
    let before_brace = &working_text[..insert_pos];
    let mut result = String::new();

    // Check if the last meaningful line before the closing brace needs a comma
    let needs_comma = before_brace
        .lines()
        .rev()
        .find(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with("//")
        })
        .map(|line| {
            let trimmed = line.trim();
            !trimmed.ends_with(',') && !trimmed.ends_with('{')
        })
        .unwrap_or(false);

    if needs_comma {
        // Add comma to the last non-empty, non-comment line
        let lines: Vec<&str> = before_brace.lines().collect();
        for i in (0..lines.len()).rev() {
            let trimmed = lines[i].trim();
            if !trimmed.is_empty() && !trimmed.starts_with("//") {
                // Append comma to this line
                result = lines[..i].join("\n");
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(lines[i]);
                result.push(',');
                result.push('\n');
                if i + 1 < lines.len() {
                    result.push_str(&lines[i + 1..].join("\n"));
                    result.push('\n');
                }
                break;
            }
        }
        if result.is_empty() {
            // Fallback: no line found to add comma to
            result = before_brace.to_string();
        }
    } else {
        result = before_brace.to_string();
        if !result.ends_with('\n') {
            result.push('\n');
        }
    }

    result.push_str(&managed_block);
    result.push('\n');
    result.push_str(&working_text[insert_pos..]);

    // Ensure trailing newline
    if !result.ends_with('\n') {
        result.push('\n');
    }

    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            result.len()
        );
        return Ok(());
    }

    // Create backup of existing file before modifying (settings.json is high-value user content).
    // Always back up on first-time insertion into existing file, regardless of --force.
    // Skip if the force+remove path above already created a backup this invocation.
    if path.exists() && !already_backed_up {
        super::fs_helpers::create_backup_always(path)?;
    }

    super::fs_helpers::atomic_write(path, &result, 0o644)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

/// Remove all lines between begin_marker and end_marker (inclusive).
fn remove_managed_block(
    text: &str,
    begin_marker: &str,
    end_marker: &str,
) -> Result<String, String> {
    let mut result = Vec::new();
    let mut suppressing = false;

    for line in text.lines() {
        if line.contains(begin_marker) {
            suppressing = true;
            continue;
        }
        if line.contains(end_marker) {
            if !suppressing {
                return Err("tirith: found END marker without BEGIN in managed block".to_string());
            }
            suppressing = false;
            continue;
        }
        if !suppressing {
            result.push(line);
        }
    }

    if suppressing {
        return Err(
            "tirith: corrupted tirith-hooks block — missing END marker, fix manually".to_string(),
        );
    }

    let mut out = result.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── merge_mcp_json ──────────────────────────────────────────────

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

        // Second call should succeed (skip)
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

        // dry_run + drift should NOT error
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
        assert!(!path.exists()); // dry-run should not create
    }

    #[test]
    fn mcp_json_dry_run_force_no_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        merge_mcp_json(&path, "tirith", json!({"command": "old"}), false, false).unwrap();

        // dry-run + force should not create backup files
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

    // ── merge_hooks_json ────────────────────────────────────────────

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

    // ── merge_claude_settings ───────────────────────────────────────

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

    // ── merge_vscode_settings ───────────────────────────────────────

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

    // ── remove_managed_block ────────────────────────────────────────

    #[test]
    fn remove_managed_block_removes_block() {
        let text = "before\n// BEGIN x\nstuff\n// END x\nafter\n";
        let result = remove_managed_block(text, "// BEGIN x", "// END x").unwrap();
        assert_eq!(result, "before\nafter\n");
    }

    #[test]
    fn remove_managed_block_errors_on_missing_end() {
        let text = "before\n// BEGIN x\nstuff\n";
        let result = remove_managed_block(text, "// BEGIN x", "// END x");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing END"));
    }

    #[test]
    fn remove_managed_block_errors_on_orphan_end() {
        let text = "before\n// END x\nstuff\n";
        let result = remove_managed_block(text, "// BEGIN x", "// END x");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("END marker without BEGIN"));
    }
}
