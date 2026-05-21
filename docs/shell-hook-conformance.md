# Shell-Hook Conformance Contract

Tirith installs a shell hook (bash, zsh, fish, PowerShell, nushell) that
intercepts every command *before* it runs. The hook is the only thing standing
between a pasted `curl … | bash` and your shell executing it, so the hook must
be correct about one thing above all else: **delivering the command you typed —
exactly the command, exactly once, and only when it is allowed.**

A hook that gets delivery wrong is both a correctness bug and a safety bug:

- A **swallowed** command silently disappears — you press Enter and nothing
  happens (issue #111).
- A **duplicated** command runs twice — destructive operations run twice.
- A command that runs **despite a block** defeats the entire tool.
- A hook that loses its blocking ability and **does not say so** leaves you
  unprotected while you believe you are protected.

This document defines the **conformance contract**: the invariants every
tirith shell hook must satisfy. The contract is enforced by the Rust-native
PTY harness in `crates/tirith/tests/shell_conformance.rs` (driver:
`crates/tirith/tests/pty_support/mod.rs`).

## The contract

Every shell hook, in every mode it supports, must satisfy all seven
invariants:

| # | Invariant | What it means |
|---|-----------|---------------|
| a | **Executes exactly once** | An *allowed* command runs once — never zero times, never twice. |
| b | **Not swallowed** | An *allowed* command is delivered to the shell; its output reaches the terminal. Pressing Enter always does something. |
| c | **No history duplication** | An executed command appears in shell history exactly once. |
| d | **A blocked command does not execute** | When the hook (in a blocking mode) blocks a command, the command's side effects never happen. |
| e | **A warned command executes once** | A *warn* verdict is advisory: the command still runs, exactly once. |
| f | **Degradation is visible, not silent** | If the hook cannot deliver on its protection guarantee, it must say so — and (where applicable) persist a safe-mode flag — never quietly drop to a weaker mode. |
| g | **Non-interactive shells carry no tirith status** | Sourcing the hook in a non-interactive shell (a script, `bash -c`, `BASH_ENV`, `fish -c`) installs nothing: no traps, no key bindings, no state writes. The `TIRITH_STATUS` prompt indicator is a non-exported shell variable, so a non-interactive *child* of a protected interactive shell never inherits it either — a process with no tirith protection must never appear to carry a tirith status. |

Invariant (f) is the safety floor. A hook is allowed to *fail* — terminals are
varied and hostile environments exist — but it is never allowed to fail
*silently*. If blocking protection is lost, the user has to be told so they can
make an informed decision (restart the shell, switch modes, or accept
warn-only).

## How the harness checks the contract

The harness drives a **disposable** shell through a real pseudo-terminal:

1. Spawn the shell through a PTY with a fully isolated environment
   (`HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME` all point at
   fresh temp dirs — a test never touches the developer's real tirith state).
2. Source the *embedded* hook copy under `crates/tirith/assets/shell/lib/`
   (kept byte-identical to `shell/lib/` by the
   `embedded_shell_hooks_match_repo_hooks` test).
3. Send bytes — commands followed by a carriage return, the byte a real
   terminal delivers when you press Enter.
4. Read terminal output and assert the invariants.

The test **driver is Rust** — there is no dependency on the external `expect`
Tcl tool, which is flaky on macOS and silently sensitive to the bash version on
`PATH`.

### Ground truth: filesystem side effects, not terminal echo

Terminal output is noisy — it contains the keystroke echo, autosuggestions,
escape sequences, and the command's own output. To assert "executed exactly
once" the harness has the command append a line to a **marker file** and then
counts the lines. The filesystem side effect is unambiguous in a way terminal
text is not.

### Answering terminal-capability queries

Fish 4.x probes the terminal at startup (primary device attributes, cursor
position, the OSC 11 background-colour query, the kitty keyboard-protocol
query, XTGETTCAP). A real terminal emulator answers these; a bare PTY does
not, and fish blocks in startup forever. The harness installs a minimal,
honest auto-responder so the shell proceeds. It is harmless for bash, so it is
always on.

## Test tiers and graceful skipping

`cargo test --workspace` must stay green on any machine, including one with no
modern bash, no fish, no tmux and no SSH. The harness therefore **skips
cleanly** — never fails — when a prerequisite is missing:

- macOS ships an ancient `/bin/bash` 3.2. The harness locates a modern bash
  (>= 5, typically `/opt/homebrew/bin/bash` from Homebrew) and **skips** the
  bash tests entirely if none is found. To run them, put a modern bash first
  on `PATH`: `PATH=/opt/homebrew/bin:$PATH cargo test`.
- Fish tests **skip** when fish is not installed.
- zsh / PowerShell / nushell coverage is a documented **follow-up** (see
  below); those tests are `#[ignore]`d stubs today.

## Current coverage

| Shell / mode | Invariants covered | Status |
|--------------|--------------------|--------|
| bash — preexec (DEBUG-trap, warn-only) | a, b, c, e, g | Passing |
| bash — preexec with `TIRITH_BASH_PREEXEC_ENFORCE=1` | d | Passing |
| bash — enter (`bind -x` Enter override) | f | Passing |
| bash — #111 capability gate | a, b, d | Passing |
| fish | a, b, c, d, e, g | Passing |
| zsh | — | Follow-up |
| PowerShell | — | Follow-up |
| nushell | — | Follow-up |

### Issue #111 — bash enter-mode delivery, and the capability gate

Bash *enter* mode rebinds Enter to a shell function with `bind -x`. In many
environments, `bind -x` on `\C-m` runs the bound function but **does not then
accept the line** — so bash never returns to its command loop, `PROMPT_COMMAND`
never fires, and the pending command (captured into `_TIRITH_PENDING_EVAL`) is
never delivered. The command is silently eaten. This is issue #111.

Whether `bind -x` accepts the line is a *capability* of the specific
bash/readline build, not a function of the bash version number — so tirith
cannot decide enter-vs-preexec by a version gate. The fix is **capability-based**:

- `tirith setup` and `tirith doctor` (and the explicit
  `tirith doctor --simulate-enter`) run a disposable-PTY **self-test**
  (`crates/tirith/src/cli/bash_capability.rs`). It spawns a throwaway bash,
  sources the real hook in enter mode, and verifies that an allowed command is
  delivered exactly once **and** that a command tirith would block is actually
  stopped.
- The self-test writes a small `key=value` **cache file**
  (`<state-dir>/bash-enter-capability`) recording the verdict. Freshness is
  keyed on the bash identity — `$BASH_VERSION` and the bash binary path —
  because `bind -x` line-acceptance is a property of that specific
  bash/readline build, not of the tirith release. The cache `schema` number is
  the cross-tirith-version invalidator (any change to the probe semantics or
  cache format bumps it); the recorded `tirith_version` is diagnostic only.
- `tirith init` is unchanged — it must stay fast because it is `eval`'d on
  every interactive shell startup, and the self-test is far too heavy to run
  there. The bash hook itself reads the cache file at startup (a single
  small-file read, which *is* init-safe): it selects enter mode only when the
  cache proves enter delivery works for the running bash, and otherwise falls
  back to the safe default, preexec.

The harness reproduces #111 precisely (its bare PTY is an environment where
`bind -x` delivery is broken), so the capability-correct behaviour there is the
fallback to preexec. The regression tests assert the **capability-gated system
contract** rather than a literal enter-mode contract — a literal enter-mode
"blocked command did not run" assertion under broken delivery would pass
*vacuously*, because a swallowed allowed command and a swallowed blocked command
are indistinguishable:

- `bash_enter_allowed_command_executes_exactly_once` — with no proven enter
  capability, the hook falls back to preexec and delivers an allowed command
  exactly once (0 = the #111 swallow; 2 = double-delivery).
- `bash_enter_blocked_command_does_not_execute` — with
  `TIRITH_BASH_PREEXEC_ENFORCE=1` the preexec fallback *blocks*. The test first
  runs an allowed command and asserts it executed (the **anti-vacuous guard**:
  commands are being delivered, not eaten), then asserts the blocked
  `curl … | bash` left no marker.
- `bash_capability_cache_steers_default_mode` — a seeded `works` verdict makes
  the hook choose enter; `broken` / stale verdicts make it choose preexec.
- `bash_enter_degradation_is_visible_not_silent` — `TIRITH_BASH_MODE=enter` is
  an explicit override that forces enter even when the gate would pick preexec;
  a forced-but-broken enter mode must still degrade *visibly* and persist the
  safe-mode flag (invariant f).

The capability-cache reader's robustness against hostile bash history
configuration (`HISTCONTROL`, `HISTIGNORE`, `set +o history`, a pre-set `IFS`,
an already-enabled `extdebug`) is covered by the `capability_*` tests in
`crates/tirith/tests/bash_preexec_enforce.rs`.

## Follow-up

- **zsh / PowerShell / nushell PTY conformance.** The harness is
  shell-agnostic; each shell needs a spawn helper and its delivery quirks
  encoded (zsh `zle` widget, PowerShell PSReadLine handler, nushell hook
  model). Tracked as M0.1 follow-up; placeholder `#[ignore]`d tests mark the
  gap.
- **Offline isolation.** The bash enter-mode hook shells out to `tirith
  check`, which may attempt a background threat-DB refresh. The conformance
  tests do not currently assert on network behaviour. The `--offline` switch
  (and the `TIRITH_OFFLINE` environment variable) now exists: setting
  `TIRITH_OFFLINE=1` in a harness session makes that background refresh a
  guaranteed no-op, so a future conformance test can pin network behaviour
  deterministically.
