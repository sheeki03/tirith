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
| g | **Non-interactive sourcing is a complete no-op** | Sourcing the hook in a non-interactive shell (a script, `bash -c`, `BASH_ENV`, `fish -c`) installs nothing: no traps, no key bindings, no state writes, no exported status vars. |

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
| bash — enter | a, b, c, d | `#[ignore]` — issue #111 |
| fish | a, b, c, d, e, g | Passing |
| zsh | — | Follow-up |
| PowerShell | — | Follow-up |
| nushell | — | Follow-up |

### Known bug: bash enter mode (#111)

Bash *enter* mode rebinds Enter to a shell function with `bind -x`. In a
standard PTY, `bind -x` on `\C-m` runs the bound function but **does not then
accept the line** — so bash never returns to its command loop, `PROMPT_COMMAND`
never fires, and the pending command (captured into `_TIRITH_PENDING_EVAL`) is
never delivered. The next Enter sees the un-consumed pending command and the
hook degrades to preexec. This is issue #111: a command is eaten, followed by a
silent-feeling enter→preexec degrade.

The harness reproduces this precisely. Two consequences:

- The enter-mode **delivery** tests
  (`bash_enter_allowed_command_executes_exactly_once`,
  `bash_enter_blocked_command_does_not_execute`) are written and `#[ignore]`d
  with a `#111` reference. They are ready regression tests — remove the
  `#[ignore]` when #111 is fixed — and keep `cargo test` green meanwhile.
- The enter-mode **degradation** test
  (`bash_enter_degradation_is_visible_not_silent`) is *active and passing*: a
  buggy enter mode must still satisfy invariant (f) — fail loudly and persist
  the safe-mode flag. It does.

## Follow-up

- **zsh / PowerShell / nushell PTY conformance.** The harness is
  shell-agnostic; each shell needs a spawn helper and its delivery quirks
  encoded (zsh `zle` widget, PowerShell PSReadLine handler, nushell hook
  model). Tracked as M0.1 follow-up; placeholder `#[ignore]`d tests mark the
  gap.
- **Offline isolation.** The bash enter-mode hook shells out to `tirith
  check`, which may attempt a background threat-DB refresh. The conformance
  tests do not assert on network behaviour, but a dedicated `--offline`
  switch (roadmap M0.3) would let the harness pin this deterministically.
- **Fixing #111.** Once bash enter-mode delivery is fixed, un-`#[ignore]` the
  two enter-mode delivery tests.
