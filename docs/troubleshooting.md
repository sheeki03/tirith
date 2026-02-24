# Troubleshooting

## Shell hooks not loading

Run `tirith doctor` to see the hook directory being used and whether hooks were materialized from the embedded binary.

If hooks are not found:
1. Ensure `tirith` is in your PATH
2. Run `eval "$(tirith init)"` and check for error messages (if you use multiple shells, prefer `tirith init --shell bash|zsh|fish`)
3. Set `TIRITH_SHELL_DIR` to point to your shell hooks directory explicitly

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

## Bash: Enter mode vs preexec mode

tirith supports two bash integration modes:
- **enter mode** (default outside SSH): Binds to Enter key via `bind -x`. Intercepts commands and paste before execution. Includes startup health gate and runtime self-healing that auto-degrade to preexec if failures are detected.
- **preexec mode**: Uses `DEBUG` trap (tirith owns this trap). Compatible with more environments but warn-only — cannot block commands. No paste interception.

Set via: `export TIRITH_BASH_MODE=enter` or `export TIRITH_BASH_MODE=preexec` (set before `tirith init` in your shell rc)

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

In preexec mode (including after auto-degrade from enter mode), tirith sets the `DEBUG` trap. This is the same behavior used by default in SSH sessions. If you have custom `DEBUG` traps in your shell configuration, they will be overridden when tirith is in preexec mode.

## Bash: no visible input after `ssh` / `gcloud compute ssh`

tirith automatically defaults to preexec mode when `SSH_CONNECTION`, `SSH_TTY`, or `SSH_CLIENT` is set. If you still see input issues, force preexec explicitly:

```bash
export TIRITH_BASH_MODE=preexec
eval "$(tirith init --shell bash)"
```

This avoids `bind -x` enter interception in environments where PTY handling is fragile.

## PowerShell: PSReadLine conflicts

If using PSReadLine, ensure the tirith hook loads after PSReadLine initialization. The hook overrides `PSConsoleHostReadLine` to intercept pastes.

## Latency

tirith's Tier 1 fast path (no URLs detected) targets <2ms. If you notice latency:

1. Run `tirith check --json -- "your command"` and check `timings_ms`
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

## Unexpected tirith exit codes

Tirith uses a **mixed fail-safe policy** for unexpected exit codes (crashes, OOM-kills, missing binary). The policy balances safety against terminal usability:

- **Bash enter mode**: Auto-degrades to preexec on unexpected tirith exit code. The current command is not executed; subsequent commands go through preexec warn-only mode. Recoverable via `tirith doctor --reset-bash-safe-mode` or `export TIRITH_BASH_MODE=enter`.
- **Zsh / Fish / PowerShell**: Warns and executes on unexpected exit code. A diagnostic message is printed so you know protection is degraded. The terminal never breaks.
- **All paste paths**: Fail-closed — discards paste on any unexpected exit code. Safe because you can re-paste.

Expected exit codes: `0` (allow), `1` (block), `2` (warn). Anything else is treated as unexpected.

## Audit log location

Default: `~/.local/share/tirith/log.jsonl` (XDG-compliant)

Each entry is a JSON line with timestamp, action, rule IDs, and redacted command.
