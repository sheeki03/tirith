# Showing tirith's protection level in your prompt (`TIRITH_STATUS`)

When tirith's shell hook is active it sets a shell variable, `TIRITH_STATUS`,
describing the **live protection level** of the current shell. You can
reference it in your prompt (PS1 / `fish_prompt` / a PowerShell `prompt`
function) to keep tirith's state visible at a glance.

tirith itself prints **nothing** on every prompt — it only sets the variable.
Wiring it into a prompt is entirely opt-in; if you do nothing, nothing
changes.

> **`TIRITH_STATUS` is a non-exported shell variable, not an environment
> variable.** Your prompt runs *inside* the interactive shell, so it reads the
> variable directly — PS1 command substitution, `PROMPT_COMMAND`, a
> `fish_prompt` function and a PowerShell `prompt` function all see a
> non-exported variable fine. It is deliberately *not* exported because a
> non-interactive child process (a script, `bash -c …`) has **no tirith
> protection** — inheriting a `TIRITH_STATUS` there would misrepresent the
> child as protected. The one consequence: an *external* prompt renderer that
> runs as a separate process (Starship — see below) cannot see it without you
> opting back into exporting it yourself.

## Values

| Value | Meaning |
|-------|---------|
| `blocks` | A dangerous command is stopped before it runs (bash enter mode, bash preexec with enforcement, zsh, fish, PowerShell). |
| `warn-only` | Commands are checked and you are warned, but a dangerous one is **not** blocked (bash preexec without enforcement). |
| `degraded` | Protection was **downgraded mid-session** from a stronger level — for example bash enter mode fell back to preexec warn-only. Worth noticing: you are less protected than when the shell started. |
| `off` | The hook installed nothing in this shell (for example PowerShell without PSReadLine). |

The variable is **never set** in a non-interactive shell — the hook is a
complete no-op there — and, because it is not exported, it is also never
inherited by a non-interactive child of an interactive shell. Either way a
script never sees a misleading status.

`degraded` is deliberately distinct from `warn-only`: a shell that simply
*starts* in warn-only is `warn-only`, while a shell that *loses* a stronger
guarantee at runtime is `degraded`.

> **nushell** does not set `TIRITH_STATUS`. Nushell has no session variable
> that is both readable by a prompt closure and not inherited by child
> processes — any nushell `$env` entry is exported — so the nushell hook
> deliberately exposes no status variable. nushell is warn-only regardless.

## bash / zsh — add a segment to `PS1`

This helper prints a short, coloured tag only when the variable is set, and
nothing at all when it is unset (non-interactive shells, or tirith not
installed):

```bash
_tirith_prompt_tag() {
  case "${TIRITH_STATUS:-}" in
    blocks)    printf '\001\033[32m\002[tirith]\001\033[0m\002 ' ;;     # green
    warn-only) printf '\001\033[33m\002[tirith warn]\001\033[0m\002 ' ;; # yellow
    degraded)  printf '\001\033[31m\002[tirith DEGRADED]\001\033[0m\002 ' ;; # red
    off)       printf '\001\033[90m\002[tirith off]\001\033[0m\002 ' ;;  # grey
  esac
}
PS1='$(_tirith_prompt_tag)'"$PS1"
```

For **zsh**, drop the `\001`/`\002` readline markers and use zsh prompt escapes
instead:

```zsh
_tirith_prompt_tag() {
  case "${TIRITH_STATUS:-}" in
    blocks)    print -n '%F{green}[tirith]%f ' ;;
    warn-only) print -n '%F{yellow}[tirith warn]%f ' ;;
    degraded)  print -n '%F{red}[tirith DEGRADED]%f ' ;;
    off)       print -n '%F{8}[tirith off]%f ' ;;
  esac
}
setopt prompt_subst
PS1='$(_tirith_prompt_tag)'"$PS1"
```

## fish — add it to `fish_prompt`

```fish
function fish_prompt
    switch "$TIRITH_STATUS"
        case blocks
            set_color green;  echo -n '[tirith] '
        case warn-only
            set_color yellow; echo -n '[tirith warn] '
        case degraded
            set_color red;    echo -n '[tirith DEGRADED] '
        case off
            set_color brblack; echo -n '[tirith off] '
    end
    set_color normal
    # ... your existing prompt ...
end
```

## PowerShell — add it to your `prompt` function

The PowerShell hook sets `TIRITH_STATUS` as a session-scoped `$global:`
variable (not `$env:`, which would export it to child processes). A `prompt`
function runs in the global scope, so reference it as `$global:TIRITH_STATUS`:

```powershell
function prompt {
    switch ($global:TIRITH_STATUS) {
        'blocks'    { Write-Host '[tirith] ' -NoNewline -ForegroundColor Green }
        'warn-only' { Write-Host '[tirith warn] ' -NoNewline -ForegroundColor Yellow }
        'degraded'  { Write-Host '[tirith DEGRADED] ' -NoNewline -ForegroundColor Red }
        'off'       { Write-Host '[tirith off] ' -NoNewline -ForegroundColor DarkGray }
    }
    "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
}
```

## Starship

Starship is an **external** prompt renderer: each prompt it shells out to a
separate process. That process is a child of your shell and therefore does
**not** inherit `TIRITH_STATUS` — the variable is a non-exported shell
variable (see the note at the top of this page), so a Starship `custom`
module's `command` cannot read it as-is.

If you want the tirith status in Starship, you must opt back into exporting
the variable yourself, accepting that it will then also be visible to other
child processes. Re-export it in your shell rc *after* the tirith hook is
sourced — for bash/zsh:

```bash
# In ~/.bashrc / ~/.zshrc, AFTER the line that sources the tirith hook:
export TIRITH_STATUS
```

then add a [`custom`](https://starship.rs/config/#custom-commands) module:

```toml
[custom.tirith]
command = "echo $TIRITH_STATUS"
when = ''' test -n "$TIRITH_STATUS" '''
format = "[$output]($style) "
style = "bold yellow"
```

For an in-shell prompt (PS1 / `fish_prompt` / a PowerShell `prompt` function)
no re-export is needed — only Starship's separate-process model requires it.

## Notes

- The variable is updated **in place** when protection changes during a
  session — for example a bash enter-mode degrade flips it from `blocks` to
  `degraded` — so a `$TIRITH_STATUS`-based prompt segment reflects the change
  on the next prompt with no extra work.
- For the full picture of a degraded session, run `tirith doctor` (it shows an
  explicit `protection:` line and, when degraded, a callout) or
  `tirith doctor --bundle` for a redacted diagnostic report.
- Adding a `$TIRITH_STATUS` segment is purely cosmetic — it does not change
  what tirith blocks or warns on.
