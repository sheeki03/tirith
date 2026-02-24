#!/usr/bin/env bash
# tirith bash hook
# Two modes controlled by TIRITH_BASH_MODE:
#   enter (default outside SSH): bind -x Enter override. Can block + intercept paste.
#     Startup health gate + pending-not-consumed detection auto-degrade to preexec.
#   preexec: DEBUG trap warn-only. Cannot block. No paste interception.

# Guard against double-loading (session-local only).
# If inherited from environment (exported by attacker/parent), ignore it.
if [[ -n "$_TIRITH_BASH_LOADED" ]]; then
  if [[ "$(declare -p _TIRITH_BASH_LOADED 2>/dev/null)" =~ ^declare\ -[a-zA-Z]*x ]]; then
    unset _TIRITH_BASH_LOADED  # Inherited from env — ignore and load fresh
  else
    return  # Set in this session — genuine double-source guard
  fi
fi
_TIRITH_BASH_LOADED=1

# Clear attacker-controllable env vars before any hooks are installed.
# _TIRITH_PENDING_EVAL/_PENDING_SOURCE: pre-set value would be eval'd on first prompt.
unset _TIRITH_PENDING_EVAL _TIRITH_PENDING_SOURCE
# _TIRITH_TEST_*: only clear if inherited from environment (exported by parent).
# Session-local values (set without export) are trusted test overrides.
[[ "$(declare -p _TIRITH_TEST_SKIP_HEALTH 2>/dev/null)" =~ ^declare\ -[a-zA-Z]*x ]] && unset _TIRITH_TEST_SKIP_HEALTH
[[ "$(declare -p _TIRITH_TEST_FAIL_HEALTH 2>/dev/null)" =~ ^declare\ -[a-zA-Z]*x ]] && unset _TIRITH_TEST_FAIL_HEALTH

# Output helper: use stderr for Warp terminal (which doesn't display /dev/tty properly),
# otherwise use /dev/tty for proper terminal output that doesn't mix with command output.
# Allow override via TIRITH_OUTPUT=stderr for terminals that hide /dev/tty.
_tirith_output() {
  if [[ "${TIRITH_OUTPUT:-}" == "stderr" ]] || [[ "$TERM_PROGRAM" == "WarpTerminal" ]]; then
    printf '%s\n' "$1" >&2
  else
    printf '%s\n' "$1" >/dev/tty
  fi
}

# ─── Persistent safe mode infrastructure ───

# Trim whitespace to match Rust policy.rs:state_dir() behavior
_TIRITH_STATE_DIR="${XDG_STATE_HOME:-}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR#"${_TIRITH_STATE_DIR%%[![:space:]]*}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR%"${_TIRITH_STATE_DIR##*[![:space:]]}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR:-$HOME/.local/state}/tirith"
_TIRITH_SAFE_MODE_FLAG="$_TIRITH_STATE_DIR/bash-safe-mode"

_tirith_check_safe_mode() { [[ -f "$_TIRITH_SAFE_MODE_FLAG" ]]; }

_tirith_persist_safe_mode() {
  mkdir -p "$_TIRITH_STATE_DIR" 2>/dev/null || return
  printf '1\n' > "$_TIRITH_SAFE_MODE_FLAG" 2>/dev/null || return
}

# ─── Preexec function (used by both preexec mode and degrade fallback) ───

_tirith_preexec() {
  # Only run once per command (guard against DEBUG firing multiple times)
  [[ "${_tirith_last_cmd:-}" == "$BASH_COMMAND" ]] && return
  _tirith_last_cmd="$BASH_COMMAND"

  # Warn-only: command is already committed, we can only print warnings
  tirith check --shell posix -- "$BASH_COMMAND" || true
}

# ─── Degrade function ───

_tirith_degrade_to_preexec() {
  local reason="${1:-unknown}"
  # Only print warnings in interactive shells
  if [[ $- == *i* ]]; then
    _tirith_output "tirith: enter mode failed ($reason) — switching to preexec"
    _tirith_output "  Persistent. Re-enable: TIRITH_BASH_MODE=enter"
  fi

  # Safe deterministic degrade: set known-safe defaults for current session.
  # Custom bindings from .inputrc/.bashrc return on next shell (safe mode persisted,
  # so tirith won't install bind-x on restart).
  if [[ "${_TIRITH_BINDS_INSTALLED:-0}" == "1" ]]; then
    bind '"\C-m": accept-line' 2>/dev/null || true
    bind '"\C-j": accept-line' 2>/dev/null || true
    # Restore bracketed paste to readline default if available, otherwise unbind
    bind '"\e[200~": bracketed-paste-begin' 2>/dev/null || bind -r '"\e[200~"' 2>/dev/null || true
    _TIRITH_BINDS_INSTALLED=0
  fi

  trap '_tirith_preexec' DEBUG
  _TIRITH_BASH_MODE="preexec"
  _tirith_persist_safe_mode
  if [[ $- == *i* ]]; then
    _tirith_output "  Restart your shell for full custom keybindings to return."
  fi
}

# ─── PROMPT_COMMAND management ───

_tirith_prompt_hook() {
  local pending_eval="${_TIRITH_PENDING_EVAL:-}"
  local pending_source="${_TIRITH_PENDING_SOURCE:-}"
  unset _TIRITH_PENDING_EVAL _TIRITH_PENDING_SOURCE

  if [[ -n "$pending_source" ]]; then
    source "$pending_source"
    rm -f "$pending_source"
  elif [[ -n "$pending_eval" ]]; then
    eval -- "$pending_eval"
  fi
}

_tirith_is_prompt_hook_attached() {
  local pc_decl
  pc_decl="$(declare -p PROMPT_COMMAND 2>/dev/null)" || return 1

  if [[ "$pc_decl" == "declare -a"* ]]; then
    local entry
    for entry in "${PROMPT_COMMAND[@]}"; do
      [[ "$entry" == "_tirith_prompt_hook" ]] && return 0
    done
    return 1
  else
    # String form: use regex to match _tirith_prompt_hook as a semicolon-delimited
    # token with optional surrounding whitespace.
    [[ "$PROMPT_COMMAND" =~ (^|;)[[:space:]]*_tirith_prompt_hook[[:space:]]*(;|$) ]] && return 0
    return 1
  fi
}

_tirith_ensure_prompt_hook() {
  _tirith_is_prompt_hook_attached && return 0

  local pc_decl
  pc_decl="$(declare -p PROMPT_COMMAND 2>/dev/null)" || pc_decl=""

  if [[ "$pc_decl" == "declare -a"* ]]; then
    PROMPT_COMMAND=(_tirith_prompt_hook "${PROMPT_COMMAND[@]}") 2>/dev/null || return 1
  elif [[ -n "${PROMPT_COMMAND:-}" ]]; then
    PROMPT_COMMAND="_tirith_prompt_hook;${PROMPT_COMMAND}" 2>/dev/null || return 1
  else
    PROMPT_COMMAND="_tirith_prompt_hook" 2>/dev/null || return 1
  fi
  return 0
}

# ─── Mode selection ───

if [[ -n "${TIRITH_BASH_MODE:-}" ]]; then
  _TIRITH_BASH_MODE="$TIRITH_BASH_MODE"
elif _tirith_check_safe_mode; then
  _TIRITH_BASH_MODE="preexec"
  # Only print warning in interactive shells (avoid polluting scripted output)
  [[ $- == *i* ]] && _tirith_output "tirith: safe mode active (preexec) — previous enter-mode failure detected"
  [[ $- == *i* ]] && _tirith_output "  Re-enable: TIRITH_BASH_MODE=enter or tirith doctor --reset-bash-safe-mode"
elif [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" || -n "${SSH_CLIENT:-}" ]]; then
  # SSH PTY environments are more reliable with DEBUG-trap preexec mode.
  _TIRITH_BASH_MODE="preexec"
else
  _TIRITH_BASH_MODE="enter"
fi

# ─── Helpers ───

# Check if a command is unsafe to eval (heredocs, multiline, etc.)
_tirith_unsafe_to_eval() {
  local cmd="$1"

  # Contains literal newline
  if [[ "$cmd" == *$'\n'* ]]; then
    return 0
  fi

  # Ends with backslash (line continuation)
  if [[ "$cmd" == *'\' ]]; then
    return 0
  fi

  # Contains heredoc
  if [[ "$cmd" == *'<<'* ]]; then
    return 0
  fi

  # Contains compound command keywords that suggest multi-line constructs
  local keywords='(^|[;&| ])(\{|\}|function |case |select |for |while |until |coproc )'
  if [[ "$cmd" =~ $keywords ]]; then
    return 0
  fi

  # Contains '; do' or '; then' patterns (inline loops/conditionals)
  if [[ "$cmd" == *'; do'* ]] || [[ "$cmd" == *'; then'* ]]; then
    return 0
  fi

  # Contains command group parentheses
  if [[ "$cmd" == *'( '* ]] || [[ "$cmd" == *' )'* ]]; then
    return 0
  fi

  return 1
}

# ─── Startup health gate ───

_tirith_startup_health_check() {
  # Test-only override: bypass startup gate to reach runtime failure paths in PTY tests.
  [[ "${_TIRITH_TEST_SKIP_HEALTH:-}" == "1" ]] && return 0
  # Test-only override for CI (avoids needing PTY)
  [[ "${_TIRITH_TEST_FAIL_HEALTH:-}" == "1" ]] && return 1
  # Verify both \C-m and \C-j are bound to _tirith_enter
  local binds
  binds="$(bind -X 2>/dev/null)" || return 1
  [[ "$binds" =~ \\C-m.*_tirith_enter ]] || return 1
  [[ "$binds" =~ \\C-j.*_tirith_enter ]] || return 1
  # Verify prompt hook is still attached
  _tirith_is_prompt_hook_attached || return 1
  return 0
}

# ─── Enter mode (interactive only) ───

if [[ "$_TIRITH_BASH_MODE" == "enter" ]] && [[ $- == *i* ]]; then
  # Enter mode: interactive shell only (bind-x requires readline).
  # Non-interactive sourcing (bash -c, scripts, BASH_ENV) skips this entire block.
  # Mode variable stays "enter" but nothing is installed — effectively a no-op.
  # No traps, no bindings, no state writes in non-interactive context.
  _TIRITH_BINDS_INSTALLED=0

  # Attach prompt hook (gates further setup)
  if ! _tirith_ensure_prompt_hook; then
    _tirith_degrade_to_preexec "PROMPT_COMMAND is readonly or unattachable"
  else
    _tirith_enter() {
      # Save terminal state — bind -x can corrupt echo in some PTY environments (gcloud ssh, etc.)
      local _saved_stty
      _saved_stty=$(stty -g 2>/dev/null) || true

      # Ensure terminal state is restored on exit
      trap 'stty "$_saved_stty" 2>/dev/null || true' RETURN

      # Self-heal: verify prompt hook is still attached
      if ! _tirith_ensure_prompt_hook; then
        _tirith_degrade_to_preexec "PROMPT_COMMAND reattachment failed"
        return  # READLINE_LINE stays intact
      fi

      # Detect broken delivery: if previous pending was never consumed
      if [[ -n "${_TIRITH_PENDING_EVAL:-}" || -n "${_TIRITH_PENDING_SOURCE:-}" ]]; then
        [[ -n "${_TIRITH_PENDING_SOURCE:-}" ]] && rm -f "${_TIRITH_PENDING_SOURCE}"
        unset _TIRITH_PENDING_EVAL _TIRITH_PENDING_SOURCE
        _tirith_degrade_to_preexec "previous command not delivered (check shell history)"
        return  # READLINE_LINE stays intact
      fi

      # Empty input: just return (shows new prompt)
      if [[ -z "$READLINE_LINE" ]]; then
        READLINE_LINE=""
        READLINE_POINT=0
        return
      fi

      # Check for incomplete input (open quotes, unclosed blocks)
      local syntax_err
      syntax_err=$(bash -n <<< "$READLINE_LINE" 2>&1)
      local syntax_rc=$?
      if [[ $syntax_rc -ne 0 ]] && [[ "$syntax_err" == *"unexpected EOF"* || "$syntax_err" == *"unexpected end of file"* ]]; then
        # Incomplete input: insert newline for continued editing
        READLINE_LINE+=$'\n'
        READLINE_POINT=${#READLINE_LINE}
        return
      fi

      # Run tirith check, use temp file to prevent tty leakage in bind -x context
      local tmpfile=$(mktemp)
      tirith check --non-interactive --shell posix -- "$READLINE_LINE" >"$tmpfile" 2>&1
      local rc=$?
      local output=$(<"$tmpfile")
      rm -f "$tmpfile"

      if [[ $rc -eq 0 ]]; then
        # Allow: execute silently (fall through to execute block)
        :
      elif [[ $rc -eq 2 ]]; then
        # Warn: print warning then execute (fall through to execute block)
        _tirith_output ""
        _tirith_output "command> $READLINE_LINE"
        [[ -n "$output" ]] && _tirith_output "$output"
      elif [[ $rc -eq 1 ]]; then
        # Block: tirith intentionally blocked this command
        _tirith_output ""
        _tirith_output "command> $READLINE_LINE"
        [[ -n "$output" ]] && _tirith_output "$output"
        READLINE_LINE=""
        READLINE_POINT=0
        return
      else
        # Unexpected exit code (crash, OOM, missing binary): degrade to preexec
        # Block this command but don't break the terminal — use Issue #20 infrastructure
        _tirith_output ""
        _tirith_output "command> $READLINE_LINE"
        [[ -n "$output" ]] && _tirith_output "$output"
        _tirith_degrade_to_preexec "tirith returned unexpected exit code $rc"
        return  # READLINE_LINE preserved for re-execution via preexec
      fi

      # rc was 0 or 2: execute the command
      local cmd="$READLINE_LINE"
      READLINE_LINE=""
      READLINE_POINT=0

      # Check if safe to eval
      if _tirith_unsafe_to_eval "$cmd"; then
        # Unsafe for eval: fall back to preexec-style warn-only
        # Add to history and print warning that blocking is limited
        history -s -- "$cmd"
        >&2 printf 'tirith: complex command — executing without block capability\n'
        # Write to a temp file and source it to avoid eval pitfalls
        local tmpf
        tmpf=$(mktemp "${TMPDIR:-/tmp}/tirith.XXXXXX") || {
          # If mktemp fails, defer direct eval — fail-open
          _TIRITH_PENDING_EVAL="$cmd"
          return
        }
        printf '%s\n' "$cmd" > "$tmpf"
        _TIRITH_PENDING_SOURCE="$tmpf"
        return
      fi

      history -s -- "$cmd"
      _TIRITH_PENDING_EVAL="$cmd"
    }

    # Bracketed paste interception
    _tirith_paste() {
      # Save terminal state — bind -x can corrupt echo in some PTY environments (gcloud ssh, etc.)
      local _saved_stty
      _saved_stty=$(stty -g 2>/dev/null) || true
      trap 'stty "$_saved_stty" 2>/dev/null || true' RETURN

      # Read pasted content until bracketed paste end sequence (\e[201~)
      local pasted=""
      local char
      while IFS= read -r -n 1 -d '' -t 1 char; do
        pasted+="$char"
        # Check for end of bracketed paste
        if [[ "$pasted" == *$'\e[201~' ]]; then
          # Strip the end sequence
          pasted="${pasted%$'\e[201~'}"
          break
        fi
      done

      if [[ -n "$pasted" ]]; then
        # Check with tirith paste, use temp file to prevent tty leakage
        local tmpfile=$(mktemp)
        printf '%s' "$pasted" | tirith paste --shell posix >"$tmpfile" 2>&1
        local rc=$?
        local output=$(<"$tmpfile")
        rm -f "$tmpfile"

        if [[ $rc -eq 0 ]]; then
          # Allow: fall through to insert
          :
        elif [[ $rc -eq 2 ]]; then
          # Warn: show warning, fall through to insert
          [[ -n "$output" ]] && { _tirith_output ""; _tirith_output "$output"; }
        else
          # Block (rc=1) or unexpected: discard paste (safe — user can re-paste)
          _tirith_output ""
          _tirith_output "paste> $pasted"
          [[ -n "$output" ]] && _tirith_output "$output"
          [[ $rc -ne 1 ]] && _tirith_output "tirith: paste check failed (exit code $rc)"
          return
        fi
      fi

      # Allow: insert into readline buffer
      READLINE_LINE="${READLINE_LINE:0:$READLINE_POINT}${pasted}${READLINE_LINE:$READLINE_POINT}"
      READLINE_POINT=$((READLINE_POINT + ${#pasted}))
    }

    # Install key bindings
    bind -x '"\C-m": _tirith_enter' || true
    bind -x '"\C-j": _tirith_enter' || true
    bind -x '"\e[200~": _tirith_paste' || true
    _TIRITH_BINDS_INSTALLED=1

    # Startup health gate: verify bind-x took effect for BOTH keys
    if ! _tirith_startup_health_check; then
      _tirith_degrade_to_preexec "startup health check failed (bind-x or PROMPT_COMMAND)"
    fi
  fi

elif [[ "$_TIRITH_BASH_MODE" == "preexec" ]] && [[ $- == *i* ]]; then
  # Only install DEBUG trap in interactive shells.
  # Non-interactive sourcing (bash -c, BASH_ENV, scripts) is a clean no-op.
  trap '_tirith_preexec' DEBUG
fi
