#!/usr/bin/env bash
# tirith bash hook
# Two modes controlled by TIRITH_BASH_MODE:
#   enter (default outside SSH): bind -x Enter override. Can block execution.
#   preexec: DEBUG trap warn-only. Cannot block.

# Guard against double-loading
[[ -n "$_TIRITH_BASH_LOADED" ]] && return
_TIRITH_BASH_LOADED=1

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

if [[ -n "${TIRITH_BASH_MODE:-}" ]]; then
  _TIRITH_BASH_MODE="$TIRITH_BASH_MODE"
elif [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" || -n "${SSH_CLIENT:-}" ]]; then
  # SSH PTY environments are more reliable with DEBUG-trap preexec mode.
  _TIRITH_BASH_MODE="preexec"
else
  _TIRITH_BASH_MODE="enter"
fi

# Queue command execution into PROMPT_COMMAND so interactive commands
# (ssh, gcloud compute ssh, etc.) run outside the bind -x callback.
_tirith_register_prompt_hook() {
  [[ -n "${_TIRITH_PROMPT_HOOKED:-}" ]] && return
  _TIRITH_PROMPT_HOOKED=1

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

  if declare -p PROMPT_COMMAND >/dev/null 2>&1 && [[ "$(declare -p PROMPT_COMMAND)" == "declare -a"* ]]; then
    PROMPT_COMMAND=(_tirith_prompt_hook "${PROMPT_COMMAND[@]}")
  elif [[ -n "${PROMPT_COMMAND:-}" ]]; then
    PROMPT_COMMAND="_tirith_prompt_hook;${PROMPT_COMMAND}"
  else
    PROMPT_COMMAND="_tirith_prompt_hook"
  fi
}

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

if [[ "$_TIRITH_BASH_MODE" == "enter" ]]; then
  # Mode: enter — bind -x Enter override with full block+warn capability

  _tirith_register_prompt_hook

  _tirith_enter() {
    # Save terminal state — bind -x can corrupt echo in some PTY environments (gcloud ssh, etc.)
    local _saved_stty
    _saved_stty=$(stty -g 2>/dev/null) || true

    # Ensure terminal state is restored on exit
    trap 'stty "$_saved_stty" 2>/dev/null || true' RETURN

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

    if [[ $rc -eq 1 ]]; then
      # Block: show the command that was blocked, print warning, clear line
      _tirith_output ""
      _tirith_output "command> $READLINE_LINE"
      [[ -n "$output" ]] && _tirith_output "$output"
      READLINE_LINE=""
      READLINE_POINT=0
    elif [[ $rc -eq 2 ]]; then
      # Warn: print warning then execute
      _tirith_output ""
      _tirith_output "command> $READLINE_LINE"
      [[ -n "$output" ]] && _tirith_output "$output"
      # Fall through to execute
    fi

    if [[ $rc -ne 1 ]]; then
      # Allow (0) or Warn (2): execute the command
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
    fi
  }

  bind -x '"\C-m": _tirith_enter' || true
  bind -x '"\C-j": _tirith_enter' || true

  # Bracketed paste interception
  _tirith_paste() {
    # Save terminal state — bind -x can corrupt echo in some PTY environments (gcloud ssh, etc.)
    local _saved_stty
    _saved_stty=$(stty -g 2>/dev/null) || true
    trap 'stty "$_saved_stty" 2>/dev/null || true' RETURN

    # Read pasted content until bracketed paste end sequence (\e[201~)
    local pasted=""
    local char
    while IFS= read -r -n 1 -t 1 char; do
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

      if [[ $rc -eq 1 ]]; then
        # Block: show what was pasted, then warning, discard paste
        _tirith_output ""
        _tirith_output "paste> $pasted"
        [[ -n "$output" ]] && _tirith_output "$output"
        return
      elif [[ $rc -eq 2 ]]; then
        # Warn: show warning, keep paste
        [[ -n "$output" ]] && { _tirith_output ""; _tirith_output "$output"; }
      fi
    fi

    # Allow: insert into readline buffer
    READLINE_LINE="${READLINE_LINE:0:$READLINE_POINT}${pasted}${READLINE_LINE:$READLINE_POINT}"
    READLINE_POINT=$((READLINE_POINT + ${#pasted}))
  }

  # Bind bracketed paste start sequence
  bind -x '"\e[200~": _tirith_paste' || true

elif [[ "$_TIRITH_BASH_MODE" == "preexec" ]]; then
  # Mode: preexec — DEBUG trap, warn-only (cannot block)

  _tirith_preexec() {
    # Only run once per command (guard against DEBUG firing multiple times)
    [[ "${_tirith_last_cmd:-}" == "$BASH_COMMAND" ]] && return
    _tirith_last_cmd="$BASH_COMMAND"

    # Warn-only: command is already committed, we can only print warnings
    tirith check --shell posix -- "$BASH_COMMAND" || true
  }

  trap '_tirith_preexec' DEBUG
fi
