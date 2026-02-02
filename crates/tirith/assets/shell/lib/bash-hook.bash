#!/usr/bin/env bash
# tirith bash hook
# Two modes controlled by TIRITH_BASH_MODE:
#   enter (default): bind -x Enter override. Can block execution.
#   preexec: DEBUG trap warn-only. Cannot block.

# Guard against double-loading
[[ -n "$_TIRITH_BASH_LOADED" ]] && return
_TIRITH_BASH_LOADED=1

_TIRITH_BASH_MODE="${TIRITH_BASH_MODE:-enter}"

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

  _tirith_enter() {
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

    # Run tirith check. Binary prints warnings/blocks directly to stderr.
    tirith check --shell posix -- "$READLINE_LINE"
    local rc=$?

    if [[ $rc -eq 1 ]]; then
      # Block: clear the line
      READLINE_LINE=""
      READLINE_POINT=0
    else
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
          # If mktemp fails, just execute directly — fail-open
          eval -- "$cmd"
          return
        }
        printf '%s\n' "$cmd" > "$tmpf"
        source "$tmpf"
        rm -f "$tmpf"
        return
      fi

      history -s -- "$cmd"
      eval -- "$cmd"
    fi
  }

  bind -x '"\C-m": _tirith_enter' || true
  bind -x '"\C-j": _tirith_enter' || true

  # Bracketed paste interception
  _tirith_paste() {
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
      # Check with tirith paste
      printf '%s' "$pasted" | tirith paste --shell posix
      local rc=$?

      if [[ $rc -eq 1 ]]; then
        # Block: discard paste
        return
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
