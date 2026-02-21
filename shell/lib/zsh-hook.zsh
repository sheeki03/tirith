#!/usr/bin/env zsh
# tirith zsh hook
# Overrides accept-line widget to check commands before execution.
# Overrides bracketed-paste widget to check pasted content.

# Guard against double-loading
[[ -n "$_TIRITH_ZSH_LOADED" ]] && return
_TIRITH_ZSH_LOADED=1

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

# Save original accept-line widget if it exists
if zle -la | grep -q '^accept-line$'; then
  zle -A accept-line _tirith_original_accept_line
fi

_tirith_accept_line() {
  local buf="$BUFFER"

  # Empty input: pass through
  if [[ -z "$buf" ]]; then
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
    return
  fi

  # Run tirith check, redirect to temp file to prevent tty leakage
  local tmpfile=$(mktemp)
  tirith check --non-interactive --interactive --shell posix -- "$buf" >"$tmpfile" 2>&1
  local rc=$?
  local output=$(<"$tmpfile")
  rm -f "$tmpfile"

  if [[ $rc -eq 1 ]]; then
    # Block: show command and output
    BUFFER=""
    _tirith_output ""
    _tirith_output "command> $buf"
    [[ -n "$output" ]] && _tirith_output "$output"
    zle send-break
  elif [[ $rc -eq 2 ]]; then
    # Warn: show command and output, then execute
    _tirith_output ""
    _tirith_output "command> $buf"
    [[ -n "$output" ]] && _tirith_output "$output"
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
  else
    # Allow: execute normally
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
  fi
}

zle -N accept-line _tirith_accept_line

# Bracketed paste interception
if zle -la | grep -q '^bracketed-paste$'; then
  zle -A bracketed-paste _tirith_original_bracketed_paste
fi

_tirith_bracketed_paste() {
  # Read the pasted content into CUTBUFFER via the original widget
  local old_buffer="$BUFFER"
  local old_cursor="$CURSOR"
  zle _tirith_original_bracketed_paste 2>/dev/null || zle .bracketed-paste

  # The new content is what was added to BUFFER
  local new_buffer="$BUFFER"
  local pasted="${new_buffer:$old_cursor:$((${#new_buffer} - ${#old_buffer}))}"

  if [[ -n "$pasted" ]]; then
    # Pipe pasted content to tirith paste, use temp file to prevent tty leakage
    local tmpfile=$(mktemp)
    echo -n "$pasted" | tirith paste --shell posix >"$tmpfile" 2>&1
    local rc=$?
    local output=$(<"$tmpfile")
    rm -f "$tmpfile"

    if [[ $rc -eq 1 ]]; then
      # Block: show paste content and output
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      _tirith_output ""
      _tirith_output "paste> $pasted"
      [[ -n "$output" ]] && _tirith_output "$output"
      zle send-break
    elif [[ $rc -eq 2 ]]; then
      # Warn: show warning, keep paste
      [[ -n "$output" ]] && { _tirith_output ""; _tirith_output "$output"; }
    fi
    # Allow (0): keep the paste silently
  fi
}

zle -N bracketed-paste _tirith_bracketed_paste
