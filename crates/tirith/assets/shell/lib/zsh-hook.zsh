#!/usr/bin/env zsh
# tirith zsh hook
# Overrides accept-line widget to check commands before execution.
# Overrides bracketed-paste widget to check pasted content.

# Guard against double-loading
[[ -n "$_TIRITH_ZSH_LOADED" ]] && return
_TIRITH_ZSH_LOADED=1

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

  # Run tirith check. Binary prints warnings/blocks directly to stderr.
  tirith check --shell posix -- "$buf"
  local rc=$?

  if [[ $rc -eq 1 ]]; then
    # Block: clear the line
    zle kill-whole-line
    zle reset-prompt
  else
    # Allow (0) or Warn (2): execute normally
    # Warn message already printed to stderr by the binary
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
    # Pipe pasted content to tirith paste
    echo -n "$pasted" | tirith paste --shell posix
    local rc=$?

    if [[ $rc -eq 1 ]]; then
      # Block: revert the paste
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      zle reset-prompt
    fi
    # Allow (0) or Warn (2): keep the paste, warning already printed
  fi
}

zle -N bracketed-paste _tirith_bracketed_paste
