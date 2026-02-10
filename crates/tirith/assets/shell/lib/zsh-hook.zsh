#!/usr/bin/env zsh
# tirith zsh hook
# Overrides accept-line widget to check commands before execution.
# Overrides bracketed-paste widget to check pasted content.

# Guard against double-loading (session-local only).
# If inherited from environment (exported by attacker/parent), ignore it.
if [[ -n "$_TIRITH_ZSH_LOADED" ]]; then
  if [[ "${(t)_TIRITH_ZSH_LOADED}" == *export* ]]; then
    unset _TIRITH_ZSH_LOADED  # Inherited from env — ignore and load fresh
  else
    return  # Set in this session — genuine double-source guard
  fi
fi
_TIRITH_ZSH_LOADED=1

# Session tracking: generate ID per shell session if not inherited
if [[ -z "${TIRITH_SESSION_ID:-}" ]]; then
  TIRITH_SESSION_ID="$(printf '%x-%x' "$$" "$(date +%s)")"
  export TIRITH_SESSION_ID
fi

# Output helper: write to stderr by default (ADR-7).
# Override via TIRITH_OUTPUT=tty to write to /dev/tty instead.
_tirith_output() {
  if [[ "${TIRITH_OUTPUT:-}" == "tty" ]]; then
    printf '%s\n' "$1" >/dev/tty
  else
    printf '%s\n' "$1" >&2
  fi
}

# ─── Approval workflow helpers (ADR-7) ───

_tirith_parse_approval() {
  local file="$1"
  _tirith_ap_required="no"
  _tirith_ap_timeout=0
  _tirith_ap_fallback="block"
  _tirith_ap_rule=""
  _tirith_ap_desc=""

  if [[ ! -r "$file" ]]; then
    _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
    rm -f "$file"  # ADR-7: delete on all paths
    _tirith_ap_required="yes"
    _tirith_ap_fallback="block"
    _tirith_ap_timeout=0
    return 1
  fi

  local valid_keys=0
  while IFS='=' read -r key value; do
    case "$key" in
      TIRITH_REQUIRES_APPROVAL) _tirith_ap_required="$value"; valid_keys=$((valid_keys + 1)) ;;
      TIRITH_APPROVAL_TIMEOUT) _tirith_ap_timeout="$value" ;;
      TIRITH_APPROVAL_FALLBACK) _tirith_ap_fallback="$value" ;;
      TIRITH_APPROVAL_RULE) _tirith_ap_rule="$value" ;;
      TIRITH_APPROVAL_DESCRIPTION) _tirith_ap_desc="$value" ;;
    esac
  done < "$file"

  rm -f "$file"

  if [[ $valid_keys -eq 0 ]]; then
    _tirith_output "tirith: warning: approval file corrupt, failing closed"
    _tirith_ap_required="yes"
    _tirith_ap_fallback="block"
    return 1
  fi
  return 0
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

  # Run tirith check with approval workflow (stdout=approval file path, stderr=human output)
  local errfile=$(mktemp)
  local approval_path
  approval_path=$(tirith check --approval-check --non-interactive --shell posix -- "$buf" 2>"$errfile")
  local rc=$?
  local output=$(<"$errfile")
  rm -f "$errfile"

  if [[ $rc -eq 0 ]]; then
    :  # Allow: no output
  elif [[ $rc -eq 2 ]]; then
    _tirith_output ""
    _tirith_output "command> $buf"
    [[ -n "$output" ]] && _tirith_output "$output"
  elif [[ $rc -eq 1 ]]; then
    _tirith_output ""
    _tirith_output "command> $buf"
    [[ -n "$output" ]] && _tirith_output "$output"
  else
    # Unexpected rc: warn + execute (fail-open to avoid terminal breakage)
    _tirith_output ""
    [[ -n "$output" ]] && _tirith_output "$output"
    _tirith_output "tirith: unexpected exit code $rc — running unprotected"
    [[ -n "$approval_path" ]] && rm -f "$approval_path"
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
    return
  fi

  # Approval workflow: runs for ALL exit codes (0, 1, 2).
  # For rc=1 (block), approval gives user a chance to override.
  if [[ -n "$approval_path" ]]; then
    _tirith_parse_approval "$approval_path"
    if [[ "$_tirith_ap_required" == "yes" ]]; then
      _tirith_output "tirith: approval required for $_tirith_ap_rule"
      [[ -n "$_tirith_ap_desc" ]] && _tirith_output "  $_tirith_ap_desc"
      local response=""
      if [[ "$_tirith_ap_timeout" -gt 0 ]]; then
        read -t "$_tirith_ap_timeout" "response?Approve? (${_tirith_ap_timeout}s timeout) [y/N] " </dev/tty 2>/dev/null
      else
        read "response?Approve? [y/N] " </dev/tty 2>/dev/null
      fi
      if [[ "$response" == [yY]* ]]; then
        :  # Approved: fall through to execute
      else
        case "$_tirith_ap_fallback" in
          allow)
            _tirith_output "tirith: approval not granted — fallback: allow"
            ;;
          warn)
            _tirith_output "tirith: approval not granted — fallback: warn"
            ;;
          *)
            _tirith_output "tirith: approval not granted — fallback: block"
            BUFFER=""
            zle send-break
            return
            ;;
        esac
      fi
    elif [[ $rc -eq 1 ]]; then
      # Approval not required but command was blocked: honor block
      BUFFER=""
      zle send-break
      return
    fi
  elif [[ $rc -eq 1 ]]; then
    # No approval file: honor block
    BUFFER=""
    zle send-break
    return
  fi

  # Execute (rc=0, rc=2, or approval granted)
  zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
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

    if [[ $rc -eq 0 ]]; then
      # Allow: fall through to keep paste
      :
    elif [[ $rc -eq 2 ]]; then
      [[ -n "$output" ]] && { _tirith_output ""; _tirith_output "$output"; }
    else
      # Block or unexpected: revert paste
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      _tirith_output ""
      _tirith_output "paste> $pasted"
      [[ -n "$output" ]] && _tirith_output "$output"
      [[ $rc -ne 1 ]] && _tirith_output "tirith: unexpected exit code $rc — paste blocked for safety"
      zle send-break
      return
    fi
  fi
}

zle -N bracketed-paste _tirith_bracketed_paste
