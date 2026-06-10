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

# M9 ch4 — record a shell-start environment snapshot for `tirith env diff`.
# We exec a hidden tirith subcommand that reads ITS OWN inherited environment
# and writes ONLY variable names + an 8-char value-hash prefix (never raw
# values, never a recoverable hash) to <state-dir>/env_snapshot.json. The child
# inherits this shell's exported env, so no value ever crosses an argv boundary
# or a temp file. Interactive-only and backgrounded (&) so it never blocks the
# prompt. The hook is sourced once per session (guarded above), so this runs
# once per shell start.
if [[ -o interactive ]]; then
  command tirith env snapshot >/dev/null 2>&1 &!
fi

# M8 ch2 — surface "this shell is on the remote side of an SSH session" to
# `tirith prompt-status` (planned for M8 ch6) and any other downstream
# consumer. Set NOW so chunk 6 can read it without a follow-up hook patch.
# Standard SSH env vars: SSH_CONNECTION, SSH_CLIENT, SSH_TTY. Setting at
# every hook source is idempotent — if the parent already exported it
# (e.g. a nested sub-shell on the remote side), we keep the parent value.
if [[ -z "${TIRITH_SSH_REMOTE:-}" ]] \
   && { [[ -n "${SSH_CONNECTION:-}" ]] || [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_TTY:-}" ]]; }; then
  TIRITH_SSH_REMOTE=1
  export TIRITH_SSH_REMOTE
fi

# Output helper: write to stderr by default.
# Override via TIRITH_OUTPUT=tty to write to /dev/tty instead.
_tirith_output() {
  if [[ "${TIRITH_OUTPUT:-}" == "tty" ]]; then
    printf '%s\n' "$@" >/dev/tty
  else
    printf '%s\n' "$@" >&2
  fi
}

_tirith_escape_preview() {
  printf '%q' -- "$1"
}


_tirith_parse_approval() {
  local file="$1"
  _tirith_ap_required="no"
  _tirith_ap_timeout=0
  _tirith_ap_fallback="block"
  _tirith_ap_rule=""
  _tirith_ap_desc=""

  if [[ ! -r "$file" ]]; then
    _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
    command rm -f "$file"  # delete on all paths
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

  command rm -f "$file"

  if [[ $valid_keys -eq 0 ]]; then
    _tirith_output "tirith: warning: approval file corrupt, failing closed"
    _tirith_ap_required="yes"
    _tirith_ap_fallback="block"
    return 1
  fi
  return 0
}


_tirith_parse_warn_ack() {
  local file="$1"
  _tirith_wa_findings=0
  _tirith_wa_max_severity=""

  if [[ ! -r "$file" ]]; then
    command rm -f "$file"
    return 1
  fi

  while IFS='=' read -r key value; do
    case "$key" in
      TIRITH_WARN_ACK_FINDINGS) _tirith_wa_findings="$value" ;;
      TIRITH_WARN_ACK_MAX_SEVERITY) _tirith_wa_max_severity="$value" ;;
    esac
  done < "$file"

  command rm -f "$file"
  return 0
}

# Save original accept-line widget if it exists
if zle -la | grep -q '^accept-line$'; then
  zle -A accept-line _tirith_original_accept_line
fi

_tirith_accept_line() {
  setopt localoptions clobber   # mktemp + redirect needs clobber
  local buf="$BUFFER"

  # Empty input: pass through
  if [[ -z "$buf" ]]; then
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
    return
  fi

  # Run tirith check with approval workflow (stdout=approval file path, stderr=human output)
  local errfile=$(mktemp)
  local approval_path
  approval_path=$(_TIRITH_HOOK=1 command tirith check --approval-check --non-interactive --interactive --shell posix -- "$buf" 2>"$errfile")
  local rc=$?
  local output=$(<"$errfile")
  command rm -f "$errfile"

  # Exit code 3 (WarnAck): stdout has two lines — approval path + warn-ack path.
  # Split them so approval workflow gets the right file.
  local warn_ack_path=""
  if [[ $rc -eq 3 ]]; then
    # Split multi-line stdout: line 1 = approval, line 2 = warn-ack
    local _lines=("${(f)approval_path}")
    approval_path="${_lines[1]}"
    warn_ack_path="${_lines[2]}"
  fi

  if [[ $rc -eq 0 ]]; then
    :  # Allow: no output
  elif [[ $rc -eq 2 || $rc -eq 3 ]]; then
    local escaped_buf=$(_tirith_escape_preview "$buf")
    _tirith_output ""
    _tirith_output "command> $escaped_buf"
    [[ -n "$output" ]] && _tirith_output "$output"
  elif [[ $rc -eq 1 ]]; then
    local escaped_buf=$(_tirith_escape_preview "$buf")
    _tirith_output ""
    _tirith_output "command> $escaped_buf"
    [[ -n "$output" ]] && _tirith_output "$output"
  else
    # Unexpected rc: warn + execute (fail-open to avoid terminal breakage)
    _tirith_output ""
    [[ -n "$output" ]] && _tirith_output "$output"
    _tirith_output "tirith: unexpected exit code $rc — running unprotected"
    [[ -n "$approval_path" ]] && command rm -f "$approval_path"
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
    return
  fi

  # Approval workflow: runs for ALL exit codes (0, 1, 2, 3).
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
            [[ -n "$warn_ack_path" ]] && command rm -f "$warn_ack_path"
            BUFFER=""
            zle send-break
            return
            ;;
        esac
      fi
    elif [[ $rc -eq 1 ]]; then
      # Approval not required but command was blocked: honor block
      [[ -n "$warn_ack_path" ]] && command rm -f "$warn_ack_path"
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

  # Warn-ack workflow (exit code 3): strict_warn requires explicit acknowledgement
  if [[ $rc -eq 3 && -n "$warn_ack_path" ]]; then
    _tirith_parse_warn_ack "$warn_ack_path"
    local response=""
    read "response?tirith: proceed with ${_tirith_wa_findings} warning(s)? [y/N] " </dev/tty 2>/dev/null
    if [[ "$response" == [yY]* ]]; then
      :  # Acknowledged: fall through to execute
    else
      _tirith_output "tirith: warnings not acknowledged — command blocked"
      BUFFER=""
      zle send-break
      return
    fi
  elif [[ -n "$warn_ack_path" ]]; then
    # Clean up warn-ack file if present but not rc=3 (shouldn't happen, but be safe)
    command rm -f "$warn_ack_path"
  fi

  # Execute (rc=0, rc=2, rc=3 acknowledged, or approval granted)
  zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
}

zle -N accept-line _tirith_accept_line

# Bracketed paste interception
if zle -la | grep -q '^bracketed-paste$'; then
  zle -A bracketed-paste _tirith_original_bracketed_paste
fi

_tirith_bracketed_paste() {
  setopt localoptions clobber   # mktemp + redirect needs clobber
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
    echo -n "$pasted" | _TIRITH_HOOK=1 command tirith paste --shell posix --interactive >"$tmpfile" 2>&1
    local rc=$?
    local output=$(<"$tmpfile")
    command rm -f "$tmpfile"

    if [[ $rc -eq 0 ]]; then
      # Allow: fall through to keep paste
      :
    elif [[ $rc -eq 2 ]]; then
      [[ -n "$output" ]] && { _tirith_output ""; _tirith_output "$output"; }
    else
      # Block or unexpected: revert paste
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      local escaped_paste=$(_tirith_escape_preview "$pasted")
      _tirith_output ""
      _tirith_output "paste> $escaped_paste"
      [[ -n "$output" ]] && _tirith_output "$output"
      [[ $rc -ne 1 ]] && _tirith_output "tirith: unexpected exit code $rc — paste blocked for safety"
      zle send-break
      return
    fi
  fi
}

zle -N bracketed-paste _tirith_bracketed_paste

# Exit summary: show session warnings on shell exit
_tirith_exit_summary() {
  [[ -n "${TIRITH_SESSION_ID:-}" ]] || return
  local _sd="${XDG_STATE_HOME:-$HOME/.local/state}/tirith"
  [[ -f "$_sd/sessions/$TIRITH_SESSION_ID.json" ]] || return
  command tirith warnings --summary
}
autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook zshexit _tirith_exit_summary

# TIRITH_STATUS: a small public contract a user can reference in their PS1 to
# surface tirith's live protection level in their prompt (see
# docs/prompt-status.md). tirith prints NOTHING per-prompt — it only sets the
# variable; wiring it into a prompt is opt-in. The zsh hook overrides the
# accept-line widget, which can abort a blocked command, so its protection
# level is always `blocks`; zsh has no runtime-degrade path. Interactive-only,
# so a non-interactive `source` (a script, `zsh -c`) sets no status var —
# conformance invariant (g).
#
# Deliberately NOT exported: the prompt runs in THIS interactive shell, which
# reads a plain shell variable fine, and a non-interactive child process has no
# tirith protection — so it must not inherit a status that would misrepresent
# it. (A `typeset -g` is unnecessary here: the hook is sourced at top level, so
# a bare assignment already creates the shell-global parameter.)
if [[ -o interactive ]]; then
  TIRITH_STATUS="blocks"
fi

# ── tirith output wrap (M7 ch1) ─────────────────────────────────────────────
# Opt-in output-direction wrapper. Commented out by default in this embedded
# hook copy; `tirith output wrap on` writes an active copy of the function
# into the user's shell-profile separately. This block is kept here as the
# canonical source so a user reading the hook understands the surface area.
#
# Scope honesty: this wraps INDIVIDUAL commands invoked via `tirith-out
# <cmd>`. It does NOT intercept output from anything run outside the wrapper.
#
# tirith-output-guard-wrap() {
#   if [[ "$#" -eq 0 ]]; then
#     printf 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]\n' >&2
#     return 2
#   fi
#   "$@" 2>&1 | command tirith view --max-bytes 16777216 -
# }
# alias tirith-out='tirith-output-guard-wrap'
