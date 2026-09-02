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
  builtin printf -v TIRITH_SESSION_ID '%x-%x-%x-%x' \
    "$$" "${SECONDS:-0}" "${RANDOM:-0}" "${RANDOM:-0}"
  export TIRITH_SESSION_ID
fi

# Pin the executable before any repository command can mutate PATH. All hook
# callbacks use this absolute path for the lifetime of the shell session.
_TIRITH_BIN="${commands[tirith]:-}"
if [[ -n "$_TIRITH_BIN" ]]; then
  _TIRITH_BIN="${_TIRITH_BIN:A}"
fi
if [[ -z "$_TIRITH_BIN" || ! -x "$_TIRITH_BIN" ]]; then
  print -u2 -- "tirith: executable not found; zsh hooks disabled"
  TIRITH_STATUS=off
  return
fi

# Protocol-v3 callbacks run after arbitrary commands may have changed PATH.
# Pin every external helper they use to a fixed system location now, and only
# advertise receipt support when the complete helper set is available.
_TIRITH_MKTEMP_BIN=""
[[ -f /usr/bin/mktemp && -x /usr/bin/mktemp ]] && _TIRITH_MKTEMP_BIN=/usr/bin/mktemp
[[ -z "$_TIRITH_MKTEMP_BIN" && -f /bin/mktemp && -x /bin/mktemp ]] \
  && _TIRITH_MKTEMP_BIN=/bin/mktemp
_TIRITH_RM_BIN=""
[[ -f /bin/rm && -x /bin/rm ]] && _TIRITH_RM_BIN=/bin/rm
[[ -z "$_TIRITH_RM_BIN" && -f /usr/bin/rm && -x /usr/bin/rm ]] \
  && _TIRITH_RM_BIN=/usr/bin/rm
_TIRITH_WC_BIN=""
[[ -f /usr/bin/wc && -x /usr/bin/wc ]] && _TIRITH_WC_BIN=/usr/bin/wc
[[ -z "$_TIRITH_WC_BIN" && -f /bin/wc && -x /bin/wc ]] \
  && _TIRITH_WC_BIN=/bin/wc
_TIRITH_ENV_BIN=""
[[ -f /usr/bin/env && -x /usr/bin/env ]] && _TIRITH_ENV_BIN=/usr/bin/env
[[ -z "$_TIRITH_ENV_BIN" && -f /bin/env && -x /bin/env ]] \
  && _TIRITH_ENV_BIN=/bin/env
_TIRITH_SH_BIN=""
[[ -f /bin/sh && -x /bin/sh ]] && _TIRITH_SH_BIN=/bin/sh
[[ -z "$_TIRITH_SH_BIN" && -f /usr/bin/sh && -x /usr/bin/sh ]] \
  && _TIRITH_SH_BIN=/usr/bin/sh
_TIRITH_V3_HELPERS_READY=1
for _tirith_helper in "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN" \
  "$_TIRITH_ENV_BIN" "$_TIRITH_SH_BIN"; do
  [[ "$_tirith_helper" == /* && -f "$_tirith_helper" && -x "$_tirith_helper" ]] \
    || _TIRITH_V3_HELPERS_READY=0
done
unset _tirith_helper

# One receipt protocol instance per sourced hook. It is deliberately
# non-exported; only individual Tirith subprocesses receive it. Older binaries
# fail the capability probe and keep the legacy check flow with an honest
# degraded status instead of misparsing the hidden flag. Registration itself
# happens further down, after the capture-file helpers are defined.
_TIRITH_RECEIPT_PROTOCOL=0
_TIRITH_RECEIPT_INSTANCE=""
_TIRITH_RECEIPT_REGISTER_ERROR=""
_TIRITH_RECEIPT_SHELL_PID="$$"
_TIRITH_RECEIPT_FAMILY="zsh"

# M9 ch4 — record a shell-start environment snapshot for `tirith env diff`.
# We exec a hidden tirith subcommand that reads ITS OWN inherited environment
# and writes ONLY variable names + an 8-char value-hash prefix (never raw
# values, never a recoverable hash) to <state-dir>/env_snapshot.json. The child
# inherits this shell's exported env, so no value ever crosses an argv boundary
# or a temp file. Interactive-only and backgrounded (&) so it never blocks the
# prompt. The hook is sourced once per session (guarded above), so this runs
# once per shell start.
if [[ -o interactive ]]; then
  command "$_TIRITH_BIN" env snapshot >/dev/null 2>&1 &!
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

_tirith_receipt_reconcile_at() {
  local token="$1" original_cwd="$2"
  [[ $_TIRITH_V3_HELPERS_READY -eq 1 && -n "$token" && -n "$original_cwd" ]] \
    || return 1
  builtin printf '%s' "$token" | command "$_TIRITH_ENV_BIN" \
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    _TIRITH_RECEIPT_CWD="$original_cwd" \
    _TIRITH_BIN="$_TIRITH_BIN" \
    "$_TIRITH_SH_BIN" -c 'cd "$_TIRITH_RECEIPT_CWD" 2>/dev/null || exit 1; exec "$_TIRITH_BIN" __execution-receipt reconcile --channel zsh' \
    >/dev/null 2>&1
}

_tirith_receipt_consume_at() {
  local token="$1" expected="$2" original_cwd="$3"
  [[ $_TIRITH_V3_HELPERS_READY -eq 1 && -n "$token" && -n "$original_cwd" ]] \
    || return 1
  builtin printf '%s\n%s' "$token" "$expected" | command "$_TIRITH_ENV_BIN" \
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    _TIRITH_RECEIPT_CWD="$original_cwd" \
    _TIRITH_BIN="$_TIRITH_BIN" \
    "$_TIRITH_SH_BIN" -c 'cd "$_TIRITH_RECEIPT_CWD" 2>/dev/null || exit 1; exec "$_TIRITH_BIN" __execution-receipt consume --channel zsh' \
    >/dev/null
}

_tirith_receipt_discard_at() {
  local token="$1" original_cwd="$2"
  [[ $_TIRITH_V3_HELPERS_READY -eq 1 && -n "$token" && -n "$original_cwd" ]] \
    || return 1
  builtin printf '%s' "$token" | command "$_TIRITH_ENV_BIN" \
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    _TIRITH_RECEIPT_CWD="$original_cwd" \
    _TIRITH_BIN="$_TIRITH_BIN" \
    "$_TIRITH_SH_BIN" -c 'cd "$_TIRITH_RECEIPT_CWD" 2>/dev/null || exit 1; exec "$_TIRITH_BIN" __execution-receipt discard --channel zsh' \
    >/dev/null 2>&1
}

_tirith_unresolved_receipt_cleanup() {
  local token="${_TIRITH_UNRESOLVED_RECEIPT:-}"
  local original_cwd="${_TIRITH_UNRESOLVED_RECEIPT_CWD:-}"
  [[ -n "$token" ]] || return 0
  if _tirith_receipt_reconcile_at "$token" "$original_cwd" \
     || _tirith_receipt_discard_at "$token" "$original_cwd"; then
    unset _TIRITH_UNRESOLVED_RECEIPT _TIRITH_UNRESOLVED_RECEIPT_CWD
    return 0
  fi
  return 1
}

_tirith_receipt_discard_or_retain() {
  local token="$1" original_cwd="$2"
  [[ -n "$token" && -n "$original_cwd" ]] || return 1
  if _tirith_receipt_discard_at "$token" "$original_cwd"; then
    return 0
  fi
  if [[ -z "${_TIRITH_UNRESOLVED_RECEIPT:-}" ]]; then
    _TIRITH_UNRESOLVED_RECEIPT="$token"
    _TIRITH_UNRESOLVED_RECEIPT_CWD="$original_cwd"
  fi
  return 1
}

_tirith_v3_new_capture_file() {
  [[ "$_TIRITH_MKTEMP_BIN" == /* && "$_TIRITH_RM_BIN" == /* ]] || return 1
  local file
  file="$(umask 077; command "$_TIRITH_MKTEMP_BIN")" || return 1
  if [[ -z "$file" || ! -f "$file" || -L "$file" || ! -O "$file" ]]; then
    [[ -n "$file" ]] && command "$_TIRITH_RM_BIN" -f -- "$file" 2>/dev/null
    return 1
  fi
  print -r -- "$file"
}

_tirith_v3_remove_capture_files() {
  [[ "$_TIRITH_RM_BIN" == /* && "$#" -gt 0 ]] || return 1
  command "$_TIRITH_RM_BIN" -f -- "$@"
}

_tirith_v3_cleanup_registration_files() {
  local file
  for file in "$@"; do
    [[ -n "$file" ]] || continue
    _tirith_v3_remove_capture_files "$file" >/dev/null 2>&1 || :
  done
  return 0
}

# Protocol-v3 registration. The Rust side binds the receipt capability to its
# immediate parent pid, so tirith MUST run as a direct child of this shell.
# A command substitution breaks that whenever zsh's exec optimization is
# suppressed (e.g. a prompt framework installed a WINCH trap earlier in the
# rc): the substitution then runs through an intermediate forked subshell and
# registration is rejected. Capture stdout/stderr through temp files from a
# plain foreground command instead, and keep the failure reason for the
# status warning below instead of discarding it.
if [[ -o interactive ]] \
   && [[ $_TIRITH_V3_HELPERS_READY -eq 1 ]] \
   && [[ "$(command "$_TIRITH_BIN" __execution-receipt capability 2>/dev/null)" == "TIRITH_EXECUTION_RECEIPT_PROTOCOL=3" ]]; then
  _tirith_register_out="$(_tirith_v3_new_capture_file)" || _tirith_register_out=""
  _tirith_register_err="$(_tirith_v3_new_capture_file)" || _tirith_register_err=""
  if [[ -n "$_tirith_register_out" && -n "$_tirith_register_err" ]]; then
    # Keep a rejected registration inside an explicit condition so a user's
    # ERR_EXIT setting cannot abort hook initialization before we record the
    # rejection and fall back honestly. The files already exist, so force the
    # redirects through a user's NOCLOBBER setting.
    if command "$_TIRITH_BIN" __execution-receipt register \
         --family zsh --shell-pid "$_TIRITH_RECEIPT_SHELL_PID" \
         >|"$_tirith_register_out" 2>|"$_tirith_register_err"; then
      :
    fi
    _TIRITH_RECEIPT_INSTANCE="$(<"$_tirith_register_out")"
    _TIRITH_RECEIPT_INSTANCE="${_TIRITH_RECEIPT_INSTANCE%%$'\n'*}"
    if [[ ${#_TIRITH_RECEIPT_INSTANCE} -eq 64 && "$_TIRITH_RECEIPT_INSTANCE" != *[^0-9a-f]* ]]; then
      _TIRITH_RECEIPT_PROTOCOL=3
    else
      _TIRITH_RECEIPT_INSTANCE=""
      _TIRITH_RECEIPT_REGISTER_ERROR="$(<"$_tirith_register_err")"
      _TIRITH_RECEIPT_REGISTER_ERROR="${_TIRITH_RECEIPT_REGISTER_ERROR%%$'\n'*}"
    fi
    _tirith_v3_cleanup_registration_files "$_tirith_register_out" "$_tirith_register_err"
  else
    _tirith_v3_cleanup_registration_files "$_tirith_register_out" "$_tirith_register_err"
  fi
  unset _tirith_register_out _tirith_register_err
fi


_tirith_parse_approval() {
  local file="$1"
  _tirith_ap_required="no"
  _tirith_ap_timeout=0
  _tirith_ap_fallback="block"
  _tirith_ap_rule=""
  _tirith_ap_desc=""

  if [[ ! -r "$file" ]]; then
    _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
    _tirith_v3_remove_capture_files "$file" >/dev/null 2>&1  # delete on all paths
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

  _tirith_v3_remove_capture_files "$file" >/dev/null 2>&1

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
    _tirith_v3_remove_capture_files "$file" >/dev/null 2>&1
    return 1
  fi

  while IFS='=' read -r key value; do
    case "$key" in
      TIRITH_WARN_ACK_FINDINGS) _tirith_wa_findings="$value" ;;
      TIRITH_WARN_ACK_MAX_SEVERITY) _tirith_wa_max_severity="$value" ;;
    esac
  done < "$file"

  _tirith_v3_remove_capture_files "$file" >/dev/null 2>&1
  return 0
}

# Save original accept-line widget if it exists
if (( $+widgets[accept-line] )); then
  zle -A accept-line _tirith_original_accept_line
fi

_tirith_accept_line() {
  setopt localoptions clobber   # mktemp + redirect needs clobber
  local buf="$BUFFER"

  # Never create or deliver a second receipt while recovery of an older one is
  # unresolved. Reconciliation/discard runs in the original working directory.
  if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]] \
     && ! _tirith_unresolved_receipt_cleanup; then
    _tirith_output "tirith: execution receipt remains unresolved; command not accepted"
    return
  fi

  # Empty input: pass through
  #
  # Protocol v3 calls the BUILTIN accept-line rather than a saved third-party
  # widget, here and after a receipt commit below. That is deliberate: a saved
  # widget runs with full control of $BUFFER, so on the commit path it executes
  # after the "command changed after receipt commit" check and could run
  # something the armed receipt does not cover, and on this empty-buffer path it
  # could synthesize a command that was never analyzed at all. The legacy
  # (protocol-off) path keeps delegating, because it has no receipt to bind.
  if [[ -z "$buf" ]]; then
    if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
      zle .accept-line
    else
      zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
    fi
    return
  fi

  # Protocol v3 returns only an already-armed receipt token on stdout. The
  # protocol-off path below retains the legacy approval temp-file workflow.
  local errfile=""
  local approval_path="" warn_ack_path="" receipt_token=""
  local check_stdout="" rc=1 output=""
  if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
    local outfile="" receipt_cwd="$PWD"
    if ! errfile="$(_tirith_v3_new_capture_file)" \
       || ! outfile="$(_tirith_v3_new_capture_file)"; then
      [[ -n "$errfile" ]] && _tirith_v3_remove_capture_files "$errfile" >/dev/null 2>&1
      _tirith_output "tirith: secure execution-receipt capture unavailable; command blocked"
      BUFFER=""
      zle send-break
      return
    fi
    _TIRITH_HOOK=1 _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
      _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
      _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
      command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell posix \
      --execution-receipt zsh -- "$buf" >"$outfile" 2>"$errfile"
    rc=$?
    output=$(<"$errfile")

    local receipt_prefix="TIRITH_EXECUTION_RECEIPT=" receipt_line="" candidate_token=""
    local stdout_bytes stdout_lines expected_bytes first_line_status=1 frame_valid=0
    stdout_bytes=$(LC_ALL=C command "$_TIRITH_WC_BIN" -c <"$outfile" 2>/dev/null)
    stdout_bytes="${stdout_bytes//[[:space:]]/}"
    stdout_lines=$(LC_ALL=C command "$_TIRITH_WC_BIN" -l <"$outfile" 2>/dev/null)
    stdout_lines="${stdout_lines//[[:space:]]/}"
    expected_bytes=$((${#receipt_prefix} + 65))
    IFS= read -r receipt_line <"$outfile"
    first_line_status=$?
    if [[ "$receipt_line" == "${receipt_prefix}"* ]]; then
      candidate_token="${receipt_line#${receipt_prefix}}"
      if [[ ${#candidate_token} -eq 64 && "$candidate_token" != *[^0-9a-f]* ]]; then
        receipt_token="$candidate_token"
      fi
    fi

    if { [[ $rc -eq 0 ]] || [[ $rc -eq 2 ]]; } \
       && [[ $first_line_status -eq 0 ]] \
       && [[ "$stdout_bytes" == "$expected_bytes" ]] \
       && [[ "$stdout_lines" == "1" ]] \
       && [[ -n "$receipt_token" ]] \
       && [[ "$receipt_line" == "${receipt_prefix}${receipt_token}" ]]; then
      frame_valid=1
    fi

    if [[ $frame_valid -eq 1 ]]; then
      if ! _tirith_v3_remove_capture_files "$outfile" "$errfile"; then
        _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
        _tirith_output "tirith: execution-receipt capture cleanup failed; command blocked"
        zle redisplay
        return
      fi
      if [[ "$BUFFER" != "$buf" ]]; then
        _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
        _tirith_output "tirith: command changed before receipt commit; command not executed — press Enter for a fresh check"
        zle redisplay
        return
      fi
      if ! _tirith_receipt_consume_at "$receipt_token" "$buf" "$receipt_cwd"; then
        if _tirith_receipt_reconcile_at "$receipt_token" "$receipt_cwd"; then
          _tirith_output "tirith: receipt recovery completed but cannot authorize replay; command not executed — press Enter for a fresh check"
        else
          _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
          _tirith_output "tirith: execution receipt could not be committed; command not executed — press Enter for a fresh check"
        fi
        zle redisplay
        return
      fi
      if [[ $rc -eq 2 ]]; then
        local v3_escaped_buf=$(_tirith_escape_preview "$buf")
        _tirith_output ""
        _tirith_output "command> $v3_escaped_buf"
        [[ -n "$output" ]] && _tirith_output "$output"
      fi
      if [[ "$BUFFER" != "$buf" ]]; then
        _tirith_output "tirith: command changed after receipt commit; command not executed with conservative unresolved line-acceptance evidence"
        zle redisplay
        return
      fi
      # Builtin accept-line, not _tirith_original_accept_line: a third-party
      # widget would run AFTER the buffer check directly above and could mutate
      # $BUFFER, executing a command the committed receipt does not describe.
      zle .accept-line
      return
    fi

    if [[ $rc -eq 1 && "$stdout_bytes" == "0" ]]; then
      _tirith_v3_remove_capture_files "$outfile" "$errfile" >/dev/null 2>&1
      local v3_blocked_buf=$(_tirith_escape_preview "$buf")
      _tirith_output ""
      _tirith_output "command> $v3_blocked_buf"
      [[ -n "$output" ]] && _tirith_output "$output"
      BUFFER=""
      zle send-break
      return
    fi

    # Any other status/stdout pairing is a malformed v3 frame. If its first
    # line contains a syntactically valid token, retire it before blocking.
    [[ -n "$receipt_token" ]] \
      && _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
    _tirith_v3_remove_capture_files "$outfile" "$errfile" >/dev/null 2>&1
    local v3_malformed_buf=$(_tirith_escape_preview "$buf")
    _tirith_output ""
    _tirith_output "command> $v3_malformed_buf"
    [[ -n "$output" ]] && _tirith_output "$output"
    _tirith_output "tirith: invalid execution-receipt response; command blocked"
    BUFFER=""
    zle send-break
    return
  fi

  # Legacy protocol-off behavior: stdout is the approval metadata path(s), and
  # the shell retains ownership of the historical prompt/fallback workflow.
  if ! errfile="$(_tirith_v3_new_capture_file)"; then
    _tirith_output "tirith: secure preflight capture unavailable; command blocked"
    BUFFER=""
    zle send-break
    return
  fi
  check_stdout=$(_TIRITH_HOOK=1 command "$_TIRITH_BIN" check \
    --approval-check --non-interactive --interactive --shell posix -- "$buf" 2>"$errfile")
  rc=$?
  output=$(<"$errfile")
  _tirith_v3_remove_capture_files "$errfile" >/dev/null 2>&1

  approval_path="$check_stdout"
  if [[ $rc -eq 3 ]]; then
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
    [[ -n "$approval_path" ]] && _tirith_v3_remove_capture_files "$approval_path" >/dev/null 2>&1
    [[ -n "$warn_ack_path" ]] && _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
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
            [[ -n "$warn_ack_path" ]] && _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
            BUFFER=""
            zle send-break
            return
            ;;
        esac
      fi
    elif [[ $rc -eq 1 ]]; then
      # Approval not required but command was blocked: honor block
      [[ -n "$warn_ack_path" ]] && _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
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
    _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
  fi

  # Execute (rc=0, rc=2, rc=3 acknowledged, or approval granted)
  zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
}

zle -N accept-line _tirith_accept_line

# Bracketed paste interception
if (( $+widgets[bracketed-paste] )); then
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
    local tmpfile="" output="" rc=1
    if ! tmpfile="$(_tirith_v3_new_capture_file)"; then
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      _tirith_output "tirith: secure paste capture unavailable; paste blocked for safety"
      zle send-break
      return
    fi
    builtin printf '%s' "$pasted" \
      | _TIRITH_HOOK=1 command "$_TIRITH_BIN" paste --shell posix --interactive >"$tmpfile" 2>&1
    rc=$?
    output=$(<"$tmpfile")
    if ! _tirith_v3_remove_capture_files "$tmpfile" >/dev/null 2>&1; then
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      _tirith_output "tirith: secure paste capture cleanup failed; paste blocked for safety"
      zle send-break
      return
    fi

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
  _tirith_unresolved_receipt_cleanup >/dev/null 2>&1 || true
  [[ -n "${TIRITH_SESSION_ID:-}" ]] || return
  local _sd="${XDG_STATE_HOME:-$HOME/.local/state}/tirith"
  [[ -f "$_sd/sessions/$TIRITH_SESSION_ID.json" ]] || return
  command "$_TIRITH_BIN" warnings --summary
}
_TIRITH_RECEIPT_HOOKS_READY=0
if autoload -Uz add-zsh-hook 2>/dev/null \
   && add-zsh-hook zshexit _tirith_exit_summary; then
  _TIRITH_RECEIPT_HOOKS_READY=1
else
  # Never enable receipts unless unresolved-state exit cleanup is confirmed.
  if (( $+functions[add-zsh-hook] )); then
    add-zsh-hook -d zshexit _tirith_exit_summary 2>/dev/null || true
  fi
  _TIRITH_RECEIPT_PROTOCOL=0
fi

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
  if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
    TIRITH_STATUS="blocks"
  else
    TIRITH_STATUS="degraded"
    _tirith_output "tirith: execution receipts unavailable; shell protection is running in legacy mode"
    [[ -n "${_TIRITH_RECEIPT_REGISTER_ERROR:-}" ]] \
      && _tirith_output "$_TIRITH_RECEIPT_REGISTER_ERROR"
  fi
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
