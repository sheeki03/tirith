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
# A pre-set value would be eval'd on the first prompt.
unset _TIRITH_PENDING_EVAL
unset _TIRITH_PENDING_RECEIPT _TIRITH_PENDING_COMMAND
# _TIRITH_TEST_*: only clear if inherited from environment (exported by parent).
# Session-local values (set without export) are trusted test overrides.
[[ "$(declare -p _TIRITH_TEST_SKIP_HEALTH 2>/dev/null)" =~ ^declare\ -[a-zA-Z]*x ]] && unset _TIRITH_TEST_SKIP_HEALTH
[[ "$(declare -p _TIRITH_TEST_FAIL_HEALTH 2>/dev/null)" =~ ^declare\ -[a-zA-Z]*x ]] && unset _TIRITH_TEST_FAIL_HEALTH

# Session tracking: generate ID per shell session if not inherited
if [[ -z "${TIRITH_SESSION_ID:-}" ]]; then
  builtin printf -v TIRITH_SESSION_ID '%x-%x-%x-%x' \
    "$$" "${SECONDS:-0}" "${RANDOM:-0}" "${RANDOM:-0}"
  export TIRITH_SESSION_ID
fi

# Pin the executable before any repository command can mutate PATH. Resolve
# the containing directory with shell builtins so this security initialization
# does not itself execute a PATH-controlled helper.
_TIRITH_BASH_BIN="${BASH:-}"
case "$_TIRITH_BASH_BIN" in
  /*) [[ -x "$_TIRITH_BASH_BIN" ]] || _TIRITH_BASH_BIN="" ;;
  *) _TIRITH_BASH_BIN="" ;;
esac
_tirith_resolved_bin="$(type -P tirith 2>/dev/null || true)"
_TIRITH_BIN=""
if [[ -n "$_tirith_resolved_bin" ]]; then
  _tirith_bin_name="${_tirith_resolved_bin##*/}"
  _tirith_bin_dir="${_tirith_resolved_bin%/*}"
  [[ "$_tirith_bin_dir" == "$_tirith_resolved_bin" ]] && _tirith_bin_dir="."
  _TIRITH_BIN="$(
    builtin cd -P -- "$_tirith_bin_dir" 2>/dev/null \
      && printf '%s/%s' "$PWD" "$_tirith_bin_name"
  )"
fi
unset _tirith_resolved_bin _tirith_bin_name _tirith_bin_dir
if [[ $- == *i* && ( -z "$_TIRITH_BIN" || ! -x "$_TIRITH_BIN" ) ]]; then
  printf '%s\n' "tirith: executable not found; bash hooks disabled" >&2
  TIRITH_STATUS=off
  return
fi

# Stock macOS Bash 3.2 runs an external command inside `$(...)` from a subshell.
# Protocol-v3 receipt operations bind Tirith to its exact parent shell PID, so a
# command-substitution capture would make the helper subshell (not this
# long-lived interactive shell) Tirith's parent. Capture Tirith stdout in a
# private temporary file instead: Tirith remains a direct child, parsing happens
# in this shell, and every caller removes the file immediately.
_TIRITH_MKTEMP_BIN=""
[[ -f /usr/bin/mktemp && -x /usr/bin/mktemp ]] && _TIRITH_MKTEMP_BIN=/usr/bin/mktemp
[[ -z "$_TIRITH_MKTEMP_BIN" && -f /bin/mktemp && -x /bin/mktemp ]] && _TIRITH_MKTEMP_BIN=/bin/mktemp
_TIRITH_RM_BIN=""
[[ -f /bin/rm && -x /bin/rm ]] && _TIRITH_RM_BIN=/bin/rm
[[ -z "$_TIRITH_RM_BIN" && -f /usr/bin/rm && -x /usr/bin/rm ]] && _TIRITH_RM_BIN=/usr/bin/rm
_TIRITH_MKDIR_BIN=""
[[ -f /bin/mkdir && -x /bin/mkdir ]] && _TIRITH_MKDIR_BIN=/bin/mkdir
[[ -z "$_TIRITH_MKDIR_BIN" && -f /usr/bin/mkdir && -x /usr/bin/mkdir ]] && _TIRITH_MKDIR_BIN=/usr/bin/mkdir
_TIRITH_WC_BIN=""
[[ -f /usr/bin/wc && -x /usr/bin/wc ]] && _TIRITH_WC_BIN=/usr/bin/wc
[[ -z "$_TIRITH_WC_BIN" && -f /bin/wc && -x /bin/wc ]] && _TIRITH_WC_BIN=/bin/wc
_TIRITH_STTY_BIN=""
[[ -f /bin/stty && -x /bin/stty ]] && _TIRITH_STTY_BIN=/bin/stty
[[ -z "$_TIRITH_STTY_BIN" && -f /usr/bin/stty && -x /usr/bin/stty ]] && _TIRITH_STTY_BIN=/usr/bin/stty

_tirith_new_capture_file() {
  [[ -n "$_TIRITH_MKTEMP_BIN" && -n "$_TIRITH_RM_BIN" ]] || return 1
  local base="${TMPDIR:-/tmp}"
  case "$base" in
    *$'\n'*|*$'\r'*) return 1 ;;
  esac
  [[ -d "$base" ]] || return 1
  (umask 077; builtin command "$_TIRITH_MKTEMP_BIN" "${base%/}/tirith-bash.XXXXXXXX")
}

_tirith_capture_file_is_private() {
  local file="${1:-}"
  [[ -n "$file" && -f "$file" && ! -L "$file" && -O "$file" ]]
}

_tirith_remove_capture_file() {
  local file="${1:-}"
  [[ -n "$file" && -n "$_TIRITH_RM_BIN" ]] || return 1
  builtin command "$_TIRITH_RM_BIN" -f -- "$file"
}

_tirith_restore_terminal_state() {
  local state="${1:-}"
  [[ -n "$state" && -n "$_TIRITH_STTY_BIN" ]] || return 0
  builtin command "$_TIRITH_STTY_BIN" "$state" 2>/dev/null || true
}

# Bash 3.2 predates `exec {var}` dynamic descriptor allocation. Allocate one
# unused descriptor from a small fixed range without interpolating payload text
# into `eval`; each writer receives its bytes as a quoted data argument.
_tirith_fixed_fd_is_valid() {
  case "${1:-}" in
    10|11|12|13|14|15|16|17|18|19) return 0 ;;
    *) return 1 ;;
  esac
}

# Receipt stdin frames must be byte-exact: no sentinel and no extra newline.
# The consumer blocks on the anonymous pipe until the writer supplies the frame,
# while Tirith itself remains a direct child of the long-lived Bash process.
_tirith_open_exact_input_pipe() {
  local payload="$1" candidate
  local previous_internal="${_TIRITH_BASH_INTERNAL:-0}"
  _TIRITH_OPENED_FD=""
  for candidate in 19 18 17 16 15 14 13 12 11 10; do
    [[ -e "/dev/fd/$candidate" ]] && continue
    _TIRITH_PIPE_BYTES="$payload"
    _TIRITH_BASH_INTERNAL=1
    if builtin eval "exec ${candidate}< <(builtin printf '%s' \"\$_TIRITH_PIPE_BYTES\")"; then
      _TIRITH_BASH_INTERNAL="$previous_internal"
      _TIRITH_OPENED_FD="$candidate"
      unset _TIRITH_PIPE_BYTES
      return 0
    fi
    _TIRITH_BASH_INTERNAL="$previous_internal"
  done
  _TIRITH_BASH_INTERNAL="$previous_internal"
  unset _TIRITH_PIPE_BYTES
  return 1
}

_tirith_close_pending_fd() {
  local pending_fd="${1:-}"
  _tirith_fixed_fd_is_valid "$pending_fd" || return 1
  builtin eval "exec ${pending_fd}<&-"
}

# Read exactly one text line without a command substitution. The result is
# returned in `_TIRITH_CAPTURE_LINE`; empty, unterminated, or multi-line files
# fail closed.
_tirith_read_single_capture_line() {
  local file="$1" line="" count=0 terminated=0 read_rc=0 byte_count="" expected_bytes=0
  _TIRITH_CAPTURE_LINE=""
  _tirith_capture_file_is_private "$file" || return 1
  while :; do
    line=""
    IFS= read -r line
    read_rc=$?
    [[ $read_rc -ne 0 && -z "$line" ]] && break
    count=$((count + 1))
    [[ $count -eq 1 ]] && _TIRITH_CAPTURE_LINE="$line"
    if [[ $read_rc -eq 0 ]]; then
      terminated=1
    else
      terminated=0
    fi
    [[ $count -gt 1 || $read_rc -ne 0 ]] && break
  done < "$file"
  [[ $count -eq 1 && $terminated -eq 1 && -n "$_TIRITH_WC_BIN" ]] || return 1
  byte_count="$(builtin command "$_TIRITH_WC_BIN" -c < "$file" 2>/dev/null)" || return 1
  byte_count="${byte_count//[^0-9]/}"
  [[ -n "$byte_count" ]] || return 1
  expected_bytes=$((${#_TIRITH_CAPTURE_LINE} + 1))
  [[ "$byte_count" == "$expected_bytes" ]]
}

# Parse the complete protocol-v3 stdout contract for one receipt-enabled check.
# Returns 0 for an executable rc=0/2 response carrying exactly one already-armed
# token, 1 for a valid rc=1 block with empty stdout, and 2 for every malformed or
# unsupported rc/stdout combination. A recoverable token is exposed for cleanup.
_tirith_parse_v3_receipt_response() {
  local file="$1" check_rc="$2" line_ok=0
  _TIRITH_PARSED_RECEIPT=""
  _tirith_capture_file_is_private "$file" || return 2
  if _tirith_read_single_capture_line "$file"; then
    line_ok=1
    if [[ "$_TIRITH_CAPTURE_LINE" =~ ^TIRITH_EXECUTION_RECEIPT=([0-9a-f]{64})$ ]]; then
      _TIRITH_PARSED_RECEIPT="${BASH_REMATCH[1]}"
    fi
  fi
  case "$check_rc" in
    0|2)
      [[ $line_ok -eq 1 && -n "$_TIRITH_PARSED_RECEIPT" ]] && return 0
      return 2
      ;;
    1)
      [[ ! -s "$file" ]] && return 1
      return 2
      ;;
    *) return 2 ;;
  esac
}

# Validate the exact readline buffer without Bash 3.2's here-string temp file.
# The command remains shell data passed through an anonymous pipe. Capture the
# parser's status explicitly: a user-enabled pipefail or a writer-side SIGPIPE
# must never replace the `bash -n` verdict.
_tirith_check_command_syntax() {
  local command_text="$1"
  _TIRITH_SYNTAX_ERROR="$(
    set +o pipefail
    builtin printf '%s\n' "$command_text" \
      | builtin command "$_TIRITH_BASH_BIN" -n 2>&1
    exit "${PIPESTATUS[1]}"
  )"
  _TIRITH_SYNTAX_RC=$?
}

_TIRITH_RECEIPT_PROTOCOL=0
_TIRITH_RECEIPT_INSTANCE=""
_TIRITH_RECEIPT_SHELL_PID="$$"
_TIRITH_RECEIPT_FAMILY="bash"

# `$$` intentionally remains the top-level shell PID in Bash subshells. With
# functrace (`set -T`), however, an inherited DEBUG trap can run from a process
# whose actual PID/parent relation differs from the registered shell. Never
# make a strict receipt claim from that context.
_tirith_receipt_parent_context_is_valid() {
  [[ "${BASH_SUBSHELL:-0}" == "0" \
     && "$$" == "$_TIRITH_RECEIPT_SHELL_PID" ]]
}

_tirith_receipt_capture_file=""
if [[ $- == *i* ]]; then
  _tirith_receipt_capture_file="$(_tirith_new_capture_file 2>/dev/null)" || _tirith_receipt_capture_file=""
  if [[ -n "$_tirith_receipt_capture_file" ]] \
     && builtin command "$_TIRITH_BIN" __execution-receipt capability \
          >"$_tirith_receipt_capture_file" 2>/dev/null \
     && _tirith_read_single_capture_line "$_tirith_receipt_capture_file" \
     && [[ "$_TIRITH_CAPTURE_LINE" == "TIRITH_EXECUTION_RECEIPT_PROTOCOL=3" ]]; then
    : > "$_tirith_receipt_capture_file"
    if builtin command "$_TIRITH_BIN" __execution-receipt register \
         --family bash --shell-pid "$_TIRITH_RECEIPT_SHELL_PID" \
         >"$_tirith_receipt_capture_file" 2>/dev/null \
       && _tirith_read_single_capture_line "$_tirith_receipt_capture_file"; then
      _TIRITH_RECEIPT_INSTANCE="$_TIRITH_CAPTURE_LINE"
    fi
    if [[ "$_TIRITH_RECEIPT_INSTANCE" =~ ^[0-9a-f]{64}$ ]]; then
      _TIRITH_RECEIPT_PROTOCOL=3
    else
      _TIRITH_RECEIPT_INSTANCE=""
    fi
  fi
  [[ -n "$_tirith_receipt_capture_file" ]] \
    && _tirith_remove_capture_file "$_tirith_receipt_capture_file" >/dev/null 2>&1
fi
unset _tirith_receipt_capture_file _TIRITH_CAPTURE_LINE

# M8 ch2 — surface "this shell is on the remote side of an SSH session" to
# `tirith prompt-status` (planned for M8 ch6) and any other downstream
# consumer. Set NOW so chunk 6 can read it without a follow-up hook patch.
# Standard SSH env vars: SSH_CONNECTION, SSH_CLIENT, SSH_TTY.
if [[ -z "${TIRITH_SSH_REMOTE:-}" ]] \
   && { [[ -n "${SSH_CONNECTION:-}" ]] || [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_TTY:-}" ]]; }; then
  TIRITH_SSH_REMOTE=1
  export TIRITH_SSH_REMOTE
fi

# M9 ch4 — record a shell-start environment snapshot for `tirith env diff`.
# Exec a hidden tirith subcommand that reads ITS OWN inherited environment and
# writes ONLY variable names + an 8-char value-hash prefix (never raw values,
# never a recoverable hash) to <state-dir>/env_snapshot.json. The child
# inherits this shell's exported env, so no value crosses an argv boundary or a
# temp file. Interactive-only and backgrounded so it never blocks the prompt.
# Sourced once per session (guarded above), so this runs once per shell start.
if [[ $- == *i* ]]; then
  builtin command "$_TIRITH_BIN" env snapshot >/dev/null 2>&1 &
  disown 2>/dev/null || true
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
  printf '%q' "$1"
}

_tirith_receipt_discard() {
  local channel="$1" token="$2"
  [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 && -n "$token" ]] || return 0
  _tirith_receipt_parent_context_is_valid || return 1
  local input_fd rc
  _tirith_open_exact_input_pipe "$token" || return 1
  input_fd="$_TIRITH_OPENED_FD"
  unset _TIRITH_OPENED_FD
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    _TIRITH_BASH_INTERNAL=1 builtin command "$_TIRITH_BIN" __execution-receipt discard \
    --channel "$channel" <&"$input_fd" >/dev/null 2>&1
  rc=$?
  _tirith_close_pending_fd "$input_fd" 2>/dev/null || rc=1
  return "$rc"
}

_tirith_receipt_consume() {
  local channel="$1" token="$2" command_text="$3"
  [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 && -n "$token" && -n "$command_text" ]] || return 1
  _tirith_receipt_parent_context_is_valid || return 1
  local input_fd rc
  _tirith_open_exact_input_pipe "$token"$'\n'"$command_text" || return 1
  input_fd="$_TIRITH_OPENED_FD"
  unset _TIRITH_OPENED_FD
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    _TIRITH_BASH_INTERNAL=1 builtin command "$_TIRITH_BIN" __execution-receipt consume \
    --channel "$channel" <&"$input_fd" >/dev/null
  rc=$?
  _tirith_close_pending_fd "$input_fd" 2>/dev/null || rc=1
  return "$rc"
}

_tirith_receipt_reconcile() {
  local channel="$1" token="$2"
  [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 && -n "$token" ]] || return 1
  _tirith_receipt_parent_context_is_valid || return 1
  local input_fd rc
  _tirith_open_exact_input_pipe "$token" || return 1
  input_fd="$_TIRITH_OPENED_FD"
  unset _TIRITH_OPENED_FD
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    _TIRITH_BASH_INTERNAL=1 builtin command "$_TIRITH_BIN" __execution-receipt reconcile \
    --channel "$channel" <&"$input_fd" >/dev/null 2>&1
  rc=$?
  _tirith_close_pending_fd "$input_fd" 2>/dev/null || rc=1
  return "$rc"
}


# Parse approval temp file. On success, sets _tirith_ap_* variables.
# On failure (missing/unreadable/corrupt), returns 1 with fail-closed defaults.
_tirith_parse_approval() {
  local file="$1"
  _tirith_ap_required="no"
  _tirith_ap_timeout=0
  _tirith_ap_fallback="block"
  _tirith_ap_rule=""
  _tirith_ap_desc=""

  if [[ ! -r "$file" ]]; then
    _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
    _tirith_remove_capture_file "$file" >/dev/null 2>&1  # delete on all paths
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

  # Delete temp file after reading
  _tirith_remove_capture_file "$file" >/dev/null 2>&1

  # Corrupt file (no valid keys) → fail closed (reset all fields)
  if [[ $valid_keys -eq 0 ]]; then
    _tirith_output "tirith: warning: approval file corrupt, failing closed"
    _tirith_ap_required="yes"
    _tirith_ap_fallback="block"
    _tirith_ap_timeout=0
    return 1
  fi
  return 0
}


_tirith_parse_warn_ack() {
  local file="$1"
  _tirith_wa_findings=0
  _tirith_wa_max_severity=""

  if [[ ! -r "$file" ]]; then
    _tirith_remove_capture_file "$file" >/dev/null 2>&1
    return 1
  fi

  while IFS='=' read -r key value; do
    case "$key" in
      TIRITH_WARN_ACK_FINDINGS) _tirith_wa_findings="$value" ;;
      TIRITH_WARN_ACK_MAX_SEVERITY) _tirith_wa_max_severity="$value" ;;
    esac
  done < "$file"

  _tirith_remove_capture_file "$file" >/dev/null 2>&1
  return 0
}


# Trim whitespace to match Rust policy.rs:state_dir() behavior
_TIRITH_STATE_DIR="${XDG_STATE_HOME:-}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR#"${_TIRITH_STATE_DIR%%[![:space:]]*}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR%"${_TIRITH_STATE_DIR##*[![:space:]]}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR:-$HOME/.local/state}/tirith"
_TIRITH_SAFE_MODE_FLAG="$_TIRITH_STATE_DIR/bash-safe-mode"

_tirith_check_safe_mode() { [[ -f "$_TIRITH_SAFE_MODE_FLAG" ]]; }

_tirith_persist_safe_mode() {
  if [[ -z "$_TIRITH_MKDIR_BIN" ]] \
     || ! builtin command "$_TIRITH_MKDIR_BIN" -p -- "$_TIRITH_STATE_DIR" 2>/dev/null \
     || ! builtin printf '1\n' > "$_TIRITH_SAFE_MODE_FLAG" 2>/dev/null; then
    builtin printf '%s\n' "tirith: warning: could not persist safe-mode flag" >&2
  fi
}

# --- Enter-mode capability cache (issue #111) -------------------------------
#
# `bind -x` on Enter runs the bound function but, in many environments, does
# NOT then accept the line — bash never returns to its command loop, the
# pending command is never delivered, and it is silently eaten. Whether this
# happens is a property of the running bash/readline build, not the version
# number, so it cannot be decided by a version gate.
#
# `tirith setup` / `tirith doctor` run a PTY self-test that PROVES whether
# enter-mode delivery works, and write the verdict to a cache file. This hook
# is sourced on every interactive shell, so it must not run that probe — it
# only READS the cache (one small-file read, fast enough for startup). When the
# cache proves enter mode works for the running bash, the default mode is
# enter; otherwise the hook falls back to the safe default, preexec.
#
# Cache freshness is gated on (a) the schema number and (b) the bash identity
# (version + path). The SCHEMA is the cross-tirith-version invalidator: any
# change to the probe semantics or the cache format that could make an old
# verdict wrong must bump `cli::bash_capability::CACHE_SCHEMA`, which a stale
# cache then fails. Enter-mode delivery itself is a bash-build property — it
# does not change with the tirith version — so the cache is keyed on bash, not
# on tirith. (`tirith_version` is still recorded in the file for diagnostics.)
_TIRITH_ENTER_CAP_SCHEMA=2
_TIRITH_ENTER_CAP_FILE="$_TIRITH_STATE_DIR/bash-enter-capability"

# Read the enter-mode capability cache and decide whether enter mode is proven
# to work for THIS bash. Returns 0 only when the cache exists, parses, its
# schema matches, its recorded bash version AND bash path match the running
# shell, and the verdict is `works`. Any other state (missing, malformed,
# stale, broken) returns non-zero so the caller falls back to the safe
# default. Fails closed.
_tirith_enter_capability_proven() {
  [[ -r "$_TIRITH_ENTER_CAP_FILE" ]] || return 1

  # Guard against a junk/oversized file masquerading as the cache. `wc -c`
  # pads its count with leading whitespace on BSD/macOS, so strip everything
  # but digits before the numeric check.
  local size
  [[ -n "$_TIRITH_WC_BIN" ]] || return 1
  size="$(builtin command "$_TIRITH_WC_BIN" -c < "$_TIRITH_ENTER_CAP_FILE" 2>/dev/null)" \
    || return 1
  size="${size//[^0-9]/}"
  [[ -n "$size" ]] || return 1
  (( size > 4096 )) && return 1

  local schema="" cache_bash_version="" cache_bash_path="" capability=""
  local cache_bash_fingerprint=""
  local key value
  while IFS='=' read -r key value; do
    case "$key" in
      schema)           schema="$value" ;;
      bash_version)     cache_bash_version="$value" ;;
      bash_path)        cache_bash_path="$value" ;;
      bash_fingerprint) cache_bash_fingerprint="$value" ;;
      enter_capability) capability="$value" ;;
    esac
  done < "$_TIRITH_ENTER_CAP_FILE"

  # Schema must match exactly — a format or probe-semantics change bumps it,
  # invalidating caches written by a different tirith.
  [[ "$schema" == "$_TIRITH_ENTER_CAP_SCHEMA" ]] || return 1

  # The verdict must be an explicit `works`. `broken`, `inconclusive`, an empty
  # value, or anything unrecognised all mean "do not use enter mode".
  [[ "$capability" == "works" ]] || return 1

  # The cache is bash-version specific: readline's bind-x behaviour can change
  # across builds, so a verdict for a different bash must not be trusted.
  [[ -n "$cache_bash_version" ]] || return 1
  [[ "$cache_bash_version" == "$BASH_VERSION" ]] || return 1

  # The verdict is also bound to the bash *binary* the self-test measured — the
  # capability is a property of the build, not just the version string. The
  # cache records `command -v bash`; require the running shell ($BASH) to be
  # that same binary. A mismatch (a different bash now on PATH) is treated as
  # stale and falls back to preexec — fail-safe.
  [[ -n "$cache_bash_path" ]] || return 1
  [[ "$cache_bash_path" == "${BASH:-}" ]] || return 1

  # repo-0211: an in-place rebuild keeps path and version — also require the
  # recorded mtime:size fingerprint to match the live binary.
  [[ -n "$cache_bash_fingerprint" ]] || return 1
  local live_mtime live_size live_fp
  if live_mtime="$(builtin command stat -Lf %m "${BASH:-/dev/null}" 2>/dev/null)"; then
    :
  else
    live_mtime="$(builtin command stat -Lc %Y "${BASH:-/dev/null}" 2>/dev/null)" || return 1
  fi
  if live_size="$(builtin command stat -Lf %z "${BASH:-/dev/null}" 2>/dev/null)"; then
    :
  else
    live_size="$(builtin command stat -Lc %s "${BASH:-/dev/null}" 2>/dev/null)" || return 1
  fi
  [[ -n "$live_mtime" && -n "$live_size" ]] || return 1
  live_fp="${live_mtime}:${live_size}"
  [[ "$cache_bash_fingerprint" == "$live_fp" ]] || return 1

  return 0
}
# --- end enter-mode capability cache ----------------------------------------


# Read the most recent history entry as "<index>|<cmd>" on stdout. Returns 1
# with empty stdout when history is unavailable, disabled, or malformed.
# HISTTIMEFORMAT is neutralised with a function-local empty value so bash
# restores the user's outer setting on return.
_tirith_read_history_entry() {
  local HISTTIMEFORMAT=''
  local raw
  raw="$(builtin history 1 2>/dev/null)" || return 1
  [[ -z "$raw" ]] && return 1
  if [[ "$raw" =~ ^[[:space:]]*([0-9]+)[[:space:]]+(.*)$ ]]; then
    printf '%s|%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  return 1
}

# Collapse runs of whitespace and trim spacing around shell operators.
# Used to bridge cosmetic spacing differences (`>/dev/null` vs `> /dev/null`)
# between BASH_COMMAND and the history line in enforcement mode.
_tirith_normalize_spacing() {
  local input="$1" s="" pending_space=0 i char op
  for ((i=0; i<${#input}; i++)); do
    char="${input:i:1}"
    case "$char" in
      [[:space:]])
        [[ -n "$s" ]] && pending_space=1
        ;;
      *)
        [[ $pending_space -eq 1 ]] && s+=" "
        s+="$char"
        pending_space=0
        ;;
    esac
  done
  for op in '|' '&' ';' '>' '<'; do
    while [[ "$s" == *" $op"* ]]; do s="${s//" $op"/$op}"; done
    while [[ "$s" == *"$op "* ]]; do s="${s//"$op "/$op}"; done
  done
  printf '%s' "$s"
}

# Escape POSIX-ERE metacharacters so the result can be embedded literally into
# a bash =~ regex pattern.
_tirith_regex_escape() {
  local s="$1" out="" i c
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      '\'|'.'|'*'|'+'|'?'|'|'|'('|')'|'['|']'|'{'|'}'|'^'|'$')
        out+='\'"$c" ;;
      *)
        out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

# Return 0 when $1 (BASH_COMMAND) corresponds to one of the simple commands
# in $2 (history_line). Uses three steps:
#
#   1. Literal word-boundary match of BASH_COMMAND in history_line.
#   2. Whitespace-normalised retry (bridges `ls -l >/dev/null` vs
#      `ls -l > /dev/null`).
#   3. Command-name fallback: the first token of BASH_COMMAND (the program
#      name) must appear as a bounded token somewhere in history_line. This
#      bridges bash's internal rewriting of redirection FDs (`>&2` typed,
#      `1>&2` in BASH_COMMAND) while still catching alias expansion (the
#      alias's output command name won't appear in the typed line).
_tirith_cmd_is_in_line() {
  local needle="$1" haystack="$2"
  [[ -z "$needle" || -z "$haystack" ]] && return 1
  [[ "$haystack" == "$needle" ]] && return 0

  local esc boundary
  boundary='(^|[[:space:]|&;<>()])'
  esc="$(_tirith_regex_escape "$needle")"
  if [[ "$haystack" =~ ${boundary}${esc}([[:space:]|&\;<>()]|$) ]]; then
    return 0
  fi

  local n_needle n_haystack
  n_needle="$(_tirith_normalize_spacing "$needle")"
  n_haystack="$(_tirith_normalize_spacing "$haystack")"
  [[ "$n_haystack" == "$n_needle" ]] && return 0
  esc="$(_tirith_regex_escape "$n_needle")"
  if [[ "$n_haystack" =~ ${boundary}${esc}([[:space:]|&\;<>()]|$) ]]; then
    return 0
  fi

  local first_token="${needle%%[[:space:]]*}"
  [[ -z "$first_token" ]] && return 1
  esc="$(_tirith_regex_escape "$first_token")"
  if [[ "$haystack" =~ ${boundary}${esc}([[:space:]|&\;<>()]|$) ]]; then
    return 0
  fi
  return 1
}

# Install-time gate for preexec enforcement. Hostile history configurations
# cannot provide a trustworthy whole-line view, so the hook stays in
# warn-only rather than claim protection it cannot deliver.
_tirith_history_is_trustworthy_for_enforcement() {
  case ":${HISTCONTROL:-}:" in
    *:ignorespace:*|*:ignoredups:*|*:ignoreboth:*) return 1 ;;
  esac
  [[ -n "${HISTIGNORE:-}" ]] && return 1
  if ! shopt -oq history 2>/dev/null; then
    return 1
  fi
  return 0
}

# Enable `extdebug` if (and only if) tirith is the one turning it on. Tracks
# ownership via _TIRITH_OWNS_EXTDEBUG so we can safely clean up at shell exit;
# it is deliberately left on for the rest of the session once enabled, because
# disabling it inside the DEBUG trap would break the `return 1` skip semantic
# bash relies on.
_tirith_enable_extdebug() {
  if shopt -q extdebug; then
    return 0
  fi
  shopt -s extdebug
  _TIRITH_OWNS_EXTDEBUG=1
}

# Idempotent DEBUG-trap installer. Chains through any pre-existing user DEBUG
# trap via a trampoline so warn-only + enforcement do not clobber the user's
# own instrumentation. Second and later calls are no-ops.
#
# We capture the caller's line number (BASH_LINENO[0] here, since the
# trampoline IS the topmost function called from the trap) and pass it
# explicitly to _tirith_preexec — otherwise preexec would see only its own
# call frame's line, not the user-typed line.
_tirith_debug_trampoline() {
  local _user_line_id="${BASH_LINENO[0]:-0}"
  if [[ -n "${_TIRITH_PREV_DEBUG_TRAP:-}" ]]; then
    builtin eval -- "$_TIRITH_PREV_DEBUG_TRAP" || true
  fi
  _tirith_preexec "$_user_line_id"
}

_tirith_extract_trap_body() {
  local specification="${1:-}" signal="${2:-}"
  local prefix="trap -- '" suffix="' $signal"
  _TIRITH_EXTRACTED_TRAP=""
  [[ -n "$signal" && "$specification" == "$prefix"*"$suffix" ]] || return 1
  specification="${specification#"$prefix"}"
  specification="${specification%"$suffix"}"
  _TIRITH_EXTRACTED_TRAP="$specification"
}

_tirith_install_debug_trap() {
  local current
  current="$(builtin trap -p DEBUG 2>/dev/null)"
  [[ "$current" == *"_tirith_debug_trampoline"* ]] && return 0

  _TIRITH_PREV_DEBUG_TRAP=""
  if _tirith_extract_trap_body "$current" DEBUG; then
    _TIRITH_PREV_DEBUG_TRAP="$_TIRITH_EXTRACTED_TRAP"
  fi
  builtin trap '_tirith_debug_trampoline' DEBUG
}

# --- Protection-status indicator + one-shot degrade banner -----------------
#
# `TIRITH_STATUS` is a small public contract a user can reference in their PS1
# to surface tirith's live protection level in their prompt. tirith itself
# prints NOTHING per-prompt — it only sets the variable; wiring it into a
# prompt is opt-in (see docs/prompt-status.md). Values:
#   blocks     enter mode (or enforced preexec) — a blocked command is stopped
#   warn-only  preexec warn-only — commands are observed but not blocked
#   degraded   protection was DOWNGRADED mid-session from a stronger level
#   off        the hook installed nothing
#
# `degraded` is deliberately distinct from `warn-only`: a shell that simply
# *starts* in preexec warn-only is `warn-only`, but a shell that *loses* a
# stronger guarantee at runtime is `degraded` — a state the user should notice.
#
# It is a plain shell variable, deliberately NOT exported: the prompt runs in
# THIS interactive shell, which reads a non-exported variable fine (PS1 /
# PROMPT_COMMAND), and a non-interactive child process has no tirith
# protection — so it must not inherit a status that would misrepresent it.
# (`TIRITH_BASH_EFFECTIVE_*` below are exported on purpose: `tirith doctor` is
# a child process and can only see exported vars.) An assignment inside a
# function with no matching `local` writes the global, so this is the shell's
# session-global `TIRITH_STATUS`.
_tirith_set_status() {
  TIRITH_STATUS="$1"
}

# Emit the one-time degraded-protection warning. Fires at most once per shell
# session (guarded by `_TIRITH_DEGRADE_WARNED`), is interactive-only, and is
# deliberately terse — a single consolidated message, never naggy. The optional
# `$1` is an extra detail line appended under the headline.
_tirith_warn_degraded_once() {
  [[ -n "${_TIRITH_DEGRADE_WARNED:-}" ]] && return 0
  _TIRITH_DEGRADE_WARNED=1
  [[ $- == *i* ]] || return 0
  _tirith_output "tirith: protection downgraded to warn-only (does not block) — run 'tirith doctor' for details"
  [[ -n "${1:-}" ]] && _tirith_output "  $1"
  return 0
}

# Cache-then-degrade: flip the session to warn-only mode and re-export the
# effective protection string so a subsequent `tirith doctor` sees the truth.
# Callers that already know a history index should pin the cache BEFORE
# invoking this helper so the current line's remaining DEBUG fires stay
# blocked (extdebug stays on for the life of the session).
_tirith_session_degrade_to_warn_only() {
  local reason="$1"
  _TIRITH_PREEXEC_ENFORCE=0
  _TIRITH_WARN_ONLY_USE_BASH_COMMAND=1
  _TIRITH_PREEXEC_WARNED=1   # suppress the generic warn-only banner
  export TIRITH_BASH_EFFECTIVE_PROTECTION="warn-only"
  _tirith_set_status "degraded"
  # One consolidated headline, then the path-specific reason as the detail line.
  _tirith_warn_degraded_once "$reason"
}

_tirith_preexec_receipt_check() {
  local scan_target="$1" warn_only="$2"
  _tirith_receipt_parent_context_is_valid || return 1
  local -a render_args
  render_args=()
  [[ "$warn_only" == "yes" ]] && render_args=(--warn-only)
  local stdout_file rc
  stdout_file="$(_tirith_new_capture_file 2>/dev/null)" || return 1
  [[ -n "$stdout_file" ]] || return 1
  _TIRITH_HOOK=1 _TIRITH_BASH_INTERNAL=1 \
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    builtin command "$_TIRITH_BIN" check --approval-check --execution-receipt bash-preexec \
    --non-interactive --interactive --shell posix "${render_args[@]}" -- "$scan_target" \
    >"$stdout_file"
  rc=$?

  local parse_rc token
  _tirith_parse_v3_receipt_response "$stdout_file" "$rc"
  parse_rc=$?
  token="$_TIRITH_PARSED_RECEIPT"
  _tirith_remove_capture_file "$stdout_file" >/dev/null 2>&1 || parse_rc=2
  unset _TIRITH_CAPTURE_LINE _TIRITH_PARSED_RECEIPT
  case "$parse_rc" in
    0) ;;
    1) return 1 ;;
    *)
      _tirith_receipt_discard bash-preexec "$token"
      return 1
      ;;
  esac
  if ! _tirith_receipt_consume bash-preexec "$token" "$scan_target"; then
    _tirith_receipt_reconcile bash-preexec "$token" || return 1
  fi
  return 0
}


_tirith_preexec() {
  [[ "${_TIRITH_BASH_INTERNAL:-0}" == "1" ]] && return 0

  # Once-per-shell warn-only banner for interactive preexec users.
  if [[ -z "${_TIRITH_PREEXEC_WARNED:-}" ]] \
     && [[ $- == *i* ]] \
     && [[ "${_TIRITH_PREEXEC_ENFORCE:-0}" != "1" ]]; then
    _TIRITH_PREEXEC_WARNED=1
    _tirith_output "tirith: bash is in preexec mode (warn-only, does not block)"
    _tirith_output "  Run 'tirith doctor' to test enter mode (blocking) for this shell"
  fi

  local bash_cmd="$BASH_COMMAND"
  local entry history_index="" history_line=""
  if entry="$(_tirith_read_history_entry)"; then
    history_index="${entry%%|*}"
    history_line="${entry#*|}"
  fi

  # Per-typed-line cache key. The trampoline captures the caller's line
  # number (BASH_LINENO[0] from its own frame) and passes it as $1; that
  # value advances on each prompt-boundary even when the user's
  # HISTCONTROL/HISTIGNORE settings make `history 1` skip entries, so it
  # identifies "same typed line" reliably even in filtered shells. All
  # simple commands of one typed line (`a; b`, `a | b`, `a && b`) share
  # the same value. Fall back to the topmost BASH_LINENO frame for the
  # rare case preexec is invoked directly without going through the
  # trampoline.
  local line_id="${1:-${BASH_LINENO[${#BASH_LINENO[@]}-1]:-0}}"

  local _tirith_prev_internal="${_TIRITH_BASH_INTERNAL:-0}"
  local rc

  if [[ "${_TIRITH_PREEXEC_ENFORCE:-0}" == "1" ]]; then
    # Helper failed (no history entry available): cannot enforce whole-line
    # semantics, so block the current DEBUG fire and downgrade the session.
    if [[ -z "$history_index" ]]; then
      _tirith_session_degrade_to_warn_only \
        "tirith: bash history is unavailable in this shell (history disabled or buffer empty), cannot enforce whole-line semantics; falling back to warn-only. For guaranteed blocking, use enter mode (export TIRITH_BASH_MODE=enter)."
      return 1
    fi

    # Drift check FIRST. Critical: a stale history index (e.g. when a
    # filtered command leaves history_index unchanged from a prior allow)
    # MUST NOT short-circuit to the cache before we re-validate that the
    # current BASH_COMMAND still belongs to the typed line. Otherwise an
    # attacker can flip on `HISTCONTROL=ignorespace` mid-session and reuse
    # an earlier allow verdict for a brand-new blocked command.
    if ! _tirith_cmd_is_in_line "$bash_cmd" "$history_line"; then
      _tirith_last_key="$line_id"
      _tirith_last_rc=1
      _tirith_session_degrade_to_warn_only \
        "tirith: bash history no longer matches BASH_COMMAND (likely HISTCONTROL/HISTIGNORE filtering, an alias, or a shell transformation outside the whole-line drift check); cannot enforce whole-line semantics; falling back to warn-only. For guaranteed blocking, use enter mode (export TIRITH_BASH_MODE=enter)."
      return 1
    fi

    # Cache hit on the current typed line (drift just validated).
    if [[ "${_tirith_last_key:-}" == "$line_id" ]]; then
      return "${_tirith_last_rc:-0}"
    fi

    # Cache miss: fresh whole-line scan.
    _TIRITH_BASH_INTERNAL=1
    if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
      _tirith_preexec_receipt_check "$history_line" no
      rc=$?
    else
      _TIRITH_HOOK=1 builtin command "$_TIRITH_BIN" check --shell posix -- "$history_line"
      rc=$?
    fi
    _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"

    case "$rc" in
      0|2)
        _tirith_last_key="$line_id"
        _tirith_last_rc=0
        return 0
        ;;
      1)
        _tirith_last_key="$line_id"
        _tirith_last_rc=1
        return 1
        ;;
      *)
        _tirith_last_key="$line_id"
        _tirith_last_rc=1
        _tirith_session_degrade_to_warn_only \
          "tirith: preexec enforcement failed unexpectedly (exit $rc), blocking this command and disabling enforcement for this shell"
        return 1
        ;;
    esac
  fi

  # Cross-path pinned-block carryover: a prior degrade may have written
  # (_tirith_last_key=$line_id, _tirith_last_rc=1) so the rest of the same
  # typed line continues to be skipped by extdebug. Keying on LINENO means
  # a later prompt cannot inherit the block — even in shells where history
  # filtering keeps history_index pinned across prompts.
  if [[ "${_tirith_last_key:-}" == "$line_id" ]] \
     && [[ "${_tirith_last_rc:-}" == "1" ]]; then
    return 1
  fi

  # When the session has been degraded (install-time hostile-config or
  # runtime drift), history_line can no longer be trusted to correspond to
  # the current simple command, so scan BASH_COMMAND instead. Otherwise
  # prefer history_line so composite rules (pipe-to-interpreter, etc.) fire
  # on the full typed line.
  local scan_target
  if [[ "${_TIRITH_WARN_ONLY_USE_BASH_COMMAND:-0}" == "1" ]]; then
    scan_target="$bash_cmd"
  elif [[ -n "$history_line" ]]; then
    scan_target="$history_line"
  else
    scan_target="$bash_cmd"
  fi

  # Within-line dedupe: skip when this exact scan target was already sent
  # to tirith on the SAME typed line (DEBUG can fire multiple times for one
  # simple command via subshell expansion). Combine the per-line id with
  # the scan target so identical commands on separate prompts each get a
  # fresh DETECTED banner — the prompt boundary advances line_id and
  # naturally invalidates the dedupe.
  local dedupe_key="${line_id}|${scan_target}"
  [[ "${_tirith_last_cmd:-}" == "$dedupe_key" ]] && return 0
  _tirith_last_cmd="$dedupe_key"

  _TIRITH_BASH_INTERNAL=1
  if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
    if _tirith_receipt_parent_context_is_valid; then
      _tirith_preexec_receipt_check "$scan_target" yes || true
    else
      # A functrace-inherited DEBUG trap may run in a Bash subshell where `$$`
      # still names the registered top-level shell. Do not make a false strict
      # receipt claim there; retain the mode's honest warn-only scan instead.
      _TIRITH_HOOK=1 builtin command "$_TIRITH_BIN" check --shell posix --warn-only -- "$scan_target" || true
    fi
  else
    _TIRITH_HOOK=1 builtin command "$_TIRITH_BIN" check --shell posix --warn-only -- "$scan_target" || true
  fi
  _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"
  return 0
}


_tirith_degrade_to_preexec() {
  local reason="${1:-unknown}"

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

  _tirith_install_debug_trap
  _TIRITH_BASH_MODE="preexec"
  _tirith_persist_safe_mode
  if [[ $- == *i* ]]; then
    # Re-export the effective-state contract so a child `tirith doctor` sees the
    # post-degrade truth, not the stale enter/blocks values exported at startup.
    # Hardcoded warn-only: a shell that degrades out of enter mode never had
    # preexec enforcement enabled (enforcement is evaluated only at startup for
    # shells that START in preexec).
    export TIRITH_BASH_EFFECTIVE_MODE="preexec"
    export TIRITH_BASH_EFFECTIVE_PROTECTION="warn-only"
    _tirith_set_status "degraded"
  fi
  # One consolidated, one-shot degraded-protection banner — same wording as
  # every other degrade path. The enter-mode specifics (what failed, how to
  # re-enable) go on the detail line so the message stays a single clear shape.
  _tirith_warn_degraded_once \
    "enter mode failed ($reason); now warn-only. Persistent — restart your shell, or re-enable with TIRITH_BASH_MODE=enter."
}


_tirith_prompt_hook() {
  local pending_eval="${_TIRITH_PENDING_EVAL:-}"
  local pending_receipt="${_TIRITH_PENDING_RECEIPT:-}"
  local pending_command="${_TIRITH_PENDING_COMMAND:-}"
  unset _TIRITH_PENDING_EVAL
  unset _TIRITH_PENDING_RECEIPT _TIRITH_PENDING_COMMAND

  if [[ -n "$pending_receipt" ]]; then
    if [[ $_TIRITH_RECEIPT_PROTOCOL -ne 3 \
          || -z "$pending_eval" \
          || -z "$pending_command" \
          || "$pending_eval" != "$pending_command" ]]; then
      _tirith_receipt_discard bash-enter "$pending_receipt" || true
      _tirith_degrade_to_preexec "deferred command state did not match its receipt"
      return 1
    fi
    if ! _tirith_receipt_consume bash-enter "$pending_receipt" "$pending_command"; then
      if ! _tirith_receipt_reconcile bash-enter "$pending_receipt"; then
        _tirith_degrade_to_preexec "execution receipt could not be committed before delivery"
        return 1
      fi
    fi
  elif [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 \
          && ( -n "$pending_eval" || -n "$pending_command" ) ]]; then
    _tirith_degrade_to_preexec "deferred command state lacks its receipt commit marker"
    return 1
  fi

  if [[ -n "$pending_eval" ]]; then
    builtin eval -- "$pending_eval"
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


if [[ -n "${TIRITH_BASH_MODE:-}" ]]; then
  # Explicit user override always wins. A user who exports TIRITH_BASH_MODE has
  # made a deliberate choice; if they force `enter` in an environment where
  # delivery is broken, the startup health gate and the pending-not-consumed
  # detection still degrade visibly (contract invariant f) — never silently.
  _TIRITH_BASH_MODE="$TIRITH_BASH_MODE"
elif _tirith_check_safe_mode; then
  _TIRITH_BASH_MODE="preexec"
  # Only print warning in interactive shells (avoid polluting scripted output)
  [[ $- == *i* ]] && _tirith_output "tirith: safe mode active (preexec) — previous enter-mode failure detected"
  [[ $- == *i* ]] && _tirith_output "  Re-enable: TIRITH_BASH_MODE=enter or tirith doctor --reset-bash-safe-mode"
elif [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" || -n "${SSH_CLIENT:-}" ]]; then
  # SSH PTY environments are more reliable with DEBUG-trap preexec mode.
  _TIRITH_BASH_MODE="preexec"
elif _tirith_enter_capability_proven; then
  # Default path: enter mode is used only when the capability self-test (run by
  # `tirith setup` / `tirith doctor`) has PROVEN, for this exact bash, that
  # enter-mode delivery works and blocking works. See issue #111.
  _TIRITH_BASH_MODE="enter"
else
  # No proof that enter mode works here (cache missing, stale, or recorded a
  # failure). Fall back to the safe default rather than risk silently eating a
  # command. `tirith doctor` (or `tirith doctor --simulate-enter`) runs the
  # self-test and, when enter mode works, enables it for subsequent shells.
  _TIRITH_BASH_MODE="preexec"
fi

#
# Doctor is a child process and cannot read shell-local `_TIRITH_*` variables,
# so the hook exports a small public contract: `TIRITH_BASH_EFFECTIVE_MODE` and
# `TIRITH_BASH_EFFECTIVE_PROTECTION`. These are re-exported on every state
# change (degrade, enforcement flip) so a subsequent `tirith doctor` invocation
# in the same shell sees truthful live state. Only exported in interactive
# shells where the hook actually installs interception; non-interactive
# sourcing is a no-op and must not leak status vars into child processes.
if [[ $- == *i* ]]; then
  export TIRITH_BASH_EFFECTIVE_MODE="$_TIRITH_BASH_MODE"
  if [[ "$_TIRITH_BASH_MODE" == "enter" ]]; then
    export TIRITH_BASH_EFFECTIVE_PROTECTION="blocks"
    # TIRITH_STATUS: opt-in prompt indicator (see docs/prompt-status.md), a
    # non-exported shell variable. enter mode blocks; preexec without
    # enforcement is warn-only. A later enforcement flip or a runtime degrade
    # updates this in place.
    _tirith_set_status "blocks"
  else
    export TIRITH_BASH_EFFECTIVE_PROTECTION="warn-only"
    _tirith_set_status "warn-only"
  fi
fi

#
# Users who set TIRITH_BASH_PREEXEC_ENFORCE to a truthy value get real
# blocking in preexec mode via `shopt -s extdebug` + `return 1` from the
# DEBUG trap. Enforcement requires a trustworthy whole-line view, so hostile
# history configs are rejected at install time: HISTCONTROL containing
# ignorespace/ignoredups/ignoreboth, any HISTIGNORE, or `set +o history`
# downgrade the session to warn-only with a pointer at enter mode.
_TIRITH_PREEXEC_ENFORCE=0
_TIRITH_OWNS_EXTDEBUG=0
_TIRITH_WARN_ONLY_USE_BASH_COMMAND=0

_tirith_env_is_truthy() {
  case "${1:-}" in
    1|true|TRUE|True|yes|YES|Yes|on|ON|On) return 0 ;;
  esac
  return 1
}

if [[ "$_TIRITH_BASH_MODE" == "preexec" ]] \
   && [[ $- == *i* ]] \
   && _tirith_env_is_truthy "${TIRITH_BASH_PREEXEC_ENFORCE:-}"; then
  if _tirith_history_is_trustworthy_for_enforcement; then
    _TIRITH_PREEXEC_ENFORCE=1
    _tirith_enable_extdebug
    export TIRITH_BASH_EFFECTIVE_PROTECTION="blocks"
    # Enforcement engaged: preexec now blocks, so the prompt indicator is
    # `blocks`, not the `warn-only` exported by the startup block above.
    _tirith_set_status "blocks"
  else
    # Same hostile-history check that triggers a runtime drift downgrade —
    # so the warn-only scan target must also flip to BASH_COMMAND, not the
    # untrustworthy history_line. Without this the warn-only path would
    # produce stale DETECTED banners scanned against whatever entry
    # `history 1` happens to surface.
    _TIRITH_WARN_ONLY_USE_BASH_COMMAND=1
    # The user asked for blocking (TIRITH_BASH_PREEXEC_ENFORCE) but a hostile
    # history config prevents it — that is a downgrade from the requested
    # protection level, so the prompt indicator is `degraded`. Routed through
    # the one-shot banner so the headline matches every other degrade path.
    _tirith_set_status "degraded"
    _tirith_warn_degraded_once \
      "preexec enforcement could not engage (HISTCONTROL/HISTIGNORE or disabled history prevents a trustworthy whole-line view). For guaranteed blocking, use enter mode (export TIRITH_BASH_MODE=enter)."
  fi
fi

# New hooks can keep running their legacy decision checks against an older
# binary, but without the one-shot receipt protocol they cannot prove that a
# permitted command reached the shell boundary. Surface that evidence loss
# explicitly without overwriting the live interception contract above:
# blocking/warn-only protection and durable execution evidence are separate
# claims.
if [[ $- == *i* ]] && [[ $_TIRITH_RECEIPT_PROTOCOL -ne 3 ]]; then
  if [[ -z "${_TIRITH_RECEIPT_DEGRADE_WARNED:-}" ]]; then
    _TIRITH_RECEIPT_DEGRADE_WARNED=1
    _tirith_output "tirith: execution receipts unavailable; legacy checks remain active but session execution evidence is degraded"
  fi
fi


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
      if [[ -n "$_TIRITH_STTY_BIN" ]]; then
        _saved_stty="$(builtin command "$_TIRITH_STTY_BIN" -g 2>/dev/null)" || _saved_stty=""
      fi

      # Ensure terminal state is restored on exit
      builtin trap '_tirith_restore_terminal_state "$_saved_stty"' RETURN

      # Self-heal: verify prompt hook is still attached
      if ! _tirith_ensure_prompt_hook; then
        _tirith_degrade_to_preexec "PROMPT_COMMAND reattachment failed"
        return  # READLINE_LINE stays intact
      fi

      # Detect broken delivery: if previous pending was never consumed
      if [[ -n "${_TIRITH_PENDING_EVAL:-}" \
            || -n "${_TIRITH_PENDING_COMMAND:-}" \
            || -n "${_TIRITH_PENDING_RECEIPT:-}" ]]; then
        _tirith_receipt_discard bash-enter "${_TIRITH_PENDING_RECEIPT:-}"
        unset _TIRITH_PENDING_EVAL
        unset _TIRITH_PENDING_RECEIPT _TIRITH_PENDING_COMMAND
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
      local syntax_err syntax_rc
      _tirith_check_command_syntax "$READLINE_LINE"
      syntax_err="$_TIRITH_SYNTAX_ERROR"
      syntax_rc="$_TIRITH_SYNTAX_RC"
      unset _TIRITH_SYNTAX_ERROR _TIRITH_SYNTAX_RC
      if [[ $syntax_rc -ne 0 ]] && [[ "$syntax_err" == *"unexpected EOF"* || "$syntax_err" == *"unexpected end of file"* ]]; then
        # Incomplete input: insert newline for continued editing
        READLINE_LINE+=$'\n'
        READLINE_POINT=${#READLINE_LINE}
        return
      fi

      # Run Tirith directly from this long-lived shell. Capturing the receipt in
      # `$(...)` would make Tirith a child of a Bash 3.2 helper subshell and break
      # protocol-v3 parent-PID validation.
      local errfile stdout_file rc
      errfile="$(_tirith_new_capture_file 2>/dev/null)" || errfile=""
      stdout_file="$(_tirith_new_capture_file 2>/dev/null)" || stdout_file=""
      if [[ -z "$errfile" || -z "$stdout_file" ]]; then
        [[ -n "$errfile" ]] && _tirith_remove_capture_file "$errfile" >/dev/null 2>&1
        [[ -n "$stdout_file" ]] && _tirith_remove_capture_file "$stdout_file" >/dev/null 2>&1
        _tirith_degrade_to_preexec "could not create private receipt capture files"
        return
      fi
      local approval_path="" warn_ack_path="" receipt_token=""
      local _tirith_prev_internal="${_TIRITH_BASH_INTERNAL:-0}"
      _TIRITH_BASH_INTERNAL=1
      local -a receipt_args
      receipt_args=()
      [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]] && receipt_args=(--execution-receipt bash-enter)
      _TIRITH_HOOK=1 _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
        _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
        _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
        builtin command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell posix \
        "${receipt_args[@]}" -- "$READLINE_LINE" >"$stdout_file" 2>"$errfile"
      rc=$?
      _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"
      local output
      output=$(<"$errfile")
      _tirith_remove_capture_file "$errfile" >/dev/null 2>&1

      local receipt_lines=0 path_lines=0 malformed_stdout=0 line
      if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
        local protocol_parse_rc
        _tirith_parse_v3_receipt_response "$stdout_file" "$rc"
        protocol_parse_rc=$?
        receipt_token="$_TIRITH_PARSED_RECEIPT"
        _tirith_remove_capture_file "$stdout_file" >/dev/null 2>&1 || protocol_parse_rc=2
        unset _TIRITH_CAPTURE_LINE _TIRITH_PARSED_RECEIPT
        case "$protocol_parse_rc" in
          0)
            if [[ $rc -eq 2 ]]; then
              local escaped_line
              escaped_line=$(_tirith_escape_preview "$READLINE_LINE")
              _tirith_output ""
              _tirith_output "command> $escaped_line"
              [[ -n "$output" ]] && _tirith_output "$output"
            fi
            ;;
          1)
            local escaped_line
            escaped_line=$(_tirith_escape_preview "$READLINE_LINE")
            _tirith_output ""
            _tirith_output "command> $escaped_line"
            [[ -n "$output" ]] && _tirith_output "$output"
            READLINE_LINE=""
            READLINE_POINT=0
            return
            ;;
          *)
            local escaped_line
            escaped_line=$(_tirith_escape_preview "$READLINE_LINE")
            _tirith_output ""
            _tirith_output "command> $escaped_line"
            [[ -n "$output" ]] && _tirith_output "$output"
            _tirith_receipt_discard bash-enter "$receipt_token"
            _tirith_degrade_to_preexec "invalid protocol-v3 execution-receipt response (exit $rc)"
            return
            ;;
        esac
      else
        while IFS= read -r line || [[ -n "$line" ]]; do
          if [[ "$line" == TIRITH_EXECUTION_RECEIPT=* ]]; then
            receipt_lines=$((receipt_lines + 1))
            receipt_token="${line#TIRITH_EXECUTION_RECEIPT=}"
          elif [[ -n "$line" ]]; then
            path_lines=$((path_lines + 1))
            if [[ $path_lines -eq 1 ]]; then
              approval_path="$line"
            elif [[ $path_lines -eq 2 && $rc -eq 3 ]]; then
              warn_ack_path="$line"
            else
              malformed_stdout=1
            fi
          fi
        done < "$stdout_file"
        _tirith_remove_capture_file "$stdout_file" >/dev/null 2>&1 || malformed_stdout=1
        if [[ $malformed_stdout -ne 0 ]]; then
          [[ -n "$approval_path" ]] && _tirith_remove_capture_file "$approval_path" >/dev/null 2>&1
          [[ -n "$warn_ack_path" ]] && _tirith_remove_capture_file "$warn_ack_path" >/dev/null 2>&1
          _tirith_degrade_to_preexec "invalid legacy check response"
          return
        fi
      fi
      local approval_outcome="" warn_acknowledged="no"

      # Protocol v3 has already finalized approvals/warn acknowledgement and
      # returned an armed token. Only an unnegotiated legacy binary may enter
      # the temp-path parsing and prompt workflow below.
      if [[ $_TIRITH_RECEIPT_PROTOCOL -ne 3 ]]; then
        if [[ $rc -eq 0 ]]; then
          :  # Allow: no output
        elif [[ $rc -eq 2 || $rc -eq 3 ]]; then
          local escaped_line
          escaped_line=$(_tirith_escape_preview "$READLINE_LINE")
          _tirith_output ""
          _tirith_output "command> $escaped_line"
          [[ -n "$output" ]] && _tirith_output "$output"
        elif [[ $rc -eq 1 ]]; then
          local escaped_line
          escaped_line=$(_tirith_escape_preview "$READLINE_LINE")
          _tirith_output ""
          _tirith_output "command> $escaped_line"
          [[ -n "$output" ]] && _tirith_output "$output"
        else
          # Unexpected exit code: degrade to preexec
          local escaped_line
          escaped_line=$(_tirith_escape_preview "$READLINE_LINE")
          _tirith_output ""
          _tirith_output "command> $escaped_line"
          [[ -n "$output" ]] && _tirith_output "$output"
          [[ -n "$approval_path" ]] && _tirith_remove_capture_file "$approval_path" >/dev/null 2>&1
          [[ -n "$warn_ack_path" ]] && _tirith_remove_capture_file "$warn_ack_path" >/dev/null 2>&1
          _tirith_receipt_discard bash-enter "$receipt_token"
          _tirith_degrade_to_preexec "tirith returned unexpected exit code $rc"
          return  # READLINE_LINE preserved for re-execution via preexec
        fi

        # Approval workflow: runs for ALL exit codes (0, 1, 2, 3).
        # For rc=1 (block), approval gives user a chance to override.
        if [[ -n "$approval_path" ]]; then
          _tirith_parse_approval "$approval_path"
          if [[ "$_tirith_ap_required" == "yes" ]]; then
            _tirith_output "tirith: approval required for $_tirith_ap_rule"
            [[ -n "$_tirith_ap_desc" ]] && _tirith_output "  $_tirith_ap_desc"
            local response=""
            local approval_read_rc=0
            if [[ "$_tirith_ap_timeout" -gt 0 ]]; then
              read -t "$_tirith_ap_timeout" -p "Approve? (${_tirith_ap_timeout}s timeout) [y/N] " response </dev/tty 2>/dev/null || approval_read_rc=$?
            else
              read -p "Approve? [y/N] " response </dev/tty 2>/dev/null || approval_read_rc=$?
            fi
            if [[ "$response" == [yY]* ]]; then
              approval_outcome="granted"
            else
              if [[ "$_tirith_ap_timeout" -gt 0 && $approval_read_rc -ne 0 ]]; then
                approval_outcome="timed-out"
              else
                approval_outcome="rejected"
              fi
              case "$_tirith_ap_fallback" in
                allow)
                  _tirith_output "tirith: approval not granted — fallback: allow"
                  ;;
                warn)
                  _tirith_output "tirith: approval not granted — fallback: warn"
                  ;;
                *)
                  _tirith_output "tirith: approval not granted — fallback: block"
                  [[ -n "$warn_ack_path" ]] && _tirith_remove_capture_file "$warn_ack_path" >/dev/null 2>&1
                  _tirith_receipt_discard bash-enter "$receipt_token"
                  READLINE_LINE=""
                  READLINE_POINT=0
                  return
                  ;;
              esac
            fi
          elif [[ $rc -eq 1 ]]; then
            # Approval not required but command was blocked: honor block
            [[ -n "$warn_ack_path" ]] && _tirith_remove_capture_file "$warn_ack_path" >/dev/null 2>&1
            _tirith_receipt_discard bash-enter "$receipt_token"
            READLINE_LINE=""
            READLINE_POINT=0
            return
          fi
        elif [[ $rc -eq 1 ]]; then
          # No approval file: honor block
          _tirith_receipt_discard bash-enter "$receipt_token"
          READLINE_LINE=""
          READLINE_POINT=0
          return
        fi

        # Warn-ack workflow (exit code 3): strict_warn requires explicit acknowledgement
        if [[ $rc -eq 3 && -n "$warn_ack_path" ]]; then
          if ! _tirith_parse_warn_ack "$warn_ack_path"; then
            _tirith_receipt_discard bash-enter "$receipt_token"
            _tirith_output "tirith: warning acknowledgement metadata is invalid; command blocked"
            READLINE_LINE=""
            READLINE_POINT=0
            return
          fi
          local response=""
          read -p "tirith: proceed with ${_tirith_wa_findings} warning(s)? [y/N] " response </dev/tty 2>/dev/null
          if [[ "$response" == [yY]* ]]; then
            warn_acknowledged="yes"
          else
            _tirith_output "tirith: warnings not acknowledged — command blocked"
            _tirith_receipt_discard bash-enter "$receipt_token"
            READLINE_LINE=""
            READLINE_POINT=0
            return
          fi
        elif [[ -n "$warn_ack_path" ]]; then
          _tirith_remove_capture_file "$warn_ack_path" >/dev/null 2>&1
        fi
      fi

      # Execute the command (approval workflow above handled block cases)
      local cmd="$READLINE_LINE"
      READLINE_LINE=""
      READLINE_POINT=0
      # The full buffer already passed Bash's syntax check above. Passing it as
      # one quoted argument to the builtin preserves multiline/heredoc/compound
      # syntax without a source file, process-substitution race, or disk copy.
      if _tirith_unsafe_to_eval "$cmd"; then
        history -s -- "$cmd"
        _TIRITH_PENDING_EVAL="$cmd"
        _TIRITH_PENDING_COMMAND="$cmd"
        # Commit marker: publish only after both command copies are complete.
        if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
          _TIRITH_PENDING_RECEIPT="$receipt_token"
        fi
        return 0
      fi

      history -s -- "$cmd"
      _TIRITH_PENDING_EVAL="$cmd"
      _TIRITH_PENDING_COMMAND="$cmd"
      # Commit marker: publish only after both command copies are complete.
      if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
        _TIRITH_PENDING_RECEIPT="$receipt_token"
      fi
      return 0
    }

    # Bracketed paste interception
    _tirith_paste() {
      # Save terminal state — bind -x can corrupt echo in some PTY environments (gcloud ssh, etc.)
      local _saved_stty
      if [[ -n "$_TIRITH_STTY_BIN" ]]; then
        _saved_stty="$(builtin command "$_TIRITH_STTY_BIN" -g 2>/dev/null)" || _saved_stty=""
      fi
      builtin trap '_tirith_restore_terminal_state "$_saved_stty"' RETURN

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
        local tmpfile
        tmpfile="$(_tirith_new_capture_file 2>/dev/null)" || {
          _tirith_output "tirith: paste check failed (could not create private output capture)"
          return
        }
        local _tirith_prev_internal="${_TIRITH_BASH_INTERNAL:-0}"
        _TIRITH_BASH_INTERNAL=1
        printf '%s' "$pasted" | builtin command "$_TIRITH_BIN" paste --shell posix --interactive >"$tmpfile" 2>&1
        local rc=$?
        _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"
        local output=$(<"$tmpfile")
        _tirith_remove_capture_file "$tmpfile" >/dev/null 2>&1

        if [[ $rc -eq 0 ]]; then
          # Allow: fall through to insert
          :
        elif [[ $rc -eq 2 ]]; then
          # Warn: show warning, fall through to insert
          [[ -n "$output" ]] && { _tirith_output ""; _tirith_output "$output"; }
        else
          # Block (rc=1) or unexpected: discard paste (safe — user can re-paste)
          local escaped_paste
          escaped_paste=$(_tirith_escape_preview "$pasted")
          _tirith_output ""
          _tirith_output "paste> $escaped_paste"
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

fi

# Exit summary: show session warnings on shell exit
_tirith_exit_summary() {
  local pending_receipt="${_TIRITH_PENDING_RECEIPT:-}"
  unset _TIRITH_PENDING_EVAL
  unset _TIRITH_PENDING_RECEIPT _TIRITH_PENDING_COMMAND
  [[ -n "$pending_receipt" ]] && _tirith_receipt_discard bash-enter "$pending_receipt"
  [[ -n "${TIRITH_SESSION_ID:-}" ]] || return
  local _sd="${XDG_STATE_HOME:-$HOME/.local/state}/tirith"
  [[ -f "$_sd/sessions/$TIRITH_SESSION_ID.json" ]] || return
  builtin command "$_TIRITH_BIN" warnings --summary
}

_tirith_exit_trampoline() {
  if [[ -n "${_TIRITH_PREV_EXIT_TRAP:-}" ]]; then
    builtin eval -- "$_TIRITH_PREV_EXIT_TRAP" || true
  fi
  _tirith_exit_summary
}

_tirith_prev_exit_spec="$(builtin trap -p EXIT 2>/dev/null)"
_TIRITH_PREV_EXIT_TRAP=""
if _tirith_extract_trap_body "$_tirith_prev_exit_spec" EXIT; then
  _TIRITH_PREV_EXIT_TRAP="$_TIRITH_EXTRACTED_TRAP"
fi
if [[ -n "$_TIRITH_PREV_EXIT_TRAP" ]]; then
  builtin trap '_tirith_exit_trampoline' EXIT
else
  builtin trap '_tirith_exit_summary' EXIT
fi
unset _tirith_prev_exit_spec _TIRITH_EXTRACTED_TRAP

# Install the DEBUG trap as the absolute last step so no more internal hook
# code fires it during sourcing. The enter-mode path installs its own bind-x
# earlier; the degrade path installs DEBUG on demand inside
# `_tirith_degrade_to_preexec`.
if [[ "$_TIRITH_BASH_MODE" == "preexec" ]] && [[ $- == *i* ]]; then
  _tirith_install_debug_trap
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
