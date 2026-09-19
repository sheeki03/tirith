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
# A source-level always scope restores the caller option on early return and
# interrupt as well as success. Explicit public exports remain intentional.
builtin unset _TIRITH_INIT_ALLEXPORT
_TIRITH_INIT_ALLEXPORT="${options[allexport]}"
{
builtin unsetopt allexport
builtin typeset +x _TIRITH_INIT_ALLEXPORT
_TIRITH_ZSH_LOADED=1

# A fresh load must not retain an inherited or failed integration label.
unset TIRITH_INTEGRATION_VERSION TIRITH_INTEGRATION_SHELL

# Each freshly loaded shell owns its session. Inherited IDs from a parent
# shell or terminal multiplexer must not join independent receipt ledgers.
# The double-source guard above preserves this ID in the same live shell;
# ordinary child commands still inherit it for that shell's correlation.
builtin printf -v TIRITH_SESSION_ID '%x-%x-%x-%x' \
  "$$" "${SECONDS:-0}" "${RANDOM:-0}" "${RANDOM:-0}"
export TIRITH_SESSION_ID
# Pin the executable before any repository command can mutate PATH. All hook
# callbacks use this absolute path for the lifetime of the shell session.
if [[ "$#" -eq 2 && "$1" == "--tirith-executable" ]]; then
  # Bind native CLI source arguments from `tirith init`, bypassing launchers
  # that would otherwise break the direct-parent receipt registration.
  _TIRITH_BIN="$2"
  [[ "$_TIRITH_BIN" == /* && -f "$_TIRITH_BIN" && -x "$_TIRITH_BIN" ]] || _TIRITH_BIN=""
else
  _TIRITH_BIN="${commands[tirith]:-}"
fi
if [[ -n "$_TIRITH_BIN" ]]; then
  _TIRITH_BIN="${_TIRITH_BIN:A}"
fi
if [[ -z "$_TIRITH_BIN" || ! -x "$_TIRITH_BIN" ]]; then
  print -u2 -- "tirith: executable not found; zsh hooks disabled"
  TIRITH_STATUS=off
  return
fi

# Protocol-v3 callbacks run after arbitrary commands may have changed PATH.
# Prefer system helpers, then search the source-time PATH for non-FHS systems
# (NixOS/Guix). Inspect files directly to ignore stale command hashes, aliases
# and functions. Relative/empty PATH entries must never become helper pins.
_tirith_resolve_helper() {
  local name="$1" candidate directory
  shift
  for candidate in "$@"; do
    if [[ "$candidate" == /* && -f "$candidate" && -x "$candidate" ]]; then
      builtin print -r -- "$candidate"
      return 0
    fi
  done
  for directory in "${path[@]}"; do
    [[ "$directory" == /* ]] || continue
    candidate="${directory%/}/$name"
    if [[ -f "$candidate" && -x "$candidate" ]]; then
      builtin print -r -- "$candidate"
      return 0
    fi
  done
  return 1
}

_TIRITH_MKTEMP_BIN="$(_tirith_resolve_helper mktemp /usr/bin/mktemp /bin/mktemp)" || _TIRITH_MKTEMP_BIN=""
_TIRITH_RM_BIN="$(_tirith_resolve_helper rm /bin/rm /usr/bin/rm)" || _TIRITH_RM_BIN=""
_TIRITH_WC_BIN="$(_tirith_resolve_helper wc /usr/bin/wc /bin/wc)" || _TIRITH_WC_BIN=""
_TIRITH_ENV_BIN="$(_tirith_resolve_helper env /usr/bin/env /bin/env)" || _TIRITH_ENV_BIN=""
_TIRITH_SH_BIN="$(_tirith_resolve_helper sh /bin/sh /usr/bin/sh)" || _TIRITH_SH_BIN=""
_TIRITH_V3_HELPERS_READY=1
for _tirith_helper in "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN" \
  "$_TIRITH_ENV_BIN" "$_TIRITH_SH_BIN"; do
  [[ "$_tirith_helper" == /* && -f "$_tirith_helper" && -x "$_tirith_helper" ]] \
    || _TIRITH_V3_HELPERS_READY=0
done
unset _tirith_helper

# Legacy preflight also requires private capture files. If these prerequisites
# are absent at startup, leave the user's Enter/paste bindings intact instead
# of installing a hook that discards every command. Runtime capture failures
# still block: they must not provide a way to bypass an already-active hook.
if [[ -o interactive && ( -z "$_TIRITH_MKTEMP_BIN" || -z "$_TIRITH_RM_BIN" ) ]]; then
  builtin print -u2 -r -- "tirith: mktemp or rm unavailable; zsh hooks disabled — install these helpers and restart the shell"
  TIRITH_STATUS=off
  unset _TIRITH_ZSH_LOADED
  return 0
fi

# One receipt protocol instance per sourced hook. It is deliberately
# non-exported; only individual Tirith subprocesses receive it. Older binaries
# fail the capability probe and keep the legacy check flow with an honest
# degraded status instead of misparsing the hidden flag. Registration itself
# happens further down, after the capture-file helpers are defined.
_TIRITH_RECEIPT_PROTOCOL=0
# Discard inherited export attributes before creating the private shell capability.
unset _TIRITH_RECEIPT_INSTANCE
_TIRITH_RECEIPT_INSTANCE=""
_TIRITH_RECEIPT_REGISTER_ERROR=""
_TIRITH_RECEIPT_SHELL_PID="$$"
_TIRITH_RECEIPT_FAMILY="zsh"

# Automatic activation: zsh-activation-native.zsh
_tirith_activation_empty_module_query() {
  builtin setopt localoptions noxtrace noallexport pipefail
  local -h +x kind="${1-}" module="${2-}" answer='' rc=1
  [[ "$kind" == aliases || "$kind" == dependencies ]] || return 1
  case "$module" in
    zsh/system|zsh/stat|zsh/files|zsh/rlimits) ;;
    *) return 1 ;;
  esac
  # No module code is loaded by either metadata query. The producer prints the
  # fixed module name before any variable-length target/dependency. A reader
  # consumes one byte and closes the pipe; default SIGPIPE terminates overflow.
  # Only a fixed marker can reach command substitution. All children are
  # synchronous shell-owned pipeline members, never sampled PID targets.
  answer="$(
    (
      builtin unfunction TRAPPIPE TRAPEXIT TRAPDEBUG TRAPZERR 2>/dev/null
      builtin trap - PIPE EXIT DEBUG ZERR
      if [[ "$kind" == aliases ]]; then
        if builtin zmodload -A "$module" 2>/dev/null; then
          builtin exit 1
        fi
        builtin exit 0
      fi
      builtin zmodload -d "$module"
    ) | (
      local -h +x byte=''
      if builtin read -r -u 0 -k 1 byte; then
        builtin print -r -- occupied
        builtin exit 1
      fi
      builtin exit 0
    )
  )" 2>/dev/null
  rc=$?
  (( rc == 0 )) && [[ -z "$answer" ]]
}

_tirith_activation_fresh_native_modules() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x module feature state
  # zsh/parameter metadata is an already-present shell facility here. Never
  # trigger its autoload from the caller's search path to run this preflight.
  [[ "${parameters[modules]-}" == *association*readonly*special* \
     && "${parameters[builtins]-}" == *association*readonly*special* ]] || return 1
  for module in zsh/system zsh/stat zsh/files zsh/rlimits; do
    _tirith_activation_empty_module_query aliases "$module" || return 1
    _tirith_activation_empty_module_query dependencies "$module" || return 1
    # The preceding alias refusal prevents copying a variable-length alias
    # target through the modules parameter getter. Empty dependency-only nodes
    # are invisible in that parameter, hence the separate dependency query.
    state="${modules[$module]-}"
    if [[ "$module" == zsh/rlimits ]]; then
      # The observed clean Apple 5.9 shell registers this autoload by default.
      # It remains unloaded; loading below is explicit through the fixed path.
      [[ -z "$state" || "$state" == autoloaded ]] || return 1
    else
      [[ -z "$state" ]] || return 1
    fi
  done
  for feature in sysopen sysread sysseek zstat zf_rm; do
    [[ -z "${builtins[$feature]-}" ]] || return 1
  done
  [[ -z "${builtins[ulimit]-}" || "${builtins[ulimit]-}" == undefined ]] || return 1
}

_tirith_activation_initialize_native() {
  builtin setopt localoptions noxtrace noallexport
  # These shell parameters narrow admission only. Native validation must use
  # the authenticated actual parent and exact fixed files, never these hints.
  [[ "$ZSH_VERSION" == 5.9 && "$OSTYPE" == darwin* && "$_TIRITH_BIN" == /* \
     && "${_TIRITH_RECEIPT_PROTOCOL:-0}" == 3 ]] || return 1
  [[ "${parameters[module_path]-}" == *array*special* \
     && "${parameters[module_path]-}" != *readonly* ]] || return 1
  _tirith_activation_fresh_native_modules || return 1
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
  _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
  _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    command "$_TIRITH_BIN" __setup-activation modules --channel zsh \
      </dev/null >/dev/null 2>&1 || return 1
  # Recheck metadata after the native round trip. Never repair caller aliases,
  # dependencies or preloaded native features, and never use ambient paths.
  _tirith_activation_fresh_native_modules || return 1
  local -a +x module_path=(/usr/lib/zsh/5.9) || return 1
  builtin typeset -r module_path || return 1
  [[ "${parameters[module_path]}" == *array*readonly*special* \
     && ${#module_path} == 1 && "${module_path[1]}" == /usr/lib/zsh/5.9 ]] || return 1
  builtin zmodload -F zsh/rlimits b:ulimit || return 1
  builtin zmodload -F zsh/system b:sysopen b:sysread b:sysseek || return 1
  builtin zmodload -F zsh/stat b:zstat || return 1
  builtin zmodload -F zsh/files b:zf_rm || return 1
  [[ "${builtins[ulimit]-}" == defined ]] && _tirith_activation_rpc_features
}

# Automatic activation: zsh-activation-keymaps.zsh
_tirith_activation_keymap_capture() {
  builtin setopt localoptions noxtrace noallexport nomultibyte
  local -h +x _tirith_act_reply_fd='' wire='' extra='' count=0 rc=1
  local -A -h +x metadata
  local -a -h +x lines
  _tirith_act_keymaps=()
  _tirith_activation_rpc_features || return 1
  [[ "${builtins[ulimit]-}" == defined ]] || return 1
  {
    _tirith_activation_open_reply || return 1
    # A synchronous shell-owned subshell inherits the actual current keymaps.
    # It has no external program, process substitution, background job, sampled
    # PID, or signal target. Resource limits and trap changes stay in the child.
    {
      (
        builtin unfunction TRAPEXIT TRAPDEBUG TRAPZERR TRAPXFSZ TRAPXCPU 2>/dev/null
        builtin trap - EXIT DEBUG ZERR XFSZ XCPU
        builtin ulimit -HS -c 0 -f 1 -t 1 || builtin exit 1
        builtin bindkey -lL main || builtin exit 1
        builtin bindkey -M emacs '^M' || builtin exit 1
        builtin bindkey -M emacs '^J' || builtin exit 1
        builtin bindkey -M viins '^M' || builtin exit 1
        builtin bindkey -M vicmd '^M' || builtin exit 1
      ) >&$_tirith_act_reply_fd 2>/dev/null
      rc=$?
    } 2>/dev/null
    (( rc == 0 )) || return 1
    rc=1
    builtin zstat -H metadata -f "$_tirith_act_reply_fd" || return 1
    (( metadata[nlink] == 0 && metadata[size] > 0 && metadata[size] <= 256 )) || return 1
    builtin sysseek -u "$_tirith_act_reply_fd" 0 || return 1
    builtin sysread -i "$_tirith_act_reply_fd" -s 257 -c count wire || return 1
    (( count == metadata[size] && count <= 256 )) || return 1
    builtin sysread -i "$_tirith_act_reply_fd" -s 1 extra
    (( $? == 5 )) && [[ -z "$extra" && "$wire" == *$'\n' ]] || return 1
    wire="${wire%$'\n'}"
    lines=("${(@f)wire}")
    (( ${#lines} == 5 )) || return 1
    # These are data, never shell input. Exact editor eligibility is checked by
    # its caller; the sampler keeps the actual bounded vi-map values as before.
    [[ "${lines[1]}" == 'bindkey '* && "${lines[2]}" == '"^M" '* \
       && "${lines[3]}" == '"^J" '* && "${lines[4]}" == '"^M" '* \
       && "${lines[5]}" == '"^M" '* ]] || return 1
    _tirith_act_keymaps=("${lines[@]}")
    rc=0
  } always {
    if [[ -n "$_tirith_act_reply_fd" ]]; then
      builtin exec {_tirith_act_reply_fd}>&- || rc=1
      _tirith_act_reply_fd=''
    fi
    (( rc == 0 )) || _tirith_act_keymaps=()
  }
  return "$rc"
}

# Automatic activation: zsh-activation-rpc.zsh
_tirith_activation_rpc_features() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x feature
  for feature in sysopen sysread sysseek zstat zf_rm; do
    [[ "${builtins[$feature]-}" == defined ]] || return 1
  done
}

# The descriptor is returned through the caller's dynamically scoped local.
# The temporary pathname holds no loaded state/capability and is removed
# before a native child receives the descriptor. Names are not entropy claims:
# O_EXCL, nofollow, owner/mode and the held unlinked inode are the boundary.
_tirith_activation_open_reply() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x candidate='' index
  local -A -h +x metadata
  for index in {1..8}; do
    candidate="/tmp/tirith-activation-$EUID-$$-$RANDOM-$RANDOM"
    if builtin sysopen -rw -m 600 -o creat,excl,nofollow,nonblock,cloexec -u _tirith_act_reply_fd "$candidate" 2>/dev/null; then
      if ! builtin zstat -H metadata -f "$_tirith_act_reply_fd" \
         || (( (metadata[mode] & 8#170000) != 8#100000 || (metadata[mode] & 8#777) != 8#600 || metadata[uid] != EUID || metadata[nlink] != 1 || metadata[size] != 0 )); then
        builtin exec {_tirith_act_reply_fd}>&-
        _tirith_act_reply_fd=''
        builtin zf_rm -f -- "$candidate" 2>/dev/null
        return 1
      fi
      if ! builtin zf_rm -- "$candidate" 2>/dev/null \
         || ! builtin zstat -H metadata -f "$_tirith_act_reply_fd" \
         || (( metadata[nlink] != 0 )); then
        builtin exec {_tirith_act_reply_fd}>&-
        _tirith_act_reply_fd=''
        return 1
      fi
      return 0
    fi
  done
  return 1
}

_tirith_activation_loaded_state() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x name rendered='' total=0 count=0
  local -a -h +x _tirith_act_keymaps
  _tirith_activation_keymap_capture || return 1
  (( ${#functions} <= 2048 )) || return 1
  for name in ${(k)functions}; do
    [[ "$name" == _tirith_* ]] || continue
    (( ${#name} <= 256 )) || return 1
    (( count += 1, total += 4 * (${#functions[$name]} + ${#name} + 128) ))
    (( count <= 128 && total <= 262144 )) || return 1
  done
  # Fixed builtin-only sampler: never execute a potentially redefined sampler
  # callback. The sampler definition itself remains part of the captured text.
  # The native receiver independently caps actual bytes at 256 KiB. Existing
  # Keymap output is separately bounded before command substitution. Its
  # formatter still needs a native macro-allocation bound for a universal row.
  (( ${#precmd_functions} <= 1 && ${#preexec_functions} <= 1 && ${#zshexit_functions} <= 1 )) || return 1
  (( ${#${(j: :)precmd_functions}} <= 256 && ${#${(j: :)preexec_functions}} <= 256 && ${#${(j: :)zshexit_functions}} <= 256 )) || return 1
  (( ${#widgets[accept-line]} <= 256 && ${#widgets[bracketed-paste]} <= 256 )) || return 1
  (( ${#_TIRITH_RECEIPT_PROTOCOL} <= 2 && ${#TIRITH_STATUS} <= 16 && ${#TIRITH} <= 8 )) || return 1
  rendered="$(
    builtin print -r -- tirith-loaded-shell-v1
    for name in ${(ok)functions}; do
      [[ "$name" == _tirith_* ]] && builtin functions "$name"
    done
    builtin typeset -p precmd_functions preexec_functions zshexit_functions 2>/dev/null
    builtin zle -l -L accept-line bracketed-paste 2>/dev/null
    builtin print -r -- "${_tirith_act_keymaps[2]}"
    builtin print -r -- "${_tirith_act_keymaps[4]}"
    builtin print -r -- "${_tirith_act_keymaps[5]}"
    builtin print -r -- "protocol=${_TIRITH_RECEIPT_PROTOCOL:-0} protection=${TIRITH_STATUS:-unknown} bypass=${TIRITH:-1}"
  )" || return 1
  (( ${#rendered} > 0 && ${#rendered} <= 262144 )) || return 1
  _tirith_act_loaded="$rendered"
}

_tirith_activation_request_valid() {
  builtin setopt localoptions noxtrace noallexport
  (( $# == 4 )) || return 1
  if [[ "$1" == discover ]]; then
    [[ "$2|$3|$4" == '-|-|none' ]]
    return $?
  fi
  _tirith_activation_uuid "$2" && _tirith_activation_uuid "$3" || return 1
  case "$1" in
    start|next|restored) [[ "$4" == none ]] ;;
    cancel)
      case "$4" in
        unsupported-editor|callbacks|input-present|history-context|cancelled|deadline|context-drift|busy|backend-unavailable|protocol|proof-refused) return 0 ;;
        *) return 1 ;;
      esac ;;
    *) return 1 ;;
  esac
}

_tirith_activation_read_reply() {
  builtin setopt localoptions noxtrace noallexport nomultibyte
  local -h +x wire='' extra='' count=0 rc=0
  local -A -h +x metadata
  builtin zstat -H metadata -f "$_tirith_act_reply_fd" || return 1
  (( metadata[nlink] == 0 && metadata[size] > 0 && metadata[size] <= 256 )) || return 1
  builtin sysseek -u "$_tirith_act_reply_fd" 0 || return 1
  builtin sysread -i "$_tirith_act_reply_fd" -s 257 -c count wire || return 1
  (( count == metadata[size] && count <= 256 )) || return 1
  builtin sysread -i "$_tirith_act_reply_fd" -s 1 extra
  rc=$?
  (( rc == 5 )) && [[ -z "$extra" && "$wire" == *$'\n' ]] || return 1
  wire="${wire%$'\n'}"
  _tirith_activation_parse_frame "$wire" || return 1
  _TIRITH_ACT_REPLY="$wire"
}

_tirith_activation_rpc() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x action="${1-}" operation="${2-}" attempt="${3-}" reason="${4-}"
  local -h +x _tirith_act_loaded='' _tirith_act_reply_fd='' inputfd='' rc=1 previous=''
  _TIRITH_ACT_REPLY=''
  _tirith_activation_request_valid "$@" || return 1
  _tirith_activation_rpc_features || return 1
  [[ "$_TIRITH_BIN" == /* && -x "$_TIRITH_BIN" && "${_TIRITH_RECEIPT_PROTOCOL:-0}" == 3 ]] || return 1
  if [[ "$action" == start ]]; then
    previous="${!:-0}"
    (( ${#jobstates} == 0 )) && [[ "$previous" == 0 ]] || return 1
  fi
  {
    _tirith_activation_loaded_state || return 1
    if [[ "$action" == start ]]; then
      # Acquire inside the outer always scope. An interrupt must not leave a
      # persistent parent-shell input FD after its dynamic local disappears.
      builtin exec {inputfd}<<<"$_tirith_act_loaded" || return 1
      {
        builtin setopt localoptions nomonitor
        _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
        _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
        _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
          command "$_TIRITH_BIN" __setup-activation broker --channel zsh \
            --operation-id "$operation" --attempt-id "$attempt" \
            <&$inputfd >/dev/null 2>&1 &!
        rc=$?
      } 2>/dev/null
      builtin exec {inputfd}<&- || return 1
      inputfd=''
      (( rc == 0 )) || return "$rc"
      # Native Start relay waits for this one broker under the absolute attempt
      # deadline. A lost reply never authorizes a replacement broker launch.
    fi
    _tirith_activation_open_reply || return 1
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
      command "$_TIRITH_BIN" __setup-activation relay --channel zsh \
        --action "$action" --operation-id="$operation" \
        --attempt-id="$attempt" --reason "$reason" \
        <<<"$_tirith_act_loaded" >&$_tirith_act_reply_fd 2>/dev/null
    rc=$?
    if (( rc == 0 )); then
      _tirith_activation_read_reply || rc=1
    fi
  } always {
    # Preserve the native command/interrupt result; a cleanup failure can only
    # refuse the operation, never turn a nonzero status into success.
    if [[ -n "$inputfd" ]]; then
      builtin exec {inputfd}<&- || rc=1
      inputfd=''
    fi
    if [[ -n "$_tirith_act_reply_fd" ]]; then
      builtin exec {_tirith_act_reply_fd}>&- || rc=1
      _tirith_act_reply_fd=''
    fi
  }
  return "$rc"
}

# Automatic activation: zsh-activation.zsh
_tirith_activation_uuid() {
  builtin setopt localoptions noxtrace noallexport extendedglob
  [[ "$1" == [0-9a-f]##-[0-9a-f]##-[0-9a-f]##-[0-9a-f]##-[0-9a-f]## ]] || return 1
  [[ "$1" != 00000000-0000-0000-0000-000000000000 ]] || return 1
  [[ ${#1} == 36 && "${1[9]}${1[14]}${1[19]}${1[24]}" == '----' ]] || return 1
  [[ "${1//-/}" == [0-9a-f]## && ${#${1//-/}} == 32 ]]
}

_tirith_activation_parse_frame() {
  builtin setopt localoptions noxtrace noallexport extendedglob
  local frame="$1"
  local -a fields
  (( ${#frame} <= 256 )) || return 1
  [[ "$frame" != *$'\n'* && "$frame" != *$'\r'* ]] || return 1
  fields=( "${(@s:|:)frame}" )
  (( ${#fields} == 6 )) || return 1
  [[ "${fields[1]}" == TA1 ]] || return 1
  case "${fields[2]}" in
    none)
      [[ "${fields[3]}|${fields[4]}|${fields[5]}|${fields[6]}" == '-|-|-|none' ]] || return 1 ;;
    pending)
      _tirith_activation_uuid "${fields[3]}" && _tirith_activation_uuid "${fields[4]}" || return 1
      [[ "${fields[5]}|${fields[6]}" == '-|none' ]] || return 1 ;;
    allowed|blocked|status|restore|complete|wait)
      _tirith_activation_uuid "${fields[3]}" && _tirith_activation_uuid "${fields[4]}" && _tirith_activation_uuid "${fields[5]}" || return 1
      [[ "${fields[6]}" == none ]] || return 1 ;;
    unavailable|cancelled|failed)
      _tirith_activation_uuid "${fields[3]}" && _tirith_activation_uuid "${fields[4]}" || return 1
      [[ "${fields[5]}" == - ]] || _tirith_activation_uuid "${fields[5]}" || return 1
      case "${fields[6]}" in
        unsupported-editor|callbacks|input-present|history-context|cancelled|deadline|context-drift|busy|backend-unavailable|protocol|proof-refused) ;;
        *) return 1 ;;
      esac ;;
    *) return 1 ;;
  esac
  _TIRITH_ACT_FRAME_STAGE="${fields[2]}"
  _TIRITH_ACT_FRAME_OP="${fields[3]}"
  _TIRITH_ACT_FRAME_ATTEMPT="${fields[4]}"
  _TIRITH_ACT_FRAME_CHALLENGE="${fields[5]}"
  _TIRITH_ACT_FRAME_REASON="${fields[6]}"
}

# Read-only qualification. No attempt is made to fix unknown editor/prompt
# composition into something that can pass the diagnostic.
_tirith_activation_eligible() {
  builtin setopt localoptions noxtrace noallexport
  local mode="${1:-active}" name
  local -a -h +x _tirith_act_keymaps
  [[ -z "${_TIRITH_UNRESOLVED_RECEIPT:-}" ]] || return 1
  _TIRITH_ACT_LOCAL_REASON=unsupported-editor
  [[ -o interactive && -o zle && ! -o restricted && "$ZSH_NAME" == zsh ]] || return 1
  [[ "${widgets[accept-line]-}" == 'user:_tirith_accept_line' ]] || return 1
  if [[ "$mode" == install ]]; then
    (( ! $+widgets[zle-line-init] && ! $+functions[TRAPINT] )) || return 1
  else
    [[ "${widgets[zle-line-init]-}" == 'user:_tirith_activation_line_init' ]] || return 1
  fi
  [[ "${_TIRITH_RECEIPT_PROTOCOL:-0}" == 3 && "${TIRITH_STATUS:-unknown}" == blocks && "${TIRITH:-1}" != 0 ]] || return 1
  # Only the emacs native row has mechanism evidence so far. The broker also
  # verifies its supported native build/platform row; a version/env string is
  # not authority to add a row here.
  [[ "$mode" == install || "$KEYMAP" == main || "$KEYMAP" == emacs ]] || return 1
  _tirith_activation_keymap_capture || return 1
  [[ "${_tirith_act_keymaps[1]}" == 'bindkey -A emacs main' ]] || return 1
  [[ "${_tirith_act_keymaps[2]}" == '"^M" accept-line' ]] || return 1
  [[ "${_tirith_act_keymaps[3]}" == '"^J" accept-line' ]] || return 1
  _TIRITH_ACT_LOCAL_REASON=callbacks
  [[ ! -o promptsubst && ! -o promptbang && "${PERIOD:-0}" == 0 && "${TMOUT:-0}" == 0 ]] || return 1
  for name in precmd preexec periodic zshaddhistory zshexit; do
    (( ! $+functions[$name] )) || return 1
  done
  (( ${#precmd_functions} == 0 && ${#preexec_functions} == 0 && ${#periodic_functions} == 0 && ${#zshaddhistory_functions} == 0 )) || return 1
  (( ${#zshexit_functions} == 0 )) || [[ "${(j: :)zshexit_functions}" == _tirith_exit_summary ]] || return 1
  [[ -z "$(builtin zle -F)" ]] || return 1
  for name in zle-line-finish zle-history-line-set zle-keymap-select; do
    (( ! $+widgets[$name] )) || return 1
  done
  # The core owner must bind this exact permanent trap definition in the
  # loaded-state fingerprint. Unknown signal callback composition stays manual.
  for name in ${(k)functions}; do
    if [[ "$name" == TRAP* ]]; then
      [[ "$name" == TRAPINT && "${functions[$name]}" == "${functions[_tirith_activation_interrupt]}" ]] || return 1
    fi
  done
  # String traps are separate from TRAP* functions in Zsh. Accept exactly
  # the permanent owned INT trap or no trap before installation, never both.
  if [[ "$mode" == install ]]; then
    [[ -z "$(builtin trap)" ]] || return 1
  else
    [[ "$(builtin trap)" == "$(builtin functions TRAPINT)" ]] || return 1
  fi
  for name in HISTFILE HISTSIZE SAVEHIST; do
    [[ "${parameters[$name]-}" != *readonly* ]] || return 1
  done
  [[ "$mode" == install ]] && { _TIRITH_ACT_LOCAL_REASON=none; return 0; }
  _TIRITH_ACT_LOCAL_REASON=history-context
  if (( ${_TIRITH_ACT_HISTORY_OWNED:-0} )); then
    (( ! ${+HISTFILE} )) && [[ "$HISTSIZE" == 8 && "$SAVEHIST" == 0 ]] || return 1
  fi
  _TIRITH_ACT_LOCAL_REASON=input-present
  [[ -z "$BUFFER" && -z "$PREBUFFER" && "$CURSOR" == 0 && "$MARK" == 0 && "${REGION_ACTIVE:-0}" == 0 ]] || return 1
  (( ${+PENDING} && ${+KEYS_QUEUED_COUNT} && PENDING == 0 && KEYS_QUEUED_COUNT == 0 )) || return 1
  _TIRITH_ACT_LOCAL_REASON=none
}

_tirith_activation_restore_history() {
  builtin setopt localoptions noxtrace noallexport
  (( ${_TIRITH_ACT_HISTORY_OWNED:-0} )) || return 0
  # Qualified callback composition must exclude another fc -p/-P. If the
  # context metadata no longer matches, do not pop an unknown user context.
  (( ! ${+HISTFILE} )) && [[ "$HISTSIZE" == 8 && "$SAVEHIST" == 0 ]] || return 1
  builtin fc -P || return 1
  _TIRITH_ACT_HISTORY_OWNED=0
  [[ "${+HISTFILE}" == "$_TIRITH_ACT_SAVED_HISTFILE_SET" && "${HISTFILE-}" == "$_TIRITH_ACT_SAVED_HISTFILE" && "$HISTSIZE" == "$_TIRITH_ACT_SAVED_HISTSIZE" && "$SAVEHIST" == "$_TIRITH_ACT_SAVED_SAVEHIST" ]]
}

_tirith_activation_interrupt() {
  builtin setopt localoptions noxtrace noallexport
  (( ${_TIRITH_ACT_ACTIVE:-0} )) && _TIRITH_ACT_CANCELLED=1
  # Nonzero preserves interrupt propagation. Native cancellation restores on
  # the next editor entry; normal EOF retains the interrupted status 130.
  # Ordinary-command parity remains a product integration acceptance gate.
  return 130
}

_tirith_activation_abort() {
  builtin setopt localoptions noxtrace noallexport
  local reason="$1"
  _TIRITH_ACT_ACTIVE=0
  _TIRITH_ACT_FINISHED=1
  if ! _tirith_activation_restore_history; then
    reason=history-context
    builtin print -ru2 -- 'tirith: automatic activation verification could not restore its history context; open a fresh terminal.'
  fi
  # A relay failure cannot start another attempt or promote the result.
  _tirith_activation_rpc cancel "$_TIRITH_ACT_OP" "$_TIRITH_ACT_ATTEMPT" "$reason" >/dev/null 2>&1 || true
}

_tirith_activation_line_init() {
  local saved_status=$?
  builtin setopt localoptions noxtrace noallexport
  {
    (( ${_TIRITH_ACT_FINISHED:-0} )) && return "$saved_status"
    (( $+functions[_tirith_activation_rpc] )) || return "$saved_status"
    if (( ${_TIRITH_ACT_CANCELLED:-0} )); then
      _tirith_activation_abort cancelled
      return "$saved_status"
    fi
    if ! _tirith_activation_eligible; then
      if (( ${_TIRITH_ACT_ACTIVE:-0} )); then
        _tirith_activation_abort "$_TIRITH_ACT_LOCAL_REASON"
      else
        # One automatic opportunity at initial editor entry. Never run later
        # after user activity has changed the initial input/prompt context.
        _TIRITH_ACT_FINISHED=1
      fi
      return "$saved_status"
    fi
    if (( ! ${_TIRITH_ACT_ACTIVE:-0} )); then
      # Lost discovery is inconclusive. Discovery is idempotent for the native
      # shell start identity; the controller cannot retry with a new attempt.
      _TIRITH_ACT_FINISHED=1
      _tirith_activation_rpc discover - - none || return "$saved_status"
      _tirith_activation_parse_frame "$_TIRITH_ACT_REPLY" || return "$saved_status"
      [[ "$_TIRITH_ACT_FRAME_STAGE" == none ]] && { _TIRITH_ACT_FINISHED=1; return "$saved_status"; }
      [[ "$_TIRITH_ACT_FRAME_STAGE" == pending ]] || return "$saved_status"
      _TIRITH_ACT_OP="$_TIRITH_ACT_FRAME_OP"
      _TIRITH_ACT_ATTEMPT="$_TIRITH_ACT_FRAME_ATTEMPT"
      _TIRITH_ACT_CHALLENGE=''
      # The RPC start adapter launches the one fixed direct-shell child broker;
      # it must not introduce a helper parent or accept an arbitrary binary path.
      _TIRITH_ACT_ACTIVE=1
      _tirith_activation_rpc start "$_TIRITH_ACT_OP" "$_TIRITH_ACT_ATTEMPT" none || { _tirith_activation_abort backend-unavailable; return "$saved_status"; }
      _tirith_activation_parse_frame "$_TIRITH_ACT_REPLY" || { _tirith_activation_abort protocol; return "$saved_status"; }
      [[ "$_TIRITH_ACT_FRAME_STAGE" == pending && "$_TIRITH_ACT_FRAME_OP" == "$_TIRITH_ACT_OP" && "$_TIRITH_ACT_FRAME_ATTEMPT" == "$_TIRITH_ACT_ATTEMPT" ]] || { _tirith_activation_abort protocol; return "$saved_status"; }
      # Start/IO can take time. Recheck queued input before pushing history or
      # submitting any line, and keep input untouched on refusal.
      _tirith_activation_eligible || { _tirith_activation_abort "$_TIRITH_ACT_LOCAL_REASON"; return "$saved_status"; }
      (( ! _TIRITH_ACT_CANCELLED )) || { _tirith_activation_abort cancelled; return "$saved_status"; }
      _TIRITH_ACT_FINISHED=0
      _TIRITH_ACT_SAVED_HISTFILE_SET="${+HISTFILE}"
      _TIRITH_ACT_SAVED_HISTFILE="${HISTFILE-}"
      _TIRITH_ACT_SAVED_HISTSIZE="$HISTSIZE"
      _TIRITH_ACT_SAVED_SAVEHIST="$SAVEHIST"
      builtin fc -p || { _tirith_activation_abort history-context; return "$saved_status"; }
      HISTSIZE=8
      SAVEHIST=0
      _TIRITH_ACT_HISTORY_OWNED=1
      _TIRITH_ACT_ACTIVE=1
      _TIRITH_ACT_SUBMITTED=''
    fi
    _tirith_activation_rpc next "$_TIRITH_ACT_OP" "$_TIRITH_ACT_ATTEMPT" none || { _tirith_activation_abort backend-unavailable; return "$saved_status"; }
    _tirith_activation_parse_frame "$_TIRITH_ACT_REPLY" || { _tirith_activation_abort protocol; return "$saved_status"; }
    [[ "$_TIRITH_ACT_FRAME_OP" == "$_TIRITH_ACT_OP" && "$_TIRITH_ACT_FRAME_ATTEMPT" == "$_TIRITH_ACT_ATTEMPT" ]] || { _tirith_activation_abort protocol; return "$saved_status"; }
    if [[ -z "$_TIRITH_ACT_CHALLENGE" ]]; then
      _TIRITH_ACT_CHALLENGE="$_TIRITH_ACT_FRAME_CHALLENGE"
    fi
    [[ "$_TIRITH_ACT_FRAME_CHALLENGE" == "$_TIRITH_ACT_CHALLENGE" ]] || { _tirith_activation_abort protocol; return "$saved_status"; }
    case "$_TIRITH_ACT_FRAME_STAGE" in
      allowed|blocked|status)
        case "$_TIRITH_ACT_SUBMITTED:$_TIRITH_ACT_FRAME_STAGE" in
          :allowed|allowed:blocked|blocked:status) ;;
          *) _tirith_activation_abort protocol; return "$saved_status" ;;
        esac
        # Do not combine input arriving during the foreground relay with the
        # diagnostic line. The broker's unconsumed issued directive is terminal
        # cancellation, never permission to retry it later.
        _tirith_activation_eligible || { _tirith_activation_abort "$_TIRITH_ACT_LOCAL_REASON"; return "$saved_status"; }
        (( ! _TIRITH_ACT_CANCELLED )) || { _tirith_activation_abort cancelled; return "$saved_status"; }
        # Deadline and immutable submission intent are already persisted by the
        # broker before this directive. Never retry a submitted stage locally.
        _TIRITH_ACT_SUBMITTED="$_TIRITH_ACT_FRAME_STAGE"
        BUFFER="_tirith_verification_probe $_TIRITH_ACT_CHALLENGE $_TIRITH_ACT_FRAME_STAGE"
        CURSOR=${#BUFFER}
        builtin zle accept-line -w
        ;;
      restore)
        [[ "$_TIRITH_ACT_SUBMITTED" == status ]] || { _tirith_activation_abort protocol; return "$saved_status"; }
        _tirith_activation_restore_history || { _tirith_activation_abort history-context; return "$saved_status"; }
        _tirith_activation_rpc restored "$_TIRITH_ACT_OP" "$_TIRITH_ACT_ATTEMPT" none || { _tirith_activation_abort backend-unavailable; return "$saved_status"; }
        _tirith_activation_parse_frame "$_TIRITH_ACT_REPLY" || { _tirith_activation_abort protocol; return "$saved_status"; }
        [[ "$_TIRITH_ACT_FRAME_STAGE" == complete && "$_TIRITH_ACT_FRAME_OP" == "$_TIRITH_ACT_OP" && "$_TIRITH_ACT_FRAME_ATTEMPT" == "$_TIRITH_ACT_ATTEMPT" && "$_TIRITH_ACT_FRAME_CHALLENGE" == "$_TIRITH_ACT_CHALLENGE" ]] || { _tirith_activation_abort proof-refused; return "$saved_status"; }
        _TIRITH_ACT_ACTIVE=0
        _TIRITH_ACT_FINISHED=1
        # The broker consumed the real proof for this completed shell observation.
        # This notification never sets TIRITH_STATUS or a verified environment bit.
        builtin print -r -- 'tirith: activation verified in this terminal.'
        ;;
      *) _tirith_activation_abort proof-refused ;;
    esac
    return "$saved_status"
  } always {
    # The baseline runs only after this one automatic opportunity terminates.
    # It never participates in the challenge and is not proof of protection.
    if [[ "${_TIRITH_ACT_FINISHED:-0}" == 1 && "${_TIRITH_ACT_ACTIVE:-0}" == 0 ]]        && (( $+functions[_tirith_env_snapshot_once] )); then
      _tirith_env_snapshot_once
    fi
  }
}

# Install once after receipt registration and native module qualification.
# Never replace an unknown native widget or trap.
_tirith_activation_install_scheduler() {
  builtin setopt localoptions noxtrace noallexport
  local name
  (( $+functions[_tirith_activation_rpc] )) || return 1
  # Refuse imported/preexisting scheduler namespace attributes before assigning
  # any state; native authentication is still required independently.
  for name in ${(k)parameters}; do
    [[ "$name" != _TIRITH_ACT_* ]] || return 1
  done
  _tirith_activation_eligible install || return 1
  builtin zle -N zle-line-init _tirith_activation_line_init || return 1
  functions[TRAPINT]="${functions[_tirith_activation_interrupt]}"
  builtin typeset -gi _TIRITH_ACT_ACTIVE=0 _TIRITH_ACT_FINISHED=0 _TIRITH_ACT_CANCELLED=0 _TIRITH_ACT_HISTORY_OWNED=0
}

# The installed accept-line widget uses this path only for the exact inert
# line submitted by its active scheduler. Policy and execution receipts remain
# ordinary core decisions. Every external command is a fixed bounded Tirith
# helper; temporary capture uses already-unlinked owner-private descriptors.

_tirith_activation_receipt_frame() {
  builtin setopt localoptions noxtrace noallexport nomultibyte
  local -h +x wire='' extra='' count=0
  local -A -h +x metadata
  _tirith_act_receipt=''
  builtin zstat -H metadata -f "$_tirith_act_reply_fd" || return 1
  (( metadata[nlink] == 0 && metadata[size] >= 90 )) || return 1
  builtin sysseek -u "$_tirith_act_reply_fd" 0 || return 1
  # Retain only a canonical first token line for cleanup, even when extra
  # output makes the frame invalid. Never collect that extra output.
  builtin sysread -i "$_tirith_act_reply_fd" -s 90 -c count wire || return 1
  (( count == 90 )) && [[ "$wire" == *$'\n' ]] || return 1
  wire="${wire%$'\n'}"
  [[ "$wire" == TIRITH_EXECUTION_RECEIPT=* ]] || return 1
  wire="${wire#TIRITH_EXECUTION_RECEIPT=}"
  [[ ${#wire} == 64 && "$wire" != *[^0-9a-f]* ]] || return 1
  _tirith_act_receipt="$wire"
  # Cleanup correlation is not acceptance: size and EOF must both be exact.
  (( metadata[size] == 90 )) || return 1
  builtin sysread -i "$_tirith_act_reply_fd" -s 1 extra
  (( $? == 5 )) && [[ -z "$extra" ]]

}

_tirith_activation_retire_receipt() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x token="$1" original_cwd="$2"
  [[ -n "$token" ]] || return 1
  if [[ "$PWD" == "$original_cwd" ]]; then
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
  _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
  _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    command "$_TIRITH_BIN" __setup-activation receipt-reconcile --channel zsh \
      <<<"$token" >/dev/null 2>&1 && return 0
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
  _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
  _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    command "$_TIRITH_BIN" __setup-activation receipt-discard --channel zsh \
      <<<"$token" >/dev/null 2>&1 && return 0
  fi
  # Uncertain commitment never allows a body or a fresh user receipt. The
  # existing hook recovery path retains the original working-directory guard.
  if [[ -z "${_TIRITH_UNRESOLVED_RECEIPT:-}" ]]; then
    builtin typeset -g +x _TIRITH_UNRESOLVED_RECEIPT="$token"
    builtin typeset -g +x _TIRITH_UNRESOLVED_RECEIPT_CWD="$original_cwd"
  fi
  return 1
}

_tirith_activation_accept_line() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x expected="$1" original_cwd="$PWD" _tirith_act_loaded=''
  local -h +x _tirith_act_reply_fd='' _tirith_act_receipt='' rc=1 check_rc=1 outcome=refused
  local -A -h +x metadata
  {
    _tirith_activation_uuid "${_TIRITH_ACT_CHALLENGE:-}" || return 1
    case "${_TIRITH_ACT_SUBMITTED:-}" in
      allowed|blocked|status) ;;
      *) return 1 ;;
    esac
    [[ -z "${_TIRITH_UNRESOLVED_RECEIPT:-}" && "${_TIRITH_ACT_ACTIVE:-0}" == 1 \
       && "${_TIRITH_ACT_CANCELLED:-1}" == 0 \
       && "$BUFFER" == "$expected" \
       && "$expected" == "_tirith_verification_probe $_TIRITH_ACT_CHALLENGE $_TIRITH_ACT_SUBMITTED" ]] || return 1
    _tirith_activation_loaded_state || return 1
    _tirith_activation_open_reply || return 1
    _TIRITH_VERIFICATION_CAPTURE=1 _TIRITH_HOOK=1 \
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
      command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell posix \
        --execution-receipt zsh --offline -- "$expected" \
        <<<"$_tirith_act_loaded" >&$_tirith_act_reply_fd 2>/dev/null
    check_rc=$?
    if [[ "$_TIRITH_ACT_SUBMITTED" == blocked ]]; then
      builtin zstat -H metadata -f "$_tirith_act_reply_fd" || return 1
      if (( check_rc == 1 && metadata[nlink] == 0 && metadata[size] == 0 )); then
        outcome=blocked
      else
        _tirith_activation_receipt_frame || true
        return 1
      fi
    else
      _tirith_activation_receipt_frame || return 1
      (( check_rc == 0 )) || return 1
      outcome=allowed
    fi
    builtin exec {_tirith_act_reply_fd}>&- || return 1
    _tirith_act_reply_fd=''
    [[ "$BUFFER" == "$expected" && "$PWD" == "$original_cwd" \
       && "${_TIRITH_ACT_CANCELLED:-1}" == 0 ]] || return 1
    (( ${+PENDING} && ${+KEYS_QUEUED_COUNT} && PENDING == 0 && KEYS_QUEUED_COUNT == 0 )) || return 1
    if [[ "$outcome" == allowed ]]; then
      _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
      _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
      _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
        command "$_TIRITH_BIN" __setup-activation receipt-consume --channel zsh \
          <<<"$_tirith_act_receipt"$'\n'"$expected" >/dev/null 2>&1 || return 1
      # Acknowledged commitment cannot be discarded or used again. If input
      # arrives before accept-line, only core's conservative committed
      # observation remains; this is not a local unresolved-token guard.
      _tirith_act_receipt=''
      [[ "$BUFFER" == "$expected" && "$PWD" == "$original_cwd" \
         && "${_TIRITH_ACT_CANCELLED:-1}" == 0 ]] || return 1
      (( PENDING == 0 && KEYS_QUEUED_COUNT == 0 )) || return 1
    else
      # Advance the editor with an empty line. send-break would incorrectly
      # turn this expected diagnostic refusal into user cancellation.
      BUFFER=''
      CURSOR=0
    fi
    rc=0
    builtin zle .accept-line
    rc=$?
  } always {
    if [[ -n "$_tirith_act_reply_fd" ]]; then
      builtin exec {_tirith_act_reply_fd}>&- || rc=1
      _tirith_act_reply_fd=''
    fi
    if [[ -n "$_tirith_act_receipt" ]]; then
      _tirith_activation_retire_receipt "$_tirith_act_receipt" "$original_cwd" || true
    fi
    if (( rc != 0 )); then
      _tirith_activation_abort proof-refused
      if [[ "$BUFFER" == "$expected" ]]; then
        BUFFER=''
        CURSOR=0
      fi
      builtin zle redisplay
    fi
  }
  return "$rc"
}


# The shell-start environment baseline records variable names only. Defer this
# best-effort background write until the one automatic editor opportunity has
# completed or refused; a snapshot is never protection evidence.
_tirith_env_snapshot_once() {
  builtin setopt localoptions noxtrace noallexport
  [[ "${_TIRITH_ENV_SNAPSHOT_PENDING:-0}" == 1 ]] || return 0
  _TIRITH_ENV_SNAPSHOT_PENDING=0
  command "$_TIRITH_BIN" env snapshot >/dev/null 2>&1 &!
  return 0
}
unset _TIRITH_ENV_SNAPSHOT_PENDING
builtin typeset -gi _TIRITH_ENV_SNAPSHOT_PENDING=0
[[ -o interactive ]] && _TIRITH_ENV_SNAPSHOT_PENDING=1

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
  builtin setopt localoptions noxtrace noallexport
  local -h +x token="$1" original_cwd="$2"
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
  builtin setopt localoptions noxtrace noallexport
  local -h +x token="$1" expected="$2" original_cwd="$3"
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
  builtin setopt localoptions noxtrace noallexport
  local -h +x token="$1" original_cwd="$2"
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
  builtin setopt localoptions noxtrace noallexport
  local -h +x token="${_TIRITH_UNRESOLVED_RECEIPT:-}"
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
  builtin setopt localoptions noxtrace noallexport
  local -h +x token="$1" original_cwd="$2"
  [[ -n "$token" && -n "$original_cwd" ]] || return 1
  if _tirith_receipt_discard_at "$token" "$original_cwd"; then
    return 0
  fi
  if [[ -z "${_TIRITH_UNRESOLVED_RECEIPT:-}" ]]; then
    builtin typeset -g +x _TIRITH_UNRESOLVED_RECEIPT="$token"
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
_TIRITH_REGISTER_TRACE=0
if [[ -o xtrace ]]; then builtin unsetopt xtrace; _TIRITH_REGISTER_TRACE=1; fi
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


if [[ $_TIRITH_REGISTER_TRACE == 1 ]]; then
  unset _TIRITH_REGISTER_TRACE
  builtin setopt xtrace
else
  unset _TIRITH_REGISTER_TRACE
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
  builtin setopt localoptions noxtrace noallexport
  setopt localoptions clobber   # mktemp + redirect needs clobber
  local -h +x buf="$BUFFER"

  if [[ "${_TIRITH_ACT_ACTIVE:-0}" == 1 && -n "${_TIRITH_ACT_CHALLENGE:-}" \
       && "$buf" == "_tirith_verification_probe $_TIRITH_ACT_CHALLENGE $_TIRITH_ACT_SUBMITTED" ]]; then
    _tirith_activation_accept_line "$buf"
    return
  fi

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
  local -h +x approval_path="" warn_ack_path="" receipt_token=""
  local -h +x check_stdout="" rc=1 output=""
  if [[ $_TIRITH_RECEIPT_PROTOCOL -eq 3 ]]; then
    local outfile="" receipt_cwd="$PWD"
    if ! errfile="$(_tirith_v3_new_capture_file)" \
       || ! outfile="$(_tirith_v3_new_capture_file)"; then
      [[ -n "$errfile" ]] && _tirith_v3_remove_capture_files "$errfile" >/dev/null 2>&1
      _tirith_output "tirith: secure execution-receipt capture unavailable; command blocked. tirith: recovery: open a separate terminal with zsh -f, inspect tirith doctor --quick, pinned helpers and writable TMPDIR, then restart and verify. Pre-binary hook failures cannot be repaired with TIRITH=0."
      BUFFER=""
      zle send-break
      return
    fi
    if [[ "$buf" == "_tirith_verification_probe "* ]]; then
      local -h +x verification_capture="$(_tirith_verification_state)"
    _TIRITH_VERIFICATION_CAPTURE=1 _TIRITH_HOOK=1 _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
      _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
      _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
      command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell posix \
      --execution-receipt zsh -- "$buf" >"$outfile" 2>"$errfile" <<<"$verification_capture"
    else
    _TIRITH_HOOK=1 _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
      _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
      _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
      command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell posix \
      --execution-receipt zsh -- "$buf" >"$outfile" 2>"$errfile"
    fi
    rc=$?
    output=$(<"$errfile")

    local -h +x receipt_prefix="TIRITH_EXECUTION_RECEIPT=" receipt_line="" candidate_token=""
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
        local -h +x v3_escaped_buf=$(_tirith_escape_preview "$buf")
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
      local -h +x v3_blocked_buf=$(_tirith_escape_preview "$buf")
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
    local -h +x v3_malformed_buf=$(_tirith_escape_preview "$buf")
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
    _tirith_output "tirith: secure preflight capture unavailable; command blocked. tirith: recovery: open a separate terminal with zsh -f, inspect tirith doctor --quick, pinned helpers and writable TMPDIR, then restart and verify. Pre-binary hook failures cannot be repaired with TIRITH=0."
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
    local -h +x escaped_buf=$(_tirith_escape_preview "$buf")
    _tirith_output ""
    _tirith_output "command> $escaped_buf"
    [[ -n "$output" ]] && _tirith_output "$output"
  elif [[ $rc -eq 1 ]]; then
    local -h +x escaped_buf=$(_tirith_escape_preview "$buf")
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
  builtin setopt localoptions noxtrace noallexport
  setopt localoptions clobber   # mktemp + redirect needs clobber
  # Read the pasted content into CUTBUFFER via the original widget
  local -h +x old_buffer="$BUFFER"
  local old_cursor="$CURSOR"
  zle _tirith_original_bracketed_paste 2>/dev/null || zle .bracketed-paste

  # The new content is what was added to BUFFER
  local -h +x new_buffer="$BUFFER"
  local -h +x pasted="${new_buffer:$old_cursor:$((${#new_buffer} - ${#old_buffer}))}"

  if [[ -n "$pasted" ]]; then
    # Pipe pasted content to tirith paste, use temp file to prevent tty leakage
    local -h +x tmpfile="" output="" rc=1
    if ! tmpfile="$(_tirith_v3_new_capture_file)"; then
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      _tirith_output "tirith: secure paste capture unavailable; paste blocked for safety. tirith: recovery: open a separate terminal with zsh -f, inspect tirith doctor --quick, pinned helpers and writable TMPDIR, then restart and verify. Pre-binary hook failures cannot be repaired with TIRITH=0."
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
      local -h +x escaped_paste=$(_tirith_escape_preview "$pasted")
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

# Sample loaded definitions and native bindings in memory for explicit probes.
# Include the sampler/helper bodies so redefinition invalidates the challenge.
_tirith_verification_state() {
  local name
  builtin print -r -- tirith-loaded-shell-v1
  for name in ${(ok)functions}; do
    [[ "$name" == _tirith_* ]] && builtin functions "$name"
  done
  builtin typeset -p precmd_functions preexec_functions zshexit_functions 2>/dev/null
  builtin zle -l -L accept-line bracketed-paste 2>/dev/null
  builtin bindkey -M emacs '^M'
  builtin bindkey -M viins '^M'
  builtin bindkey -M vicmd '^M'
  builtin print -r -- "protocol=${_TIRITH_RECEIPT_PROTOCOL:-0} protection=${TIRITH_STATUS:-unknown} bypass=${TIRITH:-1}"
}

_tirith_verification_probe() {
  builtin setopt localoptions noxtrace noallexport
  local -h +x action id="" state
  if [[ "$#" -eq 1 && "$1" == start ]]; then
    action=start
  elif [[ "$#" -eq 2 && ( "$2" == allowed || "$2" == blocked || "$2" == status ) ]]; then
    id="$1"
    action="$2"
  else
    builtin print -ru2 -- 'tirith: use _tirith_verification_probe start, then its exact challenge commands'
    return 2
  fi
  if [[ "${_TIRITH_RECEIPT_PROTOCOL:-0}" != 3 ]]; then
    builtin print -ru2 -- 'tirith: authenticated shell verification requires the current protocol-v3 hook'
    return 1
  fi
  if [[ "${_TIRITH_ACT_ACTIVE:-0}" == 1 && -n "$id" \
       && "$id" == "${_TIRITH_ACT_CHALLENGE:-}" && "$action" == "${_TIRITH_ACT_SUBMITTED:-}" ]]; then
    local -h +x _tirith_act_loaded=''
    _tirith_activation_loaded_state || return 1
    _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
      command "$_TIRITH_BIN" __setup-activation probe "$action" --channel zsh --id "$id" \
        <<<"$_tirith_act_loaded" 2>/dev/null
    return $?
  fi
  state="$(_tirith_verification_state)" || return 1
  local -a id_args=()
  [[ -n "$id" ]] && id_args=(--id "$id")
  _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
    _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
    _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
    command "$_TIRITH_BIN" __shell-verification "$action" --channel zsh "${id_args[@]}" <<<"$state"
}

# Admit only the fixed native module row and supported fresh editor. Unknown
# composition keeps ordinary hook behavior and starts its deferred baseline.
if [[ "${_TIRITH_ENV_SNAPSHOT_PENDING:-0}" == 1 ]]; then
  if ! _tirith_activation_initialize_native || ! _tirith_activation_install_scheduler; then
    _tirith_env_snapshot_once
  fi
fi

# Report loaded code only after this fresh initialization reaches installation.
if [[ -o interactive ]]; then
  export TIRITH_INTEGRATION_VERSION="${_TIRITH_INIT_VERSION:-unknown}" TIRITH_INTEGRATION_SHELL=zsh
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

} always {
  if [[ "${_TIRITH_INIT_ALLEXPORT:-off}" == on ]]; then
    builtin unset _TIRITH_INIT_ALLEXPORT
    builtin setopt allexport
  else
    builtin unset _TIRITH_INIT_ALLEXPORT
    builtin unsetopt allexport
  fi
}
