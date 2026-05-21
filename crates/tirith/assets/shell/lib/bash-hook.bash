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

# Session tracking: generate ID per shell session if not inherited
if [[ -z "${TIRITH_SESSION_ID:-}" ]]; then
  TIRITH_SESSION_ID="$(printf '%x-%x' "$$" "$(date +%s)")"
  export TIRITH_SESSION_ID
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

  # Delete temp file after reading
  command rm -f "$file"

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


# Trim whitespace to match Rust policy.rs:state_dir() behavior
_TIRITH_STATE_DIR="${XDG_STATE_HOME:-}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR#"${_TIRITH_STATE_DIR%%[![:space:]]*}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR%"${_TIRITH_STATE_DIR##*[![:space:]]}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR:-$HOME/.local/state}/tirith"
_TIRITH_SAFE_MODE_FLAG="$_TIRITH_STATE_DIR/bash-safe-mode"

_tirith_check_safe_mode() { [[ -f "$_TIRITH_SAFE_MODE_FLAG" ]]; }

_tirith_persist_safe_mode() {
  if ! mkdir -p "$_TIRITH_STATE_DIR" 2>/dev/null || ! printf '1\n' > "$_TIRITH_SAFE_MODE_FLAG" 2>/dev/null; then
    echo "tirith: warning: could not persist safe-mode flag" >&2
  fi
}


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
  local s="$1"
  s="$(printf '%s' "$s" | tr -s '[:space:]' ' ')"
  s="${s# }"
  s="${s% }"
  local op
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
    eval "$_TIRITH_PREV_DEBUG_TRAP" || true
  fi
  _tirith_preexec "$_user_line_id"
}

_tirith_install_debug_trap() {
  local current
  current="$(trap -p DEBUG 2>/dev/null)"
  [[ "$current" == *"_tirith_debug_trampoline"* ]] && return 0

  _TIRITH_PREV_DEBUG_TRAP="$(trap -p DEBUG 2>/dev/null | sed "s/^trap -- '//;s/' DEBUG\$//")"
  trap '_tirith_debug_trampoline' DEBUG
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
  if [[ $- == *i* ]]; then
    _tirith_output "$reason"
  fi
}


_tirith_preexec() {
  [[ "${_TIRITH_BASH_INTERNAL:-0}" == "1" ]] && return 0

  # Once-per-shell warn-only banner for interactive preexec users.
  if [[ -z "${_TIRITH_PREEXEC_WARNED:-}" ]] \
     && [[ $- == *i* ]] \
     && [[ "${_TIRITH_PREEXEC_ENFORCE:-0}" != "1" ]]; then
    _TIRITH_PREEXEC_WARNED=1
    _tirith_output "tirith: bash is in preexec mode (warn-only, does not block)"
    _tirith_output "  For guaranteed blocking use enter mode (export TIRITH_BASH_MODE=enter)"
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
    command tirith check --shell posix -- "$history_line"
    rc=$?
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
  command tirith check --shell posix --warn-only -- "$scan_target" || true
  _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"
  return 0
}


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
    _tirith_output "  Restart your shell for full custom keybindings to return."
  fi
}


_tirith_prompt_hook() {
  local pending_eval="${_TIRITH_PENDING_EVAL:-}"
  local pending_source="${_TIRITH_PENDING_SOURCE:-}"
  unset _TIRITH_PENDING_EVAL _TIRITH_PENDING_SOURCE

  if [[ -n "$pending_source" ]]; then
    source "$pending_source"
    command rm -f "$pending_source"
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
  else
    export TIRITH_BASH_EFFECTIVE_PROTECTION="warn-only"
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
  else
    # Same hostile-history check that triggers a runtime drift downgrade —
    # so the warn-only scan target must also flip to BASH_COMMAND, not the
    # untrustworthy history_line. Without this the warn-only path would
    # produce stale DETECTED banners scanned against whatever entry
    # `history 1` happens to surface.
    _TIRITH_WARN_ONLY_USE_BASH_COMMAND=1
    _tirith_output "tirith: cannot enable preexec enforcement in this shell (HISTCONTROL/HISTIGNORE or disabled history prevent trustworthy whole-line view). Running in warn-only. For guaranteed blocking, use enter mode (export TIRITH_BASH_MODE=enter)."
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
        [[ -n "${_TIRITH_PENDING_SOURCE:-}" ]] && command rm -f "${_TIRITH_PENDING_SOURCE}"
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

      # Run tirith check with approval workflow (stdout=approval file path, stderr=human output)
      local errfile=$(mktemp)
      local approval_path
      local _tirith_prev_internal="${_TIRITH_BASH_INTERNAL:-0}"
      _TIRITH_BASH_INTERNAL=1
      approval_path=$(command tirith check --approval-check --non-interactive --interactive --shell posix -- "$READLINE_LINE" 2>"$errfile")
      local rc=$?
      _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"
      local output=$(<"$errfile")
      command rm -f "$errfile"

      # Exit code 3 (WarnAck): stdout has two lines — approval path + warn-ack path.
      # Split them so approval workflow gets the right file.
      local warn_ack_path=""
      if [[ $rc -eq 3 ]]; then
        local _first_line _rest
        IFS=$'\n' read -r _first_line <<< "$approval_path"
        _rest="${approval_path#*$'\n'}"
        if [[ "$_rest" != "$approval_path" ]]; then
          warn_ack_path="$_rest"
        fi
        approval_path="$_first_line"
      fi

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
        [[ -n "$approval_path" ]] && command rm -f "$approval_path"
        [[ -n "$warn_ack_path" ]] && command rm -f "$warn_ack_path"
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
          if [[ "$_tirith_ap_timeout" -gt 0 ]]; then
            read -t "$_tirith_ap_timeout" -p "Approve? (${_tirith_ap_timeout}s timeout) [y/N] " response </dev/tty 2>/dev/null
          else
            read -p "Approve? [y/N] " response </dev/tty 2>/dev/null
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
                READLINE_LINE=""
                READLINE_POINT=0
                return
                ;;
            esac
          fi
        elif [[ $rc -eq 1 ]]; then
          # Approval not required but command was blocked: honor block
          [[ -n "$warn_ack_path" ]] && command rm -f "$warn_ack_path"
          READLINE_LINE=""
          READLINE_POINT=0
          return
        fi
      elif [[ $rc -eq 1 ]]; then
        # No approval file: honor block
        READLINE_LINE=""
        READLINE_POINT=0
        return
      fi

      # Warn-ack workflow (exit code 3): strict_warn requires explicit acknowledgement
      if [[ $rc -eq 3 && -n "$warn_ack_path" ]]; then
        _tirith_parse_warn_ack "$warn_ack_path"
        local response=""
        read -p "tirith: proceed with ${_tirith_wa_findings} warning(s)? [y/N] " response </dev/tty 2>/dev/null
        if [[ "$response" == [yY]* ]]; then
          :  # Acknowledged: fall through to execute
        else
          _tirith_output "tirith: warnings not acknowledged — command blocked"
          READLINE_LINE=""
          READLINE_POINT=0
          return
        fi
      elif [[ -n "$warn_ack_path" ]]; then
        command rm -f "$warn_ack_path"
      fi

      # Execute the command (approval workflow above handled block cases)
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

      # Honor explicit TIRITH=0 bypass: skip paste scanning
      if [[ "${TIRITH:-}" == "0" ]]; then
        READLINE_LINE="${READLINE_LINE:0:$READLINE_POINT}${pasted}${READLINE_LINE:$READLINE_POINT}"
        READLINE_POINT=$((READLINE_POINT + ${#pasted}))
        return
      fi

      if [[ -n "$pasted" ]]; then
        # Check with tirith paste, use temp file to prevent tty leakage
        local tmpfile=$(mktemp)
        local _tirith_prev_internal="${_TIRITH_BASH_INTERNAL:-0}"
        _TIRITH_BASH_INTERNAL=1
        printf '%s' "$pasted" | command tirith paste --shell posix --interactive >"$tmpfile" 2>&1
        local rc=$?
        _TIRITH_BASH_INTERNAL="$_tirith_prev_internal"
        local output=$(<"$tmpfile")
        command rm -f "$tmpfile"

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
  [[ -n "${TIRITH_SESSION_ID:-}" ]] || return
  local _sd="${XDG_STATE_HOME:-$HOME/.local/state}/tirith"
  [[ -f "$_sd/sessions/$TIRITH_SESSION_ID.json" ]] || return
  command tirith warnings --summary
}
_tirith_prev_exit_trap=$(trap -p EXIT 2>/dev/null | sed "s/^trap -- '//;s/' EXIT$//")
if [[ -n "$_tirith_prev_exit_trap" ]]; then
  eval "trap '${_tirith_prev_exit_trap}; _tirith_exit_summary' EXIT"
else
  trap '_tirith_exit_summary' EXIT
fi
unset _tirith_prev_exit_trap

# Install the DEBUG trap as the absolute last step so no more internal hook
# code fires it during sourcing. The enter-mode path installs its own bind-x
# earlier; the degrade path installs DEBUG on demand inside
# `_tirith_degrade_to_preexec`.
if [[ "$_TIRITH_BASH_MODE" == "preexec" ]] && [[ $- == *i* ]]; then
  _tirith_install_debug_trap
fi
