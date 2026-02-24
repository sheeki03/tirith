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
    command rm -f "$file"  # ADR-7: delete on all paths
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

  # Delete temp file after reading (ADR-7 lifecycle)
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

# ─── Persistent safe mode infrastructure ───

# Trim whitespace to match Rust policy.rs:state_dir() behavior
_TIRITH_STATE_DIR="${XDG_STATE_HOME:-}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR#"${_TIRITH_STATE_DIR%%[![:space:]]*}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR%"${_TIRITH_STATE_DIR##*[![:space:]]}"}"
_TIRITH_STATE_DIR="${_TIRITH_STATE_DIR:-$HOME/.local/state}/tirith"
_TIRITH_SAFE_MODE_FLAG="$_TIRITH_STATE_DIR/bash-safe-mode"

_tirith_check_safe_mode() { [[ -f "$_TIRITH_SAFE_MODE_FLAG" ]]; }

_tirith_persist_safe_mode() {
  mkdir -p "$_TIRITH_STATE_DIR" 2>/dev/null || return
  printf '1\n' > "$_TIRITH_SAFE_MODE_FLAG" 2>/dev/null || return
}

# ─── Preexec function (used by both preexec mode and degrade fallback) ───

_tirith_preexec() {
  # Only run once per command (guard against DEBUG firing multiple times)
  [[ "${_tirith_last_cmd:-}" == "$BASH_COMMAND" ]] && return
  _tirith_last_cmd="$BASH_COMMAND"

  # Warn-only: command is already committed, we can only print warnings
  tirith check --shell posix -- "$BASH_COMMAND" || true
}

# ─── Degrade function ───

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

  trap '_tirith_preexec' DEBUG
  _TIRITH_BASH_MODE="preexec"
  _tirith_persist_safe_mode
  if [[ $- == *i* ]]; then
    _tirith_output "  Restart your shell for full custom keybindings to return."
  fi
}

# ─── PROMPT_COMMAND management ───

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

# ─── Mode selection ───

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

# ─── Helpers ───

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

# ─── Startup health gate ───

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

# ─── Enter mode (interactive only) ───

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
      approval_path=$(tirith check --approval-check --non-interactive --interactive --shell posix -- "$READLINE_LINE" 2>"$errfile")
      local rc=$?
      local output=$(<"$errfile")
      command rm -f "$errfile"

      if [[ $rc -eq 0 ]]; then
        :  # Allow: no output
      elif [[ $rc -eq 2 ]]; then
        _tirith_output ""
        _tirith_output "command> $READLINE_LINE"
        [[ -n "$output" ]] && _tirith_output "$output"
      elif [[ $rc -eq 1 ]]; then
        _tirith_output ""
        _tirith_output "command> $READLINE_LINE"
        [[ -n "$output" ]] && _tirith_output "$output"
      else
        # Unexpected exit code: degrade to preexec
        _tirith_output ""
        _tirith_output "command> $READLINE_LINE"
        [[ -n "$output" ]] && _tirith_output "$output"
        [[ -n "$approval_path" ]] && command rm -f "$approval_path"
        _tirith_degrade_to_preexec "tirith returned unexpected exit code $rc"
        return  # READLINE_LINE preserved for re-execution via preexec
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
                READLINE_LINE=""
                READLINE_POINT=0
                return
                ;;
            esac
          fi
        elif [[ $rc -eq 1 ]]; then
          # Approval not required but command was blocked: honor block
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

      if [[ -n "$pasted" ]]; then
        # Check with tirith paste, use temp file to prevent tty leakage
        local tmpfile=$(mktemp)
        printf '%s' "$pasted" | tirith paste --shell posix >"$tmpfile" 2>&1
        local rc=$?
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
          _tirith_output ""
          _tirith_output "paste> $pasted"
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

elif [[ "$_TIRITH_BASH_MODE" == "preexec" ]] && [[ $- == *i* ]]; then
  # Only install DEBUG trap in interactive shells.
  # Non-interactive sourcing (bash -c, BASH_ENV, scripts) is a clean no-op.
  trap '_tirith_preexec' DEBUG
fi
