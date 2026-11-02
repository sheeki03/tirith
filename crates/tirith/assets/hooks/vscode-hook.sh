#!/usr/bin/env bash
# Tirith security hook for VS Code (PreToolUse)
# Same protocol as Claude Code but implemented as a shell script.
# Filters on hook_event_name == PreToolUse and tool_name matching shell tools.
# A warning is never an approval: by default it is answered without a
# permissionDecision (VS Code's own confirmation rules apply), with the
# warning in systemMessage (user) and additionalContext (model).
# TIRITH_HOOK_WARN_ACTION=ask asks the user to confirm, deny blocks, and any
# other value blocks.
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ is replaced at setup time by resolve_tirith_bin() —
# either "tirith" (portable) or "/abs/path/to/tirith" (fallback)
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
TIRITH_PYTHON=__TIRITH_PYTHON__
_tirith_hook_event() {
  # Optional telemetry owns its child; no background shell job or PID timer.
  # Missing Python skips telemetry without changing the security decision.
  [ -x "$TIRITH_PYTHON" ] || return 0
  "$TIRITH_PYTHON" -I -S - "$TIRITH_BIN" vscode pre_tool_use "$@" >/dev/null 2>/dev/null <<'PY_TELEMETRY'
import subprocess
import sys
child = None
try:
    cmd = [sys.argv[1], "hook-event", "--integration", sys.argv[2],
           "--hook-type", sys.argv[3], "--event", sys.argv[4]]
    if len(sys.argv) > 5:
        cmd.extend(["--detail", sys.argv[5]])
    child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    child.wait(timeout=0.25)
except Exception:
    pass
finally:
    if child is not None:
        try:
            if child.poll() is None:
                try:
                    child.kill()
                finally:
                    child.wait(timeout=0.25)
        except Exception:
            sys.exit(1)
PY_TELEMETRY
  if [ "$?" -ne 0 ]; then
    printf '%s\n' 'tirith: optional hook telemetry unavailable' >&2
  fi
  return 0
}

SHELL_TOOL_PATTERN="^(Bash|bash|shell|sh|zsh|terminal|Terminal|terminal_exec|terminalExec)$"

deny() {
  "$TIRITH_PYTHON" -I -S -c "
import sys, json
reason = sys.argv[1]
print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': reason}}))
" "$1" 2>/dev/null || echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Security check failed"}}'
  exit 0
}

if [ -z "$TIRITH_BIN" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  deny "tirith binary not found — install tirith or set TIRITH_FAIL_OPEN=1"
fi
if [ ! -x "$TIRITH_PYTHON" ]; then
  _tirith_hook_event python3_missing
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  # Cannot use deny() without the pinned interpreter — emit static JSON.
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"configured Python interpreter is unavailable — re-run tirith setup or set TIRITH_FAIL_OPEN=1"}}'
  exit 0
fi

INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below

# Extract event, tool name, command state, and command from stdin JSON. The
# state line is "ok" only for a non-empty string command; anything else (a
# missing, null, non-string, or blank command, or a non-object tool_input) is
# "invalid" and a matched shell tool is denied below without a check.
PARSED=$("$TIRITH_PYTHON" -I -S -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    event = d.get('hook_event_name', d.get('hookEventName', ''))
    tool = d.get('tool_name', d.get('toolName', ''))
    ti = d.get('tool_input', d.get('toolInput', {}))
    cmd = ti.get('command') if isinstance(ti, dict) else None
    ok = isinstance(cmd, str) and cmd.strip() != ''
    # One line each, so a newline in a name cannot shift the fields below.
    print(str(event).replace('\r', ' ').replace('\n', ' '))
    print(str(tool).replace('\r', ' ').replace('\n', ' '))
    print('ok' if ok else 'invalid')
    print(cmd if ok else '')
except Exception:
    print('')
    print('')
    print('')
    print('')
" <<< "$INPUT" 2>/dev/null)
PARSE_RC=$?

if [ "$PARSE_RC" -ne 0 ] || [ -z "$PARSED" ]; then
  _tirith_hook_event parse_error
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  deny "tirith: failed to parse hook input — blocked for safety"
fi

# Read the event, tool, and command-state lines; the command is the rest.
EVENT=$(echo "$PARSED" | head -n 1)
TOOL=$(echo "$PARSED" | sed -n '2p')
COMMAND_STATE=$(echo "$PARSED" | sed -n '3p')
COMMAND=$(echo "$PARSED" | tail -n +4)

# Only intercept PreToolUse + shell tools
if [ "$EVENT" != "PreToolUse" ]; then
  exit 0
fi
if ! echo "$TOOL" | grep -qE "$SHELL_TOOL_PATTERN"; then
  exit 0
fi
# A shell tool call without a string command cannot be checked; it is not a
# no-op the hook may silently allow.
if [ "$COMMAND_STATE" != "ok" ] || [ -z "$COMMAND" ]; then
  _tirith_hook_event parse_error "no command in shell tool input"
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  deny "tirith: no command found in hook input — blocked for safety"
fi

RESULT=$(TIRITH_INTEGRATION=vscode "$TIRITH_BIN" check --json --non-interactive --shell posix -- "$COMMAND" 2>/dev/null)
RC=$?  # No || true: we need the actual exit code. Without set -e, script continues safely.

# Helper: describe warning findings (severity, title, rule id, short fix)
_warning_summary() {
  "$TIRITH_PYTHON" -I -S -c "
import sys, json
try:
    v = json.loads(sys.stdin.read())
    parts = []
    for f in v.get('findings', []):
        if not isinstance(f, dict):
            continue
        rule = f.get('rule_id') if isinstance(f.get('rule_id'), str) else ''
        title = f.get('title') if isinstance(f.get('title'), str) and f.get('title') else (rule or 'unknown')
        sev = f.get('severity')
        part = '[%s] %s' % (sev, title) if isinstance(sev, str) and sev else title
        if rule and rule != title:
            part += ' (%s)' % rule
        fix = f.get('remediation')
        if isinstance(fix, str) and fix.strip():
            fix = ' '.join(fix.split())
            end = fix.find('. ')
            if end != -1:
                fix = fix[:end + 1]
            if len(fix) > 200:
                fix = fix[:197].rstrip() + '...'
            part += ' \u2014 fix: ' + fix
        parts.append(part)
    print('Tirith warning: ' + '; '.join(parts) if parts else 'Tirith warning: the security check reported a warning')
except Exception:
    print('Tirith warning: the security check reported a warning')
" <<< "$RESULT" 2>/dev/null || echo "Tirith warning: the security check reported a warning"
}

# Helper: extract finding titles from JSON result via python3
_findings_summary() {
  "$TIRITH_PYTHON" -I -S -c "
import sys, json
try:
    v = json.loads(sys.stdin.read())
    fs = v.get('findings', [])
    if fs:
        parts = []
        for f in fs:
            t = f.get('title', f.get('rule_id', 'unknown'))
            s = f.get('severity', '')
            parts.append('[%s] %s' % (s, t) if s else t)
        print('Tirith: ' + '; '.join(parts))
    else:
        print('Tirith: security check failed')
except Exception:
    print('Tirith: security check failed')
" <<< "$RESULT" 2>/dev/null || echo "Tirith: security check failed"
}

if [ "$RC" -eq 2 ]; then
  WARN_ACTION_RAW="${TIRITH_HOOK_WARN_ACTION:-allow}"
  WARN_ACTION=$(printf '%s' "$WARN_ACTION_RAW" | tr '[:upper:]' '[:lower:]')
  case "$WARN_ACTION" in
    allow|ask|deny) ;;
    # An unparseable security setting fails closed.
    *) WARN_ACTION="invalid" ;;
  esac
fi

# A successful/warning exit is not execution permission while a policy approval
# is pending. Malformed metadata is a checker error, not an ordinary warning.
if [ "$RC" -eq 0 ] || [ "$RC" -eq 2 ]; then
  APPROVAL_STATE=$("$TIRITH_PYTHON" -I -S -c "
import sys, json
v = json.loads(sys.stdin.read())
if not isinstance(v, dict) or type(v.get('requires_approval')) is not bool:
    sys.exit(1)
print('required' if v['requires_approval'] else 'none')
" <<< "$RESULT" 2>/dev/null)
  if [ "$?" -ne 0 ]; then
    _tirith_hook_event parse_error "invalid check approval metadata"
    if [ "${TIRITH_FAIL_OPEN:-}" = "1" ] && { [ "$RC" -ne 2 ] || [ "$WARN_ACTION" = "allow" ]; }; then exit 0; fi
    deny "Tirith: invalid approval metadata from security check — blocked for safety"
  fi
  if [ "$APPROVAL_STATE" = "required" ]; then
    _tirith_hook_event approval_required
    deny "Tirith: command requires policy approval. This hook cannot request approval; ask your operator to review the command in an approval-capable Tirith integration."
  fi
fi

if [ "$RC" -eq 0 ]; then
  _tirith_hook_event check_ok
  exit 0
elif [ "$RC" -eq 1 ] || [ "$RC" -eq 4 ]; then
  # Block — always deny. Exit 4 is a deferred block (pending review), never a
  # checker error eligible for fail-open.
  _tirith_hook_event check_block
  REASON=$(_findings_summary)
  deny "$REASON"
elif [ "$RC" -eq 2 ]; then
  REASON=$(_warning_summary)
  if [ "$WARN_ACTION" = "allow" ]; then
    # No permissionDecision: VS Code applies its own confirmation rules exactly
    # as for a clean command. systemMessage reaches the user and
    # additionalContext reaches the model.
    _tirith_hook_event warn_allowed
    WARN_JSON=$("$TIRITH_PYTHON" -I -S -c "
import sys, json
msg = sys.argv[1]
print(json.dumps({'systemMessage': msg, 'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'additionalContext': msg}}))
" "$REASON" 2>/dev/null) || true
    if [ -z "$WARN_JSON" ]; then
      echo '{"systemMessage":"Tirith warning: the security check reported a warning","hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"Tirith warning: the security check reported a warning"}}'
    else
      echo "$WARN_JSON"
    fi
    exit 0
  elif [ "$WARN_ACTION" = "ask" ]; then
    # The reason is shown to the user in the confirmation prompt.
    _tirith_hook_event warn_ask
    ASK_JSON=$("$TIRITH_PYTHON" -I -S -c "
import sys, json
msg = sys.argv[1]
print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'ask', 'permissionDecisionReason': msg, 'additionalContext': msg}}))
" "$REASON" 2>/dev/null) || true
    if [ -z "$ASK_JSON" ]; then
      echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Tirith warning: the security check reported a warning","additionalContext":"Tirith warning: the security check reported a warning"}}'
    else
      echo "$ASK_JSON"
    fi
    exit 0
  elif [ "$WARN_ACTION" = "invalid" ]; then
    _tirith_hook_event warn_denied "unrecognized warn action"
    deny "tirith: unrecognized TIRITH_HOOK_WARN_ACTION='$WARN_ACTION_RAW' (valid values: allow, ask, deny) — warning blocked for safety. $REASON"
  else
    # Treat warn as deny
    _tirith_hook_event warn_denied
    deny "$REASON"
  fi
elif [ "$RC" -eq 3 ]; then
  # WarnAck is an execution gate, not a checker failure eligible for fail-open.
  _tirith_hook_event warn_denied "warning acknowledgement required"
  deny "Tirith: command requires warning acknowledgement. This hook cannot collect it; review the command in an acknowledgement-capable Tirith integration."
else
  _tirith_hook_event unexpected_exit "exit code $RC"
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  deny "tirith returned unexpected exit code — blocked for safety"
fi
