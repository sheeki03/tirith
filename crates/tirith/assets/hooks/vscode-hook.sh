#!/usr/bin/env bash
# Tirith security hook for VS Code (PreToolUse)
# Same protocol as Claude Code but implemented as a shell script.
# Filters on hook_event_name == PreToolUse and tool_name matching shell tools.
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
  "$TIRITH_PYTHON" -c "
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

# Extract event, tool name, and command from stdin JSON
PARSED=$("$TIRITH_PYTHON" -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    event = d.get('hook_event_name', d.get('hookEventName', ''))
    tool = d.get('tool_name', d.get('toolName', ''))
    ti = d.get('tool_input', d.get('toolInput', {}))
    cmd = ti.get('command', '') if isinstance(ti, dict) else ''
    print(event)
    print(tool)
    print(cmd)
except Exception:
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

# Read the three lines from PARSED
EVENT=$(echo "$PARSED" | head -n 1)
TOOL=$(echo "$PARSED" | sed -n '2p')
COMMAND=$(echo "$PARSED" | tail -n +3)

# Only intercept PreToolUse + shell tools
if [ "$EVENT" != "PreToolUse" ]; then
  exit 0
fi
if ! echo "$TOOL" | grep -qE "$SHELL_TOOL_PATTERN"; then
  exit 0
fi
if [ -z "$COMMAND" ]; then
  exit 0
fi

RESULT=$(TIRITH_INTEGRATION=vscode "$TIRITH_BIN" check --json --non-interactive --shell posix -- "$COMMAND" 2>/dev/null)
RC=$?  # No || true: we need the actual exit code. Without set -e, script continues safely.

# Helper: extract finding titles from JSON result via python3
_findings_summary() {
  "$TIRITH_PYTHON" -c "
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

if [ "$RC" -eq 0 ]; then
  _tirith_hook_event check_ok
  exit 0
elif [ "$RC" -eq 1 ]; then
  # Block — always deny
  _tirith_hook_event check_block
  REASON=$(_findings_summary)
  deny "$REASON"
elif [ "$RC" -eq 2 ]; then
  # Warn — check TIRITH_HOOK_WARN_ACTION (default: allow)
  WARN_ACTION="${TIRITH_HOOK_WARN_ACTION:-allow}"
  WARN_ACTION=$(echo "$WARN_ACTION" | tr '[:upper:]' '[:lower:]')
  if [ "$WARN_ACTION" != "allow" ] && [ "$WARN_ACTION" != "deny" ]; then
    echo "tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='$WARN_ACTION', defaulting to 'allow'" >&2
    WARN_ACTION="allow"
  fi
  if [ "$WARN_ACTION" = "deny" ]; then
    # Treat warn as deny
    _tirith_hook_event warn_denied
    REASON=$(_findings_summary)
    deny "$REASON"
  else
    # Warn-allow: emit allow with additionalContext so findings reach the model
    _tirith_hook_event warn_allowed
    REASON=$(_findings_summary)
    ALLOW_JSON=$("$TIRITH_PYTHON" -c "
import sys, json
msg = sys.argv[1]
print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'allow', 'permissionDecisionReason': msg, 'additionalContext': msg}}))
" "$REASON" 2>/dev/null) || true
    if [ -z "$ALLOW_JSON" ]; then
      echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Tirith: warnings detected (non-blocking)","additionalContext":"Tirith: warnings detected (non-blocking)"}}'
    else
      echo "$ALLOW_JSON"
    fi
    exit 0
  fi
else
  _tirith_hook_event unexpected_exit "exit code $RC"
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  deny "tirith returned unexpected exit code — blocked for safety"
fi
