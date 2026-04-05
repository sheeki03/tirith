#!/usr/bin/env bash
# Tirith security hook for Cursor (beforeShellExecution)
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ is replaced at setup time by resolve_tirith_bin() —
# either "tirith" (portable) or "/abs/path/to/tirith" (fallback)
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
_tirith_hook_event() {
  if [ $# -ge 2 ]; then
    "$TIRITH_BIN" hook-event --integration cursor --hook-type before_shell_execution --event "$1" --detail "$2" 2>/dev/null &
  else
    "$TIRITH_BIN" hook-event --integration cursor --hook-type before_shell_execution --event "$1" 2>/dev/null &
  fi
}
if [ -z "$TIRITH_BIN" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith binary not found — install tirith or set TIRITH_FAIL_OPEN=1"}' ; exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  _tirith_hook_event python3_missing
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"python3 not found — install python3 or set TIRITH_FAIL_OPEN=1"}'; exit 0
fi
INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below
COMMAND=$(python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('command',''))" <<< "$INPUT" 2>/dev/null)
PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ] || [ -z "$COMMAND" ]; then
  _tirith_hook_event parse_error
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith: failed to parse hook input — blocked for safety"}'; exit 0
fi
RESULT=$(TIRITH_INTEGRATION=cursor "$TIRITH_BIN" check --json --non-interactive --shell posix -- "$COMMAND" 2>/dev/null)
RC=$?  # No || true here: we need the actual exit code. Without set -e, script continues safely.

# Helper: extract finding titles from JSON result via python3
_findings_summary() {
  python3 -c "
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
  echo '{"permission":"allow"}'
elif [ "$RC" -eq 1 ]; then
  # Block — always deny
  _tirith_hook_event check_block
  REASON=$(_findings_summary)
  DENY_JSON=$(python3 -c "
import sys, json
reason = sys.argv[1]
print(json.dumps({'permission': 'deny', 'user_message': reason, 'agent_message': 'Command blocked by Tirith: ' + reason}))
" "$REASON" 2>/dev/null) || true
  if [ -z "$DENY_JSON" ]; then
    echo '{"permission":"deny","user_message":"Tirith: command blocked by security check"}'
  else
    echo "$DENY_JSON"
  fi
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
    DENY_JSON=$(python3 -c "
import sys, json
reason = sys.argv[1]
print(json.dumps({'permission': 'deny', 'user_message': reason, 'agent_message': 'Command blocked by Tirith: ' + reason}))
" "$REASON" 2>/dev/null) || true
    if [ -z "$DENY_JSON" ]; then
      echo '{"permission":"deny","user_message":"Tirith: command blocked by security check"}'
    else
      echo "$DENY_JSON"
    fi
  else
    # Warn-allow: emit allow JSON with findings + stderr fallback
    _tirith_hook_event warn_allowed
    REASON=$(_findings_summary)
    echo "$REASON" >&2
    ALLOW_JSON=$(python3 -c "
import sys, json
msg = sys.argv[1]
print(json.dumps({'permission': 'allow', 'user_message': msg}))
" "$REASON" 2>/dev/null) || true
    if [ -z "$ALLOW_JSON" ]; then
      echo '{"permission":"allow","user_message":"Tirith: warnings detected (non-blocking)"}'
    else
      echo "$ALLOW_JSON"
    fi
  fi
else
  _tirith_hook_event unexpected_exit "exit code $RC"
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith returned unexpected exit code — blocked for safety"}'
fi
exit 0
