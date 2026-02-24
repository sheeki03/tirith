#!/usr/bin/env bash
# Tirith security hook for Cursor (beforeShellExecution)
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ is replaced at setup time by resolve_tirith_bin() —
# either "tirith" (portable) or "/abs/path/to/tirith" (fallback)
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
if [ -z "$TIRITH_BIN" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith binary not found — install tirith or set TIRITH_FAIL_OPEN=1"}' ; exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"python3 not found — install python3 or set TIRITH_FAIL_OPEN=1"}'; exit 0
fi
INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below
COMMAND=$(python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('command',''))" <<< "$INPUT" 2>/dev/null)
PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ] || [ -z "$COMMAND" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith: failed to parse hook input — blocked for safety"}'; exit 0
fi
RESULT=$("$TIRITH_BIN" check --json --non-interactive --shell posix -- "$COMMAND" 2>/dev/null)
RC=$?  # No || true here: we need the actual exit code. Without set -e, script continues safely.
if [ "$RC" -eq 0 ]; then
  echo '{"permission":"allow"}'
elif [ "$RC" -eq 1 ] || [ "$RC" -eq 2 ]; then
  DENY_JSON=$(python3 -c "
import sys, json
try:
    v = json.loads(sys.stdin.read())
    fs = v.get('findings', [])
    reason = '; '.join(f.get('title', f.get('rule_id', '')) for f in fs) if fs else 'Security check failed'
except Exception:
    reason = 'Security check failed'
print(json.dumps({'permission': 'deny', 'user_message': 'Tirith: ' + reason, 'agent_message': 'Command blocked by Tirith: ' + reason}))
" <<< "$RESULT" 2>/dev/null) || true
  if [ -z "$DENY_JSON" ]; then
    # Python formatter failed — emit static fallback deny
    echo '{"permission":"deny","user_message":"Tirith: command blocked by security check"}'
  else
    echo "$DENY_JSON"
  fi
else
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith returned unexpected exit code — blocked for safety"}'
fi
exit 0
