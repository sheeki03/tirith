#!/usr/bin/env bash
# Tirith security hook for Cursor (beforeShellExecution)
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ is replaced at setup time by resolve_tirith_bin() —
# either "tirith" (portable) or "/abs/path/to/tirith" (fallback)
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
TIRITH_PYTHON=__TIRITH_PYTHON__
_tirith_hook_event() {
  # Optional telemetry owns its child; no background shell job or PID timer.
  # Missing Python skips telemetry without changing the security decision.
  [ -x "$TIRITH_PYTHON" ] || return 0
  "$TIRITH_PYTHON" -I -S - "$TIRITH_BIN" cursor before_shell_execution "$@" >/dev/null 2>/dev/null <<'PY_TELEMETRY'
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
if [ -z "$TIRITH_BIN" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"tirith binary not found — install tirith or set TIRITH_FAIL_OPEN=1"}' ; exit 0
fi
if [ ! -x "$TIRITH_PYTHON" ]; then
  _tirith_hook_event python3_missing
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then
    echo '{"permission":"allow"}'; exit 0
  fi
  echo '{"permission":"deny","user_message":"configured Python interpreter is unavailable — re-run tirith setup or set TIRITH_FAIL_OPEN=1"}'; exit 0
fi
INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below
COMMAND=$("$TIRITH_PYTHON" -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('command',''))" <<< "$INPUT" 2>/dev/null)
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
  echo '{"permission":"allow"}'
elif [ "$RC" -eq 1 ]; then
  # Block — always deny
  _tirith_hook_event check_block
  REASON=$(_findings_summary)
  DENY_JSON=$("$TIRITH_PYTHON" -c "
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
    DENY_JSON=$("$TIRITH_PYTHON" -c "
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
    ALLOW_JSON=$("$TIRITH_PYTHON" -c "
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
