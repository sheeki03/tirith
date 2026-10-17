#!/usr/bin/env bash
# Tirith security hook for Windsurf (pre_run_command)
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ replaced at setup time (see resolve_tirith_bin())
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
TIRITH_PYTHON=__TIRITH_PYTHON__
_tirith_hook_event() {
  # Optional telemetry owns its child; no background shell job or PID timer.
  # Missing Python skips telemetry without changing the security decision.
  [ -x "$TIRITH_PYTHON" ] || return 0
  "$TIRITH_PYTHON" -I -S - "$TIRITH_BIN" windsurf pre_run_command "$@" >/dev/null 2>/dev/null <<'PY_TELEMETRY'
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
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: binary not found — install tirith or set TIRITH_FAIL_OPEN=1" >&2; exit 2
fi
if [ ! -x "$TIRITH_PYTHON" ]; then
  _tirith_hook_event python3_missing
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: configured Python interpreter is unavailable — re-run tirith setup or set TIRITH_FAIL_OPEN=1" >&2; exit 2
fi
INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below
COMMAND=$("$TIRITH_PYTHON" -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('tool_info',{}).get('command_line',''))" <<< "$INPUT" 2>/dev/null); PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ] || [ -z "$COMMAND" ]; then
  _tirith_hook_event parse_error
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: failed to parse hook input — blocked for safety" >&2; exit 2
fi
RESULT=$(TIRITH_INTEGRATION=windsurf "$TIRITH_BIN" check --json --non-interactive --shell posix -- "$COMMAND" 2>/dev/null)
RC=$?  # No || true: we need the actual exit code. Without set -e, script continues safely.
if [ "$RC" -eq 0 ]; then _tirith_hook_event check_ok; exit 0; fi

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

# Exit 1 = block (High/Critical findings)
if [ "$RC" -eq 1 ]; then
  _tirith_hook_event check_block
  _findings_summary >&2
  exit 2
fi

# Exit 2 = warn (Medium/Low findings) — check TIRITH_HOOK_WARN_ACTION
if [ "$RC" -eq 2 ]; then
  WARN_ACTION=$(echo "${TIRITH_HOOK_WARN_ACTION:-allow}" | tr '[:upper:]' '[:lower:]')
  if [ "$WARN_ACTION" != "allow" ] && [ "$WARN_ACTION" != "deny" ]; then
    echo "tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='$WARN_ACTION', defaulting to 'allow'" >&2
    WARN_ACTION="allow"
  fi
  if [ "$WARN_ACTION" = "deny" ]; then
    _tirith_hook_event warn_denied
    _findings_summary >&2
    exit 2
  fi
  # allow: print warnings to stderr, but let the command through
  _tirith_hook_event warn_allowed
  _findings_summary >&2
  exit 0
fi
_tirith_hook_event unexpected_exit "exit code $RC"
if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
echo "tirith: unexpected exit code $RC — blocked for safety" >&2; exit 2
