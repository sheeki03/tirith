#!/usr/bin/env bash
# Tirith security hook for Windsurf (pre_run_command)
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ replaced at setup time (see resolve_tirith_bin())
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
_tirith_hook_event() {
  if [ $# -ge 2 ]; then
    "$TIRITH_BIN" hook-event --integration windsurf --hook-type pre_run_command --event "$1" --detail "$2" 2>/dev/null &
  else
    "$TIRITH_BIN" hook-event --integration windsurf --hook-type pre_run_command --event "$1" 2>/dev/null &
  fi
}
if [ -z "$TIRITH_BIN" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: binary not found — install tirith or set TIRITH_FAIL_OPEN=1" >&2; exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  _tirith_hook_event python3_missing
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: python3 not found — install python3 or set TIRITH_FAIL_OPEN=1" >&2; exit 2
fi
INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below
COMMAND=$(python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('tool_info',{}).get('command_line',''))" <<< "$INPUT" 2>/dev/null); PARSE_RC=$?
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
