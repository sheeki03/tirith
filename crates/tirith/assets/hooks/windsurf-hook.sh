#!/usr/bin/env bash
# Tirith security hook for Windsurf (pre_run_command)
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ replaced at setup time (see resolve_tirith_bin())
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"
if [ -z "$TIRITH_BIN" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: binary not found — install tirith or set TIRITH_FAIL_OPEN=1" >&2; exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: python3 not found — install python3 or set TIRITH_FAIL_OPEN=1" >&2; exit 2
fi
INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below
COMMAND=$(python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('tool_info',{}).get('command_line',''))" <<< "$INPUT" 2>/dev/null); PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ] || [ -z "$COMMAND" ]; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  echo "tirith: failed to parse hook input — blocked for safety" >&2; exit 2
fi
"$TIRITH_BIN" check --non-interactive --shell posix -- "$COMMAND" >/dev/null 2>&1
RC=$?  # No || true: we need the actual exit code. Without set -e, script continues safely.
[ "$RC" -eq 0 ] && exit 0
if [ "$RC" -eq 1 ] || [ "$RC" -eq 2 ]; then
  echo "Tirith: command blocked by security check" >&2; exit 2
fi
if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
echo "tirith: unexpected exit code $RC — blocked for safety" >&2; exit 2
