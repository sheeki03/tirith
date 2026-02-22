#!/usr/bin/env bash
# Tirith security hook for VS Code (PreToolUse)
# Same protocol as Claude Code but implemented as a shell script.
# Filters on hook_event_name == PreToolUse and tool_name matching shell tools.
set -uo pipefail  # No -e: we handle errors explicitly per command
# __TIRITH_BIN__ is replaced at setup time by resolve_tirith_bin() —
# either "tirith" (portable) or "/abs/path/to/tirith" (fallback)
TIRITH_BIN="${TIRITH_BIN:-__TIRITH_BIN__}"

SHELL_TOOL_PATTERN="^(Bash|bash|shell|sh|zsh|terminal|Terminal|terminal_exec|terminalExec)$"

deny() {
  python3 -c "
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
if ! command -v python3 >/dev/null 2>&1; then
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  # Cannot use deny() without python3 — emit static JSON
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"python3 not found — install python3 or set TIRITH_FAIL_OPEN=1"}}'
  exit 0
fi

INPUT=$(cat) || true  # guard: cat failure → empty string → deny path below

# Extract event, tool name, and command from stdin JSON
PARSED=$(python3 -c "
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

RESULT=$("$TIRITH_BIN" check --json --non-interactive --shell posix -- "$COMMAND" 2>/dev/null)
RC=$?  # No || true: we need the actual exit code. Without set -e, script continues safely.
if [ "$RC" -eq 0 ]; then
  exit 0
elif [ "$RC" -eq 1 ] || [ "$RC" -eq 2 ]; then
  REASON=$(python3 -c "
import sys, json
try:
    v = json.loads(sys.stdin.read())
    fs = v.get('findings', [])
    reason = '; '.join(f.get('title', f.get('rule_id', '')) for f in fs) if fs else 'Security check failed'
except Exception:
    reason = 'Security check failed'
print('Tirith: ' + reason)
" <<< "$RESULT" 2>/dev/null) || true
  if [ -z "$REASON" ]; then
    REASON="Tirith: command blocked by security check"
  fi
  deny "$REASON"
else
  if [ "${TIRITH_FAIL_OPEN:-}" = "1" ]; then exit 0; fi
  deny "tirith returned unexpected exit code — blocked for safety"
fi
