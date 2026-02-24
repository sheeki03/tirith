#!/usr/bin/env python3
"""Claude Code PreToolUse hook — runs tirith check on Bash tool calls.

Reads JSON from stdin (Claude Code hook protocol), extracts the command,
and delegates to `tirith check --json` for security analysis.

Exit codes:
  0 — hook completed successfully (decision in stdout JSON if blocking)
  Non-zero — hook error (Claude Code treats as allow / fail-open)

Output (stdout, only for deny):
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": "..."
    }
  }

Environment:
  TIRITH_BIN              — path to tirith binary (default: "tirith")
  TIRITH_HOOK_WARN_ACTION — "deny" (default) or "allow"
"""

import json
import os
import shutil
import subprocess
import sys


def get(data, *keys):
    """Return the first matching key from data (supports dual-case fields)."""
    for k in keys:
        if k in data:
            return data[k]
    return None


def deny(reason):
    """Print a deny decision using hookSpecificOutput and exit 0."""
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        sys.exit(0)

    if not isinstance(data, dict):
        sys.exit(0)

    # Dual-case field extraction (camelCase and snake_case)
    event = get(data, "hook_event_name", "hookEventName")
    tool = get(data, "tool_name", "toolName")
    tool_input = get(data, "tool_input", "toolInput") or {}

    # Only intercept PreToolUse + Bash
    if event != "PreToolUse" or tool != "Bash":
        sys.exit(0)

    if not isinstance(tool_input, dict):
        sys.exit(0)

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        sys.exit(0)

    # Locate tirith binary
    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"

    try:
        result = subprocess.run(
            [
                tirith_bin,
                "check",
                "--json",
                "--non-interactive",
                "--shell",
                "posix",
                "--",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # Fail open — tirith missing, timed out, or other OS error
        sys.exit(0)

    # Fail open if tirith produced no parseable JSON verdict (e.g. unknown flag)
    if result.returncode not in (0, 1, 2):
        sys.exit(0)
    if result.returncode != 0 and not result.stdout.strip():
        sys.exit(0)

    # Exit 0 = clean, allow
    if result.returncode == 0:
        sys.exit(0)

    # Exit 2 = warn — check TIRITH_HOOK_WARN_ACTION
    if result.returncode == 2:
        warn_action = os.environ.get("TIRITH_HOOK_WARN_ACTION", "deny").lower()
        if warn_action == "allow":
            sys.exit(0)

    # Exit 1 = block, Exit 2 + deny = block
    # Build reason from tirith JSON output
    reason = "Tirith security check failed"
    if result.stdout.strip():
        try:
            verdict = json.loads(result.stdout)
            findings = verdict.get("findings", [])
            if findings:
                parts = []
                for f in findings:
                    title = f.get("title", f.get("rule_id", "unknown"))
                    severity = f.get("severity", "")
                    parts.append(f"[{severity}] {title}" if severity else title)
                reason = "Tirith: " + "; ".join(parts)
        except json.JSONDecodeError:
            reason = result.stdout.strip()[:500]

    deny(reason)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Fail open on any unexpected error
        sys.exit(0)
