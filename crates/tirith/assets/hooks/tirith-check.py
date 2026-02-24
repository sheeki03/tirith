#!/usr/bin/env python3
"""Claude Code PreToolUse hook — runs tirith check on Bash tool calls.

Reads JSON from stdin (Claude Code hook protocol), extracts the command,
and delegates to `tirith check --json` for security analysis.

Exit codes:
  0 — hook completed successfully (decision in stdout JSON)
  Non-zero — hook error (fail-closed by default; set TIRITH_FAIL_OPEN=1 for fail-open)

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


def fail_action():
    """Return the fail action: deny (default, fail-closed) or allow (fail-open via env)."""
    return "allow" if os.environ.get("TIRITH_FAIL_OPEN") == "1" else "deny"


def fail_closed(reason):
    """Deny or allow based on TIRITH_FAIL_OPEN, for error/missing-binary paths."""
    action = fail_action()
    if action == "deny":
        deny(reason)
    else:
        sys.exit(0)


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            # Empty input — cannot determine command, fail-closed
            fail_closed("tirith: empty hook input — blocked for safety")
            return
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        fail_closed("tirith: failed to parse hook input — blocked for safety")
        return

    if not isinstance(data, dict):
        fail_closed("tirith: invalid hook input format — blocked for safety")
        return

    # Dual-case field extraction (camelCase and snake_case)
    event = get(data, "hook_event_name", "hookEventName")
    tool = get(data, "tool_name", "toolName")
    tool_input = get(data, "tool_input", "toolInput") or {}

    # Only intercept PreToolUse + Bash
    if event != "PreToolUse" or tool != "Bash":
        sys.exit(0)

    if not isinstance(tool_input, dict):
        fail_closed("tirith: invalid tool_input format — blocked for safety")
        return

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        fail_closed("tirith: no command found in hook input — blocked for safety")
        return

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
    except FileNotFoundError:
        fail_closed(f"tirith: {tirith_bin} not found — install tirith or set TIRITH_FAIL_OPEN=1")
        return
    except subprocess.TimeoutExpired:
        fail_closed("tirith: check timed out — blocked for safety")
        return
    except OSError as e:
        fail_closed(f"tirith: OS error running check — {e}")
        return

    # Unexpected exit code — fail-closed
    if result.returncode not in (0, 1, 2):
        fail_closed(f"tirith: unexpected exit code {result.returncode} — blocked for safety")
        return
    if result.returncode != 0 and not result.stdout.strip():
        fail_closed("tirith: check returned non-zero with no output — blocked for safety")
        return

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
        # Fail-closed on unexpected errors (respects TIRITH_FAIL_OPEN)
        if os.environ.get("TIRITH_FAIL_OPEN") == "1":
            sys.exit(0)
        # Deny — print structured output so Claude Code shows a message
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": "tirith: unexpected hook error — blocked for safety",
                    }
                }
            )
        )
        sys.exit(0)
