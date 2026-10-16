#!/usr/bin/env python3
"""Claude Code PreToolUse hook — runs tirith check on Bash tool calls.

Reads JSON from stdin (Claude Code hook protocol), extracts the command,
and delegates to `tirith check --json` for security analysis.

Approvals and mandatory acknowledgements are denied: this hook has no
confirmation channel. Warn-allow and TIRITH_FAIL_OPEN never bypass either gate.
Blocks (check exit 1) and deferred blocks (exit 4) are always denied.

Exit codes:
  0 — hook completed successfully (decision in stdout JSON)
  Non-zero — hook error (fail-closed by default; set TIRITH_FAIL_OPEN=1 for fail-open)

Output (stdout):
  For deny:
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
      "permissionDecision": "deny", "permissionDecisionReason": "..."}}
  For warn-allow:
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
      "permissionDecision": "allow", "permissionDecisionReason": "...",
      "additionalContext": "..."}}

Environment:
  TIRITH_BIN              — path to tirith binary (default: "tirith")
  TIRITH_HOOK_WARN_ACTION — "allow" (default) or "deny"
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


def _hook_event(event, detail=None):
    """Log a hook telemetry event via tirith hook-event (fire-and-forget)."""
    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"
    try:
        cmd = [
            tirith_bin,
            "hook-event",
            "--integration",
            "claude-code",
            "--hook-type",
            "pre_tool_use",
            "--event",
            event,
        ]
        if detail:
            cmd.extend(["--detail", detail])
        subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


def _build_warning_text(stdout):
    """Extract finding titles from tirith JSON output into a human-readable string."""
    text = "Tirith security check failed"
    if stdout and stdout.strip():
        try:
            verdict = json.loads(stdout)
            findings = verdict.get("findings", []) if isinstance(verdict, dict) else []
            if isinstance(findings, list):
                parts = []
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    title = f.get("title") or f.get("rule_id", "unknown")
                    severity = f.get("severity", "")
                    if not isinstance(title, str):
                        continue
                    parts.append(f"[{severity}] {title}" if isinstance(severity, str) and severity else title)
                if parts:
                    text = "Tirith: " + "; ".join(parts)
        except (ValueError, RecursionError):
            text = stdout.strip()[:500]
    return text


def warn_action():
    """Return the validated TIRITH_HOOK_WARN_ACTION: "allow" (default) or "deny"."""
    value = os.environ.get("TIRITH_HOOK_WARN_ACTION", "allow").lower()
    if value in ("allow", "deny"):
        return value
    print(
        f"tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='{value}', defaulting to 'allow'",
        file=sys.stderr,
    )
    return "allow"


def checker_error(returncode, reason):
    """Fail closed (or open) on a damaged response, never past an intact verdict.

    A warning the operator configured to deny stays denied when its response is
    damaged, so TIRITH_FAIL_OPEN cannot turn a denied warning into an allow.
    """
    if returncode == 2 and warn_action() == "deny":
        deny(reason)
    fail_closed(reason)


def _block_reason(returncode, stdout):
    """Describe a block; exit 4 is a deferred block awaiting `tirith pending` review."""
    reason = _build_warning_text(stdout)
    if returncode == 4:
        reason += " — blocked, pending review (deferred). Resolve with `tirith pending`."
    return reason


def _check_verdict(stdout):
    """Validate the approval contract before permitting analyzed execution."""
    try:
        verdict = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise ValueError("check returned invalid JSON") from error
    if not isinstance(verdict, dict) or not isinstance(verdict.get("requires_approval"), bool):
        raise ValueError(
            "check response is missing a boolean requires_approval; update tirith and re-run setup"
        )
    return verdict


def _approval_reason(verdict, stdout):
    """Use checker-redacted context, never the original secret-bearing command."""
    reason = "Tirith: approval or acknowledgement required"
    rule = verdict.get("approval_rule")
    if isinstance(rule, str) and rule:
        reason += f" ({rule})"
    reason += ". " + _build_warning_text(stdout)
    description = verdict.get("approval_description")
    if isinstance(description, str) and description:
        reason += ". " + description
    return (
        reason
        + " — blocked; this host hook cannot collect approval or acknowledgement. "
        "Review the command and retry from a Tirith-protected interactive shell to confirm it."
    )


def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            # Empty input — cannot determine command, fail-closed
            fail_closed("tirith: empty hook input — blocked for safety")
            return
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        _hook_event("parse_error")
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

    env = os.environ.copy()
    env["TIRITH_INTEGRATION"] = "claude-code"

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
            encoding="utf-8",
            errors="replace",
            timeout=10,
            env=env,
        )
    except FileNotFoundError:
        fail_closed(f"tirith: {tirith_bin} not found — install tirith or set TIRITH_FAIL_OPEN=1")
        return
    except subprocess.TimeoutExpired:
        _hook_event("timeout")
        fail_closed("tirith: check timed out — blocked for safety")
        return
    except OSError as e:
        _hook_event("unexpected_exit", str(e))
        fail_closed(f"tirith: OS error running check — {e}")
        return

    # Unexpected exit code — fail-closed
    if result.returncode not in (0, 1, 2, 3, 4):
        _hook_event("unexpected_exit", f"exit code {result.returncode}")
        fail_closed(f"tirith: unexpected exit code {result.returncode} — blocked for safety")
        return
    if result.returncode == 3:
        _hook_event("check_block")
        deny(_approval_reason({}, result.stdout))
    if result.returncode in (1, 4):
        # A block is a verdict, not a checker error, even with damaged output.
        # Exit 4 is a deferred block (pending review).
        _hook_event("check_block")
        deny(_block_reason(result.returncode, result.stdout))
    if not result.stdout.strip():
        _hook_event("unexpected_exit", f"exit code {result.returncode} with no output")
        checker_error(result.returncode, "tirith: check returned no output — blocked for safety")
        return
    try:
        verdict = _check_verdict(result.stdout)
    except ValueError as error:
        _hook_event("unexpected_exit", "invalid approval metadata")
        checker_error(result.returncode, f"tirith: {error} — blocked for safety")
        return
    if verdict["requires_approval"]:
        _hook_event("check_block")
        deny(_approval_reason(verdict, result.stdout))

    # Exit 0 = clean, allow
    if result.returncode == 0:
        _hook_event("check_ok")
        sys.exit(0)

    # Exit 2 = warn — check TIRITH_HOOK_WARN_ACTION
    if result.returncode == 2:
        if warn_action() != "deny":
            _hook_event("warn_allowed")
            warning_text = _build_warning_text(result.stdout)
            print(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow",
                            "permissionDecisionReason": warning_text,
                            "additionalContext": warning_text,
                        }
                    }
                )
            )
            sys.exit(0)

    # Exit 2 + deny = block.
    _hook_event("warn_denied")
    reason = _build_warning_text(result.stdout)
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
