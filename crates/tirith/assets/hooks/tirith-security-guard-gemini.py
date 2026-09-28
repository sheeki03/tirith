#!/usr/bin/env python3
"""Gemini CLI BeforeTool hook — runs tirith check on shell tool calls.

Reads JSON from stdin (Gemini CLI hook protocol), extracts the command,
and delegates to `tirith check --json` for security analysis.

Exit codes:
  0 — hook completed successfully (decision in stdout JSON)
  Non-zero — hook error (fail-closed by default; set TIRITH_FAIL_OPEN=1 for fail-open)

Output (stdout, only for deny):
  {"decision": "deny", "reason": "..."}

Environment:
  TIRITH_BIN              — path to tirith binary (default: "tirith")
  TIRITH_HOOK_WARN_ACTION — "allow" (default) or "deny"
"""

import json
import os
import shutil
import subprocess
import sys
import time


# Optional telemetry owns its child until exit, or a bounded kill/reap attempt.
# These waits do not extend the checker or host timeout.
HOOK_EVENT_WAIT_SECONDS = 0.25
HOOK_EVENT_REAP_SECONDS = 0.25
_HOOK_CHECK_DEADLINE = None


def get(data, *keys):
    """Return the first matching key from data (supports dual-case fields)."""
    for k in keys:
        if k in data:
            return data[k]
    return None


def deny(reason):
    """Print a deny decision and exit 0."""
    print(json.dumps({"decision": "deny", "reason": reason}))
    sys.exit(0)


def fail_action():
    """Return the fail action: deny (default, fail-closed) or allow (fail-open via env)."""
    return "allow" if os.environ.get("TIRITH_FAIL_OPEN") == "1" else "deny"


def _hook_event(event, detail=None):
    """Log optional telemetry without leaving an ordinary background writer."""
    if (_HOOK_CHECK_DEADLINE is not None and
            time.monotonic() + HOOK_EVENT_WAIT_SECONDS + HOOK_EVENT_REAP_SECONDS >= _HOOK_CHECK_DEADLINE):
        return  # Telemetry cannot extend an exhausted check budget.
    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"
    child = None
    try:
        cmd = [
            tirith_bin,
            "hook-event",
            "--integration",
            "gemini-cli",
            "--hook-type",
            "before_tool",
            "--event",
            event,
        ]
        if detail:
            cmd.extend(["--detail", detail])
        child = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        child.wait(timeout=HOOK_EVENT_WAIT_SECONDS)
    except Exception:
        pass
    finally:
        if child is not None:
            try:
                if child.poll() is None:
                    try:
                        child.kill()
                    finally:
                        child.wait(timeout=HOOK_EVENT_REAP_SECONDS)
            except Exception:
                # A bounded wait cannot guarantee kernel reaping. Do not claim
                # cleanup or change the already selected security decision.
                print("tirith: optional hook telemetry unavailable", file=sys.stderr)


def _build_warning_text(stdout):
    """Extract finding titles from tirith JSON output into a human-readable string."""
    text = "Tirith security check failed"
    if stdout and stdout.strip():
        try:
            verdict = json.loads(stdout)
            findings = verdict.get("findings", [])
            if findings:
                parts = []
                for f in findings:
                    title = f.get("title", f.get("rule_id", "unknown"))
                    severity = f.get("severity", "")
                    parts.append(f"[{severity}] {title}" if severity else title)
                text = "Tirith: " + "; ".join(parts)
        except json.JSONDecodeError:
            text = stdout.strip()[:500]
    return text


def fail_closed(reason):
    """Deny or allow based on TIRITH_FAIL_OPEN, for error/missing-binary paths."""
    action = fail_action()
    if action == "deny":
        deny(reason)
    else:
        sys.exit(0)


def main():
    global _HOOK_CHECK_DEADLINE
    _HOOK_CHECK_DEADLINE = None
    try:
        raw = sys.stdin.read()
        if not raw.strip():
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

    # Defensive guard: only intercept BeforeTool + run_shell_command
    if event != "BeforeTool" or tool != "run_shell_command":
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
    env["TIRITH_INTEGRATION"] = "gemini-cli"
    _HOOK_CHECK_DEADLINE = time.monotonic() + 10.0

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
    if result.returncode not in (0, 1, 2):
        _hook_event("unexpected_exit", f"exit code {result.returncode}")
        fail_closed(f"tirith: unexpected exit code {result.returncode} — blocked for safety")
        return
    if result.returncode != 0 and not result.stdout.strip():
        _hook_event("unexpected_exit", f"exit code {result.returncode} with no output")
        fail_closed("tirith: check returned non-zero with no output — blocked for safety")
        return

    # Exit 0 = clean, allow
    if result.returncode == 0:
        _hook_event("check_ok")
        sys.exit(0)

    # Exit 2 = warn — check TIRITH_HOOK_WARN_ACTION
    if result.returncode == 2:
        warn_action = os.environ.get("TIRITH_HOOK_WARN_ACTION", "allow").lower()
        if warn_action not in ("allow", "deny"):
            print(
                f"tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='{warn_action}', defaulting to 'allow'",
                file=sys.stderr,
            )
            warn_action = "allow"
        if warn_action != "deny":
            _hook_event("warn_allowed")
            warning_text = _build_warning_text(result.stdout)
            print(warning_text, file=sys.stderr)
            sys.exit(0)

    # Exit 1 = block, Exit 2 + deny = block
    if result.returncode == 1:
        _hook_event("check_block")
    else:
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
        print(
            json.dumps(
                {"decision": "deny", "reason": "tirith: unexpected hook error — blocked for safety"}
            )
        )
        sys.exit(0)
