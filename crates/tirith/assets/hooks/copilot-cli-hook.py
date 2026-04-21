#!/usr/bin/env python3
"""GitHub Copilot CLI preToolUse hook — runs tirith check on bash tool calls.

Reads JSON from stdin (Copilot CLI hook protocol), parses the bash command
out of the JSON-encoded `toolArgs` field, and delegates to `tirith check
--json` for security analysis.

Exit codes:
  0 — hook completed (decision in stdout JSON if any).
  Non-zero — never. Copilot ignores hook exit codes; the deny decision is
              communicated via stdout JSON.

Output (stdout, only for deny):
  {"permissionDecision": "deny", "permissionDecisionReason": "..."}

For allow / warn-allow, no stdout output is emitted (Copilot's docs do not
document a stderr-findings path for preToolUse, so we don't rely on it).

Environment:
  TIRITH_BIN              — path to tirith binary (default: "tirith")
  TIRITH_HOOK_WARN_ACTION — "allow" (default) or "deny"
  TIRITH_FAIL_OPEN        — set to "1" to allow on missing binary / errors
"""

import json
import os
import shutil
import subprocess
import sys


def deny(reason):
    """Print a deny decision and exit 0."""
    print(json.dumps({
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }))
    sys.exit(0)


def fail_action():
    """Return the fail action: deny (default, fail-closed) or allow (fail-open via env)."""
    return "allow" if os.environ.get("TIRITH_FAIL_OPEN") == "1" else "deny"


def fail_closed(reason):
    """Deny or allow based on TIRITH_FAIL_OPEN, for error/missing-binary paths."""
    if fail_action() == "deny":
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
            "copilot-cli",
            "--hook-type",
            "pre_tool_use",
            "--event",
            event,
        ]
        if detail:
            cmd.extend(["--detail", detail])
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _build_reason(stdout):
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


def _extract_command(data):
    """Pull the bash command string out of Copilot's preToolUse stdin JSON.

    Copilot wire format: {timestamp, cwd, toolName, toolArgs}.
    `toolArgs` is a JSON-encoded *string* containing {"command": "..."}.

    Returns a (kind, value) tuple:
      ("allow", None)   — not a bash tool call, silent allow
      ("deny", reason)  — bash tool call with malformed payload, fail-closed
      ("check", cmd)    — bash tool call with extractable command, scan it

    The tri-state separation matters: collapsing 'not bash' and 'malformed
    bash payload' into a single None would let a bash call with a broken
    toolArgs slip through, which is the exact case this hook is meant to
    guard against.
    """
    if data.get("toolName") != "bash":
        return ("allow", None)
    raw = data.get("toolArgs", "")
    if isinstance(raw, str):
        try:
            args = json.loads(raw)
        except json.JSONDecodeError:
            return ("deny", "tirith: malformed toolArgs JSON for bash tool — blocked for safety")
    elif isinstance(raw, dict):
        args = raw
    else:
        return ("deny", "tirith: unexpected toolArgs type for bash tool — blocked for safety")
    if not isinstance(args, dict):
        return ("deny", "tirith: toolArgs did not decode to an object — blocked for safety")
    cmd = args.get("command")
    if isinstance(cmd, str) and cmd.strip():
        return ("check", cmd)
    return ("deny", "tirith: missing or empty 'command' in bash toolArgs — blocked for safety")


def main():
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

    kind, value = _extract_command(data)
    if kind == "allow":
        # Not a bash tool call — silent allow.
        sys.exit(0)
    if kind == "deny":
        _hook_event("malformed_payload")
        fail_closed(value)
        return
    command = value

    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"
    env = os.environ.copy()
    env["TIRITH_INTEGRATION"] = "copilot-cli"

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

    if result.returncode not in (0, 1, 2):
        _hook_event("unexpected_exit", f"exit code {result.returncode}")
        fail_closed(f"tirith: unexpected exit code {result.returncode} — blocked for safety")
        return
    if result.returncode != 0 and not result.stdout.strip():
        _hook_event("unexpected_exit", f"exit code {result.returncode} with no output")
        fail_closed("tirith: check returned non-zero with no output — blocked for safety")
        return

    if result.returncode == 0:
        _hook_event("check_ok")
        sys.exit(0)

    if result.returncode == 2:
        warn_action = os.environ.get("TIRITH_HOOK_WARN_ACTION", "allow").lower()
        if warn_action not in ("allow", "deny"):
            warn_action = "allow"
        if warn_action != "deny":
            _hook_event("warn_allowed")
            sys.exit(0)
        _hook_event("warn_denied")
    else:
        _hook_event("check_block")

    deny(_build_reason(result.stdout))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        if os.environ.get("TIRITH_FAIL_OPEN") == "1":
            sys.exit(0)
        print(json.dumps({
            "permissionDecision": "deny",
            "permissionDecisionReason": "tirith: unexpected hook error — blocked for safety",
        }))
        sys.exit(0)
