#!/usr/bin/env python3
"""Kiro CLI preToolUse hook — runs tirith check on execute_bash tool calls.

Reads JSON from stdin (Kiro CLI hook protocol), extracts the bash command
from `tool_input`, and delegates to `tirith check --json` for security
analysis.

Exit codes (Kiro contract):
  0 — allow (silent)
  2 — block tool execution; stderr is relayed to the LLM as the reason
  Other — Kiro displays a warning but allows execution; we treat as fail
          (deny + exit 2 by default; allow + exit 0 with TIRITH_FAIL_OPEN=1)

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
    """Print reason to stderr (relayed to LLM) and exit 2 (Kiro block)."""
    print(reason, file=sys.stderr)
    sys.exit(2)


def fail_action():
    return "allow" if os.environ.get("TIRITH_FAIL_OPEN") == "1" else "deny"


def fail_closed(reason):
    if fail_action() == "deny":
        deny(reason)
    else:
        sys.exit(0)


def _hook_event(event, detail=None):
    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"
    try:
        cmd = [
            tirith_bin,
            "hook-event",
            "--integration",
            "kiro",
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
    """Pull the bash command out of Kiro's preToolUse stdin JSON.

    Kiro wire format: {hook_event_name, cwd, session_id, tool_name, tool_input}.
    Tool name for shell is "execute_bash" (canonical) or "shell" (alias).
    `tool_input` is an object containing {"command": "..."} for bash tools.

    Returns a (kind, value) tuple:
      ("allow", None)   — not a shell tool call, silent allow
      ("deny", reason)  — shell tool call with malformed payload, fail-closed
      ("check", cmd)    — shell tool call with extractable command, scan it

    The tri-state separation matters: collapsing 'not shell' and 'malformed
    shell payload' into a single None would let a shell call with a broken
    tool_input slip through, which is the exact case this hook is meant to
    guard against.
    """
    tool = data.get("tool_name") or data.get("toolName")
    if tool not in ("execute_bash", "shell"):
        return ("allow", None)
    tool_input = data.get("tool_input") or data.get("toolInput")
    if tool_input is None:
        return ("deny", "tirith: missing tool_input for shell tool — blocked for safety")
    if not isinstance(tool_input, dict):
        return ("deny", "tirith: tool_input is not an object for shell tool — blocked for safety")
    cmd = tool_input.get("command")
    if isinstance(cmd, str) and cmd.strip():
        return ("check", cmd)
    return ("deny", "tirith: missing or empty 'command' in shell tool_input — blocked for safety")


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
        # Not a shell tool call — silent allow.
        sys.exit(0)
    if kind == "deny":
        _hook_event("malformed_payload")
        fail_closed(value)
        return
    command = value

    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"
    env = os.environ.copy()
    env["TIRITH_INTEGRATION"] = "kiro"

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
        print("tirith: unexpected hook error — blocked for safety", file=sys.stderr)
        sys.exit(2)
