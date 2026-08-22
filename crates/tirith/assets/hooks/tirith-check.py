#!/usr/bin/env python3
"""Pre-tool-use hook for shell tool calls, for every host that runs a command.

Reads JSON from stdin, extracts the command, and delegates to
`tirith check --json` for security analysis. Claude Code is the default wire
format; setup sets TIRITH_HOOK_PROTOCOL to select another host's event names,
decision envelope, and exit-code contract:

  claude-code (default) — PreToolUse/Bash, {"hookSpecificOutput": {...}}, exit 0
  grok-build            — pre_tool_use/run_terminal_command, {"decision": ...}
  cline                 — PreToolUse/execute_command, {"cancel": bool, ...}
  openhands             — pre_tool_use/terminal, {"decision": ...} and exit 2
                          on deny, because OpenHands treats any exit code other
                          than 0 or 2 as an error and lets the tool proceed.

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
  TIRITH_HOOK_PROTOCOL    — "claude-code" (default), "grok-build", "cline",
                            or "openhands"
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


def protocol():
    """Return the setup-selected host protocol."""
    return os.environ.get("TIRITH_HOOK_PROTOCOL", "claude-code").lower()


def decision(action, reason=None):
    """Print one host-native PreToolUse decision and exit with its own code."""
    proto = protocol()
    exit_code = 0
    if proto == "grok-build":
        output = {"decision": action}
        if action == "deny" and reason:
            output["reason"] = reason
        elif reason:
            # Grok's decision envelope carries a reason only for deny, so a
            # warn-allow would otherwise be discarded and the user would never
            # learn why the command was flagged. Grok surfaces hook stderr, so
            # send the finding there rather than dropping it.
            print(reason, file=sys.stderr)
    elif proto == "cline":
        # Cline reads `cancel`, and shows `errorMessage` when it is true.
        output = {"cancel": action == "deny"}
        if reason:
            if action == "deny":
                output["errorMessage"] = reason
            else:
                # A warn-allow has no error to show, but `contextModification`
                # is delivered to the agent, so the finding is not lost.
                output["contextModification"] = reason
    elif proto == "openhands":
        # OpenHands treats exit 2 as the block and lets the JSON `decision`
        # override the exit code. Anything OTHER than 0 or 2 is an error, and
        # an error lets the operation proceed, so a deny must exit exactly 2.
        output = {"decision": "deny" if action == "deny" else "allow"}
        if reason:
            if action == "deny":
                output["reason"] = reason
                exit_code = 2
            else:
                output["additionalContext"] = reason
        elif action == "deny":
            exit_code = 2
    else:
        specific = {
            "hookEventName": "PreToolUse",
            "permissionDecision": action,
        }
        if reason:
            specific["permissionDecisionReason"] = reason
            if action == "allow":
                specific["additionalContext"] = reason
        output = {"hookSpecificOutput": specific}
    print(json.dumps(output))
    sys.exit(exit_code)


def deny(reason):
    """Print a deny decision and exit 0 so the host parses stdout."""
    decision("deny", reason)


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
            protocol(),
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
    proto = protocol()
    event = get(data, "hook_event_name", "hookEventName")
    tool = get(data, "tool_name", "toolName")
    tool_input = get(data, "tool_input", "toolInput") or {}

    if proto == "cline":
        # Cline nests the tool under `preToolUse` and names the shell tool
        # `execute_command`, with the command in `parameters`.
        event = get(data, "hookName") or event
        pre = get(data, "preToolUse") or {}
        if isinstance(pre, dict):
            tool = get(pre, "toolName") or tool
            tool_input = get(pre, "parameters") or {}
        is_shell_pretool = event == "PreToolUse" and tool == "execute_command"
    elif proto == "openhands":
        # OpenHands serializes its pydantic `HookEvent` to stdin, whose event
        # field is `event_type` with the CamelCase value `PreToolUse`. The
        # Claude-compatible spellings are accepted too, because its docs say
        # hook scripts can be shared with Claude Code, but `event_type` is what
        # the real executor sends and is the one that must work.
        event = get(data, "event_type") or event
        is_shell_pretool = event in ("pre_tool_use", "PreToolUse") and tool in (
            "terminal",
            "Bash",
        )
    elif proto == "grok-build":
        # Grok's native envelope uses pre_tool_use/run_terminal_command while
        # its Claude-compatible matcher is named PreToolUse/Bash.
        is_shell_pretool = event in ("pre_tool_use", "PreToolUse") and tool in (
            "run_terminal_command",
            "Bash",
        )
    else:
        is_shell_pretool = event == "PreToolUse" and tool == "Bash"
    if not is_shell_pretool:
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
    env["TIRITH_INTEGRATION"] = proto

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

    # Exit 0 = clean, allow. Cline reads a decision object from stdout and logs
    # an error on empty output, so it gets an explicit allow; every other host
    # treats a silent exit 0 as allow.
    if result.returncode == 0:
        _hook_event("check_ok")
        if proto == "cline":
            print(json.dumps({"cancel": False}))
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
            decision("allow", warning_text)

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
        # Deny with the selected host's structured output.
        deny("tirith: unexpected hook error — blocked for safety")
