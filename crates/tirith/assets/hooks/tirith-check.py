#!/usr/bin/env python3
"""Pre-tool-use hook for shell tool calls, for every host that runs a command.

Reads JSON from stdin, extracts the command, and delegates to
`tirith check --json` for security analysis. Claude Code is the default wire
format; setup sets TIRITH_HOOK_PROTOCOL to select another host's event names,
decision envelope, and exit-code contract:

  claude-code (default) — PreToolUse/Bash, {"hookSpecificOutput": {...}}, exit 0
  grok-build            — pre_tool_use/run_terminal_command, {"decision": ...}
  cline                 — PreToolUse/execute_command or run_commands,
                          {"cancel": bool, ...}
  openhands             — pre_tool_use/terminal, {"decision": ...} and exit 2
                          on deny, because OpenHands treats any exit code other
                          than 0 or 2 as an error and lets the tool proceed.

Approvals and mandatory acknowledgements are denied: these adapters have no
confirmation channel. Warn-allow and TIRITH_FAIL_OPEN never bypass either gate.
Blocks (check exit 1) and deferred blocks (exit 4) are always denied.

A warning (check exit 2) is never an approval. By default the hook answers it
without a permission decision, so the host applies the user's own permission
rules exactly as if Tirith had not answered, and the warning reaches the user
and the agent through the host's message fields. Claude Code's "allow" skips
its permission prompt, so a warned command would otherwise be less gated than
a clean one.

Exit codes:
  0 — hook completed successfully (decision in stdout JSON)
  Non-zero — hook error (fail-closed by default; set TIRITH_FAIL_OPEN=1 for fail-open)

Output (stdout, claude-code):
  For deny:
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
      "permissionDecision": "deny", "permissionDecisionReason": "..."}}
  For a warning (default): no permission decision; `systemMessage` is shown to
  the user and `additionalContext` is added to the model's context:
    {"systemMessage": "...", "hookSpecificOutput": {"hookEventName":
      "PreToolUse", "additionalContext": "..."}}
  For a warning with TIRITH_HOOK_WARN_ACTION=ask (the reason is shown to the
  user in the permission prompt):
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
      "permissionDecision": "ask", "permissionDecisionReason": "...",
      "additionalContext": "..."}}

Environment:
  TIRITH_BIN              — path to tirith binary (default: "tirith")
  TIRITH_HOOK_PROTOCOL    — "claude-code" (default), "grok-build", "cline",
                            or "openhands"
  TIRITH_HOOK_WARN_ACTION — "allow" (default: pass the warning on and let the
                            host's own permission rules decide), "ask" (ask the
                            user to confirm; hosts without a confirmation prompt
                            deny instead), or "deny". Any other value denies.
  TIRITH_HOOK_UNRESOLVED_ACTION — "deny" (default) or "warn" when OpenHands
                            sends input to an unknown persistent process
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import time


# Optional telemetry owns its child until exit, or a bounded kill/reap attempt.
# These waits do not extend the checker or host timeout.
HOOK_EVENT_WAIT_SECONDS = 0.25
HOOK_EVENT_REAP_SECONDS = 0.25
_HOOK_CHECK_DEADLINE = None


MAX_HOOK_INPUT_BYTES = 2 * 1024 * 1024
MAX_COMMANDS = 16
MAX_COMMAND_BYTES = 1024 * 1024
MAX_ANALYSES = 48
CHECK_BUDGET_SECONDS = 10.0
OPENHANDS_SAFE_PROCESS_CONTROLS = frozenset(("C-c", "C-d", "C-z"))


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
            if action == "ask":
                # The reason is shown to the user in the prompt; the agent
                # learns why through its context.
                specific["additionalContext"] = reason
        output = {"hookSpecificOutput": specific}
    print(json.dumps(output))
    sys.exit(exit_code)


def warn_through(reason):
    """Pass a warning on without a permission decision, and exit.

    The host then applies its own permission rules exactly as for a command
    Tirith did not flag; the warning only adds information. Each protocol uses
    the fields its host delivers to the user and the agent.
    """
    proto = protocol()
    if proto == "grok-build":
        # A clean command gets no stdout, so neither does a warning. Grok
        # surfaces hook stderr, and its envelope has no reason field for allow.
        print(reason, file=sys.stderr)
        sys.exit(0)
    if proto == "cline":
        # `cancel: false` lets Cline's own approval settings decide, and
        # `contextModification` is delivered to the agent.
        output = {"cancel": False, "contextModification": reason}
    elif proto == "openhands":
        # OpenHands treats a missing decision like a clean command; the
        # executor reads `additionalContext` without one.
        output = {"additionalContext": reason}
    else:
        # Claude Code: `systemMessage` is shown to the user and
        # `additionalContext` reaches the model. With no permissionDecision the
        # normal permission flow runs (the user's allow, ask and deny rules and
        # the default prompt), so a warning never skips the prompt.
        output = {
            "systemMessage": reason,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": reason,
            },
        }
    print(json.dumps(output))
    sys.exit(0)


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


WARN_ACTIONS = ("allow", "ask", "deny")


def warn_action():
    """Return TIRITH_HOOK_WARN_ACTION: "allow" (default), "ask", "deny" or "invalid".

    An unrecognized value is "invalid", which callers treat as deny: a security
    setting that cannot be parsed fails closed rather than passing warnings.
    """
    value = (os.environ.get("TIRITH_HOOK_WARN_ACTION") or "allow").lower()
    return value if value in WARN_ACTIONS else "invalid"


def supports_ask():
    """Whether the selected host has a confirmation prompt a hook can request."""
    return protocol() not in ("grok-build", "cline", "openhands")


def warn_denial(action, warning_text):
    """Explain why a warning is denied under a non-allow warn action."""
    if action == "invalid":
        value = os.environ.get("TIRITH_HOOK_WARN_ACTION", "")
        return (
            f"tirith: unrecognized TIRITH_HOOK_WARN_ACTION={value!r} "
            "(valid values: allow, ask, deny) — warning blocked for safety. "
            + warning_text
        )
    if action == "ask":
        return (
            warning_text
            + " — blocked; TIRITH_HOOK_WARN_ACTION=ask needs a confirmation prompt"
            " this host hook does not have. Review the command and retry from a"
            " Tirith-protected interactive shell to confirm it."
        )
    return warning_text


def checker_error(returncode, reason):
    """Deny a damaged response unless TIRITH_FAIL_OPEN=1, never past an intact verdict.

    A warning the operator configured to gate (ask, deny, or an unrecognized
    value) stays denied when its response is damaged, so TIRITH_FAIL_OPEN cannot
    turn a gated warning into an allow. Under fail-open this returns, so the
    rest of a batch is still checked and a later command's block or approval
    still applies.
    """
    if returncode == 2 and warn_action() != "allow":
        deny(reason)
    if fail_action() == "deny":
        deny(reason)


def unresolved_action():
    """Return the action for execution whose real interpreter is unavailable."""
    if warn_action() != "allow":
        # Only hosts without a confirmation prompt reach this path, so ask and
        # an unrecognized warn action are as strict as deny here.
        return "deny"
    value = os.environ.get("TIRITH_HOOK_UNRESOLVED_ACTION", "deny").lower()
    if value in ("deny", "warn"):
        return value
    print(
        "tirith: warning: unrecognized TIRITH_HOOK_UNRESOLVED_ACTION="
        f"{value!r}, defaulting to 'deny'",
        file=sys.stderr,
    )
    return "deny"


def unresolved(reason):
    """Deny an uninspectable execution path, or visibly apply the opt-out."""
    _hook_event("unresolved_vector", reason)
    if unresolved_action() == "warn":
        warn_through(
            reason
            + " — allowed by TIRITH_HOOK_UNRESOLVED_ACTION=warn; the input was not inspected",
        )
    deny(
        reason
        + " — blocked; set TIRITH_HOOK_UNRESOLVED_ACTION=warn to opt out"
    )


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
            protocol(),
            "--hook-type",
            "pre_tool_use",
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


MAX_FIX_CHARS = 200


def _short_fix(remediation):
    """Return the first sentence of a finding's remediation, bounded."""
    if not isinstance(remediation, str):
        return ""
    text = " ".join(remediation.split())
    end = text.find(". ")
    if end != -1:
        text = text[: end + 1]
    if len(text) > MAX_FIX_CHARS:
        text = text[: MAX_FIX_CHARS - 3].rstrip() + "..."
    return text


def _warning_summary(stdout):
    """Describe warning findings: severity, title, rule id and a short fix."""
    try:
        verdict = json.loads(stdout)
    except (ValueError, RecursionError):
        return _build_warning_text(stdout)
    findings = verdict.get("findings") if isinstance(verdict, dict) else None
    parts = []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            rule = finding.get("rule_id")
            rule = rule if isinstance(rule, str) and rule else ""
            title = finding.get("title")
            if not isinstance(title, str) or not title:
                title = rule or "unknown"
            severity = finding.get("severity")
            part = f"[{severity}] {title}" if isinstance(severity, str) and severity else title
            if rule and rule != title:
                part += f" ({rule})"
            fix = _short_fix(finding.get("remediation"))
            if fix:
                part += f" — fix: {fix}"
            parts.append(part)
    if not parts:
        return "Tirith warning: the security check reported a warning"
    return "Tirith warning: " + "; ".join(parts)


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


def _json_object(value, label):
    """Accept a native object or the JSON-stringified object Cline emits."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError(f"{label} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _shells_for_hint(hint):
    """Map a host shell hint, or conservatively cover plausible Cline shells."""
    if hint is None or hint == "":
        # Cline does not consistently include the terminal profile in hook
        # payloads. Scan more than one grammar so PowerShell syntax cannot be
        # treated as a clean POSIX command (or vice versa).
        if os.name == "nt":
            return ["powershell", "cmd", "posix"]
        return ["posix", "powershell"]
    if not isinstance(hint, str):
        raise ValueError("shell hint must be a string")
    normalized = hint.strip().lower()
    aliases = {
        "sh": "posix",
        "bash": "posix",
        "zsh": "posix",
        "posix": "posix",
        "fish": "fish",
        "powershell": "powershell",
        "pwsh": "powershell",
        "cmd": "cmd",
        "cmd.exe": "cmd",
    }
    if normalized not in aliases:
        raise ValueError(f"unsupported shell hint: {hint}")
    return [aliases[normalized]]


def _command_for_shell(command, args, shell):
    if args is None:
        return command
    argv = [command] + args
    if shell in ("posix", "fish"):
        return shlex.join(argv)
    if shell == "powershell":
        return " ".join("'" + value.replace("'", "''") + "'" for value in argv)
    return subprocess.list2cmdline(argv)


def _cline_commands(pre):
    """Return (command, argv, shell-list) entries for both Cline generations."""
    tool = get(pre, "toolName", "tool")
    parameters = _json_object(get(pre, "parameters") or {}, "Cline parameters")
    parameter_hint = get(parameters, "shell", "shellType", "shell_type")

    if tool == "execute_command":
        command = parameters.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("execute_command.command must be a non-empty string")
        entries = [(command, None, _shells_for_hint(parameter_hint))]
    elif tool == "run_commands":
        commands = parameters.get("commands")
        if isinstance(commands, str):
            try:
                commands = json.loads(commands)
            except json.JSONDecodeError as error:
                raise ValueError(f"run_commands.commands is not valid JSON: {error}") from error
        if not isinstance(commands, list) or not commands:
            raise ValueError("run_commands.commands must be a non-empty array")
        if len(commands) > MAX_COMMANDS:
            raise ValueError(f"run_commands.commands exceeds the {MAX_COMMANDS}-command limit")
        entries = []
        for index, item in enumerate(commands):
            item_hint = parameter_hint
            args = None
            if isinstance(item, str):
                command = item
            elif isinstance(item, dict):
                command = item.get("command")
                item_hint = get(item, "shell", "shellType", "shell_type") or parameter_hint
                args = item.get("args")
                if args is not None and (
                    not isinstance(args, list)
                    or not all(isinstance(arg, str) for arg in args)
                ):
                    raise ValueError(f"run_commands.commands[{index}].args must be strings")
            else:
                raise ValueError(f"run_commands.commands[{index}] has an invalid shape")
            if not isinstance(command, str) or not command.strip():
                raise ValueError(f"run_commands.commands[{index}].command is empty")
            entries.append((command, args, _shells_for_hint(item_hint)))
    else:
        return tool, []

    analyses = sum(len(shells) for _, _, shells in entries)
    if analyses > MAX_ANALYSES:
        raise ValueError(f"Cline command batch exceeds the {MAX_ANALYSES}-analysis limit")
    for command, args, shells in entries:
        for shell in shells:
            rendered = _command_for_shell(command, args, shell)
            if len(rendered.encode("utf-8")) > MAX_COMMAND_BYTES:
                raise ValueError("Cline command exceeds the analysis size limit")
    return tool, entries


def _run_check(tirith_bin, command, shell, env, timeout):
    return subprocess.run(
        [
            tirith_bin,
            "check",
            "--json",
            "--non-interactive",
            "--shell",
            shell,
            "--",
            command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
    )


def main():
    global _HOOK_CHECK_DEADLINE
    _HOOK_CHECK_DEADLINE = None
    try:
        raw = sys.stdin.read(MAX_HOOK_INPUT_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_HOOK_INPUT_BYTES:
            fail_closed("tirith: hook input exceeds the safety limit")
            return
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
        # Cline nests the tool under `preToolUse`. Older releases used
        # execute_command; current releases batch shell work in run_commands.
        event = get(data, "hookName") or event
        pre = get(data, "preToolUse") or {}
        try:
            pre = _json_object(pre, "Cline preToolUse")
            tool, cline_commands = _cline_commands(pre)
        except ValueError as error:
            fail_closed(f"tirith: malformed Cline command payload — {error}")
            return
        is_shell_pretool = event == "PreToolUse" and tool in (
            "execute_command",
            "run_commands",
        )
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
        if proto == "cline":
            # Cline parses stdout for every hook invocation; a silent success
            # is reported as a hook error even for tools Tirith does not guard.
            decision("allow")
        sys.exit(0)

    if not isinstance(tool_input, dict):
        fail_closed("tirith: invalid tool_input format — blocked for safety")
        return

    if proto == "cline":
        command_specs = cline_commands
    else:
        command = tool_input.get("command")
        if proto == "openhands":
            is_input = tool_input.get("is_input", False)
            if not isinstance(is_input, bool):
                fail_closed("tirith: OpenHands is_input must be a boolean — blocked for safety")
                return
            if is_input:
                if not isinstance(command, str):
                    fail_closed("tirith: OpenHands process input must be a string — blocked for safety")
                    return
                if command == "" or command in OPENHANDS_SAFE_PROCESS_CONTROLS:
                    # An empty input only polls for output. These exact control
                    # tokens interrupt, suspend, or close the process; unlike a
                    # newline, none can complete buffered executable text.
                    decision("allow")
                unresolved(
                    "tirith: OpenHands process input targets a persistent process "
                    "whose interpreter is not present in the hook event"
                )
        if not isinstance(command, str) or not command.strip():
            fail_closed("tirith: no command found in hook input — blocked for safety")
            return
        command_specs = [(command, None, ["posix"])]

    # Locate tirith binary
    tirith_bin = os.environ.get("TIRITH_BIN") or shutil.which("tirith") or "tirith"

    env = os.environ.copy()
    env["TIRITH_INTEGRATION"] = proto

    deadline = time.monotonic() + CHECK_BUDGET_SECONDS
    _HOOK_CHECK_DEADLINE = deadline
    warning_texts = []
    skipped = False
    for command, args, shells in command_specs:
        for shell in shells:
            rendered = _command_for_shell(command, args, shell)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _hook_event("timeout")
                fail_closed("tirith: command batch exceeded the check budget")
                return
            try:
                result = _run_check(tirith_bin, rendered, shell, env, remaining)
            except FileNotFoundError:
                fail_closed(
                    f"tirith: {tirith_bin} not found — install tirith or set TIRITH_FAIL_OPEN=1"
                )
                return
            except subprocess.TimeoutExpired:
                _hook_event("timeout")
                fail_closed("tirith: check timed out — blocked for safety")
                return
            except OSError as error:
                _hook_event("unexpected_exit", str(error))
                fail_closed(f"tirith: OS error running check — {error}")
                return

            if result.returncode not in (0, 1, 2, 3, 4):
                _hook_event("unexpected_exit", f"exit code {result.returncode}")
                checker_error(
                    result.returncode,
                    f"tirith: unexpected exit code {result.returncode} — blocked for safety",
                )
                skipped = True
                continue
            if result.returncode == 3:
                _hook_event("check_block")
                deny(_approval_reason({}, result.stdout))
            if result.returncode in (1, 4):
                # A block is a verdict, not a checker error, even with damaged
                # output. Exit 4 is a deferred block (pending review).
                _hook_event("check_block")
                deny(_block_reason(result.returncode, result.stdout))
            if not result.stdout.strip():
                _hook_event(
                    "unexpected_exit", f"exit code {result.returncode} with no output"
                )
                checker_error(
                    result.returncode,
                    "tirith: check returned no output — blocked for safety",
                )
                skipped = True
                continue
            try:
                verdict = _check_verdict(result.stdout)
            except ValueError as error:
                _hook_event("unexpected_exit", "invalid approval metadata")
                checker_error(result.returncode, f"tirith: {error} — blocked for safety")
                skipped = True
                continue
            if verdict["requires_approval"]:
                _hook_event("check_block")
                deny(_approval_reason(verdict, result.stdout))
            if result.returncode == 2:
                warning_texts.append(_warning_summary(result.stdout))

    if not warning_texts:
        if not skipped:
            _hook_event("check_ok")
        if proto == "cline":
            print(json.dumps({"cancel": False}))
        sys.exit(0)

    # Exit 2 = warn. TIRITH_HOOK_WARN_ACTION selects how it is answered; none of
    # the answers is a permission grant.
    warning_text = "; ".join(dict.fromkeys(warning_texts))[:2000]
    action = warn_action()
    if action == "allow":
        _hook_event("warn_allowed")
        warn_through(warning_text)
    if action == "ask" and supports_ask():
        _hook_event("warn_ask")
        decision("ask", warning_text)
    _hook_event("warn_denied")
    deny(warn_denial(action, warning_text))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Fail-closed on unexpected errors (respects TIRITH_FAIL_OPEN)
        if os.environ.get("TIRITH_FAIL_OPEN") == "1":
            sys.exit(0)
        # Deny with the selected host's structured output.
        deny("tirith: unexpected hook error — blocked for safety")
