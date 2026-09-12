#!/usr/bin/env python3
"""Native Claude tool-runner smoke evidence using a scripted loopback provider.

No model credentials, user configuration, project data, or remote model service
are used. This qualifies only the explicitly recorded host/binary/hook tuple and
three inert cases; it is not the complete real-agent release certification gate.
"""

import argparse
from contextlib import contextmanager
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile
import threading
import time


POLICY = """threat_intel:
  auto_update_hours: 0
  osv_enabled: false
  deps_dev_enabled: false
custom_rules:
  - id: native-agent-inert-block
    pattern: TIRITH_AGENT_BLOCK_MARKER
    severity: critical
    title: Inert native agent certification block
    context: [exec]
"""


@contextmanager
def fixture_directory(prefix):
    directory = tempfile.TemporaryDirectory(prefix=prefix)
    try:
        yield Path(directory.name)
    finally:
        # Existing hooks emit short detached telemetry writes. Let those finish
        # before removing their private root; never target other host state.
        for attempt in range(25):
            try:
                directory.cleanup()
                break
            except OSError:
                if attempt == 24:
                    raise
                time.sleep(0.1)


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def execute(argv, root, env, timeout=45):
    process = subprocess.Popen(
        argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Kill only this fixture's process group, including any hook children.
        import signal
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        return {"exit": None, "timed_out": True}, stdout, stderr
    return {"exit": process.returncode, "timed_out": False}, stdout, stderr


def isolated_env(root, binary):
    home = root / "home"
    env = {
        "HOME": str(home), "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_DATA_HOME": str(root / "data"), "XDG_STATE_HOME": str(root / "state"),
        "XDG_CACHE_HOME": str(root / "cache"), "TMPDIR": str(root / "tmp"),
        "CLAUDE_CONFIG_DIR": str(home / ".claude"),
        "PATH": os.pathsep.join([str(binary.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
        "SHELL": "/bin/zsh" if Path("/bin/zsh").exists() else "/bin/sh",
        "LANG": "C.UTF-8", "NO_COLOR": "1", "CI": "1",
        "TIRITH_BIN": str(binary), "TIRITH_OFFLINE": "1", "TIRITH_HOOK_WARN_ACTION": "deny",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1", "DISABLE_AUTOUPDATER": "1",
        "ANTHROPIC_API_KEY": "tirith-inert-loopback-fixture-not-a-credential",
        "ANTHROPIC_MODEL": "claude-sonnet-4-6", "ANTHROPIC_SMALL_FAST_MODEL": "claude-sonnet-4-6",
        "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "127.0.0.1,localhost",
    }
    for name in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                 "XDG_CACHE_HOME", "TMPDIR", "CLAUDE_CONFIG_DIR"]:
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    (root / "config/tirith").mkdir()
    (root / "config/tirith/policy.yaml").write_text(POLICY)
    return env


class Provider(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, command):
        super().__init__(("127.0.0.1", 0), ProviderHandler)
        self.command = command
        self.requests = 0
        self.tool_issued = 0
        self.tool_results = 0
        self.rejected = 0
        self.lock = threading.Lock()


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > 2 * 1024 * 1024:
            self.send_error(413)
            return
        try:
            request = json.loads(self.rfile.read(int(length)))
        except (ValueError, OSError):
            self.send_error(400)
            return
        with self.server.lock:
            self.server.requests += 1
            if self.server.requests > 32 or self.path.split("?")[0] != "/v1/messages":
                self.server.rejected += 1
                self.send_error(404)
                return
            names = [tool.get("name") for tool in request.get("tools", [])]
            for message in request.get("messages", []):
                content = message.get("content", [])
                if isinstance(content, list):
                    self.server.tool_results += sum(
                        item.get("type") == "tool_result" for item in content if isinstance(item, dict)
                    )
            emit_tool = "Bash" in names and self.server.tool_issued == 0
            if emit_tool:
                self.server.tool_issued += 1
        if emit_tool:
            block = {"type": "tool_use", "id": "toolu_tirith_fixture", "name": "Bash",
                     "input": {"command": self.server.command,
                               "description": "Execute the inert local certification marker once"}}
        else:
            block = {"type": "text", "text": "Inert local fixture finished."}
        message = {"id": "msg_tirith_fixture", "type": "message", "role": "assistant",
                   "model": "claude-sonnet-4-6", "content": [block],
                   "stop_reason": "tool_use" if emit_tool else "end_turn", "stop_sequence": None,
                   "usage": {"input_tokens": 1, "output_tokens": 1}}
        if request.get("stream"):
            start = dict(message, content=[], stop_reason=None)
            events = [("message_start", {"type": "message_start", "message": start})]
            initial = dict(block, input={}) if emit_tool else dict(block, text="")
            events.append(("content_block_start", {"type": "content_block_start", "index": 0,
                                                    "content_block": initial}))
            delta = ({"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                     if emit_tool else {"type": "text_delta", "text": block["text"]})
            events.extend([
                ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}),
                ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                ("message_delta", {"type": "message_delta", "delta": {
                    "stop_reason": message["stop_reason"], "stop_sequence": None},
                    "usage": {"output_tokens": 1}}),
                ("message_stop", {"type": "message_stop"}),
            ])
            body = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()
            content_type = "text/event-stream"
        else:
            body = json.dumps(message).encode()
            content_type = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_case(binary, host, case):
    with fixture_directory(prefix=f"tirith-native-claude-{case}-") as root:
        env = isolated_env(root, binary)
        project = root / "project"
        project.mkdir()
        setup, setup_stdout, setup_stderr = execute(
            [str(binary), "setup", "claude-code", "--scope", "user"], project, env, timeout=120,
        )
        if setup["exit"] != 0:
            return {"case": case, "passed": False, "stage": "setup", **setup,
                    "diagnostic": (setup_stdout + setup_stderr).decode(errors="replace")[-6000:]}
        settings = Path(env["HOME"]) / ".claude/settings.json"
        hook = settings.parent / "hooks/tirith-check.py"
        before = {"settings_sha256": digest(settings), "hook_sha256": digest(hook)}
        token = "TIRITH_AGENT_ALLOW_MARKER" if case == "allowed" else "TIRITH_AGENT_BLOCK_MARKER"
        marker = project / "execution-marker.txt"
        command = f"printf '%s\\n' {token} >> {shlex.quote(str(marker))}"
        preflight, output, _ = execute(
            [str(binary), "check", "--json", "--non-interactive", "--shell", "posix", "--", command],
            project, env,
        )
        if preflight["exit"] != (0 if case == "allowed" else 1):
            return {"case": case, "passed": False, "stage": "preflight", **preflight,
                    "diagnostic": output.decode(errors="replace")[-6000:]}
        if case == "hook-disabled":
            document = json.loads(settings.read_text())
            document.pop("hooks", None)
            settings.write_text(json.dumps(document))
        provider = Provider(command)
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{provider.server_port}"
        try:
            result, stdout, stderr = execute(
                [str(host), "--print", "--output-format", "stream-json", "--verbose",
                 "--no-session-persistence", "--setting-sources", "", "--settings", str(settings),
                 "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                 "--tools", "Bash", "--allowedTools", "Bash", "--permission-mode", "dontAsk",
                 "--permission-prompts", "none", "--include-hook-events",
                 "--system-prompt", "Execute only the inert local fixture tool call provided.",
                 "Run the single inert local certification command, then finish."],
                project, env, timeout=90,
            )
        finally:
            provider.shutdown()
            provider.server_close()
            thread.join(timeout=2)
        lines = marker.read_text().splitlines() if marker.exists() else []
        expected = [] if case == "blocked" else [token]
        parsed = []
        for line in stdout.decode(errors="replace").splitlines():
            try:
                parsed.append(json.loads(line))
            except ValueError:
                pass
        hook_events = sum("hook" in str(item.get("subtype", "")) for item in parsed)
        passed = (result["exit"] == 0 and provider.tool_issued == 1
                  and provider.tool_results >= 1 and lines == expected)
        report = {"case": case, "passed": passed, "stage": "native_host", **result, **before,
                  "provider_requests": provider.requests, "tool_calls_issued": provider.tool_issued,
                  "tool_result_observations": provider.tool_results, "rejected_provider_requests": provider.rejected,
                  "host_hook_events": hook_events, "marker_count": len(lines), "expected_marker_count": len(expected)}
        if not passed:
            report["diagnostic"] = (stdout + stderr).decode(errors="replace")[-12000:]
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tirith", type=Path, required=True)
    parser.add_argument("--claude", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this initial native-host fixture supports POSIX hosts only")
    # Managed configuration cannot be isolated by --setting-sources.
    for path in ["/Library/Application Support/ClaudeCode/managed-settings.json",
                 "/Library/Application Support/ClaudeCode/managed-mcp.json",
                 "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-mcp.json"]:
        if Path(path).exists():
            parser.error("managed host configuration is present; isolation cannot be established")
    binary, host = args.tirith.resolve(strict=True), args.claude.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="tirith-native-claude-version-") as temp:
        root = Path(temp)
        env = isolated_env(root, binary)
        versions = {}
        for name, path in [("tirith", binary), ("claude", host)]:
            result, stdout, _ = execute([str(path), "--version"], root, env)
            if result["exit"] != 0:
                parser.error(f"{name} version probe failed")
            versions[name] = {"path": str(path), "version": stdout.decode().strip(), "sha256": digest(path)}
    cases = []
    for case in ["allowed", "blocked", "hook-disabled"]:
        result = run_case(binary, host, case)
        cases.append(result)
        print(json.dumps({"case": case, "passed": result["passed"], "stage": result["stage"]}), flush=True)
    unchanged = digest(binary) == versions["tirith"]["sha256"] and digest(host) == versions["claude"]["sha256"]
    report = {"schema_version": 1, "evidence_kind": "scripted-provider-native-host",
              "recorded_unix": int(time.time()), "os": platform.platform(), "versions": versions,
              "scope": "explicit-settings Claude Bash tool on this host; standalone candidate bytes",
              "complete_release_certification": False, "binaries_unchanged_during_run": unchanged,
              "remaining": ["alternate tools", "MCP-only control", "timeout and crash",
                            "moved interpreter", "reload omission", "native Windows",
                            "beginner pilot", "real-model workflow"],
              "passed": unchanged and all(case["passed"] for case in cases), "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
