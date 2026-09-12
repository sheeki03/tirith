#!/usr/bin/env python3
"""Native Claude tool-runner smoke evidence using a scripted loopback provider.

No model credentials, user configuration, project data, or remote model service
are used. This qualifies only the explicitly recorded host/binary/hook tuple and
inert cases selected below; it is not the complete real-agent release certification gate.
"""

import argparse
import errno
from contextlib import contextmanager
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import socket
import shlex
import shutil
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
        hasher = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
        return hasher.hexdigest()


MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024


def bytes_evidence(value):
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


class BoundedProcess:
    """Own one new process group, bounded pipes and a finite reap deadline."""

    def __init__(self, argv, root, env, interactive=False, output_limit=MAX_OUTPUT_BYTES):
        self.process = subprocess.Popen(
            argv, cwd=root, env=env,
            stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        self.selector = selectors.DefaultSelector()
        self.stdout, self.stderr = bytearray(), bytearray()
        self.output_limit = output_limit
        self.failure = None
        self.closed = False
        self.record_offset = 0
        for stream, name in [(self.process.stdout, "stdout"), (self.process.stderr, "stderr")]:
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)
        if interactive:
            os.set_blocking(self.process.stdin.fileno(), False)

    def pump(self, timeout):
        for key, _ in self.selector.select(timeout):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                self.selector.unregister(key.fileobj)
                continue
            remaining = self.output_limit - len(self.stdout) - len(self.stderr)
            getattr(self, key.data).extend(data[:max(0, remaining)])
            if len(data) > remaining:
                self.failure = "output_limit"
                raise RuntimeError("bounded host output exceeded")

    def send(self, message):
        payload = (json.dumps({"type": "user", "message": {
            "role": "user", "content": message}}) + "\n").encode()
        if len(payload) > 65536:
            raise ValueError("fixture input exceeds its bound")
        deadline = time.monotonic() + 5
        with selectors.DefaultSelector() as ready:
            ready.register(self.process.stdin, selectors.EVENT_WRITE)
            while payload:
                if time.monotonic() >= deadline or self.process.poll() is not None:
                    raise RuntimeError("native host input deadline or early exit")
                if ready.select(min(0.1, max(0, deadline - time.monotonic()))):
                    try:
                        count = os.write(self.process.stdin.fileno(), payload)
                    except BlockingIOError:
                        continue
                    payload = payload[count:]

    def read_turn(self, timeout=90):
        deadline = time.monotonic() + timeout
        events = []
        while time.monotonic() < deadline:
            while True:
                end = self.stdout.find(b"\n", self.record_offset)
                if end < 0:
                    if len(self.stdout) - self.record_offset > MAX_LINE_BYTES:
                        raise RuntimeError("bounded host line exceeded")
                    break
                if end - self.record_offset > MAX_LINE_BYTES:
                    raise RuntimeError("bounded host line exceeded")
                line = self.stdout[self.record_offset:end]
                self.record_offset = end + 1
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                events.append(event)
                if event.get("type") == "result":
                    return events
            if self.process.poll() is not None and not self.selector.get_map():
                raise RuntimeError("native host ended before its next result")
            self.pump(min(0.1, max(0, deadline - time.monotonic())))
        raise RuntimeError("native host result deadline")

    def close(self):
        if self.closed:
            return self.cleanup
        # Publish a complete conservative result before cleanup can encounter an
        # error. A second close always returns that same recorded result.
        self.cleanup = {"leader_reaped": False, "output_eof": False,
                        "process_group_cleanup_requested": False}
        self.cleanup_error = None
        self.closed = True
        deadline = time.monotonic() + 3
        try:
            while time.monotonic() < deadline:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.cleanup["process_group_cleanup_requested"] = True
                except OSError as error:
                    if error.errno == errno.ESRCH:
                        self.cleanup["process_group_cleanup_requested"] = True
                    elif error.errno != errno.EPERM:
                        self.cleanup_error = "process_group_signal_error"
                        break
                    # Darwin may return EPERM while this owned child is exiting.
                    # Wait only for our child and retry; permission denial alone
                    # never establishes either group cleanup or successful reap.
                try:
                    self.process.wait(timeout=min(0.05, max(0, deadline - time.monotonic())))
                    self.cleanup["leader_reaped"] = True
                except subprocess.TimeoutExpired:
                    pass
                if all((self.cleanup["leader_reaped"], self.cleanup["process_group_cleanup_requested"])):
                    break
                time.sleep(0.01)
            if not self.cleanup["process_group_cleanup_requested"] and self.cleanup_error is None:
                self.cleanup_error = "process_group_permission_deadline"
            if not self.cleanup["leader_reaped"]:
                # Last bounded attempt targets only the Popen-owned leader.
                # It cannot repair a failed group cleanup claim.
                try:
                    self.process.kill()
                except OSError:
                    self.cleanup_error = self.cleanup_error or "owned_child_signal_error"
                try:
                    self.process.wait(timeout=2)
                    self.cleanup["leader_reaped"] = True
                except subprocess.TimeoutExpired:
                    self.cleanup_error = self.cleanup_error or "owned_child_reap_deadline"
            deadline = time.monotonic() + 2
            while self.selector.get_map() and time.monotonic() < deadline and self.failure is None:
                try:
                    self.pump(0.05)
                except (OSError, RuntimeError):
                    self.cleanup_error = self.cleanup_error or "output_drain_error"
                    break
            self.cleanup["output_eof"] = not self.selector.get_map()
        finally:
            self.selector.close()
            for stream in [self.process.stdin, self.process.stdout, self.process.stderr]:
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        self.cleanup_error = self.cleanup_error or "pipe_close_error"
        return self.cleanup


def execute(argv, root, env, timeout=45):
    started = time.monotonic()
    child = BoundedProcess(argv, root, env)
    timed_out = False
    exit_code = None
    try:
        deadline = time.monotonic() + timeout
        while child.process.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            child.pump(min(0.1, max(0, deadline - time.monotonic())))
        if not timed_out:
            exit_code = child.process.poll()
    except RuntimeError:
        pass
    finally:
        cleanup = child.close()
    stdout, stderr = bytes(child.stdout), bytes(child.stderr)
    return {"exit": exit_code, "timed_out": timed_out,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "output_limit_exceeded": child.failure == "output_limit", "cleanup": cleanup,
            "cleanup_error": child.cleanup_error,
            "stdout": bytes_evidence(stdout), "stderr": bytes_evidence(stderr)}, stdout, stderr


def execution_ok(result):
    return (result["exit"] == 0 and not result["timed_out"]
            and not result.get("output_limit_exceeded", False) and not result.get("cleanup_error")
            and result.get("cleanup", {}).get("leader_reaped", False)
            and result.get("cleanup", {}).get("output_eof", False))


def policy_check_ok(result, output, action):
    try:
        value = json.loads(output)
    except (ValueError, TypeError):
        return False
    return (isinstance(value, dict) and value.get("action") == action
            and result.get("exit") == (0 if action == "allow" else 1)
            and not result.get("timed_out", True) and not result.get("output_limit_exceeded", True)
            and not result.get("cleanup_error")
            and result.get("cleanup", {}).get("leader_reaped", False)
            and result.get("cleanup", {}).get("output_eof", False))


def json_events(output):
    result = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            result.append(item)
    return result


def hook_count(events):
    return sum("hook" in str(event.get("subtype", "")) for event in events)


def successful_turn(events):
    results = [event for event in events if event.get("type") == "result"]
    return len(results) == 1 and results[0].get("is_error") is False


def provider_facts(provider):
    with provider.lock:
        return {"provider_requests": provider.requests,
                "tool_calls_issued": provider.tool_issued,
                "tool_result_observations": provider.tool_results,
                "rejected_provider_requests": provider.rejected}


def stop_provider(provider, thread):
    provider.shutdown()
    provider.server_close()
    thread.join(timeout=2)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with provider.connection_lock:
            if not provider.connections:
                break
        time.sleep(0.01)
    with provider.connection_lock:
        if thread.is_alive() or provider.connections:
            raise RuntimeError("fixture provider did not stop within its cleanup bound")


@contextmanager
def running_provider(provider, env):
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{provider.server_port}"
    try:
        yield provider
    finally:
        stop_provider(provider, thread)


def isolated_env(root, binary, python=None, claude_invocation=None):
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
    if python is not None:
        selected_dirs = [str(binary.parent), str(python.parent)]
        if claude_invocation is not None:
            selected_dirs.append(str(claude_invocation.parent))
        env["PATH"] = os.pathsep.join(dict.fromkeys(selected_dirs + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]))
        if Path(shutil.which("python3", path=env["PATH"]) or "missing").resolve() != python.resolve():
            raise ValueError("fixture PATH does not select the requested Python executable")
        if claude_invocation is not None and Path(shutil.which("claude", path=env["PATH"]) or "missing").resolve() != claude_invocation.resolve():
            raise ValueError("fixture PATH does not select the requested native Claude executable")
    for name in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                 "XDG_CACHE_HOME", "TMPDIR", "CLAUDE_CONFIG_DIR"]:
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    (root / "config/tirith").mkdir()
    (root / "config/tirith/policy.yaml").write_text(POLICY)
    return env


class Provider(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, command, write_target=None):
        super().__init__(("127.0.0.1", 0), ProviderHandler)
        self.command = command
        self.tool_name = "Write" if write_target else "Bash"
        self.tool_input = ({"file_path": str(write_target), "content": "TIRITH_AGENT_BLOCK_MARKER\n"}
                           if write_target else {"command": command,
                           "description": "Execute the inert local certification marker once"})
        self.requests = 0
        self.tool_issued = 0
        self.tool_results = 0
        self.rejected = 0
        self.lock = threading.Lock()
        self.tool_sequence = 0
        self.expected_tool_id = None
        self.connection_slots = threading.BoundedSemaphore(8)
        self.connections = set()
        self.connection_lock = threading.Lock()

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.connection_lock:
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.connection_lock:
                self.connections.discard(request)
            self.connection_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.discard(request)
            self.connection_slots.release()

    def server_close(self):
        with self.connection_lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        super().server_close()


class ProviderHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def do_POST(self):
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > 2 * 1024 * 1024:
            self.send_error(413)
            return
        try:
            request = json.loads(self.rfile.read(int(length)))
            if not isinstance(request, dict):
                raise ValueError("provider request must be an object")
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
                        item.get("type") == "tool_result" and item.get("tool_use_id") == self.server.expected_tool_id
                        for item in content if isinstance(item, dict)
                    )
            emit_tool = self.server.tool_name in names and self.server.tool_issued == 0
            if emit_tool:
                self.server.tool_issued += 1
                self.server.tool_sequence += 1
                self.server.expected_tool_id = f"toolu_tirith_fixture_{self.server.tool_sequence}"
            tool_id = self.server.expected_tool_id
        if emit_tool:
            block = {"type": "tool_use", "id": tool_id,
                     "name": self.server.tool_name, "input": self.server.tool_input}
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


BASELINE_CASES = ("allowed", "blocked", "hook-disabled")
FAILURE_CASES = ("interpreter-unavailable", "checker-unavailable", "hook-crash",
                 "checker-deadline", "shortened-host-timeout", "unmatched-write")
BOUNDARY_CASES = ("hook-disabled", "shortened-host-timeout", "unmatched-write")


def combined_parts(command):
    if not command.startswith("TIRITH_BIN="):
        return None
    parts = shlex.split(command)
    if len(parts) != 8 or not parts[0].startswith("TIRITH_BIN=") or parts[2:4] != ["-I", "-S"] or parts[5:] != ["||", "exit", "2"]:
        raise ValueError("combined launcher changed from the exact fixture contract")
    binary = parts[0].split("=", 1)[1]
    if not all(Path(value).is_absolute() for value in [binary, parts[1], parts[4]]) or not parts[4].endswith("/.claude/hooks/tirith-check.py"):
        raise ValueError("combined launcher paths are not fixed absolute inputs")
    return [binary, parts[1], parts[4]]


def combined_command(parts):
    return f"TIRITH_BIN={shlex.quote(parts[0])} {shlex.quote(parts[1])} -I -S {shlex.quote(parts[2])} || exit 2"


def apply_control(root, env, settings, hook, case):
    """Mutate only private fixture inputs; preserve the generated launcher guard."""
    document = json.loads(settings.read_text())
    control = {"kind": case, "configuration_mutated": False}
    if case == "hook-disabled":
        document.pop("hooks", None)
        control["configuration_mutated"] = True
    elif case == "interpreter-unavailable":
        entry = document["hooks"]["PreToolUse"][0]["hooks"][0]
        command = entry["command"]
        parts = combined_parts(command)
        if parts is not None:
            parts[1] = str(root / "missing-python")
            entry["command"] = combined_command(parts)
            control.update(configuration_mutated=True, generated_blocking_guard=True)
        else:
            suffix = ' "$HOME/.claude/hooks/tirith-check.py"'
            guard = " || exit 2" if command.endswith(" || exit 2") else ""
            expected_end = suffix + guard
            if not command.endswith(expected_end):
                raise ValueError("generated user hook launcher no longer matches the fixture contract")
            interpreter = command[:-len(expected_end)]
            if len(shlex.split(interpreter)) != 1:
                raise ValueError("generated interpreter is not one quoted executable")
            entry["command"] = shlex.quote(str(root / "missing-python")) + expected_end
            control.update(configuration_mutated=True, generated_blocking_guard=bool(guard))
    elif case == "checker-unavailable":
        env["TIRITH_BIN"] = str(root / "missing-tirith")
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        entry = document["hooks"]["PreToolUse"][0]["hooks"][0]
        parts = combined_parts(entry["command"])
        if parts is not None:
            parts[0] = env["TIRITH_BIN"]
            entry["command"] = combined_command(parts)
            control["configuration_mutated"] = True
    elif case == "hook-crash":
        hook.write_text("import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")
        control["configuration_mutated"] = True
    elif case == "checker-deadline":
        # This is an intentionally controlled checker executable; the real
        # setup-installed Python hook enforces its own shared ten-second budget.
        checker = root / "sleeping-checker"
        started = root / "checker-started.txt"
        checker.write_text("#!/bin/sh\n[ \"$1\" = check ] || exit 0\nprintf '%s\\n' started >> " + shlex.quote(str(started)) + "\nexec /bin/sleep 30\n")
        checker.chmod(0o700)
        env["TIRITH_BIN"] = str(checker)
        control["controlled_checker_sha256"] = digest(checker)
        control["deadline_source"] = "unchanged_installed_hook"
        entries = document["hooks"]["PreToolUse"]
        if entries:
            entry = entries[0]["hooks"][0]
            parts = combined_parts(entry["command"])
            if parts is not None:
                parts[0] = str(checker)
                entry["command"] = combined_command(parts)
                control["configuration_mutated"] = True
    elif case == "shortened-host-timeout":
        hook.write_text("import time\ntime.sleep(8)\n")
        document["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 1
        control.update(configuration_mutated=True, host_timeout_seconds=1,
                       expected_boundary="host_terminates_hook_before_its_own_deadline")
    if control["configuration_mutated"]:
        settings.write_text(json.dumps(document))
    return control


def run_case(binary, host, case, setup_mode="legacy", python=None, claude_invocation=None, runtime=None, settings_loading="explicit", mcp_only=False):
    runtime = runtime or python
    with fixture_directory(prefix=f"tirith-native-claude-{case}-") as root:
        env = isolated_env(root, binary, python, claude_invocation)
        project = root / "project"
        project.mkdir()
        setup_args = [str(binary), "setup", "claude-code", "--scope", "user"] if setup_mode != "recommended" else [str(binary), "setup", "recommended", "--shell", "zsh", "--agent", "claude-code", "--json"]
        setup, setup_stdout, setup_stderr = execute(setup_args, project, env, timeout=120)
        if not execution_ok(setup):
            return {"case": case, "passed": False, "stage": "setup", **setup,
                    "diagnostic": (setup_stdout + setup_stderr).decode(errors="replace")[-6000:]}
        settings = Path(env["HOME"]) / ".claude/settings.json"
        hook = settings.parent / "hooks/tirith-check.py"
        before = {"settings_sha256": digest(settings), "hook_sha256": digest(hook)}
        policy_hash_before = digest(root / "config/tirith/policy.yaml")
        if setup_mode == "candidate-command":
            proposed = json.loads(settings.read_text())
            proposed["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = combined_command([str(binary), str(runtime), str(hook)])
            settings.write_text(json.dumps(proposed))
        installed_command = json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        parts = combined_parts(installed_command)
        if setup_mode in ("recommended", "candidate-command") and (parts is None or Path(parts[0]).resolve() != binary or Path(parts[1]).resolve() != runtime.resolve() or Path(parts[2]) != hook):
            return {"case":case, "passed":False, "stage":"installed_command_identity"}
        token = "TIRITH_AGENT_ALLOW_MARKER" if case == "allowed" else "TIRITH_AGENT_BLOCK_MARKER"
        marker = project / "execution-marker.txt"
        command = f"printf '%s\\n' {token} >> {shlex.quote(str(marker))}"
        preflight, output, _ = execute(
            [str(binary), "check", "--json", "--non-interactive", "--shell", "posix", "--", command],
            project, env,
        )
        if not policy_check_ok(preflight, output, "allow" if case == "allowed" else "block"):
            return {"case": case, "passed": False, "stage": "preflight", **preflight,
                    "diagnostic": output.decode(errors="replace")[-6000:]}
        control = apply_control(root, env, settings, hook, case)
        mcp_config = {"mcpServers": {}}
        if mcp_only:
            if case != "hook-disabled":
                raise ValueError("MCP-only route must remove the interception hook")
            mcp_config["mcpServers"]["tirith-fixture"] = {
                "type": "stdio", "command": str(binary), "args": ["mcp-server"]}
        provider = Provider(command, marker if case == "unmatched-write" else None)
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{provider.server_port}"
        executed = {"settings_sha256": digest(settings), "hook_sha256": digest(hook)}
        settings_args = ["--setting-sources", "", "--settings", str(settings)] if settings_loading == "explicit" else ["--setting-sources", "user,project,local"]
        try:
            result, stdout, stderr = execute(
                [str(host), "--print", "--output-format", "stream-json", "--verbose",
                 "--no-session-persistence", *settings_args,
                 "--strict-mcp-config", "--mcp-config", json.dumps(mcp_config),
                 "--tools", provider.tool_name, "--allowedTools", provider.tool_name, "--permission-mode", "dontAsk",
                 "--permission-prompts", "none", "--include-hook-events",
                 "--system-prompt", "Execute only the inert local fixture tool call provided.",
                 "Run the single inert local certification command, then finish."],
                project, env, timeout=90,
            )
        finally:
            stop_provider(provider, thread)
        lines = marker_lines(marker)
        expected = [token] if case == "allowed" or case in BOUNDARY_CASES else []
        parsed = json_events(stdout)
        hook_events = hook_count(parsed)
        inputs_unchanged = executed == {"settings_sha256": digest(settings), "hook_sha256": digest(hook)}
        expected_hooks = hook_events == 0 if case in ("hook-disabled", "unmatched-write") else hook_events >= 2
        checker_started = True
        if case == "checker-deadline":
            started = root / "checker-started.txt"
            observed_starts = started.read_text().splitlines() if started.is_file() else []
            control["checker_started_count"] = len(observed_starts)
            checker_started = observed_starts == ["started"]
        policy_unchanged = policy_hash_before == digest(root / "config/tirith/policy.yaml")
        passed = (policy_unchanged and checker_started and inputs_unchanged and expected_hooks and execution_ok(result) and provider.rejected == 0 and provider.tool_issued == 1
                  and provider.tool_results >= 1 and lines == expected)
        report = {"case": case, "passed": passed, "stage": "native_host", "setup_mode": setup_mode, "candidate_command_substitution": setup_mode == "candidate-command", "settings_loading": settings_loading, **result, **before,
                  "executed_settings_sha256": executed["settings_sha256"],
                  "executed_hook_sha256": executed["hook_sha256"],
                  "configuration_unchanged_during_host_run": inputs_unchanged,
                  "tool": provider.tool_name, "control": control,
                  "evidence_scope": "explicit_boundary_control" if case in BOUNDARY_CASES else "configured_bash_hook",
                  "provider_requests": provider.requests, "tool_calls_issued": provider.tool_issued,
                  "tool_result_observations": provider.tool_results, "rejected_provider_requests": provider.rejected,
                  "host_hook_events": hook_events, "marker_count": len(lines), "expected_marker_count": len(expected)}
        report["policy_sha256"] = policy_hash_before
        report["policy_unchanged_during_host_run"] = policy_unchanged
        report["setup"] = setup
        report["command_sha256"] = hashlib.sha256(command.encode()).hexdigest()
        report["preflight"] = preflight
        if mcp_only:
            connections = [server for event in parsed
                           if event.get("type") == "system" and event.get("subtype") == "init"
                           for server in event.get("mcp_servers", []) if isinstance(server, dict)]
            connected = any(server.get("name") == "tirith-fixture" and server.get("status") == "connected"
                            for server in connections)
            report["control"]["kind"] = "mcp-only-access"
            report.update(case="mcp-only-access", mcp_connections=connections,
                          mcp_config_sha256=hashlib.sha256(json.dumps(mcp_config).encode()).hexdigest(),
                          passed=passed and connected, evidence_scope="explicit_mcp_boundary_control",
                          interpretation="MCP access alone does not intercept Bash; this control requires the policy-denied marker to execute once with the hook absent.")
        if not report["passed"]:
            report["diagnostic"] = (stdout + stderr).decode(errors="replace")[-12000:]
        return report


def marker_lines(marker):
    if not marker.exists():
        return []
    if marker.stat().st_size > 4096:
        raise ValueError("fixture marker exceeded its bound")
    return marker.read_text().splitlines()


def configuration_evidence(settings):
    return {"settings_sha256": digest(settings),
            "hook_sha256": digest(settings.parent / "hooks/tirith-check.py")}


def installed_recommended_identity(settings, binary, runtime):
    document = json.loads(settings.read_text())
    command = document["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    parts = combined_parts(command)
    hook = settings.parent / "hooks/tirith-check.py"
    if (parts is None or Path(parts[0]).resolve() != binary
            or Path(parts[1]).resolve() != runtime.resolve() or Path(parts[2]) != hook):
        raise ValueError("recommended setup did not install the exact candidate/interpreter/hook tuple")


def reload_observation(events, before, after, facts):
    """Classify evidence; never promote a settings write into an activation claim."""
    classification = "inconclusive"
    hooks = hook_count(events)
    if (successful_turn(events) and facts["tool_calls_issued"] == 1
            and facts["tool_result_observations"] >= 1 and facts["rejected_provider_requests"] == 0):
        if hooks >= 2 and after == before:
            classification = "observed_hook_and_blocked"
        elif hooks == 0 and after == before + ["TIRITH_AGENT_BLOCK_MARKER"]:
            classification = "hook_not_observed_marker_executed_once"
    return {"classification": classification, "host_hook_events": hooks,
            "additional_marker_executions": len(after) - len(before), **facts}


def begin_provider_turn(provider, tool_name):
    with provider.lock:
        provider.tool_name = tool_name
        provider.tool_issued = 0
        provider.tool_results = 0
        provider.expected_tool_id = None


def run_reload(binary, host, python, claude_invocation, runtime):
    report = {"case": "retained-host-reload", "passed": False,
              "evidence_scope": "retained_host_visibility_and_fresh_host_blocking",
              "setup_mode": "recommended", "settings_loading": "default-user",
              "candidate_command_substitution": False,
              "universal_hot_reload_claimed": False}
    with fixture_directory(prefix="tirith-native-claude-reload-") as root:
        env = isolated_env(root, binary, python, claude_invocation)
        project = root / "project"
        project.mkdir()
        marker = project / "execution-marker.txt"
        settings = Path(env["HOME"]) / ".claude/settings.json"
        command = "printf '%s\\n' TIRITH_AGENT_BLOCK_MARKER >> " + shlex.quote(str(marker))
        policy = root / "config/tirith/policy.yaml"
        original_policy = digest(policy)
        report.update(policy_before_setup_sha256=original_policy,
                      command_sha256=hashlib.sha256(command.encode()).hexdigest())
        preflight, preflight_output, _ = execute([str(binary), "check", "--json", "--non-interactive",
                                  "--shell", "posix", "--", command], project, env)
        report["preflight"] = preflight
        if not policy_check_ok(preflight, preflight_output, "block"):
            return dict(report, stage="preflight")
        argv = [str(host), "--print", "--input-format", "stream-json",
                "--output-format", "stream-json", "--verbose", "--no-session-persistence",
                "--setting-sources", "user,project,local", "--strict-mcp-config",
                "--mcp-config", '{"mcpServers":{}}', "--tools", "Bash", "--allowedTools", "Bash",
                "--permission-mode", "dontAsk", "--permission-prompts", "none", "--include-hook-events",
                "--system-prompt", "Execute only the inert local fixture tool call provided."]
        provider = Provider(command)
        child = None
        try:
            with running_provider(provider, env):
                begin_provider_turn(provider, "FixtureNoTool")
                child = BoundedProcess(argv, project, env, interactive=True)
                pid = child.process.pid
                child.send("Initialize the inert fixture and finish this turn without invoking a tool.")
                initial = child.read_turn()
                initialized = (successful_turn(initial)
                               and any(event.get("type") == "system" and event.get("subtype") == "init"
                                       for event in initial)
                               and not settings.exists() and not marker.exists()
                               and provider.tool_issued == 0)
                report["initialized_before_publication"] = initialized
                if not initialized:
                    raise RuntimeError("host was not initialized with an absent hook before publication")
                setup, stdout, _ = execute([str(binary), "setup", "recommended", "--shell", "zsh",
                                           "--agent", "claude-code", "--json"], project, env, timeout=120)
                setup_completed = time.monotonic()
                report["setup"] = setup
                if not execution_ok(setup):
                    raise RuntimeError("real recommended setup failed")
                status = json.loads(stdout)
                steps = status.get("steps", [])
                if (status.get("kind") != "recommended-setup"
                        or status.get("state") not in ("completed", "completed-with-recovery")
                        or not steps or not all(step.get("state") in ("applied", "applied-with-recovery")
                                                for step in steps)):
                    raise RuntimeError("recommended setup did not complete every requested step")
                installed_recommended_identity(settings, binary, runtime)
                report["setup_operation"] = {key: status.get(key) for key in ("operation_id", "kind", "state", "no_op")}
                report["setup_step_states"] = [{"activation": step.get("activation"), "state": step.get("state")}
                                                for step in steps]
                publication = configuration_evidence(settings)
                report["publication"] = publication
                published_policy = digest(policy)
                report["published_policy_sha256"] = published_policy
                observations = []
                report["retained_host_observations"] = observations
                before = []
                for name in ("immediate_existing_host", "existing_host_after_policy_recheck"):
                    if child.process.poll() is not None or child.process.pid != pid:
                        raise RuntimeError("original native host did not remain alive")
                    if name == "existing_host_after_policy_recheck":
                        checked, checked_output, _ = execute([str(binary), "check", "--json", "--non-interactive",
                                                 "--shell", "posix", "--", command], project, env)
                        report["policy_recheck"] = checked
                        if not policy_check_ok(checked, checked_output, "block"):
                            raise RuntimeError("unchanged fixture policy no longer refused the command")
                    begin_provider_turn(provider, "Bash")
                    seconds_since_setup = round(time.monotonic() - setup_completed, 3)
                    child.send("Run the single inert local certification command, then finish.")
                    events = child.read_turn()
                    after = marker_lines(marker)
                    observation = reload_observation(events, before, after, provider_facts(provider))
                    observation["stage"] = name
                    observation["seconds_since_setup_before_turn"] = seconds_since_setup
                    observation["published_policy_unchanged"] = published_policy == digest(policy)
                    observation["same_host_retained"] = child.process.poll() is None and child.process.pid == pid
                    observation["configuration_unchanged"] = publication == configuration_evidence(settings)
                    observation["host_stdout_so_far"] = bytes_evidence(child.stdout)
                    observation["host_stderr_so_far"] = bytes_evidence(child.stderr)
                    observations.append(observation)
                    before = after
                    if (observation["classification"] == "inconclusive"
                            or not observation["same_host_retained"] or not observation["configuration_unchanged"]
                            or not observation["published_policy_unchanged"]):
                        raise RuntimeError("retained-host observation did not meet the exact fixture contract")
                report["retained_host_observations"] = observations
                report["retained_host_cleanup"] = child.close()
                report["retained_host_cleanup_error"] = child.cleanup_error
                begin_provider_turn(provider, "Bash")
                fresh_argv = argv.copy()
                index = fresh_argv.index("--input-format")
                del fresh_argv[index:index + 2]
                fresh_argv.append("Run the single inert local certification command, then finish.")
                fresh, stdout, _ = execute(fresh_argv, project, env, timeout=90)
                after = marker_lines(marker)
                observed = reload_observation(json_events(stdout), before, after, provider_facts(provider))
                report["fresh_host_after_reload"] = {**fresh, **observed}
                report["configuration_unchanged"] = publication == configuration_evidence(settings)
                report["published_policy_unchanged"] = published_policy == digest(policy)
                report["passed"] = (execution_ok(fresh) and observed["classification"] == "observed_hook_and_blocked"
                                    and report["configuration_unchanged"] and report["published_policy_unchanged"]
                                    and all(report["retained_host_cleanup"].values()))
                report["stage"] = "native_host"
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            report.update(stage="native_host", diagnostic=str(error)[:2000], passed=False)
        finally:
            if child is not None:
                report["retained_host_cleanup"] = child.close()
                report["retained_host_stdout"] = bytes_evidence(child.stdout)
                report["retained_host_stderr"] = bytes_evidence(child.stderr)
                report["retained_host_cleanup_error"] = child.cleanup_error
                report["passed"] = report["passed"] and all(child.cleanup.values()) and child.cleanup_error is None
    report["interpretation"] = ("Existing-host observations apply only to the recorded turns and exact host tuple. "
                                "Fresh-host blocking is a separate required observation; no universal or immediate hot reload is inferred.")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tirith", type=Path, required=True)
    parser.add_argument("--claude", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--route", choices=["hooks", "mcp-only", "retained-host-reload"], default="hooks",
                        help="hooks preserves the baseline/failure cases; boundary routes require recommended setup and default-user settings")
    parser.add_argument("--settings-loading", choices=["explicit", "default-user"], default="explicit")
    parser.add_argument("--case", choices=BASELINE_CASES + FAILURE_CASES, action="append", dest="cases")
    parser.add_argument("--setup-mode", choices=["legacy", "recommended", "candidate-command"], default="legacy")
    parser.add_argument("--python", type=Path, help="exact installed python3 invocation to select on the isolated PATH")
    parser.add_argument("--claude-invocation", type=Path, help="installed claude PATH alias resolving to --claude")
    parser.add_argument("--failure-controls", action="store_true",
                        help="also exercise isolated launch failures, checker deadlines and host-scope limits")
    args = parser.parse_args()
    if args.route != "hooks" and (args.setup_mode != "recommended" or args.settings_loading != "default-user"
                                  or args.cases or args.failure_controls):
        parser.error("boundary routes require --setup-mode recommended --settings-loading default-user, without --case or --failure-controls")
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a new evidence file; existing reports are never replaced")
    if os.name != "posix":
        parser.error("this initial native-host fixture supports POSIX hosts only")
    # Managed configuration cannot be isolated by --setting-sources.
    for path in ["/Library/Application Support/ClaudeCode/managed-settings.json",
                 "/Library/Application Support/ClaudeCode/managed-mcp.json",
                 "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-mcp.json"]:
        if Path(path).exists():
            parser.error("managed host configuration is present; isolation cannot be established")
    binary, host = args.tirith.resolve(strict=True), args.claude.resolve(strict=True)
    python = args.python.absolute() if args.python else Path("/usr/bin/python3")
    if python.name != "python3" or not python.is_file():
        parser.error("--python must be an existing installed python3 invocation")
    claude_invocation = args.claude_invocation.absolute() if args.claude_invocation else None
    if args.setup_mode == "recommended":
        if claude_invocation is None or claude_invocation.name != "claude" or claude_invocation.resolve() != host:
            parser.error("recommended setup requires --claude-invocation selecting the same native host")
    with tempfile.TemporaryDirectory(prefix="tirith-native-claude-version-") as temp:
        root = Path(temp)
        env = isolated_env(root, binary, python, claude_invocation)
        discovered, runtime_output, _ = execute([str(python), "-I", "-S", "-c", "import sys;print(sys.executable)"], root, env)
        if not execution_ok(discovered):
            parser.error("isolated Python runtime discovery failed")
        runtime = Path(runtime_output.decode().strip())
        if not runtime.is_absolute() or not runtime.is_file():
            parser.error("Python runtime discovery did not identify a regular absolute executable")
        versions = {}
        for name, path in [("tirith", binary), ("claude", host), ("python", python), ("python-runtime", runtime)]:
            result, stdout, _ = execute([str(path), "--version"], root, env)
            if not execution_ok(result):
                parser.error(f"{name} version probe failed")
            versions[name] = {"path": str(path), "version": stdout.decode().strip(), "sha256": digest(path), "resolved_path": str(path.resolve())}
    if claude_invocation is not None:
        versions["claude-invocation"] = {"path": str(claude_invocation),
                                         "resolved_path": str(claude_invocation.resolve()),
                                         "sha256": digest(claude_invocation)}
    source_hash = digest(Path(__file__))
    cases = []
    selected_cases = (args.cases or BASELINE_CASES + (FAILURE_CASES if args.failure_controls else ())) if args.route == "hooks" else (
        ("mcp-only-access",) if args.route == "mcp-only" else ("retained-host-reload",))
    if len(set(selected_cases)) != len(selected_cases):
        parser.error("select each case once")
    for case in selected_cases:
        try:
            if args.route == "retained-host-reload":
                result = run_reload(binary, host, python, claude_invocation, runtime)
            else:
                result = run_case(binary, host, "hook-disabled" if args.route == "mcp-only" else case,
                                  args.setup_mode, python, claude_invocation, runtime, args.settings_loading,
                                  mcp_only=args.route == "mcp-only")
            result["fixture_cleanup_completed"] = True
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
            result = {"case": case, "passed": False, "stage": "fixture_error", "diagnostic": str(error)[:2000]}

        cases.append(result)
        print(json.dumps({"case": case, "passed": result["passed"], "stage": result["stage"]}), flush=True)
    postcheck = {}
    for name, value in versions.items():
        try:
            path = Path(value["path"])
            postcheck[name] = {"sha256": digest(path), "resolved_path": str(path.resolve(strict=True))}
        except OSError:
            postcheck[name] = {"unavailable": True}
    unchanged = all(postcheck[name].get("sha256") == value["sha256"]
                    and postcheck[name].get("resolved_path") == value.get("resolved_path", str(Path(value["path"]).resolve()))
                    for name, value in versions.items()) and digest(Path(__file__)) == source_hash
    report = {"schema_version": 1, "evidence_kind": "scripted-provider-native-host", "harness_sha256": source_hash, "inputs_postcheck": postcheck,
              "recorded_unix": int(time.time()), "os": platform.platform(), "versions": versions,
              "scope": f"{args.settings_loading} settings; {args.route} route on this host; standalone candidate bytes",
              "fixture_cleanup_completed": all(case.get("fixture_cleanup_completed", False) for case in cases),
              "complete_release_certification": False, "binaries_unchanged_during_run": unchanged,
              "failure_controls_requested": args.failure_controls, "setup_mode": args.setup_mode, "settings_loading": args.settings_loading, "selected_cases": list(selected_cases),
              "route": args.route,
              "remaining": (["MCP-only control"] if args.route != "mcp-only" else []) +
                           (["reload visibility"] if args.route != "retained-host-reload" else []) +
                           ["native Windows",
                            "beginner pilot", "real-model workflow"] +
                           ([] if args.failure_controls else ["alternate tools", "timeout and crash", "moved interpreter"]),
              "passed": unchanged and all(case["passed"] for case in cases), "cases": cases}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
