#!/usr/bin/env python3
"""Focused fixture invariants; these unit tests are not native host certification."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import signal
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('harness', Path(__file__).with_name('certify-claude-host.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

@unittest.skipUnless(os.name == "posix", "native launcher fixture uses POSIX shell semantics")
class Controls(unittest.TestCase):
    def test_environment_does_not_inherit_provider_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.dict(os.environ, {
                "TIRITH": "0",
                "ANTHROPIC_AUTH_TOKEN": "inert-inherited-auth-placeholder",
                "OPENAI_API_KEY": "inert-inherited-key-placeholder",
                "ANTHROPIC_API_KEY": "inert-inherited-key-placeholder",
                "HTTP_PROXY": "http://inert.invalid",
            }):
                env = h.isolated_env(Path(temp), Path(temp) / 'tirith')
            self.assertNotIn("TIRITH", env)
            self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env)
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertEqual(env["ANTHROPIC_API_KEY"], "tirith-inert-loopback-fixture-not-a-credential")
            self.assertEqual(env["HTTP_PROXY"], "")

    def test_missing_interpreter_retains_only_the_generated_guard(self):
        for guarded in (False, True):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                env = h.isolated_env(root, root / 'tirith')
                settings = Path(env['HOME']) / '.claude/settings.json'
                hook = settings.parent / 'hooks/tirith-check.py'
                hook.parent.mkdir()
                hook.write_text('pass\n')
                original = shlex.quote("/opt/fake interpreter's $path") + ' "$HOME/.claude/hooks/tirith-check.py"' + (' || exit 2' if guarded else '')
                settings.write_text(json.dumps({'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': original}]}]}}))
                h.apply_control(root, env, settings, hook, 'interpreter-unavailable')
                command = json.loads(settings.read_text())['hooks']['PreToolUse'][0]['hooks'][0]['command']
                observed = subprocess.run(['/bin/sh', '-c', command], env=env, capture_output=True)
                self.assertEqual(observed.returncode, 2 if guarded else 127)
                self.assertEqual(hook.read_text(), 'pass\n')

    def test_checker_deadline_does_not_change_generated_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = h.isolated_env(root, root / 'tirith')
            settings = Path(env['HOME']) / '.claude/settings.json'
            settings.write_text('{"hooks":{"PreToolUse":[]}}\n')
            hook = settings.parent / 'hook.py'
            hook.write_text('unchanged')
            before = settings.read_bytes(), hook.read_bytes()
            control = h.apply_control(root, env, settings, hook, 'checker-deadline')
            self.assertEqual((settings.read_bytes(), hook.read_bytes()), before)
            self.assertEqual(control['controlled_checker_sha256'], h.digest(Path(env['TIRITH_BIN'])))
            process = subprocess.Popen([env['TIRITH_BIN'], 'check'], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                started = root / "checker-started.txt"
                deadline = time.monotonic() + 2
                while not started.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(started.read_text().splitlines(), ["started"])
                telemetry = subprocess.run([env['TIRITH_BIN'], "hook-event", "--event", "timeout"], capture_output=True, timeout=2)
                self.assertEqual(telemetry.returncode, 0)
                self.assertEqual(started.read_text().splitlines(), ["started"])
                self.assertIsNone(process.poll(), "controlled checker must still be stalled")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=2)

class CombinedControls(unittest.TestCase):
    def test_combined_parser_retains_exact_shell_argument_identity(self):
        parts = ["/safe/binary with ' quote", "/python3", "/home/$(touch nope)/.claude/hooks/tirith-check.py"]
        self.assertEqual(h.combined_parts(h.combined_command(parts)), parts)
        for command in [h.combined_command(parts) + " ; true", "TIRITH_BIN=/binary /python /hook || true", "TIRITH_BIN=relative /python /home/.claude/hooks/tirith-check.py || exit 2"]:
            with self.assertRaises(ValueError):
                h.combined_parts(command)

    def test_combined_failure_controls_change_only_the_selected_input(self):
        for case in ["interpreter-unavailable", "checker-unavailable", "checker-deadline"]:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                env = h.isolated_env(root, root / "tirith")
                settings = Path(env["HOME"]) / ".claude/settings.json"
                hook = settings.parent / "hooks/tirith-check.py"
                hook.parent.mkdir()
                hook.write_text("unchanged")
                parts = [str(root / "tirith"), "/usr/bin/python3", str(hook)]
                settings.write_text(json.dumps({"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":h.combined_command(parts)}]}]}}))
                control = h.apply_control(root, env, settings, hook, case)
                changed = h.combined_parts(json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
                index = 1 if case == "interpreter-unavailable" else 0
                self.assertNotEqual(changed[index], parts[index])
                self.assertEqual(changed[1-index], parts[1-index])
                self.assertEqual(changed[2], parts[2])
                self.assertEqual(hook.read_text(), "unchanged")
                self.assertTrue(control["configuration_mutated"])

class PythonIsolation(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix" and Path("/usr/bin/python3").is_file(), "requires installed POSIX Python")
    def test_fixed_runtime_flags_ignore_python_home_and_path_injection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            injected = root / "injected"
            injected.mkdir()
            marker = root / "injection-marker"
            (injected / "json.py").write_text(f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')")
            hook = root / ".claude/hooks/tirith-check.py"
            hook.parent.mkdir(parents=True)
            hook.write_text("import json; print('ISOLATED')")
            command = h.combined_command(["/inert/tirith", "/usr/bin/python3", str(hook)])
            result = subprocess.run(["/bin/sh", "-c", command], env={"PATH":"/usr/bin:/bin", "PYTHONHOME":str(root/"missing"), "PYTHONPATH":str(injected)}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"ISOLATED\n")
            self.assertFalse(marker.exists())

@unittest.skipUnless(os.name == "posix", "bounded fixture process groups require POSIX")
class BoundedExecution(unittest.TestCase):
    def run_python(self, program, timeout=2):
        import sys
        return h.execute([sys.executable, "-I", "-S", "-c", program], Path.cwd(), {}, timeout)

    def test_timeout_kills_and_reaps_own_group(self):
        started = time.monotonic()
        result, _, _ = self.run_python("import time;time.sleep(20)", timeout=0.1)
        self.assertTrue(result["timed_out"])
        self.assertGreaterEqual(result["elapsed_seconds"], 0.1)
        self.assertLess(result["elapsed_seconds"], 4)
        self.assertTrue(all(result["cleanup"].values()))
        self.assertLess(time.monotonic() - started, 4)

    def test_exited_parent_does_not_wait_forever_for_inherited_pipe(self):
        result, stdout, _ = self.run_python(
            "import os,time;pid=os.fork();time.sleep(20) if pid==0 else print('parent-done',flush=True)")
        self.assertTrue(h.execution_ok(result), result)
        self.assertIn(b"parent-done", stdout)

    def test_output_limit_is_failure_even_if_process_exits_zero(self):
        result, stdout, stderr = self.run_python("import os;os.write(1,b'x'*(5*1024*1024))")
        self.assertTrue(result["output_limit_exceeded"])
        self.assertFalse(h.execution_ok(result))
        self.assertLessEqual(len(stdout) + len(stderr), h.MAX_OUTPUT_BYTES)
        self.assertTrue(result["cleanup"]["leader_reaped"])
        self.assertEqual(result["stdout"], h.bytes_evidence(stdout))

    def test_interactive_turn_has_deadline_and_json_object_validation(self):
        import sys
        child = h.BoundedProcess([sys.executable, "-I", "-S", "-c",
                                  "import time;print('[]',flush=True);time.sleep(20)"], Path.cwd(), {}, interactive=True)
        try:
            with self.assertRaisesRegex(RuntimeError, "result deadline"):
                child.read_turn(timeout=0.1)
        finally:
            self.assertTrue(all(child.close().values()))

    def test_fast_exiting_process_retries_permission_race(self):
        import errno
        import sys
        child = h.BoundedProcess([sys.executable, "-I", "-S", "-c", "pass"], Path.cwd(), {})
        actual_killpg = os.killpg
        attempts = []
        def racing_killpg(pid, signum):
            self.assertEqual(pid, child.process.pid)
            attempts.append(pid)
            if len(attempts) <= 2:
                raise PermissionError(errno.EPERM, "controlled exit race")
            return actual_killpg(pid, signum)
        with mock.patch.object(h.os, "killpg", side_effect=racing_killpg):
            cleanup = child.close()
        self.assertTrue(all(cleanup.values()), cleanup)
        self.assertIsNone(child.cleanup_error)
        self.assertGreaterEqual(len(attempts), 3)
        self.assertIs(child.close(), cleanup)

    def test_persistent_permission_failure_is_recorded_and_owned_child_reaped(self):
        import errno
        import sys
        child = h.BoundedProcess([sys.executable, "-I", "-S", "-c", "import time;time.sleep(20)"], Path.cwd(), {})
        started = time.monotonic()
        with mock.patch.object(h.os, "killpg", side_effect=PermissionError(errno.EPERM, "controlled refusal")):
            cleanup = child.close()
        self.assertTrue(cleanup["leader_reaped"])
        self.assertFalse(cleanup["process_group_cleanup_requested"])
        self.assertEqual(child.cleanup_error, "process_group_permission_deadline")
        self.assertLess(time.monotonic() - started, 7)
        self.assertIs(child.close(), cleanup)
        self.assertFalse(h.execution_ok({"exit": 0, "timed_out": False, "cleanup": cleanup,
                                         "cleanup_error": child.cleanup_error}))

    def test_unreaped_child_cannot_pass_cleanup(self):
        import sys
        child = h.BoundedProcess([sys.executable, "-I", "-S", "-c", "import time;time.sleep(20)"], Path.cwd(), {})
        try:
            with mock.patch.object(child.process, "wait", side_effect=subprocess.TimeoutExpired("owned fixture", 0.05)):
                cleanup = child.close()
            self.assertFalse(cleanup["leader_reaped"])
            self.assertEqual(child.cleanup_error, "owned_child_reap_deadline")
            self.assertIs(child.close(), cleanup)
        finally:
            child.process.kill()
            child.process.wait(timeout=2)

    def test_fast_pty_and_process_exit_sequence(self):
        # The outer fixture owns and reaps each PTY child; no PTY or descendant
        # from this control is allowed to survive the process-group fixture.
        program = """import os,pty
for _ in range(8):
    child,fd=pty.fork()
    if child==0:os._exit(0)
    os.waitpid(child,0)
    os.close(fd)
print('pty-children-reaped',flush=True)
"""
        result, stdout, _ = self.run_python(program, timeout=5)
        self.assertTrue(h.execution_ok(result), result)
        self.assertIn(b"pty-children-reaped", stdout)


class BoundaryEvidence(unittest.TestCase):
    @staticmethod
    def facts():
        return {"provider_requests": 2, "tool_calls_issued": 1,
                "tool_result_observations": 1, "rejected_provider_requests": 0}

    def test_nonzero_checker_failure_is_not_a_policy_block(self):
        result = {"exit": 1, "timed_out": False, "output_limit_exceeded": False,
                  "cleanup": {"leader_reaped": True, "output_eof": True}}
        self.assertTrue(h.policy_check_ok(result, b'{"action":"block"}', "block"))
        for output in [b"checker failed", b'{"error":"unavailable"}', b'{"action":"allow"}', b'[]']:
            self.assertFalse(h.policy_check_ok(result, output, "block"))
        self.assertFalse(h.policy_check_ok(dict(result, timed_out=True), b'{"action":"block"}', "block"))

    def test_reload_visibility_does_not_imply_blocking(self):
        success = [{"type": "result", "is_error": False}]
        hooks = [{"subtype": "hook_started"}, {"subtype": "hook_response"}] + success
        before = ["TIRITH_AGENT_BLOCK_MARKER"]
        allowed = h.reload_observation(success, [], before, self.facts())
        blocked = h.reload_observation(hooks, before, before, self.facts())
        self.assertEqual(allowed["classification"], "hook_not_observed_marker_executed_once")
        self.assertEqual(blocked["classification"], "observed_hook_and_blocked")
        # Hook events with executed bytes, missing tool dispatch/result, duplicate
        # markers, and an errored host turn cannot certify either observation.
        for events, after, facts in [
            (hooks, before, self.facts()),
            (success, before * 2, self.facts()),
            (success, before, dict(self.facts(), tool_calls_issued=0)),
            (success, before, dict(self.facts(), tool_result_observations=0)),
            ([{"type": "result", "is_error": True}], before, self.facts()),
        ]:
            self.assertEqual(h.reload_observation(events, [], after, facts)["classification"], "inconclusive")

    def test_provider_counts_only_the_current_tool_result(self):
        import http.client
        provider = h.Provider("printf inert")
        with h.running_provider(provider, {}):
            def request(messages):
                conn = http.client.HTTPConnection("127.0.0.1", provider.server_port, timeout=2)
                try:
                    conn.request("POST", "/v1/messages", json.dumps({"tools": [{"name": "Bash"}], "messages": messages}))
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    return json.loads(response.read())
                finally:
                    conn.close()
            first = request([])["content"][0]["id"]
            h.begin_provider_turn(provider, "Bash")
            second = request([])["content"][0]["id"]
            self.assertNotEqual(first, second)
            request([{"content": [{"type": "tool_result", "tool_use_id": first}]}])
            self.assertEqual(provider.tool_results, 0)
            request([{"content": [{"type": "tool_result", "tool_use_id": second}]}])
            self.assertEqual(provider.tool_results, 1)

    def test_boundary_routes_do_not_change_default_nine_selection(self):
        self.assertEqual(h.BASELINE_CASES + h.FAILURE_CASES,
                         ("allowed", "blocked", "hook-disabled", "interpreter-unavailable",
                          "checker-unavailable", "hook-crash", "checker-deadline",
                          "shortened-host-timeout", "unmatched-write"))

    def test_preexisting_output_is_not_overwritten(self):
        import sys
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            output.write_text("old evidence")
            result = subprocess.run([sys.executable, h.__file__, "--tirith", sys.executable,
                                     "--claude", sys.executable, "--output", str(output)],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_text(), "old evidence")


@unittest.skipUnless(os.name == "posix", "fixture uses POSIX subprocesses")
class ScriptedHostRoute(unittest.TestCase):
    """This fake host validates harness control flow, never native enforcement."""

    def test_reload_keeps_immediate_later_and_fresh_observations_distinct(self):
        import sys
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            binary, host = root / "tirith", root / "claude"
            hook_python = root / "python3"
            hook_python.symlink_to(sys.executable)
            binary.write_text("inert candidate identity")
            host.write_text("#!" + sys.executable + "\n" + r'''
import http.client,json,os,shlex,subprocess,sys,urllib.parse
url=urllib.parse.urlsplit(os.environ['ANTHROPIC_BASE_URL'])
interactive='--input-format' in sys.argv
turn=0
def emit(value):print(json.dumps(value),flush=True)
def complete():
 global turn
 messages=[]
 def request():
  c=http.client.HTTPConnection(url.hostname,url.port,timeout=2)
  c.request('POST','/v1/messages',json.dumps({'tools':[{'name':'Bash'}],'messages':messages}))
  r=c.getresponse();body=json.loads(r.read());c.close();return body['content'][0]
 block=request()
 if block['type']=='tool_use':
  blocked=not interactive or turn>=2
  if blocked:
   emit({'type':'system','subtype':'hook_started'})
   emit({'type':'system','subtype':'hook_response'})
  else:subprocess.run(['/bin/sh','-c',block['input']['command']],check=True)
  messages.append({'content':[{'type':'tool_result','tool_use_id':block['id'],'content':'fixture result'}]})
  assert request()['type']=='text'
 emit({'type':'result','is_error':False})
 turn+=1
emit({'type':'system','subtype':'init'})
if interactive:
 for line in sys.stdin:complete()
else:complete()
''')
            host.chmod(0o700)
            real_execute = h.execute
            setups = []
            def execute(argv, cwd, env, timeout=45):
                if argv[0] == str(binary):
                    if argv[1] == "check":
                        return {"exit": 1, "timed_out": False, "output_limit_exceeded": False,
                                "cleanup": {"leader_reaped": True, "output_eof": True}}, b'{"action":"block"}', b""
                    self.assertEqual(argv[1:3], ["setup", "recommended"])
                    setups.append(1)
                    # Real recommended setup may add a profile while preserving the marker rule.
                    policy = Path(env["XDG_CONFIG_HOME"]) / "tirith/policy.yaml"
                    policy.write_text(policy.read_text() + "# generated profile selection\n")
                    settings = Path(env["HOME"]) / ".claude/settings.json"
                    hook = settings.parent / "hooks/tirith-check.py"
                    hook.parent.mkdir()
                    hook.write_text("inert hook")
                    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command":
                        h.combined_command([str(binary), str(hook_python), str(hook)])}]}]}}))
                    status = {"kind": "recommended-setup", "state": "completed", "steps": [{"activation": "claude-code", "state": "applied"}]}
                    return {"exit": 0, "timed_out": False, "cleanup": {"leader_reaped": True, "output_eof": True}}, json.dumps(status).encode(), b""
                return real_execute(argv, cwd, env, timeout)
            with mock.patch.object(h, "execute", side_effect=execute):
                result = h.run_reload(binary, host, hook_python, host, hook_python)
            self.assertTrue(result["passed"], result)
            self.assertEqual(setups, [1])
            self.assertNotEqual(result["policy_before_setup_sha256"], result["published_policy_sha256"])
            self.assertTrue(result["published_policy_unchanged"])
            self.assertFalse(result["universal_hot_reload_claimed"])
            immediate, later = result["retained_host_observations"]
            self.assertEqual(immediate["classification"], "hook_not_observed_marker_executed_once")
            self.assertEqual(later["classification"], "observed_hook_and_blocked")
            self.assertEqual(result["fresh_host_after_reload"]["classification"], "observed_hook_and_blocked")
            self.assertTrue(all(result["retained_host_cleanup"].values()))
            self.assertNotEqual(result["retained_host_stdout"]["sha256"], result["retained_host_stderr"]["sha256"])

    def test_mcp_only_requires_connection_and_exact_absent_hook_control(self):
        import sys
        for connected in (False, True):
            with self.subTest(connected=connected), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                binary, host = root / "tirith", root / "claude"
                python = root / "python3"
                python.symlink_to(sys.executable)
                binary.write_text("inert candidate identity")
                host.write_text("#!" + sys.executable + "\nCONNECTED=" + repr(connected) + "\n" + r'''
import http.client,json,os,subprocess,sys,urllib.parse
from pathlib import Path
config=json.loads(sys.argv[sys.argv.index('--mcp-config')+1])
assert config=={'mcpServers':{'tirith-fixture':{'type':'stdio','command':os.environ['TIRITH_BIN'],'args':['mcp-server']}}}
assert 'hooks' not in json.loads((Path(os.environ['HOME'])/'.claude/settings.json').read_text())
assert sys.argv[sys.argv.index('--tools')+1]=='Bash'
print(json.dumps({'type':'system','subtype':'init','mcp_servers':[{'name':'tirith-fixture','status':'connected' if CONNECTED else 'failed'}]}),flush=True)
url=urllib.parse.urlsplit(os.environ['ANTHROPIC_BASE_URL'])
def request(messages):
 c=http.client.HTTPConnection(url.hostname,url.port,timeout=2)
 c.request('POST','/v1/messages',json.dumps({'tools':[{'name':'Bash'}],'messages':messages}))
 response=c.getresponse();result=json.loads(response.read());c.close();return result['content'][0]
block=request([])
subprocess.run(['/bin/sh','-c',block['input']['command']],check=True)
request([{'content':[{'type':'tool_result','tool_use_id':block['id']}]}])
print(json.dumps({'type':'result','is_error':False}),flush=True)
''')
                host.chmod(0o700)
                real_execute = h.execute
                def execute(argv, cwd, env, timeout=45):
                    if argv[0] != str(binary):
                        return real_execute(argv, cwd, env, timeout)
                    ok = {"exit": 0, "timed_out": False, "output_limit_exceeded": False,
                          "cleanup": {"leader_reaped": True, "output_eof": True}}
                    if argv[1] == "check":
                        return dict(ok, exit=1), b'{"action":"block"}', b""
                    settings = Path(env["HOME"]) / ".claude/settings.json"
                    hook = settings.parent / "hooks/tirith-check.py"
                    hook.parent.mkdir()
                    hook.write_text("inert hook")
                    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"command":
                        h.combined_command([str(binary), str(python), str(hook)])}]}]}}))
                    return ok, b"{}", b""
                with mock.patch.object(h, "execute", side_effect=execute):
                    result = h.run_case(binary, host, "hook-disabled", "recommended", python, host, python,
                                        "default-user", mcp_only=True)
                self.assertEqual(result["passed"], connected, result)
                self.assertEqual(result["case"], "mcp-only-access")
                self.assertEqual(result["marker_count"], 1)
                self.assertEqual(result["host_hook_events"], 0)
                self.assertEqual(result["tool_calls_issued"], 1)
                self.assertTrue(result["configuration_unchanged_during_host_run"])
                self.assertEqual(result["evidence_scope"], "explicit_mcp_boundary_control")

if __name__ == '__main__':
    unittest.main()
