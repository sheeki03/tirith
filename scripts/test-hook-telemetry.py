#!/usr/bin/env python3
"""Exercise shipped telemetry helpers; this is not native host qualification."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'crates/tirith/assets/hooks'
PYTHON_ASSETS = ('tirith-check.py', 'copilot-cli-hook.py', 'kiro-hook.py',
                 'tirith-security-guard-gemini.py')
SHELL_ASSETS = ('cursor-hook.sh', 'vscode-hook.sh', 'windsurf-hook.sh')
NODE_ASSETS = ('tirith-guard.ts', 'openclaw-tirith-guard.ts')


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load(ROOT / 'scripts/certify-claude-host.py')


@unittest.skipUnless(os.name == 'posix', 'real executable fixtures use POSIX shebangs')
class TelemetryChildren(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tirith-telemetry-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / 'fake-tirith'
        self.fake.write_text('#!' + sys.executable + '\n' + '''
import json, os, pathlib, signal, sys, time
if sys.argv[1] == 'check':
    print(json.dumps({'findings':[{'title':'inert finding','severity':'high'}]}))
    raise SystemExit(int(os.environ.get('CHECK_EXIT', '0')))
root = pathlib.Path(os.environ['TELEMETRY_ROOT'])
root.joinpath('started.json').write_text(json.dumps({'argv':sys.argv[1:], 'stdin':sys.stdin.read()}))
mode = os.environ.get('TELEMETRY_MODE', 'normal')
if mode == 'stubborn':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    root.joinpath('stubborn-ready').write_text('ready')
    time.sleep(1)
    root.joinpath('late-write').write_text('should not survive helper return')
elif mode == 'nonzero':
    raise SystemExit(17)
else:
    time.sleep(.04)
    root.joinpath('completed').write_text('done')
''')
        self.fake.chmod(0o700)

    def environment(self, root, mode='normal', check=0):
        root.mkdir()
        return {'PATH': '/usr/bin:/bin', 'HOME': str(self.root),
                'TIRITH_BIN': str(self.fake), 'TELEMETRY_ROOT': str(root),
                'TELEMETRY_MODE': mode, 'CHECK_EXIT': str(check),
                'PYTHONDONTWRITEBYTECODE': '1'}

    def test_python_helpers_wait_and_reap_without_inheriting_stdin(self):
        popen = subprocess.Popen
        for name in PYTHON_ASSETS:
            for mode in ('normal', 'nonzero', 'stubborn'):
                with self.subTest(asset=name, mode=mode):
                    module = load(ASSETS / name)
                    self.assertEqual(module.HOOK_EVENT_WAIT_SECONDS, .25)
                    self.assertEqual(module.HOOK_EVENT_REAP_SECONDS, .25)
                    if mode != 'stubborn':
                        # Normal telemetry may legitimately be discarded at
                        # 250 ms on a cold/loaded CI machine. This control
                        # tests successful wait/reap with a generous fixture
                        # budget; the stubborn control keeps production 250 ms.
                        module.HOOK_EVENT_WAIT_SECONDS = 2.0
                    root = self.root / (name + '-' + mode)
                    children = []
                    spawn_returned = []

                    def capture(*args, **kwargs):
                        child = popen(*args, **kwargs)
                        children.append(child)
                        if mode == 'stubborn':
                            deadline = time.monotonic() + 4
                            while not (root / 'stubborn-ready').exists():
                                if child.poll() is not None or time.monotonic() >= deadline:
                                    raise RuntimeError('controlled telemetry child never became ready')
                                time.sleep(.01)
                        spawn_returned.append(time.monotonic())
                        return child

                    try:
                        with mock.patch.dict(os.environ, self.environment(root, mode), clear=True), \
                                mock.patch.object(module.subprocess, 'Popen', side_effect=capture):
                            module._hook_event('check_ok', 'inert detail')
                        self.assertLess(time.monotonic()-spawn_returned[0], 2.5)
                        self.assertEqual(len(children), 1)
                        child = children[0]
                        self.assertIsNotNone(child.returncode, 'helper must reap before returning')
                        expected = {'normal': 0, 'nonzero': 17, 'stubborn': -signal.SIGKILL}[mode]
                        self.assertEqual(child.returncode, expected)
                        with self.assertRaises(ChildProcessError):
                            os.waitpid(child.pid, os.WNOHANG)
                        event = json.loads((root / 'started.json').read_text())
                        self.assertEqual(event['stdin'], '')
                        self.assertEqual(event['argv'][-2:], ['--detail', 'inert detail'])
                        self.assertEqual((root / 'completed').exists(), mode == 'normal')
                        self.assertFalse((root / 'late-write').exists())
                    finally:
                        for child in children:
                            if child.poll() is None:
                                child.kill()
                            child.wait(timeout=2)

    def test_python_exhausted_budget_and_missing_executable_are_optional(self):
        for name in PYTHON_ASSETS:
            with self.subTest(asset=name):
                module = load(ASSETS / name)
                module._HOOK_CHECK_DEADLINE = time.monotonic()
                with mock.patch.object(module.subprocess, 'Popen') as spawn:
                    module._hook_event('timeout')
                    spawn.assert_not_called()
                module._HOOK_CHECK_DEADLINE = None
                with mock.patch.dict(os.environ, {'TIRITH_BIN': str(self.root / 'absent')}, clear=True):
                    module._hook_event('check_ok')

    def test_python_unproven_reap_has_only_a_bounded_pathless_diagnostic(self):
        for name in PYTHON_ASSETS:
            with self.subTest(asset=name):
                module = load(ASSETS / name)
                child = mock.Mock()
                child.poll.return_value = None
                child.wait.side_effect = subprocess.TimeoutExpired('sensitive argv', .25)
                errors = io.StringIO()
                with mock.patch.object(module.subprocess, 'Popen', return_value=child), \
                        contextlib.redirect_stderr(errors):
                    module._hook_event('check_ok', 'sensitive detail')
                child.kill.assert_called_once_with()
                self.assertEqual(child.wait.call_count, 2)
                self.assertTrue(all(call.kwargs['timeout'] == .25 for call in child.wait.call_args_list))
                self.assertEqual(errors.getvalue(), 'tirith: optional hook telemetry unavailable\n')

    def test_python_telemetry_failures_preserve_allow_and_block_decisions(self):
        payloads = {
            'tirith-check.py': {'hook_event_name':'PreToolUse', 'tool_name':'Bash', 'tool_input':{'command':'echo inert'}},
            'copilot-cli-hook.py': {'toolName':'bash', 'toolArgs':json.dumps({'command':'echo inert'})},
            'kiro-hook.py': {'tool_name':'execute_bash', 'tool_input':{'command':'echo inert'}},
            'tirith-security-guard-gemini.py': {'hook_event_name':'BeforeTool', 'tool_name':'run_shell_command', 'tool_input':{'command':'echo inert'}},
        }
        for name in PYTHON_ASSETS:
            for check in (0, 1):
                observations = []
                for mode in ('normal', 'nonzero', 'stubborn'):
                    with self.subTest(asset=name, check=check, mode=mode):
                        module = load(ASSETS / name)
                        root = self.root / f'{name}-{check}-{mode}'
                        stdout, stderr = io.StringIO(), io.StringIO()
                        with mock.patch.dict(os.environ, self.environment(root, mode, check), clear=True), \
                                mock.patch.object(sys, 'stdin', io.StringIO(json.dumps(payloads[name]))), \
                                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            with self.assertRaises(SystemExit) as result:
                                module.main()
                        observations.append((result.exception.code, stdout.getvalue(), stderr.getvalue()))
                        # Optional telemetry may be discarded before interpreter
                        # startup; that must not change this decision control.
                self.assertEqual(observations[0], observations[1])
                self.assertEqual(observations[0], observations[2])
                if check == 1:
                    self.assertTrue('deny' in observations[0][1] or observations[0][0] == 2)

    def test_shell_helpers_wait_and_stop_late_writers(self):
        for name in SHELL_ASSETS:
            for mode in ('normal', 'nonzero', 'stubborn'):
                with self.subTest(asset=name, mode=mode):
                    root = self.root / (name + '-' + mode)
                    env = self.environment(root, mode)
                    source = (ASSETS / name).read_text()
                    begin = source.index('_tirith_hook_event() {')
                    end = source.index('\n}', begin) + 2
                    helper = source[begin:end]
                    self.assertEqual(helper.count('child.wait(timeout=0.25)'), 2)
                    if mode != 'stubborn':
                        helper = helper.replace('child.wait(timeout=0.25)', 'child.wait(timeout=2.0)', 1)
                    else:
                        # Admit a ready controlled child before measuring the
                        # unchanged production wait/kill/reap sequence.
                        helper = helper.replace('    child.wait(timeout=0.25)', '''    import os, pathlib, time
    ready = pathlib.Path(os.environ['TELEMETRY_ROOT']) / 'stubborn-ready'
    ready_deadline = time.monotonic() + 4
    while not ready.exists():
        if child.poll() is not None or time.monotonic() >= ready_deadline:
            raise RuntimeError('controlled child never became ready')
        time.sleep(.01)
    child.wait(timeout=0.25)''', 1)
                    driver = root / 'driver.sh'
                    driver.write_text('TIRITH_PYTHON=' + shlex.quote(sys.executable) + '\n' +
                                      helper + '\n_tirith_hook_event check_ok "inert detail"\n' +
                                      shlex.quote(sys.executable) + ' -I -S -c ' + shlex.quote(
                                          'import os,pathlib,time; r=pathlib.Path(os.environ["TELEMETRY_ROOT"]); '
                                          'assert r.joinpath("started.json").exists(); '
                                          'assert r.joinpath("completed").exists() == (os.environ["TELEMETRY_MODE"] == "normal"); '
                                          'time.sleep(1.1); assert not r.joinpath("late-write").exists()') + '\n')
                    result, _, errors = harness.execute(['/bin/bash', str(driver)], root, env, timeout=5)
                    self.assertTrue(harness.execution_ok(result), (result, errors.decode()))

    def test_shell_launcher_failure_has_no_raw_diagnostic_or_background_fallback(self):
        for name in SHELL_ASSETS:
            with self.subTest(asset=name):
                root = self.root / (name + '-launcher-failure')
                env = self.environment(root)
                launcher = root / 'failed-python'
                launcher.write_text('#!/bin/sh\nprintf raw-sensitive-placeholder >&2\nexit 1\n')
                launcher.chmod(0o700)
                source = (ASSETS / name).read_text()
                begin = source.index('_tirith_hook_event() {')
                end = source.index('\n}', begin) + 2
                driver = root / 'driver.sh'
                driver.write_text('TIRITH_PYTHON=' + shlex.quote(str(launcher)) + '\n' +
                                  source[begin:end] + '\n_tirith_hook_event check_ok\n')
                result, output, errors = harness.execute(['/bin/bash', str(driver)], root, env, timeout=5)
                self.assertTrue(harness.execution_ok(result))
                self.assertEqual(output, b'')
                self.assertEqual(errors, b'tirith: optional hook telemetry unavailable\n')
                self.assertFalse((root / 'started.json').exists())

    @unittest.skipUnless(shutil.which('node'), 'Node runtime required for TypeScript-compatible assets')
    def test_pi_optional_telemetry_cannot_shorten_the_checker_budget(self):
        root = self.root / 'pi-checker-budget'
        env = self.environment(root)
        env['TIRITH_HOOK_UNRESOLVED_ACTION'] = 'warn'
        source = (ASSETS / 'tirith-guard.ts').read_text()
        source = source.replace('"__TIRITH_BIN__"', '"/controlled/tirith"')
        source = source.replace('"__TIRITH_INTEGRATION__"', '"pi"')
        source = source.replace('import { execFileSync } from "node:child_process";', '''
const performance = {now:() => globalThis.controlledTelemetry.now};
function execFileSync(binary,args,options) {
  const state = globalThis.controlledTelemetry;
  state.events.push({command:args[0], timeout:options.timeout});
  if (args[0] === "check") {
    if (options.timeout < 9850) throw Object.assign(new Error("check timed out"), {killed:true, code:"ETIMEDOUT"});
    state.now += 9850;
    return "";
  }
  if (state.stubborn) {
    state.now += 250;
    throw Object.assign(new Error("telemetry timed out"), {signal:"SIGKILL", code:"ETIMEDOUT"});
  }
}''')
        (root / 'asset.mjs').write_text(source)
        driver = root / 'driver.mjs'
        driver.write_text('''import assert from "node:assert/strict";
import plugin from "./asset.mjs";
let handler;
plugin({on(name, callback) {handler=callback;}});
for (const stubborn of [false,true]) {
  globalThis.controlledTelemetry={now:0, events:[], stubborn};
  const result=await handler({toolName:"debug",input:{action:"launch",program:"echo",args:["inert"]}});
  assert.equal(result, undefined);
  assert.deepEqual(globalThis.controlledTelemetry.events,[{command:"check",timeout:10000}]);
}
''')
        result, _, errors = harness.execute([shutil.which('node'), str(driver)], root, env, timeout=5)
        self.assertTrue(harness.execution_ok(result), (result, errors.decode()))

    @unittest.skipUnless(shutil.which('node'), 'Node runtime required for TypeScript-compatible assets')
    def test_node_helpers_wait_stop_late_writers_and_skip_expired_budgets(self):
        node = shutil.which('node')
        for name in NODE_ASSETS:
            for mode in ('normal', 'nonzero', 'stubborn', 'expired'):
                with self.subTest(asset=name, mode=mode):
                    root = self.root / (name + '-' + mode)
                    env = self.environment(root, mode)
                    env['TIRITH_BIN'] = node
                    asset = root / 'asset.mjs'
                    source = (ASSETS / name).read_text()
                    # The Pi family pins this literal during setup; it does
                    # not use the ambient TIRITH_BIN environment variable.
                    source = source.replace('"__TIRITH_BIN__"', json.dumps(node))
                    source = source.replace('"__TIRITH_INTEGRATION__"', '"pi"')
                    # Record the actual native sync-child result. Allow normal
                    # startup a fixture-only generous budget; the stubborn
                    # control still executes the production 250 ms timeout.
                    source = source.replace('import { execFileSync } from "node:child_process";', '''
import { execFileSync as nativeExecFileSync } from "node:child_process";
globalThis.telemetryChildResults = [];
function execFileSync(binary, args, options) {
  if (options.timeout !== 250 || options.killSignal !== "SIGKILL" || options.stdio !== "ignore") throw new Error("telemetry contract changed");
  const timeout = ["normal", "nonzero"].includes(process.env.TELEMETRY_MODE) ? 2000 : options.timeout;
  try {
    const result = nativeExecFileSync(binary, args, {...options, timeout});
    globalThis.telemetryChildResults.push({status:0});
    return result;
  } catch (error) {
    globalThis.telemetryChildResults.push({status:error.status, signal:error.signal, code:error.code});
    throw error;
  }
}''')
                    asset.write_text(source + '\nexport { hookEvent };\n')
                    # Use the already selected Node runtime as a controlled
                    # child, without an unrelated Python cold-start budget.
                    (root / 'hook-event').write_text('''
const fs = require("node:fs"), path = require("node:path");
const root = process.env.TELEMETRY_ROOT, mode = process.env.TELEMETRY_MODE;
fs.writeFileSync(path.join(root,"started.json"), JSON.stringify({stdin:fs.readFileSync(0,"utf8")}));
if (mode === "stubborn") {
  process.on("SIGTERM", () => {});
  setTimeout(() => fs.writeFileSync(path.join(root,"late-write"), "should not survive"),1000);
} else if (mode === "nonzero") process.exit(17);
else setTimeout(() => fs.writeFileSync(path.join(root,"completed"),"done"),40);
''')
                    driver = root / 'driver.mjs'
                    driver.write_text('''import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { hookEvent } from "./asset.mjs";
const mode=process.env.TELEMETRY_MODE, root=process.env.TELEMETRY_ROOT;
hookEvent("check_ok", "inert detail", mode === "expired" ? 0 : Infinity);
if (mode !== "stubborn") assert.equal(existsSync(join(root,"started.json")), mode !== "expired");
if (existsSync(join(root,"started.json"))) assert.equal(JSON.parse(readFileSync(join(root,"started.json"))).stdin, "");
if (mode === "stubborn") assert.equal(globalThis.telemetryChildResults[0].signal, "SIGKILL");
if (mode === "nonzero") assert.equal(globalThis.telemetryChildResults[0].status,17);
assert.equal(existsSync(join(root,"completed")), mode === "normal");
await new Promise(resolve => setTimeout(resolve, 1100));
assert.equal(existsSync(join(root,"late-write")), false);
''')
                    result, _, errors = harness.execute([node, str(driver)], root, env, timeout=5)
                    self.assertTrue(harness.execution_ok(result), (result, errors.decode()))


if __name__ == '__main__':
    unittest.main()
