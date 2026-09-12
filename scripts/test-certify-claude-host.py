#!/usr/bin/env python3
"""Focused fixture invariants; these unit tests are not native host certification."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
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
            self.assertEqual(Path(env['TIRITH_BIN']).read_text(), '#!/bin/sh\nexec /bin/sleep 30\n')

if __name__ == '__main__':
    unittest.main()
