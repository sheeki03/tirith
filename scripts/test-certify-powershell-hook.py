#!/usr/bin/env python3
"""Test native certification resource bounds without requiring PowerShell."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location(
    'powershell_certification', Path(__file__).with_name('certify-powershell-hook.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class NativeProcessBounds(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_fixture(self, code, timeout=5):
        harness.run_bounded([sys.executable, '-I', '-c', code], self.root,
                            dict(os.environ), self.root / 'process.log', timeout)

    def test_fast_oversized_output_is_rejected_after_process_exit(self):
        with self.assertRaisesRegex(AssertionError, 'output limit'):
            self.run_fixture('import os; os.write(1, b"x" * 3145728)')

    def test_nonzero_native_exit_is_not_accepted(self):
        with self.assertRaisesRegex(AssertionError, 'native process exit 17'):
            self.run_fixture('raise SystemExit(17)')

    def test_stalled_native_process_is_bounded(self):
        start = time.monotonic()
        with self.assertRaisesRegex(AssertionError, 'time/output limit'):
            self.run_fixture('import time; time.sleep(30)', timeout=.1)
        self.assertLess(time.monotonic() - start, 5)

    @unittest.skipUnless(os.name == 'posix', 'native POSIX process-group contract')
    def test_background_descendant_is_stopped_when_direct_child_finishes(self):
        # The direct child exits normally; its descendant would write later if
        # the harness only cleaned up a still-running direct child.
        self.run_fixture(
            'import os, pathlib, time; child = os.fork(); '
            'os._exit(0) if child else None; time.sleep(.6); '
            'pathlib.Path("escaped.txt").write_text("ran")')
        time.sleep(.8)
        self.assertFalse((self.root / 'escaped.txt').exists())

    def test_existing_evidence_directory_is_never_overwritten(self):
        sentinel = self.root / 'sentinel'
        sentinel.write_text('retain me')
        process = subprocess.run([
            sys.executable, '-I', str(Path(harness.__file__)),
            '--binary', sys.executable, '--powershell', sys.executable,
            '--hook', str(sentinel), '--output', str(self.root),
            '--noninteractive-only'], capture_output=True, timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(sentinel.read_text(), 'retain me')
        self.assertFalse((self.root / 'report.json').exists())

    @unittest.skipUnless(os.name == 'posix', 'native POSIX PTY contract')
    def test_quick_exit_terminal_is_reaped_and_trace_is_retained(self):
        terminal = harness.Terminal('/usr/bin/true', self.root, dict(os.environ), [])
        terminal.pump(.1)
        time.sleep(.1)
        terminal.close()
        self.assertTrue((self.root / 'terminal.log').is_file())
        with self.assertRaises(ChildProcessError):
            os.waitpid(terminal.pid, os.WNOHANG)


if __name__ == '__main__':
    unittest.main()
