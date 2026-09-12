"""Fixture tests for the runner, not release/native compatibility evidence."""
import base64
import json
import os
import signal
import subprocess
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

import mixed_audit_native as runner


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = runner.isolated_env(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def child(self, script, timeout=2):
        return runner.Job("fixture", [sys.executable, "-c", script], self.root, self.env, timeout)

    def test_environment_isolated_from_caller(self):
        with mock.patch.dict(os.environ, {"TIRITH_POLICY": "/operator/policy", "SECRET_TOKEN": "secret"}):
            root = self.root / "another"
            root.mkdir()
            env = runner.isolated_env(root)
        self.assertNotIn("TIRITH_POLICY", env)
        self.assertNotIn("SECRET_TOKEN", env)
        self.assertEqual(env["HOME"], str(root))
        self.assertEqual(env["TIRITH_OFFLINE"], "1")
        self.assertTrue(all(str(root) in value for key, value in env.items() if key.startswith("XDG_")))

    def test_output_limit_kills_and_bounds_both_streams(self):
        job = self.child("import os; os.write(1,b'x'*2000000)")
        row = runner.finish([job])[0]
        self.assertEqual(row["failure"], "output-limit")
        self.assertEqual(len(row["stdout"]), runner.OUTPUT_LIMIT)
        self.assertIsNotNone(job.process.poll())

    def test_timeout_reaps_child(self):
        job = self.child("import time; time.sleep(10)", timeout=0.05)
        started = time.monotonic()
        row = runner.finish([job])[0]
        self.assertEqual(row["failure"], "timeout")
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNotNone(job.process.poll())

    def test_timeout_after_stdout_is_closed(self):
        job = self.child("import os,time; os.close(1); os.close(2); time.sleep(10)", timeout=0.05)
        self.assertEqual(runner.finish([job])[0]["failure"], "timeout")

    def test_descendant_inheriting_pipe_is_bounded(self):
        script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'])"
        started = time.monotonic()
        row = runner.finish([self.child(script, timeout=0.15)])[0]
        self.assertEqual(row["failure"], "timeout")
        self.assertLess(time.monotonic() - started, 2)

    def test_pipe_drain_deadline_does_not_signal_an_unrelated_group(self):
        # An explicitly owned second fixture holds an inherited write end. It
        # models an out-of-group pipe holder without orphaning an escaped child
        # or signaling a stale PID from a file during test cleanup.
        read_fd, write_fd = os.pipe()
        holder = runner.OwnedProcess([sys.executable, "-c", "import time; time.sleep(10)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(write_fd,), start_new_session=True)
        job = self.child("pass", timeout=0.1)
        original = job.process.stdout
        job.process.stdout = os.fdopen(read_fd, "rb", buffering=0)
        os.close(write_fd)
        try:
            started = job.started = time.monotonic()
            row = runner.finish([job])[0]
            self.assertEqual(row["failure"], "timeout")
            self.assertFalse(row["cleanup"]["output_eof"])
            self.assertLess(time.monotonic() - started, 4)
            with self.assertRaises(AssertionError):
                runner.success(row)
        finally:
            job.kill()
            original.close()
            holder.kill()
            holder.wait(timeout=2)
            holder.reap()
            holder.stdout.close()
            holder.stderr.close()

    def test_persistent_group_permission_failure_cannot_pass_cleanup(self):
        job = self.child("print('inert',flush=True)")
        with mock.patch.object(runner.os, "killpg", side_effect=PermissionError("fixture refusal")), \
             mock.patch.object(runner, "group_members", return_value=[{"pid": job.process.pid, "state": "live"}]), \
             mock.patch.object(runner, "CLEANUP_TIMEOUT", 0.05):
            row = runner.finish([job])[0]
        self.assertEqual(row["failure"], "process-cleanup")
        self.assertTrue(row["cleanup"]["leader_reaped"])
        self.assertFalse(row["cleanup"]["group_signaled_or_absent"])
        self.assertFalse(row["cleanup"]["group_members_exited"])

    def test_poll_and_wait_retain_waitable_native_leader(self):
        job = self.child("raise SystemExit(7)")
        self.assertEqual(job.process.wait(timeout=2), 7)
        self.assertEqual(job.process.poll(), 7)
        event = os.waitid(os.P_PID, job.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        self.assertEqual(event.si_pid, job.process.pid)
        self.assertEqual(event.si_status, 7)
        self.assertFalse(job.process.reaped)
        row = runner.finish([job])[0]
        self.assertEqual(row["exit"], 7)
        self.assertTrue(all(row["cleanup"].values()))
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_PID, job.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def test_group_signals_precede_single_reap_and_never_repeat_afterwards(self):
        job = self.child("pass")
        job.process.wait(timeout=2)
        calls = []
        original_killpg = os.killpg
        def checked_signal(pid, sig):
            event = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            self.assertEqual(event.si_pid, job.process.pid)
            calls.append((pid, sig))
            return original_killpg(pid, sig)
        with mock.patch.object(runner.os, "killpg", side_effect=checked_signal), \
             mock.patch.object(job.process._child, "wait", wraps=job.process._child.wait) as reaper:
            row = runner.finish([job])[0]
            count = len(calls)
            job.kill()
            job.process.poll()
            job.process.wait(timeout=0)
            self.assertEqual(len(calls), count)
            self.assertEqual(reaper.call_count, 1)
        self.assertTrue(all(row["cleanup"].values()))

    def test_closed_pipe_descendant_is_observed_and_terminated(self):
        ready = self.root / "closed-pipe-descendant"
        source = ("import subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-c',"
            "'import os,time; os.close(1); os.close(2); time.sleep(10)']); "
            f"open({str(ready)!r},'w').write(str(p.pid)); time.sleep(10)")
        job = self.child(source)
        try:
            deadline = time.monotonic() + 2
            while not ready.exists() or not ready.read_text():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            child_pid = int(ready.read_text())
            self.assertIn(child_pid, [member["pid"] for member in runner.group_members(job.process.pid)])
            job.kill()
            row = runner.finish([job])[0]
            self.assertTrue(row["cleanup"]["group_members_exited"])
            self.assertTrue(row["group_observation"]["leader_retained_waitable"])
            self.assertTrue(all(member["state"] == "exited" for member in row["group_observation"]["members"]))
            self.assertTrue(all(row["cleanup"].values()))
        finally:
            job.kill()

    def test_native_observation_failure_cannot_pass_even_with_output_eof(self):
        job = self.child("pass")
        with mock.patch.object(runner, "group_members", side_effect=OSError("fixture observation denied")):
            row = runner.finish([job])[0]
        self.assertEqual(row["failure"], "process-cleanup")
        self.assertTrue(row["cleanup"]["output_eof"])
        self.assertTrue(row["cleanup"]["leader_reaped"])
        self.assertFalse(row["cleanup"]["group_members_exited"])

    def test_empty_native_group_result_cannot_hide_observer_error(self):
        library = mock.Mock()
        for code in (runner.errno.EPERM, runner.errno.ENOMEM, runner.errno.ESRCH, runner.errno.ENOENT):
            def denied(*args):
                runner.ctypes.set_errno(code)
                return 0
            library.proc_listpids.side_effect = denied
            with self.subTest(errno=code), \
                 mock.patch.object(runner.sys, "platform", "darwin"), \
                 mock.patch.object(runner, "_darwin_proc", return_value=library):
                with self.assertRaisesRegex(AssertionError, "absence proof"):
                    runner.group_members(123)

    def test_unsupported_waitid_refuses_before_spawn(self):
        with mock.patch.object(runner.os, "waitid", create=True, new=None), \
             mock.patch.object(runner.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(AssertionError, "waitid"):
                self.child("pass")
            spawn.assert_not_called()

    def test_premature_explicit_reap_refuses_all_numeric_group_signals(self):
        job = self.child("pass")
        job.process.wait(timeout=2)
        job.process.reap()
        with mock.patch.object(runner.os, "killpg") as send:
            row = runner.finish([job])[0]
            send.assert_not_called()
        self.assertEqual(row["failure"], "process-cleanup")
        self.assertFalse(row["cleanup"]["group_members_exited"])

    def test_external_reap_loses_ownership_and_cannot_signal_a_reused_pid(self):
        job = self.child("pass")
        job.process.wait(timeout=2)
        pid, status = os.waitpid(job.process.pid, 0)
        self.assertEqual(pid, job.process.pid)
        with mock.patch.object(runner.os, "killpg") as group_send, \
             mock.patch.object(runner.os, "kill") as direct_send:
            job.kill()
            group_send.assert_not_called()
            direct_send.assert_not_called()
        self.assertTrue(job.process.ownership_lost)
        self.assertEqual(job.failure, "process-cleanup")
        self.assertFalse(job.cleanup["group_members_exited"])
        # The test consumed the owned status deliberately; avoid letting Popen's
        # destructor attempt a second reap. Production never invents this value.
        job.process._child.returncode = os.waitstatus_to_exitcode(status)
        job.process.stdout.close()
        job.process.stderr.close()

    def test_observed_stop_does_not_reap_or_replace_exit_status(self):
        job = self.child("import time; time.sleep(10)")
        try:
            job.process.send_signal(signal.SIGSTOP)
            deadline = time.monotonic() + 2
            while True:
                event = job.process.observe_stop()
                if event is not None:
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            self.assertEqual(event.si_code, os.CLD_STOPPED)
            self.assertEqual(event.si_status, signal.SIGSTOP)
            self.assertIsNone(job.process.poll())
            job.kill()
            row = runner.finish([job])[0]
            self.assertEqual(row["exit"], -signal.SIGKILL)
            self.assertTrue(all(row["cleanup"].values()))
        finally:
            job.kill()

    def test_fast_exit_cleanup_reaps_every_owned_child(self):
        for _ in range(8):
            row = runner.finish([self.child("pass")])[0]
            runner.success(row)
            self.assertTrue(all(row["cleanup"].values()))

    def test_stopped_child_cleanup(self):
        job = self.child("import os,signal; os.kill(os.getpid(),signal.SIGSTOP)", timeout=0.05)
        self.assertEqual(runner.finish([job])[0]["failure"], "timeout")
        self.assertIsNotNone(job.process.poll())

    def test_concurrent_drain_preserves_each_result(self):
        jobs = [self.child(f"print({index})") for index in range(4)]
        rows = runner.finish(jobs)
        self.assertEqual([r["stdout"].strip() for r in rows], [str(i) for i in range(4)])
        for row in rows:
            runner.success(row)

    def test_hash_mismatch_rejected_before_output_creation(self):
        baseline, candidate = self.root / "baseline", self.root / "candidate"
        baseline.write_bytes(b"baseline-fixture")
        candidate.write_bytes(b"candidate-fixture")
        output = self.root / "report"
        with self.assertRaisesRegex(AssertionError, "SHA-256 mismatch"):
            runner.main(["--baseline", str(baseline), "--baseline-sha256", "0" * 64,
                         "--candidate", str(candidate), "--candidate-sha256", runner.file_sha(candidate),
                         "--output", str(output)])
        self.assertFalse(output.exists())

    def test_existing_output_never_overwritten(self):
        baseline, candidate = self.root / "baseline", self.root / "candidate"
        baseline.write_bytes(b"baseline-fixture")
        candidate.write_bytes(b"candidate-fixture")
        output = self.root / "already-exists"
        output.mkdir()
        sentinel = output / "operator-content"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            runner.main(["--baseline", str(baseline), "--baseline-sha256", runner.file_sha(baseline),
                         "--candidate", str(candidate), "--candidate-sha256", runner.file_sha(candidate),
                         "--output", str(output)])
        self.assertEqual(sentinel.read_text(), "preserve")

    def test_symlink_binary_rejected(self):
        target = self.root / "target"
        target.write_bytes(b"fixture")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaisesRegex(AssertionError, "regular file"):
            runner.file_sha(link)

    def test_fixture_file_read_cap(self):
        path = self.root / "oversize"
        path.write_bytes(b"12345")
        with mock.patch.object(runner, "FILE_LIMIT", 4):
            with self.assertRaisesRegex(AssertionError, "exceeds limit"):
                runner.read_bytes(path)

    def test_signed_shape_and_count_checks(self):
        sig = base64.b64encode(bytes(64)).decode()
        # All-zero bytes intentionally test framing only. Real signatures are
        # established exclusively by BOTH actual native verification commands.
        fixture = json.dumps({"sig": sig}).encode() + b"\n"
        self.assertEqual(len(runner.check_rows(fixture, True, 1)), 1)
        for body, signed, count in [(b"{}\n", True, 1), (fixture, False, 1),
                                    (fixture, True, 2), (fixture[:-1], True, 1)]:
            with self.assertRaises(AssertionError):
                runner.check_rows(body, signed, count)

    def test_command_accounting_rejects_duplicate_with_correct_count(self):
        rows = [{"command_redacted": "echo one"}, {"command_redacted": "echo one"}]
        with self.assertRaisesRegex(AssertionError, "duplicated"):
            runner.check_commands(rows, ["echo one", "echo two"])
        runner.check_commands(rows, ["echo one", "echo one"])

    def test_native_verifier_result_must_include_head_count_and_signing(self):
        row = {"name": "fixture", "exit": 0, "failure": None, "stderr": "",
               "stdout": "tirith audit verify: OK (3 lines, 2 chained, 0 legacy)\n  head receipt OK (count 3)\n  signing: enabled (3 signed line(s))\n"}
        runner.verify_output(row, True, 3)
        for bad in [dict(row, exit=1), dict(row, failure="timeout"),
                    dict(row, stdout=row["stdout"].replace("count 3", "count 2")),
                    dict(row, stdout=row["stdout"].replace("3 signed", "2 signed"))]:
            with self.assertRaises(AssertionError):
                runner.verify_output(bad, True, 3)

    def test_failing_case_removes_public_fixture_private_key(self):
        case = runner.Case(self.root, "cleanup-test", True, {})
        self.assertEqual(case.key.read_bytes(), runner.FIXTURE_SEED)
        self.assertEqual(case.key.stat().st_mode & 0o777, 0o600)
        result = case.complete(lambda _: runner.require(False, "injected fixture failure"))
        self.assertFalse(result["passed"])
        self.assertTrue(result["fixture_private_key_removed"])
        self.assertFalse(case.key.exists())
        self.assertIn("injected fixture failure", result["error"])
        self.assertEqual(json.loads((case.root / "case.json").read_text()), result)

    def test_cleanup_exception_still_removes_public_fixture_private_key(self):
        case = runner.Case(self.root, "cleanup-exception", True, {})
        job = mock.Mock()
        job.process.poll.return_value = None
        job.kill.side_effect = RuntimeError("fixture cleanup error")
        case.jobs.append(job)
        with self.assertRaisesRegex(RuntimeError, "fixture cleanup error"):
            case.complete(lambda _: None)
        self.assertFalse(case.key.exists())

    def test_archive_bytes_cannot_be_substituted(self):
        case = runner.Case(self.root, "archive-test", False, {})
        directory = case.log.parent / "audit-segments/op"
        directory.mkdir(parents=True)
        body = b'{"action":"Allow"}\n'
        (directory / "0000.chunk").write_bytes(body)
        runner.save_json(directory / "manifest.json", {"operation_id": "op", "chunks": [
            {"bytes": len(body), "sha256": runner.sha(body)}]})
        with self.assertRaisesRegex(AssertionError, "exact original log bytes"):
            case.archive("op", b"different original\n", b"head")


if __name__ == "__main__":
    unittest.main(verbosity=2)
