"""Runner contracts only; these fixtures are not product recovery evidence."""
import errno
import fcntl
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import durable_boundaries_native as runner


class RunnerContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.case = runner.Case(self.root, "fixture", Path(sys.executable))

    def tearDown(self):
        for job in self.case.jobs:
            if not getattr(job, "qualification_finished", False):
                job.kill()
                self.case.finish(job)
        self.temp.cleanup()

    def result(self):
        return {"name": "fixture", "failure": None, "exit": 0, "stdout": "", "stderr": "",
                "cleanup": {"leader_reaped": True, "group_signaled_or_absent": True, "group_members_exited": True, "output_eof": True}}

    def test_clean_requires_each_explicit_boolean_cleanup_fact(self):
        for invalid in ({}, {"leader_reaped": True}, {"leader_reaped": True,
            "group_signaled_or_absent": True, "output_eof": 1}):
            with self.subTest(cleanup=invalid), self.assertRaisesRegex(AssertionError, "cleanup"):
                runner.clean(dict(self.result(), cleanup=invalid))
        for key in self.result()["cleanup"]:
            result = self.result()
            result["cleanup"][key] = False
            with self.subTest(key=key), self.assertRaises(AssertionError):
                runner.clean(result)
        runner.clean(self.result(), 0)

    def test_killed_result_needs_exact_signal_and_successful_cleanup(self):
        result = dict(self.result(), exit=-signal.SIGKILL)
        runner.clean(result, -signal.SIGKILL)
        for bad in (dict(result, exit=-signal.SIGTERM), dict(result, failure="output-drain-timeout")):
            with self.assertRaises(AssertionError):
                runner.clean(bad, -signal.SIGKILL)

    def test_expected_status_text_cannot_hide_runner_failure(self):
        result = dict(self.result(), stdout='{"state":"completed"}', failure="process-cleanup")
        with self.assertRaises(AssertionError):
            runner.operation_state(result, {"completed"})

    def test_status_rejects_unknown_or_malformed_result(self):
        for text in ('{"state":"running"}', '{}', 'not json'):
            with self.assertRaises((AssertionError, KeyError, json.JSONDecodeError)):
                runner.operation_state(dict(self.result(), stdout=text), {"completed"})

    def test_completed_json_requires_the_command_success_exit(self):
        for state in ("completed", "completed-with-recovery", "undone", "cancelled"):
            for code in (1, 7, -signal.SIGSEGV):
                with self.subTest(state=state, code=code), self.assertRaises(AssertionError):
                    runner.operation_state(dict(self.result(), exit=code, stdout=json.dumps({"state": state})), {state})
        with self.assertRaises(AssertionError):
            runner.operation_state(dict(self.result(), stdout='{"state":"recovery-required"}'), {"recovery-required"})

    def test_crash_with_expected_refusal_text_is_not_a_refusal(self):
        for code in (-signal.SIGSEGV, -signal.SIGKILL, 2):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                runner.refusal(dict(self.result(), exit=code, stderr="expected diagnostic"), "expected diagnostic")
        runner.refusal(dict(self.result(), exit=1, stderr="expected diagnostic"), "expected diagnostic")
        with self.assertRaises(AssertionError):
            runner.refusal(dict(self.result(), exit=1, stderr="unrelated failure"), "expected diagnostic")

    def test_profile_published_requires_all_exact_owned_values(self):
        path = self.root / "policy.yaml"
        for bad in (b"action_overrides: {}\nscan: {}\nstrict_warn: false\n",
                    runner.STRICT_PROFILE_BYTES.replace(b"paranoia: 1", b"paranoia: 4"),
                    runner.STRICT_PROFILE_BYTES.replace(b"allow_bypass_env: false\n", b"")):
            path.write_bytes(bad)
            with self.assertRaises(AssertionError):
                runner.strict_profile_published(path)
        path.write_bytes(runner.STRICT_PROFILE_BYTES)
        runner.strict_profile_published(path)

    def test_claimed_completed_noop_profile_fails_actual_recovery_route(self):
        self.case.policy.parent.mkdir(parents=True)
        self.case.original = b"action_overrides: {}\nscan: {}\nstrict_warn: false\n"
        self.case.policy.write_bytes(self.case.original)
        boundary = {"observed_stage": "before-policy-publication", "snapshot": self.case.snapshot()}
        def operation(action):
            state = "recovery-required" if action == "status" else "completed"
            return dict(self.result(), exit=1 if action == "status" else 0,
                        stdout=json.dumps({"state": state}))
        with mock.patch.object(self.case, "prepare_profile"), mock.patch.object(self.case, "start"), \
             mock.patch.object(self.case, "capture_stopped", return_value=boundary), \
             mock.patch.object(self.case, "kill_stopped"), mock.patch.object(self.case, "operation", side_effect=operation):
            with self.assertRaisesRegex(AssertionError, "owned postconditions"):
                runner.crash_profile(self.case, "before-policy-publication")

    def test_profile_journal_rejects_noop_or_changed_owned_value(self):
        fields = [{"Field": {"yaml": True, "pointer": pointer, "before": None, "after": value}}
                  for pointer, value in runner.STRICT_PROFILE_FIELDS.items()]
        record = {"kind": "set-profile", "steps": [{"edit": {"Compound": fields}}]}
        runner.strict_profile_plan(record)
        fields[0]["Field"]["after"] = None
        with self.assertRaises(AssertionError):
            runner.strict_profile_plan(record)
        record["steps"] = []
        with self.assertRaises(AssertionError):
            runner.strict_profile_plan(record)

    def test_fingerprint_detects_replaced_inode_with_identical_bytes(self):
        path = self.root / "generation"
        path.write_bytes(b"fixed bytes")
        before = runner.fingerprint(path)
        held = path.open("rb")
        try:
            replacement = self.root / "replacement"
            replacement.write_bytes(b"fixed bytes")
            replacement.replace(path)
            after = runner.fingerprint(path)
            self.assertEqual(before["sha256"], after["sha256"])
            self.assertNotEqual(before["identity"], after["identity"])
        finally:
            held.close()

    def test_fingerprint_rejects_symlink(self):
        path = self.root / "target"
        path.write_bytes(b"fixture")
        link = self.root / "alias"
        link.symlink_to(path)
        with self.assertRaisesRegex(AssertionError, "regular"):
            runner.fingerprint(link)

    def test_lock_probe_does_not_leave_lock_held(self):
        path = self.root / "lock"
        path.touch()
        self.assertFalse(runner.lock_busy(path))
        with path.open("rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(runner.lock_busy(path))
            fcntl.flock(held, fcntl.LOCK_UN)
        self.assertFalse(runner.lock_busy(path))

    def test_actual_stop_acknowledgement_lock_release_and_kill(self):
        lock = self.case.execution_lock
        lock.parent.mkdir(parents=True)
        ready = self.case.root / "ready"
        source = "import fcntl,time; f=open(%r,'w'); fcntl.flock(f,fcntl.LOCK_EX); open(%r,'w').write('ready'); time.sleep(20)" % (str(lock), str(ready))
        job = self.case.start("lock-owner", ["-c", source])
        deadline = time.monotonic() + 3
        while not ready.exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.001)
        evidence = runner.stopped_owner(job, lock)
        self.assertEqual(evidence["pid"], job.process.pid)
        self.assertTrue(evidence["lock_contended_while_stopped"])
        self.case.kill_stopped(job)
        self.assertFalse(runner.lock_busy(lock))
        self.assertEqual(self.case.rows[-1]["exit"], -signal.SIGKILL)

    def test_exit_racing_stop_does_not_reap_or_signal_again(self):
        job = mock.Mock()
        job.process.pid = 123
        job.process.poll.return_value = None
        job.process.observe_stop.return_value = SimpleNamespace(si_pid=123, si_code=os.CLD_EXITED, si_status=7)
        with mock.patch.object(runner.os, "waitpid") as reaping_wait:
            with self.assertRaises(runner.Unobserved):
                runner.stopped_owner(job, self.root / "unused")
        reaping_wait.assert_not_called()
        job.process.send_signal.assert_called_once_with(signal.SIGSTOP)

    def test_stopped_waiter_is_not_certified_as_lock_owner(self):
        lock = self.root / "unheld-lock"
        lock.touch()
        job = self.case.start("not-owner", ["-c", "import time; time.sleep(20)"])
        with self.assertRaisesRegex(AssertionError, "did not retain"):
            runner.stopped_owner(job, lock)
        job.kill()
        runner.clean(self.case.finish(job)[0], -signal.SIGKILL)

    def test_unobserved_case_drains_an_already_exited_process(self):
        def unobserved(case):
            job = case.start("fast-exit", ["-c", "print('inert')"])
            job.process.wait(timeout=3)
            raise runner.Unobserved("test boundary not observed")
        result = self.case.complete(unobserved)
        self.assertEqual(result["outcome"], "unobserved")
        self.assertTrue(all(result["rows"][0]["cleanup"].values()))

    def test_unobserved_case_cleans_a_still_live_process(self):
        def unobserved(case):
            case.start("live", ["-c", "import time; time.sleep(20)"])
            raise runner.Unobserved("test boundary not observed")
        result = self.case.complete(unobserved)
        self.assertEqual(result["outcome"], "unobserved")
        self.assertEqual(result["rows"][0]["exit"], -signal.SIGKILL)

    def test_cleanup_failure_never_becomes_an_unobserved_skip(self):
        def unobserved(case):
            job = mock.Mock()
            job.qualification_finished = True
            job.failure = "process-cleanup"
            job.cleanup = {"leader_reaped": False}
            case.jobs.append(job)
            raise runner.Unobserved("boundary missed")
        result = self.case.complete(unobserved)
        self.assertEqual(result["outcome"], "failed")

    def test_rotation_classifier_requires_exact_barrier_and_genesis(self):
        self.case.log.parent.mkdir(parents=True)
        self.case.original = b'original\n'
        self.case.original_head = b'{"head":"original"}'
        barrier, genesis, head = b'{"rotation":"fixture"}', b'genesis\n', b'{"head":"genesis"}'
        self.case.plan = {"barrier": list(barrier), "genesis": list(genesis), "genesis_head": list(head)}
        for body, receipt, expected in ((b'original\n', self.case.original_head, 'before-archive'),
            (b'original\n', barrier, 'barrier-before-truncate'), (b'', barrier, 'empty-after-truncate'),
            (genesis, barrier, 'genesis-before-head'), (genesis, head, 'applied-before-result'),
            (b'other\n', head, 'other'), (b'gen', barrier, 'other-barrier-state')):
            self.case.log.write_bytes(body)
            self.case.head.write_bytes(receipt)
            self.assertEqual(self.case.rotation_stage(), expected)

    def test_presignal_stage_cannot_certify_a_different_stopped_stage(self):
        self.case.journal.parent.mkdir(parents=True)
        self.case.log.parent.mkdir(parents=True)
        self.case.log.write_bytes(b"original\n")
        runner.save_json(self.case.journal, {"state": "running", "steps": [{"state": "applying"}]})
        job = mock.Mock()
        job.process.poll.return_value = None
        with mock.patch.object(self.case, "rotation_stage", side_effect=["before-archive", "archive-published"]), \
             mock.patch.object(runner, "lock_busy", return_value=True), \
             mock.patch.object(runner, "stopped_owner", return_value={"pid": 123}):
            with self.assertRaisesRegex(runner.Unobserved, "boundary advanced"):
                self.case.capture_stopped(job, "audit", "before-archive")
        observed = self.case.observations["boundary"]
        self.assertEqual(observed["requested_stage"], "before-archive")
        self.assertEqual(observed["observed_stage"], "archive-published")
        self.assertTrue((self.case.root / "stopped-boundary.json").exists())

    def test_stopped_journal_must_still_be_running_and_applying(self):
        self.case.journal.parent.mkdir(parents=True)
        self.case.log.parent.mkdir(parents=True)
        self.case.log.write_bytes(b"original\n")
        for state, step in (("completed", "applied"), ("running", "applied"), ("completed", "applying")):
            runner.save_json(self.case.journal, {"state": "running", "steps": [{"state": "applying"}]})
            job = mock.Mock()
            job.process.poll.return_value = None
            def stop(*args):
                runner.save_json(self.case.journal, {"state": state, "steps": [{"state": step}]})
                return {"pid": 123}
            with self.subTest(state=state, step=step), \
                 mock.patch.object(self.case, "rotation_stage", return_value="before-archive"), \
                 mock.patch.object(runner, "lock_busy", return_value=True), \
                 mock.patch.object(runner, "stopped_owner", side_effect=stop):
                with self.assertRaisesRegex(runner.Unobserved, "boundary advanced"):
                    self.case.capture_stopped(job, "audit", "before-archive")
            self.assertEqual(self.case.observations["boundary"]["journal_state"], state)
            self.assertEqual(self.case.observations["boundary"]["step_states"], [step])

    def test_partial_or_mismatched_observations_fail_aggregate_and_exit(self):
        candidate = self.root / "candidate"
        candidate.write_bytes(b"unused fixture candidate")
        bad_cases = (
            {"outcome": "unobserved", "observations": {}, "reason": "not sampled"},
            {"outcome": "passed", "observations": {"boundary": {
                "requested_stage": "before-archive", "observed_stage": "archive-published"}}},
        )
        for index, bad in enumerate(bad_cases):
            output = self.root / ("partial-" + str(index))
            good = {"outcome": "passed", "observations": {}}
            with self.subTest(case=bad), mock.patch.object(runner.os, "geteuid", return_value=501), \
                 mock.patch.object(runner.Case, "complete", side_effect=[good, bad]), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = runner.main(["--candidate", str(candidate), "--candidate-sha256", runner.shared.file_sha(candidate),
                                    "--output", str(output), "--case", "audit-before-archive", "--case", "audit-archive-published"])
            self.assertEqual(code, 1)
            report = json.loads((output / "report.json").read_bytes())
            self.assertFalse(report["passed"])
            self.assertFalse(report["all_requested_boundaries_observed"])
            self.assertEqual(report["cases"][1], bad)

    def test_archive_verification_rejects_changed_exact_source_bytes(self):
        self.case.archive.mkdir(parents=True)
        self.case.original = b"original bytes"
        self.case.original_head = b"head"
        body = b"different bytes"
        (self.case.archive / "0000.chunk").write_bytes(body)
        runner.save_json(self.case.archive / "manifest.json", {"operation_id": self.case.id,
            "chunks": [{"bytes": len(body), "sha256": runner.sha(body)}], "sha256": runner.sha(body)})
        with self.assertRaises(AssertionError):
            self.case.verify_archive()

    def test_bad_binary_hash_refuses_before_evidence_creation(self):
        path = self.root / "candidate"
        path.write_bytes(b"fixture")
        output = self.root / "evidence"
        with mock.patch.object(runner.os, "geteuid", return_value=501), self.assertRaisesRegex(AssertionError, "SHA-256 mismatch"):
            runner.main(["--candidate", str(path), "--candidate-sha256", "0" * 64, "--output", str(output)])
        self.assertFalse(output.exists())

    def test_existing_output_never_overwritten(self):
        path = self.root / "candidate"
        path.write_bytes(b"fixture")
        output = self.root / "evidence"
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_bytes(b"preserve")
        with mock.patch.object(runner.os, "geteuid", return_value=501), self.assertRaises(FileExistsError):
            runner.main(["--candidate", str(path), "--candidate-sha256", runner.shared.file_sha(path), "--output", str(output)])
        self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_root_cannot_claim_permission_failure(self):
        with mock.patch.object(runner.os, "geteuid", return_value=0), self.assertRaises(runner.Unobserved):
            runner.storage_failure(self.case, "log-permission")

    def test_os_file_size_ceiling_returns_real_efbig(self):
        # Tests the resource-ceiling mechanism only, not a native Tirith append.
        target = self.case.root / "size-bound"
        target.write_bytes(b"full")
        script = ("import os,resource,signal,errno; resource.setrlimit(resource.RLIMIT_FSIZE,(4,4)); "
                  "signal.signal(signal.SIGXFSZ,signal.SIG_IGN); f=os.open(%r,os.O_APPEND|os.O_WRONLY); os.lseek(f,0,os.SEEK_END); "
                  "\ntry: os.write(f,b'x')\nexcept OSError as e: print(e.errno)\nfinally: os.close(f)" % str(target))
        result = self.case.run("ceiling", ["-c", script])
        runner.clean(result, 0)
        self.assertEqual(int(result["stdout"].strip()), errno.EFBIG)
        self.assertEqual(target.read_bytes(), b"full")


if __name__ == "__main__":
    unittest.main(verbosity=2)
