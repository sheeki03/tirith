#!/usr/bin/env python3
"""Owner/predicate controls: inert files and finite Python children, no product/browser."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import uuid

PATH = Path(__file__).with_name("test-control-browser.py")
spec = importlib.util.spec_from_file_location("control_browser_owner", PATH)
HARNESS = importlib.util.module_from_spec(spec)
with patch.dict("sys.modules", {"playwright": types.ModuleType("playwright"),
        "playwright.sync_api": types.SimpleNamespace(sync_playwright=None)}):
    spec.loader.exec_module(HARNESS)


def row():
    return {"name": "owned-service-fixture", "pid": 43210, "exit": 0, "failure": None,
            "elapsed_seconds": 0.1, "group_observation": {"method": "fixture"},
            "stdout": "secret-launch-output", "stderr": "", "argv": ["private-argv"],
            "cleanup": dict.fromkeys(("leader_reaped", "group_signaled_or_absent",
                                      "group_members_exited", "output_eof"), True)}


class Job:
    def __init__(self):
        self.process = types.SimpleNamespace(pid=43210, poll=lambda: None,
            stdout=types.SimpleNamespace(close=lambda: None), stderr=types.SimpleNamespace(close=lambda: None))
        self.started, self.timeout = time.monotonic(), 900
        self.failure, self.killed, self.cleanup_attempted = None, False, False
        self.row = row()
    def kill(self):
        self.killed = True
        self.cleanup_attempted = True
    def result(self):
        return self.row


class OwnerControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / "service.json"
        self.job = Job()
        self.startup = str(uuid.uuid4())
        self.record = {"protocol": 1, "pid": self.job.process.pid, "startup_id": self.startup,
                       "binary_sha256": "a" * 64, "cwd": str(self.root), "port": 12345,
                       "service_id": str(uuid.uuid4()), "token": "b" * 64}
        self.write_record()
        self.report = {"checks": [], "cli_observations": []}
        self.native = types.SimpleNamespace(finish=lambda jobs: [jobs[0].row])
        self.owner = HARNESS.BrowserOwner(self.native, self.root / "inert-binary", self.root, self.report, 900)
        self.owner.service = self.job
        self.owner.authentication = ("http://127.0.0.1:12345", "bearer-canary", "csrf-canary")
    def write_record(self):
        self.path.write_text(json.dumps(self.record)); self.path.chmod(0o600)
    def discovery(self):
        return HARNESS.read_discovery(self.path, self.job, self.startup, "a" * 64, self.root)
    def test_private_discovery_binds_actual_owner_and_startup(self):
        self.assertEqual(self.discovery(), self.record)
        for key, bad in (("pid", 43211), ("startup_id", str(uuid.uuid4())), ("protocol", True),
                         ("binary_sha256", "c" * 64), ("cwd", "/different"), ("port", True),
                         ("service_id", "not-a-uuid"), ("token", "not-a-token")):
            with self.subTest(key=key):
                prior = self.record[key]; self.record[key] = bad; self.write_record()
                with self.assertRaises((AssertionError, ValueError)):
                    self.discovery()
                self.record[key] = prior
    def test_exited_leader_is_not_admitted(self):
        with patch.object(self.job.process, "poll", return_value=0), self.assertRaises(AssertionError):
            self.discovery()
    def test_discovery_rejects_nonprivate_or_nonregular_files(self):
        self.path.chmod(0o644)
        with self.assertRaises(AssertionError): self.discovery()
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaises(AssertionError): self.discovery()
        self.path.unlink(); other = self.root / "other"; other.write_text("{}"); self.path.symlink_to(other)
        with self.assertRaises(OSError): self.discovery()
    def test_discovery_rejects_hardlinks_and_oversized_records(self):
        os.link(self.path, self.root / "linked")
        with self.assertRaises(AssertionError): self.discovery()
        (self.root / "linked").unlink(); self.path.write_text(" " * 16385)
        with self.assertRaises(AssertionError): self.discovery()
    def test_public_launcher_must_reuse_exact_owned_service(self):
        launch = {"kind": "dashboard_launch", "service_id": self.record["service_id"],
                  "url": f"http://127.0.0.1:12345/#token={self.record['token']}",
                  "browser_opened": False, "protection_changed": False}
        HARNESS.verify_launch(launch, self.record)
        for key, bad in (("service_id", str(uuid.uuid4())), ("url", "http://other.example/"),
                         ("browser_opened", True), ("protection_changed", True)):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                HARNESS.verify_launch({**launch, key: bad}, self.record)
    def test_launcher_probe_explicitly_forbids_detached_replacement(self):
        launch = {"kind": "dashboard_launch", "service_id": self.record["service_id"],
                  "url": f"http://127.0.0.1:12345/#token={self.record['token']}",
                  "browser_opened": False, "protection_changed": False}
        seen = []
        def cli(*args):
            seen.append(args)
            return launch
        self.assertEqual(HARNESS.reuse_owned_service(cli, self.record), launch)
        self.assertEqual(seen, [("dashboard", "--no-browser", "--json", "--require-service-id", self.record["service_id"])])
        def refused(*args): raise RuntimeError("owned service exited")
        with self.assertRaisesRegex(RuntimeError, "owned service exited"):
            HARNESS.reuse_owned_service(refused, self.record)
    def test_expired_constructor_deadline_is_raised_after_retention_and_cleanup(self):
        def slow_constructor(*args, **kwargs):
            self.assertGreater(HARNESS.signal.getitimer(HARNESS.signal.ITIMER_REAL)[0], 0)
            self.assertNotIn(HARNESS.signal.SIGALRM, HARNESS.signal.pthread_sigmask(HARNESS.signal.SIG_BLOCK, set()))
            time.sleep(0.04)
            return self.job
        native = types.SimpleNamespace(Job=slow_constructor, finish=lambda jobs: [jobs[0].row])
        with self.assertRaisesRegex(TimeoutError, "while retaining"):
            with HARNESS.journey_deadline(0.01):
                HARNESS.owned_cli(native, "inert-constructor", [], self.root, {}, self.report)
        self.assertTrue(self.job.killed)
        self.assertEqual(self.job.failure, "cli-interrupted")
        self.assertEqual(len(self.report["cli_observations"]), 1)
        self.assertEqual(HARNESS.signal.getitimer(HARNESS.signal.ITIMER_REAL), (0.0, 0.0))
        self.assertNotIn(HARNESS.signal.SIGALRM, HARNESS.signal.pthread_sigmask(HARNESS.signal.SIG_BLOCK, set()))
    def test_retained_constructor_keeps_original_timer_running(self):
        with HARNESS.journey_deadline(0.5):
            before = HARNESS.signal.getitimer(HARNESS.signal.ITIMER_REAL)[0]
            with HARNESS.retain_spawn(): time.sleep(0.03)
            after = HARNESS.signal.getitimer(HARNESS.signal.ITIMER_REAL)[0]
            self.assertGreater(after, 0); self.assertLess(after, before - 0.02)
    def test_alarm_exception_is_deferred_until_owner_retained(self):
        retained = False
        with self.assertRaises(TimeoutError):
            with HARNESS.journey_deadline(1):
                with HARNESS.retain_spawn():
                    os.kill(os.getpid(), HARNESS.signal.SIGALRM)
                    retained = True
        self.assertTrue(retained)
    def test_unmanaged_timer_refuses_before_spawning(self):
        with patch.object(HARNESS.signal, "getitimer", return_value=(1.0, 0.0)), self.assertRaises(AssertionError):
            with HARNESS.retain_spawn(): self.fail("must not construct a child")
    def test_nested_acquisition_defers_reentrant_expiry_until_outer_retention(self):
        inner_retained, outer_retained = False, False
        with self.assertRaisesRegex(TimeoutError, "while retaining"):
            with HARNESS.journey_deadline(1):
                with HARNESS.retain_spawn():
                    with HARNESS.retain_spawn():
                        os.kill(os.getpid(), HARNESS.signal.SIGALRM)
                        inner_retained = True
                    os.kill(os.getpid(), HARNESS.signal.SIGALRM)
                    outer_retained = True
        self.assertTrue(inner_retained and outer_retained)
        self.assertIsNone(HARNESS._JOURNEY)
    def test_initially_blocked_alarm_refuses_before_any_journey(self):
        with patch.object(HARNESS.signal, "pthread_sigmask", return_value={HARNESS.signal.SIGALRM}), self.assertRaises(AssertionError):
            with HARNESS.journey_deadline(1): self.fail("must not run journey")
        self.assertIsNone(HARNESS._JOURNEY)
    def test_startup_binding_is_retained_before_discovery_failure(self):
        self.owner.service = None; self.owner.report["binary_sha256"] = "a" * 64
        self.native.Job = lambda *args, **kwargs: self.job
        with patch.object(HARNESS, "await_discovery", side_effect=RuntimeError("discovery refused")), self.assertRaises(RuntimeError):
            self.owner.launch(self.root, {})
        binding = self.report["service_startup"]
        self.assertEqual(binding["owned_pid"], self.job.process.pid)
        self.assertEqual(binding["binary_sha256"], "a" * 64)
        self.assertEqual(binding["cwd"], str(self.root))
        self.assertEqual(str(uuid.UUID(binding["startup_id"])), binding["startup_id"])
    def test_shared_managed_fixture_retains_failure_and_unknown_cleanup(self):
        for status in ({"passed": False}, {"passed": True, "owned_service": {**row(), "cleanup": {"output_eof": False}}}):
            with self.subTest(status=status):
                with HARNESS.retained_fixture_directory(status, "tirith-owner-fixture-control-") as root:
                    (root / "evidence").write_text("retain")
                try:
                    self.assertTrue(status["fixture_retained"]); self.assertTrue(root.is_dir())
                finally:
                    shutil.rmtree(root)  # This predicate fixture starts no child.
    def test_process_metadata_omits_launch_output_and_arguments(self):
        observed = HARNESS.process_observation(row())
        self.assertNotIn("stdout", observed); self.assertNotIn("argv", observed)
        text = HARNESS.safe_diagnostic("bearer-canary csrf-canary " + "x" * 5000, self.owner.authentication)
        self.assertNotIn("canary", text); self.assertEqual(len(text), 4096)
    def test_selector_setup_failure_still_uses_owned_cleanup(self):
        with patch.object(self.native, "finish", side_effect=OSError("selector failed")), self.assertRaises(OSError):
            HARNESS.finish_owned(self.native, self.job)
        self.assertTrue(self.job.killed)
    def test_quiesce_requires_graceful_exit_and_every_cleanup_fact(self):
        response = {"state": "draining", "new_mutations_accepted": False}
        with patch.object(HARNESS, "request", return_value=response):
            self.owner.finish()
        for fact in row()["cleanup"]:
            bad = Job(); bad.row["cleanup"][fact] = False; self.owner.service = bad
            with self.subTest(fact=fact), patch.object(HARNESS, "request", return_value=response), self.assertRaises(AssertionError):
                self.owner.finish()
        for key, value in (("failure", "timeout"), ("exit", -9)):
            bad = Job(); bad.row[key] = value; self.owner.service = bad
            with self.subTest(key=key), patch.object(HARNESS, "request", return_value=response), self.assertRaises(AssertionError):
                self.owner.finish()
    def test_startup_failure_still_finishes_actual_owned_child(self):
        self.owner.authentication = None
        self.job.row.update(exit=-9, failure="service-quiesce")
        with patch.object(HARNESS, "request", side_effect=AssertionError("must not request")) as request, self.assertRaises(AssertionError):
            self.owner.finish()
        request.assert_not_called(); self.assertTrue(self.job.killed)
        self.assertEqual(self.report["owned_service"]["exit"], -9)
    def test_session_failure_retains_cleanup_and_redacts_error(self):
        self.owner.authentication = ("origin", "bearer-canary", None)
        self.job.row.update(exit=-9, failure="service-quiesce")
        with patch.object(HARNESS, "request", side_effect=RuntimeError("bearer-canary refused")), self.assertRaises(AssertionError):
            self.owner.finish()
        self.assertNotIn("bearer-canary", self.report["shutdown_error"])
        self.assertTrue(self.job.killed); self.assertIn("cleanup", self.report["owned_service"])
    def fixture_report(self):
        binary = self.root / "inert-binary"; binary.write_text("never executed")
        report = {"binary_sha256": HARNESS.digest(binary), "harness_sha256": HARNESS.digest(PATH), "checks": []}
        return binary, report
    def test_failed_journey_preserves_private_root_and_report(self):
        binary, report = self.fixture_report(); output = self.root / "failed"
        with patch.object(HARNESS, "native_helper", return_value=self.native), self.assertRaisesRegex(RuntimeError, "failed journey"):
            with HARNESS.browser_fixture(binary, output, report, "fixture-", 10) as owner:
                (owner.root / "failure-canary").write_text("retain")
                raise RuntimeError("failed journey")
        result = json.loads((output / "browser-results.json").read_text())
        self.assertFalse(result["passed"]); self.assertTrue(result["fixture_retained"])
        self.assertTrue((Path(result["fixture_root"]) / "failure-canary").is_file())
    def test_cleanup_failure_preserves_root_even_after_completed_body(self):
        binary, report = self.fixture_report(); output = self.root / "cleanup-failed"
        def failed(owner):
            owner.report["owned_service"] = HARNESS.process_observation(row())
            owner.report["owned_service"]["cleanup"]["group_members_exited"] = False
            raise AssertionError("cleanup incomplete")
        with patch.object(HARNESS, "native_helper", return_value=self.native), patch.object(HARNESS.BrowserOwner, "finish", failed), self.assertRaises(AssertionError):
            with HARNESS.browser_fixture(binary, output, report, "fixture-", 10) as owner:
                owner.service = self.job
        result = json.loads((output / "browser-results.json").read_text())
        self.assertFalse(result["passed"]); self.assertTrue(Path(result["fixture_root"]).is_dir())
    def test_success_requires_owner_and_removes_only_complete_fixture(self):
        binary, report = self.fixture_report(); output = self.root / "success"
        def finished(owner):
            owner.report["owned_service"] = HARNESS.process_observation(row())
        with patch.object(HARNESS, "native_helper", return_value=self.native), patch.object(HARNESS.BrowserOwner, "finish", finished):
            with HARNESS.browser_fixture(binary, output, report, "fixture-", 10) as owner:
                owner.service = self.job
        self.assertTrue(report["passed"]); self.assertFalse(report["fixture_retained"])
        self.assertFalse(Path(report["fixture_root"]).exists())
        with self.assertRaises(FileExistsError):
            with HARNESS.browser_fixture(binary, output, {}, "fixture-", 10): pass
    def test_input_change_refuses_success_and_retains_root(self):
        binary, report = self.fixture_report(); output = self.root / "changed"
        def finished(owner): owner.report["owned_service"] = HARNESS.process_observation(row())
        with patch.object(HARNESS, "native_helper", return_value=self.native), patch.object(HARNESS.BrowserOwner, "finish", finished), self.assertRaises(AssertionError):
            with HARNESS.browser_fixture(binary, output, report, "fixture-", 10) as owner:
                owner.service = self.job; binary.write_text("changed")
        self.assertFalse(report["passed"]); self.assertTrue(Path(report["fixture_root"]).exists())
    def test_optimized_python_refuses_before_imports_or_processes(self):
        with self.assertRaisesRegex(RuntimeError, "without -O"):
            exec(compile(PATH.read_text(), str(PATH), "exec", optimize=1), {})
    def test_alarm_restores_previous_handler_and_existing_alarm_refuses(self):
        original = HARNESS.signal.getsignal(HARNESS.signal.SIGALRM)
        with self.assertRaises(TimeoutError):
            with HARNESS.journey_deadline(0.01): time.sleep(0.1)
        self.assertEqual(HARNESS.signal.getitimer(HARNESS.signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(HARNESS.signal.getsignal(HARNESS.signal.SIGALRM), original)
        with patch.object(HARNESS.signal, "getitimer", return_value=(1.0, 0.0)), self.assertRaises(AssertionError):
            with HARNESS.journey_deadline(1): pass


class NativeSubstrate(unittest.TestCase):
    """Finite inert Python children; these results are not Tirith qualification."""
    def test_graceful_finite_child_observes_all_four_cleanup_facts(self):
        native = HARNESS.native_helper()
        root = Path(tempfile.mkdtemp(prefix="tirith-browser-owner-substrate-"))
        passed, owner = False, None
        try:
            report = {"checks": []}
            owner = HARNESS.BrowserOwner(native, Path(sys.executable), root, report, 5)
            with HARNESS.journey_deadline(5):
                with HARNESS.retain_spawn():
                    owner.service = native.Job("harmless-browser-owner", [sys.executable, "-c",
                        "import json,os,signal,time; time.sleep(0.2); print(json.dumps({'pid':os.getpid(),'blocked':signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK,set())}))"],
                        root, {"PATH": "/usr/bin:/bin"}, timeout=5)
            owner.authentication = ("fixture-origin", "fixture-token", "fixture-csrf")
            try:
                with patch.object(HARNESS, "request", return_value={"state": "draining", "new_mutations_accepted": False}):
                    owner.finish()
                self.assertEqual(report["owned_service"]["exit"], 0)
                actual = json.loads(bytes(owner.service.output["stdout"]))
                self.assertEqual(actual, {"pid": owner.service.process.pid, "blocked": False})
                self.assertTrue(all(report["owned_service"]["cleanup"].values()))
                passed = True
            finally:
                owner.service.kill()
                for stream in (owner.service.process.stdout, owner.service.process.stderr): stream.close()
        finally:
            if owner is not None and owner.service is not None:
                owner.service.kill()
                for stream in (owner.service.process.stdout, owner.service.process.stderr): stream.close()
            if passed:
                shutil.rmtree(root)
            else:
                print(f"retained harmless fixture: {root}", file=sys.stderr)
    def test_startup_refusal_cleans_retained_finite_child(self):
        native = HARNESS.native_helper()
        root = Path(tempfile.mkdtemp(prefix="tirith-browser-owner-substrate-"))
        passed, owner = False, None
        try:
            report = {"checks": []}
            owner = HARNESS.BrowserOwner(native, Path(sys.executable), root, report, 5)
            owner.service = native.Job("harmless-browser-startup-refusal", [sys.executable, "-c", "import time; time.sleep(2)"], root, {"PATH": "/usr/bin:/bin"}, timeout=5)
            try:
                with self.assertRaisesRegex(AssertionError, "did not exit gracefully"):
                    owner.finish()
                self.assertTrue(all(report["owned_service"]["cleanup"].values()))
                self.assertEqual(report["owned_service"]["failure"], "service-quiesce")
                passed = True
            finally:
                owner.service.kill()
                for stream in (owner.service.process.stdout, owner.service.process.stderr): stream.close()
        finally:
            if owner is not None and owner.service is not None:
                owner.service.kill()
                for stream in (owner.service.process.stdout, owner.service.process.stderr): stream.close()
            if passed:
                shutil.rmtree(root)
            else:
                print(f"retained harmless fixture: {root}", file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
