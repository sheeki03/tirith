#!/usr/bin/env python3
"""Pure ownership/refusal fixtures; --native adds owned inert-child cleanup tests.

Synthetic discovery/HTTP values test producer predicates, not Tirith activation.
Native cases signal only direct Job-owned fixture groups and are never release
or resource-distribution evidence.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import contextmanager

spec = importlib.util.spec_from_file_location("measure_local_control", Path(__file__).with_name("measure-local-control.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NATIVE_REQUESTED = "--native" in sys.argv
if NATIVE_REQUESTED:
    sys.argv.remove("--native")


def native_row():
    return {"name": "SYNTHETIC owned child", "pid": 42, "exit": 0, "failure": None,
            "cleanup": dict.fromkeys(module.CLEANUP_FIELDS, True),
            "group_observation": {"method": "procfs", "leader_retained_waitable": True,
                                  "members": [{"pid": 42, "state": "exited"}]},
            "elapsed_seconds": .1, "stdout": "private-output", "stderr": "private-error"}


class FakeJob:
    def __init__(self, row=None):
        self.row = copy.deepcopy(row or native_row())
        self.process = SimpleNamespace(pid=42, poll=lambda: None)
        self.failure, self.timeout, self.started = None, 1200, time.monotonic()
        self.killed = self.finished = False
    def kill(self):
        self.killed = True
    def result(self):
        result = copy.deepcopy(self.row)
        result["failure"] = self.failure or result["failure"]
        return result


def fake_finish(jobs):
    for job in jobs:
        job.finished = True
    return [job.result() for job in jobs]


class ProcessAccounting(unittest.TestCase):
    def test_native_cpu_formats_and_rss_units(self):
        for clock, expected in [("0:00.02", 20), ("01:02:03", 3723000), ("2-01:02:03", 176523000)]:
            with self.subTest(clock=clock):
                value = module.parse_process_sample(f"42 Sat Sep 12 17:36:09 2026 1234 {clock}", 42)
                self.assertEqual(value["cpu_ms"], expected)
                self.assertEqual(value["rss_bytes"], 1234 * 1024)

    def test_invalid_pid_accounting_and_nonfinite_cpu_are_refused(self):
        for pid, rss, clock in [(41, 1234, "0:00.02"), (42, -1, "0:00.02"), (42, 1234, "0:nan"),
                                (42, 1234, "0:inf"), (42, 1234, "0:60"), (42, 1234, "-1:00")]:
            with self.subTest(pid=pid, rss=rss, clock=clock), self.assertRaises(ValueError):
                module.parse_process_sample(f"{pid} Sat Sep 12 17:36:09 2026 {rss} {clock}", 42)


class OwnedDiscovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "service.json"
        self.job = FakeJob()
        self.record = {"protocol": 1, "pid": 42, "startup_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                       "service_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "binary_sha256": "c" * 64,
                       "cwd": str(self.root), "port": 32123, "token": "d" * 64}
        self.write()
    def write(self):
        self.path.write_text(json.dumps(self.record))
        self.path.chmod(0o600)
    def read(self):
        return module.read_discovery(self.path, self.job, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "c" * 64, self.root)
    def test_valid_owned_identity(self):
        self.assertEqual(self.read(), self.record)
    def test_wrong_owner_context_and_noncanonical_identity(self):
        for field, value in [("pid", 43), ("pid", True), ("startup_id", "other"), ("binary_sha256", "other"),
                             ("cwd", "elsewhere"), ("protocol", True), ("port", True), ("port", 65536),
                             ("service_id", "B" * 32), ("service_id", "00000000-0000-0000-0000-000000000000"),
                             ("token", "secret")]:
            previous = self.record[field]
            with self.subTest(field=field, value=value):
                self.record[field] = value
                self.write()
                with self.assertRaises(ValueError): self.read()
            self.record[field] = previous
        self.write()
    def test_exited_child_refused(self):
        self.job.process.poll = lambda: 0
        with self.assertRaisesRegex(ValueError, "exited"): self.read()
    def test_duplicate_oversized_mode_and_nonregular_refuse(self):
        for body in [b'{"pid":42,"pid":42}', b"x" * 16385]:
            self.path.write_bytes(body)
            with self.assertRaises(ValueError): self.read()
        self.write(); self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "unsafe"): self.read()
        self.path.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaisesRegex(ValueError, "unsafe"): self.read()
    def test_symlink_and_hardlink_refuse(self):
        target = self.root / "target.json"
        self.path.rename(target); self.path.symlink_to(target)
        with self.assertRaises(OSError): self.read()
        self.path.unlink(); os.link(target, self.path)
        with self.assertRaisesRegex(ValueError, "unsafe"): self.read()
    def test_launcher_requires_exact_owned_reuse_without_side_effects(self):
        launch = {"kind": "dashboard_launch", "service_id": self.record["service_id"],
                  "url": f"http://127.0.0.1:32123/#token={'d' * 64}",
                  "browser_opened": False, "protection_changed": False}
        module.verify_launch(launch, self.record)
        for field, value in [("service_id", "other"), ("url", "http://127.0.0.1:9/#token=secret"),
                             ("browser_opened", True), ("protection_changed", True)]:
            bad = {**launch, field: value}
            with self.assertRaises(ValueError): module.verify_launch(bad, self.record)


class OwnedCleanup(unittest.TestCase):
    def owner(self, row=None):
        owner = module.OwnedService(SimpleNamespace(finish=fake_finish), Path("/candidate"), "c" * 64,
                                    Path("/fixture"), Path("/fixture/project"), {})
        owner.job = FakeJob(row)
        owner.authentication = ("http://127.0.0.1:123", "private-token", "private-csrf")
        owner.identity_validated = owner.launcher_reused = True
        return owner
    def ack(self, *args, **kwargs):
        return {"state": "draining", "new_mutations_accepted": False}, 1, 20
    def test_ack_and_actual_exit_with_all_cleanup_facts(self):
        owner, report = self.owner(), {}
        with patch.object(module, "http", side_effect=self.ack): owner.finish(report)
        self.assertTrue(owner.job.finished)
        self.assertFalse(owner.job.killed)
        self.assertTrue(report["owned_service"]["quiesce_acknowledged"])
        text = json.dumps(report)
        for private in ("private-token", "private-csrf", "private-output", "private-error"):
            self.assertNotIn(private, text)
    def test_ack_without_each_cleanup_fact_is_failure(self):
        for fact in module.CLEANUP_FIELDS:
            row = native_row(); row["cleanup"][fact] = False
            owner, report = self.owner(row), {}
            with patch.object(module, "http", side_effect=self.ack), self.assertRaises(RuntimeError):
                owner.finish(report)
            self.assertFalse(report["owned_service"]["cleanup"][fact])
    def test_nonzero_exit_and_helper_failure_are_not_success(self):
        for field, value in (("exit", -9), ("failure", "timeout")):
            row = native_row(); row[field] = value
            owner, report = self.owner(row), {}
            with patch.object(module, "http", side_effect=self.ack), self.assertRaises(RuntimeError): owner.finish(report)
    def test_pre_session_failure_still_cleans_owned_child(self):
        owner, report = self.owner(), {}
        owner.authentication = None
        with patch.object(module, "http") as request, self.assertRaises(RuntimeError): owner.finish(report)
        request.assert_not_called()
        self.assertTrue(owner.job.killed and owner.job.finished)
        self.assertEqual(report["owned_service"]["failure"], "service-quiesce")
    def test_session_failure_quiesce_failure_and_early_exit_retain_refusal(self):
        for stage in ("session", "quiesce", "early_exit"):
            owner, report = self.owner(), {}
            if stage == "session": owner.authentication = (*owner.authentication[:2], None)
            if stage == "early_exit": owner.job.process.poll = lambda: 0
            with patch.object(module, "http", side_effect=ValueError("private-token private-csrf")), self.assertRaises(RuntimeError):
                owner.finish(report)
            self.assertTrue(owner.job.killed and owner.job.finished)
            self.assertNotIn("private-token", json.dumps(report))
    def test_interrupted_shutdown_still_finishes_owned_group(self):
        owner, report = self.owner(), {}
        with patch.object(module, "http", side_effect=KeyboardInterrupt()), self.assertRaises(RuntimeError): owner.finish(report)
        self.assertTrue(owner.job.killed and owner.job.finished)
    def test_finish_exception_still_records_bounded_cleanup(self):
        owner, report = self.owner(), {}
        owner.native.finish = lambda jobs: (_ for _ in ()).throw(RuntimeError("fixture finish error"))
        with patch.object(module, "http", side_effect=self.ack), self.assertRaises(RuntimeError): owner.finish(report)
        self.assertIn("owned_service", report)
    def test_report_failure_suppresses_original_secret_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "candidate"; binary.write_bytes(b"fixture")
            report = {"schema_version": 2, "status": "failed", "binary_sha256": module.hashlib.sha256(binary.read_bytes()).hexdigest()}
            with patch("builtins.print"), self.assertRaises(RuntimeError) as caught:
                try: raise ValueError("private-token")
                except ValueError:
                    module.write_report(report, root / "report.json", binary, None,
                                        module.hashlib.sha256(module.NATIVE_PATH.read_bytes()).hexdigest(),
                                        module.hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertEqual(json.loads((root / "report.json").read_text())["status"], "failed")


class ProducerSourceBinding(unittest.TestCase):
    def test_edited_producer_refuses_without_relabeling_loaded_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary, output = root / "producer.py", root / "candidate", root / "report.json"
            source.write_bytes(b"SYNTHETIC first producer")
            binary.write_bytes(b"SYNTHETIC binary")
            initial = module.hashlib.sha256(source.read_bytes()).hexdigest()
            source.write_bytes(b"SYNTHETIC changed producer")
            report = {"status": "completed", "binary_sha256": module.hashlib.sha256(binary.read_bytes()).hexdigest()}
            helper_hash = module.hashlib.sha256(module.NATIVE_PATH.read_bytes()).hexdigest()
            with patch.object(module, "__file__", str(source)), patch("builtins.print"), self.assertRaises(RuntimeError):
                module.write_report(report, output, binary, None, helper_hash, initial)
            retained = json.loads(output.read_text())
            self.assertEqual(retained["harness_sha256"], initial)
            self.assertIs(retained["harness_unchanged_during_run"], False)
            self.assertEqual(retained["status"], "failed")
            self.assertEqual(retained["failure"], "measurement_input_changed")


class SamplerShutdown(unittest.TestCase):
    def sampler(self):
        sampler = module.ServiceSampler.__new__(module.ServiceSampler)
        sampler.stop = module.threading.Event()
        sampler.thread = Mock()
        sampler.owner = SimpleNamespace(verify=Mock(side_effect=AssertionError("must not touch Job during observation")))
        sampler.samples, sampler.errors = [], []
        sampler.pid, sampler.identity = 42, None
        sampler.started, sampler.availability = time.monotonic(), "available"
        return sampler

    def test_unjoined_sampler_is_explicitly_incomplete_and_never_touches_job(self):
        sampler = self.sampler()
        sampler.thread.is_alive.return_value = True
        row = sampler.finish()
        self.assertIs(row["sampler_joined"], False)
        self.assertIn("sampler_stop_timeout", row["errors"])
        sampler.thread.join.assert_called_once_with(timeout=3)
        sampler.owner.verify.assert_not_called()

    def test_observer_sample_has_no_mutable_job_or_pipe_access(self):
        sampler = self.sampler()
        result = SimpleNamespace(returncode=0, stdout="42 Sat Sep 12 17:36:09 2026 1234 0:00.02")
        with patch.object(module.subprocess, "run", return_value=result): sampler.sample()
        sampler.owner.verify.assert_not_called()
        self.assertEqual(len(sampler.samples), 1)


class CompleteProducerFailurePaths(unittest.TestCase):
    def run_fixture(self, stage):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "candidate"; binary.write_bytes(b"SYNTHETIC candidate")
            output = root / "report.json"
            jobs = []
            def spawn(owner):
                self.assertEqual(module.signal.getitimer(module.signal.ITIMER_REAL), (0.0, 0.0))
                owner.job = FakeJob(); jobs.append(owner.job)
                if stage == "post_spawn": raise ValueError("private-token")
            @contextmanager
            def deadline():
                self.assertEqual(len(jobs), 1, "alarm must begin only after retained Job assignment")
                yield
            def start(owner):
                if stage == "startup": raise ValueError("private-token")
                owner.identity_validated = True
                owner.record = {"service_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "port": 32123, "token": "d" * 64}
                owner.authentication = ("http://127.0.0.1:32123", "d" * 64, None)
                if stage == "session": raise ValueError("private-token")
                owner.authentication = (*owner.authentication[:2], "private-csrf")
                return 5.0
            def command(argv, **kwargs):
                # All subprocess calls are replaced. This test never launches
                # a candidate, a native Job, ps, or the resource wrapper.
                resource_path = Path(argv[3])
                resource_path.write_text(json.dumps({"elapsed_ms": 1.0, "availability": "available",
                    "cpu_user_ms": 1, "cpu_system_ms": 1, "peak_rss_bytes": 4096}))
                launch = "dashboard" in argv
                if launch:
                    self.assertEqual(argv[-5:], ["dashboard", "--no-browser", "--json", "--require-service-id",
                                                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"])
                    if stage == "launcher_refused":
                        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"private-token")
                    if stage == "launcher_exit_race":
                        jobs[0].process.poll = lambda: 0
                value = {"kind": "dashboard_launch", "service_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                         "url": f"http://127.0.0.1:32123/#token={'d' * 64}", "browser_opened": False, "protection_changed": False}
                if launch and stage == "launch": value["url"] = "private-token"
                return SimpleNamespace(returncode=0, stdout=json.dumps(value if launch else {}).encode(), stderr=b"")
            def request(origin, token, csrf, route, body=None, timeout=40):
                if route == "/api/quiesce":
                    if stage == "quiesce": raise ValueError("private-token")
                    return {"state": "draining", "new_mutations_accepted": False}, 1, 20
                if route == "/api/session": return {"csrf": "private-csrf"}, 1, 20
                if stage == "response": raise ValueError("private-token")
                if stage == "interrupt": raise KeyboardInterrupt("private-token")
                if route == "/api/history": return {"events": [], "inspected_bytes": 100, "next_cursor": None}, 1, 20
                return {"inspected_bytes_this_refresh": 100, "earlier_history_uninspected": False}, 1, 20
            class Sampler:
                def __init__(self, owner):
                    if stage == "sampler_start": raise ValueError("private-token")
                def finish(self):
                    if stage == "sampler_finish": raise ValueError("private-token")
                    return {"errors": ["sampler_stop_timeout"] if stage == "sampler_unjoined" else [],
                            "sampler_joined": stage != "sampler_unjoined"}
            def verify(owner):
                # The real discovery reader's retained-child poll predicate is
                # covered separately; this exercises its failure at the exact
                # producer post-reuse boundary without launching a subprocess.
                if owner.job.process.poll() is not None:
                    raise RuntimeError("owned child exited during launcher reuse")
            helper_hash = module.hashlib.sha256(module.NATIVE_PATH.read_bytes()).hexdigest()
            with patch.object(module, "load_native", return_value=(SimpleNamespace(finish=fake_finish), helper_hash)), \
                 patch.object(module.OwnedService, "spawn", spawn), patch.object(module, "service_deadline", deadline),                  patch.object(module.OwnedService, "start", start), patch.object(module.OwnedService, "verify", verify), \
                 patch.object(module.subprocess, "run", side_effect=command), patch.object(module, "http", side_effect=request), \
                 patch.object(module, "ServiceSampler", Sampler), patch("builtins.print"):
                if stage == "success":
                    module.run(binary, output, 3, 1000, resources=True)
                else:
                    with self.assertRaises(RuntimeError): module.run(binary, output, 3, 1000, resources=True)
            report = json.loads(output.read_text())
            self.assertEqual(len(jobs), 1)
            self.assertTrue(jobs[0].finished)
            self.assertEqual(report["status"], "completed" if stage == "success" else "failed")
            self.assertIn("owned_service", report)
            for secret in ("private-token", "private-csrf", "d" * 64, "private-output", "private-error"):
                self.assertNotIn(secret, output.read_text())
            return report
    def test_unsupported_runtime_refuses_before_any_workload(self):
        with patch.object(module, "load_native", side_effect=RuntimeError("unsupported runtime")), \
             patch.object(module.subprocess, "run") as command, self.assertRaisesRegex(RuntimeError, "unsupported"):
            module.run(Path("/unused"), Path("/unused-report"), 3, 1000, resources=True)
        command.assert_not_called()

    def test_success_separates_direct_start_from_launcher_reuse(self):
        report = self.run_fixture("success")
        self.assertEqual(report["schema_version"], 2)
        self.assertIs(report["harness_unchanged_during_run"], True)
        self.assertEqual(report["harness_sha256"], module.hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
        self.assertNotIn("service_launch", report["measurements"])
        self.assertIn("service_direct_start", report["measurements"])
        self.assertIn("service_launcher_reuse", report["measurements"])
    def test_all_after_spawn_failures_retain_cleanup_and_refuse(self):
        for stage in ("post_spawn", "startup", "session", "launch", "launcher_refused", "launcher_exit_race", "response", "interrupt", "quiesce", "sampler_start", "sampler_finish", "sampler_unjoined"):
            with self.subTest(stage=stage): self.run_fixture(stage)



@unittest.skipUnless(NATIVE_REQUESTED, "explicit --native required; no native fixture runs by default")
class NativeOwnedCleanup(unittest.TestCase):
    def test_timeout_refuses_and_observes_owned_fixture_group_cleanup(self):
        native, _ = module.load_native()
        with tempfile.TemporaryDirectory() as directory:
            job = native.Job("inert-resource-timeout-fixture", [sys.executable, "-c", "import time; time.sleep(10)"],
                             Path(directory), dict(os.environ), timeout=.2)
            row = native.finish([job])[0]
            self.assertEqual(row["failure"], "timeout")
            self.assertIsNotNone(row["exit"])
            self.assertTrue(all(row["cleanup"].get(fact) is True for fact in module.CLEANUP_FIELDS))
    def test_clean_owned_fixture_exit_is_observed_before_reap(self):
        native, _ = module.load_native()
        with tempfile.TemporaryDirectory() as directory:
            job = native.Job("inert-resource-clean-fixture", [sys.executable, "-c", "pass"],
                             Path(directory), dict(os.environ), timeout=3)
            row = native.finish([job])[0]
            native.success(row)
            self.assertTrue(row["group_observation"]["leader_retained_waitable"])


if __name__ == "__main__":
    unittest.main()
