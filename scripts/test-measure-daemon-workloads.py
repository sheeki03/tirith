#!/usr/bin/env python3
"""Pure admission/file/protocol controls. No product or child execution."""
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import tempfile
import time
import types
import unittest

spec = importlib.util.spec_from_file_location("daemon_measure", Path(__file__).with_name("measure-daemon-workloads.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Controls(unittest.TestCase):
    def test_distribution_preserves_order_and_even_median_nearest_rank(self):
        raw = list(range(100, 0, -1))
        d = m.distribution(raw)
        self.assertEqual((d["p50_ms"], d["p95_ms"], d["n"]), (50.5, 95, 100))
        self.assertEqual(d["raw_ms"], raw)
        for bad in ([], [math.nan], [-1], [True], [math.inf]):
            with self.assertRaises(RuntimeError):m.distribution(bad)

    def test_duplicate_response_identity_is_refused(self):
        with self.assertRaises(RuntimeError):m.decode('{"action":"block","action":"allow"}')

    def test_binding_requires_exact_schema_and_matching_bytes(self):
        value = {"binary_sha256": "a" * 64, "product_commit": "b" * 40, "product_tree": "c" * 40}
        m.admit_binding(value, "a" * 64)
        for bad in ({**value, "extra": True}, {**value, "product_tree": "bad"},
                    {**value, "binary_sha256": "d" * 64}):
            with self.assertRaises(RuntimeError):m.admit_binding(bad, "a" * 64)

    def test_final_cleanup_continues_after_interrupt_without_resetting_attempt(self):
        calls = []
        def job(name, attempted):
            value = types.SimpleNamespace(name=name, cleanup_attempted=attempted,
                process=types.SimpleNamespace(reaped=False), cleanup={k:False for k in m.CLEANUP_KEYS},
                timeout=900, pipe_deadline=None)
            def kill():
                calls.append((name, "kill"));value.cleanup_attempted = True
            value.kill = kill
            return value
        first, second = job("prior-interrupt", True), job("still-owned", False)
        def finish(jobs):
            value = jobs[0];calls.append((value.name, "finish"))
            self.assertEqual(value.timeout, 0)
            self.assertLessEqual(value.pipe_deadline, time.monotonic() + 2)
            if value is first:raise KeyboardInterrupt()
            value.process.reaped = True;value.cleanup = {k:True for k in m.CLEANUP_KEYS}
        runner = types.SimpleNamespace(jobs=[first,second], native=types.SimpleNamespace(finish=finish))
        errors = m.cleanup_registered(runner)
        self.assertEqual(calls, [("prior-interrupt","finish"),("still-owned","kill"),("still-owned","finish")])
        self.assertEqual(errors, [{"name":"prior-interrupt","stage":"drain","error":"KeyboardInterrupt"}])
        self.assertFalse(first.process.reaped)
        self.assertTrue(second.process.reaped)

    def test_signed_database_admission_never_rewrites_original_age(self):
        p = Path("/fixture/db.dat")
        value = {"installed": True, "signature_valid": True, "error": None, "path": str(p),
                 "build_sequence": 42, "build_timestamp": 12345, "total_entries": 2,
                 "age_hours": 900.25, "stale": False}
        before = json.dumps(value, sort_keys=True)
        self.assertEqual(m.admitted_database(value, p)["build_timestamp"], 12345)
        self.assertEqual(json.dumps(value, sort_keys=True), before)
        for key, bad in (("signature_valid", False), ("installed", False), ("error", "signature"),
                         ("path", "/different"), ("build_sequence", True), ("total_entries", 0)):
            with self.assertRaises(RuntimeError):m.admitted_database({**value, key: bad}, p)

    def test_semantics_refuse_weaker_result_or_policy_error(self):
        p = Path("/fixture/policy.yaml")
        base = {"action": "block", "findings": [{"rule_id": "custom_rule", "severity": "HIGH", "custom_rule_id": "wp17-000"}],
                "tier_reached": 3, "bypass_honored": False, "policy_path_used": str(p)}
        expected = m.same_result(None, base, 1, p, m.COMMANDS[1])
        self.assertEqual(expected, m.same_result(expected, dict(base), 1, p, m.COMMANDS[1]))
        for change in ({"action": "allow"}, {"findings": []}, {"error": "internal error"},
                       {"policy_path_used": "/wrong"}, {"bypass_honored": True}, {"policy_diagnostics": ["refused"]}):
            with self.assertRaises(RuntimeError):m.same_result(expected, {**base, **change}, 1, p, m.COMMANDS[1])

    def test_custom_policy_and_nested_fixture_are_finite(self):
        raw = m.policy_bytes(256)
        self.assertEqual(raw.count(b"  - id:"), 256)
        self.assertEqual(raw.count(b"pattern: 'WP17_BLOCK'"), 1)
        self.assertIn(b"auto_update_hours: 0", raw)
        self.assertLess(len(raw), 64 * 1024)
        with self.assertRaises(RuntimeError):m.policy_bytes(257)
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="w17test-") as tmp:
            f = m.Fixture(Path(tmp).resolve(), 256, b"opaque-test-bytes-never-executed")
            f.verify()
            self.assertEqual(f.description["nested_depth"], 8)
            self.assertEqual(len(list(f.project.glob("fixture-*.txt"))), 128)
            f.policy.write_bytes(b"replacement")
            with self.assertRaises(RuntimeError):f.verify()

    def test_held_input_refuses_symlink_oversize_and_preserves_empty_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "file"
            p.write_bytes(b"abcdef")
            self.assertEqual(m.held_bytes(p, 6), b"abcdef")
            with self.assertRaises(RuntimeError):m.held_bytes(p, 5)
            link = p.with_name("link");link.symlink_to(p)
            with self.assertRaises(OSError):m.held_bytes(link, 6)
            p.write_bytes(b"")
            with self.assertRaises(RuntimeError):m.held_bytes(p, 6)
            self.assertEqual(m.held_bytes(p, 6, allow_empty=True), b"")

    def test_storage_refuses_dangling_alias_and_fifo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").write_bytes(b"abc")
            self.assertEqual(m.storage(root)["regular_logical_bytes"], 3)
            link = root / "link";link.symlink_to(root / "absent")
            with self.assertRaises(RuntimeError):m.storage(root)
            link.unlink();os.mkfifo(link)
            with self.assertRaises(RuntimeError):m.storage(root)

    def test_deadline_clamps_and_never_admits_expired_work(self):
        with self.assertRaises(RuntimeError):m.remaining(time.monotonic() - 1, 15)
        self.assertEqual(m.remaining(time.monotonic() + 30, 2), 2)
        self.assertLessEqual(m.remaining(time.monotonic() + .1, 2), .1)

    def test_socket_generation_replacement_with_same_pid_is_refused(self):
        # No server/child is run. Real private Unix socket filesystem identities
        # test the admission boundary against a replaced same-path endpoint.
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="w17sock-") as tmp:
            root = Path(tmp);root.chmod(0o700)
            endpoint = root / "daemon.sock";pidfile = root / "daemon.pid"
            pidfile.write_text(str(os.getpid()));pidfile.chmod(0o600)
            fixture = types.SimpleNamespace(socket=endpoint, pidfile=pidfile)
            process = types.SimpleNamespace(pid=os.getpid(), poll=lambda:None)
            runner = types.SimpleNamespace(deadline=time.monotonic() + 10)
            owner = m.Daemon(runner, fixture);owner.job = types.SimpleNamespace(process=process)
            owner.drain = lambda:None
            with socket.socket(socket.AF_UNIX) as first, socket.socket(socket.AF_UNIX) as second:
                first.bind(str(endpoint));endpoint.chmod(0o600)
                owner.record = m.socket_record(fixture, owner.job)
                owner.verify()
                endpoint.rename(root / "retained-first.sock")
                second.bind(str(endpoint));endpoint.chmod(0o600)
                with self.assertRaises(RuntimeError):owner.verify()

    def test_journal_refuses_replaced_path_and_holds_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "observations.jsonl"
            j = m.Journal(path);j.add({"event": "retained"})
            path.rename(path.with_suffix(".held"));path.write_text("different")
            with self.assertRaises(RuntimeError):j.close()
            self.assertEqual(json.loads(path.with_suffix(".held").read_text()), {"event": "retained"})


if __name__ == "__main__":
    unittest.main()
