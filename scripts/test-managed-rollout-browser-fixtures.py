#!/usr/bin/env python3
"""Pure harness predicate fixtures; no candidate, browser or native group launch."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import uuid
import yaml

PATH = Path(__file__).with_name("test-managed-rollout-browser.py")
spec = importlib.util.spec_from_file_location("managed_browser", PATH)
HARNESS = importlib.util.module_from_spec(spec)
# Parsing/predicate fixtures do not need an installed Chromium or Playwright.
with patch.dict("sys.modules", {"playwright": types.ModuleType("playwright"),
        "playwright.sync_api": types.SimpleNamespace(sync_playwright=None)}):
    spec.loader.exec_module(HARNESS)


class Process:
    pid = 43210
    def poll(self):
        return None


class Job:
    def __init__(self):
        self.process = Process()
        self.started = time.monotonic()
        self.timeout = 330
        self.failure = None
        self.killed = False
    def kill(self):
        self.killed = True
    def result(self):
        return row()


def row():
    return {"name": "owned-service-fixture", "exit": 0, "failure": None,
            "cleanup": dict.fromkeys(("leader_reaped", "group_signaled_or_absent",
                                      "group_members_exited", "output_eof"), True)}


class Predicates(unittest.TestCase):
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
        self.document = {"organization_note": "preserve-managed-browser-fixture",
                         **copy.deepcopy(HARNESS.BALANCED), "protection_profile": copy.deepcopy(HARNESS.SELECTION)}
        self.effective = {"scope": "org", "source_path": str(self.path),
                          "policy": copy.deepcopy(HARNESS.BALANCED),
                          "resolution": {"effective_profile": copy.deepcopy(HARNESS.SELECTION)}}
    def write_record(self):
        self.path.write_text(json.dumps(self.record))
        self.path.chmod(0o600)
    def discovery(self):
        return HARNESS.read_discovery(self.path, self.job, self.startup, "a" * 64, self.root)
    def test_owned_identity_accepts_exact_private_record(self):
        self.assertEqual(self.discovery(), self.record)
    def test_discovery_rejects_other_process_startup_binary_and_cwd(self):
        for key, bad in (("pid", 43211), ("startup_id", str(uuid.uuid4())),
                         ("binary_sha256", "c" * 64), ("cwd", "/different")):
            with self.subTest(key=key):
                prior = self.record[key]
                self.record[key] = bad
                self.write_record()
                with self.assertRaises(AssertionError):
                    self.discovery()
                self.record[key] = prior
    def test_discovery_rejects_exited_owned_leader(self):
        with patch.object(self.job.process, "poll", return_value=0):
            with self.assertRaises(AssertionError):
                self.discovery()
    def test_discovery_rejects_public_permissions(self):
        self.path.chmod(0o644)
        with self.assertRaises(AssertionError):
            self.discovery()
    def test_discovery_rejects_symlink(self):
        other = self.root / "other"
        self.path.rename(other)
        self.path.symlink_to(other)
        with self.assertRaises(OSError):
            self.discovery()
    def test_discovery_rejects_oversized_record(self):
        self.path.write_text(" " * 16385)
        with self.assertRaises(AssertionError):
            self.discovery()
    def test_discovery_refuses_fifo_without_waiting_for_a_writer(self):
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(AssertionError):
            self.discovery()
    def test_error_projection_withholds_authentication_and_bounds_output(self):
        authentication = ("http://127.0.0.1:12345", "bearer-canary", "csrf-canary")
        text = HARNESS.safe_diagnostic("navigation #token=bearer-canary header csrf-canary", authentication)
        self.assertNotIn("bearer-canary", text)
        self.assertNotIn("csrf-canary", text)
        self.assertEqual(text.count("[withheld]"), 2)
        self.assertEqual(len(HARNESS.safe_diagnostic("x" * 5000, None)), 4096)
    def test_launcher_must_reuse_service_and_exact_local_url(self):
        launch = {"kind": "dashboard_launch", "service_id": self.record["service_id"],
                  "url": f"http://127.0.0.1:12345/#token={self.record['token']}",
                  "browser_opened": False, "protection_changed": False}
        HARNESS.verify_launch(launch, self.record)
        for key, bad in (("service_id", str(uuid.uuid4())), ("url", "http://other.example/")):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                HARNESS.verify_launch({**launch, key: bad}, self.record)
    def test_balanced_requires_materialized_document_and_effective_fields(self):
        HARNESS.verify_balanced(yaml.safe_dump(self.document), self.effective, self.path)
        for key in HARNESS.BALANCED:
            broken = copy.deepcopy(self.document)
            del broken[key]
            with self.subTest(missing=key), self.assertRaises(AssertionError):
                HARNESS.verify_balanced(yaml.safe_dump(broken), self.effective, self.path)
            broken_effective = copy.deepcopy(self.effective)
            broken_effective["policy"][key] = None
            with self.subTest(effective=key), self.assertRaises(AssertionError):
                HARNESS.verify_balanced(yaml.safe_dump(self.document), broken_effective, self.path)
    def test_balanced_rejects_other_scope_or_marker_only(self):
        for bad in ({**self.effective, "scope": "user"},
                    {**self.effective, "source_path": "/other"}):
            with self.assertRaises(AssertionError):
                HARNESS.verify_balanced(yaml.safe_dump(self.document), bad, self.path)
        marker_only = {"organization_note": "preserve-managed-browser-fixture",
                       "protection_profile": HARNESS.SELECTION}
        with self.assertRaises(AssertionError):
            HARNESS.verify_balanced(yaml.safe_dump(marker_only), self.effective, self.path)
    def test_restore_rejects_every_residual_field_and_empty_map(self):
        HARNESS.verify_restore(HARNESS.ORIGINAL)
        for suffix in ("fail_mode: open\n", "severity_overrides: {}\n", "allow_bypass_env: true\n",
                       "protection_profile: null\n", "other_note: remaining\n"):
            with self.subTest(suffix=suffix), self.assertRaises(AssertionError):
                HARNESS.verify_restore(HARNESS.ORIGINAL + suffix)
    def test_graceful_exit_and_four_facts_required(self):
        response = {"state": "draining", "new_mutations_accepted": False}
        with patch.object(HARNESS.SHARED, "request", return_value=response), \
             patch.object(HARNESS.NATIVE, "finish", return_value=[row()]):
            report = {}
            HARNESS.finish_service(self.job, ("origin", "token", "csrf"), report)
            self.assertFalse(self.job.killed)
            self.assertEqual(report["owned_service"]["exit"], 0)
        for fact in row()["cleanup"]:
            bad = row(); bad["cleanup"][fact] = False
            with self.subTest(fact=fact), patch.object(HARNESS.SHARED, "request", return_value=response), \
                 patch.object(HARNESS.NATIVE, "finish", return_value=[bad]), self.assertRaises(AssertionError):
                HARNESS.finish_service(Job(), ("origin", "token", "csrf"), {})
    def test_draining_acknowledgement_cannot_mask_timeout_or_killed_exit(self):
        response = {"state": "draining", "new_mutations_accepted": False}
        for bad in ({**row(), "exit": -9}, {**row(), "failure": "timeout"}):
            with patch.object(HARNESS.SHARED, "request", return_value=response), \
                 patch.object(HARNESS.NATIVE, "finish", return_value=[bad]), self.assertRaises(AssertionError):
                HARNESS.finish_service(Job(), ("origin", "token", "csrf"), {})
    def test_startup_failure_still_finishes_owned_child(self):
        bad = {**row(), "exit": -9, "failure": "service-quiesce"}
        report = {}
        with patch.object(HARNESS.NATIVE, "finish", return_value=[bad]) as finish, self.assertRaises(AssertionError):
            HARNESS.finish_service(self.job, None, report)
        self.assertTrue(self.job.killed)
        finish.assert_called_once_with([self.job])
        self.assertEqual(report["owned_service"], bad)
    def test_session_or_quiesce_failure_retains_cleanup(self):
        bad = {**row(), "exit": -9, "failure": "service-quiesce"}
        report = {}
        with patch.object(HARNESS.SHARED, "request", side_effect=RuntimeError("session refused")), \
             patch.object(HARNESS.NATIVE, "finish", return_value=[bad]), self.assertRaises(AssertionError):
            HARNESS.finish_service(self.job, ("origin", "token", None), report)
        self.assertTrue(self.job.killed)
        self.assertEqual(report["owned_service"], bad)
    def test_optimized_python_refuses_before_dependency_or_process_use(self):
        with self.assertRaisesRegex(RuntimeError, "without -O"):
            exec(compile(PATH.read_text(), str(PATH), "exec", optimize=1), {})


if __name__ == "__main__":
    unittest.main()
