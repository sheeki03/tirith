#!/usr/bin/env python3
"""Synthetic cohort admission controls; no measurements or performance claims."""
from contextlib import ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


SCRIPTS = Path(__file__).parent
gate = module("admission", Path(__file__).with_name("admit-native-resource-budget.py"))
collector = module("collector", SCRIPTS / "collect-native-resource-reference.py")
fixtures = module("budget_fixtures", SCRIPTS / "test-check-resource-budgets.py")
check = fixtures.check


class Admission(unittest.TestCase):
    def setUp(self):
        _, _, context, self.budget = fixtures.fixtures()
        self.budget["native_helper_sha256"] = "9" * 64
        self.runtime = {"version": "fixture Python", "executable": "/fixture/python", "sha256": "8" * 64}
        self.host = {"boot": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "runner_name": "fixture",
                     "class": {**context["host"], **{k: v for k, v in context["runner"].items() if k != "label"}}}
        self.source = {"revision": "2" * 40, "tree": "3" * 40,
                       "manifests": copy.deepcopy(self.budget["build_contract"]["build_manifest_sha256"]),
                       "producers": copy.deepcopy(self.budget["producer_sha256"]), "helper": "9" * 64}
        self.admission = {"schema_version": 1, "status": "reviewed", "review": "synthetic test only",
                          "budget_path": "budget.json", "budget_sha256": "7" * 64,
                          "python_runtime": collector.python_runtime_key(self.runtime),
                          "tools_sha256": {p: "6" * 64 for p in (
                              "scripts/collect-native-resource-reference.py", "scripts/check-resource-budgets.py",
                              "scripts/record-resource-context.py")}}
        self.observed = {}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for target, value in (("tracked", lambda root, path: root / path),
                              ("sha", lambda path: "6" * 64),
                              ("host_identity", lambda observed: self.host),
                              ("python_runtime", lambda: self.runtime),
                              ("snapshot", lambda root: self.source),
                              ("command", lambda name, *args: self.budget["build_contract"][name + "_verbose"])):
            self.stack.enter_context(patch.object(collector, target, side_effect=value))
        self.stack.enter_context(patch.object(check, "load", side_effect=lambda path:
            (self.admission, "5" * 64) if path.name == "admission.json" else (self.budget, "7" * 64)))
        self.stack.enter_context(patch.dict(os.environ, {
            "GITHUB_SHA": "2" * 40, "GITHUB_WORKFLOW_SHA": "2" * 40,
            "RESOURCE_RUNNER_LABEL": "fixture",
            "GITHUB_WORKFLOW_REF": "fixture/repo/.github/workflows/bench.yml@refs/pull/1/merge"}))

    def run_admission(self):
        gate.admit(Path("/fixture/source"), "admission.json", collector, check, self.observed)

    def test_new_event_source_can_use_compatible_historical_budget(self):
        self.run_admission()
        self.assertNotEqual(self.source["revision"], self.budget["baseline_evidence"][0]["source_revision"])
        self.assertEqual(self.observed["source"], self.source)
        self.assertNotIn("budget_enforced", self.observed)

    def test_stale_source_and_different_workflow_refuse(self):
        for field in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
            with self.subTest(field=field), patch.dict(os.environ, {field: "4" * 40}), \
                    self.assertRaisesRegex(ValueError, "event source"):
                self.run_admission()
        with patch.dict(os.environ, {"GITHUB_WORKFLOW_REF": "fixture/repo/.github/workflows/other.yml@refs/heads/fixture"}), \
                self.assertRaisesRegex(ValueError, "compiler/build"):
            self.run_admission()

    def test_changed_host_refuses_before_source_or_build(self):
        for field, value in (("image_version", "changed"), ("cpu_model", "different CPU"), ("logical_cpus", 4)):
            original = copy.deepcopy(self.host)
            self.host["class"][field] = value
            with self.subTest(field=field), patch.object(collector, "snapshot", side_effect=AssertionError("too late")), \
                    self.assertRaisesRegex(ValueError, "runner differs"):
                self.run_admission()
            self.host = original

    def test_changed_python_bytes_or_version_refuse_but_path_does_not(self):
        self.runtime["executable"] = "/another/python"
        self.run_admission()
        for field, value in (("version", "new version"), ("sha256", "4" * 64)):
            original = self.runtime[field]
            self.runtime[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Python runtime changed"):
                self.run_admission()
            self.runtime[field] = original

    def test_changed_producer_helper_and_manifest_refuse(self):
        changes = [("producers", "local"), ("manifests", "Cargo.lock")]
        for parent, field in changes:
            original = self.source[parent][field]
            self.source[parent][field] = "4" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_admission()
            self.source[parent][field] = original
        self.source["helper"] = "4" * 64
        with self.assertRaisesRegex(ValueError, "native helper changed"):
            self.run_admission()

    def test_changed_measurement_tool_refuses_before_host_probe(self):
        with patch.object(collector, "sha", return_value="4" * 64), \
                patch.object(collector, "host_identity", side_effect=AssertionError("too late")), \
                self.assertRaisesRegex(ValueError, "measurement tools changed"):
            self.run_admission()

    def test_unreviewed_and_changed_budget_refuse(self):
        for target, field, value in ((self.admission, "status", "draft"),
                                     (self.admission, "schema_version", True),
                                     (self.admission, "budget_sha256", "4" * 64),
                                     (self.budget, "status", "draft")):
            original = target[field]
            target[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.run_admission()
            target[field] = original

    def test_post_collection_rejects_runtime_boot_and_source_handoff_drift(self):
        self.run_admission()
        prior = {"status": "compatible_for_measurement", "budget_enforced": False,
                 "observed": copy.deepcopy(self.observed)}
        inputs = {"source": copy.deepcopy(self.source), "role": "baseline",
                  "native_host": copy.deepcopy(self.host), "python": copy.deepcopy(self.runtime)}
        documents = {"prior.json": prior, "build-inputs.json": inputs,
                     "source-before.json": copy.deepcopy(self.source), "source-after.json": copy.deepcopy(self.source)}
        with patch.object(check, "load", side_effect=lambda p: (documents[p.name], "5" * 64)):
            def confirm():
                gate.confirm_collection(Path("/fixture/collection"), Path("prior.json"), self.observed, collector, check)
            confirm()
            for document, field, bad in ((inputs["python"], "sha256", "4" * 64),
                                         (inputs["native_host"], "boot", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                                         (inputs["source"], "revision", "4" * 40),
                                         (documents["source-after.json"], "tree", "4" * 40),
                                         (prior, "status", "refused")):
                old = document[field]
                document[field] = bad
                with self.subTest(field=field), self.assertRaises(ValueError):
                    confirm()
                document[field] = old
            prior["observed"]["tools_sha256"]["scripts/check-resource-budgets.py"] = "4" * 64
            with self.assertRaisesRegex(ValueError, "admission facts changed"):
                confirm()

    def test_cli_keeps_refusal_hashes_and_never_claims_enforcement(self):
        self.admission["budget_sha256"] = "4" * 64
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            output = root / "result.json"
            argv = ["admit", "--source", str(root), "--admission", "admission.json", "--output", str(output)]
            with patch.object(gate.sys, "argv", argv), patch.object(gate, "load_module", side_effect=[collector, check]), \
                    patch("builtins.print"):
                self.assertEqual(gate.main(), 2)
            result = json.loads(output.read_bytes())
            self.assertEqual(result["status"], "refused")
            self.assertFalse(result["budget_enforced"])
            self.assertEqual(result["observed"]["admission_sha256"], "5" * 64)
            self.assertEqual(result["observed"]["budget_sha256"], "7" * 64)


if __name__ == "__main__":
    unittest.main()
