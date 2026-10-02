#!/usr/bin/env python3
"""Collector contracts only; no builds, native workloads or product execution."""
import copy
from contextlib import redirect_stdout
import io
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace


spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("collect-native-resource-reference.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorContracts(unittest.TestCase):
    def runtime(self, path="/fixture/python3"):
        return {"version": "3.14.0 (synthetic parser control)", "executable": path, "sha256": "a" * 64}

    def test_python_runtime_identity_requires_version_and_exact_bytes_but_not_same_install_path(self):
        original = self.runtime()
        collector.same_python(original, self.runtime("/another/job/python3"))
        for field, value in (("version", "different"), ("sha256", "b" * 64)):
            changed = {**original, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Python runtime"):
                collector.same_python(original, changed)
        for changed in (None, {}, {**original, "executable": "relative"},
                        {**original, "sha256": "A" * 64}, {**original, "version": ""},
                        {**original, "version": "x" * 2049}, {**original, "extra": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                collector.python_runtime_key(changed)

    def test_pair_refuses_python_drift_before_metric_evaluation(self):
        keys = ("runner_boot_id", "runner_name", "runner_class", "run_id", "event_revision", "workflow_sha", "rustc_verbose", "cargo_verbose")
        role = {"provenance": {key: key for key in keys}, "python": self.runtime(),
                "context": {}, "local": {}, "allocation": {}, "metrics": {}}
        def reached(*args):
            raise RuntimeError("metric evaluation reached")
        checker = SimpleNamespace(evaluate=reached)
        for field, value in (("version", "other"), ("sha256", "b" * 64)):
            pair = {"control": copy.deepcopy(role), "growth": copy.deepcopy(role)}
            pair["growth"]["python"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Python runtime"):
                collector.qualify("clean_first", pair, {}, checker)
        pair = {"control": copy.deepcopy(role), "growth": copy.deepcopy(role)}
        pair["growth"]["python"]["executable"] = "/another/job/python3"
        with self.assertRaisesRegex(RuntimeError, "metric evaluation reached"):
            collector.qualify("clean_first", pair, {}, checker)

    def test_growth_protocol_binds_every_baseline_to_the_verified_base_tree(self):
        # In-memory parser controls. No Git revisions, artifacts, builds or
        # measured native evidence are created by this fixture.
        base, tree = "a" * 40, "b" * 40
        raw = b"inert mutation parser control"
        protocol = {"schema_version": 1, "status": "reviewed", "review": "control",
                    "cohort": "fixture", "base_revision": base, "base_tree": tree,
                    "budget_path": "budget.json", "budget_sha256": "c" * 64,
                    "checker_sha256": "d" * 64,
                    "python_runtime": collector.python_runtime_key(self.runtime()),
                    "experiments": {"clean_first": {
                        role: {"revision": rev * 40, "tree": branch * 40,
                               "source_sha256": hashlib.sha256(raw).hexdigest()}
                        for role, rev, branch in (("control", "1", "2"), ("growth", "3", "4"))}}}
        budget = {"status": "reviewed", "baseline_evidence": [{"source_revision": base} for _ in range(3)],
                  "limits": [{"metric": row[0], "unit": "bytes"} for row in collector.EXPERIMENTS.values()]}
        root = Path("/in-memory-control")
        checker = SimpleNamespace(load=lambda path: (protocol, "e" * 64) if path.name == "protocol.json" else (budget, "c" * 64),
                                  text=lambda *args: None, digest=lambda *args: None)
        trees = {base: tree, "1" * 40: "2" * 40, "3" * 40: "4" * 40}
        def git(root, *args):
            return trees[args[1].removesuffix("^{tree}")] if args[0] == "rev-parse" else collector.EXPERIMENTS["clean_first"][3]
        with patch.object(collector, "tracked", side_effect=lambda root, name: root / name), \
             patch.object(collector, "sha", return_value="d" * 64), \
             patch.object(collector, "git", side_effect=git), \
             patch.object(collector.subprocess, "check_output", return_value=raw):
            self.assertEqual(collector.read_protocol(root, "protocol.json", "clean_first", checker)[0], protocol)
            for index in range(3):
                budget["baseline_evidence"][index]["source_revision"] = "f" * 40
                with self.subTest(index=index), self.assertRaisesRegex(ValueError, "every reviewed baseline"):
                    collector.read_protocol(root, "protocol.json", "clean_first", checker)
                budget["baseline_evidence"][index]["source_revision"] = base
            protocol["base_tree"] = "f" * 40
            with self.assertRaisesRegex(ValueError, "base tree differs"):
                collector.read_protocol(root, "protocol.json", "clean_first", checker)
            protocol["base_tree"] = tree
            protocol["python_runtime"]["sha256"] = "missing"
            with self.assertRaisesRegex(ValueError, "Python executable digest"):
                collector.read_protocol(root, "protocol.json", "clean_first", checker)

    def test_growth_role_refuses_runtime_different_from_reviewed_cohort_before_build(self):
        runtime = self.runtime()
        protocol = {"python_runtime": {**collector.python_runtime_key(runtime), "sha256": "b" * 64}}
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(collector, "python_runtime", return_value=runtime), \
             patch.object(collector, "snapshot", return_value={"revision": "a" * 40}), \
             patch.object(collector, "command", return_value="release: 1.98.1\nhost: aarch64-apple-darwin"), \
             patch.object(collector, "invoke") as invoke:
            with self.assertRaisesRegex(ValueError, "reviewed baseline cohort"):
                collector.collect(Path(temp), Path(temp) / "control", "control", "a" * 40, {}, None, protocol, {})
            invoke.assert_not_called()

    def test_baseline_reviewer_requires_one_python_identity_and_exact_virtual_cpu(self):
        # Only the reviewer's identity join is exercised here. Inputs are
        # in-memory synthetic parser controls; report/provenance validators
        # are mocked and no measurement evidence is written or qualified.
        spec = importlib.util.spec_from_file_location("baseline_review", Path(__file__).with_name("review-native-resource-baselines.py"))
        reviewer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reviewer)
        directories = [Path("/in-memory-control") / str(index) for index in range(3)]
        runtimes = [self.runtime(f"/job/{index}/python3") for index in range(3)]
        cpus = ["Apple M1 (Virtual)"] * 3
        before = {"revision": "a" * 40, "tree": "b" * 40,
                  "producers": {}, "helper": "helper",
                  "manifests": {"Cargo.toml": "toml", "Cargo.lock": "lock"}}
        local = {"schema_version": 2, "binary_sha256": "product", "native_helper_sha256": "helper",
                 "history_fixture": {}, "measurements": {reviewer.check.CLI[0]: {"n": 100}}}
        allocation = {"instrumented_harness_sha256": "allocation", "history_fixture": {},
                      "workloads": [{"samples": [None] * 100}]}
        metrics = {row[0]: {"value": 1} for row in collector.EXPERIMENTS.values()}
        def load(path):
            index = int(path.parts[2])
            native = {"boot": str(index), "runner_name": "runner", "class": {}}
            provenance = {"source_revision": before["revision"], "source_tree": before["tree"],
                          "build_manifest_sha256": before["manifests"], "runner_boot_id": native["boot"],
                          "runner_name": "runner", "runner_class": {}, "reference_cohort": None,
                          "run_id": str(index), "build_profile": "release", "rustc_verbose": "rustc",
                          "cargo_verbose": "cargo", "workflow_ref": "sheeki03/tirith/.github/workflows/bench.yml@refs/heads/control"}
            records = {
                "result.json": {"status": "baseline_collected_unbudgeted", "budget_enforced": False, "baseline_boot": native["boot"]},
                "resource-context.json": {"host": {"system": "Darwin", "machine": "arm64"},
                                          "runner": {"label": "macos-15", "cpu_model": cpus[index]}, "producer_sha256": {}},
                "resource-build-provenance.json": provenance,
                "source-before.json": before, "source-after.json": before,
                "native-host.json": native,
                "build-inputs.json": {"source": before, "role": "baseline", "native_host": native,
                                      "python": runtimes[index], "build_target": "aarch64-apple-darwin",
                                      "product": {"sha256": "product"}, "allocation": {"sha256": "allocation"}},
            }
            digest = "same-source" if path.name.startswith("source-") else f"{index}:{path.name}"
            return records[path.name], digest
        with patch.object(reviewer.check, "load", side_effect=load), \
             patch.object(reviewer.check, "reports", return_value=(local, allocation, {}, metrics)), \
             patch.object(reviewer.check, "context_check"), patch.object(reviewer.check, "provenance_check"):
            result = reviewer.review(directories)
            self.assertEqual(result["contract"]["python_runtime"], collector.python_runtime_key(self.runtime()))
            self.assertFalse(result["budget_enforced"])
            self.assertFalse(result["limits_selected"])
            for index in range(3):
                for cpu in ("Apple M1", "Apple M2", "Apple M1 (Virtual) "):
                    cpus[index] = cpu
                    with self.subTest(index=index, cpu=cpu), self.assertRaisesRegex(ValueError, "selected native Mac cohort"):
                        reviewer.review(directories)
                cpus[index] = "Apple M1 (Virtual)"
            for index in (1, 2):
                for field, value in (("version", "other"), ("sha256", "b" * 64)):
                    runtimes[index][field] = value
                    with self.subTest(index=index, field=field), self.assertRaisesRegex(ValueError, "Python runtime"):
                        reviewer.review(directories)
                    runtimes[index] = self.runtime(f"/job/{index}/python3")

    def host(self, cpu="Apple M1 (Virtual)", boot="ABABABAB-1234-4234-8234-123456789ABC"):
        def command(*args, **kwargs):
            return cpu if args[-1] == "machdep.cpu.brand_string" else boot
        with patch.object(collector.platform, "system", return_value="Darwin"), \
             patch.object(collector.platform, "machine", return_value="arm64"), \
             patch.object(collector, "command", side_effect=command), \
             patch.dict(collector.os.environ, {"ImageOS": "macos15", "ImageVersion": "fixture", "RUNNER_NAME": "fixture"}):
            return collector.host_identity()

    def test_actual_boot_uuid_is_canonicalized_without_inventing_an_identity(self):
        self.assertEqual(self.host()["boot"], "abababab-1234-4234-8234-123456789abc")
        with self.assertRaises(ValueError):
            self.host(boot="00000000-0000-0000-0000-000000000000")
        with self.assertRaises(ValueError):
            self.host(boot="missing")

    def test_exact_virtual_mac_cpu_is_retained_without_normalization(self):
        self.assertEqual(self.host()["class"]["cpu_model"], "Apple M1 (Virtual)")

    def test_unexpected_mac_cpu_refuses_instead_of_relabeling(self):
        for cpu in ("Apple M1", "Apple M2", "Apple M1 (Virtual) ", "Apple M1 Pro"):
            with self.subTest(cpu=cpu), self.assertRaisesRegex(ValueError, r"Apple M1 \(Virtual\)"):
                self.host(cpu=cpu)

    def test_main_retains_actual_host_facts_when_cpu_admission_refuses(self):
        # No native commands, builds or measurement evidence: exercise the real
        # output/refusal path with synthetic host observations only.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            output = root / "new-output"
            argv = ["collector", "--source", str(root), "--output", str(output), "--experiment", "baseline"]
            with patch.object(collector.sys, "argv", argv), \
                 patch.object(collector.platform, "system", return_value="Darwin"), \
                 patch.object(collector.platform, "machine", return_value="arm64"), \
                 patch.object(collector.platform, "release", return_value="fixture-kernel"), \
                 patch.object(collector.os, "cpu_count", return_value=6), \
                 patch.object(collector, "command", return_value="Apple M2") as command, \
                 patch.object(collector, "collect") as collect, \
                 patch.object(collector, "git") as git, \
                 patch.dict(collector.os.environ, {"RESOURCE_LEGACY_REFERENCE": "false", "ImageOS": "macos15",
                                                  "ImageVersion": "fixture-image", "RUNNER_NAME": "fixture-runner"}), \
                 redirect_stdout(io.StringIO()) as logged:
                self.assertEqual(collector.main(), 2)
            report = json.loads((output / "evidence/result.json").read_text())
            self.assertEqual(json.loads(logged.getvalue()), report)
            self.assertEqual(report["status"], "refused")
            self.assertFalse(report["budget_enforced"])
            self.assertIn("Apple M1 (Virtual)", report["error"])
            diagnostic = report["host_observation"]
            self.assertEqual(diagnostic["scope"], "diagnostic_only_not_admitted")
            self.assertEqual(diagnostic["expected"]["cpu_model"], "Apple M1 (Virtual)")
            for key, value in {"cpu_model": "Apple M2", "system": "Darwin", "machine": "arm64",
                               "release": "fixture-kernel", "logical_cpus": 6, "image": "macos15",
                               "image_version": "fixture-image", "runner_name": "fixture-runner"}.items():
                self.assertEqual(diagnostic["observed"][key], value)
            self.assertNotIn("boot_raw", diagnostic["observed"])
            self.assertFalse((output / "evidence/native-host.json").exists())
            self.assertFalse((output / "evidence/baseline").exists())
            command.assert_called_once_with("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
            collect.assert_not_called()
            git.assert_not_called()

    def test_unavailable_cpu_is_not_invented_after_platform_refusal(self):
        observed = {}
        with patch.object(collector.platform, "system", return_value="Linux"), \
             patch.object(collector.platform, "machine", return_value="aarch64"), \
             patch.object(collector, "command") as command, \
             self.assertRaisesRegex(ValueError, "Darwin ARM64"):
            collector.host_identity(observed)
        self.assertEqual(observed["system"], "Linux")
        self.assertEqual(observed["machine"], "aarch64")
        self.assertNotIn("cpu_model", observed)
        self.assertNotIn("boot_raw", observed)
        command.assert_not_called()

    def test_pair_does_not_accept_different_boot_even_when_cpu_matches(self):
        observed = self.host()
        changed = copy.deepcopy(observed)
        changed["boot"] = "bbbbbbbb-1234-4234-8234-123456789abc"
        with self.assertRaisesRegex(ValueError, "changed"):
            collector.same_host(observed, changed)

    def test_source_paths_cannot_escape_or_alias_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for bad in ("../budget.json", "/budget.json", "a/../../budget.json", "budget;echo.json"):
                with self.subTest(path=bad), self.assertRaises(ValueError):
                    collector.tracked(root, bad)
            (root / "regular.json").write_text("{}")
            (root / "alias.json").symlink_to(root / "regular.json")
            with self.assertRaises(ValueError):
                collector.tracked(root, "alias.json")

    def test_selected_source_must_be_an_immutable_revision(self):
        for value in ("main", "123", "A" * 40, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.immutable(value)
        self.assertEqual(collector.immutable("a" * 40), "a" * 40)

    def test_qualification_refuses_cross_runner_pair_before_evaluating_metrics(self):
        keys = ("runner_boot_id", "runner_name", "runner_class", "run_id", "event_revision", "workflow_sha", "rustc_verbose", "cargo_verbose")
        original = {key: key for key in keys}
        for field in keys:
            other = dict(original)
            other[field] = "different"
            pair = {"control": {"provenance": original}, "growth": {"provenance": other}}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "pair native/build identity"):
                collector.qualify("clean_first", pair, {}, None)

    def test_cargo_source_role_and_completion_are_bound_before_image_use(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            image = root / "inert-not-executed"
            image.write_bytes(b"Parser fixture, not an executable")
            package = root / "crates/tirith"
            original = {"reason": "compiler-artifact", "executable": str(image),
                "manifest_path": str(package / "Cargo.toml"), "package_id": "path+" + package.as_uri() + "#0.4.2",
                "target": {"name": "tirith", "kind": ["bin"], "src_path": str(package / "src/main.rs")},
                "profile": {"opt_level": "3", "debug_assertions": False, "test": False}}
            complete = {"reason": "build-finished", "success": True}
            def retain(rows):
                (root / "cargo.stdout").write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            retain([original, complete])
            self.assertEqual(collector.executable(root, "cargo", root, "tirith", "bin")[0], image)
            for field in ("manifest_path", "package_id", "src_path", "test"):
                changed = copy.deepcopy(original)
                if field == "src_path": changed["target"][field] = str(root / "other.rs")
                elif field == "test": changed["profile"][field] = True
                else: changed[field] = "different checkout"
                retain([changed, complete])
                with self.subTest(field=field), self.assertRaises(ValueError):
                    collector.executable(root, "cargo", root, "tirith", "bin")
            for rows in ([original], [original, original, complete]):
                retain(rows)
                with self.assertRaises(ValueError):
                    collector.executable(root, "cargo", root, "tirith", "bin")


if __name__ == "__main__":
    unittest.main()
