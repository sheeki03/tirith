#!/usr/bin/env python3
"""Synthetic evaluator contracts; fixture limits are not product budgets."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


check = module("resource_budgets", "check-resource-budgets.py")
measure = module("measure", "measure-local-control.py")
record = module("record", "record-resource-context.py")


def provenance_fixture(context):
    return {"schema_version": 1, "source_revision": context["source_revision"], "source_tree": "2" * 40,
            "selected_measurement_source": context["source_revision"], "expected_measurement_tree": None,
            "event_revision": context["source_revision"], "run_id": context["run_id"],
            "workflow_ref": "fixture/repo/.github/workflows/bench.yml@refs/heads/fixture",
            "workflow_sha": context["source_revision"], "runner_name": "fixture runner",
            "runner_boot_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "runner_class": {**context["host"], **{key: value for key, value in context["runner"].items() if key != "label"}},
            "expected_reference_class": None, "source_clean_before_build": True,
            "rustc_verbose": "SYNTHETIC rustc\nhost: fixture", "cargo_verbose": "SYNTHETIC cargo\nhost: fixture",
            "build_profile": "release", "build_manifest_sha256": {"Cargo.toml": "e" * 64, "Cargo.lock": "f" * 64},
            "expected_build_manifest_sha256": None, "reference_cohort": None, "workload_samples": 3, "admission_issues": []}


def contract_fixture(provenance):
    value = {key: copy.deepcopy(provenance[key]) for key in ("build_profile", "rustc_verbose", "cargo_verbose", "build_manifest_sha256")}
    value["workflow_path"] = "fixture/repo/.github/workflows/bench.yml"
    return value


def fixtures():
    sample = {"availability": "available", "cpu_user_ms": 1.0, "cpu_system_ms": 2.0, "peak_rss_bytes": 4096}
    local = {"schema_version": 1, "measurement_kind": "local_candidate_characterization",
             "binary_sha256": "a" * 64, "harness_sha256": "b" * 64, "binary_unchanged_during_run": True,
             "host": {"system": "Linux", "release": "fixture-kernel", "machine": "x86_64"},
             "sampling": {"unit": "one subprocess or HTTP request", "order": "serial", "cold_cache_claim": False},
             "resource_method": {"source": "RUSAGE_CHILDREN in one fresh wrapper per command", "wrapper_startup_included": False},
             "history_fixture": {"rows": 1000, "bytes": 100000},
             "bounds": {"history_page_bytes": 2097152, "history_records_requested": 100, "response_bytes": 524288, "assertions_passed": True},
             "measurements": {},
             "service_resources": {"availability": "available", "errors": [], "nominal_interval_ms": 250, "sample_limit": 4800,
                                   "samples": [{"elapsed_ms": 1, "rss_bytes": 4096, "cpu_ms": 0}, {"elapsed_ms": 251, "rss_bytes": 8192, "cpu_ms": 10}],
                                   "sampled_max_rss_bytes": 8192, "cpu_observed_ms": 10}}
    for name in check.CLI + check.HTTP:
        row = measure.distribution([1.0, 2.0, 3.0])
        if name in check.CLI:
            row.update(first_ms=1.0, subsequent=measure.distribution([2.0, 3.0]), resources=[copy.deepcopy(sample) for _ in range(3)])
        else:
            row["max_response_bytes"] = 100
        local["measurements"][name] = row
    local["measurements"]["service_launch"] = {"ms": 2.0, "resources": [copy.deepcopy(sample)]}
    allocation = {"schema_version": 1, "measurement_kind": "instrumented_core_thread_allocations",
                  "instrumented_harness_sha256": "c" * 64, "os": "linux", "arch": "x86_64",
                  "method": {"allocator": "System with thread-local counters", "cold_cache_claim": False},
                  "history_fixture": {"rows": 10000, "bytes": 4360000}, "workloads": []}
    for name in check.CORE:
        allocation["workloads"].append({"name": name, "samples": [
            {"elapsed_ns": value, "counts": {field: value for field in check.COUNTS}} for value in [1, 2, 3]], "p50_ns": 2, "p95_ns": 3})
    context = {"schema_version": 1, "source_revision": "1" * 40, "build_profile": "release", "run_id": "fixture-run",
               "host": copy.deepcopy(local["host"]), "runner": {"label": "fixture", "image": "fixture", "image_version": "1", "cpu_model": "fixture CPU", "logical_cpus": 2},
               "producer_sha256": {"local": "b" * 64, "allocation": "d" * 64}, "report_sha256": {},
               "executable_sha256": {"local": "a" * 64, "allocation": "c" * 64}}
    budget = {"schema_version": 2, "status": "reviewed", "review": "SYNTHETIC FIXTURE ONLY", "scope": "four fixture metrics",
              "host": copy.deepcopy(context["host"]), "runner": copy.deepcopy(context["runner"]), "producer_sha256": copy.deepcopy(context["producer_sha256"]),
              "history_fixture": {"local": local["history_fixture"], "allocation": allocation["history_fixture"]},
              "workload_samples": {"local": 3, "allocation": 3},
              "baseline_evidence": [{"run_id": "fixture-" + str(i), "context_sha256": str(i) * 64, "source_revision": "1" * 40,
                                     "build_profile": "release", "derivation": "Synthetic fixture; never a performance claim",
                                     "build_provenance_sha256": str(i + 3) * 64,
                                     "runner_boot_id": f"0000000{i}-0000-4000-8000-000000000000"} for i in range(1, 4)],
              "build_contract": contract_fixture(provenance_fixture(context)),
              "limits": [{"metric": name, "unit": unit, "maximum": maximum, "minimum_samples": 3,
                          "rationale": "Synthetic exact-boundary test, not a reviewed product threshold"} for name, unit, maximum in [
                              ("local.cli_version.latency_ms.p95", "ms", 3), ("local.cli_version.cpu_ms.median", "ms", 3),
                              ("local.cli_version.peak_rss_bytes.max", "bytes", 4096),
                              ("allocation.tier1_clean.allocation_calls.max", "calls", 3)]]}
    return local, allocation, context, budget


def owned_fixture(local):
    local["schema_version"] = 2
    local["status"] = "completed"
    local["native_helper_sha256"] = "9" * 64
    local["native_helper_unchanged_during_run"] = True
    local["harness_unchanged_during_run"] = True
    local["service_resources"]["sampler_joined"] = True
    local["owned_service"] = {"pid": 42, "exit": 0, "failure": None,
        "startup_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "service_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "binary_sha256": local["binary_sha256"],
        "identity_validated": True, "launcher_reused": True, "quiesce_acknowledged": True,
        "cleanup": {key: True for key in ("leader_reaped", "group_signaled_or_absent", "group_members_exited", "output_eof")},
        "group_observation": {"method": "procfs", "leader_retained_waitable": True,
                              "members": [{"pid": 42, "state": "exited"}]}}
    launch = local["measurements"].pop("service_launch")
    launch["scope"] = "public launcher reuse of the already running owned service"
    local["measurements"]["service_launcher_reuse"] = launch
    local["measurements"]["service_direct_start"] = {
        "ms": 5, "scope": "owned direct spawn through validated discovery and authenticated session"}



class ResourceBudgets(unittest.TestCase):
    def setUp(self):
        self.local, self.allocation, self.context, self.budget = fixtures()
        self.provenance = provenance_fixture(self.context)

    def metrics(self):
        return {**check.local_metrics(self.local), **check.allocation_metrics(self.allocation)}

    def evaluate(self):
        return check.evaluate(self.budget, self.context, self.local, self.allocation, self.metrics(), self.provenance)

    def test_owned_startup_and_reuse_are_distinct_from_historical_launch(self):
        historical = self.metrics()
        self.assertIn("local.service_launch.latency_ms.max", historical)
        owned_fixture(self.local)
        current = self.metrics()
        self.assertNotIn("local.service_launch.latency_ms.max", current)
        self.assertEqual(current["local.service_direct_start.latency_ms.max"]["value"], 5)
        self.assertIn("local.service_launcher_reuse.peak_rss_bytes.max", current)
        self.assertNotIn("local.service_direct_start.peak_rss_bytes.max", current)

    def test_owned_enforcement_requires_exact_helper_hash(self):
        owned_fixture(self.local)
        with self.assertRaises(check.Invalid): self.evaluate()
        self.budget["native_helper_sha256"] = self.local["native_helper_sha256"]
        self.assertTrue(all(row["passed"] for row in self.evaluate()))
        self.budget["native_helper_sha256"] = "8" * 64
        with self.assertRaisesRegex(check.Invalid, "native helper changed"): self.evaluate()

    def test_owned_report_requires_each_real_cleanup_and_lifecycle_fact(self):
        owned_fixture(self.local)
        original = copy.deepcopy(self.local)
        for field in ("identity_validated", "launcher_reused", "quiesce_acknowledged"):
            self.local = copy.deepcopy(original)
            self.local["owned_service"][field] = False
            with self.assertRaises(check.Invalid): self.metrics()
        for field in original["owned_service"]["cleanup"]:
            for bad in (False, 1):
                self.local = copy.deepcopy(original)
                self.local["owned_service"]["cleanup"][field] = bad
                with self.assertRaises(check.Invalid): self.metrics()
        for field, bad in (("exit", -9), ("exit", False), ("failure", "timeout")):
            self.local = copy.deepcopy(original)
            self.local["owned_service"][field] = bad
            with self.assertRaises(check.Invalid): self.metrics()

    def test_owned_report_rejects_missing_native_observation_and_failed_run(self):
        owned_fixture(self.local)
        original = copy.deepcopy(self.local)
        for mutate in (
            lambda r: r.update(status="failed"),
            lambda r: r.update(native_helper_unchanged_during_run=False),
            lambda r: r.update(harness_unchanged_during_run=False),
            lambda r: r.pop("harness_unchanged_during_run"),
            lambda r: r["service_resources"].update(sampler_joined=False),
            lambda r: r["service_resources"].pop("sampler_joined"),
            lambda r: r["owned_service"].pop("group_observation"),
            lambda r: r["owned_service"].update(binary_sha256="e" * 64),
            lambda r: r["owned_service"].update(startup_id="forged"),
            lambda r: r["owned_service"]["group_observation"].update(leader_retained_waitable=False),
            lambda r: r["owned_service"]["group_observation"]["members"][0].update(state="live"),
            lambda r: r["measurements"]["service_direct_start"].update(resources=[]),
            lambda r: r["measurements"]["service_launcher_reuse"].update(scope="cold launch"),
        ):
            self.local = copy.deepcopy(original)
            mutate(self.local)
            with self.assertRaises(check.Invalid): self.metrics()

    def test_all_four_metric_families_pass_exact_maximum_and_fail_above(self):
        self.assertTrue(all(row["passed"] for row in self.evaluate()))
        for index in range(4):
            with self.subTest(index=index):
                old = self.budget["limits"][index]["maximum"]
                self.budget["limits"][index]["maximum"] = old - .1
                self.assertFalse(self.evaluate()[index]["passed"])
                self.budget["limits"][index]["maximum"] = old

    def test_summary_only_latency_is_inventory_but_not_a_budget_pass(self):
        del self.local["measurements"]["cli_version"]["samples_ms"]
        del self.local["measurements"]["cli_version"]["subsequent"]["samples_ms"]
        self.assertFalse(self.metrics()["local.cli_version.latency_ms.p95"]["raw_samples"])
        with self.assertRaisesRegex(check.Invalid, "raw samples"):
            self.evaluate()

    def test_partial_raw_history_cannot_enable_a_contradictory_budget(self):
        for keep_parent in (False, True):
            self.setUp()
            row = self.local["measurements"]["cli_version"]
            if keep_parent:
                del row["subsequent"]["samples_ms"]
            else:
                del row["samples_ms"]
                row["subsequent"] = measure.distribution([0.0, 0.0])
            with self.assertRaisesRegex(check.Invalid, "mixed historical"):
                self.evaluate()

    def test_special_or_linked_reports_refuse_before_blocking_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            regular = root / "regular.json"
            regular.write_text('{}')
            with self.assertRaises(check.Invalid):
                check.load(root)
            if hasattr(os, "symlink"):
                link = root / "linked.json"
                link.symlink_to(regular)
                with self.assertRaises(check.Invalid):
                    check.load(link)
            if hasattr(os, "mkfifo"):
                fifo = root / "report.fifo"
                os.mkfifo(fifo)
                result = subprocess.run(
                    [sys.executable, str(Path(__file__).with_name("check-resource-budgets.py")),
                     "--local-report", str(fifo), "--allocation-report", str(regular), "--validate-only"],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "invalid")

    def test_missing_and_duplicate_workloads_fail(self):
        for source in ("local", "allocation"):
            with self.subTest(source=source):
                if source == "local":
                    del self.local["measurements"]["ordinary_check"]
                else:
                    self.allocation["workloads"][1]["name"] = self.allocation["workloads"][0]["name"]
                with self.assertRaises(check.Invalid):
                    self.metrics()
                self.setUp()

    def test_nonfinite_negative_boolean_and_huge_metrics_fail(self):
        for bad in (float("nan"), float("inf"), -1, True, 10**1000, "3"):
            for field in ("cpu_user_ms", "cpu_system_ms", "peak_rss_bytes"):
                with self.subTest(bad=type(bad).__name__, field=field), self.assertRaises(check.Invalid):
                    self.local["measurements"]["cli_version"]["resources"][0][field] = bad
                    check.local_metrics(self.local)
                self.setUp()

    def test_missing_resource_and_unavailable_samples_fail(self):
        for mutate in (lambda r: r.pop(), lambda r: r[0].update(availability="unsupported"), lambda r: r[0].pop("cpu_user_ms")):
            mutate(self.local["measurements"]["cli_version"]["resources"])
            with self.assertRaises(check.Invalid):
                self.metrics()
            self.setUp()

    def test_timing_summary_raw_count_and_order_are_checked(self):
        for mutate in (lambda r: r.update(n=True), lambda r: r.update(n=2), lambda r: r.update(p95_ms=2),
                       lambda r: r["samples_ms"].pop(), lambda r: r.update(first_ms=2),
                       lambda r: r["subsequent"].update(n=3), lambda r: r.update(min_ms=4)):
            mutate(self.local["measurements"]["cli_version"])
            with self.assertRaises(check.Invalid):
                self.metrics()
            self.setUp()

    def test_service_errors_counters_and_aggregates_are_checked(self):
        for mutate in (lambda r: r["errors"].append("timeout"), lambda r: r["samples"].pop(),
                       lambda r: r["samples"][1].update(elapsed_ms=0), lambda r: r["samples"][1].update(cpu_ms=-1),
                       lambda r: r.update(cpu_observed_ms=11), lambda r: r.update(sampled_max_rss_bytes=9999)):
            mutate(self.local["service_resources"])
            with self.assertRaises(check.Invalid):
                self.metrics()
            self.setUp()

    def test_allocation_count_types_and_summaries_are_checked(self):
        for mutate in (lambda r: r.update(p95_ns=4), lambda r: r["samples"][0]["counts"].update(allocation_calls=True),
                       lambda r: r["samples"][0]["counts"].update(requested_bytes=-1),
                       lambda r: r["samples"][0]["counts"].pop("deallocation_calls")):
            mutate(self.allocation["workloads"][0])
            with self.assertRaises(check.Invalid):
                self.metrics()
            self.setUp()

    def test_budget_draft_empty_unknown_duplicate_units_and_samples_fail(self):
        mutations = [lambda b: b.update(status="draft"), lambda b: b.update(limits=[]),
                     lambda b: b["limits"][0].update(metric="local.missing.latency_ms.p95"),
                     lambda b: b["limits"].append(copy.deepcopy(b["limits"][0])),
                     lambda b: b["limits"][0].update(unit="ns"), lambda b: b["limits"][0].update(minimum_samples=4),
                     lambda b: b["limits"][0].update(maximum=float("nan")), lambda b: b["limits"][0].update(maximum=True),
                     lambda b: b["baseline_evidence"].pop(), lambda b: b["baseline_evidence"][0].update(build_profile="debug"),
                     lambda b: b["baseline_evidence"][1].update(run_id="fixture-1")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(check.Invalid):
                mutate(self.budget); self.evaluate()
            self.setUp()

    def test_budget_context_and_fixture_changes_fail(self):
        for mutate in (lambda c: c["host"].update(release="different"), lambda c: c["runner"].update(logical_cpus=4),
                       lambda c: c["producer_sha256"].update(allocation="e" * 64)):
            mutate(self.context)
            with self.assertRaises(check.Invalid):
                self.evaluate()
            self.setUp()
        self.budget["workload_samples"]["local"] = 10
        with self.assertRaises(check.Invalid):
            self.evaluate()

    def test_context_binds_reports_executables_source_and_release_profile(self):
        hashes = {"local": "e" * 64, "allocation": "f" * 64}
        self.context["report_sha256"] = hashes
        check.context_check(self.context, self.local, self.allocation, hashes)
        for field, bad in (("build_profile", "debug"), ("source_revision", "main"), ("schema_version", True),
                           ("executable_sha256", {}), ("report_sha256", {}), ("runner", {})):
            value = copy.deepcopy(self.context); value[field] = bad
            with self.subTest(field=field), self.assertRaises(check.Invalid):
                check.context_check(value, self.local, self.allocation, hashes)

    def test_json_duplicates_nonfinite_oversize_and_nonobject_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"input.json"
            for value in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"extra":1e999}', b'[]', b'x' * (check.CAP + 1), b''):
                path.write_bytes(value)
                with self.assertRaises(check.Invalid):
                    check.load(path)

    def test_optional_baseline_is_checked_but_never_an_automatic_threshold(self):
        argv = (["--version"], ["doctor", "--quick", "--json"], ["policy", "effective", "--json"],
                ["check", "--shell", "posix", "--", "echo fixture"])
        self.local["baseline"] = {"binary_sha256": "f" * 64, "binary_unchanged_during_run": True,
                                  "measurements": {name: copy.deepcopy(self.local["measurements"][name]) for name in check.CLI[:4]},
                                  "comparison": {name: {"candidate_to_baseline_median_ratio": 1.0, "same_argv": args,
                                                       "same_fixture": True, "regression_budget_enforced": False} for name, args in zip(check.CLI[:4], argv)}}
        metrics = self.metrics()
        self.assertFalse(any(name.startswith("baseline.") for name in metrics))
        original = copy.deepcopy(self.local["baseline"])
        for mutate in (lambda b: b.update(binary_unchanged_during_run=False),
                       lambda b: b["comparison"]["cli_version"].update(candidate_to_baseline_median_ratio=float("nan")),
                       lambda b: b["comparison"]["cli_version"].update(candidate_to_baseline_median_ratio=2),
                       lambda b: b["comparison"]["cli_version"].update(same_argv=["different"]),
                       lambda b: b["measurements"]["cli_version"]["resources"].pop()):
            mutate(self.local["baseline"])
            with self.assertRaises(check.Invalid):
                self.metrics()
            self.local["baseline"] = copy.deepcopy(original)

    def test_changed_binary_and_incomplete_coverage_are_invalid(self):
        for mutate in (lambda r: r.update(binary_unchanged_during_run=False), lambda r: r.update(harness_sha256="unbound"),
                       lambda r: r["bounds"].update(assertions_passed=1), lambda r: r["host"].update(release="")):
            mutate(self.local)
            with self.assertRaises(check.Invalid):
                self.metrics()
            self.setUp()

    def test_cross_host_reports_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            local, allocation = Path(directory)/"local.json", Path(directory)/"allocation.json"
            self.allocation["arch"] = "aarch64"
            local.write_text(json.dumps(self.local)); allocation.write_text(json.dumps(self.allocation))
            with self.assertRaisesRegex(check.Invalid, "different host"):
                check.reports(local, allocation)

    def test_raw_percentile_nearest_rank_and_invalid_input(self):
        self.assertEqual(measure.distribution(list(range(1, 21)))["p95_ms"], 19)
        self.assertEqual(measure.distribution([3, 1, 2])["samples_ms"], [3, 1, 2])
        for values in ([], [float("nan")], [True], [-1]):
            with self.assertRaises(ValueError):
                measure.distribution(values)

    def test_explicit_cpu_identity_or_native_linux_model_required(self):
        self.assertEqual(record.cpu_model("fixture CPU"), "fixture CPU")
        with patch.object(record.sys, "platform", "darwin"), self.assertRaises(record.check.Invalid):
            record.cpu_model(None)

    def test_cli_distinguishes_unbudgeted_pass_exceeded_and_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {}
            for name, value in (("local", self.local), ("allocation", self.allocation)):
                path = root/(name + ".json"); path.write_text(json.dumps(value)); paths[name] = path
                self.context["report_sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
            context, budget, provenance = root/"context.json", root/"budget.json", root/"provenance.json"
            context.write_text(json.dumps(self.context)); budget.write_text(json.dumps(self.budget))
            provenance.write_text(json.dumps(self.provenance))
            base = [sys.executable, str(Path(__file__).with_name("check-resource-budgets.py")), "--local-report", str(paths["local"]), "--allocation-report", str(paths["allocation"])]
            enforcing = ["--context", str(context), "--build-provenance", str(provenance), "--budget", str(budget)]
            cases = [(0, "validated_unbudgeted", ["--validate-only"]), (0, "passed", enforcing),
                     (0, "validated_unbudgeted", ["--context", str(context), "--build-provenance", str(provenance), "--validate-only"]),
                     (2, "invalid", ["--budget", str(budget)]),
                     (2, "invalid", ["--context", str(context), "--budget", str(budget)]),
                     (2, "invalid", enforcing + ["--build-provenance", str(provenance)])]
            for code, status, extra in cases:
                result = subprocess.run(base + extra, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stdout)
                self.assertEqual(json.loads(result.stdout)["status"], status)
                if status == "passed":
                    self.assertEqual(json.loads(result.stdout)["build_provenance_sha256"], hashlib.sha256(provenance.read_bytes()).hexdigest())
                    self.assertEqual(json.loads(result.stdout)["budget_schema_version"], 2)
            self.budget["limits"][0]["maximum"] = 0
            budget.write_text(json.dumps(self.budget))
            result = subprocess.run(base + enforcing, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "budget_exceeded")
            self.local["sampling"] = None
            paths["local"].write_text(json.dumps(self.local))
            result = subprocess.run(base + ["--validate-only"], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "invalid")

    def test_v1_or_unsupported_budget_cannot_downgrade_provenance_requirement(self):
        for version in (1, 0, 3, True, "2", None):
            self.budget["schema_version"] = version
            with self.subTest(version=version), self.assertRaisesRegex(check.Invalid, "schema v2"):
                self.evaluate()
        self.budget["schema_version"] = 2
        with self.assertRaisesRegex(check.Invalid, "requires build provenance"):
            check.evaluate(self.budget, self.context, self.local, self.allocation, self.metrics())

    def test_every_provenance_field_is_required_and_unknown_fields_refuse(self):
        for field in self.provenance:
            value = copy.deepcopy(self.provenance)
            del value[field]
            with self.subTest(field=field), self.assertRaises(check.Invalid):
                check.provenance_check(value, self.context, self.local, self.allocation)
        self.provenance["other_source_revision"] = "3" * 40
        with self.assertRaisesRegex(check.Invalid, "unexpected or missing"):
            self.evaluate()

    def test_provenance_mismatches_dirty_sources_and_admission_failures_refuse(self):
        changes = {"schema_version": True, "source_revision": "3" * 40, "source_tree": "main",
                   "selected_measurement_source": "3" * 40, "run_id": "other-run",
                   "event_revision": "3" * 40, "workflow_sha": "3" * 40,
                   "source_clean_before_build": 1, "build_profile": "debug", "admission_issues": ["wrong CPU"],
                   "runner_name": "", "runner_boot_id": "0" * 36, "workload_samples": True,
                   "runner_class": {}, "rustc_verbose": "bad\x00identity", "cargo_verbose": "x" * 8193,
                   "build_manifest_sha256": {"Cargo.toml": "e" * 64},
                   "workflow_ref": "fixture/repo/.github/workflows/bench.yml@refs/heads/a@refs/heads/b"}
        for field, value in changes.items():
            original = copy.deepcopy(self.provenance)
            self.provenance[field] = value
            with self.subTest(field=field), self.assertRaises(check.Invalid):
                self.evaluate()
            self.provenance = original

    def test_consistent_new_product_source_and_workflow_revision_are_allowed(self):
        self.context["source_revision"] = "3" * 40
        for key in ("source_revision", "selected_measurement_source", "event_revision", "workflow_sha"):
            self.provenance[key] = "3" * 40
        self.provenance["source_tree"] = "4" * 40
        self.provenance["run_id"] = self.context["run_id"] = "new-product-run"
        self.provenance["workflow_ref"] = "fixture/repo/.github/workflows/bench.yml@refs/pull/99/merge"
        self.assertTrue(all(row["passed"] for row in self.evaluate()))

    def test_exact_compiler_cargo_manifests_and_workflow_path_contract_refuse_drift(self):
        for field, value in (("rustc_verbose", "NEW rustc\nhost: fixture"), ("cargo_verbose", "NEW cargo\nhost: fixture"),
                             ("build_manifest_sha256", {"Cargo.toml": "e" * 64, "Cargo.lock": "9" * 64}),
                             ("workflow_ref", "fixture/repo/.github/workflows/other.yml@refs/heads/fixture")):
            self.setUp()
            self.provenance[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(check.Invalid, "compiler/build contract differs"):
                self.evaluate()
        self.setUp()
        self.budget["build_contract"]["ambient_unchecked"] = "ignored"
        with self.assertRaises(check.Invalid):
            self.evaluate()

    def test_reference_admission_allows_frozen_source_but_refuses_partial_or_changed_expectations(self):
        self.provenance.update(reference_cohort="synthetic cohort", expected_measurement_tree=self.provenance["source_tree"],
                               expected_reference_class=copy.deepcopy(self.provenance["runner_class"]),
                               expected_build_manifest_sha256=copy.deepcopy(self.provenance["build_manifest_sha256"]),
                               event_revision="3" * 40, workflow_sha="3" * 40)
        self.assertTrue(all(row["passed"] for row in self.evaluate()))
        original = copy.deepcopy(self.provenance)
        for field, value in (("reference_cohort", None), ("expected_measurement_tree", None),
                             ("expected_measurement_tree", "4" * 40), ("expected_reference_class", {}),
                             ("expected_build_manifest_sha256", {})):
            self.provenance = copy.deepcopy(original)
            self.provenance[field] = value
            with self.subTest(field=field), self.assertRaises(check.Invalid):
                self.evaluate()

    def test_baseline_provenance_hashes_and_distinct_canonical_boots_are_required(self):
        for field, value in (("build_provenance_sha256", "missing"), ("runner_boot_id", "00000000-0000-0000-0000-000000000000"),
                             ("runner_boot_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")):
            self.setUp()
            self.budget["baseline_evidence"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(check.Invalid):
                self.evaluate()
        for field in ("build_provenance_sha256", "runner_boot_id"):
            self.setUp()
            self.budget["baseline_evidence"][1][field] = self.budget["baseline_evidence"][0][field]
            with self.subTest(field=field), self.assertRaisesRegex(check.Invalid, "duplicated baseline"):
                self.evaluate()

    def test_provenance_and_budget_contracts_reject_numeric_type_coercion(self):
        for target, field in (("provenance", "runner_class"), ("budget", "runner"), ("budget", "workload_samples")):
            self.setUp()
            value = self.provenance if target == "provenance" else self.budget
            key = "local" if field == "workload_samples" else "logical_cpus"
            value[field][key] = float(value[field][key])
            with self.subTest(target=target, field=field), self.assertRaises(check.Invalid):
                self.evaluate()
        self.setUp()
        self.budget["history_fixture"]["local"]["rows"] = 1000.0
        with self.assertRaises(check.Invalid):
            self.evaluate()

    def test_raw_allocation_growth_is_recomputed_with_an_unchanged_limit(self):
        self.assertTrue(all(row["passed"] for row in self.evaluate()))
        self.allocation["workloads"][0]["samples"][1]["counts"]["allocation_calls"] = 4
        checked = self.evaluate()
        self.assertFalse(checked[-1]["passed"])
        self.assertEqual(checked[-1]["maximum"], 3)
        self.assertEqual(checked[-1]["value"], 4)
        self.assertTrue(all(row["passed"] for row in checked[:-1]))

    def test_checked_in_candidate_stays_draft_and_cannot_enforce(self):
        path = Path(__file__).parent.parent / "docs/resource-budgets/pr250-epyc7763-v2.draft.json"
        draft, _ = check.load(path)
        self.assertEqual(draft["schema_version"], 2)
        self.assertEqual(draft["status"], "draft")
        with self.assertRaisesRegex(check.Invalid, "draft/unreviewed"):
            check.evaluate(draft, self.context, self.local, self.allocation, self.metrics(), self.provenance)

    def test_validate_only_legacy_summary_needs_no_new_provenance(self):
        for name in check.CLI + check.HTTP:
            del self.local["measurements"][name]["samples_ms"]
            if name in check.CLI:
                del self.local["measurements"][name]["subsequent"]["samples_ms"]
        metrics = self.metrics()
        self.assertFalse(metrics["local.cli_version.latency_ms.p95"]["raw_samples"])
        check.provenance_check(self.provenance, self.context, self.local, self.allocation)

    def test_provenance_file_uses_bounded_regular_nofollow_duplicate_safe_loader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = {}
            for name, value in (("local", self.local), ("allocation", self.allocation)):
                paths[name] = root / (name + ".json")
                paths[name].write_text(json.dumps(value))
                self.context["report_sha256"][name] = hashlib.sha256(paths[name].read_bytes()).hexdigest()
            context, provenance, budget = root / "context.json", root / "provenance.json", root / "budget.json"
            context.write_text(json.dumps(self.context)); budget.write_text(json.dumps(self.budget))
            command = [sys.executable, str(Path(__file__).with_name("check-resource-budgets.py")),
                       "--local-report", str(paths["local"]), "--allocation-report", str(paths["allocation"]),
                       "--context", str(context), "--build-provenance", str(provenance), "--budget", str(budget)]
            for raw in ('{"schema_version":1,"schema_version":1}', '[]', '{}', 'x' * (check.CAP + 1)):
                provenance.write_text(raw)
                result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(json.loads(result.stdout)["status"], "invalid")
            provenance.unlink()
            special = []
            if hasattr(os, "symlink"):
                special.append(lambda: provenance.symlink_to(context))
            if hasattr(os, "mkfifo"):
                special.append(lambda: os.mkfifo(provenance))
            for create in special:
                create()
                result = subprocess.run(command, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stdout)
                provenance.unlink()


if __name__ == "__main__":
    unittest.main()
