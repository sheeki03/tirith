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
    budget = {"schema_version": 1, "status": "reviewed", "review": "SYNTHETIC FIXTURE ONLY", "scope": "four fixture metrics",
              "host": copy.deepcopy(context["host"]), "runner": copy.deepcopy(context["runner"]), "producer_sha256": copy.deepcopy(context["producer_sha256"]),
              "history_fixture": {"local": local["history_fixture"], "allocation": allocation["history_fixture"]},
              "workload_samples": {"local": 3, "allocation": 3},
              "baseline_evidence": [{"run_id": "fixture-" + str(i), "context_sha256": str(i) * 64, "source_revision": "1" * 40,
                                     "build_profile": "release", "derivation": "Synthetic fixture; never a performance claim"} for i in range(1, 4)],
              "limits": [{"metric": name, "unit": unit, "maximum": maximum, "minimum_samples": 3,
                          "rationale": "Synthetic exact-boundary test, not a reviewed product threshold"} for name, unit, maximum in [
                              ("local.cli_version.latency_ms.p95", "ms", 3), ("local.cli_version.cpu_ms.median", "ms", 3),
                              ("local.cli_version.peak_rss_bytes.max", "bytes", 4096),
                              ("allocation.tier1_clean.allocation_calls.max", "calls", 3)]]}
    return local, allocation, context, budget


class ResourceBudgets(unittest.TestCase):
    def setUp(self):
        self.local, self.allocation, self.context, self.budget = fixtures()

    def metrics(self):
        return {**check.local_metrics(self.local), **check.allocation_metrics(self.allocation)}

    def evaluate(self):
        return check.evaluate(self.budget, self.context, self.local, self.allocation, self.metrics())

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
            context, budget = root/"context.json", root/"budget.json"
            context.write_text(json.dumps(self.context)); budget.write_text(json.dumps(self.budget))
            base = [sys.executable, str(Path(__file__).with_name("check-resource-budgets.py")), "--local-report", str(paths["local"]), "--allocation-report", str(paths["allocation"])]
            cases = [(0, "validated_unbudgeted", ["--validate-only"]), (0, "passed", ["--context", str(context), "--budget", str(budget)]),
                     (2, "invalid", ["--budget", str(budget)])]
            for code, status, extra in cases:
                result = subprocess.run(base + extra, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stdout)
                self.assertEqual(json.loads(result.stdout)["status"], status)
            self.budget["limits"][0]["maximum"] = 0
            budget.write_text(json.dumps(self.budget))
            result = subprocess.run(base + ["--context", str(context), "--budget", str(budget)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "budget_exceeded")
            self.local["sampling"] = None
            paths["local"].write_text(json.dumps(self.local))
            result = subprocess.run(base + ["--validate-only"], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(json.loads(result.stdout)["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
