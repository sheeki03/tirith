#!/usr/bin/env python3
"""Recompute three distinct native baselines; never select/approve ceilings."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


check = module("resource_check", Path(__file__).with_name("check-resource-budgets.py"))
collector = module("resource_collector", Path(__file__).with_name("collect-native-resource-reference.py"))


def review(directories):
    check.require(3 <= len(directories) <= 20, "three to twenty retained baseline executions required")
    first, first_python, references, values = None, None, [], {r[0]: [] for r in collector.EXPERIMENTS.values()}
    for directory in directories:
        result, _ = check.load(directory / "result.json")
        check.require(result.get("status") == "baseline_collected_unbudgeted" and result.get("budget_enforced") is False,
                      "input is not a completed unbudgeted baseline")
        root = directory / "baseline"
        local, allocation, hashes, metrics = check.reports(root / "resource-local-control.json", root / "resource-allocations.json")
        context, context_sha = check.load(root / "resource-context.json")
        provenance, provenance_sha = check.load(root / "resource-build-provenance.json")
        check.context_check(context, local, allocation, hashes)
        check.provenance_check(provenance, context, local, allocation)
        check.require(context["host"]["system"] == "Darwin" and context["host"]["machine"] == "arm64" and
                      context["runner"]["label"] == "macos-15" and context["runner"]["cpu_model"] == "Apple M1 (Virtual)",
                      "baseline is outside the explicitly selected native Mac cohort")
        before, before_sha = check.load(root / "source-before.json")
        after, after_sha = check.load(root / "source-after.json")
        check.require(before == after and before_sha == after_sha, "baseline source changed")
        check.require(before.get("revision") == provenance["source_revision"] and before.get("tree") == provenance["source_tree"] and
                      before.get("producers") == context["producer_sha256"] and before.get("helper") == local["native_helper_sha256"] and
                      {p: before.get("manifests", {}).get(p) for p in ("Cargo.toml", "Cargo.lock")} == provenance["build_manifest_sha256"],
                      "baseline source snapshot differs from measured provenance")
        native, _ = check.load(directory / "native-host.json")
        check.require(native == {"boot": provenance["runner_boot_id"], "runner_name": provenance["runner_name"],
                                 "class": provenance["runner_class"]}, "native host record differs")
        build, _ = check.load(root / "build-inputs.json")
        runtime = build.get("python")
        runtime_key = collector.python_runtime_key(runtime)
        if first_python is None:
            first_python = runtime
        collector.same_python(first_python, runtime)
        check.require(build.get("source") == before and build.get("role") == "baseline" and build.get("native_host") == native and
                      build.get("build_target") == "aarch64-apple-darwin" and
                      build.get("product", {}).get("sha256") == local["binary_sha256"] and
                      build.get("allocation", {}).get("sha256") == allocation["instrumented_harness_sha256"],
                      "retained build inputs differ from measured source/images")
        check.require(provenance["reference_cohort"] is None and
                      result.get("baseline_boot") == provenance["runner_boot_id"], "baseline boot/reference role differs")
        check.require(local["schema_version"] == 2 and local["measurements"][check.CLI[0]]["n"] == 100 and
                      len(allocation["workloads"][0]["samples"]) == 100, "100-sample owned baseline required")
        contract = {"source": before, "host": context["host"], "runner": context["runner"], "python_runtime": runtime_key,
            "producer_sha256": context["producer_sha256"], "native_helper_sha256": local["native_helper_sha256"],
            "history_fixture": {"local": local["history_fixture"], "allocation": allocation["history_fixture"]},
            "build_contract": {**{k: provenance[k] for k in ("build_profile", "rustc_verbose", "cargo_verbose", "build_manifest_sha256")},
                               "workflow_path": check.workflow_path(provenance["workflow_ref"])}}
        if first is None:
            first = contract
        check.require(check.identical(contract, first), "baseline source/runner/producer/build contracts differ; separate cohorts")
        references.append({"run_id": provenance["run_id"], "context_sha256": context_sha,
            "source_revision": provenance["source_revision"], "build_profile": "release",
            "derivation": str(directory.resolve()), "build_provenance_sha256": provenance_sha,
            "runner_boot_id": provenance["runner_boot_id"]})
        for name in values:
            values[name].append(metrics[name]["value"])
    for field in ("run_id", "context_sha256", "build_provenance_sha256", "runner_boot_id"):
        check.require(len({row[field] for row in references}) == len(references), "duplicate independent baseline identity: " + field)
    return {"status": "comparable_baselines_ready_for_review", "budget_enforced": False,
            "limits_selected": False, "contract": first, "baseline_evidence": references,
            "observations": {name: {"per_run": v, "minimum": min(v), "maximum": max(v), "spread": max(v)-min(v)}
                             for name, v in values.items()},
            "limitations": ["Native runner and build facts are recorded evidence, not independent attestations.",
                            "Three boots are a structural minimum, not a claim of long-term statistical power.",
                            "Review explicit headroom and actual growth results before activating any budget."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result, code = review(args.evidence), 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        result, code = {"status": "refused", "budget_enforced": False, "error": str(error)[:2048]}, 2
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
