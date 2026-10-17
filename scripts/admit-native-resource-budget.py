#!/usr/bin/env python3
"""Admit a reviewed native budget cohort before expensive measurement.

Admission checks compatibility, not resource use. The unchanged collector and
resource checker must subsequently measure and enforce the reviewed limits.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admit(root, admission_path, collector, check, observed):
    admission, identity = check.load(collector.tracked(root, admission_path))
    observed["admission_sha256"] = identity
    collector.keys(admission, ("schema_version", "status", "review", "budget_path",
                              "budget_sha256", "python_runtime", "tools_sha256"), "admission")
    collector.require(type(admission["schema_version"]) is int and admission["schema_version"] == 1
                      and admission["status"] == "reviewed", "native budget admission is not reviewed")
    check.text(admission["review"], "qualification review", 2048)
    check.digest(admission["budget_sha256"], "reviewed budget digest")
    tools = admission["tools_sha256"]
    expected_paths = ("scripts/collect-native-resource-reference.py", "scripts/check-resource-budgets.py",
                      "scripts/record-resource-context.py")
    collector.keys(tools, expected_paths, "measurement tools")
    observed["tools_sha256"] = {}
    for path in expected_paths:
        check.digest(tools[path], path)
        observed["tools_sha256"][path] = collector.sha(collector.tracked(root, path))
    collector.require(observed["tools_sha256"] == tools, "measurement tools changed; review compatibility")
    budget, budget_hash = check.load(collector.tracked(root, admission["budget_path"]))
    observed["budget_sha256"] = budget_hash
    collector.require(budget_hash == admission["budget_sha256"] and budget.get("status") == "reviewed",
                      "reviewed native budget changed")
    observed["host_diagnostics"] = {}
    host = collector.host_identity(observed["host_diagnostics"])
    observed["native_host"] = host
    expected_host = {**budget["host"], **{k: v for k, v in budget["runner"].items() if k != "label"}}
    collector.require(host["class"] == expected_host and
                      os.environ.get("RESOURCE_RUNNER_LABEL") == budget["runner"]["label"],
                      "runner differs from reviewed native budget; retain this refusal and review a new cohort")
    runtime = collector.python_runtime()
    observed["python_runtime"] = runtime
    collector.require(collector.python_runtime_key(runtime) == collector.python_identity(admission["python_runtime"]),
                      "Python runtime changed; review native budget compatibility")
    source = collector.snapshot(root)
    observed["source"] = source
    collector.require(source["revision"] == os.environ.get("GITHUB_SHA") == os.environ.get("GITHUB_WORKFLOW_SHA"),
                      "budget measurement must use the current workflow event source")
    collector.require(source["producers"] == budget["producer_sha256"] and
                      source["helper"] == budget["native_helper_sha256"],
                      "measurement producer or native helper changed; review compatibility")
    observed["build"] = {
        "build_profile": "release", "rustc_verbose": collector.command("rustc", "-Vv"),
        "cargo_verbose": collector.command("cargo", "-Vv"),
        "build_manifest_sha256": {p: source["manifests"][p] for p in ("Cargo.toml", "Cargo.lock")},
        "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"],
    }
    check.build_contract_check(budget["build_contract"], observed["build"])


def confirm_collection(directory, prior_path, observed, collector, check):
    prior, _ = check.load(prior_path)
    collector.require(prior.get("status") == "compatible_for_measurement" and prior.get("budget_enforced") is False,
                      "successful prior admission required")
    collector.require(prior["observed"] == observed, "admission facts changed during measurement")
    inputs, _ = check.load(directory / "build-inputs.json")
    collector.require(inputs["source"] == observed["source"] and inputs["role"] == "baseline",
                      "collected source differs from admitted event source")
    collector.require(inputs["native_host"] == observed["native_host"],
                      "collected native boot or host differs from admission")
    collector.same_python(inputs["python"], observed["python_runtime"])
    before, _ = check.load(directory / "source-before.json")
    after, _ = check.load(directory / "source-after.json")
    collector.require(before == after == observed["source"], "collected source changed during measurement")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--admission", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--collected", type=Path, help="Confirm retained collector facts after measurement")
    parser.add_argument("--prior", type=Path, help="Successful admission record from before measurement")
    args = parser.parse_args()
    if bool(args.collected) != bool(args.prior):
        parser.error("--collected and --prior must be supplied together")
    root = args.source.resolve(strict=True)
    result = {"status": "refused", "budget_enforced": False, "observed": {}}
    code = 2
    try:
        if root != args.source or not args.output.is_absolute() or args.output.exists():
            raise ValueError("canonical source and fresh absolute output required")
        collector = load_module("native_collector", root / "scripts/collect-native-resource-reference.py")
        check = load_module("native_checker", root / "scripts/check-resource-budgets.py")
        admit(root, args.admission, collector, check, result["observed"])
        if args.collected:
            confirm_collection(args.collected, args.prior, result["observed"], collector, check)
        result["status"] = "compatible_measurement" if args.collected else "compatible_for_measurement"
        code = 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)[:2048]
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
