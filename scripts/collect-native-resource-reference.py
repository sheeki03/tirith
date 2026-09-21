#!/usr/bin/env python3
"""Explicit native macOS ARM reference collection; never chooses/rebases budgets.

Baseline measures the workflow event source once. A growth run builds two exact
reviewed commits on this same boot. Measurements use the unchanged producers.
Compilation caches are permitted; neither recorded facts nor a clean tree are
independent build/host attestations. Failures remain failures and are retained.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import uuid

MIB = 1024 * 1024
EXPERIMENTS = {
    "clean_first": ("allocation.analysis_clean.requested_bytes.max", 33554432, "first", "crates/tirith-core/src/engine.rs"),
    "clean_subsequent": ("allocation.analysis_clean.subsequent.requested_bytes.max", 32768, "subsequent", "crates/tirith-core/src/engine.rs"),
    "url_first": ("allocation.analysis_url_pipeline.requested_bytes.max", 33554432, "first", "crates/tirith-core/src/engine.rs"),
    "url_subsequent": ("allocation.analysis_url_pipeline.subsequent.requested_bytes.max", 524288, "subsequent", "crates/tirith-core/src/engine.rs"),
    "history_requests": ("allocation.history_recent_100.requested_bytes.max", 4194304, "every", "crates/tirith-core/src/history.rs"),
    "ordinary_rss": ("local.ordinary_check.peak_rss_bytes.max", 16777216, "every", "crates/tirith/src/cli/check.rs"),
}
PRODUCERS = {"local": "scripts/measure-local-control.py",
             "allocation": "crates/tirith-core/benches/resource_counts.rs"}
HELPER = "tools/qualification/mixed_audit_native.py"
CHECKER = "scripts/check-resource-budgets.py"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        while part := source.read(MIB):
            h.update(part)
    return h.hexdigest()


def write(path, value):
    with Path(path).open("x") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def command(*argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=60).strip()


def git(root, *argv):
    return command("git", "-C", str(root), *argv)


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label + ": unknown/missing fields")


def immutable(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value), "immutable revision required")
    return value


def tracked(root, relative):
    require(type(relative) is str and re.fullmatch(r"[A-Za-z0-9_./-]+", relative), "invalid tracked path")
    p = Path(relative)
    require(not p.is_absolute() and ".." not in p.parts and p.parts, "path escapes source")
    full = root / p
    require(full.is_file() and not full.is_symlink() and full.resolve() == full, "tracked file aliases/refuses")
    require(git(root, "ls-files", "--", relative) == relative, "input is not tracked")
    return full


def host_identity(observed=None):
    # Refusal diagnostics are observations only, never an admitted native host.
    # Populate before each check so a failed admission retains the actual fact
    # that failed. Facts not reached (such as boot after CPU refusal) stay absent.
    if observed is None:
        observed = {}
    observed.update(system=platform.system(), release=platform.release(), machine=platform.machine(),
                    image=os.environ.get("ImageOS"), image_version=os.environ.get("ImageVersion"),
                    runner_name=os.environ.get("RUNNER_NAME"), logical_cpus=os.cpu_count(),
                    python_version=sys.version, python_optimize=sys.flags.optimize,
                    python_optimize_env=bool(os.environ.get("PYTHONOPTIMIZE")))
    require(sys.version_info >= (3, 11) and sys.flags.optimize == 0 and not os.environ.get("PYTHONOPTIMIZE"),
            "native producer needs Python3.11+ with assertions enabled")
    require(observed["system"] == "Darwin" and observed["machine"] == "arm64", "native Darwin ARM64 required")
    cpu = command("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string")
    observed["cpu_model"] = cpu
    require(cpu == "Apple M1 (Virtual)", "runner differs from the explicitly selected Apple M1 (Virtual) platform")
    observed["boot_raw"] = command("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid")
    boot = str(uuid.UUID(observed["boot_raw"]))
    require(uuid.UUID(boot).int != 0, "native boot UUID is zero")
    image, image_version = observed["image"], observed["image_version"]
    require(image and image_version, "native runner image identity is unavailable")
    return {"boot": boot, "runner_name": os.environ["RUNNER_NAME"],
            "class": {"system": "Darwin", "release": observed["release"], "machine": "arm64",
                      "image": image, "image_version": image_version,
                      "cpu_model": cpu, "logical_cpus": observed["logical_cpus"]}}


def same_host(before, after):
    require(before == after, "native boot/runner class changed during this collection")


def python_runtime():
    executable = Path(sys.executable).resolve(strict=True)
    return {"version": sys.version, "executable": str(executable), "sha256": sha(executable)}


def python_identity(value):
    keys(value, ("version", "sha256"), "Python identity")
    require(type(value["version"]) is str and 0 < len(value["version"]) <= 2048,
            "Python runtime version is missing or oversized")
    require(type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
            "Python executable digest is invalid")
    return value


def python_runtime_key(value):
    keys(value, ("version", "executable", "sha256"), "Python runtime")
    require(type(value["executable"]) is str and Path(value["executable"]).is_absolute(),
            "Python executable must have its resolved absolute path recorded")
    # Installation paths can differ across independent native jobs. Exact
    # runtime bytes and version must match; a path is not a runtime identity.
    return python_identity({"version": value["version"], "sha256": value["sha256"]})


def same_python(before, after):
    require(python_runtime_key(before) == python_runtime_key(after),
            "Python runtime version or executable bytes differ")


def snapshot(root):
    require(not git(root, "status", "--porcelain", "--untracked-files=no"), "tracked source is not clean")
    paths = git(root, "ls-files").splitlines()
    require(len(paths) <= 16384, "source inventory exceeds cap")
    manifests = [p for p in paths if Path(p).name in ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml")
                 or p.startswith(".cargo/")]
    return {"revision": git(root, "rev-parse", "HEAD"), "tree": git(root, "rev-parse", "HEAD^{tree}"),
            "manifests": {p: sha(tracked(root, p)) for p in manifests},
            "producers": {k: sha(tracked(root, p)) for k, p in PRODUCERS.items()},
            "helper": sha(tracked(root, HELPER)), "checker": sha(tracked(root, CHECKER))}


def invoke(argv, cwd, env, output, name, timeout):
    # The existing producer retains product/service lifecycle authority. This
    # wrapper owns only the direct tool process group; it does not certify an
    # arbitrary compiler descendant tree after timeout or external interruption.
    with (output / (name + ".stdout")).open("xb") as stdout, (output / (name + ".stderr")).open("xb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=15)
            raise ValueError(name + ": timeout; retained failure, no native cleanup claim")
    require(code == 0, name + ": unsuccessful exit " + str(code))
    require((output / (name + ".stdout")).stat().st_size <= 16 * MIB and
            (output / (name + ".stderr")).stat().st_size <= 16 * MIB, name + ": retained tool output exceeds cap")


def executable(output, name, root, target_name, kind):
    rows = [json.loads(line) for line in (output / (name + ".stdout")).read_text().splitlines() if line.strip()]
    require(rows and rows[-1].get("reason") == "build-finished" and rows[-1].get("success") is True,
            "Cargo did not retain successful completion")
    selected = [r for r in rows if r.get("reason") == "compiler-artifact" and r.get("executable")
                and r.get("target", {}).get("name") == target_name and r["target"].get("kind") == [kind]]
    require(len(selected) == 1, "ambiguous Cargo executable")
    row = selected[0]
    package = root / ("crates/tirith" if kind == "bin" else "crates/tirith-core")
    require(row.get("manifest_path") == str(package / "Cargo.toml") and
            row.get("package_id") == "path+" + package.as_uri() + "#0.4.2", "Cargo package source differs")
    src = package / ("src/main.rs" if kind == "bin" else "benches/resource_counts.rs")
    require(row["target"].get("src_path") == str(src), "Cargo target source differs")
    require(row.get("profile", {}).get("opt_level") == "3" and
            row["profile"].get("debug_assertions") is False, "release profile required")
    require(kind != "bin" or row["profile"].get("test") is False, "test harness cannot be the release product")
    path = Path(row["executable"])
    require(path.is_file() and not path.is_symlink(), "Cargo executable is missing or aliased")
    return path, row


def read_protocol(root, path, experiment, check):
    value, identity = check.load(tracked(root, path))
    keys(value, ("schema_version", "status", "review", "cohort", "base_revision", "base_tree", "budget_path",
                 "budget_sha256", "checker_sha256", "python_runtime", "experiments"), "protocol")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["status"] == "reviewed",
            "growth protocol must be explicitly reviewed")
    check.text(value["review"], "protocol review", 2048)
    check.text(value["cohort"], "protocol cohort")
    python_identity(value["python_runtime"])
    immutable(value["base_revision"]); immutable(value["base_tree"])
    require(git(root, "rev-parse", value["base_revision"] + "^{tree}") == value["base_tree"], "base tree differs")
    require(sha(tracked(root, CHECKER)) == value["checker_sha256"], "checker differs from reviewed protocol")
    budget, budget_hash = check.load(tracked(root, value["budget_path"]))
    require(budget_hash == value["budget_sha256"] and budget.get("status") == "reviewed", "reviewed budget differs")
    baselines = budget.get("baseline_evidence")
    require(type(baselines) is list and 3 <= len(baselines) <= 100 and
            all(type(row) is dict and row.get("source_revision") == value["base_revision"] for row in baselines),
            "every reviewed baseline must bind the protocol base revision and its verified Git tree")
    require(type(budget.get("limits")) is list and len(budget["limits"]) == len(EXPERIMENTS) and
            {r.get("metric") for r in budget["limits"]} == {row[0] for row in EXPERIMENTS.values()} and
            all(r.get("unit") == "bytes" for r in budget["limits"]), "reviewed budget must cover the exact six byte metrics")
    require(type(value["experiments"]) is dict and experiment in value["experiments"], "experiment is not reviewed")
    pair = value["experiments"][experiment]
    keys(pair, ("control", "growth"), "experiment pair")
    product_path = EXPERIMENTS[experiment][3]
    for role, entry in pair.items():
        keys(entry, ("revision", "tree", "source_sha256"), role)
        immutable(entry["revision"]); immutable(entry["tree"]); check.digest(entry["source_sha256"], role + " source")
        require(git(root, "rev-parse", entry["revision"] + "^{tree}") == entry["tree"], role + ": source tree differs")
        require(git(root, "diff", "--name-only", "--no-renames", value["base_revision"], entry["revision"], "--").splitlines()
                == [product_path], role + ": changed files exceed the reviewed mutation")
        raw = subprocess.check_output(["git", "-C", str(root), "show", entry["revision"] + ":" + product_path], timeout=60)
        require(hashlib.sha256(raw).hexdigest() == entry["source_sha256"], role + ": mutation differs")
    require(pair["control"]["revision"] != pair["growth"]["revision"], "control and growth source are identical")
    return value, identity, budget


def collect(root, output, role, revision, host, check, protocol=None, budget=None):
    output.mkdir()
    runtime = python_runtime()
    python_runtime_key(runtime)
    before = snapshot(root)
    require(before["revision"] == revision, "source differs from selected revision")
    rustc, cargo = command("rustc", "-Vv"), command("cargo", "-Vv")
    require("release: 1.98.1" in rustc.splitlines() and "host: aarch64-apple-darwin" in rustc.splitlines(),
            "pinned native Rust toolchain required")
    reference = protocol is not None
    if reference:
        require(python_runtime_key(runtime) == python_identity(protocol["python_runtime"]),
                "Python runtime differs from reviewed baseline cohort")
        require(before["producers"] == budget["producer_sha256"] and before["helper"] == budget["native_helper_sha256"],
                "measurement producer/helper changed")
        require(before["checker"] == protocol["checker_sha256"], "mutant checker changed")
    provenance = {"schema_version": 1, "source_revision": revision, "source_tree": before["tree"],
        "selected_measurement_source": revision, "expected_measurement_tree": before["tree"] if reference else None,
        "event_revision": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"] + "/" + os.environ["GITHUB_RUN_ATTEMPT"],
        "workflow_ref": os.environ["GITHUB_WORKFLOW_REF"], "workflow_sha": os.environ["GITHUB_WORKFLOW_SHA"],
        "runner_name": host["runner_name"], "runner_boot_id": host["boot"], "runner_class": host["class"],
        "expected_reference_class": {**budget["host"], **{k: v for k, v in budget["runner"].items() if k != "label"}} if reference else None,
        "source_clean_before_build": True, "rustc_verbose": rustc, "cargo_verbose": cargo, "build_profile": "release",
        "build_manifest_sha256": {p: before["manifests"][p] for p in ("Cargo.toml", "Cargo.lock")},
        "expected_build_manifest_sha256": budget["build_contract"]["build_manifest_sha256"] if reference else None,
        "reference_cohort": protocol["cohort"] if reference else None, "workload_samples": 100, "admission_issues": []}
    issues = provenance["admission_issues"]
    if not reference and revision != os.environ["GITHUB_SHA"]:
        issues.append("baseline must measure the workflow event source")
    if reference:
        if host["class"] != provenance["expected_reference_class"]:
            issues.append("runner differs from explicitly reviewed new cohort")
        if provenance["build_manifest_sha256"] != provenance["expected_build_manifest_sha256"]:
            issues.append("build manifests differ from reviewed cohort")
        try:
            check.build_contract_check(budget["build_contract"], provenance)
        except ValueError as error:
            issues.append(str(error))
    write(output / "resource-build-provenance.json", provenance)
    write(output / "source-before.json", before)
    require(not issues, "; ".join(issues))
    env = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(name, None)
    env["CARGO_TARGET_DIR"] = str(output.parent.parent / "build-target")
    env["CARGO_BUILD_TARGET"] = "aarch64-apple-darwin"
    invoke(["cargo", "build", "--locked", "--release", "-p", "tirith", "--bin", "tirith", "--message-format=json"],
           root, env, output, "cargo-product", 3600)
    product, product_record = executable(output, "cargo-product", root, "tirith", "bin")
    invoke(["cargo", "bench", "--locked", "-p", "tirith-core", "--bench", "resource_counts", "--no-run", "--message-format=json"],
           root, env, output, "cargo-allocation", 3600)
    allocation, allocation_record = executable(output, "cargo-allocation", root, "resource_counts", "bench")
    require(snapshot(root) == before, "source changed during compilation")
    same_host(host, host_identity())
    write(output / "build-inputs.json", {"source": before, "role": role, "native_host": host,
        "python": runtime,
        "product": {"sha256": sha(product), "cargo_artifact": product_record},
        "allocation": {"sha256": sha(allocation), "cargo_artifact": allocation_record},
        "build_target": env["CARGO_BUILD_TARGET"], "ambient_rust_flags_removed": True})
    invoke([str(allocation), "--output", str(output / "resource-allocations.json"), "--samples", "100"],
           root, env, output, "allocation-measurement", 1200)
    invoke([sys.executable, "-B", str(root / PRODUCERS["local"]), "--binary", str(product), "--output",
            str(output / "resource-local-control.json"), "--resources", "--samples", "100", "--history-rows", "250000"],
           root, env, output, "local-measurement", 1500)
    same_host(host, host_identity())
    after = snapshot(root)
    same_python(runtime, python_runtime())
    require(after == before, "source changed during measurements")
    invoke([sys.executable, "-B", str(root / "scripts/record-resource-context.py"), "--local-report", str(output / "resource-local-control.json"),
            "--allocation-report", str(output / "resource-allocations.json"), "--local-source", str(root / PRODUCERS["local"]),
            "--allocation-source", str(root / PRODUCERS["allocation"]), "--source-revision", revision, "--build-profile", "release",
            "--run-id", provenance["run_id"], "--runner-label", os.environ["RESOURCE_RUNNER_LABEL"], "--runner-image", host["class"]["image"],
            "--runner-image-version", host["class"]["image_version"], "--cpu-model", host["class"]["cpu_model"],
            "--output", str(output / "resource-context.json")], root, env, output, "context", 60)
    local, alloc, hashes, metrics = check.reports(output / "resource-local-control.json", output / "resource-allocations.json")
    context, context_hash = check.load(output / "resource-context.json")
    check.context_check(context, local, alloc, hashes); check.provenance_check(provenance, context, local, alloc)
    require(local["binary_sha256"] == sha(product) and alloc["instrumented_harness_sha256"] == sha(allocation),
            "measured executable differs from Cargo output")
    write(output / "source-after.json", after)
    write(output / "resource-evaluation.json", {"status": "validated_unbudgeted", "budget_enforced": False,
        "context_sha256": context_hash, "build_provenance_sha256": sha(output / "resource-build-provenance.json"),
        "report_sha256": hashes, "metrics": metrics})
    same_python(runtime, python_runtime())
    return {"local": local, "allocation": alloc, "context": context, "provenance": provenance, "metrics": metrics, "python": runtime}


def qualify(experiment, pair, budget, check):
    import statistics
    metric, dose, window, _ = EXPERIMENTS[experiment]
    a, b = pair["control"], pair["growth"]
    for key in ("runner_boot_id", "runner_name", "runner_class", "run_id", "event_revision", "workflow_sha", "rustc_verbose", "cargo_verbose"):
        require(a["provenance"][key] == b["provenance"][key], "pair native/build identity differs: " + key)
    same_python(a["python"], b["python"])
    checked = {role: check.evaluate(budget, r["context"], r["local"], r["allocation"], r["metrics"], r["provenance"])
               for role, r in pair.items()}
    require(all(r["passed"] for r in checked["control"]), "zero-dose control exceeds a reviewed ceiling")
    require([r["metric"] for r in checked["growth"] if not r["passed"]] == [metric], "growth must exceed exactly its selected ceiling")
    relevant = "local" if experiment == "ordinary_rss" else "allocation"
    require(a["context"]["executable_sha256"][relevant] != b["context"]["executable_sha256"][relevant], "same executable reused for both roles")
    deltas = []
    if experiment == "ordinary_rss":
        before = [r["peak_rss_bytes"] for r in a["local"]["measurements"]["ordinary_check"]["resources"]]
        after = [r["peak_rss_bytes"] for r in b["local"]["measurements"]["ordinary_check"]["resources"]]
        ceiling = next(r["maximum"] for r in budget["limits"] if r["metric"] == metric)
        require(len(before) == len(after) == 100 and min(after) > ceiling, "100 sustained RSS growth observations required")
        deltas = [y-x for x, y in zip(before, after)]
        require(statistics.median(deltas) >= dose * 3 // 4, "RSS median increase is below predeclared 75 percent dose")
    else:
        before = {r["name"]: r["samples"] for r in a["allocation"]["workloads"]}
        after = {r["name"]: r["samples"] for r in b["allocation"]["workloads"]}
        for workload in check.CORE:
            require(len(before[workload]) == len(after[workload]) == 100, "100 raw samples required")
            for index, (x, y) in enumerate(zip(before[workload], after[workload])):
                delta = y["counts"]["requested_bytes"] - x["counts"]["requested_bytes"]
                active = workload == metric.split(".")[1] and (window == "every" or
                         (window == "first" and index == 0) or (window == "subsequent" and index > 0))
                if active:
                    require(abs(delta-dose) <= 4096, "growth delta differs from reviewed dose")
                    require(sum(y["counts"][k]-x["counts"][k] for k in ("allocation_calls", "zeroed_allocation_calls")) >= 1,
                            "growth did not make a counted allocation")
                    deltas.append(delta)
                else:
                    require(abs(delta) <= 4096, "growth escaped the reviewed sample/workload")
    require(deltas, "no selected growth observations")
    return {"status": "detector_qualified", "budget_enforced": False, "experiment": experiment, "checked": checked,
            "delta": {"n": len(deltas), "min": min(deltas), "median": statistics.median(deltas), "max": max(deltas)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experiment", choices=("baseline", *EXPERIMENTS), required=True)
    parser.add_argument("--protocol", default="")
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    require(args.source == root and args.output.is_absolute() and not args.output.exists(), "fresh absolute output and canonical source required")
    args.output.mkdir(mode=0o700)
    evidence = args.output / "evidence"; evidence.mkdir(mode=0o700)
    result = {"status": "refused", "budget_enforced": False,
              "scope": "selected native byte workloads; not whole WP17 or release qualification"}
    observed_host = {}
    code = 2
    try:
        require(os.environ.get("RESOURCE_LEGACY_REFERENCE") == "false", "native and legacy reference modes must not be mixed")
        host = host_identity(observed_host); write(evidence / "native-host.json", host)
        require(git(root, "rev-parse", "HEAD") == os.environ["GITHUB_SHA"] == os.environ["GITHUB_WORKFLOW_SHA"],
                "controller must be the exact workflow event source")
        spec = importlib.util.spec_from_file_location("resource_check", tracked(root, CHECKER))
        check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
        shutil.copyfile(root / "scripts/collect-native-resource-reference.py", evidence / "collector.py")
        if args.experiment == "baseline":
            require(not args.protocol, "baseline collection does not admit a reference protocol")
            collect(root, evidence / "baseline", "baseline", os.environ["GITHUB_SHA"], host, check)
            result.update(status="baseline_collected_unbudgeted", baseline_boot=host["boot"])
        else:
            protocol, identity, budget = read_protocol(root, args.protocol, args.experiment, check)
            write(evidence / "reviewed-protocol.json", protocol); write(evidence / "reviewed-budget.json", budget)
            result["protocol_sha256"] = identity
            pair = {}
            for role in ("control", "growth"):
                entry = protocol["experiments"][args.experiment][role]
                checkout = args.output / (role + "-source")
                git(root, "worktree", "add", "--detach", str(checkout), entry["revision"])
                pair[role] = collect(checkout, evidence / role, role, entry["revision"], host, check, protocol, budget)
                same_host(host, host_identity())
            result.update(qualify(args.experiment, pair, budget, check))
        code = 0
    except (ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError, RecursionError, subprocess.SubprocessError) as error:
        result["error"] = str(error)[:2048]
        result["host_observation"] = {"scope": "diagnostic_only_not_admitted",
                                      "expected": {"system": "Darwin", "machine": "arm64", "cpu_model": "Apple M1 (Virtual)"},
                                      "observed": observed_host}
    write(evidence / "result.json", result)
    print(json.dumps(result, indent=2, allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
