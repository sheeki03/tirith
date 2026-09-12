#!/usr/bin/env python3
"""Validate bounded resource reports, or enforce explicitly reviewed limits.

Validation is not a budget pass. JSON exit statuses: 0 validated_unbudgeted/pass,
1 budget_exceeded, 2 invalid input. No benchmark, network, or executable is run.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import stat
import sys

CAP = 1024 * 1024
CLI = ("cli_version", "quick_status", "local_policy", "ordinary_check", "effective_policy", "profile_preview")
HTTP = ("service_policy", "service_health", "recent_operations", "aggregate_incremental")
CORE = ("tier1_clean", "analysis_clean", "analysis_url_pipeline", "output_obfuscated", "analysis_custom_policy", "history_recent_100")
COUNTS = ("allocation_calls", "zeroed_allocation_calls", "reallocation_calls", "deallocation_calls", "requested_bytes")
SHA = re.compile(r"[0-9a-f]{64}\Z")
REV = re.compile(r"[0-9a-f]{40}\Z")


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def number(value, label, integer=False, positive=False):
    require(type(value) in ((int,) if integer else (int, float)), label + ": expected number")
    require(0 <= value <= 2**63 - 1 and math.isfinite(value), label + ": invalid numeric value")
    require(not positive or value > 0, label + ": expected positive value")
    return value


def text(value, label, maximum=256):
    require(type(value) is str and 0 < len(value) <= maximum and all(ord(c) >= 32 for c in value), label + ": invalid text")
    return value


def digest(value, label):
    require(type(value) is str and SHA.fullmatch(value), label + ": expected SHA-256")
    return value


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label + ": unexpected or missing fields")


def unique_object(pairs):
    value = {}
    for key, entry in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = entry
    return value


def finite_float(value):
    parsed = float(value)
    require(math.isfinite(parsed), "nonfinite JSON number")
    return parsed


def load(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "JSON input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        held = os.fstat(fd)
        require(stat.S_ISREG(held.st_mode) and (held.st_dev, held.st_ino) == (before.st_dev, before.st_ino),
                "JSON input changed or is not a regular file")
        require(0 < held.st_size <= CAP, "JSON file exceeds size bound or is empty")
        raw = bytearray()
        while len(raw) <= CAP:
            block = os.read(fd, min(65536, CAP + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        raw = bytes(raw)
    finally:
        os.close(fd)
    require(0 < len(raw) <= CAP, "JSON file exceeds size bound or is empty")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_float=finite_float,
                           parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite JSON constant")))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid JSON document") from error
    require(type(value) is dict, "JSON root must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def quantile(values, q):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * q) - 1)]


def same(a, b):
    return math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-9)


def metric(out, name, values, unit, raw=True):
    require(values, name + ": empty samples")
    out[name + ".median"] = {"value": statistics.median(values), "n": len(values), "unit": unit, "raw_samples": raw}
    out[name + ".p95"] = {"value": quantile(values, .95), "n": len(values), "unit": unit, "raw_samples": raw}
    out[name + ".max"] = {"value": max(values), "n": len(values), "unit": unit, "raw_samples": raw}


def distribution(row, label, out, minimum=3):
    require(type(row) is dict, label + ": missing distribution")
    n = number(row.get("n"), label + ".n", integer=True)
    require(minimum <= n <= 100, label + ": invalid sample count")
    fields = ("min_ms", "median_ms", "p95_ms", "max_ms")
    values = [number(row.get(field), label + "." + field) for field in fields]
    require(values == sorted(values), label + ": inconsistent distribution ordering")
    raw = row.get("samples_ms")
    if "samples_ms" in row:
        require(type(raw) is list and len(raw) == n, label + ": raw sample count mismatch")
        for value in raw:
            number(value, label + ": sample")
        expected = (min(raw), statistics.median(raw), quantile(raw, .95), max(raw))
        require(all(same(a, b) for a, b in zip(values, expected)), label + ": summary differs from raw samples")
        metric(out, label + ".latency_ms", raw, "ms")
    else:
        # Historical reports can be inventoried, but cannot enforce latency
        # budgets without independent recomputation from retained samples.
        for suffix, field in (("median", "median_ms"), ("p95", "p95_ms"), ("max", "max_ms")):
            out[label + ".latency_ms." + suffix] = {"value": row[field], "n": n, "unit": "ms", "raw_samples": False}
    return n


def resources(row, n, label, out):
    samples = row.get("resources")
    require(type(samples) is list and len(samples) == n, label + ": resource sample count mismatch")
    for sample in samples:
        keys(sample, ("availability", "cpu_user_ms", "cpu_system_ms", "peak_rss_bytes"), label + ": resources")
        require(sample["availability"] == "available", label + ": resources unavailable")
        number(sample["cpu_user_ms"], label + ": user CPU")
        number(sample["cpu_system_ms"], label + ": system CPU")
        number(sample["peak_rss_bytes"], label + ": RSS", integer=True, positive=True)
    metric(out, label + ".cpu_ms", [s["cpu_user_ms"] + s["cpu_system_ms"] for s in samples], "ms")
    metric(out, label + ".peak_rss_bytes", [s["peak_rss_bytes"] for s in samples], "bytes")


def local_metrics(report):
    require(report.get("schema_version") == 1 and type(report.get("schema_version")) is int, "local: unsupported schema")
    require(report.get("measurement_kind") == "local_candidate_characterization", "local: wrong measurement kind")
    require(report.get("binary_unchanged_during_run") is True, "local: binary changed or identity unavailable")
    digest(report.get("binary_sha256"), "local binary")
    digest(report.get("harness_sha256"), "local measurement source")
    host = report.get("host")
    keys(host, ("system", "release", "machine"), "host")
    for key in host:
        text(host[key], "host." + key)
    require(host["system"] in ("Linux", "Darwin"), "local: native resource accounting unsupported on host")
    sampling = report.get("sampling", {})
    require(sampling.get("unit") == "one subprocess or HTTP request" and sampling.get("order") == "serial"
            and sampling.get("cold_cache_claim") is False, "local: measurement contract changed")
    require(report.get("resource_method", {}).get("source") == "RUSAGE_CHILDREN in one fresh wrapper per command"
            and report["resource_method"].get("wrapper_startup_included") is False, "local: unsupported resource method")
    fixture = report.get("history_fixture", {})
    rows = number(fixture.get("rows"), "local history rows", integer=True)
    require(1000 <= rows <= 500000, "local: history fixture outside supported range")
    number(fixture.get("bytes"), "local history bytes", integer=True, positive=True)
    bounds = report.get("bounds", {})
    require(bounds == {"history_page_bytes": 2097152, "history_records_requested": 100,
                       "response_bytes": 524288, "assertions_passed": True}
            and bounds.get("assertions_passed") is True, "local: coverage checks absent or changed")
    measurements = report.get("measurements")
    keys(measurements, (*CLI, *HTTP, "service_launch"), "local workloads")
    out, counts = {}, []
    for name in CLI + HTTP:
        row = measurements[name]
        n = distribution(row, "local." + name, out)
        counts.append(n)
        if name in CLI:
            resources(row, n, "local." + name, out)
            first = number(row.get("first_ms"), name + ": first sample")
            require(row["min_ms"] <= first <= row["max_ms"], name + ": first sample outside range")
            subsequent = row.get("subsequent")
            require(distribution(subsequent, "local." + name + ".subsequent", out, 2) == n - 1, name + ": subsequent count mismatch")
            require(("samples_ms" in row) == ("samples_ms" in subsequent),
                    name + ": mixed historical and raw sample distributions")
            if "samples_ms" in row:
                require(same(first, row["samples_ms"][0]) and subsequent.get("samples_ms") == row["samples_ms"][1:], name + ": first/subsequent sample mismatch")
        else:
            size = number(row.get("max_response_bytes"), name + ": response size", integer=True, positive=True)
            require(size <= 524288, name + ": oversized response")
    require(len(set(counts)) == 1, "local: inconsistent workload sample counts")
    if "baseline" in report:
        baseline = report["baseline"]
        require(type(baseline) is dict and baseline.get("binary_unchanged_during_run") is True, "baseline: changed or missing executable identity")
        digest(baseline.get("binary_sha256"), "baseline executable")
        keys(baseline.get("measurements"), CLI[:4], "baseline workloads")
        keys(baseline.get("comparison"), CLI[:4], "baseline comparisons")
        argv = (["--version"], ["doctor", "--quick", "--json"], ["policy", "effective", "--json"],
                ["check", "--shell", "posix", "--", "echo fixture"])
        for name, expected_argv in zip(CLI[:4], argv):
            row, comparison = baseline["measurements"][name], baseline["comparison"][name]
            n = distribution(row, "baseline." + name, {}, 3)
            require(n == counts[0], "baseline: unpaired sample count")
            resources(row, n, "baseline." + name, {})
            require(comparison.get("same_argv") == expected_argv and comparison.get("same_fixture") is True,
                    "baseline: comparison workload differs")
            ratio = number(comparison.get("candidate_to_baseline_median_ratio"), "baseline ratio")
            require(row["median_ms"] > 0 and same(ratio, measurements[name]["median_ms"] / row["median_ms"]), "baseline: invalid ratio")
    launch = measurements["service_launch"]
    number(launch.get("ms"), "launch latency")
    metric(out, "local.service_launch.latency_ms", [launch["ms"]], "ms")
    resources(launch, 1, "local.service_launch", out)
    service = report.get("service_resources", {})
    require(service.get("availability") == "available" and service.get("errors") == [], "service: unavailable or incomplete sampling")
    require(service.get("nominal_interval_ms") == 250 and service.get("sample_limit") == 4800, "service: sampling contract changed")
    samples = service.get("samples")
    require(type(samples) is list and 2 <= len(samples) <= 4800, "service: invalid sample count")
    previous_time, previous_cpu = -1, -1
    for row in samples:
        keys(row, ("elapsed_ms", "rss_bytes", "cpu_ms"), "service sample")
        elapsed = number(row["elapsed_ms"], "service sample time")
        cpu = number(row["cpu_ms"], "service CPU")
        number(row["rss_bytes"], "service RSS", integer=True, positive=True)
        require(elapsed > previous_time and cpu >= previous_cpu, "service: regressed time or CPU counter")
        previous_time, previous_cpu = elapsed, cpu
    maximum = max(s["rss_bytes"] for s in samples)
    cpu = samples[-1]["cpu_ms"] - samples[0]["cpu_ms"]
    require(number(service.get("sampled_max_rss_bytes"), "service reported RSS", integer=True) == maximum
            and same(number(service.get("cpu_observed_ms"), "service reported CPU"), cpu), "service: aggregate mismatch")
    # A sampled service maximum is not a kernel/process-tree peak. Keep names distinct.
    out["service.sampled_max_rss_bytes"] = {"value": maximum, "n": len(samples), "unit": "bytes", "raw_samples": True}
    out["service.cpu_observed_ms"] = {"value": cpu, "n": len(samples), "unit": "ms", "raw_samples": True}
    return out


def allocation_metrics(report):
    require(report.get("schema_version") == 1 and type(report.get("schema_version")) is int, "allocations: unsupported schema")
    require(report.get("measurement_kind") == "instrumented_core_thread_allocations", "allocations: wrong measurement kind")
    digest(report.get("instrumented_harness_sha256"), "allocation executable")
    require(report.get("os") in ("linux", "macos") and report.get("arch") in ("x86_64", "aarch64"), "allocations: unsupported host")
    method = report.get("method", {})
    require(method.get("allocator") == "System with thread-local counters" and method.get("cold_cache_claim") is False, "allocations: unsupported method")
    fixture = report.get("history_fixture", {})
    require(fixture.get("rows") == 10000, "allocations: history fixture changed")
    number(fixture.get("bytes"), "allocation history bytes", integer=True, positive=True)
    rows = report.get("workloads")
    require(type(rows) is list and len(rows) == len(CORE), "allocations: missing/extra workloads")
    require(all(type(row) is dict and row.get("name") in CORE for row in rows)
            and len({row["name"] for row in rows}) == len(CORE), "allocations: unknown/duplicate workload")
    out, sizes = {}, []
    for row in rows:
        name = "allocation." + row["name"]
        samples = row.get("samples")
        require(type(samples) is list and 3 <= len(samples) <= 100, name + ": invalid sample count")
        sizes.append(len(samples))
        for sample in samples:
            keys(sample, ("elapsed_ns", "counts"), name + ": sample")
            number(sample["elapsed_ns"], name + ": duration", integer=True)
            keys(sample["counts"], COUNTS, name + ": counts")
            for field in COUNTS:
                number(sample["counts"][field], name + ": " + field, integer=True)
        times = [s["elapsed_ns"] for s in samples]
        # Historical producer p50 is the upper-middle element, not arithmetic median.
        require(number(row.get("p50_ns"), name + ": reported p50", integer=True) == sorted(times)[len(times)//2]
                and number(row.get("p95_ns"), name + ": reported p95", integer=True) == quantile(times, .95), name + ": timing summary mismatch")
        metric(out, name + ".instrumented_ns", times, "ns")
        for field in COUNTS:
            metric(out, name + "." + field, [s["counts"][field] for s in samples], "bytes" if field == "requested_bytes" else "calls")
            metric(out, name + ".subsequent." + field, [s["counts"][field] for s in samples[1:]], "bytes" if field == "requested_bytes" else "calls")
    require(len(set(sizes)) == 1, "allocations: inconsistent workload sample counts")
    return out


def reports(local_path, allocation_path):
    local, local_hash = load(local_path)
    allocation, allocation_hash = load(allocation_path)
    metrics = {**local_metrics(local), **allocation_metrics(allocation)}
    os_name = {"Linux": "linux", "Darwin": "macos"}[local["host"]["system"]]
    arch = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64", "AMD64": "x86_64"}.get(local["host"]["machine"])
    require((os_name, arch) == (allocation["os"], allocation["arch"]), "reports describe different host architectures")
    return local, allocation, {"local": local_hash, "allocation": allocation_hash}, metrics


def context_check(context, local, allocation, hashes):
    keys(context, ("schema_version", "source_revision", "build_profile", "run_id", "host", "runner", "producer_sha256", "report_sha256", "executable_sha256"), "context")
    require(type(context["schema_version"]) is int and context["schema_version"] == 1, "context: unsupported schema")
    require(type(context["source_revision"]) is str and REV.fullmatch(context["source_revision"]), "context: invalid source revision")
    require(context["build_profile"] == "release", "context: release-profile evidence required")
    text(context["run_id"], "context run ID")
    require(context["host"] == local["host"], "context host does not match measurements")
    runner = context["runner"]
    keys(runner, ("label", "image", "image_version", "cpu_model", "logical_cpus"), "runner")
    for key in ("label", "image", "image_version", "cpu_model"):
        text(runner[key], "runner." + key)
    require(1 <= number(runner["logical_cpus"], "logical CPUs", integer=True) <= 4096, "invalid CPU count")
    keys(context["producer_sha256"], ("local", "allocation"), "producer hashes")
    for key, value in context["producer_sha256"].items():
        digest(value, key + " producer")
    require(context["producer_sha256"]["local"] == local["harness_sha256"], "local producer hash mismatch")
    require(context["report_sha256"] == hashes, "context report hashes do not match")
    require(context["executable_sha256"] == {"local": local["binary_sha256"], "allocation": allocation["instrumented_harness_sha256"]}, "context executable identities do not match")


def evaluate(budget, context, local, allocation, metrics):
    keys(budget, ("schema_version", "status", "review", "scope", "host", "runner", "producer_sha256", "history_fixture", "workload_samples", "baseline_evidence", "limits"), "budget")
    require(type(budget["schema_version"]) is int and budget["schema_version"] == 1, "budget: unsupported schema")
    require(budget["status"] == "reviewed", "budget: draft/unreviewed limits cannot be enforced")
    text(budget["review"], "budget review reference", 2048)
    text(budget["scope"], "budget scope", 2048)
    require(budget["host"] == context["host"] and budget["runner"] == context["runner"], "budget: runner/host class differs")
    require(budget["producer_sha256"] == context["producer_sha256"], "budget: measurement producer changed; review compatibility")
    require(budget["history_fixture"] == {"local": local["history_fixture"], "allocation": allocation["history_fixture"]}, "budget: workload fixture differs")
    require(budget["workload_samples"] == {"local": local["measurements"][CLI[0]]["n"],
                                          "allocation": len(allocation["workloads"][0]["samples"])}, "budget: measured workload sizes differ")
    evidence = budget["baseline_evidence"]
    require(type(evidence) is list and 3 <= len(evidence) <= 100, "budget: at least three pinned independent baseline runs required")
    run_ids, contexts = set(), set()
    for row in evidence:
        keys(row, ("run_id", "context_sha256", "source_revision", "build_profile", "derivation"), "baseline evidence")
        text(row["run_id"], "baseline run ID")
        digest(row["context_sha256"], "baseline context")
        require(type(row["source_revision"]) is str and REV.fullmatch(row["source_revision"]), "baseline: invalid source revision")
        require(row["build_profile"] == "release", "baseline: debug evidence cannot set release budgets")
        text(row["derivation"], "baseline derivation reference", 2048)
        run_ids.add(row["run_id"]); contexts.add(row["context_sha256"])
    require(len(run_ids) == len(evidence) == len(contexts), "budget: duplicated baseline runs")
    limits = budget["limits"]
    require(type(limits) is list and 1 <= len(limits) <= 512, "budget: empty/oversized limits")
    checked, seen = [], set()
    for rule in limits:
        keys(rule, ("metric", "unit", "maximum", "minimum_samples", "rationale"), "budget limit")
        name = rule["metric"]
        require(type(name) is str and name in metrics and name not in seen, "budget: unknown, missing or repeated metric")
        seen.add(name)
        observed = metrics[name]
        require(observed["raw_samples"], name + ": historical summary lacks retained raw samples")
        require(rule["unit"] == observed["unit"], name + ": unit mismatch")
        maximum = number(rule["maximum"], name + ": maximum")
        minimum = number(rule["minimum_samples"], name + ": minimum samples", integer=True, positive=True)
        require(minimum <= observed["n"], name + ": insufficient samples")
        text(rule["rationale"], "budget rationale", 2048)
        checked.append({"metric": name, **observed, "maximum": maximum, "passed": observed["value"] <= maximum})
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-report", required=True, type=Path)
    parser.add_argument("--allocation-report", required=True, type=Path)
    parser.add_argument("--context", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--budget", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        local, allocation, hashes, metrics = reports(args.local_report, args.allocation_report)
        context = None
        if args.context:
            context, context_hash = load(args.context)
            context_check(context, local, allocation, hashes)
        result = {"schema_version": 1, "report_sha256": hashes, "host": local["host"],
                  "scope": "selected measured workloads only; not full WP17 or native qualification", "metrics": metrics}
        if args.validate_only:
            result.update(status="validated_unbudgeted", budget_enforced=False,
                          context_verified=context is not None,
                          limitations=["Historical latency summaries without raw samples are ineligible for budgets.",
                                       "Producer context records provenance; it is not a signature or independent attestation."])
            code = 0
        else:
            require(context is not None, "budget evaluation requires pinned release measurement context")
            budget, budget_hash = load(args.budget)
            checked = evaluate(budget, context, local, allocation, metrics)
            passed = all(row["passed"] for row in checked)
            result.update(status="passed" if passed else "budget_exceeded", budget_enforced=True,
                          context_sha256=context_hash, budget_sha256=budget_hash,
                          checked=checked, unbudgeted_metric_count=len(metrics)-len(checked))
            code = 0 if passed else 1
    except (Invalid, OSError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as error:
        result, code = {"schema_version": 1, "status": "invalid", "budget_enforced": False,
                        "error": str(error)[:2048]}, 2
    rendered = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
