#!/usr/bin/env python3
"""Measure a supplied candidate in isolated operator/project roots.

These measurements characterize this machine and these exact bytes. They do not
stand in for installed-package/native matrix certification or prove SLOs on other
hardware. The history fixture exceeds the old dashboard's read cap without
modifying any real audit log. Only ordinary read/preview routes are measured.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request


def http(origin, token, csrf, path, body=None):
    headers = {"Authorization": "Bearer " + token}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers.update({"Origin": origin, "X-Tirith-CSRF": csrf, "Content-Type": "application/json"})
    req = urllib.request.Request(origin + path, data=payload, headers=headers)
    start = time.perf_counter()
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=40) as response:
        data = response.read(524289)
        assert len(data) <= 524288, "response exceeded service ceiling"
    return json.loads(data), (time.perf_counter() - start) * 1000, len(data)


def distribution(samples):
    values = sorted(samples)
    return {"n": len(values), "min_ms": values[0], "median_ms": statistics.median(values),
            "p95_ms": values[min(len(values) - 1, int(len(values) * .95))], "max_ms": values[-1]}


def run(binary, output, samples, history_rows, baseline=None):
    assert 3 <= samples <= 100
    assert 1000 <= history_rows <= 500000
    report = {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "measurement_kind": "local_candidate_characterization", "measurements": {}, "bounds": {},
              "qualification": "not_native_release_matrix_or_universal_slo",
              "sampling": {"unit": "one subprocess or HTTP request", "order": "serial",
                           "cold_cache_claim": False,
                           "first_sample": "first invocation in this fixture; OS caches are not cleared",
                           "contention": "ambient host activity is not controlled"}}
    if baseline is not None:
        report["baseline"] = {"binary_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                              "measurements": {}, "comparison": {}}
    with tempfile.TemporaryDirectory(prefix="tirith-perf-fixture-") as raw:
        root = Path(raw).resolve()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("TIRITH_") and key not in {"SUDO_USER", "SUDO_UID", "SUDO_GID"}}
        roots = {"HOME": "home", "USERPROFILE": "home", "XDG_CONFIG_HOME": "home/.config",
                 "XDG_CONFIG_DIRS": "config-dirs", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
                 "XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "runtime", "APPDATA": "appdata",
                 "LOCALAPPDATA": "local-appdata", "TMPDIR": "temp", "TMP": "temp", "TEMP": "temp"}
        for name, suffix in roots.items():
            directory = root / suffix
            directory.mkdir(parents=True, exist_ok=True)
            env[name] = str(directory)
        env.update({"TIRITH_OFFLINE": "1", "TIRITH_THREATDB_PATH": str(root / "missing-db"),
                    "TIRITH_THREATDB_SUPPLEMENTAL_PATH": str(root / "missing-extra-db")})
        cwd = root / "project"
        (cwd / ".git").mkdir(parents=True)
        config = root / "home/.config/tirith"
        config.mkdir(parents=True)
        (config / "policy.yml").write_text("paranoia: 2\n")
        audit = root / "data/tirith/log.jsonl"
        audit.parent.mkdir(parents=True)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {"timestamp": now, "entry_type": "verdict", "action": "WarnAck",
                  "command_redacted": "echo " + "fixture" * 28, "rule_ids": ["curl_pipe_shell"],
                  "bypass_requested": False, "bypass_honored": False}
        line = json.dumps(record) + "\n"
        with audit.open("w") as file:
            for _ in range(history_rows):
                file.write(line)
        report["history_fixture"] = {"rows": history_rows, "bytes": audit.stat().st_size}

        def cli(args, executable=binary):
            start = time.perf_counter()
            result = subprocess.run([str(executable), *args], cwd=cwd, env=env, capture_output=True, timeout=45)
            assert result.returncode == 0, (args, result.stderr.decode(errors="replace"))
            return result.stdout, (time.perf_counter() - start) * 1000

        common = [("cli_version", ["--version"]), ("quick_status", ["doctor", "--quick", "--json"]),
                  ("local_policy", ["policy", "effective", "--json"]),
                  ("ordinary_check", ["check", "--shell", "posix", "--", "echo fixture"])]
        candidate_only = [("effective_policy", ["policy", "effective", "--runtime", "--json"]),
                          ("profile_preview", ["policy", "profile", "balanced", "--dry-run", "--json"])]
        for name, args in common + candidate_only:
            timings = []
            baseline_timings = []
            for index in range(samples):
                # Alternate the order to reduce systematic advantage from warmed
                # filesystem caches; this is still a serial local comparison.
                if baseline is not None and (name, args) in common and index % 2 == 0:
                    _, elapsed = cli(args, baseline)
                    baseline_timings.append(elapsed)
                _, elapsed = cli(args)
                timings.append(elapsed)
                if baseline is not None and (name, args) in common and index % 2 == 1:
                    _, elapsed = cli(args, baseline)
                    baseline_timings.append(elapsed)
            report["measurements"][name] = {**distribution(timings), "first_ms": timings[0],
                                             "subsequent": distribution(timings[1:])}
            if baseline_timings:
                prior = distribution(baseline_timings)
                report["baseline"]["measurements"][name] = {**prior, "first_ms": baseline_timings[0],
                                                             "subsequent": distribution(baseline_timings[1:])}
                report["baseline"]["comparison"][name] = {
                    "candidate_to_baseline_median_ratio": statistics.median(timings) / prior["median_ms"],
                    "same_argv": args, "same_fixture": True, "regression_budget_enforced": False}
        launched, launch_ms = cli(["dashboard", "--no-browser", "--json"])
        launch = json.loads(launched)
        parsed = urllib.parse.urlsplit(launch["url"])
        origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        token = urllib.parse.parse_qs(parsed.fragment)["token"][0]
        session, _, _ = http(origin, token, "", "/api/session")
        csrf = session["csrf"]
        report["measurements"]["service_launch"] = {"ms": launch_ms}
        try:
            for name, route, body in [("service_policy", "/api/policy", None), ("service_health", "/api/state", None),
                                      ("recent_operations", "/api/jobs", None), ("aggregate_incremental", "/api/activity/summary", None)]:
                timings, sizes = [], []
                for _ in range(samples):
                    value, elapsed, size = http(origin, token, csrf, route, body)
                    timings.append(elapsed); sizes.append(size)
                    if name == "aggregate_incremental":
                        assert value["inspected_bytes_this_refresh"] <= 2 * 1024 * 1024
                        assert value["earlier_history_uninspected"] == (report["history_fixture"]["bytes"] > 2 * 1024 * 1024), "history coverage does not match fixture size"
                report["measurements"][name] = {**distribution(timings), "max_response_bytes": max(sizes)}
            cursor = None
            for _ in range(samples):
                page, _, _ = http(origin, token, csrf, "/api/history", {"cursor": cursor, "limit": 100, "filter": {}})
                assert len(page["events"]) <= 100 and page["inspected_bytes"] <= 2 * 1024 * 1024
                cursor = page["next_cursor"]
            report["bounds"] = {"history_page_bytes": 2 * 1024 * 1024, "history_records_requested": 100,
                                "response_bytes": 512 * 1024, "assertions_passed": True}
        finally:
            try:
                http(origin, token, csrf, "/api/quiesce", {})
            finally:
                time.sleep(1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--history-rows", type=int, default=250000)
    parser.add_argument("--baseline", type=Path, help="Optional earlier release for identical CLI comparisons")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.output.resolve(), args.samples, args.history_rows,
        args.baseline.resolve(strict=True) if args.baseline else None)
