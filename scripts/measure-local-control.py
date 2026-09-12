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
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
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
    if not samples or any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in samples):
        raise ValueError("timing samples must be nonempty, finite and nonnegative")
    values = sorted(samples)
    return {"n": len(values), "min_ms": values[0], "median_ms": statistics.median(values),
            "p95_ms": values[math.ceil(len(values) * .95) - 1], "max_ms": values[-1],
            "samples_ms": list(samples)}


def resource_child(report_path, command):
    """One fresh wrapper gives getrusage an independent completed-child sample.

    The measured interval excludes this Python interpreter's startup. Kernel RSS
    is the largest completed child, not a sum of concurrent process-tree memory.
    Live detached descendants (such as the dashboard) are outside this sample.
    """
    try:
        import resource
    except ImportError:
        resource = None
    before = resource.getrusage(resource.RUSAGE_CHILDREN) if resource else None
    started = time.perf_counter()
    result = subprocess.run(command, capture_output=True, timeout=45)
    metrics = {"elapsed_ms": (time.perf_counter() - started) * 1000,
               "availability": "available" if resource else "unsupported"}
    if resource:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        metrics.update({"cpu_user_ms": (after.ru_utime - before.ru_utime) * 1000,
                        "cpu_system_ms": (after.ru_stime - before.ru_stime) * 1000,
                        "peak_rss_bytes": int(after.ru_maxrss * (1 if sys.platform == "darwin" else 1024))})
    Path(report_path).write_text(json.dumps(metrics) + "\n")
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode



def parse_process_sample(text, pid):
    fields = text.split()
    if len(fields) != 8 or fields[0] != str(pid):
        raise ValueError("unexpected process sample")
    elapsed = fields[7]
    days, elapsed = elapsed.split("-", 1) if "-" in elapsed else ("0", elapsed)
    clock = elapsed.split(":")
    if len(clock) not in (2, 3):
        raise ValueError("unexpected process CPU time")
    hours, minutes, seconds = ("0", *clock) if len(clock) == 2 else clock
    days, hours, minutes, seconds = int(days), int(hours), int(minutes), float(seconds)
    rss = int(fields[6]) * 1024
    if min(days, hours, minutes, seconds, rss) < 0 or minutes >= 60 or not seconds < 60:
        raise ValueError("invalid process accounting")
    return {"start_identity": " ".join(fields[1:6]), "rss_bytes": rss,
            "cpu_ms": ((days * 24 + hours) * 3600 + minutes * 60 + seconds) * 1000}


class ServiceSampler:
    """Observe only the new fixture service; sampled RSS is not an exact peak.

    The private record routes to a PID, and ps start time detects PID changes.
    No credentials, executable arguments or operator process list are collected.
    """
    def __init__(self, record_path, launch, binary_sha256):
        self.stop = threading.Event()
        self.samples, self.errors = [], []
        self.thread = None
        self.record_path = record_path
        self.service_id = launch["service_id"]
        self.binary_sha256 = binary_sha256
        self.pid, self.identity = None, None
        self.started = time.monotonic()
        self.availability = "available" if sys.platform in ("linux", "darwin") else "unsupported"
        if self.availability != "available":
            return
        self.sample()
        self.thread = threading.Thread(target=self.observe, daemon=True)
        self.thread.start()

    def sample(self):
        with self.record_path.open("rb") as source:
            data = source.read(16385)
        if len(data) > 16384:
            raise ValueError("fixture service record exceeds bound")
        record = json.loads(data)
        if record["service_id"] != self.service_id or record["binary_sha256"] != self.binary_sha256:
            raise ValueError("fixture service identity changed")
        pid = record["pid"]
        if type(pid) is not int or not 1 < pid < 2 ** 31 or self.pid not in (None, pid):
            raise ValueError("fixture service process changed")
        self.pid = pid
        result = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "pid=", "-o", "lstart=", "-o", "rss=", "-o", "time="],
                                env={**os.environ, "LC_ALL":"C"}, capture_output=True, text=True, timeout=2)
        if result.returncode or len(result.stdout) > 4096:
            raise ValueError("fixture service process unavailable")
        sample = parse_process_sample(result.stdout, pid)
        identity = sample.pop("start_identity")
        if self.identity not in (None, identity):
            raise ValueError("fixture service PID was reused")
        self.identity = identity
        sample["elapsed_ms"] = (time.monotonic() - self.started) * 1000
        self.samples.append(sample)

    def observe(self):
        while not self.stop.wait(.25):
            if len(self.samples) >= 4800:
                self.errors.append("sample_limit_reached")
                return
            try:
                self.sample()
            except Exception as error:
                self.errors.append(type(error).__name__)
                return

    def finish(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                self.errors.append("sampler_stop_timeout")
        if self.availability == "available" and not self.errors:
            if len(self.samples) < 4800:
                self.sample()
            else:
                self.errors.append("sample_limit_reached")
        report = {"availability":self.availability, "source":"ps for fixture PID with unchanged start time and private service record",
                  "nominal_interval_ms":250, "sample_limit":4800, "samples":self.samples, "errors":self.errors,
                  "scope":"service only between launch response and quiesce; excludes startup and children",
                  "identity_precision":"ps lstart has one-second resolution; this fixture check is not a process security boundary",
                  "memory":"sampled RSS maximum is a lower bound, not a kernel peak or process-tree total",
                  "cpu":"delta of cumulative ps CPU time; limited by platform display precision"}
        if self.samples:
            delta = self.samples[-1]["cpu_ms"] - self.samples[0]["cpu_ms"]
            if delta < 0:
                self.errors.append("cpu_counter_regressed")
            report.update(sampled_max_rss_bytes=max(x["rss_bytes"] for x in self.samples),
                          cpu_observed_ms=delta if delta >= 0 else None)
        return report


def fixture_storage(root):
    """Count regular-file bytes in only this private, bounded fixture tree."""
    import stat
    total, files = 0, 0
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs[:] = [name for name in subdirs if not (Path(directory) / name).is_symlink()]
        for name in names:
            metadata = (Path(directory) / name).lstat()
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
                files += 1
                if files > 20000:
                    raise AssertionError("fixture storage measurement exceeded its file bound")
    return {"regular_file_bytes": total, "regular_files": files}


def run(binary, output, samples, history_rows, baseline=None, resources=False):
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
    if resources:
        report["resource_method"] = {
            "source": "RUSAGE_CHILDREN in one fresh wrapper per command",
            "wrapper_startup_included": False,
            "peak_memory": "kernel maximum for completed children; not simultaneous process-tree total",
            "detached_service_resources": "separate bounded PID/start-time sampling",
            "allocations": "not_measured",
            "resource_samples": "same measured commands; baseline and candidate alternate as above"}
    if baseline is not None:
        report["baseline"] = {"binary_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                              "measurements": {}, "comparison": {}}
    with tempfile.TemporaryDirectory(prefix="tirith-perf-fixture-") as raw:
        root = Path(raw).resolve()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("TIRITH_") and key not in {"TIRITH", "SUDO_USER", "SUDO_UID", "SUDO_GID"}}
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

        resource_samples = {}
        storage_before = fixture_storage(root)

        def cli(args, executable=binary, role="candidate"):
            command = [str(executable), *args]
            metrics_path = root / "resource-sample.json"
            if resources:
                command = [sys.executable, str(Path(__file__).resolve()), "--resource-child", str(metrics_path), *command]
            start = time.perf_counter()
            result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=60 if resources else 45)
            elapsed = (time.perf_counter() - start) * 1000
            assert result.returncode == 0, (args, result.stderr.decode(errors="replace"))
            if resources:
                metrics = json.loads(metrics_path.read_text())
                metrics_path.unlink()
                elapsed = metrics.pop("elapsed_ms")
                resource_samples.setdefault((role, tuple(args)), []).append(metrics)
            return result.stdout, elapsed

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
                    _, elapsed = cli(args, baseline, role="baseline")
                    baseline_timings.append(elapsed)
                _, elapsed = cli(args)
                timings.append(elapsed)
                if baseline is not None and (name, args) in common and index % 2 == 1:
                    _, elapsed = cli(args, baseline, role="baseline")
                    baseline_timings.append(elapsed)
            report["measurements"][name] = {**distribution(timings), "first_ms": timings[0],
                                             "subsequent": distribution(timings[1:])}
            if resources:
                report["measurements"][name]["resources"] = resource_samples[("candidate", tuple(args))]
            if baseline_timings:
                prior = distribution(baseline_timings)
                report["baseline"]["measurements"][name] = {**prior, "first_ms": baseline_timings[0],
                                                             "subsequent": distribution(baseline_timings[1:])}
                if resources:
                    report["baseline"]["measurements"][name]["resources"] = resource_samples[("baseline", tuple(args))]
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
        if resources:
            report["measurements"]["service_launch"]["resources"] = resource_samples[("candidate", ("dashboard", "--no-browser", "--json"))]
        service_sampler = None
        try:
            if resources:
                service_sampler = ServiceSampler(root / "state/tirith/control/v1/service.json", launch, report["binary_sha256"])
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
                if service_sampler is not None:
                    report["service_resources"] = service_sampler.finish()
            finally:
                try:
                    http(origin, token, csrf, "/api/quiesce", {})
                finally:
                    time.sleep(1)
        if resources and report.get("service_resources", {}).get("errors"):
            raise AssertionError("service resource sampling failed: " + str(report["service_resources"]["errors"]))
        storage_after = fixture_storage(root)
        report["fixture_storage"] = {"before": storage_before, "after": storage_after,
                                     "growth_bytes": storage_after["regular_file_bytes"] - storage_before["regular_file_bytes"],
                                     "scope": "all fixture runs combined, including baseline when selected; live user data excluded"}
    report["binary_unchanged_during_run"] = hashlib.sha256(binary.read_bytes()).hexdigest() == report["binary_sha256"]
    assert report["binary_unchanged_during_run"], "candidate bytes changed during measurement"
    if baseline is not None:
        report["baseline"]["binary_unchanged_during_run"] = hashlib.sha256(baseline.read_bytes()).hexdigest() == report["baseline"]["binary_sha256"]
        assert report["baseline"]["binary_unchanged_during_run"], "baseline bytes changed during measurement"
    report["harness_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "--resource-child":
        raise SystemExit(resource_child(sys.argv[2], sys.argv[3:]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--history-rows", type=int, default=250000)
    parser.add_argument("--baseline", type=Path, help="Optional earlier release for identical CLI comparisons")
    parser.add_argument("--resources", action="store_true", help="Measure per-command CPU and peak RSS with isolated native child accounting")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True), args.output.resolve(), args.samples, args.history_rows,
        args.baseline.resolve(strict=True) if args.baseline else None, args.resources)
