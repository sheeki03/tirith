#!/usr/bin/env python3
"""Measure a supplied candidate in isolated operator/project roots.

These measurements characterize this machine and these exact bytes. They do not
stand in for installed-package/native matrix certification or prove SLOs on other
hardware. The history fixture exceeds the old dashboard's read cap without
modifying any real audit log. Only ordinary read/preview routes are measured.
"""
if not __debug__:
    raise RuntimeError("resource measurement requires Python without -O/PYTHONOPTIMIZE")

import argparse
from contextlib import contextmanager
import importlib.util
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid


def http(origin, token, csrf, path, body=None, timeout=40):
    headers = {"Authorization": "Bearer " + token}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers.update({"Origin": origin, "X-Tirith-CSRF": csrf, "Content-Type": "application/json"})
    req = urllib.request.Request(origin + path, data=payload, headers=headers)
    start = time.perf_counter()
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as response:
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


NATIVE_PATH = Path(__file__).resolve().parents[1] / "tools/qualification/mixed_audit_native.py"
CLEANUP_FIELDS = ("leader_reaped", "group_signaled_or_absent", "group_members_exited", "output_eof")
SERVICE_DEADLINE_SECONDS = 1200


def load_native():
    before = hashlib.sha256(NATIVE_PATH.read_bytes()).hexdigest()
    spec = importlib.util.spec_from_file_location("resource_owned_native", NATIVE_PATH)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    if hashlib.sha256(NATIVE_PATH.read_bytes()).hexdigest() != before:
        raise RuntimeError("native helper changed while loading")
    native.require_process_observation()
    return native, before


def require_unused_service_alarm():
    if threading.current_thread() is not threading.main_thread() or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise RuntimeError("service deadline requires an unused main-thread alarm")


@contextmanager
def service_deadline(seconds=SERVICE_DEADLINE_SECONDS):
    # Arm only after native.Job has returned and its retained handle is stored.
    # This alarm interrupts the producer, whose finally block cleans that child.
    require_unused_service_alarm()
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise TimeoutError("owned service measurement deadline expired")
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate service record field")
        result[key] = value
    return result


def read_discovery(path, job, startup_id, binary_sha256, project):
    # The private record routes HTTP only. Ownership comes from Job's retained
    # waitable direct child, never from a PID or timestamp found in this file.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1):
            raise ValueError("unsafe fixture service record")
        body = source.read(16385)
    if not body or len(body) > 16384:
        raise ValueError("fixture service record exceeds bound or is empty")
    record = json.loads(body, object_pairs_hook=unique_object)
    if not (type(record) is dict and type(record.get("protocol")) is int and record["protocol"] == 1
            and type(record.get("pid")) is int and record["pid"] == job.process.pid
            and record.get("startup_id") == startup_id and record.get("binary_sha256") == binary_sha256
            and record.get("cwd") == str(project)):
        raise ValueError("fixture service identity changed")
    service_id = record.get("service_id")
    if type(service_id) is not str or str(uuid.UUID(service_id)) != service_id or uuid.UUID(service_id).int == 0:
        raise ValueError("invalid fixture service identity")
    if type(record.get("port")) is not int or not 0 < record["port"] < 65536:
        raise ValueError("invalid fixture service port")
    token = record.get("token")
    if type(token) is not str or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
        raise ValueError("invalid fixture service credential")
    if job.process.poll() is not None:
        raise ValueError("owned service exited before discovery validation")
    return record


def verify_launch(launch, record):
    expected = f"http://127.0.0.1:{record['port']}/#token={record['token']}"
    if not (type(launch) is dict and launch.get("kind") == "dashboard_launch"
            and launch.get("service_id") == record["service_id"] and launch.get("url") == expected
            and launch.get("browser_opened") is False and launch.get("protection_changed") is False):
        raise ValueError("public launcher did not reuse the owned service")


class OwnedService:
    def __init__(self, native, binary, binary_sha256, root, project, env):
        self.native, self.binary, self.binary_sha256 = native, binary, binary_sha256
        self.root, self.project, self.env = root, project, env
        self.path = root / "state/tirith/control/v1/service.json"
        self.startup_id = str(uuid.uuid4())
        self.job = self.record = self.authentication = None
        self.identity_validated = self.launcher_reused = self.quiesce_acknowledged = False

    def spawn(self):
        # Job/Popen construction has no interruptible timeout in the shared
        # helper. Do not introduce our alarm into its handle-acquisition window.
        require_unused_service_alarm()
        self.startup_started = time.perf_counter()
        self.startup_deadline = time.monotonic() + 12
        self.job = self.native.Job("resource-control-serve",
            [str(self.binary), "dashboard", "control-serve", "--startup-id", self.startup_id],
            self.project, self.env, timeout=SERVICE_DEADLINE_SECONDS + 20)

    def start(self):
        if self.job is None:
            raise RuntimeError("owned service handle is missing")
        for stream in (self.job.process.stdout, self.job.process.stderr):
            os.set_blocking(stream.fileno(), False)
        while time.monotonic() < self.startup_deadline:
            self.drain()
            if self.job.process.poll() is not None:
                raise RuntimeError("owned control service exited during startup")
            try:
                self.record = read_discovery(self.path, self.job, self.startup_id, self.binary_sha256, self.project)
                break
            except FileNotFoundError:
                time.sleep(.025)
        if self.record is None:
            raise TimeoutError("owned control service did not publish discovery")
        self.identity_validated = True
        origin = f"http://127.0.0.1:{self.record['port']}"
        self.authentication = (origin, self.record["token"], None)
        session, _, _ = http(origin, self.record["token"], "", "/api/session")
        if type(session) is not dict or type(session.get("csrf")) is not str or not session["csrf"]:
            raise ValueError("owned service session is invalid")
        self.authentication = (origin, self.record["token"], session["csrf"])
        self.verify()
        return (time.perf_counter() - self.startup_started) * 1000

    def drain(self):
        # Sampling drains bounded output but never signals. Native finish owns
        # all termination/reaping, after the sampler has joined.
        for name in ("stdout", "stderr"):
            stream = getattr(self.job.process, name)
            while True:
                try:
                    block = os.read(stream.fileno(), 16384)
                except BlockingIOError:
                    break
                if not block:
                    break
                room = self.native.OUTPUT_LIMIT - len(self.job.output[name])
                self.job.output[name].extend(block[:room])
                if len(block) > room:
                    self.job.failure = self.job.failure or "output-limit"
                    raise RuntimeError("owned service output exceeded bound")

    def verify(self):
        self.drain()
        if read_discovery(self.path, self.job, self.startup_id, self.binary_sha256, self.project) != self.record:
            raise ValueError("owned service discovery changed")

    def finish(self, report):
        if self.job is None:
            return
        try:
            if self.job.process.poll() is not None:
                raise RuntimeError("owned service exited before requested quiesce")
            if not self.authentication:
                raise RuntimeError("startup failed before service authentication")
            origin, token, csrf = self.authentication
            if csrf is None:
                session, _, _ = http(origin, token, "", "/api/session", timeout=3)
                csrf = session["csrf"]
            response, _, _ = http(origin, token, csrf, "/api/quiesce", {}, timeout=3)
            if response.get("state") != "draining" or response.get("new_mutations_accepted") is not False:
                raise ValueError("owned service did not acknowledge quiesce")
            self.quiesce_acknowledged = True
        except BaseException as error:
            report["shutdown_error"] = type(error).__name__
            self.job.failure = self.job.failure or "service-quiesce"
            self.job.kill()
        finally:
            self.job.timeout = min(self.job.timeout, time.monotonic() - self.job.started + 12)
            try:
                self.native.finish([self.job])
            finally:
                row = self.job.result()
                # Child diagnostics and authentication responses are deliberately
                # not persisted, including on malformed startup/launch responses.
                report["owned_service"] = {key: row[key] for key in
                    ("name", "pid", "exit", "failure", "cleanup", "group_observation", "elapsed_seconds")}
                report["owned_service"].update(identity_validated=self.identity_validated,
                    launcher_reused=self.launcher_reused, quiesce_acknowledged=self.quiesce_acknowledged,
                    startup_id=self.startup_id, service_id=self.record.get("service_id") if self.record else None,
                    binary_sha256=self.binary_sha256)
        row = report["owned_service"]
        if row["exit"] != 0 or row["failure"] is not None or any(row["cleanup"].get(key) is not True for key in CLEANUP_FIELDS):
            raise RuntimeError("owned service did not exit and clean up successfully")
        if not all((self.identity_validated, self.launcher_reused, self.quiesce_acknowledged)):
            raise RuntimeError("owned service lifecycle is incomplete")


class ServiceSampler:
    """Observe only the new fixture service; sampled RSS is not an exact peak.

    PID ownership comes from the retained direct child; private discovery and ps
    start time are consistency checks. No sampled PID ever authorizes signals.
    """
    def __init__(self, owner):
        self.stop = threading.Event()
        self.samples, self.errors = [], []
        self.thread = None
        self.owner = owner
        self.pid, self.identity = owner.job.process.pid, None
        self.started = time.monotonic()
        self.availability = "available" if sys.platform in ("linux", "darwin") else "unsupported"
        if self.availability != "available":
            return
        self.owner.verify()
        self.sample()
        self.thread = threading.Thread(target=self.observe, daemon=True)
        self.thread.start()

    def sample(self):
        # The observer thread reads only ps for the retained PID. It never
        # touches Job/pipes, so failed joining cannot race native cleanup.
        pid = self.pid
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
        joined = self.thread is None or not self.thread.is_alive()
        if self.availability == "available" and not self.errors:
            if len(self.samples) < 4800:
                self.owner.verify()
                self.sample()
            else:
                self.errors.append("sample_limit_reached")
        report = {"availability":self.availability, "sampler_joined": joined,
                  "source":"ps for retained unreaped direct child; discovery checked before and after sampling",
                  "nominal_interval_ms":250, "sample_limit":4800, "samples":self.samples, "errors":self.errors,
                  "scope":"owned service only after launcher reuse and before quiesce; excludes startup and children",
                  "identity_precision":"ps lstart has one-second resolution; signal authority is the retained unreaped native child",
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
    producer_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    native, native_hash = load_native()
    require_unused_service_alarm()
    assert 3 <= samples <= 100
    assert 1000 <= history_rows <= 500000
    report = {"schema_version": 2, "native_helper_sha256": native_hash, "status": "running", "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
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
            "owned_service_resources": "separate retained-child sampling and native exit/cleanup observation",
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
        owner = OwnedService(native, binary, report["binary_sha256"], root, cwd, env)
        service_sampler = None
        try:
            try:
                owner.spawn()
                with service_deadline():
                    direct_ms = owner.start()
                    report["measurements"]["service_direct_start"] = {
                        "ms": direct_ms, "scope": "owned direct spawn through validated discovery and authenticated session"}
                    # Required reuse cannot spawn a detached replacement if
                    # the retained service exits between discovery and launch.
                    reuse_args = ["dashboard", "--no-browser", "--json", "--require-service-id", owner.record["service_id"]]
                    launched, reuse_ms = cli(reuse_args)
                    verify_launch(json.loads(launched), owner.record)
                    owner.verify()
                    owner.launcher_reused = True
                    origin, token, csrf = owner.authentication
                    report["measurements"]["service_launcher_reuse"] = {
                        "ms": reuse_ms, "scope": "public launcher reuse of the already running owned service"}
                    if resources:
                        report["measurements"]["service_launcher_reuse"]["resources"] = resource_samples[("candidate", tuple(reuse_args))]
                        service_sampler = ServiceSampler(owner)
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
                    owner.finish(report)
            if resources and report.get("service_resources", {}).get("errors"):
                raise RuntimeError("owned service resource sampling failed")
        except BaseException as error:
            report["status"] = "failed"
            report["failure"] = type(error).__name__
            write_report(report, output, binary, baseline, native_hash, producer_hash)
            raise RuntimeError("owned service measurement failed; bounded report retained") from None
        storage_after = fixture_storage(root)
        report["fixture_storage"] = {"before": storage_before, "after": storage_after,
                                     "growth_bytes": storage_after["regular_file_bytes"] - storage_before["regular_file_bytes"],
                                     "scope": "all fixture runs combined, including baseline when selected; live user data excluded"}
    report["status"] = "completed"
    write_report(report, output, binary, baseline, native_hash, producer_hash)


def write_report(report, output, binary, baseline, native_hash, producer_hash):
    report["binary_unchanged_during_run"] = hashlib.sha256(binary.read_bytes()).hexdigest() == report["binary_sha256"]
    report["native_helper_unchanged_during_run"] = hashlib.sha256(NATIVE_PATH.read_bytes()).hexdigest() == native_hash
    report["harness_sha256"] = producer_hash
    report["harness_unchanged_during_run"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == producer_hash
    if baseline is not None:
        report["baseline"]["binary_unchanged_during_run"] = hashlib.sha256(baseline.read_bytes()).hexdigest() == report["baseline"]["binary_sha256"]
    if not report["binary_unchanged_during_run"] or not report["native_helper_unchanged_during_run"] or not report["harness_unchanged_during_run"] or (baseline is not None and not report["baseline"]["binary_unchanged_during_run"]):
        report["status"] = "failed"
        report["failure"] = "measurement_input_changed"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    if report["status"] != "completed":
        raise RuntimeError("resource measurement incomplete; bounded report retained") from None


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
