#!/usr/bin/env python3
"""Bounded Unix standalone/direct-daemon characterization; never execute inputs.

No installation, background daemon launcher, network fetch or cache
purge. A direct socket response is required; there is no CLI fallback inference.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import resource
import selectors
import shutil
import signal
import socket
import stat
import statistics
import struct
import sys
import tempfile
import time

HELPER_SHA = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
SAMPLES = 100
DEADLINE = 900
MIB = 1024 * 1024
RESPONSE_LIMIT = 64 * 1024
FIXTURE_LIMIT = 192 * MIB
JOURNAL_LIMIT = 16 * MIB
CLEANUP_KEYS = ("leader_reaped", "group_signaled_or_absent", "group_members_exited", "output_eof")
COMMANDS = ("curl --head https://wp17-characterization.invalid", "printf '%s\\n' WP17_BLOCK")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate JSON field")
        out[key] = value
    return out


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    s = path.lstat()
    return {"dev": s.st_dev, "ino": s.st_ino, "uid": s.st_uid,
            "gid": s.st_gid, "mode": s.st_mode}


def held_bytes(path, cap, allow_empty=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        require(stat.S_ISREG(s.st_mode) and (allow_empty or s.st_size > 0) and s.st_size <= cap, "input file bound/type")
        raw = f.read(cap + 1)
        after = os.fstat(f.fileno())
        stable = lambda info: tuple(getattr(info, field) for field in (
            "st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))
        require(len(raw) == s.st_size and stable(s) == stable(after) == stable(path.lstat()),
                "input changed during bounded read")
    return raw


def remaining(deadline, cap):
    left = deadline - time.monotonic()
    require(left > 0, "overall work deadline expired")
    return min(left, cap)


def distribution(values):
    require(bool(values) and all(type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in values),
            "invalid distribution")
    ordered = sorted(values)
    return {"n": len(values), "p50_ms": statistics.median(values),
            "p95_ms": ordered[math.ceil(len(values) * .95) - 1],
            "min_ms": ordered[0], "max_ms": ordered[-1], "raw_ms": values}


def policy_bytes(count):
    require(count in (1, 256), "unreviewed policy size")
    # The daemon periodic updater discovers the user policy without a cwd.
    # Offline request flags alone do not disable that separate timer.
    text = "threat_intel:\n  auto_update_hours: 0\ncustom_rules:\n"
    for i in range(count):
        pattern = "WP17_BLOCK" if i == count - 1 else f"WP17_NEVER_{i:03d}"
        text += (f"  - id: wp17-{i:03d}\n    pattern: '{pattern}'\n"
                 f"    title: 'WP17 rule {i:03d}'\n    severity: HIGH\n    context: [exec]\n")
    raw = text.encode()
    require(len(raw) <= 64 * 1024, "policy exceeded bound")
    return raw


def semantic(value, exit_code, policy):
    require(type(value) is dict and value.get("error") is None, "analysis error")
    action = value.get("action")
    require(action in ("allow", "warn", "block", "warn_ack"), "unknown action")
    require(type(exit_code) is int and exit_code == {"allow": 0, "warn": 2, "block": 1, "warn_ack": 3}[action],
            "action/exit mismatch")
    require(value.get("bypass_honored") is False, "unexpected bypass")
    require(value.get("policy_path_used") == str(policy), "expected policy not loaded")
    require(not value.get("policy_diagnostics"), "policy diagnostics present")
    findings = value.get("findings")
    require(type(findings) is list and len(findings) <= 256, "finding bound")
    tuples = []
    for f in findings:
        require(type(f) is dict and type(f.get("rule_id")) is str
                and type(f.get("severity")) is str, "invalid finding")
        tuples.append((f["rule_id"], f["severity"], f.get("custom_rule_id")))
    require(type(value.get("tier_reached")) is int, "missing reached tier")
    return {"action": action, "exit": exit_code, "error": None,
            "findings": sorted(tuples, key=repr), "tier": value["tier_reached"],
            "urls": value.get("urls_extracted_count"), "bypass": False,
            "policy": str(policy)}


def admitted_database(value, path):
    require(type(value) is dict and value.get("installed") is True
            and value.get("signature_valid") is True and value.get("error") is None
            and value.get("path") == str(path), "product did not admit supplied database")
    for key in ("build_sequence", "build_timestamp", "total_entries"):
        require(type(value.get(key)) is int and value[key] >= 0, "missing DB identity")
    require(value["total_entries"] > 0, "empty DB cannot characterize load")
    # Preserve original age/freshness facts. auto_update_hours=0 affects the
    # product's stale boolean; it never changes the signed bytes or timestamp.
    return {k: value[k] for k in ("build_sequence", "build_timestamp", "total_entries")}


def admit_binding(binding, expected):
    require(type(binding) is dict and set(binding) == {"binary_sha256", "product_commit", "product_tree"},
            "source binding must use the exact three-field schema")
    require(binding["binary_sha256"] == expected, "source binding selects different binary")
    for key in ("product_commit", "product_tree"):
        value = binding[key]
        require(type(value) is str and len(value) == 40 and all(c in "0123456789abcdef" for c in value),
                "source binding missing exact Git identity")


def storage(root, allowed_socket=None):
    count, total, allocated = 0, 0, 0
    pending = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        require(depth <= 24, "fixture depth exceeded")
        with os.scandir(directory) as entries:
            for item in entries:
                count += 1
                require(count <= 4096, "fixture entry limit")
                s = item.stat(follow_symlinks=False)
                if stat.S_ISDIR(s.st_mode):
                    pending.append((Path(item.path), depth + 1))
                elif stat.S_ISREG(s.st_mode):
                    require(s.st_nlink == 1 and s.st_size <= 64 * MIB, "fixture file bound/link")
                    total += s.st_size
                    allocated += s.st_blocks * 512
                else:
                    require(Path(item.path) == allowed_socket and stat.S_ISSOCK(s.st_mode),
                            "unexpected fixture alias/special file")
                require(s.st_uid == os.geteuid() and total <= FIXTURE_LIMIT, "fixture ownership/size bound")
    return {"entries": count, "regular_logical_bytes": total, "regular_allocated_bytes": allocated}


class Journal:
    def __init__(self, path):
        self.path = path
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.identity = identity(path)
        self.count = self.size = 0

    def add(self, row):
        raw = (json.dumps(row, sort_keys=True, allow_nan=False) + "\n").encode()
        require(len(raw) <= 256 * 1024 and self.size + len(raw) <= JOURNAL_LIMIT, "journal byte bound")
        view = memoryview(raw)
        while view:
            n = os.write(self.fd, view)
            require(n > 0, "journal short write")
            view = view[n:]
        self.size += len(raw)
        self.count += 1

    def close(self):
        try:
            require(identity(self.path) == self.identity and os.fstat(self.fd).st_size == self.size,
                    "journal path or size changed")
        finally:
            os.close(self.fd)


class Runner:
    def __init__(self, native, binary, deadline, journal):
        self.native, self.binary, self.deadline, self.journal = native, binary, deadline, journal
        self.jobs = []

    def check_disk(self, root):
        s = os.statvfs(root)
        require(s.f_bavail * s.f_frsize >= 2 * 1024 * MIB, "free disk below 2 GiB floor")

    def cli(self, fixture, name, arguments):
        self.check_disk(fixture.root)
        storage(fixture.root)
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.monotonic()
        job = self.native.Job(name, [self.binary, *arguments], fixture.cwd, fixture.env,
                              timeout=remaining(self.deadline, 15))
        self.jobs.append(job)
        try:
            row = self.native.finish([job])[0]
        except BaseException:
            self.journal.add({"kind": "standalone-owner-failure", **job.result()})
            raise
        elapsed = (time.monotonic() - start) * 1000
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row.update(elapsed_ms=elapsed, cpu_user_ms=(after.ru_utime - before.ru_utime) * 1000,
                   cpu_system_ms=(after.ru_stime - before.ru_stime) * 1000)
        self.journal.add({"kind": "standalone", **row})
        require(row["failure"] is None and all(row["cleanup"].get(k) is True for k in CLEANUP_KEYS),
                "standalone child failed or cleanup incomplete")
        storage(fixture.root)
        remaining(self.deadline, 1)
        return decode(row["stdout"]), row


def cleanup_registered(runner):
    """Final finite cleanup after any interrupted finish, without renewed authority.

    Work stops on its first failure, so only the current CLI/observer and daemon
    can be incomplete. Never reset cleanup_attempted or signal a reaped PID.
    An interrupted prior group observation stays unproven and retains the root.
    """
    errors = []
    for job in runner.jobs:
        if job.process.reaped and all(job.cleanup.get(k) is True for k in CLEANUP_KEYS):
            continue
        if not job.cleanup_attempted:
            try:
                job.kill()
            except BaseException as error:
                errors.append({"name": job.name, "stage": "kill", "error": type(error).__name__})
        # finish may have been interrupted before it installed its pipe deadline.
        # These bounds apply even when kill is now an idempotent no-op.
        job.timeout = 0
        job.pipe_deadline = min(job.pipe_deadline or float("inf"), time.monotonic() + 2)
        try:
            runner.native.finish([job])
        except BaseException as error:
            errors.append({"name": job.name, "stage": "drain", "error": type(error).__name__})
    return errors


class Fixture:
    def __init__(self, root, count, db_raw):
        self.root = root
        self.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(root),
                    "LANG": "C", "LC_ALL": "C", "TIRITH_OFFLINE": "1", "TIRITH_LOG": "0"}
        for key, leaf in (("XDG_CONFIG_HOME", "c"), ("XDG_DATA_HOME", "d"),
                          ("XDG_STATE_HOME", "s"), ("XDG_CACHE_HOME", "k"), ("TMPDIR", "t")):
            path = root / leaf
            path.mkdir(mode=0o700)
            self.env[key] = str(path)
        self.env.update(TMP=self.env["TMPDIR"], TEMP=self.env["TMPDIR"])
        conf = root / "c/tirith"
        conf.mkdir(mode=0o700)
        self.policy = conf / "policy.yaml"
        self.policy.write_bytes(policy_bytes(count))
        self.policy.chmod(0o600)
        self.db = root / "d/primary.dat"
        self.db.write_bytes(db_raw)
        self.db.chmod(0o400)
        self.env["TIRITH_THREATDB_PATH"] = str(self.db)
        self.env["TIRITH_THREATDB_SUPPLEMENTAL_PATH"] = str(root / "d/absent.dat")
        self.project = root / "p"
        self.project.mkdir(mode=0o700)
        (self.project / ".git").mkdir(mode=0o700)
        self.cwd = self.project
        depth = 8 if count == 256 else 0
        for i in range(depth):
            self.cwd = self.cwd / f"n{i}"
            self.cwd.mkdir(mode=0o700)
        for i in range(128 if count == 256 else 1):
            (self.project / f"fixture-{i:03d}.txt").write_bytes(b"inert repository fixture\n")
        self.socket = root / "s/tirith/daemon.sock"
        self.pidfile = self.socket.with_name("daemon.pid")
        require(len(os.fsencode(self.socket)) <= 103, "Unix socket path exceeds portable bound")
        self.inputs = {str(self.policy): digest(self.policy.read_bytes()), str(self.db): digest(db_raw)}
        self.description = {"custom_rules": count, "nested_depth": depth,
                            "repository_files": 128 if count == 256 else 1,
                            "policy_sha256": self.inputs[str(self.policy)], "policy_bytes": self.policy.stat().st_size,
                            "cwd": str(self.cwd), "synthetic_git_marker": True, "environment": self.env}

    def verify(self):
        for path, expected in self.inputs.items():
            require(digest(held_bytes(Path(path), 64 * MIB)) == expected, "fixture input changed")


def socket_record(fixture, job):
    require(job.process.poll() is None, "retained daemon exited")
    parent = identity(fixture.socket.parent)
    sock = identity(fixture.socket)
    pid = identity(fixture.pidfile)
    require(stat.S_ISDIR(parent["mode"]) and stat.S_IMODE(parent["mode"]) == 0o700
            and parent["uid"] == os.geteuid(), "daemon directory identity")
    require(stat.S_ISSOCK(sock["mode"]) and stat.S_IMODE(sock["mode"]) == 0o600
            and sock["uid"] == os.geteuid(), "daemon socket identity")
    require(stat.S_ISREG(pid["mode"]) and pid["uid"] == os.geteuid()
            and pid["mode"] & 0o022 == 0, "daemon PID record identity")
    require(held_bytes(fixture.pidfile, 32) == str(job.process.pid).encode(), "daemon PID differs from owned child")
    return {"directory": parent, "socket": sock, "pidfile": pid, "owned_pid": job.process.pid}


def peer_pid(stream):
    if sys.platform == "darwin":
        # Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2.
        return struct.unpack("i", stream.getsockopt(0, 2, struct.calcsize("i")))[0]
    require(sys.platform.startswith("linux"), "unsupported peer PID substrate")
    pid, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == os.geteuid(), "unexpected daemon peer uid")
    return pid


class Daemon:
    def __init__(self, runner, fixture):
        self.runner, self.fixture, self.job, self.record = runner, fixture, None, None
        self.resource_samples = []
        self.cleanup_result = None

    def drain(self):
        for name in ("stdout", "stderr"):
            stream = getattr(self.job.process, name)
            # Read a finite number of chunks even if a faulty child floods.
            for _ in range(8):
                try:
                    block = os.read(stream.fileno(), 16384)
                except BlockingIOError:
                    break
                if not block:
                    break
                room = self.runner.native.OUTPUT_LIMIT - len(self.job.output[name])
                self.job.output[name].extend(block[:room])
                require(len(block) <= room, "daemon output limit")

    def verify(self):
        self.drain()
        require(socket_record(self.fixture, self.job) == self.record, "daemon generation changed")
        remaining(self.runner.deadline, 1)

    def start(self):
        f = self.fixture
        require(not os.path.lexists(f.socket) and not os.path.lexists(f.pidfile), "daemon paths not fresh")
        start = time.monotonic()
        self.job = self.runner.native.Job("foreground-daemon", [self.runner.binary, "daemon", "start"],
                                         f.cwd, f.env, timeout=remaining(self.runner.deadline, DEADLINE))
        self.runner.jobs.append(self.job)
        for name in ("stdout", "stderr"):
            os.set_blocking(getattr(self.job.process, name).fileno(), False)
        until = time.monotonic() + remaining(self.runner.deadline, 10)
        while time.monotonic() < until:
            self.drain()
            require(self.job.process.poll() is None, "daemon startup exited")
            try:
                self.record = socket_record(f, self.job)
                break
            except FileNotFoundError:
                time.sleep(.01)
        require(self.record is not None, "daemon startup deadline")
        ping = self.exchange([{"command": "ping", "input": ""}])[0]
        require(ping["response"].get("exit_code") == 0 and ping["response"].get("error") is None,
                "daemon ping refused")
        return {"startup_ms": (time.monotonic() - start) * 1000,
                "generation": self.record, "ping": ping}

    def exchange(self, requests):
        require(1 <= len(requests) <= 2, "connection batch bound")
        self.verify()
        self.runner.check_disk(self.fixture.root)
        storage(self.fixture.root, allowed_socket=self.fixture.socket)
        limit = time.monotonic() + remaining(self.runner.deadline, 5)
        selector = selectors.DefaultSelector()
        rows, streams = [], []
        try:
            # Both peer-authenticated connections are opened before either is
            # sent in a pair. This is direct client concurrency, not shell timing.
            for request in requests:
                stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                streams.append(stream)
                stream.settimeout(remaining(limit, 5))
                stream.connect(str(self.fixture.socket))
                require(peer_pid(stream) == self.job.process.pid, "socket answered by a different process")
                rows.append({"request": request, "peer_pid": self.job.process.pid, "raw": bytearray()})
            for stream, row in zip(streams, rows):
                wire = (json.dumps(row["request"], separators=(",", ":")) + "\n").encode()
                require(len(wire) <= 1024, "request bound")
                row["sent_at"] = time.monotonic()
                stream.settimeout(remaining(limit, 5))
                stream.sendall(wire)
                stream.setblocking(False)
                selector.register(stream, selectors.EVENT_READ, row)
            while selector.get_map():
                self.verify()
                for event, _ in selector.select(min(.02, remaining(limit, 5))):
                    row = event.data
                    block = event.fileobj.recv(16384)
                    require(len(row["raw"]) + len(block) <= RESPONSE_LIMIT, "daemon response bound")
                    row["raw"].extend(block)
                    if not block:
                        row["finished_at"] = time.monotonic()
                        selector.unregister(event.fileobj)
                        raw = bytes(row.pop("raw"))
                        require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "daemon response framing")
                        row.update(response=decode(raw), response_sha256=digest(raw), response_bytes=len(raw),
                                   elapsed_ms=(row["finished_at"] - row["sent_at"]) * 1000)
            self.verify()
            return rows
        except BaseException as error:
            self.runner.journal.add({"kind": "socket-failure", "error": type(error).__name__,
                                     "requests": requests, "partial": [{k: (bytes(v).hex() if k == "raw" else v)
                                     for k, v in r.items()} for r in rows]})
            raise
        finally:
            selector.close()
            for stream in streams:
                stream.close()

    def sample_resources(self):
        self.verify()
        job = self.runner.native.Job("daemon-ps", ["/bin/ps", "-p", str(self.job.process.pid),
            "-o", "pid=", "-o", "rss=", "-o", "time="], self.fixture.cwd, self.fixture.env,
            timeout=remaining(self.runner.deadline, 2))
        self.runner.jobs.append(job)
        row = self.runner.native.finish([job])[0]
        self.runner.journal.add({"kind": "resource-observer", **row})
        self.runner.native.success(row)
        fields = row["stdout"].split()
        require(len(fields) == 3 and fields[0] == str(self.job.process.pid), "ps identity/shape")
        clock = fields[2]
        days, clock = clock.split("-", 1) if "-" in clock else ("0", clock)
        parts = clock.split(":")
        require(len(parts) in (2, 3), "ps CPU format")
        h, m, s = ("0", *parts) if len(parts) == 2 else parts
        d, h, m, s, rss = int(days), int(h), int(m), float(s), int(fields[1]) * 1024
        require(min(d, h, m, s, rss) >= 0 and m < 60 and s < 60, "ps CPU/RSS range")
        sample = {"monotonic": time.monotonic(), "rss_bytes": rss,
                  "cpu_ms": (((d * 24 + h) * 60 + m) * 60 + s) * 1000}
        self.resource_samples.append(sample)
        self.verify()

    def finish(self):
        if self.job is None:
            return None
        # This retained direct child is the sole signal authority. Never invoke
        # product daemon stop or signal a PID learned from the on-disk record.
        try:
            self.job.process.send_signal(signal.SIGTERM)
        finally:
            self.job.timeout = min(self.job.timeout, time.monotonic() - self.job.started + 3)
            try:
                self.runner.native.finish([self.job])
            finally:
                row = self.job.result()
                row.update(generation=self.record, resource_samples=self.resource_samples)
                self.cleanup_result = row
                self.runner.journal.add({"kind": "daemon-cleanup", **row})
        require(row["failure"] is None and row["exit"] == 0
                and all(row["cleanup"].get(k) is True for k in CLEANUP_KEYS), "daemon cleanup failed")
        require(not os.path.lexists(self.fixture.socket) and not os.path.lexists(self.fixture.pidfile), "daemon files retained")
        return row


def request(command, cwd):
    return {"command": "check", "input": command, "context": "exec", "cwd": str(cwd),
            "shell": "posix", "interactive": False, "offline": True, "bypass_requested": False}


def same_result(expected, value, exit_code, policy, command):
    observed = semantic(value, exit_code, policy)
    if command == COMMANDS[0]:
        require(type(observed["urls"]) is int and observed["urls"] >= 1 and observed["tier"] >= 2,
                "URL workload did not reach URL analysis")
    if command == COMMANDS[1]:
        require(observed["action"] == "block" and any(f[2] for f in observed["findings"]),
                "custom policy did not block marker")
    if expected is not None:
        require(observed == expected, "matched workload semantics changed")
    return observed


def main(args):
    require(__debug__ and sys.platform in ("darwin", "linux"), "native nonoptimized Unix Python required")
    for pin in (args.sha256, args.database_sha256):
        require(len(pin) == 64 and all(c in "0123456789abcdef" for c in pin), "invalid input digest")
    inputs = {}
    for key, path, cap, expected in (("binary", args.binary, 128 * MIB, args.sha256),
            ("database", args.database, 64 * MIB, args.database_sha256),
            ("helper", args.native_helper, MIB, HELPER_SHA),
            ("python", Path(sys.executable).resolve(), 64 * MIB, None),
            ("ps", Path("/bin/ps").resolve(), 16 * MIB, None),
            ("binding", args.source_binding, 64 * 1024, None)):
        raw = held_bytes(path, cap)
        require(expected is None or digest(raw) == expected, f"{key} digest mismatch")
        inputs[key] = {"path": str(path), "sha256": digest(raw), "size": len(raw)}
    binding = decode(held_bytes(args.source_binding, 64 * 1024))
    admit_binding(binding, args.sha256)
    db_raw = held_bytes(args.database, 64 * MIB)
    spec = importlib.util.spec_from_file_location("wp17_owned", args.native_helper)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    require(digest(held_bytes(args.native_helper, MIB)) == HELPER_SHA, "native helper changed while loading")
    native.require_process_observation()
    args.output.mkdir(mode=0o700)
    journal = Journal(args.output / "observations.jsonl")
    deadline = time.monotonic() + DEADLINE
    runner = Runner(native, args.binary, deadline, journal)
    root = Path(tempfile.mkdtemp(prefix="tw17-", dir="/tmp")).resolve()
    root_identity = identity(root)
    producer_sha = digest(Path(__file__).read_bytes())
    report = {"status": "failed", "inputs": inputs, "source_binding": binding,
              "producer_sha256": producer_sha, "host": platform.platform(), "machine": platform.machine(),
              "logical_cpus": os.cpu_count(), "python": str(Path(sys.executable).resolve()),
              "samples": SAMPLES, "work_deadline_seconds": DEADLINE, "fixtures": [],
              "fixture_root": str(root), "ambient_contention": "uncontrolled; no intentionally concurrent qualification/build permitted",
              "scope": "offline check analysis with audit disabled; standalone process lifetime versus direct socket response; no command execution",
              "db_scope": "actual signed DB admitted by ordinary product; fresh status processes and first/repeated daemon checks; no OS cold-cache or per-request cache-hit claim",
              "concurrency_scope": "two direct socket clients; observed request intervals only; no real Zsh or server execution-overlap claim"}
    report["resource_units"] = {
        "standalone_cpu": "RUSAGE_CHILDREN user+system delta for the one completed CLI child, milliseconds; no daemon exits during these intervals",
        "completed_children_rss": "RUSAGE_CHILDREN ru_maxrss cumulative largest completed child in this collector; includes earlier CLI/ps children, not an individual-sample or process-tree peak",
        "daemon_cpu": "cumulative ps CPU counter sampled for retained direct child, milliseconds with platform display precision",
        "daemon_rss": "ps KiB multiplied by1024 to bytes; sampled maximum is a lower bound, not kernel peak or sum of descendants",
        "disk": "logical st_size bytes and allocated st_blocks times512 bytes across owned fixture; growth is aggregate, not per request"}
    try:
        runner.check_disk(root)
        if sys.platform == "darwin":
            context_job = native.Job("host-context", ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string", "kern.bootsessionuuid"],
                                     root, {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, timeout=remaining(deadline, 2))
            runner.jobs.append(context_job)
            context_row = native.finish([context_job])[0]
            journal.add({"kind": "host-context", **context_row})
            native.success(context_row)
            report["cpu_and_boot_context"] = context_row["stdout"].splitlines()
        else:
            # procfs reports size zero; explicitly bounded read without using
            # the regular on-disk file size admission used for input artifacts.
            with open("/proc/cpuinfo", "rb") as h:cpuinfo = h.read(MIB + 1)
            require(len(cpuinfo) <= MIB, "cpuinfo bound")
            with open("/proc/sys/kernel/random/boot_id", "rb") as h:boot = h.read(65)
            require(len(boot) <= 64, "boot identity bound")
            report["cpu_and_boot_context"] = {"cpuinfo_sha256": digest(cpuinfo), "boot_id": boot.decode().strip(),
                "models": sorted(set(l.decode() for l in cpuinfo.splitlines() if l.startswith((b"model name", b"Hardware"))))}
        for count in (1, 256):
            froot = root / str(count)
            froot.mkdir(mode=0o700)
            f = Fixture(froot, count, db_raw)
            summary = {"fixture": f.description, "before_storage": storage(froot), "cases": []}
            report["fixtures"].append(summary)
            states, db_times = [], []
            for index in range(SAMPLES if count == 1 else 1):
                value, row = runner.cli(f, f"db-load-{count}-{index}", ["threat-db", "status", "--json"])
                require(row["exit"] == 0, "DB status child failed")
                states.append(admitted_database(value, f.db));db_times.append(row["elapsed_ms"])
                require(states[-1] == states[0], "DB identity changed")
            summary["database"] = {"admitted_identity": states[0], "status_last": value,
                                   "fresh_process_status": distribution(db_times)}
            expected = {}
            for command in COMMANDS:
                times, cpu = [], []
                for index in range(SAMPLES):
                    value, row = runner.cli(f, f"check-{count}-{index}", ["check", "--no-daemon", "--offline",
                        "--non-interactive", "--shell", "posix", "--json", "--json-schema", "3", "--", command])
                    expected[command] = same_result(expected.get(command), value, row["exit"], f.policy, command)
                    times.append(row["elapsed_ms"]);cpu.append(row["cpu_user_ms"] + row["cpu_system_ms"])
                summary["cases"].append({"command": command, "semantic": expected[command],
                    "standalone": distribution(times), "standalone_cpu": distribution(cpu)})
            # ru_maxrss is a cumulative high-water across all completed children
            # of this collector. It is deliberately NOT attributed to a sample.
            ru = resource.getrusage(resource.RUSAGE_CHILDREN)
            summary["completed_children_rss_highwater_bytes"] = int(ru.ru_maxrss * (1 if sys.platform == "darwin" else 1024))
            daemon = Daemon(runner, f)
            try:
                summary["daemon_start"] = daemon.start()
                daemon.sample_resources()
                for case in summary["cases"]:
                    command = case["command"]
                    probe = daemon.exchange([request(command, f.cwd)])[0]
                    journal.add({"kind": "first_case_request", "fixture": count, **probe})
                    same_result(expected[command], probe["response"], probe["response"]["exit_code"], f.policy, command)
                    case["first_case_request_ms"] = probe["elapsed_ms"]
                    times = []
                    for index in range(SAMPLES):
                        row = daemon.exchange([request(command, f.cwd)])[0]
                        journal.add({"kind": "retained_request", "fixture": count, "index": index, **row})
                        same_result(expected[command], row["response"], row["response"]["exit_code"], f.policy, command)
                        times.append(row["elapsed_ms"])
                        if index % 10 == 9:daemon.sample_resources()
                    case["retained_serial"] = distribution(times)
                    batches, session_times = [], [[], []]
                    for index in range(SAMPLES):
                        rows = daemon.exchange([request(command, f.cwd)] * 2)
                        journal.add({"kind": "paired_requests", "fixture": count, "index": index, "rows": rows})
                        for session, row in enumerate(rows):
                            same_result(expected[command], row["response"], row["response"]["exit_code"], f.policy, command)
                            session_times[session].append(row["elapsed_ms"])
                        batches.append({"dispatch_skew_ms": abs(rows[1]["sent_at"] - rows[0]["sent_at"]) * 1000,
                            "span_ms": (max(r["finished_at"] for r in rows) - min(r["sent_at"] for r in rows)) * 1000,
                            "request_intervals_overlap": max(r["sent_at"] for r in rows) < min(r["finished_at"] for r in rows)})
                    case["paired_clients"] = {"raw_batches": batches, "client_distributions": list(map(distribution, session_times))}
                    daemon.sample_resources()
            finally:
                try:
                    daemon.finish()
                finally:
                    summary["daemon_cleanup"] = daemon.cleanup_result
            value, row = runner.cli(f, "db-after", ["threat-db", "status", "--json"])
            require(row["exit"] == 0 and admitted_database(value, f.db) == states[0], "DB postcheck changed")
            f.verify()
            summary["after_storage"] = storage(froot)
            summary["growth_logical_bytes"] = summary["after_storage"]["regular_logical_bytes"] - summary["before_storage"]["regular_logical_bytes"]
            samples = summary["daemon_cleanup"]["resource_samples"]
            require(samples and samples[-1]["cpu_ms"] >= samples[0]["cpu_ms"], "daemon CPU counter regressed")
            summary["daemon_resources"] = {"sampled_max_rss_bytes": max(s["rss_bytes"] for s in samples),
                "observed_cpu_delta_ms": samples[-1]["cpu_ms"] - samples[0]["cpu_ms"], "sample_count": len(samples)}
        remaining(deadline, 1)
        for pin in inputs.values():
            require(digest(held_bytes(Path(pin["path"]), 128 * MIB)) == pin["sha256"], "measurement input changed")
        require(digest(Path(__file__).read_bytes()) == producer_sha, "producer changed")
        report["status"] = "completed"
    except BaseException as error:
        report["failure"] = {"kind": type(error).__name__, "message": str(error)[:1024]}
    finally:
        cleanup_errors = cleanup_registered(runner)
        if cleanup_errors:
            report["status"] = "failed"
            report["final_cleanup_errors"] = cleanup_errors
        report["owned_children"] = [{"name": job.name, "pid": job.process.pid,
            "exit": job.process.returncode, "failure": job.failure,
            "cleanup": dict(job.cleanup), "group_observation": job.group_observation}
            for job in runner.jobs]
        try:
            journal.close()
        except BaseException as error:
            report["status"] = "failed"
            report["journal_error"] = str(error)[:1024]
        report["observations"] = {"path": str(journal.path), "rows": journal.count, "bytes": journal.size,
                                  "sha256": None}
        try:
            require(identity(journal.path) == journal.identity, "journal replaced")
            report["observations"]["sha256"] = digest(held_bytes(journal.path, JOURNAL_LIMIT, allow_empty=True))
        except BaseException as error:
            report["status"] = "failed"
            report["journal_postcheck_error"] = str(error)[:1024]
        report["fixture_cleanup"] = False
        try:
            require(identity(root) == root_identity, "fixture root identity changed")
            require(all(job.process.reaped and all(job.cleanup.get(k) is True for k in CLEANUP_KEYS)
                        for job in runner.jobs), "owned process cleanup uncertain; retain root")
            storage(root)
            shutil.rmtree(root)
            report["fixture_cleanup"] = True
        except BaseException as error:
            report["status"] = "failed"
            report["fixture_cleanup_error"] = str(error)[:1024]
        raw = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode()
        require(len(raw) <= 4 * MIB, "summary exceeds bound")
        with (args.output / "report.json").open("xb") as handle:handle.write(raw)
    return 0 if report["status"] == "completed" and report["fixture_cleanup"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("binary", "database", "native-helper", "source-binding", "output"):
        parser.add_argument("--" + flag, required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--database-sha256", required=True)
    arguments = parser.parse_args()
    for name in ("binary", "database", "native_helper", "source_binding"):
        setattr(arguments, name, getattr(arguments, name).absolute())
    raise SystemExit(main(arguments))
