#!/usr/bin/env python3
"""Native mixed-version audit qualification. No build, installation or user roots.

The signing seed below is RFC 8032's PUBLIC test vector, NEVER an operator key.
Results certify only the supplied hash-pinned executables on the recorded host.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

OUTPUT_LIMIT = 64 * 1024
FILE_LIMIT = 16 * 1024 * 1024
TIMEOUT = 45
FIXTURE_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
FIXTURE_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_bytes(path):
    require(stat.S_ISREG(path.lstat().st_mode), f"not a regular fixture file: {path}")
    with path.open("rb") as handle:
        body = handle.read(FILE_LIMIT + 1)
    require(len(body) <= FILE_LIMIT, f"fixture file exceeds limit: {path}")
    return body


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def isolated_env(root):
    # No caller TIRITH_*, proxy, credentials, shell initialization or user paths.
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(root),
           "LANG": "C", "LC_ALL": "C", "TIRITH_OFFLINE": "1",
           "TIRITH_LOG": "1", "TIRITH_AUDIT_DEBUG": "1"}
    for kind in ("CONFIG", "DATA", "STATE", "CACHE"):
        directory = root / kind.lower()
        directory.mkdir(mode=0o700)
        env[f"XDG_{kind}_HOME"] = str(directory)
    temp = root / "tmp"
    temp.mkdir(mode=0o700)
    env.update(TMPDIR=str(temp), TMP=str(temp), TEMP=str(temp))
    return env


class Job:
    def __init__(self, name, argv, root, env, timeout=TIMEOUT):
        self.name, self.argv, self.started = name, list(map(str, argv)), time.monotonic()
        self.timeout, self.output = timeout, {"stdout": bytearray(), "stderr": bytearray()}
        self.failure = None
        self.pipe_deadline = None
        self.cleanup = {"leader_reaped": False, "group_signaled_or_absent": False,
                        "output_eof": False}
        self.process = subprocess.Popen(self.argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)

    def kill(self):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.cleanup["group_signaled_or_absent"] = True
            except ProcessLookupError:
                self.cleanup["group_signaled_or_absent"] = True
            except PermissionError:
                # Darwin can briefly refuse a group signal while its owned
                # child exits. Only an observed reap and confirmed group cleanup
                # satisfy this fixture; a permanent permission error does not.
                pass
            self.cleanup["leader_reaped"] = self.process.poll() is not None
            if self.cleanup["leader_reaped"] and self.cleanup["group_signaled_or_absent"]:
                break
            time.sleep(0.01)
        if not self.cleanup["leader_reaped"]:
            try:
                self.process.kill()
                self.process.wait(timeout=1)
                self.cleanup["leader_reaped"] = True
            except (OSError, subprocess.TimeoutExpired):
                pass
        if not self.cleanup["leader_reaped"] or not self.cleanup["group_signaled_or_absent"]:
            self.failure = self.failure or "process-cleanup"
        if self.pipe_deadline is None:
            self.pipe_deadline = time.monotonic() + 2

    def result(self):
        return {"name": self.name, "argv": self.argv, "pid": self.process.pid,
                "exit": self.process.returncode, "failure": self.failure,
                "cleanup": dict(self.cleanup),
                "elapsed_seconds": round(time.monotonic() - self.started, 6),
                **{key: bytes(value).decode("utf-8", "replace") for key, value in self.output.items()}}


def finish(jobs):
    """Drain all children concurrently with hard per-stream and process bounds."""
    require(0 < len(jobs) <= 16, "invalid process batch size")
    selector = selectors.DefaultSelector()
    try:
        for job in jobs:
            for key in ("stdout", "stderr"):
                stream = getattr(job.process, key)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, (job, key))
        while selector.get_map():
            now = time.monotonic()
            for job in jobs:
                open_stream = any(event.data[0] is job for event in selector.get_map().values())
                if (job.process.poll() is None or open_stream) and now - job.started >= job.timeout and job.failure is None:
                    job.failure = "timeout"
                    job.kill()
                if open_stream and job.pipe_deadline is not None and now >= job.pipe_deadline:
                    job.failure = job.failure or "output-drain-timeout"
                    for event in list(selector.get_map().values()):
                        if event.data[0] is job:
                            selector.unregister(event.fileobj)
                            event.fileobj.close()
            for event, _ in selector.select(0.02):
                job, key = event.data
                block = os.read(event.fileobj.fileno(), 16 * 1024)
                if not block:
                    selector.unregister(event.fileobj)
                    event.fileobj.close()
                    if not any(item.data[0] is job for item in selector.get_map().values()):
                        job.cleanup["output_eof"] = True
                    continue
                room = OUTPUT_LIMIT - len(job.output[key])
                job.output[key].extend(block[:room])
                if len(block) > room:
                    if job.failure is None:
                        job.failure = "output-limit"
                        job.kill()
        for job in jobs:
            remaining = max(0.001, job.timeout - (time.monotonic() - job.started))
            try:
                job.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                job.failure = "timeout"
                job.kill()
    finally:
        selector.close()
        for job in jobs:
            job.kill()
            for key in ("stdout", "stderr"):
                getattr(job.process, key).close()
    return [job.result() for job in jobs]


def success(row):
    require(row["failure"] is None and row["exit"] == 0, f"{row['name']} failed: {row}")
    if "cleanup" in row:
        require(all(row["cleanup"].values()), f"{row['name']} cleanup incomplete: {row}")


def check_rows(body, signed, count=None):
    require(body.endswith(b"\n"), "audit log has no final newline")
    rows = [json.loads(line) for line in body.splitlines()]
    if count is not None:
        require(len(rows) == count, f"expected {count} lines, got {len(rows)}")
    require(bool(rows), "empty audit log")
    for row in rows:
        if signed:
            require(len(base64.b64decode(row.get("sig", ""), validate=True)) == 64,
                    "signed audit line missing its signature")
        else:
            require("sig" not in row, "unexpected signed line in unsigned fixture")
    return rows


def verify_output(row, signed, count):
    success(row)
    require(f"OK ({count} lines," in row["stdout"], "unexpected verification count/result")
    require(f"head receipt OK (count {count})" in row["stdout"], "head not verified")
    expected = f"signing: enabled ({count} signed line(s))" if signed else "signing: not enabled"
    require(expected in row["stdout"], "unexpected verifier signing status")


def check_commands(rows, expected):
    commands = [row.get("command_redacted") for row in rows]
    require(len(commands) == len(expected) and sorted(commands) == sorted(expected),
            "missing, duplicated, or unexpected audit command records")


class Case:
    def __init__(self, output, name, signed, binaries):
        self.root = Path(tempfile.mkdtemp(prefix=name + "-", dir=output)).resolve()
        self.env = isolated_env(self.root)
        self.name, self.signed, self.binaries = name, signed, binaries
        self.rows, self.observations, self.jobs = [], {}, []
        self.log = self.root / "data/tirith/log.jsonl"
        self.head = self.log.with_name(self.log.name + ".head")
        self.key = self.root / "config/tirith/audit-signing.key"
        if signed:
            self.key.parent.mkdir(mode=0o700)
            self.key.write_bytes(FIXTURE_SEED)
            self.key.chmod(0o600)
            self.key.with_suffix(".pub").write_bytes(FIXTURE_PUBLIC)
        save_json(self.root / "environment.json", self.env)

    def start(self, who, name, args):
        job = Job(name, [self.binaries[who], *args], self.root, self.env)
        self.jobs.append(job)
        return job

    def finish(self, jobs):
        result = finish(jobs)
        self.rows.extend(result)
        return result

    def run(self, who, name, args):
        return self.finish([self.start(who, name, args)])[0]

    def append(self, who, name):
        row = self.run(who, name, ["check", "--no-daemon", "--", "echo " + name])
        success(row)
        require("tirith: audit:" not in row["stderr"] and "audit append failed" not in row["stderr"],
                f"append reported failure: {name}")
        return row

    def snapshot(self):
        return {"log": sha(read_bytes(self.log)), "head": sha(read_bytes(self.head))}

    def rotate(self):
        row = self.run("candidate", "rotate", ["audit", "rotate", "--apply", "--json"])
        success(row)
        state = json.loads(row["stdout"])
        require(state["state"] == "completed", "rotation not completed")
        return state["operation_id"]

    def verify(self, expected):
        body = read_bytes(self.log)
        rows = check_rows(body, self.signed, expected)
        for who in ("baseline", "candidate"):
            verify_output(self.run(who, who + "-verify", ["audit", "verify"]), self.signed, len(rows))
        return rows

    def archive(self, operation_id, original, original_head):
        directory = self.log.parent / "audit-segments" / operation_id
        manifest = json.loads(read_bytes(directory / "manifest.json"))
        require(manifest["operation_id"] == operation_id, "archive operation mismatch")
        chunks = []
        total = 0
        require(0 < len(manifest["chunks"]) <= 32, "invalid chunk count")
        for index, chunk in enumerate(manifest["chunks"]):
            body = read_bytes(directory / f"{index:04}.chunk")
            require(len(body) == chunk["bytes"] and sha(body) == chunk["sha256"], "chunk digest mismatch")
            total += len(body)
            require(total <= len(original), "archive exceeds the exact original byte bound")
            chunks.append(body)
        archive = b"".join(chunks)
        require(archive == original, "archive differs from exact original log bytes")
        require(len(archive) == manifest["bytes"] and sha(archive) == manifest["sha256"],
                "archive manifest mismatch")
        require(read_bytes(directory / "original.head") == original_head, "original head changed")
        require(sha(original_head) == manifest["original_head_sha256"], "original head digest mismatch")
        checkpoint = read_bytes(directory / "checkpoint.json")
        require(sha(checkpoint) == manifest["checkpoint_sha256"], "checkpoint digest mismatch")
        active = check_rows(read_bytes(self.log), self.signed)[0]
        require(active["entry_type"] == "audit_rotation" and active["checkpoint_id"] == operation_id,
                "new genesis is not tied to rotation")
        require(active["archived_log_sha256"] == sha(original), "genesis archive digest mismatch")
        require(active["checkpoint_sha256"] == sha(checkpoint), "genesis checkpoint mismatch")
        require(active["archived_lines"] == len(original.splitlines()), "genesis archived count mismatch")
        # Native verification of the retained original under BOTH clients, using a
        # copy of the exact original head in a disposable verification subdirectory.
        verify_dir = self.root / "retained-verification"
        verify_dir.mkdir(mode=0o700)
        (verify_dir / "tirith").mkdir(mode=0o700)
        copied = verify_dir / "tirith/log.jsonl"
        copied.write_bytes(archive)
        copied.chmod(0o600)
        copied.with_name("log.jsonl.head").write_bytes(original_head)
        for who in ("baseline", "candidate"):
            env = dict(self.env, XDG_DATA_HOME=str(verify_dir))
            job = Job(who + "-archive-verify", [self.binaries[who], "audit", "verify"], self.root, env)
            self.jobs.append(job)
            row = self.finish([job])[0]
            verify_output(row, self.signed, len(archive.splitlines()))
        return manifest

    def complete(self, procedure):
        result = {"name": self.name, "signed": self.signed, "root": str(self.root), "passed": False}
        try:
            procedure(self)
            result["passed"] = True
        except Exception as error:
            result["error"] = f"{type(error).__name__}: {error}"
        finally:
            try:
                for job in self.jobs:
                    if job.process.poll() is None:
                        job.kill()
                    if job.failure is not None:
                        result["passed"] = False
            finally:
                self.key.unlink(missing_ok=True)
            result.update(rows=self.rows, observations=self.observations,
                          fixture_private_key_removed=not self.key.exists())
            save_json(self.root / "case.json", result)
        return result


def sequential(case):
    case.append("baseline", "baseline-before")
    case.append("candidate", "candidate-before")
    check_commands(case.verify(2), ["echo baseline-before", "echo candidate-before"])
    original, original_head = read_bytes(case.log), read_bytes(case.head)
    before = (case.log.stat().st_dev, case.log.stat().st_ino)
    operation = case.rotate()
    after = (case.log.stat().st_dev, case.log.stat().st_ino)
    require(before == after, "rotation replaced the active inode")
    case.observations.update(operation_id=operation, identity_before=before, identity_after=after)
    case.archive(operation, original, original_head)
    case.append("baseline", "baseline-after")
    case.append("candidate", "candidate-after")
    check_commands(case.verify(3)[1:], ["echo baseline-after", "echo candidate-after"])
    snapshot = case.snapshot()
    row = case.run("candidate", "undo-after-append", ["policy", "operation", operation, "--action", "undo"])
    require(row["failure"] is None and row["exit"] != 0 and "later audit records" in row["stderr"],
            "undo after append did not refuse precisely")
    require(case.snapshot() == snapshot, "refused undo changed active bytes")
    if case.signed:
        case.key.unlink()
        row = case.run("candidate", "missing-key-rotate", ["audit", "rotate", "--apply", "--json"])
        require(row["failure"] is None and row["exit"] != 0 and "signing key unavailable" in row["stderr"],
                "missing-key rotation did not refuse")
        require(case.snapshot() == snapshot, "refused missing-key rotation changed active bytes")
        for who in ("baseline", "candidate"):
            row = case.run(who, who + "-missing-key", ["check", "--no-daemon", "--", "echo missing-key"])
            success(row)  # Allow verdict must survive an audit-storage failure.
            require("signing key unavailable" in row["stderr"], "missing append failure diagnostic")
            if who == "candidate":
                require("audit append failed" in row["stderr"], "candidate did not visibly report audit failure")
            require(case.snapshot() == snapshot, "missing-key writer changed active bytes")
        case.verify(3)


def concurrent(case):
    case.append("baseline", "concurrent-seed")
    # Deliberate overlapping native clients. Rotation takes place between two
    # mixed bursts; this case does not claim deterministic overlap with truncation.
    for round_number in range(2):
        jobs = [case.start(who, f"{who}-burst-{round_number}-{index}",
                           ["check", "--no-daemon", "--", f"echo {who}-burst-{round_number}-{index}"])
                for index in range(3) for who in ("baseline", "candidate")]
        for row in case.finish(jobs):
            success(row)
            require("tirith: audit:" not in row["stderr"] and "audit append failed" not in row["stderr"],
                    "concurrent append failed")
        if round_number == 0:
            check_commands(case.verify(7), ["echo concurrent-seed"] + [
                f"echo {who}-burst-0-{index}" for index in range(3) for who in ("baseline", "candidate")])
            original, original_head = read_bytes(case.log), read_bytes(case.head)
            identity = (case.log.stat().st_dev, case.log.stat().st_ino)
            operation = case.rotate()
            require(identity == (case.log.stat().st_dev, case.log.stat().st_ino), "active inode changed")
            case.archive(operation, original, original_head)
        else:
            rows = case.verify(7)
            check_commands(rows[1:], [f"echo {who}-burst-1-{index}"
                                     for index in range(3) for who in ("baseline", "candidate")])
    case.observations["scope"] = "six overlapping native appends before and after rotation; no forced truncation overlap"


def observed_open(case, job, log):
    """Record OS fd evidence, not timing guesses. Never stop or instrument writer."""
    if sys.platform == "darwin":
        observer = Job(job.name + "-open-fd", ["/usr/sbin/lsof", "-nP", "-a", "-p",
                       str(job.process.pid), "-F", "fn"], case.root, case.env, timeout=3)
        row = finish([observer])[0]
        case.rows.append(row)
        require(row["failure"] is None, "fd observation failed")
        expected = "n" + str(log.resolve())
        return expected in row["stdout"].splitlines()
    if sys.platform.startswith("linux"):
        entries = list((Path("/proc") / str(job.process.pid) / "fd").iterdir())
        return any(os.path.realpath(entry) == str(log.resolve()) for entry in entries)
    raise RuntimeError("held-writer qualification requires native macOS or Linux")


def held_writer(case):
    import fcntl
    case.append("baseline", "held-seed")
    original, original_head = read_bytes(case.log), read_bytes(case.head)
    operation = str(uuid.uuid4())
    row = case.run("candidate", "prepare-held-rotation", ["audit", "rotate", "--operation-id", operation, "--json"])
    success(row)
    before = (case.log.stat().st_dev, case.log.stat().st_ino)
    # Pause ONLY the native rotator after it owns its final mutation lock. A
    # stopped waiter can acquire a flock in the kernel; stopping the lock owner
    # avoids that ambiguity. No executable instrumentation or replacement writer.
    journal = case.root / "state/tirith/operations" / (operation + ".json")
    rotator = case.start("candidate", "held-apply", ["policy", "operation", operation, "--action", "apply", "--json"])
    deadline = time.monotonic() + 5
    stopped = False
    with case.log.open("r+b") as probe:
        try:
            while not stopped:
                require(rotator.process.poll() is None and time.monotonic() < deadline,
                        "missed native rotator holding final pre-truncation lock; coverage not established")
                current = json.loads(read_bytes(journal))
                if current["steps"][0]["state"] == "applying":
                    try:
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(probe, fcntl.LOCK_UN)
                    except BlockingIOError:
                        os.kill(rotator.process.pid, signal.SIGSTOP)
                        stop_deadline = time.monotonic() + 1
                        while True:
                            pid, status = os.waitpid(rotator.process.pid, os.WNOHANG | os.WUNTRACED)
                            if pid:
                                require(os.WIFSTOPPED(status), "rotator exited before stop observation")
                                stopped = True
                                break
                            require(time.monotonic() < stop_deadline, "rotator stop not observed")
                            time.sleep(0.001)
                if not stopped:
                    time.sleep(0.001)
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                case.observations["stopped_rotator_still_owns_lock"] = True
            else:
                fcntl.flock(probe, fcntl.LOCK_UN)
                raise AssertionError("rotator released lock before stop; coverage not established")
            require(case.snapshot() == {"log": sha(original), "head": sha(original_head)},
                    "rotator already changed active bytes before stop; crossing not established")
            writer = case.start("baseline", "held-baseline", ["check", "--no-daemon", "--", "echo held-baseline"])
            deadline = time.monotonic() + 3
            while not observed_open(case, writer, case.log):
                require(writer.process.poll() is None and time.monotonic() < deadline,
                        "could not observe legacy active fd while rotator held lock")
                time.sleep(0.005)
            require(writer.process.poll() is None, "legacy writer exited before rotator resumed")
            require(case.snapshot() == {"log": sha(original), "head": sha(original_head)}, "stopped rotator changed bytes")
            case.observations.update(legacy_fd_open_before_truncation=True,
                                     original_bytes_intact_while_legacy_open=True,
                                     resume_monotonic=time.monotonic(), identity_before=before)
        finally:
            if stopped:
                os.kill(rotator.process.pid, signal.SIGCONT)
    for row in case.finish([rotator, writer]):
        success(row)
    state = json.loads(case.rows[-2]["stdout"])
    require(state["state"] == "completed", "held rotation not completed")
    require(before == (case.log.stat().st_dev, case.log.stat().st_ino), "held rotation replaced inode")
    # Exact original archive + legacy record only in active segment prove the
    # observed, already-open descriptor survived a completed rotation.
    case.archive(operation, original, original_head)
    rows = case.verify(2)
    require(rows[1].get("command_redacted") == "echo held-baseline", "held writer did not land after rotation")
    case.append("candidate", "held-candidate-after")
    case.verify(3)
    case.observations["scope"] = "native rotator stopped while owning final pre-truncation lock; observed legacy open descriptor; resumed unchanged rotator; exact original archive; legacy append in new segment"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for who in ("baseline", "candidate"):
        parser.add_argument("--" + who, type=Path, required=True)
        parser.add_argument("--" + who + "-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory (must not exist)")
    parser.add_argument("--held-writer", action="store_true", help="require observed already-open native legacy writer case")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    require(os.name == "posix", "this runner does not certify native Windows")
    pinned, binaries = {}, {}
    for who in ("baseline", "candidate"):
        path = getattr(args, who).absolute()
        expected = getattr(args, who + "_sha256")
        require(len(expected) == 64 and all(c in "0123456789abcdef" for c in expected), "invalid SHA-256 pin")
        actual = file_sha(path)
        require(actual == expected, f"{who} input SHA-256 mismatch")
        binaries[who], pinned[who] = path, {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}
    require(pinned["baseline"]["sha256"] != pinned["candidate"]["sha256"],
            "mixed-version qualification requires distinct executable bytes")
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    report = {"schema_version": 1, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "inputs": pinned, "runner_sha256": file_sha(Path(__file__).absolute()), "cases": [],
              "scope": "native supplied executables only; hash identity is not vendor signature verification",
              "not_certified": ["native Windows locking/ACLs", "durable-boundary crash injection",
                                "modified archives", "full/read-only storage", "all historic versions",
                                "global or repository policy outside fresh operator roots"],
              "fixture_key": "public RFC 8032 section 7.1 test vector 1; private fixture files removed at case end"}
    if not args.held_writer:
        report["not_certified"].append("legacy descriptor held across truncation (enable --held-writer)")
    try:
        for signed in (False, True):
            suffix = "signed" if signed else "unsigned"
            for name, procedure in [("sequential", sequential), ("concurrent", concurrent)] + (
                    [("held-writer", held_writer)] if args.held_writer else []):
                case = Case(output, name + "-" + suffix, signed, binaries)
                report["cases"].append(case.complete(procedure))
        report["inputs_unchanged"] = all(file_sha(binaries[who]) == pinned[who]["sha256"] for who in binaries)
        report["passed"] = report["inputs_unchanged"] and all(case["passed"] for case in report["cases"])
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save_json(output / "report.json", report)
        artifacts = {str(path.relative_to(output)): {"sha256": file_sha(path), "bytes": path.stat().st_size}
                     for path in sorted(output.rglob("*")) if path.is_file()}
        save_json(output / "artifacts.json", artifacts)
    print(json.dumps({"passed": report["passed"], "report": str(output / "report.json"),
                      "cases": [{"name": c["name"], "passed": c["passed"], "error": c.get("error")}
                                for c in report["cases"]]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"qualification runner: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
