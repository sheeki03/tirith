#!/usr/bin/env python3
"""Observed native process-death/recovery qualification in fresh unsigned roots.

No binary instrumentation, signing keys, dashboard service, installation or user
configuration. A sampled boundary is certified only after SIGSTOP is acknowledged,
the expected native lock is still held, and stable journal/byte evidence is saved.
This tests process death, not power loss, and never equates RLIMIT_FSIZE with ENOSPC.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
import time
import uuid

import mixed_audit_native as shared

require = shared.require
read_bytes = shared.read_bytes
save_json = shared.save_json
sha = shared.sha
OBSERVE_SECONDS = 20
SUCCESS_STATES = {"planned", "completed", "completed-with-recovery", "undone", "undone-with-recovery", "cancelled"}
# A closed version-1 strict-profile fixture, checked independently against both
# the immutable planned fields and the bytes actually published. This is not a
# general YAML parser or a reproduction of the product's mutation algorithm.
STRICT_PROFILE_FIELDS = {
    "/action_overrides/analysis_incomplete": "block",
    "/action_overrides/wrapper_chain_too_deep": "block",
    "/allow_bypass_env": False,
    "/allow_bypass_env_noninteractive": False,
    "/fail_mode": "closed",
    "/paranoia": 1,
    "/protection_profile": {"name": "strict", "owned_fields": [
        "action_overrides.analysis_incomplete", "action_overrides.wrapper_chain_too_deep",
        "allow_bypass_env", "allow_bypass_env_noninteractive", "fail_mode", "paranoia", "scan.require_complete"], "version": 1},
    "/scan/require_complete": True,
}
STRICT_PROFILE_BYTES = b"""action_overrides:
  analysis_incomplete: block
  wrapper_chain_too_deep: block
allow_bypass_env: false
allow_bypass_env_noninteractive: false
fail_mode: closed
paranoia: 1
protection_profile:
  name: strict
  owned_fields:
  - action_overrides.analysis_incomplete
  - action_overrides.wrapper_chain_too_deep
  - allow_bypass_env
  - allow_bypass_env_noninteractive
  - fail_mode
  - paranoia
  - scan.require_complete
  version: 1
scan:
  require_complete: true
strict_warn: false
"""


class Unobserved(Exception):
    """A required platform condition or sampled boundary was not established."""


def identity(path):
    value = path.lstat()
    return [value.st_dev, value.st_ino]


def fingerprint(path):
    if not path.exists():
        return None
    body = read_bytes(path)
    return {"identity": identity(path), "bytes": len(body), "sha256": sha(body)}


def lock_busy(path):
    # Read-only open; never create or hold a writer lock between observations.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def stopped_owner(job, lock_path):
    """Signal only our live, unreaped child; acknowledge stop before lock proof."""
    require(job.process.poll() is None, "owned process already exited")
    job.process.send_signal(signal.SIGSTOP)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        event = job.process.observe_stop()
        if event is not None:
            if event.si_code != os.CLD_STOPPED:
                raise Unobserved("process exited before acknowledged SIGSTOP")
            require(event.si_pid == job.process.pid and event.si_status == signal.SIGSTOP,
                    "unexpected stop owner or reason")
            require(lock_busy(lock_path), "stopped process did not retain the observed lock")
            return {"pid": event.si_pid, "stop_signal": signal.SIGSTOP,
                    "lock": str(lock_path), "lock_identity": identity(lock_path),
                    "lock_contended_while_stopped": True}
        time.sleep(0.001)
    raise AssertionError("owned process stop acknowledgement deadline")


def clean(row, expected_exit=None):
    require(row["failure"] is None and set(row["cleanup"]) == {"leader_reaped", "group_signaled_or_absent", "group_members_exited", "output_eof"}
            and all(value is True for value in row["cleanup"].values()), "process cleanup/bounds failed: " + str(row))
    if expected_exit is not None:
        require(row["exit"] == expected_exit, "unexpected exit: " + str(row))


def operation_state(row, allowed):
    clean(row)
    value = json.loads(row["stdout"])
    require(value["state"] in allowed, "unexpected operation state: " + str(value))
    clean(row, 0 if value["state"] in SUCCESS_STATES else 1)
    return value


def refusal(row, diagnostic, stream="stderr"):
    clean(row, 1)
    require(diagnostic in row[stream], "expected refusal diagnostic missing: " + str(row))


def strict_profile_plan(record):
    require(record.get("kind") == "set-profile" and len(record.get("steps", [])) == 1,
            "fixture must capture one strict-profile policy publication")
    expected = {"Compound": [{"Field": {"yaml": True, "pointer": pointer, "before": None, "after": after}}
                             for pointer, after in STRICT_PROFILE_FIELDS.items()]}
    # JSON comparison keeps booleans distinct from numbers, unlike Python ==.
    require(json.dumps(record["steps"][0]["edit"], sort_keys=True) == json.dumps(expected, sort_keys=True),
            "saved profile plan does not contain the exact intended version-1 owned values")


def strict_profile_published(path):
    require(read_bytes(path) == STRICT_PROFILE_BYTES, "published policy does not match the exact intended owned postconditions")


class Case:
    def __init__(self, output, name, binary):
        self.name, self.binary = name, binary
        self.root = Path(tempfile.mkdtemp(prefix=name + "-", dir=output)).resolve()
        self.env = shared.isolated_env(self.root)
        self.jobs, self.rows, self.observations = [], [], {}
        self.id = str(uuid.uuid4())
        self.journal = self.root / "state/tirith/operations" / (self.id + ".json")
        self.execution_lock = self.journal.with_suffix(".execution-lock")
        self.log = self.root / "data/tirith/log.jsonl"
        self.head = self.log.with_name("log.jsonl.head")
        self.policy = self.root / "config/tirith/policy.yaml"
        self.archive = self.log.parent / "audit-segments" / self.id
        save_json(self.root / "environment.json", self.env)

    def start(self, name, args, prefix=None):
        argv = [self.binary, *args]
        if prefix:
            argv = [*prefix, *argv]
        job = shared.Job(name, argv, self.root, self.env)
        self.jobs.append(job)
        return job

    def finish(self, *jobs):
        rows = shared.finish(list(jobs))
        self.rows.extend(rows)
        for job in jobs:
            job.qualification_finished = True
        return rows

    def run(self, name, args, prefix=None):
        return self.finish(self.start(name, args, prefix))[0]

    def operation(self, action):
        return self.run(action, ["policy", "operation", self.id, "--action", action, "--json"])

    def journal_value(self):
        return json.loads(read_bytes(self.journal))

    def snapshot(self):
        return {"log": fingerprint(self.log), "head": fingerprint(self.head), "policy": fingerprint(self.policy)}

    def append(self, marker):
        row = self.run(marker, ["check", "--no-daemon", "--format", "json", "--", "echo " + marker])
        clean(row, 0)
        require("audit append failed" not in row["stderr"], "seed audit append failed")
        return row

    def prepare_rotation(self):
        self.append("retained-original")
        self.original, self.original_head = read_bytes(self.log), read_bytes(self.head)
        self.original_identity = identity(self.log)
        (self.root / "original-log.jsonl").write_bytes(self.original)
        (self.root / "original.head").write_bytes(self.original_head)
        row = self.run("prepare", ["audit", "rotate", "--operation-id", self.id, "--json"])
        clean(row, 0)
        self.plan = self.journal_value()["steps"][0]["edit"]["AuditRotation"]

    def prepare_profile(self):
        self.policy.parent.mkdir(mode=0o700)
        self.policy.write_bytes(b"action_overrides: {}\nscan: {}\nstrict_warn: false\n")
        self.policy.chmod(0o600)
        self.original = read_bytes(self.policy)
        self.original_identity = identity(self.policy)
        (self.root / "original-policy.yaml").write_bytes(self.original)
        row = self.run("prepare", ["policy", "rollout", "prepare", "strict", "--command", "echo durability",
                                   "--operation-id", self.id, "--json"])
        clean(row, 0)
        planned = self.journal_value()
        strict_profile_plan(planned)
        require(planned["steps"][0]["target"] == str(self.policy), "profile plan targets a different fixture file")

    def rotation_stage(self):
        body, head = read_bytes(self.log), read_bytes(self.head)
        if body == self.original and head == self.original_head:
            return "archive-published" if (self.archive / "manifest.json").exists() else "before-archive"
        if head == bytes(self.plan["barrier"]):
            if body == self.original:
                return "barrier-before-truncate"
            if not body:
                return "empty-after-truncate"
            if body == bytes(self.plan["genesis"]):
                return "genesis-before-head"
            return "other-barrier-state"
        if body == bytes(self.plan["genesis"]) and head == bytes(self.plan["genesis_head"]):
            return "applied-before-result"
        return "other"

    def capture_stopped(self, job, kind, requested):
        lock = self.log if kind == "audit" else self.execution_lock
        deadline = time.monotonic() + OBSERVE_SECONDS
        while job.process.poll() is None and time.monotonic() < deadline:
            current = self.journal_value()
            active = current["steps"][0]["state"] in ("applying", "applied", "applied-with-recovery")
            stage = self.rotation_stage() if kind == "audit" else (
                "before-policy-publication" if read_bytes(self.policy) == self.original else "policy-published")
            if active and stage == requested and lock.exists() and lock_busy(lock):
                evidence = stopped_owner(job, lock)
                evidence["journal"] = fingerprint(self.journal)
                saved = self.journal_value()
                evidence.update(journal_state=saved["state"], step_states=[s["state"] for s in saved["steps"]],
                                operation_id=self.id, requested_stage=requested,
                                observed_stage=self.rotation_stage() if kind == "audit" else (
                                    "before-policy-publication" if read_bytes(self.policy) == self.original else "policy-published"),
                                snapshot=self.snapshot(), execution_lock_contended=lock_busy(self.execution_lock),
                                shared_setup_lock_busy=lock_busy(Path("/")),
                                archive_manifest=fingerprint(self.archive / "manifest.json"))
                require(evidence["execution_lock_contended"], "stopped child lost operation execution lock")
                if kind == "profile" and evidence["observed_stage"] == "policy-published":
                    strict_profile_published(self.policy)
                # Read twice while stopped; this is stable published-file evidence,
                # not an assertion about filesystem power-loss persistence.
                require(evidence["snapshot"] == self.snapshot(), "stopped generation was not stable")
                (self.root / "stopped-journal.json").write_bytes(read_bytes(self.journal))
                for name, path in (("log.jsonl", self.log), ("head.json", self.head), ("policy.yaml", self.policy)):
                    if path.exists():
                        (self.root / ("stopped-" + name)).write_bytes(read_bytes(path))
                save_json(self.root / "stopped-boundary.json", evidence)
                self.observations["boundary"] = evidence
                if (evidence["observed_stage"] != requested or evidence["journal_state"] != "running"
                        or evidence["step_states"] != ["applying"]):
                    raise Unobserved("boundary advanced before acknowledged stop: requested " + requested
                                     + ", observed " + evidence["observed_stage"] + ", journal "
                                     + evidence["journal_state"] + ", steps " + str(evidence["step_states"]))
                return evidence
            time.sleep(0.001)
        raise Unobserved("requested native locked boundary not sampled before process exit/deadline: " + requested)

    def kill_stopped(self, job):
        job.kill()
        row = self.finish(job)[0]
        clean(row, -signal.SIGKILL)
        require(not lock_busy(self.execution_lock), "execution lock survived owner process death")
        self.observations["execution_lock_released_after_kill"] = True
        return row

    def verify(self, count):
        row = self.run("verify", ["audit", "verify"])
        shared.verify_output(row, False, count)

    def verify_archive(self):
        manifest = json.loads(read_bytes(self.archive / "manifest.json"))
        require(manifest["operation_id"] == self.id and len(manifest["chunks"]) <= 32, "archive identity/bound mismatch")
        data = bytearray()
        for index, entry in enumerate(manifest["chunks"]):
            body = read_bytes(self.archive / (f"{index:04}.chunk"))
            require(len(body) == entry["bytes"] and sha(body) == entry["sha256"], "archive chunk changed")
            data.extend(body)
            require(len(data) <= len(self.original), "archive exceeds retained original")
        require(bytes(data) == self.original and manifest["sha256"] == sha(data), "archive lost original bytes")
        require(read_bytes(self.archive / "original.head") == self.original_head, "archive lost original head")
        require(sha(read_bytes(self.archive / "checkpoint.json")) == manifest["checkpoint_sha256"], "checkpoint hash mismatch")
        return manifest

    def complete(self, procedure):
        result = {"name": self.name, "root": str(self.root), "operation_id": self.id, "outcome": "failed"}
        try:
            procedure(self)
            result["outcome"] = "passed"
        except Unobserved as error:
            result.update(outcome="unobserved", reason=str(error))
        except Exception as error:
            result["error"] = type(error).__name__ + ": " + str(error)
        finally:
            for job in self.jobs:
                if not getattr(job, "qualification_finished", False):
                    if job.process.poll() is None:
                        job.kill()
                    self.finish(job)
                if job.failure is not None or not all(job.cleanup.values()):
                    result.update(outcome="failed", cleanup_error="owned process cleanup not confirmed")
            result.update(rows=self.rows, observations=self.observations)
            save_json(self.root / "case.json", result)
        return result


def crash_rotation(case, stage):
    case.prepare_rotation()
    job = case.start("apply-interrupted", ["policy", "operation", case.id, "--action", "apply", "--json"])
    boundary = case.capture_stopped(job, "audit", stage)
    case.kill_stopped(job)
    require(case.snapshot() == boundary["snapshot"], "process death changed durable bytes")
    require(not lock_busy(case.log), "audit lock survived owner process death")
    status = operation_state(case.operation("status"), {"recovery-required", "completed", "completed-with-recovery"})
    case.observations["reopened_status"] = status["state"]
    operation_state(case.operation("apply"), {"completed", "completed-with-recovery"})
    require(identity(case.log) == case.original_identity, "recovery replaced the active audit inode")
    case.verify_archive()
    case.verify(1)
    completed = case.snapshot()
    operation_state(case.operation("apply"), {"completed", "completed-with-recovery"})
    require(case.snapshot() == completed, "identical retry rewrote committed bytes or inode")
    operation_state(case.operation("undo"), {"undone", "undone-with-recovery"})
    require(read_bytes(case.log) == case.original and read_bytes(case.head) == case.original_head,
            "undo did not restore exact original audit bytes/head")
    require(identity(case.log) == case.original_identity, "undo replaced active audit inode")
    undone = case.snapshot()
    operation_state(case.operation("undo"), {"undone", "undone-with-recovery"})
    require(case.snapshot() == undone, "repeated undo changed bytes or inode")
    case.verify(1)


def concurrent_rotation_cancel(case):
    case.prepare_rotation()
    job = case.start("apply-cancelled", ["policy", "operation", case.id, "--action", "apply", "--json"])
    boundary = case.capture_stopped(job, "audit", "before-archive")
    if boundary["observed_stage"] != "before-archive" or boundary["shared_setup_lock_busy"]:
        raise Unobserved("stopped audit owner was not before archive with the shared setup lock free")
    # The operation execution lock must reject a second undo process before it
    # can touch the log; no fixture holds a substitute product lock here.
    row = case.operation("undo")
    refusal(row, "tirith policy operation: operation is already applying or undoing; wait for its result")
    require(case.snapshot() == boundary["snapshot"], "concurrent refused undo changed bytes")
    operation_state(case.operation("status"), {"running"})
    operation_state(case.operation("cancel"), {"cancel-requested"})
    require(lock_busy(case.execution_lock) and lock_busy(case.log), "cancellation replaced the live owner")
    case.observations["cancel_requested_while_owner_stopped"] = True
    job.process.send_signal(signal.SIGCONT)
    state = operation_state(case.finish(job)[0], {"cancelled", "partially-applied"})
    require(case.snapshot() == boundary["snapshot"], "cancelled worker published audit bytes")
    require(not (case.archive / "manifest.json").exists(), "cancelled worker completed archive publication")
    case.observations["cancel_resolution"] = state["state"]
    operation_state(case.operation("undo"), {"undone", "undone-with-recovery", "cancelled"})
    require(case.snapshot() == boundary["snapshot"], "compensation after cancellation changed original bytes")
    case.verify(1)


def crash_profile(case, stage, concurrent=None):
    case.prepare_profile()
    job = case.start("apply-interrupted", ["policy", "operation", case.id, "--action", "apply", "--json"])
    boundary = case.capture_stopped(job, "profile", stage)
    if concurrent == "cancel" and not boundary["shared_setup_lock_busy"]:
        operation_state(case.operation("cancel"), {"cancel-requested", "cancelled", "completed", "completed-with-recovery"})
        case.observations["cancel_requested_while_owner_stopped"] = True
    if concurrent == "edit":
        # An ordinary editor changes an owned setting while the original worker
        # is stopped. This is fixture content only, never an operator policy.
        case.policy.write_bytes(b"strict_warn: false\nparanoia: 4\n")
        case.policy.chmod(0o600)
        case.observations["edited_generation"] = fingerprint(case.policy)
    case.kill_stopped(job)
    operation_state(case.operation("status"), {"recovery-required", "completed", "completed-with-recovery"})
    if concurrent == "edit":
        after_edit = fingerprint(case.policy)
        row = case.operation("apply")
        state = operation_state(row, {"refresh-required"})
        require(state.get("detail") == "refresh-required: owned generation or authorization document changed",
                "changed owned generation was not explicitly identified")
        require(fingerprint(case.policy) == after_edit, "retry overwrote concurrent edit")
        row = case.operation("undo")
        refusal(row, "tirith policy operation: refresh-required: owned fields changed before undo authorization")
        require(fingerprint(case.policy) == after_edit, "undo overwrote concurrent edit")
        case.observations["concurrent_edit_preserved_with_explicit_refusal"] = True
        return
    if concurrent == "cancel":
        if not case.observations.get("cancel_requested_while_owner_stopped"):
            operation_state(case.operation("cancel"), {"cancel-requested", "cancelled", "completed", "completed-with-recovery"})
            case.observations["cancel_after_death_only"] = True
        state = operation_state(case.operation("apply"), {"cancelled", "partially-applied", "completed", "completed-with-recovery"})
        case.observations["cancel_resolution"] = state["state"]
        require(fingerprint(case.policy) == boundary["snapshot"]["policy"], "cancel replay introduced another policy publication")
        return
    operation_state(case.operation("apply"), {"completed", "completed-with-recovery"})
    strict_profile_published(case.policy)
    completed = fingerprint(case.policy)
    if boundary["observed_stage"] == "policy-published":
        require(completed == boundary["snapshot"]["policy"], "recovery replaced an already-published intended generation")
    operation_state(case.operation("apply"), {"completed", "completed-with-recovery"})
    require(fingerprint(case.policy) == completed, "profile replay republished a committed generation")
    operation_state(case.operation("undo"), {"undone", "undone-with-recovery"})
    require(read_bytes(case.policy) == case.original, "profile undo failed exact simple fixture restoration")
    undone = fingerprint(case.policy)
    operation_state(case.operation("undo"), {"undone", "undone-with-recovery"})
    require(fingerprint(case.policy) == undone, "profile undo replay republished content")


def storage_failure(case, kind):
    if os.geteuid() == 0:
        raise Unobserved("ordinary-UID storage failures cannot be established under root")
    allowed = case.append("allow-before-failure")
    blocked = case.run("block-before-failure", ["check", "--no-daemon", "--format", "json", "--", "curl https://example.com | bash"])
    clean(blocked, 1)
    require(json.loads(blocked["stdout"])["action"] == "block", "block control did not block")
    before = case.snapshot()
    original = read_bytes(case.log)
    (case.root / "original-log.jsonl").write_bytes(original)
    (case.root / "original.head").write_bytes(read_bytes(case.head))
    prefix = None
    try:
        if kind == "log-permission":
            case.log.chmod(0o400)
            try:
                fd = os.open(case.log, os.O_WRONLY | os.O_APPEND)
            except PermissionError:
                case.observations["ordinary_uid_write_probe"] = "EACCES"
            else:
                os.close(fd)
                raise Unobserved("log permissions did not deny this effective UID")
        elif kind == "head-publication-permission":
            case.log.parent.chmod(0o500)
            try:
                fd = os.open(case.log.parent / "write-probe", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except PermissionError:
                case.observations["ordinary_uid_create_probe"] = "EACCES"
            else:
                os.close(fd)
                (case.log.parent / "write-probe").unlink()
                raise Unobserved("directory permissions did not deny this effective UID")
        else:
            # Ignore XFSZ before exec so actual native write receives EFBIG. The
            # wrapper only sets an OS resource ceiling; no product API is mocked.
            script = "import os,resource,signal,sys; resource.setrlimit(resource.RLIMIT_FSIZE,(int(sys.argv[1]),int(sys.argv[1]))); signal.signal(signal.SIGXFSZ,signal.SIG_IGN); os.execve(sys.argv[2],sys.argv[2:],dict(os.environ))"
            prefix = [sys.executable, "-c", script, str(len(original))]
        for label, command, control in [("allow", "echo allow-before-failure", allowed),
                                       ("block", "curl https://example.com | bash", blocked)]:
            row = case.run(label + "-storage-failure", ["check", "--no-daemon", "--format", "json", "--", command], prefix)
            clean(row, control["exit"])
            require(json.loads(row["stdout"])["action"] == json.loads(control["stdout"])["action"], "storage changed verdict")
            require("audit append failed" in row["stderr"], "actual native failure was not visible")
            if kind == "file-size-ceiling":
                require("File too large" in row["stderr"], "EFBIG was not established")
        if kind != "head-publication-permission":
            require(case.snapshot() == before, "failed append changed existing log/head generation")
        else:
            body = read_bytes(case.log)
            require(body.startswith(original) and len(body) > len(original), "partial head failure lost original records")
            require(fingerprint(case.head) == before["head"], "failed head publication changed head")
            require(identity(case.log) == before["log"]["identity"], "head failure replaced active log")
            case.observations["partial_append"] = {"bytes": len(body) - len(original), "head_unchanged": True}
    finally:
        case.log.chmod(0o600)
        case.log.parent.chmod(0o700)
    if kind == "head-publication-permission":
        snapshot = case.snapshot()
        row = case.run("verify-after-permission-restored", ["audit", "verify"])
        refusal(row, "head receipt does not match log tail", "stdout")
        require(row["stdout"].startswith("tirith audit verify: FAILED ("), "expected failed audit verification summary missing")
        require(case.snapshot() == snapshot, "read-only verifier altered failed state")
        row = case.run("rotate-mismatched-history", ["audit", "rotate", "--operation-id", case.id, "--json"])
        refusal(row, "tirith audit rotate: audit integrity must verify before retention; inspect audit verify")
        require(case.snapshot() == snapshot, "rotation discarded mismatched history")
    else:
        case.verify(2)
        case.append("storage-recovered")
        case.verify(3)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", help="run only named cases; repeatable")
    args = parser.parse_args(argv)
    require(os.name == "posix", "native Windows is not supported by this runner")
    require(callable(getattr(os, "waitid", None)) and all(hasattr(os, name) for name in (
        "WNOWAIT", "WEXITED", "WSTOPPED", "CLD_STOPPED")),
        "unsupported Python runtime: non-reaping waitid/WNOWAIT process observation is required")
    require(os.geteuid() != 0, "run this qualification as an ordinary user")
    candidate = args.candidate.absolute()
    require(len(args.candidate_sha256) == 64 and all(c in "0123456789abcdef" for c in args.candidate_sha256), "invalid candidate SHA-256")
    require(shared.file_sha(candidate) == args.candidate_sha256, "candidate SHA-256 mismatch")
    routes = [("audit-" + stage, lambda c, stage=stage: crash_rotation(c, stage)) for stage in (
        "before-archive", "archive-published", "barrier-before-truncate", "empty-after-truncate",
        "genesis-before-head", "applied-before-result")]
    routes += [("audit-concurrent-cancel", concurrent_rotation_cancel)]
    routes += [("profile-before-publication", lambda c: crash_profile(c, "before-policy-publication")),
               ("profile-after-publication", lambda c: crash_profile(c, "policy-published")),
               ("profile-concurrent-edit", lambda c: crash_profile(c, "before-policy-publication", "edit")),
               ("profile-cancel", lambda c: crash_profile(c, "before-policy-publication", "cancel"))]
    routes += [("storage-" + kind, lambda c, kind=kind: storage_failure(c, kind)) for kind in (
        "log-permission", "head-publication-permission", "file-size-ceiling")]
    require(not args.case or set(args.case) <= {name for name, _ in routes}, "unknown case")
    os.umask(0o077)
    output = args.output.absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    report = {"schema_version": 1, "candidate": {"path": str(candidate), "sha256": args.candidate_sha256},
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "uid": os.geteuid()},
              "python": {"path": str(Path(sys.executable).resolve()), "version": sys.version, "sha256": shared.file_sha(Path(sys.executable).resolve())},
              "runner_sha256": shared.file_sha(Path(__file__)),
              "shared_runner_sha256": shared.file_sha(Path(shared.__file__)), "cases": [],
              "not_qualified": ["power loss or fsync persistence", "every durable write boundary", "signed audit rotation",
                  "actual ENOSPC/full filesystem (no disposable full filesystem supplied)", "native Windows", "binary update/rollback publication",
                  "partial genesis/restore writes not observed by these routes", "operator configuration or services"]}
    try:
        for name, procedure in routes:
            if args.case and name not in args.case:
                continue
            result = Case(output, name, candidate).complete(procedure)
            report["cases"].append(result)
            print(json.dumps({"name": name, "outcome": result["outcome"], "error": result.get("error"), "reason": result.get("reason")}), flush=True)
        report["candidate_unchanged"] = shared.file_sha(candidate) == args.candidate_sha256
        report["runner_inputs_unchanged"] = (shared.file_sha(Path(__file__)) == report["runner_sha256"] and
            shared.file_sha(Path(shared.__file__)) == report["shared_runner_sha256"] and
            shared.file_sha(Path(report["python"]["path"])) == report["python"]["sha256"])
        report["all_requested_boundaries_observed"] = bool(report["cases"]) and all(c["outcome"] == "passed" and (
            "boundary" not in c["observations"] or c["observations"]["boundary"]["observed_stage"] == c["observations"]["boundary"]["requested_stage"]) for c in report["cases"])
        report["passed"] = (report["candidate_unchanged"] and report["runner_inputs_unchanged"]
                            and report["all_requested_boundaries_observed"])
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save_json(output / "report.json", report)
        save_json(output / "artifacts.json", {str(p.relative_to(output)): fingerprint(p) for p in sorted(output.rglob("*")) if p.is_file()})
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"durability runner: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
