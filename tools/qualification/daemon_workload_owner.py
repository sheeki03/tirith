#!/usr/bin/env python3
"""Finite Python-responder substrate controls; no Tirith/product execution.

The parent owns every responder through the pinned native helper. The adapter
replaces only the foreground-daemon argv with this
script's explicit responder mode; it is not product evidence.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sys
import tempfile
import time
import types

SCRIPT = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("wp17_protocol", SCRIPT.parents[2] / "scripts/measure-daemon-workloads.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
MODES = ("normal", "oversize", "stall", "bad-frame", "duplicate", "wrong-pid", "startup-exit", "stdout-flood")
EXPECTED_REFUSAL = {"oversize": "daemon response bound", "stall": "overall work deadline expired",
    "bad-frame": "daemon response framing", "duplicate": "duplicate JSON field",
    "wrong-pid": "daemon PID differs from owned child", "startup-exit": "daemon startup exited",
    "stdout-flood": "daemon output limit"}


def responder(root, mode):
    m.require(mode in MODES and root.is_dir() and root.lstat().st_uid == os.geteuid()
              and (root.lstat().st_mode & 0o777) == 0o700, "responder root admission")
    directory = root / "s/tirith"
    directory.mkdir(mode=0o700)
    endpoint, pidfile = directory / "daemon.sock", directory / "daemon.pid"
    fd = os.open(pidfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(str(os.getpid() + 1 if mode == "wrong-pid" else os.getpid()))
    pid_identity = m.identity(pidfile)
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(endpoint));endpoint.chmod(0o600)
    socket_identity = m.identity(endpoint)
    server.listen(2);server.settimeout(.1)
    def terminate(_signum, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    deadline = time.monotonic() + 20
    try:
        if mode == "startup-exit":
            os._exit(23)  # Intentional owned failure before protocol admission.
        if mode == "stdout-flood":
            os.write(1, b"x" * (128 * 1024))
        served = 0
        while time.monotonic() < deadline and served < 10:
            try:
                stream, _ = server.accept()
            except socket.timeout:
                continue
            with stream:
                stream.settimeout(2)
                raw = bytearray()
                while not raw.endswith(b"\n"):
                    part = stream.recv(1024 - len(raw))
                    m.require(part and len(raw) + len(part) <= 1024, "responder request bound")
                    raw.extend(part)
                req = m.decode(raw)
                response = {"action": "allow", "exit_code": 0, "findings": [],
                    "error": None, "bypass_honored": False, "tier_reached": 3,
                    "urls_extracted_count": 1, "policy_path_used": str(root / "c/tirith/policy.yaml")}
                wire = (json.dumps(response) + "\n").encode()
                if req.get("command") == "check":
                    if mode == "stall":
                        # Parent clamps this to a fraction of its case deadline.
                        time.sleep(10)
                    elif mode == "oversize":
                        wire = b'{"padding":"' + b"x" * m.RESPONSE_LIMIT + b'"}\n'
                    elif mode == "bad-frame":
                        wire = wire.rstrip(b"\n")
                    elif mode == "duplicate":
                        wire = b'{"exit_code":0,"exit_code":1}\n'
                try:
                    stream.sendall(wire)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                served += 1
        return 0
    finally:
        server.close()
        # Only remove the two exact objects this responder created.
        for path, expected in ((endpoint, socket_identity), (pidfile, pid_identity)):
            if os.path.lexists(path):
                m.require(m.identity(path) == expected, "responder object replaced")
                path.unlink()


def controls(args):
    m.require(m.digest(m.held_bytes(args.native_helper, m.MIB)) == m.HELPER_SHA, "helper pin mismatch")
    spec = importlib.util.spec_from_file_location("wp17_substrate_native", args.native_helper)
    native = importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
    m.require(m.digest(m.held_bytes(args.native_helper, m.MIB)) == m.HELPER_SHA, "helper changed while loading")
    native.require_process_observation()
    args.output.mkdir(mode=0o700)
    producer = m.digest(m.held_bytes(Path(m.__file__), m.MIB))
    own_pin = m.digest(m.held_bytes(SCRIPT, m.MIB))
    rows = []
    deadline = time.monotonic() + 120
    for mode in MODES:
        m.remaining(deadline, 1)
        root = Path(tempfile.mkdtemp(prefix="w17own-", dir="/tmp")).resolve()
        root_identity = m.identity(root)
        fixture = m.Fixture(root, 1, b"opaque Python-control bytes; no product or DB admission")
        journal = m.Journal(args.output / (mode + ".jsonl"))
        def start_job(name, argv, cwd, env, timeout):
            if name == "foreground-daemon":
                argv = [sys.executable, "-B", str(SCRIPT), "--responder", str(root), "--mode", mode]
            return native.Job(name, argv, cwd, env, timeout=min(timeout, 15))
        adapter = types.SimpleNamespace(Job=start_job, finish=native.finish,
                                       success=native.success, OUTPUT_LIMIT=native.OUTPUT_LIMIT)
        runner = m.Runner(adapter, Path(sys.executable), min(deadline, time.monotonic() + 15), journal)
        owner = m.Daemon(runner, fixture)
        row = {"mode": mode, "passed": False, "product_executed": False,
               "signal_authority": "retained native direct child only", "fixture": str(root)}
        observed_error = None
        started = time.monotonic()
        try:
            row["startup"] = owner.start()
            if mode == "normal":
                single = owner.exchange([m.request(m.COMMANDS[0], fixture.cwd)])
                paired = owner.exchange([m.request(m.COMMANDS[0], fixture.cwd)] * 2)
                m.require(len(single) == 1 and len(paired) == 2, "response count")
                m.require(all(r["peer_pid"] == owner.job.process.pid and r["response"]["exit_code"] == 0
                              for r in single + paired), "actual peer or response admission")
                row["single"] = single;row["paired"] = paired
                row["dispatch_skew_ms"] = (paired[1]["sent_at"] - paired[0]["sent_at"]) * 1000
                row["request_intervals_overlap"] = max(r["sent_at"] for r in paired) < min(r["finished_at"] for r in paired)
                owner.sample_resources()
            else:
                if mode == "stall":runner.deadline = min(runner.deadline, time.monotonic() + .25)
                owner.exchange([m.request(m.COMMANDS[0], fixture.cwd)])
        except BaseException as error:
            observed_error = {"kind": type(error).__name__, "message": str(error)[:1024]}
            row["expected_refusal_observed"] = observed_error
        finally:
            try:
                owner.finish()
            except BaseException as error:
                row["finish_error"] = {"kind": type(error).__name__, "message": str(error)[:1024]}
            row["final_cleanup_errors"] = m.cleanup_registered(runner)
            row["owned_children"] = [{"name": j.name, "pid": j.process.pid,
                "exit": j.process.returncode, "failure": j.failure, "cleanup": dict(j.cleanup),
                "group_observation": j.group_observation} for j in runner.jobs]
            row["daemon_cleanup"] = owner.cleanup_result
            try:
                journal.close()
                row["journal_sha256"] = m.digest(m.held_bytes(journal.path, m.JOURNAL_LIMIT, allow_empty=True))
                complete = bool(runner.jobs) and all(j.process.reaped and all(j.cleanup.get(k) is True
                    for k in m.CLEANUP_KEYS) for j in runner.jobs)
                m.require(complete, "control child cleanup incomplete")
                m.require(m.identity(root) == root_identity, "control root changed")
                m.storage(root, allowed_socket=fixture.socket)
                shutil.rmtree(root)
                row["fixture_removed_after_cleanup"] = True
                row["passed"] = ((observed_error is None and not row.get("finish_error")) if mode == "normal"
                                 else observed_error is not None and observed_error["message"] == EXPECTED_REFUSAL[mode])
                row["passed"] &= not row["final_cleanup_errors"]
            except BaseException as error:
                row["cleanup_refusal"] = str(error)[:1024]
            row["elapsed_seconds_including_cleanup"] = time.monotonic() - started
            with (args.output / (mode + ".json")).open("x") as f:
                json.dump(row, f, indent=2);f.write("\n")
        rows.append(row)
        if not row["passed"]:
            break
    unchanged = (producer == m.digest(m.held_bytes(Path(m.__file__), m.MIB))
                 and own_pin == m.digest(m.held_bytes(SCRIPT, m.MIB))
                 and m.digest(m.held_bytes(args.native_helper, m.MIB)) == m.HELPER_SHA)
    passed = len(rows) == len(MODES) and all(r["passed"] for r in rows) and unchanged
    report = {"passed": passed, "scope": "owned Python responder substrate only", "product_executed": False,
        "producer_sha256": producer, "controller_sha256": own_pin, "helper_sha256": m.HELPER_SHA,
        "inputs_unchanged": unchanged, "rows": [{"mode":r["mode"], "passed":r["passed"]} for r in rows]}
    with (args.output / "result.json").open("x") as f:json.dump(report, f, indent=2);f.write("\n")
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--responder", type=Path)
    parser.add_argument("--mode", choices=MODES)
    parser.add_argument("--native-helper", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.responder is not None:
        raise SystemExit(responder(args.responder, args.mode))
    m.require(args.native_helper is not None and args.output is not None, "controller inputs required")
    raise SystemExit(controls(args))
