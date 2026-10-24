#!/usr/bin/env python3
"""Explicit owned native test fixture; not signed-update or final-byte evidence."""
if not __debug__:
    raise RuntimeError("fixture assertions require unoptimized Python")

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

HELPER = Path(__file__).with_name("mixed_audit_native.py")
HELPER_SHA = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
TEST = "cli::control::lifecycle::native_fixture::pending_job_quiesce_and_identity_native_fixture"
MARKER = "TIRITH_SERVICE_COORDINATION_RESULT "


def digest(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 512 * 1024 * 1024
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def finish_owned(native, job, report):
    """Retain real cleanup evidence even when finish or a close operation fails."""
    result, primary = None, None
    failures = []
    try:
        result = native.finish([job])[0]
    except BaseException as error:
        primary = error
        report["finish_error"] = str(error)[:4096]
    finally:
        try:
            job.kill()
        except BaseException as error:
            failures.append({"operation": "owned_cleanup", "error": str(error)[:4096]})
        for name in ("stdout", "stderr"):
            try:
                getattr(job.process, name).close()
            except BaseException as error:
                failures.append({"operation": name + "_close", "error": str(error)[:4096]})
        try:
            report["owned_process"] = job.result()
        except BaseException as error:
            failures.append({"operation": "owned_result", "error": str(error)[:4096]})
        report["cleanup_errors"] = failures
    if primary is not None:
        raise primary
    if failures:
        raise RuntimeError("native fixture cleanup/reporting failed; retained evidence is incomplete")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert os.name == "posix" and os.geteuid() != 0 and os.geteuid() == os.getuid()
    assert args.test_executable.is_absolute() and args.test_executable == args.test_executable.resolve(strict=True)
    assert digest(args.test_executable) == args.sha256
    assert args.output.is_absolute() and not args.output.exists()
    assert digest(HELPER) == HELPER_SHA
    spec = importlib.util.spec_from_file_location("service_coordination_owner", HELPER)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    native.require_process_observation()
    assert digest(HELPER) == HELPER_SHA
    args.output.mkdir(mode=0o700)
    root = Path(tempfile.mkdtemp(prefix="fixture-", dir=args.output)).resolve()
    report = {"schema_version": 1, "passed": False,
              "scope": "instrumented_native_worker_service_coordination",
              "fixture_root": str(root), "fixture_retained": True,
              "test_binary_sha256": args.sha256, "native_helper_sha256": HELPER_SHA,
              "harness_sha256": digest(Path(__file__).resolve()),
              "python_executable": str(Path(sys.executable).resolve()), "python_version": sys.version,
              "python_executable_sha256": digest(Path(sys.executable).resolve()),
              "signed_update_verified": False, "binary_replacement_verified": False,
              "final_byte_coverage": False,
              "cleanup_scope": "actual test process and original owned group; service/worker threads acknowledge completion in-process",
              "limitations": ["No production trust key, policy bypass or updater flag is added.",
                              "The worker's post-admission gate is test-only and capped at 30 seconds.",
                              "Discovery metadata refusal controls do not simulate another released binary or protocol.",
                              "Synchronous spawn has no pre-spawn watchdog; external interruption/escaped-session cleanup is not claimed."]}
    job = None
    try:
        env = native.isolated_env(root)
        home = root / "home"
        home.mkdir(mode=0o700)
        config = home / ".config"
        config.mkdir(mode=0o700)
        project = root / "project"
        project.mkdir(mode=0o700)
        organization = root / "organization"
        organization.mkdir(mode=0o700)
        env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(config),
                   TIRITH_POLICY_ROOT=str(organization),
                   TIRITH_TEST_CONTROL_COORDINATION_ROOT=str(root))
        job = native.Job("service-coordination-fixture",
            [str(args.test_executable), "--exact", TEST, "--ignored", "--nocapture", "--test-threads=1"],
            project, env, timeout=90)
        # Assignment retains the returned owner before any further operation.
        # A finish selector failure still invokes that owner's cleanup exactly
        # through its idempotent API; no discovery/sample PID grants authority.
        result = finish_owned(native, job, report)
        native.success(result)
        assert "1 passed; 0 failed; 0 ignored" in result["stdout"]
        markers = [line[len(MARKER):] for line in result["stdout"].splitlines() if line.startswith(MARKER)]
        assert len(markers) == 1, "missing/duplicate native coordination result"
        observed = json.loads(markers[0])
        assert observed["scope"] == report["scope"] and observed["passed"] is True
        assert observed["test_process_pid"] == job.process.pid and observed["binary_sha256"] == args.sha256
        assert all(observed[key] is False for key in ("signed_update_verified", "binary_replacement_verified", "final_byte_coverage"))
        report["coordination"] = observed
        assert digest(args.test_executable) == args.sha256 and digest(HELPER) == HELPER_SHA
        assert digest(Path(__file__).resolve()) == report["harness_sha256"]
        assert digest(Path(sys.executable).resolve()) == report["python_executable_sha256"]
        shutil.rmtree(root)
        report.update(passed=True, fixture_retained=False)
    except BaseException as error:
        report["error"] = str(error)[:4096]
    finally:
        (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "scope": report["scope"],
                      "fixture_retained": report["fixture_retained"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
