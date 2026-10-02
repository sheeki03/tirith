#!/usr/bin/env python3
"""Run native PTY tests against the binary embedded in a release package.

The report certifies only the exercised shell modes. Agent hosts and native
platforms absent from this run remain unavailable, never inferred from config.
"""

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_PROCESS_OUTPUT_BYTES = 4 * 1024 * 1024
OWNER_HELPER_SHA256 = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
OWNER_HELPER = Path(__file__).resolve().parents[1] / "tools/qualification/mixed_audit_native.py"
_OWNER_RUNTIME = None
HOOKS = ("bash-hook.bash", "zsh-hook.zsh", "fish-hook.fish",
         "powershell-hook.ps1", "nushell-hook.nu")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def packaged_binary_digest(package):
    """Inspect one regular binary member; never extract archive pathnames."""
    if zipfile.is_zipfile(package):
        with zipfile.ZipFile(package) as archive:
            members = [entry for entry in archive.infolist()
                       if Path(entry.filename).name in ("tirith", "tirith.exe")]
            if (len(members) != 1 or members[0].is_dir()
                    or members[0].file_size > MAX_BINARY_BYTES):
                raise ValueError("package must contain exactly one bounded Tirith binary")
            mode = members[0].external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise ValueError("packaged Tirith binary must be a regular ZIP member")
            with archive.open(members[0]) as stream:
                return bounded_digest(stream)
    with tarfile.open(package, "r:*") as archive:
        members = [entry for entry in archive.getmembers()
                   if Path(entry.name).name in ("tirith", "tirith.exe")]
        if (len(members) != 1 or not members[0].isfile()
                or members[0].size > MAX_BINARY_BYTES):
            raise ValueError("package must contain exactly one bounded regular Tirith binary")
        with archive.extractfile(members[0]) as stream:
            return bounded_digest(stream)


def bounded_digest(stream):
    digest = hashlib.sha256()
    total = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        total += len(block)
        if total > MAX_BINARY_BYTES:
            raise ValueError("packaged binary exceeds inspection limit")
        digest.update(block)
    return digest.hexdigest()


def owner_runtime():
    global _OWNER_RUNTIME
    if sha256(OWNER_HELPER) != OWNER_HELPER_SHA256:
        raise ValueError("owned-process helper differs from the reviewed implementation")
    if _OWNER_RUNTIME is None:
        spec = importlib.util.spec_from_file_location("shell_package_owned", OWNER_HELPER)
        _OWNER_RUNTIME = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_OWNER_RUNTIME)
        if sha256(OWNER_HELPER) != OWNER_HELPER_SHA256:
            _OWNER_RUNTIME = None
            raise ValueError("owned-process helper changed while loading")
    _OWNER_RUNTIME.require_process_observation()
    return _OWNER_RUNTIME


def merged_job(command, env, timeout):
    """Keep the existing merged pipe/input contract with shared owned cleanup.

    Job.kill owns original-group signals, WNOWAIT observations and final reap.
    Its usual two-stream finish() is not used: this wrapper must preserve the
    native ordering of merged stdout/stderr and its larger bounded test log.
    """
    owned = owner_runtime()

    class MergedJob(owned.Job):
        def __init__(self):
            self.name, self.argv, self.started = "shell-package-command", list(map(str, command)), time.monotonic()
            self.timeout = timeout
            self.output = {"stdout": bytearray(), "stderr": bytearray()}
            self.failure = None
            self.pipe_deadline = None
            self.cleanup = {"leader_reaped": False, "group_signaled_or_absent": False,
                            "group_members_exited": False, "output_eof": False}
            self.group_observation = None
            self.cleanup_attempted = False
            # stdin and cwd remain inherited, as in the original wrapper.
            self.process = owned.OwnedProcess(self.argv, env=env, stdout=subprocess.PIPE,
                                              stderr=subprocess.STDOUT, start_new_session=True)

    return MergedJob()


def run(command, env, timeout=15, observations=None):
    # Selector allocation cannot leave an already spawned child unowned.
    selector = selectors.DefaultSelector()
    job = None
    error = None
    try:
        job = merged_job(command, env, timeout)
        process = job.process
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while process.poll() is None or selector.get_map():
            now = time.monotonic()
            if process.poll() is not None:
                # Clean descendants even after a quick leader exit, including
                # descendants that retain the pipe or closed it before sleeping.
                job.kill()
            elif now - job.started >= timeout:
                job.failure = job.failure or "timeout"
                job.kill()
            if job.pipe_deadline is not None and now >= job.pipe_deadline:
                # Cleanup can fail with a still-live leader whose pipes have
                # already closed. An empty selector is not process-exit proof.
                job.failure = job.failure or ("output-drain-timeout" if selector.get_map()
                                              else "process-cleanup-timeout")
                break
            for event, _ in selector.select(0.02):
                block = os.read(event.fileobj.fileno(), 16384)
                if not block:
                    selector.unregister(event.fileobj)
                    job.cleanup["output_eof"] = True
                    continue
                room = MAX_PROCESS_OUTPUT_BYTES - len(job.output["stdout"])
                job.output["stdout"].extend(block[:room])
                if len(block) > room:
                    job.failure = job.failure or "output-limit"
                    job.kill()
    except BaseException as caught:
        error = caught
    finally:
        try:
            selector.close()
        finally:
            if job is not None:
                job.kill()
                job.process.stdout.close()
    if job is None:
        raise error
    process = job.process
    result = job.result()
    # Match text=True's newline normalization; the evidence digest below stays
    # over the exact bounded merged bytes read from the native pipe.
    output = result.pop("stdout").replace("\r\n", "\n").replace("\r", "\n")
    result.pop("stderr")
    result["merged_output_bytes"] = len(job.output["stdout"])
    result["merged_output_sha256"] = hashlib.sha256(job.output["stdout"]).hexdigest()
    result["cleanup_scope"] = "owned original process group; test-owned PTY sessions require their own cleanup"
    if observations is not None:
        observations.append(result)
    if error is not None:
        error.qualification = result
        raise error
    if not all(result["cleanup"].values()):
        error = ValueError("native command cleanup is incomplete")
    elif result["failure"] == "timeout":
        error = subprocess.TimeoutExpired(command, timeout, output=output)
    elif result["failure"] is not None:
        error = ValueError("native command failed qualification: " + result["failure"])
    if error is not None:
        error.qualification = result
        raise error
    completed = subprocess.CompletedProcess(command, process.returncode, output)
    completed.qualification = result
    return completed


def pty_cleanup_evidence(output):
    """Admit the test-owned sessions separately from the outer command group."""
    starts, ends = {}, {}
    for line in output.splitlines():
        for marker, destination in (("TIRITH_PTY_OWNED_BEGIN ", starts),
                                    ("TIRITH_PTY_OWNED_CLEANUP ", ends)):
            if marker not in line:
                continue
            value = json.loads(line.split(marker, 1)[1])
            identity = value["id"]
            if (not isinstance(identity, str) or not identity or identity in destination
                    or value["schema_version"] != 1
                    or value["scope"] != "original_owned_pty_session"
                    or type(value["pid"]) is not int or value["pid"] <= 0):
                raise ValueError("invalid or duplicate native PTY ownership record")
            destination[identity] = value
    if not starts or set(starts) != set(ends):
        raise ValueError("missing native PTY ownership or completion evidence")
    for identity, value in ends.items():
        if value["pid"] != starts[identity]["pid"]:
            raise ValueError("native PTY owner changed")
        if (any(value.get(key) is not True for key in
                ("passed", "native_eof", "reader_joined", "private_pty_handles_released"))
                or any(value["native"].get(key) is not True for key in
                ("leader_reaped", "original_group_exited", "original_session_exited",
                 "reaped_after_native_observation"))
                or value["native"].get("errors") != [] or value.get("errors") != []):
            raise ValueError("test-owned native PTY cleanup is incomplete")
    return {"scope": "original owned PTY groups/sessions, separately retained before reap",
            "sessions": list(ends.values()),
            "limitations": "No escaped-session, arbitrary process-tree, opaque Drop close-status or external-interruption claim"}


def shell_path(family, observations=None):
    candidates = [shutil.which(family)]
    if family == "bash":
        candidates = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash"] + candidates
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            path = Path(candidate).resolve()
            if family == "bash":
                version = run([str(path), "--version"], {"PATH": os.defpath},
                              observations=observations).stdout
                match = re.search(r"version (\d+)\.", version)
                if not match or int(match[1]) < 5:
                    continue
            return path
    return None


def isolated_env(root, candidate):
    """Allowlisted process environment; ambient bypass/session flags never pass."""
    return {"PATH": str(candidate.parent) + os.pathsep + os.environ.get("PATH", os.defpath),
            "HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"), "XDG_STATE_HOME": str(root / "state"),
            "TERM": "xterm-256color", "TIRITH_LOG": "0", "TIRITH_QUIET": "1",
            "TIRITH_OFFLINE": "1"}


def save_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    os.replace(temporary, path)


@contextmanager
def certification_root(report):
    """Retain failures, especially when process ownership/EOF is unproved."""
    root = Path(tempfile.mkdtemp(prefix="tirith-package-certification-")).resolve()
    report["fixture_root"] = str(root)
    report["fixture_removed"] = False
    completed = False
    try:
        yield root
        completed = True
    finally:
        processes = report["processes"]
        if (completed and report["state"] == "supported" and processes
                and all(all(row["cleanup"].values()) for row in processes)):
            shutil.rmtree(root)
            report["fixture_removed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path, help="candidate .tar.gz or .zip")
    parser.add_argument("--binary", required=True, type=Path, help="binary extracted from that package")
    parser.add_argument("--harness", required=True, type=Path,
                        help="compiled shell_conformance test executable from this checkout")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--shells", default="bash,zsh,fish")
    args = parser.parse_args()
    package, binary, harness = (path.resolve(strict=True)
                                for path in (args.package, args.binary, args.harness))
    families = args.shells.split(",")
    if not families or len(set(families)) != len(families) or any(
            family not in ("bash", "zsh", "fish") for family in families):
        parser.error("--shells must be a unique comma-separated subset of bash,zsh,fish")
    report = {
        "schema_version": 1, "started_at": int(time.time()),
        "runner_sha256": sha256(Path(__file__).resolve()),
        "owner_helper_sha256": sha256(OWNER_HELPER),
        "process_output_limit_bytes": MAX_PROCESS_OUTPUT_BYTES,
        "processes": [],
        "platform": {"system": os.uname().sysname, "release": os.uname().release,
                     "architecture": os.uname().machine},
        "package": {"name": package.name, "sha256": sha256(package)},
        "binary": {"sha256": sha256(binary)},
        "harness": {"sha256": sha256(harness)},
        "scope": "disposable native PTY sessions; packaged binary and its materialized hooks",
        "shells": [],
        "unavailable": ["native Windows PowerShell 5.1", "native Windows PowerShell 7",
                        "Unix PowerShell", "Nushell", "actual agent-host invocation"],
        "state": "running",
    }
    save_report(args.report, report)
    try:
        if packaged_binary_digest(package) != report["binary"]["sha256"]:
            raise ValueError("binary does not match the candidate package")
        with certification_root(report) as root:
            candidate = root / "installation" / "bin" / "tirith"
            candidate.parent.mkdir(parents=True)
            shutil.copy2(binary, candidate)
            candidate.chmod(0o700)
            env = isolated_env(root, candidate)
            for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
                Path(env[key]).mkdir()
            version = run([str(candidate), "--version"], env, observations=report["processes"])
            if version.returncode != 0:
                raise ValueError("candidate version probe failed")
            report["binary"]["version"] = version.stdout.strip()
            initialized = run([str(candidate), "init", "--shell", "bash"], env,
                              observations=report["processes"])
            lines = [line for line in initialized.stdout.splitlines() if line.startswith("source ")]
            if initialized.returncode != 0 or len(lines) != 1:
                raise ValueError("candidate could not materialize its own hook bundle")
            words = shlex.split(lines[0])
            hook = Path(words[1]).resolve(strict=True)
            if not hook.is_relative_to(root):
                raise ValueError("init selected an external hook bundle; use an isolated candidate environment")
            hooks = hook.parent
            report["hooks"] = {name: sha256(hooks / name) for name in HOOKS}
            report["hooks_version"] = (hooks.parent / ".hooks-version").read_text().strip()
            env.update(TIRITH_CERTIFY_BINARY=str(candidate), TIRITH_CERTIFY_HOOK_DIR=str(hooks))
            for family in families:
                row = {"family": family, "state": "running"}
                report["shells"].append(row)
                shell = shell_path(family, observations=report["processes"])
                if shell is None:
                    row.update(state="unavailable", reason="native executable is absent or unsupported")
                    save_report(args.report, report)
                    continue
                row["executable"] = str(shell)
                row["version"] = run([str(shell), "--version"], env,
                                     observations=report["processes"]).stdout.strip()
                row["executable_sha256"] = sha256(shell)
                env["TIRITH_CERTIFY_" + family.upper()] = str(shell)
                env["TIRITH_CERTIFY_SHELLS"] = family
                listing = run([str(harness), family + "_", "--list"], env,
                              observations=report["processes"])
                tests = [line.removesuffix(": test") for line in listing.stdout.splitlines()
                         if line.endswith(": test")]
                row["tests"] = tests
                if listing.returncode != 0 or not tests:
                    raise ValueError(f"harness has no {family} test cases")
                output = run([str(harness), family + "_", "--test-threads=1", "--nocapture"], env, 1200,
                             observations=report["processes"])
                log = args.report.with_name(args.report.stem + "-" + family + ".log")
                log.write_text(output.stdout)
                row["log"] = str(log.resolve())
                row["pty_cleanup"] = pty_cleanup_evidence(output.stdout)
                summary = re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", output.stdout)
                passed = bool(output.returncode == 0 and summary and
                              int(summary[1]) == len(tests) and summary[2] == "0" and summary[3] == "0"
                              and "skipping:" not in output.stdout.lower())
                row.update(state="supported" if passed else "failed", completed_at=int(time.time()))
                save_report(args.report, report)
            report["state"] = "supported" if all(row["state"] == "supported"
                                                  for row in report["shells"]) else "incomplete"
            if sha256(OWNER_HELPER) != OWNER_HELPER_SHA256:
                report["state"] = "failed"
                raise ValueError("owned-process helper changed during qualification")
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.TimeoutExpired,
            tarfile.TarError, zipfile.BadZipFile, KeyboardInterrupt) as error:
        report.update(state="failed", reason=str(error))
        for row in report["shells"]:
            if row["state"] == "running":
                row.update(state="failed", reason=str(error))
    report["completed_at"] = int(time.time())
    save_report(args.report, report)
    print(f"{report['state']}: {args.report.resolve()}")
    return 0 if report["state"] == "supported" else 1


if __name__ == "__main__":
    sys.exit(main())
