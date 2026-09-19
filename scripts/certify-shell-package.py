#!/usr/bin/env python3
"""Run native PTY tests against the binary embedded in a release package.

The report certifies only the exercised shell modes. Agent hosts and native
platforms absent from this run remain unavailable, never inferred from config.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

MAX_BINARY_BYTES = 512 * 1024 * 1024
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


def run(command, env, timeout=15):
    process = subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, output)


def shell_path(family):
    candidates = [shutil.which(family)]
    if family == "bash":
        candidates = ["/opt/homebrew/bin/bash", "/usr/local/bin/bash"] + candidates
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            path = Path(candidate).resolve()
            if family == "bash":
                version = run([str(path), "--version"], {"PATH": os.defpath}).stdout
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
        with tempfile.TemporaryDirectory(prefix="tirith-package-certification-") as temporary:
            root = Path(temporary).resolve()
            candidate = root / "installation" / "bin" / "tirith"
            candidate.parent.mkdir(parents=True)
            shutil.copy2(binary, candidate)
            candidate.chmod(0o700)
            env = isolated_env(root, candidate)
            for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
                Path(env[key]).mkdir()
            version = run([str(candidate), "--version"], env)
            if version.returncode != 0:
                raise ValueError("candidate version probe failed")
            report["binary"]["version"] = version.stdout.strip()
            initialized = run([str(candidate), "init", "--shell", "bash"], env)
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
                shell = shell_path(family)
                if shell is None:
                    row.update(state="unavailable", reason="native executable is absent or unsupported")
                    save_report(args.report, report)
                    continue
                row["executable"] = str(shell)
                row["version"] = run([str(shell), "--version"], env).stdout.strip()
                row["executable_sha256"] = sha256(shell)
                env["TIRITH_CERTIFY_" + family.upper()] = str(shell)
                env["TIRITH_CERTIFY_SHELLS"] = family
                listing = run([str(harness), family + "_", "--list"], env)
                tests = [line.removesuffix(": test") for line in listing.stdout.splitlines()
                         if line.endswith(": test")]
                row["tests"] = tests
                if listing.returncode != 0 or not tests:
                    raise ValueError(f"harness has no {family} test cases")
                output = run([str(harness), family + "_", "--test-threads=1", "--nocapture"], env, 1200)
                log = args.report.with_name(args.report.stem + "-" + family + ".log")
                log.write_text(output.stdout)
                row["log"] = str(log.resolve())
                summary = re.search(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", output.stdout)
                passed = bool(output.returncode == 0 and summary and
                              int(summary[1]) == len(tests) and summary[2] == "0" and summary[3] == "0"
                              and "skipping:" not in output.stdout.lower())
                row.update(state="supported" if passed else "failed", completed_at=int(time.time()))
                save_report(args.report, report)
            report["state"] = "supported" if all(row["state"] == "supported"
                                                  for row in report["shells"]) else "incomplete"
    except (OSError, ValueError, subprocess.TimeoutExpired, tarfile.TarError, zipfile.BadZipFile) as error:
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
