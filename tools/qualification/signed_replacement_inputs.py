#!/usr/bin/env python3
"""Read-only source/build capture for the test-only signed replacement fixture.

Never invokes Cargo, a compiler, a product, Git, or a network operation. Source
captures must bracket an independently authorized build. Recorded build facts
and retained Cargo output are evidence, not a signature or build attestation.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import sys


MIB = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
TARGETS = {("Darwin", "arm64"): "aarch64-apple-darwin",
           ("Darwin", "x86_64"): "x86_64-apple-darwin",
           ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
           ("Linux", "x86_64"): "x86_64-unknown-linux-gnu"}
# Explicit complete local workspace scopes, including compile-time embedded
# fixtures/assets, every local workspace package and compatibility generator.
SCOPES = ("Cargo.toml", "Cargo.lock", "crates", "tools/sign-license",
          "tools/license-server", "tools/policy-server", "threatdb-manifest.json",
          ".github/scripts/release-compatibility.py", "tools/qualification/mixed_audit_native.py")
OPTIONAL = (".cargo", "rust-toolchain", "rust-toolchain.toml", "build.rs")
GENERATOR_INPUTS = ("Cargo.toml", ".github/scripts/release-compatibility.py",
                    "crates/tirith-core/src/policy_migrations.rs",
                    "crates/tirith-core/src/mcp_lock.rs", "crates/tirith-core/src/trust_grants.rs",
                    "crates/tirith/src/cli/setup/change_plan.rs",
                    "crates/tirith/src/cli/control/lifecycle.rs",
                    "crates/tirith-core/src/policy_team.rs",
                    "crates/tirith/src/cli/npm_materialize.rs",
                    "crates/tirith-core/src/artifact/npm_materialize.rs")


def require(value, message):
    if not value:
        raise ValueError(message)


def strict_keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label + ": unknown/missing fields")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {"sha256": digest(raw), "size": len(raw)}


def valid_identity(value, cap):
    strict_keys(value, ("sha256", "size"), "file identity")
    require(type(value["sha256"]) is str and SHA.fullmatch(value["sha256"]) and
            type(value["size"]) is int and 0 < value["size"] <= cap, "invalid bounded identity")


def native_target():
    target = TARGETS.get((platform.system(), platform.machine()))
    require(target is not None, "unsupported native fixture host")
    if platform.system() == "Linux":
        require(platform.libc_ver()[0] == "glibc", "GNU fixture target requires native glibc")
    return target


def admit_python():
    require(sys.version_info >= (3, 11) and sys.platform in ("darwin", "linux"),
            "fixture tooling requires Python3.11+ on native macOS or Linux")
    require(all(hasattr(os, field) for field in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")),
            "native no-follow file/directory admission is unavailable")


def interpreter_identity():
    path = Path(sys.executable).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 512 * MIB,
                "interpreter is not a bounded regular executable")
        h = hashlib.sha256()
        count = 0
        while True:
            part = os.read(fd, MIB)
            if not part:
                break
            count += len(part)
            require(count <= 512 * MIB, "interpreter grew beyond cap")
            h.update(part)
        require(native_token(before) == native_token(os.fstat(fd)) == native_token(path.lstat()),
                "interpreter image changed during observation")
        return {"path": str(path), "sha256": h.hexdigest(), "size": count,
                "version": sys.version, "implementation": sys.implementation.name}
    finally:
        os.close(fd)


def native_token(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class HeldFile:
    """No-follow bounded regular file; retain generation until final revalidation."""
    def __init__(self, path, cap, private=False, allow_empty=False):
        self.path, self.cap, self.fd = Path(path), cap, None
        before = self.path.lstat()
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            held = os.fstat(self.fd)
            require(native_token(before) == native_token(held), "file changed during capture")
            require(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid() and held.st_nlink == 1
                    and held.st_mode & 0o022 == 0 and (0 if allow_empty else 1) <= held.st_size <= cap,
                    "input is not a bounded owner-held regular file")
            require(not private or stat.S_IMODE(held.st_mode) == 0o600, "metadata must be mode0600")
            self.token = native_token(held)
            self.identity = {"sha256": self.hash(), "size": held.st_size}
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def chunks(self):
        os.lseek(self.fd, 0, os.SEEK_SET)
        count = 0
        while True:
            part = os.read(self.fd, min(MIB, self.cap + 1 - count))
            if not part:
                break
            count += len(part)
            require(count <= self.cap, "file grew beyond cap")
            yield part

    def hash(self):
        h = hashlib.sha256()
        for part in self.chunks():
            h.update(part)
        return h.hexdigest()

    def read(self):
        return b"".join(self.chunks())

    def revalidate(self):
        require(native_token(os.fstat(self.fd)) == self.token and
                native_token(self.path.lstat()) == self.token and self.hash() == self.identity["sha256"] and
                native_token(os.fstat(self.fd)) == self.token and
                native_token(self.path.lstat()) == self.token,
                "retained file bytes or generation changed")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def duplicate_checked(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=duplicate_checked,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid bounded JSON") from error


def load_json(path, cap=MIB):
    with HeldFile(path, cap) as held:
        raw = held.read()
        held.revalidate()
        return parse_json(raw), identity(raw)


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def scan_source(root):
    root = Path(root)
    require(root.is_absolute() and root.resolve(strict=True) == root, "source root must be canonical")
    files, missing, entries, total = [], [], 0, 0

    def visit(path, depth=0):
        nonlocal entries, total
        entries += 1
        require(entries <= 8192 and depth <= 64 and len(str(path).encode()) <= 8192,
                "source entry/depth/path bound exceeded")
        st = path.lstat()
        require(not stat.S_ISLNK(st.st_mode), "source symlink is outside the closed capture")
        if stat.S_ISDIR(st.st_mode):
            require(st.st_uid == os.getuid() and st.st_mode & 0o022 == 0, "source directory is writable by others")
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                token = native_token(st)
                require(native_token(os.fstat(fd)) == token, "source directory changed during capture")
                children = []
                with os.scandir(fd) as listing:
                    for child in listing:
                        require(len(children) < 8192 - entries, "source directory exceeds entry bound")
                        children.append(child.name)
                for name in sorted(children):
                    visit(path / name, depth + 1)
                require(native_token(os.fstat(fd)) == token == native_token(path.lstat()),
                        "source directory changed during traversal")
            finally:
                os.close(fd)
        else:
            require(len(files) < 4096, "source file bound exceeded")
            # Empty local source/fixture files are valid. Executables and
            # metadata retain their separate positive-size admission rule.
            with HeldFile(path, 64 * MIB, allow_empty=True) as held:
                file_id = dict(held.identity)
            total += file_id["size"]
            require(total <= 1024 * MIB, "source byte bound exceeded")
            files.append({"path": path.relative_to(root).as_posix(), **file_id})

    for scope in SCOPES:
        visit(root / scope)
    for scope in OPTIONAL:
        try:
            (root / scope).lstat()
        except FileNotFoundError:
            missing.append(scope)
        else:
            visit(root / scope)
    files.sort(key=lambda row: row["path"])
    paths = [row["path"] for row in files]
    require(len(paths) == len(set(paths)), "duplicate source input")
    value = {"root": str(root), "scopes": list(SCOPES), "optional_absent": missing, "files": files}
    require(len(canonical(value)) <= MIB - 8192, "source manifest exceeds fixed cap")
    return value


def check_capture(value, stage):
    strict_keys(value, ("schema_version", "contract", "stage", "captured_at", "source"), "source capture")
    require(value["schema_version"] == 1 and type(value["schema_version"]) is int and
            value["contract"] == "tirith_signed_fixture_source_capture_v1" and value["stage"] == stage,
            "wrong source capture role")
    timestamp = datetime.datetime.fromisoformat(value["captured_at"])
    require(timestamp.tzinfo is not None, "capture timestamp lacks timezone")
    return timestamp


def cargo_artifact(path, executable, profile_test, source_root):
    with HeldFile(path, 16 * MIB) as held:
        raw = held.read()
        evidence = dict(held.identity)
    require(len(raw.splitlines()) <= 16384, "Cargo output line cap exceeded")
    rows = [parse_json(line) for line in raw.splitlines() if line.strip()]
    require(rows and all(type(row) is dict for row in rows) and
            rows[-1].get("reason") == "build-finished" and rows[-1].get("success") is True,
            "Cargo output does not retain a successful completed build")
    selected = [row for row in rows if row.get("reason") == "compiler-artifact" and
                row.get("executable") == str(executable) and row.get("target", {}).get("name") == "tirith"]
    require(len(selected) == 1, "Cargo output must identify exactly one requested tirith executable")
    record = selected[0]
    target = record.get("target", {})
    package_root = source_root / "crates/tirith"
    require(record.get("manifest_path") == str(package_root / "Cargo.toml") and
            target.get("src_path") == str(package_root / "src/main.rs") and
            record.get("package_id") == "path+" + package_root.as_uri() + "#0.4.2",
            "Cargo artifact does not belong to the captured source checkout")
    require(target.get("kind") == ["bin"] and
            record.get("profile", {}).get("test") is profile_test,
            "Cargo target/test role differs from requested image")
    if not profile_test:
        require(record["profile"].get("debug_assertions") is False and
                record["profile"].get("opt_level") == "3", "candidate must use the release product profile")
    return record, evidence


def admit_build(value, binary, cargo_json):
    strict_keys(value, ("schema_version", "contract", "role", "profile_test", "build_profile", "version",
                       "target", "binary", "source_before", "source_after", "source", "cargo_output",
                       "cargo_artifact", "rustc_verbose", "cargo_verbose"), "build input manifest")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and
            value["contract"] == "tirith_signed_fixture_build_input_v1", "wrong build manifest contract")
    test = value["role"] == "test_harness"
    require(value["role"] in ("test_harness", "product") and value["profile_test"] is test and
            value["build_profile"] == ("test" if test else "release"), "build role/profile mismatch")
    require(value["version"] == "0.4.2" and value["target"] == native_target(), "non-native or wrong-version image")
    for name in ("rustc_verbose", "cargo_verbose"):
        require(type(value[name]) is str and 0 < len(value[name]) <= 8192, "missing verbose compiler identity")
    require("host: " + value["target"] in value["rustc_verbose"], "compiler host differs from native target")
    require(value["binary"] == {"path": str(binary.path), **binary.identity}, "build manifest binary differs")
    actual, output_id = cargo_artifact(cargo_json, Path(value["cargo_artifact"]["executable"]),
                                       test, Path(value["source"]["root"]))
    require(actual == value["cargo_artifact"] and output_id == value["cargo_output"], "retained Cargo evidence differs")
    captures = []
    for field, stage in (("source_before", "before"), ("source_after", "after")):
        ref = value[field]
        strict_keys(ref, ("path", "identity"), "retained source capture")
        valid_identity(ref["identity"], MIB)
        capture, capture_id = load_json(Path(ref["path"]))
        require(capture_id == ref["identity"] and capture["source"] == value["source"],
                "retained before/after source capture differs")
        captures.append(check_capture(capture, stage))
    require(captures[0] <= captures[1], "retained source capture order differs")
    require(scan_source(Path(value["source"]["root"])) == value["source"], "source closure changed after build capture")
    return test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture-source")
    capture.add_argument("--root", type=Path, required=True)
    capture.add_argument("--stage", choices=("before", "after"), required=True)
    capture.add_argument("--output", type=Path, required=True)
    seal = sub.add_parser("seal-build")
    seal.add_argument("--before", type=Path, required=True)
    seal.add_argument("--after", type=Path, required=True)
    seal.add_argument("--binary", type=Path, required=True)
    seal.add_argument("--cargo-json", type=Path, required=True)
    seal.add_argument("--cargo-executable", type=Path, required=True,
                      help="Actual original executable path recorded by Cargo before retaining a copy")
    seal.add_argument("--role", choices=("test_harness", "product"), required=True)
    seal.add_argument("--rustc-verbose", type=Path, required=True)
    seal.add_argument("--cargo-verbose", type=Path, required=True)
    seal.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    admit_python()
    if args.command == "capture-source":
        value = {"schema_version": 1, "contract": "tirith_signed_fixture_source_capture_v1",
                 "stage": args.stage, "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "source": scan_source(args.root)}
    else:
        before, before_id = load_json(args.before)
        after, after_id = load_json(args.after)
        require(check_capture(before, "before") <= check_capture(after, "after"), "source capture order differs")
        require(before["source"] == after["source"] == scan_source(Path(after["source"]["root"])),
                "source changed before/during/after the retained build")
        test = args.role == "test_harness"
        with HeldFile(args.binary, (512 if test else 256) * MIB) as binary:
            record, cargo_id = cargo_artifact(args.cargo_json, args.cargo_executable,
                                             test, Path(after["source"]["root"]))
            # Confirm the retained copy is exactly Cargo's selected output.
            with HeldFile(args.cargo_executable, (512 if test else 256) * MIB) as original:
                require(binary.identity == original.identity, "retained executable differs from Cargo output")
            versions = {}
            for name in ("rustc_verbose", "cargo_verbose"):
                with HeldFile(getattr(args, name), 8192) as held:
                    versions[name] = held.read().decode().strip()
            value = {"schema_version": 1, "contract": "tirith_signed_fixture_build_input_v1",
                     "role": args.role, "profile_test": test, "build_profile": "test" if test else "release",
                     "version": "0.4.2", "target": native_target(),
                     "binary": {"path": str(args.binary), **binary.identity},
                     "source_before": {"path": str(args.before), "identity": before_id},
                     "source_after": {"path": str(args.after), "identity": after_id},
                     "source": after["source"], "cargo_output": cargo_id,
                     "cargo_artifact": record, **versions}
            admit_build(value, binary, args.cargo_json)
    raw = canonical(value)
    require(len(raw) <= MIB, "build/source metadata exceeds cap")
    write_new(args.output, raw)
    print(json.dumps({"status": "captured_local_build_facts_not_attestation", "output": str(args.output),
                      "identity": identity(raw)}))


if __name__ == "__main__":
    main()
