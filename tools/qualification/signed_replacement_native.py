#!/usr/bin/env python3
"""Owned native signed replacement/rollback fixture; explicit test-image substitution.

Signs only with public RFC8032 test-vector material. Never downloads, builds,
installs into user roots, invokes the ordinary update route, or claims official
release acceptance. Every failed observation and fixture root is retained.
"""
import argparse
import contextlib
import ctypes
import datetime
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
import tarfile
import time
import types
import uuid
import zlib

import signed_replacement_inputs as inputs

require = inputs.require
MIB = inputs.MIB
HELPER_SHA = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
TEST = "cli::selfupdate::signed_fixture_tests::signed_native_self_replacement_and_rollback"
MARKER = "TIRITH_SIGNED_REPLACEMENT_FIXTURE_V1_COMPLETE"
EXTRACTOR_MARKER = "TIRITH_SIGNED_REPLACEMENT_EXTRACTOR_COMPLETED"
AUTHORITY = "fixture_key_signed_checksums_not_official_release"
STORAGE_CAP = 3 * 1024 * MIB
TOTAL_SECONDS = 600
DIRS = ("home", "home/.local", "home/.local/bin", "home/.config", "home/.config/tirith",
        "inputs", "inputs/candidate", "inputs/release", "data", "state", "cache", "tmp",
        "workspace", "workspace/.git", "workspace/.tirith")
PRESERVED = {
    "policy": ("home/.config/tirith/policy.yaml",
               b"schema_version: 2\ntask_gate:\n  mode: enforce\n  effects_denied_for_untrusted_sources: []\n"),
    "startup": ("home/.zshrc", b"# retained signed replacement fixture; never sourced\n"),
    "legacy_trust": ("home/.config/tirith/trust.json", b'{"version":1,"entries":[]}\n'),
    "scoped_grants": ("home/.config/tirith/trust-grants.json", b'{"schema_version":1,"grants":[]}\n'),
    "mcp_lock": ("workspace/.tirith/mcp.lock", inputs.canonical({"format_version": 8,
                 "inventory_hash": hashlib.sha256(b"").hexdigest(), "configs": [], "servers": []})),
}
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
EMPTY_SIGNATURE = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                               "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


class Deadline:
    def __init__(self):
        self.start = time.monotonic()

    def check(self):
        require(time.monotonic() - self.start < TOTAL_SECONDS, "fixture preparation/execution deadline exceeded")


class OwnedRoot:
    def __init__(self, output):
        require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent,
                "output parent must be an existing canonical absolute path")
        parent = output.parent.stat()
        require(parent.st_uid == os.getuid() and parent.st_mode & 0o022 == 0,
                "output parent is writable by another identity")
        output.mkdir(mode=0o700)
        self.output = output
        self.fixture_id = str(uuid.uuid4())
        self.root = output / ("tirith-signed-replacement-" + self.fixture_id)
        self.root.mkdir(mode=0o700)
        self.directories = []
        self.hold_directory(output)
        self.hold_directory(self.root)
        for name in DIRS:
            path = self.root / name
            path.mkdir(mode=0o700)
            self.hold_directory(path)

    def hold_directory(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(fd)
        token = (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode))
        require(token[2:] == (os.getuid(), 0o700), "fixture directory is not owner-private")
        self.directories.append((path, fd, token))

    def revalidate(self):
        for path, fd, token in self.directories:
            for st in (os.fstat(fd), path.lstat()):
                require(stat.S_ISDIR(st.st_mode) and
                        (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode)) == token,
                        "owned fixture directory changed")

    def close(self):
        for _, fd, _ in reversed(self.directories):
            os.close(fd)
        self.directories = []

    def env(self, manifest=False):
        env = {"HOME": str(self.root / "home"), "XDG_CONFIG_HOME": str(self.root / "home/.config"),
               "XDG_DATA_HOME": str(self.root / "data"), "XDG_STATE_HOME": str(self.root / "state"),
               "XDG_CACHE_HOME": str(self.root / "cache"), "TMPDIR": str(self.root / "tmp"),
               "PATH": str(self.root / "home/.local/bin") + ":/usr/bin:/bin",
               "LANG": "C", "LC_ALL": "C", "TIRITH_LOG": "1"}
        if manifest:
            env["TIRITH_TEST_SIGNED_REPLACEMENT_MANIFEST"] = str(self.root / "manifest.json")
        return env


def native_image(held, target):
    os.lseek(held.fd, 0, os.SEEK_SET)
    header = os.read(held.fd, 64)
    if target.endswith("apple-darwin"):
        require(len(header) >= 32 and header[:4] == b"\xcf\xfa\xed\xfe", "expected one native 64-bit Mach-O image")
        cpu, _, kind = struct.unpack_from("<III", header, 4)
        require(cpu == (0x100000C if target.startswith("aarch64") else 0x1000007) and kind == 2,
                "Mach-O target or executable kind differs")
        libc = ctypes.CDLL(None, use_errno=True)
        value = ctypes.c_int(0)
        size = ctypes.c_size_t(ctypes.sizeof(value))
        status = libc.sysctlbyname(b"sysctl.proc_translated", ctypes.byref(value), ctypes.byref(size), None, 0)
        # This key is absent on native Intel macOS. Absence is not a translated process.
        require((status == 0 and value.value == 0) or
                (status == -1 and ctypes.get_errno() == 2), "translated/unknown process architecture")
    else:
        require(len(header) >= 64 and header[:6] == b"\x7fELF\x02\x01", "expected native little-endian 64-bit ELF")
        kind, machine = struct.unpack_from("<HH", header, 16)
        require(kind in (2, 3) and machine == (183 if target.startswith("aarch64") else 62),
                "ELF target or executable kind differs")
    held.revalidate()


def load_module(name, held):
    module = types.ModuleType(name)
    module.__file__ = str(held.path)
    sys.modules[name] = module
    exec(compile(held.read(), str(held.path), "exec"), module.__dict__)
    held.revalidate()
    return module


def copy_image(held, destination, deadline):
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
    try:
        os.fchmod(fd, 0o755)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            for part in held.chunks():
                deadline.check()
                stream.write(part)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    held.revalidate()
    with inputs.HeldFile(destination, held.cap) as copied:
        require(copied.identity == held.identity, "retained copy hash differs")


class BoundedWriter:
    def __init__(self, stream, deadline, cap):
        self.stream, self.deadline, self.cap, self.total = stream, deadline, cap, 0

    def write(self, block):
        self.deadline.check()
        require(self.total + len(block) <= self.cap, "compressed archive exceeds 64MiB fixture cap")
        self.total += len(block)
        return self.stream.write(block)

    def flush(self):
        self.stream.flush()


def archive_fixture(candidate, path, deadline):
    # Exact USTAR subset: one header, one actual candidate, only zero padding.
    entry = tarfile.TarInfo("tirith")
    entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = candidate.identity["size"], 0o755, 0, 0, 0
    entry.uname = entry.gname = ""
    header = entry.tobuf(format=tarfile.USTAR_FORMAT)
    require(len(header) == 512, "USTAR header is not one block")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as raw:
            writer = BoundedWriter(raw, deadline, 64 * MIB)
            with gzip.GzipFile(filename="", mode="wb", fileobj=writer, mtime=0) as compressed:
                compressed.write(header)
                for part in candidate.chunks():
                    deadline.check()
                    compressed.write(part)
                compressed.write(b"\0" * ((-entry.size) % 512 + 1024))
            raw.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    candidate.revalidate()
    with inputs.HeldFile(path, 64 * MIB, private=True) as archive:
        admit_archive(archive, candidate.identity, deadline)
        return dict(archive.identity)


def admit_archive(held, candidate, deadline):
    expected_header = tarfile.TarInfo("tirith")
    expected_header.size, expected_header.mode = candidate["size"], 0o755
    expected_header.uid = expected_header.gid = expected_header.mtime = 0
    expected_header.uname = expected_header.gname = ""
    expected_header = expected_header.tobuf(format=tarfile.USTAR_FORMAT)
    decompressor = zlib.decompressobj(wbits=31)
    header, total, payload = bytearray(), 0, hashlib.sha256()
    expansion = 512 + candidate["size"] + (-candidate["size"] % 512) + 1024

    def consume(block):
        nonlocal total
        deadline.check()
        start = total
        total += len(block)
        require(total <= expansion, "archive expanded beyond exact single-member bound")
        if start < 512:
            header.extend(block[:min(len(block), 512 - start)])
        a, b = max(512 - start, 0), min(512 + candidate["size"] - start, len(block))
        if b > a:
            payload.update(block[a:b])
        padding = max(512 + candidate["size"] - start, 0)
        if padding < len(block):
            require(not any(block[padding:]), "archive has extra member or nonzero padding")

    for part in held.chunks():
        pending = part
        while pending:
            block = decompressor.decompress(pending, MIB)
            consume(block)
            pending = decompressor.unconsumed_tail
            require(not decompressor.unused_data, "concatenated/trailing gzip data is forbidden")
    consume(decompressor.flush())
    require(decompressor.eof and total == expansion and bytes(header) == expected_header and
            payload.hexdigest() == candidate["sha256"], "independent archive/member/hash admission failed")
    held.revalidate()


def sign_checksums(body):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    require(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == PUBLIC and
            private.sign(b"") == EMPTY_SIGNATURE, "RFC8032 signing self-check failed")
    signature = private.sign(body)
    Ed25519PublicKey.from_public_bytes(PUBLIC).verify(signature, body)
    refused = False
    try:
        Ed25519PrivateKey.from_private_bytes(b"\x01" * 32).public_key().verify(signature, body)
    except InvalidSignature:
        refused = True
    require(refused, "wrong-key cryptographic control unexpectedly accepted")
    return signature


def storage_inventory(root, deadline):
    total, count, identities = 0, 0, []
    for directory, names, files in os.walk(root, followlinks=False):
        deadline.check()
        for name in names + files:
            path = Path(directory) / name
            st = path.lstat()
            count += 1
            require(count <= 4096 and not stat.S_ISLNK(st.st_mode), "unexpected fixture tree entry")
            require(st.st_uid == os.getuid() and st.st_mode & 0o022 == 0, "fixture entry lost ownership")
            if stat.S_ISREG(st.st_mode):
                require(st.st_nlink == 1, "unexpected fixture hardlink")
                total += st.st_size
                require(total <= STORAGE_CAP, "fixture owned storage exceeded 3GiB bound")
                require(st.st_size <= 512 * MIB, "unexpected oversized fixture file")
                with inputs.HeldFile(path, 512 * MIB, allow_empty=True) as held:
                    file_id = dict(held.identity)
                identities.append({"path": path.relative_to(root).as_posix(), **file_id})
            else:
                require(stat.S_ISDIR(st.st_mode), "unexpected special fixture entry")
    return {"entries": count, "regular_file_bytes": total, "ceiling_bytes": STORAGE_CAP,
            "files": sorted(identities, key=lambda row: row["path"])}


def completed(row):
    require(row["exit"] == 0 and row["failure"] is None, "native child did not exit successfully")
    inputs.strict_keys(row["cleanup"], ("leader_reaped", "group_signaled_or_absent",
                                      "group_members_exited", "output_eof"), "owned cleanup")
    require(all(value is True for value in row["cleanup"].values()), "not all four native cleanup facts passed")


def run_job(shared, jobs, name, argv, owned, env, deadline):
    deadline.check()
    owned.revalidate()
    job = shared.Job(name, argv, owned.root / "workspace", env, timeout=45)
    jobs.append(job)
    row = shared.finish([job])[0]
    inputs.write_new(owned.output / (name + ".json"), inputs.canonical(row))
    owned.revalidate()
    deadline.check()
    return row


def admit_test_output(row):
    completed(row)
    stdout = row["stdout"]
    require(stdout.splitlines().count(EXTRACTOR_MARKER) == 1, "normal trusted extractor completion missing/repeated")
    require(stdout.splitlines().index(EXTRACTOR_MARKER) < stdout.splitlines().index(MARKER)
            if MARKER in stdout.splitlines() else False, "extractor/rollback completion order differs")
    require(stdout.splitlines().count(MARKER) == 1, "exact completion marker missing/repeated")
    require(stdout.count("test " + TEST + " ... ") == 1 and stdout.splitlines().count("running 1 test") == 1,
            "unexpected selected native test count/name")
    summaries = re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [^\n]+$",
                           stdout, re.MULTILINE)
    require(len(summaries) == 1 and "test result: FAILED" not in stdout, "selected libtest outcome differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", required=True, type=Path)
    parser.add_argument("--test-source-manifest", required=True, type=Path)
    parser.add_argument("--test-cargo-json", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--candidate-source-manifest", required=True, type=Path)
    parser.add_argument("--candidate-cargo-json", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    owned, jobs, shared = None, [], None
    result = {"schema_version": 1, "status": "refused", "authority": AUTHORITY,
              "claim": "same-version test image -> retained product -> original test image",
              "official_signed_release_compatibility": False,
              "crash_or_power_loss_claim": False, "nested_process_tree_cleanup_attested": False,
              "nested_cleanup_evidence": "extractor_not_started", "jobs": [], "observations": {}}
    deadline = Deadline()
    try:
        inputs.admit_python()
        result["interpreter"] = inputs.interpreter_identity()
        require(os.getuid() != 0, "fixture must not run as root")
        owned = OwnedRoot(args.output_dir)
        result["fixture_root"] = str(owned.root)
        with contextlib.ExitStack() as stack:
            def held(path, cap, private=False):
                return stack.enter_context(inputs.HeldFile(path, cap, private))
            runner_source = held(Path(__file__).resolve(strict=True), MIB)
            inputs_source = held(Path(inputs.__file__).resolve(strict=True), MIB)
            inputs.write_new(owned.output / "runner-source.py", runner_source.read())
            inputs.write_new(owned.output / "inputs-source.py", inputs_source.read())
            result["runner_sources"] = {"runner": runner_source.identity, "inputs": inputs_source.identity}
            test_image = held(args.test_executable, 512 * MIB)
            product = held(args.candidate, 256 * MIB)
            test_manifest = held(args.test_source_manifest, MIB)
            product_manifest = held(args.candidate_source_manifest, MIB)
            test_build, product_build = inputs.parse_json(test_manifest.read()), inputs.parse_json(product_manifest.read())
            require(inputs.admit_build(test_build, test_image, args.test_cargo_json) is True and
                    inputs.admit_build(product_build, product, args.candidate_cargo_json) is False,
                    "test/product build roles were substituted")
            target = inputs.native_target()
            native_image(test_image, target)
            native_image(product, target)
            require(test_image.identity["sha256"] != product.identity["sha256"], "test image is not the product")
            result["inputs"] = {"test_image": test_image.identity, "product": product.identity,
                                "test_source_manifest": test_manifest.identity,
                                "candidate_source_manifest": product_manifest.identity}
            test_files = {row["path"]: {"sha256": row["sha256"], "size": row["size"]}
                          for row in test_build["source"]["files"]}
            product_files = {row["path"]: {"sha256": row["sha256"], "size": row["size"]}
                             for row in product_build["source"]["files"]}
            differences = [name for name in sorted(set(test_files) | set(product_files))
                           if test_files.get(name) != product_files.get(name)]
            result["observations"]["source_comparison"] = {"identical_closure": not differences,
                                                            "different_paths": differences}
            require(all(test_files.get(name) == product_files.get(name) for name in inputs.GENERATOR_INPUTS),
                    "test/product format contract generator inputs differ")
            root = Path(product_build["source"]["root"])
            helper = held(root / "tools/qualification/mixed_audit_native.py", MIB)
            require(helper.identity["sha256"] == HELPER_SHA, "owned helper differs from reviewed schema-2 helper")
            shared = load_module("signed_fixture_owned_helper", helper)
            shared.require_process_observation()
            generator = held(root / ".github/scripts/release-compatibility.py", MIB)
            expected_files = {row["path"]: {"sha256": row["sha256"], "size": row["size"]}
                              for row in product_build["source"]["files"]}
            generator_inputs = {}
            for path in inputs.GENERATOR_INPUTS:
                source = held(root / path, 64 * MIB)
                require(source.identity == expected_files[path], "compatibility generator input changed")
                generator_inputs[path] = dict(source.identity)
            compatibility_module = load_module("signed_fixture_release_contract", generator)
            compatibility = compatibility_module.contract(root, "0.4.2")
            # Conservative upper bound includes all current/extracted/backup
            # generations and metadata, before any product/test process starts.
            reserved = 3 * test_image.identity["size"] + 4 * product.identity["size"] + 2 * 64 * MIB + 64 * MIB
            require(reserved <= STORAGE_CAP, "cannot bound this test/product layout within 3GiB")
            disk = os.statvfs(owned.root)
            require(disk.f_bavail * disk.f_frsize >= reserved + 64 * MIB, "insufficient owned-fixture free space")
            result["observations"]["storage_preflight"] = {"reserved_bytes": reserved, "cap_bytes": STORAGE_CAP}
            install = owned.root / "home/.local/bin/tirith"
            candidate = owned.root / "inputs/candidate/tirith"
            copy_image(test_image, install, deadline)
            copy_image(product, candidate, deadline)
            for _, (path, body) in PRESERVED.items():
                inputs.write_new(owned.root / path, body)
            inputs.write_new(owned.root / "inputs/test-source.json", test_manifest.read())
            inputs.write_new(owned.root / "inputs/candidate-source.json", product_manifest.read())
            retained_build_inputs = []
            for role, build, cargo_path in (("test", test_build, args.test_cargo_json),
                                            ("candidate", product_build, args.candidate_cargo_json)):
                cargo = held(cargo_path, 16 * MIB)
                require(cargo.identity == build["cargo_output"], "Cargo output changed before retention")
                inputs.write_new(owned.output / (role + "-cargo.jsonl"), cargo.read())
                retained_build_inputs.append(cargo)
                for stage in ("before", "after"):
                    ref = build["source_" + stage]
                    source_capture = held(Path(ref["path"]), MIB)
                    require(source_capture.identity == ref["identity"], "source capture changed before retention")
                    inputs.write_new(owned.output / (role + "-source-" + stage + ".json"), source_capture.read())
                    retained_build_inputs.append(source_capture)
            # Product provenance is a separate owned native observation before
            # packing. It does not prove that the swapped-in image later started.
            provenance = run_job(shared, jobs, "candidate-provenance",
                                 [candidate, "version", "--provenance", "--json"], owned, owned.env(), deadline)
            completed(provenance)
            facts = inputs.parse_json(provenance["stdout"])
            require(facts.get("version") == "0.4.2" and facts.get("target") == target and
                    facts.get("binary_sha256") == product.identity["sha256"] and
                    facts.get("binary_path") == str(candidate) and facts.get("build_profile") == "release",
                    "actual retained candidate provenance differs from the admitted release image")
            result["observations"]["candidate_provenance"] = facts
            archive_name = "tirith-" + target + ".tar.gz"
            archive_path = owned.root / "inputs/release" / archive_name
            archive_id = archive_fixture(product, archive_path, deadline)
            compatibility["targets"] = {target: {"archive": archive_name,
                                                "archive_sha256": archive_id["sha256"],
                                                "binary_sha256": product.identity["sha256"]}}
            compatibility_raw = inputs.canonical(compatibility)
            require(len(compatibility_raw) <= 256 * MIB // 1024, "compatibility cap exceeded")
            inputs.write_new(owned.root / "inputs/release/release-compatibility.json", compatibility_raw)
            checksums = (archive_id["sha256"] + "  " + archive_name + "\n" +
                         inputs.digest(compatibility_raw) + "  release-compatibility.json\n").encode()
            signature = sign_checksums(checksums)
            inputs.write_new(owned.root / "inputs/release/checksums.txt", checksums)
            inputs.write_new(owned.root / "inputs/release/checksums.fixture.ed25519", signature)
            result["observations"].update(fixture_signature_python_verified=True,
                                          public_rfc8032_vector_self_check=True,
                                          wrong_public_key_rejected=True,
                                          independent_archive_admission=True,
                                          private_signing_key_written=False,
                                          cryptography_version=importlib.metadata.version("cryptography"),
                                          compatibility_generator_inputs=generator_inputs)
            manifest = {"schema_version": 1, "contract": "tirith_signed_replacement_fixture_v1",
                        "fixture_id": owned.fixture_id, "root": str(owned.root), "version": "0.4.2",
                        "target": target, "authority": AUTHORITY,
                        "test_executable": {"kind": "test_harness_not_product", "profile_test": True,
                                            "identity": test_image.identity},
                        "candidate": {"kind": "retained_product", "profile_test": False,
                                      "identity": product.identity},
                        "archive": archive_id, "checksums": inputs.identity(checksums),
                        "signature": inputs.identity(signature), "compatibility": inputs.identity(compatibility_raw),
                        "test_source_manifest": test_manifest.identity, "candidate_source_manifest": product_manifest.identity,
                        "preserved": {key: inputs.identity(body) for key, (_, body) in PRESERVED.items()}}
            manifest_raw = inputs.canonical(manifest)
            require(len(manifest_raw) <= 32 * 1024, "fixture manifest cap exceeded")
            inputs.write_new(owned.root / "manifest.json", manifest_raw)
            immutable = []
            for path, cap, private in [("manifest.json", 32 * 1024, True),
                    ("inputs/candidate/tirith", 256 * MIB, False),
                    ("inputs/test-source.json", MIB, True), ("inputs/candidate-source.json", MIB, True),
                    ("inputs/release/" + archive_name, 64 * MIB, True),
                    ("inputs/release/checksums.txt", 256 * 1024, True),
                    ("inputs/release/checksums.fixture.ed25519", 64, True),
                    ("inputs/release/release-compatibility.json", 256 * 1024, True),
                    *[(path, 64 * 1024, True) for path, _ in PRESERVED.values()]]:
                immutable.append(held(owned.root / path, cap, private))
            inputs.write_new(owned.output / "environment.json", inputs.canonical(owned.env(True)))
            result["observations"]["storage_before"] = storage_inventory(owned.output, deadline)

            for item in immutable:
                item.revalidate()
            with inputs.HeldFile(install, 512 * MIB) as selected_test:
                require(selected_test.identity == test_image.identity, "selected test image changed before execution")
            # trusted_child owns a separate extractor process group. A timeout
            # here cannot be treated as evidence that that nested group exited.
            result["nested_cleanup_evidence"] = "unknown_after_outer_failure"
            row = run_job(shared, jobs, "native-signed-replacement",
                          [install, "--exact", TEST, "--ignored", "--nocapture", "--test-threads=1"],
                          owned, owned.env(True), deadline)
            admit_test_output(row)
            # Exact native rollback readback. These paths are part of the Rust ABI.
            with inputs.HeldFile(install, 512 * MIB) as current:
                require(current.identity == test_image.identity, "rollback did not restore original test image")
            with inputs.HeldFile(install.with_name("tirith.tirith-previous"), 512 * MIB) as backup:
                require(backup.identity == test_image.identity, "retained backup differs from original test image")
            for item in immutable:
                item.revalidate()
            for item in (test_image, product, test_manifest, product_manifest, helper, generator,
                         runner_source, inputs_source):
                item.revalidate()
            for item in retained_build_inputs:
                item.revalidate()
            inputs.admit_build(test_build, test_image, args.test_cargo_json)
            inputs.admit_build(product_build, product, args.candidate_cargo_json)
            result["observations"].update(final_install_identity=test_image.identity,
                                          final_backup_identity=test_image.identity,
                                          retained_inputs_and_configuration_unchanged=True,
                                          storage_after=storage_inventory(owned.output, deadline))
            result["status"] = "fixture_native_replacement_and_rollback_passed"
            result["nested_cleanup_evidence"] = "trusted_extractor_completed_normally_no_process_tree_attestation"
    except BaseException as error:
        result["error"] = type(error).__name__ + ": " + str(error)[:4096]
    finally:
        for job in jobs:
            if not job.cleanup_attempted:
                job.kill()
            row = job.result()
            result["jobs"].append(row)
            try:
                completed(row)
            except ValueError:
                result["status"] = "refused"
        result["native_helper_sha256"] = HELPER_SHA
        result["elapsed_seconds"] = round(time.monotonic() - deadline.start, 6)
        result["limitations"] = ["Public fixture signing key; not official release/Sigstore verification.",
                                 "Same-version test executable/product substitution is explicit.",
                                 "Candidate provenance is observed before packing/swap, not proof of startup after swap.",
                                 "No numeric upgrade, shell reload, service quiescence, user installation, crash, power loss, Windows, or package-channel claim.",
                                 "Local source/build records are retained evidence, not independent build attestation.",
                                 "The trusted extractor owns a separate process group. Outer cleanup does not attest that nested group; any outer failure leaves nested cleanup unknown.",
                                 "This lane observes normal extraction completion only; it injects no interruption, extractor crash, timeout, or power-loss event."]
        if owned is not None:
            try:
                owned.revalidate()
            except BaseException as error:
                result["status"] = "refused"
                result["final_root_error"] = str(error)[:1024]
            if result["status"] != "fixture_native_replacement_and_rollback_passed" and result["nested_cleanup_evidence"] != "extractor_not_started":
                result["nested_cleanup_evidence"] = "unknown_after_outer_failure"
            rendered = inputs.canonical(result)
            require(len(rendered) <= MIB, "result exceeds fixed evidence cap")
            inputs.write_new(owned.output / "result.json", rendered)
            owned.close()
        else:
            print(inputs.canonical(result).decode(), end="")
    print(json.dumps({"status": result["status"], "output": str(args.output_dir),
                      "official_signed_release_compatibility": False}))
    return 0 if result["status"] == "fixture_native_replacement_and_rollback_passed" else 2


if __name__ == "__main__":
    sys.exit(main())
