#!/usr/bin/env python3
"""Bind non-executable upgrade compatibility facts to exact release payloads."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tomllib
import zipfile

ASSET = "release-compatibility.json"
ARCHIVE_CAP = 64 * 1024 * 1024
BINARY_CAP = 256 * 1024 * 1024
UNPACKED_CAP = 512 * 1024 * 1024
TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
)


def source_constant(root: Path, path: str, name: str) -> int:
    matches = re.findall(rf"\bconst\s+{re.escape(name)}\s*:\s*u32\s*=\s*(\d+)\s*;", (root / path).read_text())
    if len(matches) != 1:
        raise ValueError(f"cannot uniquely bind {name} to its implementation")
    return int(matches[0])


# Every persisted-state contract version and the implementation constants it
# covers (owned-change journal schema, control-service protocol, team record
# schema and policy semantics, shell receipt schemas). A changed constant needs
# a new reviewed contract version, never an automatically widened claim.
STATE_CONTRACTS = {
    1: {"journal": 1, "protocol": 1, "team": 1, "semantics": 1, "receipt": 3, "acknowledged_receipt": 4},
}


def contract(root: Path, version: str) -> dict:
    actual = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if version != actual or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("release version must equal the workspace release version")
    policy = source_constant(root, "crates/tirith-core/src/policy_migrations.rs", "CURRENT_SCHEMA_VERSION")
    lock = source_constant(root, "crates/tirith-core/src/mcp_lock.rs", "MCP_LOCK_FORMAT_VERSION")
    grants = source_constant(root, "crates/tirith-core/src/trust_grants.rs", "STORE_VERSION")
    state = source_constant(root, "crates/tirith/src/cli/lifecycle_formats.rs", "STATE_CONTRACT_VERSION")
    implementation = {
        "journal": source_constant(root, "crates/tirith/src/cli/setup/change_plan.rs", "SCHEMA"),
        "protocol": source_constant(root, "crates/tirith/src/cli/control/lifecycle.rs", "PROTOCOL"),
        "team": source_constant(root, "crates/tirith-core/src/policy_team.rs", "SCHEMA_VERSION"),
        "semantics": source_constant(root, "crates/tirith-core/src/policy_team.rs", "POLICY_SEMANTICS_VERSION"),
        "receipt": source_constant(root, "crates/tirith-core/src/execution_state/shell_receipt.rs", "RECEIPT_SCHEMA_VERSION"),
        "acknowledged_receipt": source_constant(root, "crates/tirith-core/src/execution_state/shell_receipt.rs", "ACKNOWLEDGED_RECEIPT_SCHEMA_VERSION"),
    }
    if STATE_CONTRACTS.get(state) != implementation:
        raise ValueError("persisted state implementation changed; bump STATE_CONTRACT_VERSION and review the compatibility contract before release")
    # A changed format needs a reviewed reader/migration contract, not an
    # automatically widened claim that every intervening version is supported.
    if (policy, lock, grants) != (2, 8, 1):
        raise ValueError("format implementation changed; review the compatibility contract before release")
    return {
        "schema_version": 2,
        "version": version,
        "policy_read_versions": [1, 2],
        "mcp_lock_read_versions": [4, 5, 6, 7, 8],
        "mcp_lock_authorize_versions": [8],
        "legacy_trust_read_versions": [1],
        "scoped_grant_read_versions": [1],
        "state_contract_versions": [state],
    }


def member_name(name: str) -> str:
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or ":" in name or not path.parts:
        raise ValueError("archive member escapes its root")
    return str(path)


def archive_identity(path: Path, target: str) -> dict:
    if not path.is_file() or path.stat().st_size > ARCHIVE_CAP:
        raise ValueError(f"missing or oversized archive for {target}")
    with path.open("rb") as stream:
        archive_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    binary_name = "tirith.exe" if target.endswith("windows-msvc") else "tirith"
    binary = None
    names = set()
    total = 0
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 4096:
                raise ValueError("archive member count exceeds limit")
            for entry in entries:
                name = member_name(entry.filename)
                if name in names:
                    raise ValueError("duplicate archive member")
                names.add(name)
                total += entry.file_size
                if total > UNPACKED_CAP or entry.file_size > BINARY_CAP:
                    raise ValueError("archive expands beyond limit")
                if stat.S_ISLNK(entry.external_attr >> 16):
                    raise ValueError("archive contains a symbolic link")
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError("archive contains a special file")
                if mode == stat.S_IFDIR and not entry.is_dir():
                    raise ValueError("archive member type disagrees with its name")
                if name == binary_name and not entry.is_dir():
                    binary = archive.read(entry)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for count, entry in enumerate(archive, 1):
                name = member_name(entry.name)
                if count > 4096 or name in names:
                    raise ValueError("duplicate or excessive archive members")
                names.add(name)
                total += entry.size
                if total > UNPACKED_CAP or entry.size > BINARY_CAP:
                    raise ValueError("archive expands beyond limit")
                if not entry.isfile() and not entry.isdir():
                    raise ValueError("archive contains a link or special file")
                if name == binary_name and entry.isfile():
                    stream = archive.extractfile(entry)
                    assert stream is not None
                    binary = stream.read(BINARY_CAP + 1)
    if not binary or len(binary) > BINARY_CAP:
        raise ValueError(f"archive lacks a bounded root {binary_name}")
    return {"archive": path.name, "archive_sha256": archive_sha, "binary_sha256": hashlib.sha256(binary).hexdigest()}


def build(root: Path, artifacts: Path, version: str) -> dict:
    document = contract(root, version)
    document["targets"] = {}
    for target in TARGETS:
        suffix = ".zip" if target.endswith("windows-msvc") else ".tar.gz"
        document["targets"][target] = archive_identity(artifacts / f"tirith-{target}{suffix}", target)
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    document = build(args.root, args.artifacts, args.version.removeprefix("v"))
    output = args.artifacts / ASSET
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"wrote {ASSET}; include it in the signed checksums payload")


if __name__ == "__main__":
    main()
