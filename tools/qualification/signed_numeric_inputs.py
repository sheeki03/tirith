#!/usr/bin/env python3
"""Strict build admission for the owned 0.4.2 -> 0.4.3 numeric fixture.

Read-only except for a newly created evidence output. Does not build, download,
execute a product, edit a source tree, or accept official release authority.
The existing v1 capture tool is reused unchanged; v1 build records are not
relabelled. Source captures must bracket each separately authorized build.
"""
import argparse
import copy
from pathlib import Path
import re
import tomllib

import signed_replacement_inputs as base

PIN = "d398b167eac3a672aa5996fe93c0a8ba47ab571c6dd747f777fafe02b43fac80"
CONTRACT = "tirith_signed_numeric_build_input_v1"
VERSIONS = ("0.4.2", "0.4.3")
require = base.require
BUILD_FIELDS = ("schema_version", "contract", "role", "profile_test", "build_profile", "version",
                "target", "binary", "source_before", "source_after", "source", "cargo_output",
                "cargo_artifact", "rustc_verbose", "cargo_verbose")


def admit_base():
    with base.HeldFile(Path(base.__file__).resolve(strict=True), base.MIB) as held:
        require(held.identity["sha256"] == PIN, "existing v1 capture helper differs from its byte pin")
    base.admit_python()


def source_file(source, relative):
    rows = [row for row in source["files"] if row["path"] == relative]
    require(len(rows) == 1, "source input is missing or repeated: " + relative)
    with base.HeldFile(Path(source["root"]) / relative, 64 * base.MIB, allow_empty=True) as held:
        require(held.identity == {key: rows[0][key] for key in ("sha256", "size")},
                "source input changed: " + relative)
        return held.read()


def source_version(source):
    version = tomllib.loads(source_file(source, "Cargo.toml").decode())["workspace"]["package"]["version"]
    require(type(version) is str and version in VERSIONS, "source version is outside the exact numeric pair")
    return version


def version_variant_bytes(source):
    """Return the only permitted byte changes, without writing a source variant."""
    original = source_file(source, "Cargo.toml")
    document = tomllib.loads(original.decode())
    require(document["workspace"]["package"]["version"] == VERSIONS[0], "base source must be 0.4.2")
    members = document["workspace"]["members"]
    require(type(members) is list and 1 <= len(members) <= 16 and len(set(members)) == len(members),
            "workspace member set is not bounded and unique")
    names = []
    for member in members:
        require(type(member) is str and re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)+", member),
                "workspace member is outside the closed path profile")
        package = tomllib.loads(source_file(source, member + "/Cargo.toml").decode())["package"]
        require(package["version"] == {"workspace": True} and type(package["name"]) is str,
                "workspace member does not inherit the admitted version")
        names.append(package["name"])
    require(len(set(names)) == len(names), "duplicate workspace package names")
    updated = original
    for old, new in ((b'[workspace.package]\nversion = "0.4.2"\n',
                      b'[workspace.package]\nversion = "0.4.3"\n'),
                     (b'tirith-core = { version = "0.4.2", path = "crates/tirith-core" }',
                      b'tirith-core = { version = "0.4.3", path = "crates/tirith-core" }')):
        require(updated.count(old) == 1, "manifest version byte shape changed; review the variant contract")
        updated = updated.replace(old, new)
    expected = copy.deepcopy(document)
    expected["workspace"]["package"]["version"] = "0.4.3"
    expected["workspace"]["dependencies"]["tirith-core"]["version"] = "0.4.3"
    require(tomllib.loads(updated.decode()) == expected, "manifest variant contains a non-version change")
    lock = source_file(source, "Cargo.lock")
    parsed = tomllib.loads(lock.decode())
    modified = lock
    expected_lock = copy.deepcopy(parsed)
    for name in names:
        rows = [row for row in expected_lock["package"] if row["name"] == name and "source" not in row]
        require(len(rows) == 1 and rows[0]["version"] == "0.4.2" and "checksum" not in rows[0],
                "local lock package does not match the workspace")
        rows[0]["version"] = "0.4.3"
        old = ('[[package]]\nname = "' + name + '"\nversion = "0.4.2"\n').encode()
        new = old.replace(b'"0.4.2"', b'"0.4.3"')
        require(modified.count(old) == 1, "local lock package byte shape is ambiguous")
        modified = modified.replace(old, new)
    require(tomllib.loads(modified.decode()) == expected_lock, "lock variant changes another dependency")
    return {"Cargo.toml": updated, "Cargo.lock": modified}


def admit_source_pair(old, new):
    require(old["scopes"] == new["scopes"] == list(base.SCOPES) and
            old["optional_absent"] == new["optional_absent"], "source closure scope differs")
    require(source_version(old) == "0.4.2" and source_version(new) == "0.4.3", "numeric pair order differs")
    before = {row["path"]: row for row in old["files"]}
    after = {row["path"]: row for row in new["files"]}
    require(len(before) == len(old["files"]) and len(after) == len(new["files"]) and
            set(before) == set(after), "variant adds, removes or duplicates source paths")
    differences = sorted(name for name in before if before[name] != after[name])
    require(differences == ["Cargo.lock", "Cargo.toml"], "variant must change only Cargo.toml and Cargo.lock")
    for relative, expected in version_variant_bytes(old).items():
        require(source_file(new, relative) == expected, "variant contains an unapproved byte delta: " + relative)
    return differences


def cargo_artifact(path, executable, profile_test, source_root, version):
    require(version in VERSIONS and (not profile_test or version == "0.4.2"), "invalid controller/product version")
    with base.HeldFile(path, 16 * base.MIB) as held:
        raw, evidence = held.read(), dict(held.identity)
    require(len(raw.splitlines()) <= 16384, "Cargo output line cap exceeded")
    rows = [base.parse_json(line) for line in raw.splitlines() if line.strip()]
    require(rows and all(type(row) is dict for row in rows) and rows[-1].get("reason") == "build-finished"
            and rows[-1].get("success") is True, "Cargo output lacks successful completion")
    selected = [row for row in rows if row.get("reason") == "compiler-artifact" and
                row.get("executable") == str(executable) and row.get("target", {}).get("name") == "tirith"]
    require(len(selected) == 1, "Cargo output must select exactly one tirith executable")
    row = selected[0]
    package = source_root / "crates/tirith"
    require(row.get("manifest_path") == str(package / "Cargo.toml") and
            row["target"].get("src_path") == str(package / "src/main.rs") and
            row.get("package_id") == "path+" + package.as_uri() + "#" + version,
            "Cargo package source/version differs")
    require(row["target"].get("kind") == ["bin"] and row.get("profile", {}).get("test") is profile_test,
            "Cargo target/test role differs")
    if not profile_test:
        require(row["profile"].get("debug_assertions") is False and row["profile"].get("opt_level") == "3",
                "ordinary product requires the release profile")
    return row, evidence


def admit_build(value, binary, cargo_json):
    base.strict_keys(value, BUILD_FIELDS, "numeric build manifest")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and
            value["contract"] == CONTRACT, "wrong numeric build manifest contract")
    test = value["role"] == "test_harness"
    require(value["role"] in ("test_harness", "product") and value["profile_test"] is test and
            value["build_profile"] == ("test" if test else "release"), "build role/profile differs")
    require(value["version"] == source_version(value["source"]) and value["target"] == base.native_target(),
            "build source version or native target differs")
    for key in ("rustc_verbose", "cargo_verbose"):
        require(type(value[key]) is str and 0 < len(value[key]) <= 8192, "missing compiler identity")
    require("host: " + value["target"] in value["rustc_verbose"], "compiler is not native")
    require(value["binary"] == {"path": str(binary.path), **binary.identity}, "binary identity differs")
    row, evidence = cargo_artifact(cargo_json, Path(value["cargo_artifact"]["executable"]), test,
                                   Path(value["source"]["root"]), value["version"])
    require(row == value["cargo_artifact"] and evidence == value["cargo_output"], "Cargo evidence changed")
    times = []
    for field, stage in (("source_before", "before"), ("source_after", "after")):
        ref = value[field]
        base.strict_keys(ref, ("path", "identity"), "source capture reference")
        base.valid_identity(ref["identity"], base.MIB)
        capture, identity = base.load_json(Path(ref["path"]))
        require(identity == ref["identity"] and capture["source"] == value["source"], "source capture differs")
        times.append(base.check_capture(capture, stage))
    require(times[0] <= times[1] and base.scan_source(Path(value["source"]["root"])) == value["source"],
            "source changed around the retained build")
    binary.revalidate()
    return test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cargo-json", type=Path, required=True)
    parser.add_argument("--cargo-executable", type=Path, required=True)
    parser.add_argument("--role", choices=("test_harness", "product"), required=True)
    parser.add_argument("--rustc-verbose", type=Path, required=True)
    parser.add_argument("--cargo-verbose", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    admit_base()
    before, before_id = base.load_json(args.before)
    after, after_id = base.load_json(args.after)
    require(base.check_capture(before, "before") <= base.check_capture(after, "after"), "capture order differs")
    require(before["source"] == after["source"] == base.scan_source(Path(after["source"]["root"])),
            "source changed before/during/after build")
    version = source_version(after["source"])
    test = args.role == "test_harness"
    with base.HeldFile(args.binary, (512 if test else 256) * base.MIB) as binary:
        row, cargo_id = cargo_artifact(args.cargo_json, args.cargo_executable, test,
                                       Path(after["source"]["root"]), version)
        with base.HeldFile(args.cargo_executable, binary.cap) as original:
            require(original.identity == binary.identity, "retained binary differs from Cargo output")
        identities = {}
        for key in ("rustc_verbose", "cargo_verbose"):
            with base.HeldFile(getattr(args, key), 8192) as held:
                identities[key] = held.read().decode().strip()
        value = {"schema_version": 1, "contract": CONTRACT, "role": args.role, "profile_test": test,
                 "build_profile": "test" if test else "release", "version": version, "target": base.native_target(),
                 "binary": {"path": str(args.binary), **binary.identity}, "cargo_output": cargo_id,
                 "cargo_artifact": row, "source": after["source"],
                 "source_before": {"path": str(args.before), "identity": before_id},
                 "source_after": {"path": str(args.after), "identity": after_id}, **identities}
        admit_build(value, binary, args.cargo_json)
        raw = base.canonical(value)
        require(len(raw) <= base.MIB, "numeric build record exceeds cap")
        base.write_new(args.output, raw)
    print(base.canonical({"status": "captured_local_numeric_build_facts_not_attestation",
                          "identity": base.identity(raw), "version": version}).decode(), end="")


if __name__ == "__main__":
    main()
