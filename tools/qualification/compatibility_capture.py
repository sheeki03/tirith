#!/usr/bin/env python3
"""Capture actual old/new CLI reader contracts in isolated native operator roots."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile

import mixed_audit_native as native

HASH = re.compile(r"[0-9a-f]{64}\Z")
CONTENT = b"echo inert compatibility fixture\n"
CONTENT_ID = hashlib.sha256(CONTENT).hexdigest()


def json_value(text):
    def reject_constant(_):
        raise ValueError("non-finite JSON")
    def finite_float(text):
        value = float(text)
        native.require(math.isfinite(value), "non-finite JSON number")
        return value
    def pairs(items):
        result = {}
        for key, value in items:
            native.require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant,
                      parse_float=finite_float)


def write_fixture(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)
    return {"path": str(path), "sha256": native.sha(data), "bytes": len(data)}


def receipt():
    return {
        "url": "https://fixture.example/inert.sh", "final_url": None, "redirects": [],
        "sha256": CONTENT_ID, "size": len(CONTENT), "domains_referenced": [],
        "paths_referenced": [], "analysis_method": "static", "privilege": "user",
        "timestamp": "2026-09-12T00:00:00Z", "cwd": None, "git_repo": None,
        "git_branch": None,
    }


def definitions():
    check = ["check", "--no-daemon", "--json", "--shell", "posix", "--"]
    pipe = "curl https://fixture.example/inert.sh | sh"
    cases = [
        {"name": "clean-command", "args": check + ["echo compatibility"], "exit": 0, "action": "allow"},
        {"name": "blocked-command", "args": check + [pipe], "exit": 1, "action": "block"},
        {"name": "personal-policy", "args": ["policy", "effective", "--format", "json"], "policy": "paranoia: 3\n", "exit": 0},
        {"name": "repository-policy", "args": ["policy", "effective", "--format", "json"], "repo_policy": "allowlist: ['fixture.example']\n", "exit": 0},
    ]
    for name, expiry, expected in [("permanent", None, "allow"), ("expired", "2000-01-01T00:00:00Z", "block"), ("invalid-expiry", "not-a-time", "block")]:
        cases.append({"name": "legacy-trust-" + name, "args": check + [pipe], "trust_expiry": expiry,
                      "exit": 0 if expected == "allow" else 1, "action": expected})
    for mode in ("blocks", "warn-only", "degraded", "off"):
        cases.append({"name": "reported-shell-" + mode, "args": ["doctor", "--quick", "--format", "json"],
                      "reported_mode": mode, "exit": 0})
    for route in ("list", "last", "verify"):
        args = ["receipt", route] + ([CONTENT_ID] if route == "verify" else []) + ["--json"]
        cases.append({"name": "download-receipt-" + route, "args": args, "receipt": "valid", "exit": 0})
    cases.extend([
        {"name": "download-receipt-cache-changed", "args": ["receipt", "verify", CONTENT_ID, "--json"], "receipt": "changed", "exit": 1},
        {"name": "download-receipt-cache-missing", "args": ["receipt", "verify", CONTENT_ID, "--json"], "receipt": "missing", "exit": 1},
    ])
    return cases


def validate(case, who, row):
    native.require(row["failure"] is None and all(row["cleanup"].get(key) is True for key in
                   ("leader_reaped", "group_signaled_or_absent", "group_members_exited", "output_eof")),
                   "native process did not complete cleanly")
    native.require(row["exit"] == case["exit"], "unexpected command exit")
    value = json_value(row["stdout"])
    native.require(isinstance(value, (dict, list)), "JSON command did not return an object or array")
    if "action" in case:
        native.require(isinstance(value, dict) and value.get("schema_version") == 3, "legacy check schema changed")
        native.require(value.get("action") == case["action"], "check/trust decision changed")
    if "policy" in case:
        native.require(value.get("scope") == "user" and value.get("policy", {}).get("paranoia") == 3,
                       "personal policy scope or value changed")
    if "repo_policy" in case:
        native.require(value.get("scope") == "repo" and value.get("policy", {}).get("allowlist") == [],
                       "repository policy introduced an untrusted suppression")
        native.require("allowlist" in value.get("neutralized_fields", []), "repository suppression was not explained")
    if "reported_mode" in case:
        expected_mode = "guarded" if case["reported_mode"] == "blocks" else case["reported_mode"]
        native.require(isinstance(value, dict) and type(value.get("schema_version")) is int
                       and value["schema_version"] == 1 and value.get("protection_mode") == expected_mode
                       and value.get("hook_configured") is False and "policy_path_used" in value
                       and value["policy_path_used"] is None, "legacy shell reporting contract changed")
        if who == "candidate":
            evidence = value.get("protection_evidence")
            native.require(isinstance(evidence, dict) and evidence.get("verified_blocking") is False
                           and evidence.get("fresh") is False and evidence.get("observed_at") is None,
                           "inherited environment was promoted to blocking proof")
    if case.get("receipt"):
        route = case["args"][1]
        if route == "list":
            native.require(type(value) is list and len(value) == 1, "receipt list shape or cardinality changed")
            selected = value[0]
        else:
            native.require(type(value) is dict, "receipt last/verify must return one object")
            selected = value
        if route == "verify":
            expected = {"sha256": CONTENT_ID, "url": receipt()["url"], "valid": case["receipt"] == "valid"}
            native.require(type(selected.get("valid")) is bool, "receipt verification must be boolean")
        else:
            expected = receipt()
            del expected["cwd"]
        native.require(selected == expected, "receipt public fields, identity or cached-byte verification changed")
    return {"top_level_keys": sorted(value) if isinstance(value, dict) else None,
            "json_kind": "object" if isinstance(value, dict) else "array",
            "value": value}


def run_case(output, case, who, binary):
    root = Path(tempfile.mkdtemp(prefix=case["name"] + "-" + who + "-", dir=output)).resolve()
    env = native.isolated_env(root)
    env.update(TIRITH_LOG="0", USERPROFILE=str(root), APPDATA=str(root / "appdata"),
               LOCALAPPDATA=str(root / "localappdata"), XDG_RUNTIME_DIR=str(root / "runtime"))
    result = {"case": case["name"], "client": who, "root": str(root), "passed": False,
              "fixtures": [], "fixture_origin": "synthetic compatibility inputs; native reader observations"}
    def put(path, data):
        result["fixtures"].append(write_fixture(path, data))
    if "policy" in case:
        put(root / "config/tirith/policy.yaml", case["policy"].encode())
    if "repo_policy" in case:
        (root / ".git").mkdir(mode=0o700)
        put(root / ".tirith/policy.yaml", case["repo_policy"].encode())
    if "trust_expiry" in case:
        store = {"entries": [{"pattern": "fixture.example", "rule_id": None, "ttl_expires": case["trust_expiry"]}]}
        put(root / "config/tirith/trust.json", json.dumps(store).encode())
    if "reported_mode" in case:
        env["TIRITH_STATUS"] = case["reported_mode"]
    if case.get("receipt"):
        put(root / "data/tirith/receipts" / (CONTENT_ID + ".json"), json.dumps(receipt()).encode())
        if case["receipt"] != "missing":
            put(root / "data/tirith/cache" / CONTENT_ID, CONTENT if case["receipt"] == "valid" else b"changed")
    try:
        job = native.Job(case["name"], [binary, *case["args"]], root, env)
        row = native.finish([job])[0]
        result["process"] = row
        result["projection"] = validate(case, who, row)
        for entry in result["fixtures"]:
            native.require(native.file_sha(Path(entry["path"])) == entry["sha256"], "reader rewrote a supplied fixture")
        result["passed"] = True
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    native.save_json(root / "case.json", result)
    return result


def version_capture(output, who, binary):
    root = Path(tempfile.mkdtemp(prefix="version-" + who + "-", dir=output)).resolve()
    env = native.isolated_env(root)
    env["TIRITH_LOG"] = "0"
    row = native.finish([native.Job("version", [binary, "--version"], root, env)])[0]
    native.success(row)
    match = re.fullmatch(r"tirith (\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\n?", row["stdout"])
    native.require(match is not None, "unrecognized native version output")
    if who == "baseline":
        native.require(match.group(1) == "0.4.2", "this contract capture requires the 0.4.2 baseline")
    return {"version": match.group(1), "process": row}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for who in ("baseline", "candidate"):
        parser.add_argument("--" + who, required=True, type=Path)
        parser.add_argument("--" + who + "-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    native.require(os.name == "posix", "this runner requires native POSIX process-group cleanup")
    native.require_process_observation()
    binaries, pins = {}, {}
    for who in ("baseline", "candidate"):
        path, expected = getattr(args, who), getattr(args, who + "_sha256")
        native.require(path.is_absolute() and HASH.fullmatch(expected), "absolute binaries and lowercase SHA-256 required")
        native.require(stat.S_ISREG(path.lstat().st_mode) and os.access(path, os.X_OK), "regular executable required")
        native.require(native.file_sha(path) == expected, "binary hash mismatch")
        binaries[who], pins[who] = path, expected
    native.require(pins["baseline"] != pins["candidate"], "distinct old/new binaries required")
    native.require(args.output.is_absolute() and args.output.parent.is_dir(), "absolute new output directory required")
    args.output.mkdir(mode=0o700)
    report = {"schema_version": 1, "kind": "native_cli_reader_compatibility", "passed": False,
              "binary_sha256": pins, "runner_sha256": native.file_sha(Path(__file__).resolve()),
              "process_helper_sha256": native.file_sha(Path(native.__file__).resolve()),
              "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
              "signature_verification_performed": False,
              "scope": "synthetic policy, legacy trust and download-receipt reader fixtures; inherited shell mode reporting is not live shell verification",
              "not_certified": ["native shell interception", "receipt producer/signature/publication authority", "all historical receipt schemas", "final release installation"],
              "versions": {}, "cases": []}
    try:
        for who, binary in binaries.items():
            report["versions"][who] = version_capture(args.output, who, binary)
        for case in definitions():
            for who, binary in binaries.items():
                report["cases"].append(run_case(args.output, case, who, binary))
        for who, binary in binaries.items():
            native.require(native.file_sha(binary) == pins[who], "binary changed during capture")
        native.require(native.file_sha(Path(__file__).resolve()) == report["runner_sha256"],
                       "runner source changed during capture")
        native.require(native.file_sha(Path(native.__file__).resolve()) == report["process_helper_sha256"],
                       "process helper source changed during capture")
        report["passed"] = all(case["passed"] for case in report["cases"])
    finally:
        native.save_json(args.output / "report.json", report)
    print(json.dumps({"passed": report["passed"], "cases": len(report["cases"]), "report": str(args.output / "report.json")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"compatibility capture failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
