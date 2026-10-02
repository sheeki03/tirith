#!/usr/bin/env python3
"""Real owned-volume ENOSPC and signed process-death recovery, explicit opt-in.

The six signed boundaries are observable native process states, not fsync or
power-loss claims. ENOSPC requires a separately admitted 64 MiB macOS image.
All keys are RFC 8032 public test-vector material. No caller configuration is read.
"""
import argparse
import base64
import datetime
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys

import durable_boundaries_native as durable
import mixed_audit_native as shared
from owned_full_volume import OwnedFullVolume

require = shared.require
STAGES = ("before-archive", "archive-published", "barrier-before-truncate", "empty-after-truncate",
          "genesis-before-head", "applied-before-result")
ROUTES = tuple("signed-" + stage for stage in STAGES) + ("signed-cancel", "enospc-audit", "enospc-profile")


def admit_candidate(manifest, path, digest):
    value = manifest.get("tirith_product")
    require(isinstance(value, dict) and value.get("profile_test") is False
            and value.get("sha256") == digest and value.get("path") == str(path),
            "candidate must be the manifest's exact non-test tirith_product")


def verify_fixture_signature(value):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require(isinstance(value, dict), "signed fixture must be a JSON object")
    unsigned = dict(value)
    encoded = unsigned.pop("sig", None)
    require(isinstance(encoded, str), "signature missing from signed fixture")
    signature = base64.b64decode(encoded, validate=True)
    require(len(signature) == 64, "invalid fixture signature length")
    # The closed ASCII fixture contains only objects, arrays, strings, integral
    # counts, booleans and null. This independently verifies the product's sorted
    # canonical JSON representation with the published public key.
    body = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    Ed25519PublicKey.from_public_bytes(shared.FIXTURE_PUBLIC).verify(signature, body)


class SignedCase(durable.Case):
    def __init__(self, output, name, binary):
        super().__init__(output, name, binary)
        self.key = self.root / "config/tirith/audit-signing.key"
        self.key.parent.mkdir(mode=0o700)
        self.key.write_bytes(shared.FIXTURE_SEED)
        self.key.chmod(0o600)
        self.key.with_suffix(".pub").write_bytes(shared.FIXTURE_PUBLIC)
        self.observations["signing_fixture"] = "RFC8032 section 7.1 test vector 1; publicly disclosed, non-operator key"

    def verify(self, count):
        rows = shared.check_rows(shared.read_bytes(self.log), True, count)
        for value in rows:
            verify_fixture_signature(value)
        verify_fixture_signature(json.loads(shared.read_bytes(self.head)))
        shared.verify_output(self.run("verify", ["audit", "verify"]), True, count)

    def prepare_rotation(self):
        super().prepare_rotation()
        self.verify(1)
        for field in ("checkpoint", "genesis", "genesis_head"):
            verify_fixture_signature(json.loads(bytes(self.plan[field])))
        self.observations["planned_signatures_verified"] = True

    def verify_archive(self):
        manifest = super().verify_archive()
        checkpoint = json.loads(shared.read_bytes(self.archive / "checkpoint.json"))
        verify_fixture_signature(checkpoint)
        require(checkpoint.get("operation_id") == self.id and checkpoint.get("signing_expected") is True,
                "signed checkpoint operation/baseline mismatch")
        active = shared.check_rows(shared.read_bytes(self.log), True, 1)[0]
        require(active.get("checkpoint_id") == self.id and active.get("checkpoint_sha256") == manifest["checkpoint_sha256"]
                and active.get("archived_log_sha256") == shared.sha(self.original), "signed genesis/archive linkage differs")
        # Verify the exact retained archive/head under the actual candidate in a
        # separate private data root; do not replace the active generation.
        data = self.root / "archive-verification"
        (data / "tirith").mkdir(mode=0o700, parents=True)
        copied = data / "tirith/log.jsonl"
        copied.write_bytes(self.original)
        copied.chmod(0o600)
        copied.with_name("log.jsonl.head").write_bytes(self.original_head)
        job = shared.Job("verify-signed-archive", [self.binary, "audit", "verify"], self.root,
                         dict(self.env, XDG_DATA_HOME=str(data)))
        self.jobs.append(job)
        shared.verify_output(self.finish(job)[0], True, 1)
        self.observations["checkpoint_signature_and_archive_verified"] = True
        return manifest

    def complete(self, procedure):
        try:
            result = super().complete(procedure)
        finally:
            self.key.unlink(missing_ok=True)
        result["fixture_private_key_removed"] = not self.key.exists()
        require(result["fixture_private_key_removed"], "fixture key cleanup failed")
        shared.save_json(self.root / "case.json", result)
        return result


class VolumeCase(durable.Case):
    def __init__(self, output, name, binary, volume):
        super().__init__(output, name, binary)
        self.volume = volume
        if name == "enospc-audit":
            data = volume.directory("audit-data")
            self.env["XDG_DATA_HOME"] = str(data)
            self.log = data / "tirith/log.jsonl"
            self.head = self.log.with_name("log.jsonl.head")
            self.archive = self.log.parent / "audit-segments" / self.id
        else:
            config = volume.directory("profile-config")
            self.env["XDG_CONFIG_HOME"] = str(config)
            self.policy = config / "tirith/policy.yaml"
        shared.save_json(self.root / "environment.json", self.env)

    def start(self, *args, **kwargs):
        self.volume.revalidate()
        return super().start(*args, **kwargs)

    def finish(self, *jobs):
        rows = super().finish(*jobs)
        self.volume.revalidate()
        return rows


def pressure_row(row, command, expected_exit, expected_action):
    durable.clean(row, expected_exit)
    require(json.loads(row["stdout"])["action"] == expected_action, "ENOSPC changed the security verdict for " + command)
    require("audit append failed" in row["stderr"], "missing visible audit failure while full")


def enospc_audit(case):
    case.append("space-baseline")
    blocked = case.run("baseline-block", ["check", "--no-daemon", "--format", "json", "--", "curl https://example.com | bash"])
    durable.clean(blocked, 1)
    require(json.loads(blocked["stdout"])["action"] == "block", "expected baseline block missing")
    require("audit append failed" not in blocked["stderr"], "baseline audit failed before pressure")
    case.verify(2)
    original, head, identity = shared.read_bytes(case.log), shared.read_bytes(case.head), durable.identity(case.log)
    before = case.snapshot()
    case.observations["actual_enospc"] = case.volume.fill()
    try:
        rows = []
        for label, command, code, action in (("allow", "echo full-volume", 0, "allow"),
                                             ("block", "curl https://example.com | bash", 1, "block")):
            row = case.run("full-" + label, ["check", "--no-daemon", "--format", "json", "--", command])
            pressure_row(row, command, code, action)
            rows.append(row)
        require(any("No space left on device" in row["stderr"] for row in rows),
                "product did not report ENOSPC; primitive exhaustion alone does not qualify its failure path")
        after = case.snapshot()
        case.observations["full_before"] = before
        case.observations["full_after"] = after
        require(durable.identity(case.log) == identity, "full-volume failure replaced active log inode")
        require(shared.read_bytes(case.log).startswith(original), "full-volume failure changed original audit prefix")
        require(shared.read_bytes(case.head) == head, "full-volume failure changed the committed head")
    finally:
        case.volume.release()
    if after == before:
        case.verify(2)
        case.append("space-recovered")
        case.verify(3)
        case.observations["reopen"] = "exact unchanged history verified; fresh append verified after space recovered"
    else:
        failed = case.run("verify-after-space", ["audit", "verify"])
        durable.refusal(failed, "head receipt does not match log tail", stream="stdout")
        require("FAILED" in failed["stdout"], "integrity refusal summary missing")
        frozen = case.snapshot()
        refused = case.run("rotate-after-space", ["audit", "rotate", "--operation-id", case.id, "--json"])
        durable.refusal(refused, "audit integrity must verify before retention; inspect audit verify")
        require(case.snapshot() == frozen, "refused recovery rewrote incomplete audit history")
        case.observations["reopen"] = "retained original prefix/head; explicit integrity refusal after partial append"


def enospc_profile(case):
    case.prepare_profile()
    before = durable.fingerprint(case.policy)
    case.observations["actual_enospc"] = case.volume.fill()
    try:
        state = durable.operation_state(case.operation("apply"), {"recovery-required"})
        require("No space left on device" in state.get("detail", ""), "policy publication did not report ENOSPC")
        require(durable.fingerprint(case.policy) == before, "failed policy publication changed original generation")
        require(not durable.lock_busy(case.execution_lock), "failed publisher kept operation lock")
        case.observations["failed_publication"] = state
    finally:
        case.volume.release()
    durable.operation_state(case.operation("status"), {"recovery-required"})
    durable.operation_state(case.operation("apply"), {"completed", "completed-with-recovery"})
    durable.strict_profile_published(case.policy)
    completed = durable.fingerprint(case.policy)
    durable.operation_state(case.operation("apply"), {"completed", "completed-with-recovery"})
    require(durable.fingerprint(case.policy) == completed, "completed replay rewrote policy generation")
    durable.operation_state(case.operation("undo"), {"undone", "undone-with-recovery"})
    require(shared.read_bytes(case.policy) == case.original, "undo did not restore exact original policy")
    undone = durable.fingerprint(case.policy)
    durable.operation_state(case.operation("undo"), {"undone", "undone-with-recovery"})
    require(durable.fingerprint(case.policy) == undone, "undo replay rewrote policy generation")
    case.observations["reopen"] = "exact intended policy published after freeing space; replay stable and undo exact"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", action="append", choices=ROUTES)
    parser.add_argument("--create-owned-64m-image", action="store_true")
    parser.add_argument("--filesystem", choices=("hfs", "apfs"), default="hfs")
    args = parser.parse_args(argv)
    require(os.geteuid() != 0, "ordinary user required")
    shared.require_process_observation()
    require(len(args.sha256) == 64 and all(c in "0123456789abcdef" for c in args.sha256), "canonical SHA256 required")
    require(shared.file_sha(args.candidate) == args.sha256, "candidate hash mismatch")
    manifest_body = shared.read_bytes(args.candidate_manifest)
    manifest = json.loads(manifest_body)
    admit_candidate(manifest, args.candidate, args.sha256)
    selected = args.case or list(ROUTES)
    require(len(selected) == len(set(selected)), "duplicate route")
    image_requested = any(name.startswith("enospc-") for name in selected)
    require(not image_requested or args.create_owned_64m_image, "ENOSPC needs explicit owned image opt-in")
    require(not args.output.exists(), "output must be a new private directory")
    args.output.mkdir(mode=0o700, parents=True)
    output = args.output.resolve()
    sources = {str(path): shared.file_sha(path) for path in (Path(__file__).resolve(), Path(shared.__file__).resolve(),
               Path(durable.__file__).resolve(), Path(sys.modules[OwnedFullVolume.__module__].__file__).resolve())}
    report = {"schema_version": 1, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "native frozen debug candidate; process death and owned filesystem exhaustion; not release qualification",
              "candidate": {"path": str(args.candidate), "sha256": args.sha256,
                            "manifest_sha256": shared.sha(manifest_body)},
              "python": {"path": sys.executable, "version": sys.version, "sha256": shared.file_sha(Path(sys.executable).resolve())},
              "platform": platform.platform(), "sources": sources, "requested": selected, "cases": [], "passed": False}
    (output / "candidate.json").write_bytes(manifest_body)
    if any(name.startswith("signed-") for name in selected):
        report["cryptography_version"] = importlib.metadata.version("cryptography")
    volume = None
    try:
        if image_requested:
            directory = output / "owned-volume"
            directory.mkdir(mode=0o700)
            volume = OwnedFullVolume(directory, filesystem=args.filesystem)
            volume.create()
        for name in selected:
            if name.startswith("signed-"):
                case = SignedCase(output, name, args.candidate)
                procedure = durable.concurrent_rotation_cancel if name == "signed-cancel" else (
                    lambda value, stage=name.removeprefix("signed-"): durable.crash_rotation(value, stage))
            else:
                case = VolumeCase(output, name, args.candidate, volume)
                procedure = enospc_audit if name == "enospc-audit" else enospc_profile
            report["cases"].append(case.complete(procedure))
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if volume is not None:
            try:
                volume.close()
            except Exception as error:
                report["volume_cleanup_error"] = type(error).__name__ + ": " + str(error)
            report["volume"] = {"image": str(volume.image), "mount": str(volume.mount), "detached": volume.detached,
                                "image_identity": volume.image_identity, "mount_identity": volume.mount_identity,
                                "volume_uuid": volume.volume_uuid, "filesystem": volume.filesystem,
                                "events": volume.events, "rows": volume.rows}
        unchanged = shared.file_sha(args.candidate) == args.sha256 and all(shared.file_sha(Path(path)) == digest for path, digest in sources.items())
        report["inputs_unchanged"] = unchanged
        report["passed"] = (unchanged and "error" not in report and "volume_cleanup_error" not in report
                            and len(report["cases"]) == len(selected) and all(case["outcome"] == "passed" for case in report["cases"]))
        report["not_qualified"] = ["power loss or every fsync boundary", "unobserved native stages", "Windows storage failures",
                                   "binary update publication", "operator signing keys or user configuration", "release artifacts"]
        shared.save_json(output / "report.json", report)
    print(json.dumps({"passed": report["passed"], "cases": len(report["cases"]), "report": str(output / "report.json")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
