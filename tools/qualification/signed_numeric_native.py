#!/usr/bin/env python3
"""Owned ordinary-product numeric publication and observed-death qualification.

One finite case per invocation. Never downloads/builds a product, edits source,
uses official release authority, edits a real installation, or resumes a
crashed operation. The public RFC8032 fixture key stays explicitly test-only.
"""
import argparse
import contextlib
import os
from pathlib import Path
import signal
import time
import uuid

import signed_numeric_inputs as numeric

base = numeric.base
require = base.require
MIB = base.MIB
LEGACY_SHA = "de7b2ac0af3c10d10e27fd44ec0d60fa5486803b03f69b693a5ed6b67d1b4e7b"
HELPER_SHA = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
TEST = "cli::selfupdate::signed_fixture_tests::numeric::signed_numeric_product_publication"
CONTRACT = "tirith_signed_numeric_replacement_fixture_v1"
AUTHORITY = "fixture_key_signed_checksums_not_official_release"
CASES = ("complete", "verifying", "publication_intent", "published")
CASE_SECONDS = 600


def remaining(deadline, stage_cap):
    seconds = CASE_SECONDS - (time.monotonic() - deadline.start)
    require(seconds > 0, "numeric case deadline exceeded; no further work may start")
    return min(stage_cap, seconds)


def finish(native, job):
    try:
        return native.finish([job])[0]
    finally:
        job.kill()
        for name in ("stdout", "stderr"):
            getattr(job.process, name).close()


def complete(row, exit_code=0):
    require(row["failure"] is None and row["exit"] == exit_code and all(row["cleanup"].values()),
            "owned process outcome/cleanup differs: " + row["name"])


def drain_available(job, cap=256 * 1024):
    for key in ("stdout", "stderr"):
        stream = getattr(job.process, key)
        os.set_blocking(stream.fileno(), False)
        try:
            part = os.read(stream.fileno(), 16384)
        except BlockingIOError:
            continue
        require(len(job.output[key]) + len(part) <= cap, "waiting process output exceeded cap")
        job.output[key].extend(part)


def observe_and_kill(native, job, owned, operation, boundary, installed_sha, candidate_sha, deadline):
    until = time.monotonic() + remaining(deadline, 45)
    while True:
        drain_available(job)
        event = job.process.observe_stop()
        if event is not None:
            require(event.si_code == os.CLD_STOPPED and event.si_status == signal.SIGSTOP,
                    "controller exited before an observed boundary stop")
            break
        require(time.monotonic() < until, "controller boundary observation deadline")
        time.sleep(0.01)
    marker, marker_id = base.load_json(owned.root / "observed-boundary.json", 8192)
    require(marker == {"contract": CONTRACT, "operation_id": operation, "pid": job.process.pid,
                       "phase": boundary, "published": boundary == "published"},
            "stopped controller marker differs")
    expected = candidate_sha if boundary == "published" else installed_sha
    at_stop = installed_image(owned, installed_sha, candidate_sha)
    require(at_stop == expected, "publication bytes contradict the stopped boundary")
    # Only the retained owned child/group is signalled. The marker PID is
    # never signal authority; it must equal our already retained child.
    job.kill()
    row = finish(native, job)
    complete(row, -signal.SIGKILL)
    remaining(deadline, 1)
    if boundary != "verifying":
        require("TIRITH_NUMERIC_EXTRACTOR_COMPLETED" in row["stdout"], "extractor completion not observed")
    require("TIRITH_NUMERIC_PUBLICATION_COMPLETE" not in row["stdout"], "death case completed unexpectedly")
    after_kill = installed_image(owned, installed_sha, candidate_sha)
    require(after_kill == expected, "installed binary changed after the controller was killed")
    return {"observed_stop": "waitid_WSTOPPED_SIGSTOP", "observed_exit": "SIGKILL_reaped",
            "marker": marker_id, "installed_sha256_at_stop": at_stop,
            "installed_sha256_after_kill": after_kill, "installed_image_complete": True}


def installed_image(owned, installed_sha, candidate_sha):
    """The installed slot must hold exactly the complete old or new image."""
    with base.HeldFile(owned.root / "home/.local/bin/tirith", 256 * MIB) as image:
        observed = image.identity["sha256"]
    require(observed in (installed_sha, candidate_sha), "installed binary is neither the complete old nor the complete new image")
    return observed


def replace_owned(path, expected, raw):
    with base.HeldFile(path, MIB, private=True) as current:
        require(current.identity == expected, "owned fixture metadata changed before replacement")
        temporary = path.with_name(path.name + ".next")
        base.write_new(temporary, raw)
        current.revalidate()
        os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def shell_snapshot(native, jobs, owned, phase, deadline, waiting=False):
    remaining(deadline, 1)
    # Actual interactive Zsh initializes its embedded hook and emits its own
    # inherited marker. This qualifies loaded version/reload reporting only;
    # it does not claim PTY preexec blocking or a Claude host lifecycle.
    binary = owned.root / "home/.local/bin/tirith"
    script = owned.root / (phase + ".zsh")
    body = 'umask 077\neval "$("$1" init --shell zsh)" || exit 70\n'
    if waiting:
        body += '"$1" version --provenance --json > "$2" || exit 71\n: > "${2}.ready"\n'
        body += 'for counter in {1..7500}; do [[ -e "$3" ]] && break; /bin/sleep 0.02; done\n[[ -e "$3" ]] || exit 72\n'
    body += '"$1" version --provenance --json > "$4" || exit 73\n'
    base.write_new(script, body.encode())
    job = native.Job("actual-zsh-" + phase, ["/bin/zsh", "-d", "-f", "-i", script, binary,
        owned.root / "shell-before.json", owned.root / "shell-continue", owned.root / (phase + ".json")],
        owned.root / "workspace", owned.env(), timeout=remaining(deadline, 180 if waiting else 45))
    jobs.append(job)
    if waiting:
        until = time.monotonic() + remaining(deadline, 12)
        while not (owned.root / "shell-before.json.ready").exists():
            drain_available(job)
            require(job.process.poll() is None and time.monotonic() < until, "retained Zsh initialization deadline")
            time.sleep(0.02)
    else:
        complete(finish(native, job))
    remaining(deadline, 1)
    return job


def admit_shell(value, installed, loaded, status):
    require(value["version"] == installed and value["lifecycle"]["installed_binary"]["version"] == installed and
            value["lifecycle"]["loaded_integration"]["version"] == loaded and
            value["lifecycle"]["loaded_integration"]["shell"] == "zsh" and
            value["lifecycle"]["loaded_integration"]["reload_status"] == status,
            "actual loaded shell version/reload observation differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ("controller", "installed", "candidate"):
        parser.add_argument("--" + role, type=Path, required=True)
        parser.add_argument("--" + role + "-build", type=Path, required=True)
        parser.add_argument("--" + role + "-cargo-json", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    numeric.admit_base()
    require(os.getuid() != 0, "numeric fixture cannot run as root")
    os.umask(0o077)
    result = {"schema_version": 1, "status": "refused", "authority": AUTHORITY, "case": args.case,
              "scope": "test-only signed ordinary-product numeric publication through the CLI update/rollback primitives",
              "official_release_claim": False, "production_download_worker_claim": False,
              "power_loss_claim": False, "nested_process_tree_cleanup_attested": False, "jobs": []}
    jobs, owned, native = [], None, None
    with contextlib.ExitStack() as stack:
        def held(path, cap=MIB, private=False):
            return stack.enter_context(base.HeldFile(path, cap, private))
        import types
        legacy_input = held(Path(base.__file__).resolve().with_name("signed_replacement_native.py"))
        require(legacy_input.identity["sha256"] == LEGACY_SHA, "existing native fixture helper changed")
        legacy = types.ModuleType("numeric_retained_legacy")
        legacy.__file__ = str(legacy_input.path)
        exec(compile(legacy_input.read(), str(legacy_input.path), "exec"), legacy.__dict__)
        legacy_input.revalidate()
        deadline = legacy.Deadline()
        try:
            owned = legacy.OwnedRoot(args.output_dir)
            (owned.root / "inputs/installed").mkdir(mode=0o700)
            owned.hold_directory(owned.root / "inputs/installed")
            result["fixture_root"] = str(owned.root)
            images, manifests, builds = {}, {}, {}
            for role in ("controller", "installed", "candidate"):
                images[role] = held(getattr(args, role), (512 if role == "controller" else 256) * MIB)
                manifests[role] = held(getattr(args, role + "_build"))
                builds[role] = base.parse_json(manifests[role].read())
                require(numeric.admit_build(builds[role], images[role], getattr(args, role + "_cargo_json")) is (role == "controller"),
                        "numeric build role substituted")
                require(builds[role]["version"] == ("0.4.3" if role == "candidate" else "0.4.2"), "numeric version order differs")
                legacy.native_image(images[role], base.native_target())
            require(builds["controller"]["source"]["files"] == builds["installed"]["source"]["files"], "controller and old product source differ")
            numeric.admit_source_pair(builds["installed"]["source"], builds["candidate"]["source"])
            require(len({image.identity["sha256"] for image in images.values()}) == 3, "three executable roles require distinct bytes")
            source = Path(builds["candidate"]["source"]["root"])
            helper = held(source / "tools/qualification/mixed_audit_native.py")
            require(helper.identity["sha256"] == HELPER_SHA, "native ownership helper byte pin changed")
            native = legacy.load_module("numeric_owned_native", helper)
            native.require_process_observation()
            base.write_new(owned.output / "owner-helper.py", helper.read())
            reserved = images["controller"].identity["size"] + 4 * images["installed"].identity["size"] + 4 * images["candidate"].identity["size"] + 192 * MIB
            require(reserved <= 3 * 1024 * MIB, "numeric fixture exceeds 3GiB storage cap")
            disk = os.statvfs(owned.root)
            require(disk.f_bavail * disk.f_frsize >= reserved + 64 * MIB, "insufficient bounded fixture storage")
            result["storage_reservation_bytes"] = reserved
            for role, relative in (("controller", "inputs/controller"), ("installed", "inputs/installed/tirith"),
                                   ("candidate", "inputs/candidate/tirith"), ("installed", "home/.local/bin/tirith")):
                legacy.copy_image(images[role], owned.root / relative, deadline)
            preserved = dict(legacy.PRESERVED)
            policy_path, policy = preserved["policy"]
            preserved["policy"] = (policy_path, policy + b"threat_intel:\n  auto_update_hours: 0\n  osv_enabled: false\n  deps_dev_enabled: false\ncustom_rules:\n  - id: numeric-inert-block\n    pattern: TIRITH_NUMERIC_BLOCK_MARKER\n    severity: critical\n    title: Inert numeric lifecycle control\n    context: [exec]\n")
            for _, (path, body) in preserved.items():
                base.write_new(owned.root / path, body)
            for role, name in (("controller", "test"), ("installed", "installed"), ("candidate", "candidate")):
                base.write_new(owned.root / ("inputs/" + name + "-source.json"), manifests[role].read())
                cargo = held(getattr(args, role + "_cargo_json"), 16 * MIB)
                require(cargo.identity == builds[role]["cargo_output"], "Cargo output changed")
                base.write_new(owned.output / (role + "-cargo.jsonl"), cargo.read())
                for stage in ("before", "after"):
                    reference = builds[role]["source_" + stage]
                    capture = held(Path(reference["path"]))
                    require(capture.identity == reference["identity"], "bracketing source capture changed")
                    base.write_new(owned.output / (role + "-source-" + stage + ".json"), capture.read())
            for name, path in (("numeric-runner.py", Path(__file__).resolve()),
                               ("numeric-inputs.py", Path(numeric.__file__).resolve()),
                               ("v1-inputs.py", Path(base.__file__).resolve()), ("v1-native.py", legacy_input.path)):
                retained = held(path)
                base.write_new(owned.output / name, retained.read())
            def run(name, argv, exit_code=0):
                job = native.Job(name, argv, owned.root / "workspace", owned.env(), timeout=remaining(deadline, 45))
                jobs.append(job)
                row = finish(native, job)
                complete(row, exit_code)
                remaining(deadline, 1)
                return row
            binary = owned.root / "home/.local/bin/tirith"
            def provenance(version):
                row = run("installed-product-" + version, [binary, "version", "--provenance", "--json"])
                value = base.parse_json(row["stdout"])
                role = "installed" if version == "0.4.2" else "candidate"
                require(value["version"] == version and value["binary_sha256"] == images[role].identity["sha256"] and
                        value["binary_path"] == str(binary) and value["target"] == base.native_target() and
                        value["build_profile"] == "release" and value["dev_build"] is False and
                        value["install_method"] == "self-managed" and value["install_method_resolved"] is True,
                        "actual installed product provenance differs")
                return value
            original = provenance("0.4.2")
            def functional(version):
                run("allow-" + version, [binary, "check", "--no-daemon", "--", "printf TIRITH_NUMERIC_ALLOW_MARKER"])
                denied = run("block-" + version, [binary, "check", "--no-daemon", "--", "printf TIRITH_NUMERIC_BLOCK_MARKER"], 1)
                require("numeric-inert-block" in denied["stdout"] + denied["stderr"], "inert refusal lacks the configured rule")
                return {"version": version, "allow_exit": 0, "block_exit": 1, "rule_id": "numeric-inert-block",
                        "scope": "ordinary product checker; no command execution or shell preexec claim"}
            result["functional_products"] = [functional("0.4.2")]
            base.write_new(owned.root / "inputs/installed-provenance.json", base.canonical(original))
            generator = held(source / ".github/scripts/release-compatibility.py")
            base.write_new(owned.output / "compatibility-generator.py", generator.read())
            compatibility_module = legacy.load_module("numeric_release_contract", generator)
            compatibility = compatibility_module.contract(source, "0.4.3")
            archive_name = "tirith-" + base.native_target() + ".tar.gz"
            archive_id = legacy.archive_fixture(images["candidate"], owned.root / "inputs/release" / archive_name, deadline)
            compatibility["targets"] = {base.native_target(): {"archive": archive_name, "archive_sha256": archive_id["sha256"],
                                                               "binary_sha256": images["candidate"].identity["sha256"]}}
            compatibility_raw = base.canonical(compatibility)
            checksums = (archive_id["sha256"] + "  " + archive_name + "\n" + base.digest(compatibility_raw) + "  release-compatibility.json\n").encode()
            signature = legacy.sign_checksums(checksums)
            for name, raw in (("release-compatibility.json", compatibility_raw), ("checksums.txt", checksums), ("checksums.fixture.ed25519", signature)):
                base.write_new(owned.root / "inputs/release" / name, raw)
            image = lambda role: {"kind": "test_harness_not_product" if role == "controller" else "retained_product",
                                  "profile_test": role == "controller", "identity": images[role].identity}
            fixture = {"schema_version": 1, "contract": CONTRACT, "fixture_id": owned.fixture_id, "root": str(owned.root),
                       "version": "0.4.3", "target": base.native_target(), "authority": AUTHORITY,
                       "test_executable": image("controller"), "candidate": image("candidate"), "archive": archive_id,
                       "checksums": base.identity(checksums), "signature": base.identity(signature), "compatibility": base.identity(compatibility_raw),
                       "test_source_manifest": manifests["controller"].identity, "candidate_source_manifest": manifests["candidate"].identity,
                       "preserved": {key: base.identity(body) for key, (_, body) in preserved.items()}}
            manifest = {"fixture": fixture, "installed": image("installed"), "installed_source_manifest": manifests["installed"].identity,
                        "installed_provenance": base.identity(base.canonical(original)), "operation_id": str(uuid.uuid4()),
                        "action": "update", "boundary": args.case}
            raw = base.canonical(manifest)
            base.write_new(owned.root / "numeric-manifest.json", raw)
            base.write_new(owned.output / "update-manifest.json", raw)
            immutable = [held(owned.root / path, 64 * 1024, True) for path, _ in preserved.values()]
            def controller():
                env = owned.env()
                env["TIRITH_TEST_NUMERIC_REPLACEMENT_MANIFEST"] = str(owned.root / "numeric-manifest.json")
                job = native.Job("numeric-controller-" + manifest["action"], [owned.root / "inputs/controller", "--exact", TEST,
                    "--ignored", "--nocapture", "--test-threads=1"], owned.root / "workspace", env, timeout=remaining(deadline, 45))
                jobs.append(job)
                return job
            retained_shell = None
            if args.case == "complete":
                require(Path("/bin/zsh").is_file(), "complete numeric lane requires actual native Zsh")
                retained_shell = shell_snapshot(native, jobs, owned, "retained-shell", deadline, waiting=True)
                admit_shell(base.load_json(owned.root / "shell-before.json", 64 * 1024)[0], "0.4.2", "0.4.2", "matching_version_unverified")
            job = controller()
            if args.case == "complete":
                row = finish(native, job)
                complete(row)
                remaining(deadline, 1)
                require("TIRITH_NUMERIC_PUBLICATION_COMPLETE" in row["stdout"] and "TIRITH_NUMERIC_EXTRACTOR_COMPLETED" in row["stdout"], "controller completion markers absent")
            else:
                result["death_observation"] = observe_and_kill(native, job, owned, manifest["operation_id"], args.case,
                    images["installed"].identity["sha256"], images["candidate"].identity["sha256"], deadline)
            current_version = "0.4.3" if args.case in ("complete", "published") else "0.4.2"
            result["after_publication_provenance"] = provenance(current_version)
            result["functional_products"].append(functional(current_version))
            if args.case == "complete":
                base.write_new(owned.root / "shell-continue", b"continue\n")
                complete(finish(native, retained_shell))
                remaining(deadline, 1)
                retained = base.load_json(owned.root / "retained-shell.json", 64 * 1024)[0]
                admit_shell(retained, "0.4.3", "0.4.2", "reload_required")
                shell_snapshot(native, jobs, owned, "fresh-shell", deadline)
                fresh = base.load_json(owned.root / "fresh-shell.json", 64 * 1024)[0]
                admit_shell(fresh, "0.4.3", "0.4.3", "matching_version_unverified")
                result["loaded_shell_version_observations"] = {"retained": retained, "fresh": fresh,
                    "claim": "actual interactive Zsh loaded markers; not a PTY blocking certificate"}
                updated_provenance = base.canonical(provenance("0.4.3"))
                replace_owned(owned.root / "inputs/installed-provenance.json", manifest["installed_provenance"], updated_provenance)
                manifest.update(action="rollback", operation_id=str(uuid.uuid4()), installed_provenance=base.identity(updated_provenance))
                next_raw = base.canonical(manifest)
                replace_owned(owned.root / "numeric-manifest.json", base.identity(raw), next_raw)
                base.write_new(owned.output / "rollback-manifest.json", next_raw)
                row = finish(native, controller())
                complete(row)
                remaining(deadline, 1)
                require("TIRITH_NUMERIC_PUBLICATION_COMPLETE" in row["stdout"], "rollback controller did not complete")
                result["after_rollback_provenance"] = provenance("0.4.2")
                result["functional_products"].append(functional("0.4.2"))
            for item in immutable:
                item.revalidate()
            for role in images:
                numeric.admit_build(builds[role], images[role], getattr(args, role + "_cargo_json"))
            numeric.admit_source_pair(builds["installed"]["source"], builds["candidate"]["source"])
            result.update(status="owned_numeric_case_passed", configuration_preserved=True,
                          storage=legacy.storage_inventory(owned.output, deadline))
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)[:2048]
        finally:
            for job in jobs:
                if not job.cleanup_attempted:
                    job.kill()
                    finish(native, job)
                row = job.result()
                # Service output could contain future authentication prose. Its
                # content is not evidence for this lane, so do not retain it.
                result["jobs"].append({key: row[key] for key in ("name", "argv", "pid", "exit", "failure", "cleanup", "group_observation", "elapsed_seconds")})
                if row["failure"] is not None or not all(row["cleanup"].values()):
                    result["status"] = "refused"
            result["limitations"] = ["Public fixture key; no official release or production download/worker claim.",
                "SIGKILL at three observed test-controller boundaries qualifies process death, not kernel crash or power loss.",
                "After each observed death the installed slot holds exactly the complete old or new image; interrupted runs are never resumed.",
                "Normal extractor completion is observed; original-group cleanup does not attest its separate nested group after outer failure.",
                "Loaded Zsh stamps are actual init observations, not host blocking, Claude reload, Windows, or all-channel acceptance."]
            if owned is not None:
                try:
                    owned.revalidate()
                except Exception:
                    result["status"] = "refused"
                    result["root_revalidation_failed"] = True
                rendered = base.canonical(result)
                require(len(rendered) <= MIB, "numeric result exceeds fixed evidence cap")
                base.write_new(owned.output / "result.json", rendered)
                owned.close()
    print(base.canonical({"status": result["status"], "case": args.case, "output": str(args.output_dir)}).decode(), end="")
    raise SystemExit(0 if result["status"] == "owned_numeric_case_passed" else 1)


if __name__ == "__main__":
    main()
