#!/usr/bin/env python3
"""Qualify explicit organization rollout through the candidate's embedded UI.

Uses only private fixture roots and a native ordinary operator. Commands entered
into the impact review are analyzed, never executed. No asset override is used.
Requires Playwright, Chromium, PyYAML, and native Python with os.waitid/WNOWAIT (system Python 3.9 on macOS is unsupported).
"""
if not __debug__:
    raise RuntimeError("qualification assertions require Python without -O/PYTHONOPTIMIZE")

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import tempfile
import time
import uuid

import yaml

from playwright.sync_api import sync_playwright


SHARED_PATH = Path(__file__).with_name("test-control-browser.py")
SPEC = importlib.util.spec_from_file_location("control_browser", SHARED_PATH)
SHARED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARED)
NATIVE_PATH = Path(__file__).resolve().parents[1] / "tools/qualification/mixed_audit_native.py"
NATIVE_SPEC = importlib.util.spec_from_file_location("mixed_audit_native", NATIVE_PATH)
NATIVE = importlib.util.module_from_spec(NATIVE_SPEC)
NATIVE_SPEC.loader.exec_module(NATIVE)

ORIGINAL = "organization_note: preserve-managed-browser-fixture\n"
BALANCED = {
    "allow_bypass_env": True, "allow_bypass_env_noninteractive": False,
    "approval_rules": [{"rule_ids": ["shortened_url", "package_repo_mismatch"],
                        "timeout_secs": 120, "fallback": "block"}],
    "fail_mode": "open", "paranoia": 1, "strict_warn": False,
    "severity_overrides": {"non_ascii_path": "LOW", "non_standard_port": "LOW"},
}
OWNED_FIELDS = sorted([key for key in BALANCED if key != "severity_overrides"] +
                      ["severity_overrides." + key for key in BALANCED["severity_overrides"]])
SELECTION = {"name": "balanced", "version": 1, "owned_fields": OWNED_FIELDS}


@contextmanager
def journey_deadline(seconds=300):
    """Bound the complete synchronous UI journey, including startup and CLI calls."""
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "an existing alarm owns this process"
    previous = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise TimeoutError("managed browser journey exceeded its 300 second deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def read_discovery(path, job, startup_id, binary_sha256, project):
    """Read the private fixture record; sampled identity never grants signal authority."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        body = source.read(16385)
    assert len(body) <= 16384, "discovery record exceeds its native bound"
    record = json.loads(body)
    assert type(record["protocol"]) is int and record["protocol"] == 1
    assert type(record["pid"]) is int and record["pid"] == job.process.pid
    assert record["startup_id"] == startup_id
    assert record["binary_sha256"] == binary_sha256 and record["cwd"] == str(project)
    assert type(record["port"]) is int and 0 < record["port"] < 65536
    assert str(uuid.UUID(record["service_id"])) == record["service_id"]
    assert len(record["token"]) == 64 and all(c in "0123456789abcdef" for c in record["token"])
    assert job.process.poll() is None, "owned service exited before discovery validation"
    return record


def await_discovery(path, job, startup_id, binary_sha256, project):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        assert job.process.poll() is None, "owned control-serve exited during startup"
        try:
            return read_discovery(path, job, startup_id, binary_sha256, project)
        except FileNotFoundError:
            time.sleep(0.025)
    raise TimeoutError("owned control-serve did not publish private discovery")


def verify_launch(launch, record):
    expected = f"http://127.0.0.1:{record['port']}/#token={record['token']}"
    assert launch["kind"] == "dashboard_launch" and launch["service_id"] == record["service_id"]
    assert launch["url"] == expected, "launcher did not reuse the owned service"
    assert launch["browser_opened"] is False and launch["protection_changed"] is False


def verify_balanced(document, effective, managed):
    expected = {"organization_note": "preserve-managed-browser-fixture",
                **BALANCED, "protection_profile": SELECTION}
    # Exact parsed document equality proves every materialized field and rejects
    # unrelated additions; CLI resolution separately proves runtime selection.
    assert yaml.safe_load(document) == expected, "serialized managed profile differs from balanced v1"
    assert effective["scope"] == "org" and effective["source_path"] == str(managed)
    policy = effective["policy"]
    for field, value in BALANCED.items():
        assert policy[field] == value, (field, policy[field], value)
    assert effective["resolution"]["effective_profile"] == SELECTION


def verify_restore(document):
    # This fixture starts as a canonical one-key YAML document. Byte equality
    # also rejects residual preset fields, empty maps and profile metadata.
    assert document == ORIGINAL, "undo did not restore the exact canonical fixture document"


def finish_service(job, authentication, report):
    if job is None:
        return
    try:
        if job.process.poll() is None:
            assert authentication, "startup failed before owned service authentication"
            origin, token, csrf = authentication
            if csrf is None:
                csrf = SHARED.request(origin, token, "", "/api/session")["csrf"]
            response = SHARED.request(origin, token, csrf, "/api/quiesce", {})
            assert response["state"] == "draining" and response["new_mutations_accepted"] is False
            report["quiesce_response"] = response
        else:
            raise AssertionError("owned service exited before requested quiesce")
    except Exception as error:
        report["shutdown_error"] = safe_diagnostic(error, authentication)
        job.failure = job.failure or "service-quiesce"
        job.kill()  # Only Job's retained native child may authorize signals.
    finally:
        # A draining acknowledgement is not exit proof. Allow at most 12 more
        # seconds, then retain forced-cleanup failure and the actual native exit.
        job.timeout = min(job.timeout, time.monotonic() - job.started + 12)
        try:
            rows = NATIVE.finish([job])
            report["owned_service"] = rows[0]
        except BaseException:
            report["owned_service"] = job.result()
            raise
    NATIVE.success(report["owned_service"])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_diagnostic(error, authentication):
    message = str(error)
    for secret in authentication[1:] if authentication else ():
        if secret:
            message = message.replace(secret, "[withheld]")
    return message[:4096]


def run(binary, output):
    if os.name != "posix" or os.geteuid() == 0 or os.geteuid() != os.getuid():
        raise RuntimeError("managed browser qualification requires a native ordinary POSIX owner")
    NATIVE.require_process_observation()
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "passed": False, "checks": [],
              "platform": platform.platform(), "uid": os.geteuid(),
              "binary_sha256": digest(binary), "harness_sha256": digest(Path(__file__)),
              "shared_harness_sha256": digest(SHARED_PATH), "native_helper_sha256": digest(NATIVE_PATH),
              "pyyaml_version": yaml.__version__, "cli_observations": [], "source_override": False,
              "scope": "local_managed", "remote_publication_verified": False,
              "fleet_adoption_verified": False}
    authentication = None
    try:
        with tempfile.TemporaryDirectory(prefix="tirith-managed-browser-") as directory:
            root = Path(directory).resolve()
            env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
            for key, suffix in {
                "HOME": "home", "USERPROFILE": "home", "XDG_CONFIG_HOME": "home/.config",
                "XDG_CONFIG_DIRS": "config-dirs", "XDG_DATA_HOME": "data",
                "XDG_STATE_HOME": "state", "XDG_CACHE_HOME": "cache",
                "XDG_RUNTIME_DIR": "runtime", "APPDATA": "appdata",
                "LOCALAPPDATA": "local-appdata", "TMPDIR": "temp", "TMP": "temp",
                "TEMP": "temp", "TIRITH_POLICY_ROOT": "organization",
            }.items():
                path = root / suffix
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
                env[key] = str(path)
            env.update(TIRITH_OFFLINE="1", TIRITH_THREATDB_PATH=str(root / "missing-db"),
                       TIRITH_THREATDB_SUPPLEMENTAL_PATH=str(root / "missing-supplemental"))
            project = root / "project"
            (project / ".git").mkdir(parents=True)
            managed = root / "organization/.tirith/policy.yml"
            managed.parent.mkdir(mode=0o700)
            managed.write_text(ORIGINAL)
            managed.chmod(0o600)
            personal = root / "home/.config/tirith"

            def cli(*args, expected_exit=0):
                job = NATIVE.Job("managed-browser-cli", [str(binary), *args], project, env, timeout=40)
                try:
                    row = NATIVE.finish([job])[0]
                finally:
                    # Also retain cleanup evidence when a journey timeout
                    # interrupts a CLI call. Do not retain launch bearer output.
                    observed = job.result()
                    report["cli_observations"].append({key: observed[key] for key in
                        ("name", "pid", "exit", "failure", "cleanup", "group_observation", "elapsed_seconds")})
                assert row["failure"] is None and row["exit"] == expected_exit, (
                    "candidate CLI failed", row["failure"], row["exit"], expected_exit)
                assert all(row["cleanup"].values()), "candidate CLI cleanup incomplete"
                return json.loads(row["stdout"])

            service = None
            authentication = None
            errors = []
            try:
                with journey_deadline(), sync_playwright() as playwright:
                    startup_id = str(uuid.uuid4())
                    service = NATIVE.Job("managed-browser-control-serve",
                        [str(binary), "dashboard", "control-serve", "--startup-id", startup_id],
                        project, env, timeout=330)
                    discovery_path = root / "state/tirith/control/v1/service.json"
                    record = await_discovery(discovery_path, service, startup_id,
                                             report["binary_sha256"], project)
                    origin = f"http://127.0.0.1:{record['port']}"
                    token = record["token"]
                    authentication = (origin, token, None)
                    csrf = SHARED.request(origin, token, "", "/api/session")["csrf"]
                    authentication = (origin, token, csrf)
                    launch = cli("dashboard", "--no-browser", "--json")
                    verify_launch(launch, record)
                    assert read_discovery(discovery_path, service, startup_id,
                                          report["binary_sha256"], project) == record
                    report["service_identity"] = {key: record[key] for key in
                        ("protocol", "service_id", "startup_id", "pid", "binary_sha256", "version")}
                    report["checks"].append("public_launcher_reuses_identified_owned_control_service")
                    browser = playwright.chromium.launch(headless=True, timeout=30000)
                    report["browser_version"] = browser.version
                    page = browser.new_page(viewport={"width": 1440, "height": 1050})
                    page.set_default_timeout(15000)
                    page.set_default_navigation_timeout(30000)
                    page.on("pageerror", lambda error: errors.append(safe_diagnostic(error, authentication)))

                    def stored():
                        for text in page.locator("#operation-content details pre").all_text_contents():
                            value = json.loads(text)
                            if "operation_id" in value and "state" in value:
                                return value
                        raise AssertionError("operation details are unavailable")

                    def close():
                        page.get_by_role("button", name="Close change details", exact=True).click()
                        page.wait_for_function("!document.querySelector('#operation-dialog').open")

                    def prepare():
                        page.get_by_role("button", name="Protection", exact=True).click()
                        page.locator('#content[aria-busy="false"]').wait_for()
                        page.get_by_label("Policy authority", exact=True).select_option("org")
                        page.get_by_label("Candidate profile", exact=True).select_option("balanced")
                        page.get_by_label("Representative commands, one per line", exact=True).fill(
                            "touch NEVER_EXECUTED")
                        page.get_by_role("button", name="Prepare impact review", exact=True).click()
                        page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                        operation = stored()
                        assert operation["kind"] == "set-managed-profile"
                        assert operation["state"] == "planned"
                        page.get_by_text("Organization profile impact:", exact=False).wait_for()
                        assert not page.get_by_text("Personal profile impact:", exact=False).count()
                        return operation["operation_id"]

                    def activate():
                        page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                        page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                        assert stored()["state"] in ("completed", "completed-with-recovery")

                    try:
                        page.goto(launch["url"])
                        page.locator('#content[aria-busy="false"]').wait_for()
                        assert "token=" not in page.url
                        operation_id = prepare()
                        prepared = cli("policy", "rollout", "show", operation_id, "--json")
                        assert prepared["impact"]["scope"] == "local_managed"
                        assert prepared["impact"]["exception_inventory_complete"] is False
                        assert prepared["impact"]["remote_publication_available"] is False
                        assert prepared["impact"]["fleet_adoption_verified"] is False
                        assert prepared["live"]["organization_target_effective"] is True
                        assert prepared["live"]["personal_target_effective"] is False
                        verify_restore(managed.read_text())
                        assert not (project / "NEVER_EXECUTED").exists()
                        report["checks"].append("explicit_managed_review_matches_cli_and_executes_nothing")
                        activate()
                        effective = cli("policy", "effective", "--json")
                        verify_balanced(managed.read_text(), effective, managed)
                        (output / "managed-active-policy.yml").write_text(managed.read_text())
                        (output / "managed-active-effective.json").write_text(json.dumps(effective, indent=2) + "\n")
                        assert not (personal / "policy.yaml").exists()
                        assert not (personal / "policy.yml").exists()
                        active = cli("policy", "rollout", "show", operation_id, "--json")
                        assert active["operation"]["state"] == stored()["state"]
                        assert active["impact"] == prepared["impact"]
                        page.screenshot(path=str(output / "managed-activated.png"), full_page=True)
                        report["checks"].append("browser_activation_changes_only_selected_organization_authority")
                        page.get_by_role("button", name="Undo owned change", exact=True).click()
                        page.locator("#operation-content > .badge").filter(has_text="undone").wait_for(timeout=40000)
                        restored = managed.read_text()
                        (output / "managed-restored-policy.yml").write_text(restored)
                        verify_restore(restored)
                        report["checks"].append("browser_undo_restores_unchanged_owned_managed_profile")
                        close()
                        operation_id = prepare()
                        activate()
                        verify_balanced(managed.read_text(), cli("policy", "effective", "--json"), managed)
                        newer = managed.read_text() + "later_operator_note: retain-this-generation\n"
                        managed.write_text(newer)
                        page.get_by_role("button", name="Undo owned change", exact=True).click()
                        page.locator("#operation-content p.notice").filter(
                            has_text="newer managed authority document prevents rollback"
                        ).wait_for(timeout=40000)
                        assert managed.read_text() == newer
                        latest = cli("policy", "rollout", "show", operation_id, "--json", expected_exit=1)
                        assert latest["operation"]["state"] == "refresh-required"
                        assert not (project / "NEVER_EXECUTED").exists()
                        page.screenshot(path=str(output / "managed-newer-generation-refused.png"), full_page=True)
                        report["checks"].append("newer_managed_document_refuses_browser_rollback_without_overwrite")
                        assert not errors, errors
                    except Exception as error:
                        report["error"] = safe_diagnostic(error, authentication)
                        try:
                            assert "token=" not in page.url, "initial authorization URL still present"
                            page.screenshot(path=str(output / "failure.png"), full_page=True, timeout=3000)
                            (output / "failure-view.txt").write_text(page.locator("body").inner_text(timeout=3000))
                        except Exception as capture_error:
                            report["failure_capture_error"] = safe_diagnostic(capture_error, authentication)
                        raise
                    finally:
                        report["browser_errors"] = errors
                        browser.close()
            finally:
                finish_service(service, authentication, report)
            assert digest(binary) == report["binary_sha256"]
            assert digest(Path(__file__)) == report["harness_sha256"]
            assert digest(SHARED_PATH) == report["shared_harness_sha256"]
            assert digest(NATIVE_PATH) == report["native_helper_sha256"]
            report["checks"].append("owned_service_exited_and_all_four_native_cleanup_facts_verified")
            report["passed"] = True
    except BaseException as error:
        message = safe_diagnostic(error, authentication)
        report.setdefault("error", message)
        raise RuntimeError(message) from None
    finally:
        (output / "browser-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": report["checks"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    run(arguments.binary.resolve(), arguments.output.resolve())
