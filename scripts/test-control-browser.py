#!/usr/bin/env python3
"""Exercise the embedded dashboard against an actual candidate in isolated roots.

Requires Python Playwright and its Chromium runtime. No user policy, trust store,
project content or audit history is read or changed by the fixture environment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

from playwright.sync_api import sync_playwright


def request(origin, token, csrf, path, body=None):
    headers = {"Authorization": "Bearer " + token}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers.update({"Origin": origin, "X-Tirith-CSRF": csrf, "Content-Type": "application/json"})
    req = urllib.request.Request(origin + path, data=data, headers=headers)
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=40) as response:
        return json.load(response)


def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "checks": [], "operation_observations": [], "api_observations": [],
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "execution_claim": "local_control_workflow_only"}
    with tempfile.TemporaryDirectory(prefix="tirith-browser-fixture-") as raw_root:
        root = Path(raw_root).resolve()
        names = {"HOME": "home", "USERPROFILE": "home", "XDG_CONFIG_HOME": "home/.config",
                 "XDG_CONFIG_DIRS": "config-dirs", "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
                 "XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "runtime", "APPDATA": "appdata",
                 "LOCALAPPDATA": "local-appdata", "TMPDIR": "temp", "TMP": "temp", "TEMP": "temp"}
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("TIRITH_") and key not in {"TIRITH", "SUDO_USER", "SUDO_UID", "SUDO_GID"}}
        for key, suffix in names.items():
            directory = root / suffix
            directory.mkdir(parents=True, exist_ok=True)
            env[key] = str(directory)
        env.update({"TIRITH_OFFLINE": "1", "TIRITH_THREATDB_PATH": str(root / "missing-db"),
                    "TIRITH_THREATDB_SUPPLEMENTAL_PATH": str(root / "missing-supplemental")})
        project = root / "project"
        (project / ".git").mkdir(parents=True)
        manifest = project / "package.json"
        manifest.write_text(json.dumps({"name":"browser-fixture", "scripts":{"install":"touch never-created"}}))
        config = root / "home/.config/tirith"
        config.mkdir(parents=True)
        policy = config / "policy.yml"
        policy.write_text("custom_operator_note: preserve-browser-fixture\n")
        audit_dir = root / "data/tirith"
        audit_dir.mkdir(parents=True)
        hostile = '<img src=x onerror="window.__tirithInjected=true">'
        audit = audit_dir / "log.jsonl"
        event_id = str(uuid.uuid4())
        prior_checks = "".join(json.dumps({"timestamp": "2026-09-11T00:00:00Z", "action": "Block",
                                            "command_redacted": f"history-check-{index}"}) + "\n" for index in range(600))
        audit.write_text(prior_checks + json.dumps({"timestamp": "2026-09-12T00:00:00Z", "action": "WarnAck",
                                    "event_id": event_id,
                                    "command_redacted": hostile, "rule_ids": ["curl_pipe_shell"]}) + "\n")
        launched = subprocess.run([str(binary), "dashboard", "--no-browser", "--json"], cwd=project,
                                  env=env, capture_output=True, text=True, timeout=45)
        if launched.returncode:
            raise AssertionError("candidate service failed to launch: " + launched.stderr)
        launch = json.loads(launched.stdout)
        parsed = urllib.parse.urlsplit(launch["url"])
        origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        token = urllib.parse.parse_qs(parsed.fragment)["token"][0]
        session = request(origin, token, "", "/api/session")
        csrf = session["csrf"]
        errors = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 1050})
                page.on("pageerror", lambda error: errors.append(str(error)))
                observed_started = time.monotonic()
                def observe_response(response):
                    path = urllib.parse.urlsplit(response.url).path
                    if path not in ("/api/plans", "/api/operations") or len(report["api_observations"]) >= 512:
                        return
                    try:
                        body = response.json()
                        sent = response.request.post_data_json or {}
                        operation = body.get("operation") or body
                        report["api_observations"].append({"elapsed_seconds":time.monotonic() - observed_started,
                            "path":path, "status":response.status, "action":sent.get("action"),
                            "operation_id":sent.get("operation_id"), "state":operation.get("state"),
                            "active_action":operation.get("active_action"), "error_present":bool(body.get("error"))})
                    except Exception as error:
                        report["api_observations"].append({"path":path, "observation_error":type(error).__name__})
                page.on("response", observe_response)
                try:
                    page.goto(launch["url"])
                    page.wait_for_load_state("networkidle")
                    page.get_by_role("heading", name="Overview", exact=True).wait_for()
                    page.locator('#content[aria-busy="false"]').wait_for()
                    assert "token=" not in page.url
                    assert page.get_by_text("Configured. Verify in your shell.").count() or page.get_by_text("Check your integration.").count()
                    page.screenshot(path=str(output / "overview-wide.png"), full_page=True)
                    report["checks"].append("overview_uses_evidence_not_assumed_blocking")
                    page.get_by_label("Project-relative files (optional)", exact=True).fill("package.json")
                    page.get_by_role("button", name="Inspect selected project files", exact=True).click()
                    page.get_by_role("button", name="Recheck retained file identities", exact=True).wait_for()
                    assert not (project / "never-created").exists()
                    assert not (project / "node_modules").exists()
                    replacement = project / "replacement.json"
                    replacement.write_bytes(manifest.read_bytes())
                    replacement.replace(manifest)
                    page.get_by_role("button", name="Recheck retained file identities", exact=True).click()
                    page.get_by_text("1 identities changed since capture.", exact=False).wait_for()
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("explicit_project_review_is_inert_and_detects_identical_replacement")
                    fixture = Path(__file__).resolve().parents[1] / "crates/tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz"
                    (project / "package.tgz").write_bytes(fixture.read_bytes())
                    (project / "previous.tgz").write_bytes(fixture.read_bytes())
                    page.get_by_label("npm tarball in this project", exact=True).fill("package.tgz")
                    page.get_by_role("button", name="Inspect npm tarball", exact=True).click()
                    page.get_by_role("heading", name="npm artifact inspection", exact=True).wait_for()
                    page.get_by_role("button", name="Refresh and download npm report", exact=True).wait_for()
                    assert "769755af559bda513cfe86d6c433bf8e6c0b2431dbb24955393e0dc69eeb2c0f" in page.locator("#operation-content").inner_text()
                    assert not (project / "node_modules").exists()
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_label("Previous npm tarball (for comparison)", exact=True).fill("previous.tgz")
                    page.get_by_role("button", name="Compare npm tarballs", exact=True).click()
                    page.get_by_role("heading", name="npm release comparison", exact=True).wait_for()
                    page.get_by_text("0 observed changes", exact=False).wait_for()
                    assert not (project / "package-lock.json").exists()
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("npm_artifact_inspection_and_comparison_bind_hashes_without_installation")
                    for name in ["Activity", "Protection", "Exceptions", "Integrations", "Settings"]:
                        page.get_by_role("button", name=name, exact=True).click()
                        page.get_by_role("heading", name=name, exact=True).wait_for()
                        page.locator('#content[aria-busy="false"]').wait_for()
                        assert not page.get_by_text("This view could not be refreshed.", exact=False).count()
                    report["checks"].append("all_six_pages_load_real_service_models")
                    page.get_by_role("button", name="Activity", exact=True).click()
                    page.locator("#content .row code").filter(has_text=hostile).first.wait_for()
                    assert page.evaluate("window.__tirithInjected === undefined")
                    assert page.locator("#content img").count() == 0
                    report["checks"].append("hostile_history_is_text_not_markup")
                    activity_rows = page.locator("#content .row code")
                    assert activity_rows.first.inner_text() == hostile
                    assert activity_rows.nth(1).inner_text() == "history-check-599"
                    assert activity_rows.count() == 100
                    page.get_by_role("button", name="Load older bounded page", exact=True).click()
                    page.get_by_text("history-check-401", exact=True).wait_for()
                    assert activity_rows.count() == 200
                    assert activity_rows.first.inner_text() == hostile
                    assert activity_rows.nth(100).inner_text() == "history-check-500"
                    page.get_by_role("button", name="Refresh recent activity", exact=True).click()
                    page.get_by_text("100 recorded checks among 100 loaded records", exact=False).wait_for()
                    assert activity_rows.count() == 100
                    report["checks"].append("activity_opens_newest_pages_older_and_refreshes_without_reordering")
                    page.get_by_role("button", name="Record expectation", exact=True).click()
                    page.get_by_role("button", name="Review expectation label", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    feedback = root / "state/tirith/feedback" / (event_id + ".json")
                    annotation = json.loads(feedback.read_text())
                    assert annotation["expectation"] == "expected" and annotation["policy_changed"] is False
                    assert hostile not in feedback.read_text()
                    annotated = request(origin, token, csrf, "/api/history", {"limit":100})
                    assert any(entry.get("expectation") == "expected" and entry["event_id"] == event_id for entry in annotated["annotations"]["entries"])
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="undone").wait_for(timeout=40000)
                    assert not feedback.exists() or not feedback.read_text()
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("incident_annotation_is_reviewed_metadata_and_undoable")
                    page.get_by_role("button", name="Protection", exact=True).click()
                    page.get_by_role("button", name="Review recent friction", exact=True).click()
                    page.get_by_role("heading", name="Recent friction review", exact=True).wait_for()
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("bounded_tuning_review_loads_without_mutating_policy")
                    page.get_by_role("button", name="Compare and review").nth(1).click()
                    page.get_by_role("button", name="Create change plan", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    assert "protection_profile" not in policy.read_text()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    assert "balanced" in policy.read_text()
                    assert not (config / "policy.yaml").exists()
                    assert "preserve-browser-fixture" in policy.read_text()
                    page.screenshot(path=str(output / "profile-completed.png"), full_page=True)
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="undone").wait_for(timeout=40000)
                    assert "protection_profile" not in policy.read_text()
                    report["checks"].append("profile_preview_apply_readback_undo_preserves_yml")
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_role("button", name="Exceptions", exact=True).click()
                    page.get_by_label("Exact target", exact=True).fill("https://fixture.example/install.sh")
                    page.get_by_label("Rule ID", exact=True).fill("curl_pipe_shell")
                    page.get_by_label("Reason", exact=True).fill("browser fixture")
                    page.get_by_role("button", name="Review exception", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_role("button", name="Refresh", exact=True).click()
                    page.get_by_text("https://fixture.example/install.sh", exact=True).wait_for()
                    page.get_by_role("button", name="Explain trust eligibility", exact=True).click()
                    page.get_by_text("Inspect complete details", exact=True).click()
                    page.get_by_text('"command_evaluated": false', exact=False).wait_for()
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_role("button", name="Revoke", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    report["checks"].append("project_exception_apply_explain_revoke")
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_role("button", name="Settings", exact=True).click()
                    page.get_by_role("heading", name="Saved changes and recovery", exact=True).wait_for()
                    page.get_by_role("button", name="Open saved operation", exact=True).first.click()
                    page.get_by_role("button", name="Refresh stored status", exact=True).wait_for()
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("saved_operation_can_be_reopened_without_replaying")
                    page.get_by_label("Incident event IDs", exact=True).fill(event_id)
                    page.get_by_role("button", name="Preview support report", exact=True).click()
                    page.get_by_role("button", name="Download with fresh redaction", exact=True).wait_for()
                    with page.expect_download() as download_info:
                        page.get_by_role("button", name="Download with fresh redaction", exact=True).click()
                    support = json.loads(Path(download_info.value.path()).read_text())
                    assert support["shared"] is False and support["incidents"][0]["id"] == event_id
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("selected_support_report_previews_and_downloads_without_upload")
                    # The hostile history row above is deliberately a legacy
                    # display fixture. Add an actual writer-produced chain tail
                    # before requesting a verified rotation checkpoint.
                    written = subprocess.run([str(binary), "hook-event", "--integration", "browser-fixture", "--hook-type", "retention", "--event", "before"], cwd=project, env=env, capture_output=True, text=True, timeout=40)
                    assert written.returncode == 0, written.stderr
                    original_audit = audit.read_bytes()
                    page.get_by_role("button", name="Review audit rotation", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    assert audit.read_bytes() == original_audit
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    assert audit.read_bytes() != original_audit
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="undone").wait_for(timeout=40000)
                    assert audit.read_bytes() == original_audit
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("reviewed_audit_rotation_preserves_and_restores_exact_history")
                    page.get_by_role("button", name="Review audit rotation", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    page.get_by_text("Stored operation and recovery details", exact=True).click()
                    segment_id = json.loads(page.locator("#operation-content details pre").last.inner_text())["operation_id"]
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    active_after_rotation = audit.read_bytes()
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_label("Retained segment ID", exact=True).fill(segment_id)
                    page.get_by_role("button", name="Review segment export", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    page.get_by_text("Stored operation and recovery details", exact=True).click()
                    export_id = json.loads(page.locator("#operation-content details pre").last.inner_text())["operation_id"]
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    exported = audit_dir / "audit-exports" / export_id
                    assert (exported / "manifest.json").exists()
                    assert audit.read_bytes() == active_after_rotation
                    page.get_by_role("button", name="Close change details").click()
                    page.get_by_label("I understand that deleting this segment permanently removes its retained records", exact=True).check()
                    page.get_by_role("button", name="Review permanent segment deletion", exact=True).click()
                    page.get_by_text("This operation permanently deletes retained records.", exact=False).wait_for()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="completed").wait_for(timeout=40000)
                    assert page.get_by_role("button", name="Undo owned change", exact=True).count() == 0
                    assert not (audit_dir / "audit-segments" / segment_id / "manifest.json").exists()
                    assert (exported / "manifest.json").exists()
                    assert audit.read_bytes() == active_after_rotation
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("segment_export_and_acknowledged_deletion_preserve_active_log_without_false_undo")
                    page.get_by_role("button", name="Protection", exact=True).click()
                    page.get_by_label("Representative commands, one per line", exact=True).fill("echo review-only\ncurl https://example.org/install.sh | sh")
                    page.get_by_role("button", name="Prepare impact review", exact=True).click()
                    page.get_by_text("Personal profile impact:", exact=False).wait_for()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    page.get_by_text("Personal profile impact:", exact=False).wait_for()
                    assert "balanced" in policy.read_text()
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="undone").wait_for(timeout=40000)
                    assert "protection_profile" not in policy.read_text()
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("impact_review_survives_status_apply_and_undo")
                    page.get_by_role("button", name="Integrations", exact=True).click()
                    # Native select option text participates in Playwright's
                    # wrapping-label lookup; select by its unique label prefix.
                    page.get_by_label("Intended shell", exact=False).select_option("bash")
                    page.get_by_role("button", name="Review setup", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    assert not list((root / "home").glob(".bash*"))
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    profiles = list((root / "home").glob(".bash*"))
                    assert profiles and any("BEGIN tirith-hook" in path.read_text() for path in profiles)
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="undone").wait_for(timeout=40000)
                    assert all("BEGIN tirith-hook" not in path.read_text() for path in profiles if path.exists())
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("shell_setup_plan_apply_undo_uses_owned_startup_blocks")
                    page.get_by_label("Personal setup shell", exact=True).select_option("bash")
                    page.get_by_role("button", name="Review personal setup", exact=True).click()
                    combined_started = time.monotonic()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    # The first three-step debug run was still making recorded
                    # progress at the old 40s fixture deadline. Preserve the
                    # observed duration; this deadline is not a product SLO.
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=120000)
                    report["operation_observations"].append({"kind":"combined_personal_setup_apply",
                        "elapsed_seconds":time.monotonic() - combined_started, "fixture_deadline_seconds":120})
                    assert "balanced" in policy.read_text() and "preserve-browser-fixture" in policy.read_text()
                    assert any("BEGIN tirith-hook" in path.read_text() for path in (root / "home").glob(".bash*"))
                    combined_undo_started = time.monotonic()
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content .badge").filter(has_text="undone").wait_for(timeout=120000)
                    report["operation_observations"].append({"kind":"combined_personal_setup_undo",
                        "elapsed_seconds":time.monotonic() - combined_undo_started, "fixture_deadline_seconds":120})
                    assert "protection_profile" not in policy.read_text()
                    assert all("BEGIN tirith-hook" not in path.read_text() for path in (root / "home").glob(".bash*"))
                    page.get_by_role("button", name="Close change details").click()
                    report["checks"].append("combined_personal_setup_applies_and_undoes_profile_and_hook_together")
                    page.set_viewport_size({"width": 390, "height": 844})
                    page.get_by_role("button", name="Overview", exact=True).click()
                    page.locator('#content[aria-busy="false"]').wait_for()
                    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
                    page.screenshot(path=str(output / "overview-narrow.png"), full_page=True)
                    report["checks"].append("narrow_layout_has_no_horizontal_overflow")
                    assert not errors, errors
                except Exception as error:
                    report.update(passed=False, error=str(error), browser_errors=errors)
                    (output / "browser-results.json").write_text(json.dumps(report, indent=2) + "\n")
                    page.screenshot(path=str(output / "failure.png"), full_page=True)
                    (output / "failure-view.txt").write_text(page.locator("body").inner_text())
                    (output / "failure-details.json").write_text(json.dumps(page.locator("#operation-content pre").all_text_contents(), indent=2))
                    raise
                browser.close()
        finally:
            try:
                request(origin, token, csrf, "/api/quiesce", {})
            except Exception:
                pass
            # Give the service a bounded opportunity to release open Windows
            # directory handles before the temporary fixture is removed.
            time.sleep(1)
        report["binary_unchanged_during_run"] = report["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert report["binary_unchanged_during_run"], "candidate binary changed during browser run"
        report["passed"] = True
        (output / "browser-results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"passed": True, "checks": report["checks"], "binary_sha256": report["binary_sha256"]}))


def run_response_order(binary, output, app_js=None):
    """Delay real API responses; all plans, mutations and lifecycle state are real."""
    output.mkdir(parents=True, exist_ok=True)
    source = app_js.read_bytes() if app_js else None
    report = {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "source_override": source is not None,
              "app_js_sha256": hashlib.sha256(source).hexdigest() if source else None,
              "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "execution_claim": "real_backend_response_order_with_source_override" if source else "embedded_candidate_response_order",
              "checks": [], "requests": [], "delayed_responses": []}
    with tempfile.TemporaryDirectory(prefix="tirith-browser-order-") as temporary:
        root = Path(temporary).resolve()
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("TIRITH_") and key not in {"TIRITH", "SUDO_USER", "SUDO_UID", "SUDO_GID"}}
        for key, suffix in {"HOME":"home", "USERPROFILE":"home", "XDG_CONFIG_HOME":"home/.config",
                            "XDG_CONFIG_DIRS":"config-dirs", "XDG_DATA_HOME":"data", "XDG_STATE_HOME":"state",
                            "XDG_CACHE_HOME":"cache", "XDG_RUNTIME_DIR":"runtime", "APPDATA":"appdata",
                            "LOCALAPPDATA":"local-appdata", "TMPDIR":"temp", "TMP":"temp", "TEMP":"temp"}.items():
            path = root / suffix
            path.mkdir(parents=True, exist_ok=True)
            env[key] = str(path)
        env.update({"TIRITH_OFFLINE":"1", "TIRITH_THREATDB_PATH":str(root / "missing-db"),
                    "TIRITH_THREATDB_SUPPLEMENTAL_PATH":str(root / "missing-supplemental")})
        project = root / "project"
        (project / ".git").mkdir(parents=True)
        policy = root / "home/.config/tirith/policy.yml"
        policy.parent.mkdir()
        policy.write_text("custom_operator_note: preserve-response-order-fixture\n")
        launched = subprocess.run([str(binary), "dashboard", "--no-browser", "--json"], cwd=project,
                                  env=env, capture_output=True, text=True, timeout=45)
        assert launched.returncode == 0, launched.stderr
        launch = json.loads(launched.stdout)
        parsed = urllib.parse.urlsplit(launch["url"])
        origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        token = urllib.parse.parse_qs(parsed.fragment)["token"][0]
        csrf = request(origin, token, "", "/api/session")["csrf"]
        errors, rules, held = [], [], []
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width":1440, "height":1050})
                page.on("pageerror", lambda error: errors.append(str(error)))
                if source is not None:
                    page.route(origin + "/app.js", lambda route: route.fulfill(status=200, content_type="text/javascript", body=source))

                def route_api(route):
                    path = urllib.parse.urlsplit(route.request.url).path
                    body = route.request.post_data_json or {}
                    report["requests"].append({"path":path, **body})
                    for rule in list(rules):
                        if path == rule["path"] and all(body.get(key) == value for key, value in rule.get("match", {}).items()):
                            rules.remove(rule)
                            response = route.fetch(timeout=40000)
                            result = response.json()
                            operation = result.get("operation") or result
                            report["delayed_responses"].append({"label":rule["label"], "operation_id":operation.get("operation_id"),
                                "state":operation.get("state"), "phase":operation.get("phase"), "action":body.get("action"), "http_status":response.status})
                            held.append({"rule":rule, "route":route, "response":response, "body":result})
                            if rule.get("abort"):
                                route.abort("failed")
                            return
                    route.continue_()

                page.route(origin + "/api/**", route_api)

                def wait_until(predicate, timeout=20):
                    deadline = time.monotonic() + timeout
                    while not predicate():
                        assert time.monotonic() < deadline, "bounded browser condition timed out"
                        page.wait_for_timeout(25)

                def delay(label, path, match=None, abort=False):
                    rules.append({"label":label, "path":path, "match":match or {}, "abort":abort})

                def delayed(label):
                    wait_until(lambda: any(item["rule"]["label"] == label for item in held))
                    return next(item for item in held if item["rule"]["label"] == label)

                def release(label):
                    item = delayed(label)
                    item["route"].fulfill(response=item["response"])
                    page.wait_for_timeout(100)
                    return item["body"]

                def navigate(name):
                    page.get_by_role("button", name=name, exact=True).click()
                    page.locator('#content[aria-busy="false"]').wait_for()

                def close():
                    page.get_by_role("button", name="Close change details", exact=True).click()
                    page.wait_for_function("!document.querySelector('#operation-dialog').open")

                def stored():
                    # Operation details remain raw canonical IDs/status, even
                    # when the disclosure widget is collapsed.
                    for text in page.locator("#operation-content details pre").all_text_contents():
                        value = json.loads(text)
                        if "operation_id" in value and "state" in value:
                            return value
                    raise AssertionError("no stored operation in the current dialog")

                def profile(name):
                    navigate("Protection")
                    index = {"comfortable":0, "balanced":1, "strict":2}[name]
                    page.get_by_role("button", name="Compare and review", exact=True).nth(index).click()
                    page.get_by_role("button", name="Create change plan", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    return stored()["operation_id"]

                def terminal(operation_id, allowed=("completed", "completed-with-recovery")):
                    latest = None
                    def finished():
                        nonlocal latest
                        latest = request(origin, token, csrf, "/api/operations", {"operation_id":operation_id, "action":"status"})
                        return latest["state"] in allowed
                    wait_until(finished, timeout=30)
                    return latest

                def undo():
                    page.get_by_role("button", name="Undo owned change", exact=True).wait_for(timeout=40000)
                    page.get_by_role("button", name="Undo owned change", exact=True).click()
                    page.locator("#operation-content > .badge").filter(has_text="undone").wait_for(timeout=40000)
                    close()

                try:
                    page.goto(launch["url"])
                    page.locator('#content[aria-busy="false"]').wait_for()
                    assert "token=" not in page.url
                    first_id = profile("balanced")
                    delay("old-planned-status", "/api/operations", {"operation_id":first_id, "action":"status"})
                    page.get_by_role("button", name="Refresh stored status", exact=True).click()
                    assert delayed("old-planned-status")["body"]["state"] == "planned"
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    wait_until(lambda: stored()["state"] != "planned")
                    page.evaluate("""() => { window.__orderStates = []; window.__orderObserver = new MutationObserver(() => {
                        window.__orderStates.push(document.querySelector('#operation-content > .badge')?.textContent);
                    }); window.__orderObserver.observe(document.querySelector('#operation-content'), {childList:true, subtree:true}); }""")
                    release("old-planned-status")
                    assert "planned" not in page.evaluate("window.__orderStates"), "late status regressed admitted work to planned"
                    assert stored()["operation_id"] == first_id and stored()["state"] != "planned"
                    page.evaluate("window.__orderObserver.disconnect()")
                    undo()
                    report["checks"].append("older_same_id_planned_status_cannot_replace_apply_result")

                    navigate("Protection")
                    page.get_by_label("Representative commands, one per line", exact=True).fill("echo reviewed-only")
                    delay("coalesced-impact", "/api/plans", {"kind":"policy_rollout"})
                    # Two actual submit events, before either network response;
                    # the application must issue one immutable request/UUID.
                    page.get_by_role("button", name="Prepare impact review", exact=True).evaluate("button => { button.form.requestSubmit(); button.form.requestSubmit(); }")
                    impact = delayed("coalesced-impact")["body"]["operation"]
                    page.wait_for_timeout(150)
                    impact_requests = [item for item in report["requests"] if item["path"] == "/api/plans" and item.get("kind") == "policy_rollout"]
                    assert len(impact_requests) == 1, "duplicate prepare submitted multiple network requests"
                    release("coalesced-impact")
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    assert stored()["operation_id"] == impact["operation_id"]
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    undo()
                    report["checks"].append("duplicate_prepare_coalesces_one_real_plan_and_preserves_impact_apply_undo")

                    old_id = profile("comfortable")
                    delay("old-apply", "/api/operations", {"operation_id":old_id, "action":"apply"})
                    page.get_by_role("button", name="Apply reviewed change", exact=True).click()
                    delayed("old-apply")
                    terminal(old_id)
                    close()
                    new_id = profile("strict")
                    release("old-apply")
                    assert stored()["operation_id"] == new_id and stored()["state"] == "planned"
                    page.get_by_role("button", name="Request cancellation", exact=True).click()
                    page.locator("#operation-content > .badge").filter(has_text="cancelled").wait_for(timeout=40000)
                    assert terminal(new_id, ("cancelled",))["operation_id"] == new_id
                    assert terminal(old_id)["state"] in ("completed", "completed-with-recovery")
                    close()
                    report["checks"].append("late_apply_response_cannot_replace_or_redirect_a_new_settings_operation")

                    navigate("Settings")
                    page.get_by_role("button", name="Check and review database refresh", exact=True).click()
                    # Redirected isolated ThreatDB paths deliberately refuse
                    # preview before network access. The real reserved operation
                    # still has persisted refusal state which status can read.
                    page.get_by_role("button", name="Inspect saved lifecycle request", exact=True).wait_for(timeout=40000)
                    page.get_by_role("button", name="Inspect saved lifecycle request", exact=True).click()
                    page.get_by_role("button", name="Refresh lifecycle status", exact=True).wait_for(timeout=40000)
                    lifecycle = json.loads(page.locator("#operation-content details pre").last.text_content())
                    assert lifecycle["phase"] in ("failed", "refresh_required"), lifecycle
                    assert lifecycle["preview"]["compatible"] is False, lifecycle
                    lifecycle_id = lifecycle["operation_id"]
                    delay("old-lifecycle-status", "/api/lifecycle/operation", {"operation_id":lifecycle_id, "action":"status"})
                    page.get_by_role("button", name="Refresh lifecycle status", exact=True).click()
                    delayed("old-lifecycle-status")
                    close()
                    settings_id = profile("balanced")
                    release("old-lifecycle-status")
                    assert stored()["operation_id"] == settings_id
                    page.get_by_role("button", name="Request cancellation", exact=True).click()
                    page.locator("#operation-content > .badge").filter(has_text="cancelled").wait_for(timeout=40000)
                    assert not any(item["path"] == "/api/lifecycle/operation" and item.get("action") == "apply" for item in report["requests"])
                    close()
                    report["checks"].append("stale_lifecycle_response_cannot_take_over_settings_or_launch_an_update")

                    navigate("Protection")
                    page.get_by_role("button", name="Compare and review", exact=True).nth(2).click()
                    delay("uncertain-plan", "/api/plans", {"kind":"profile"}, abort=True)
                    page.get_by_role("button", name="Create change plan", exact=True).click()
                    page.get_by_role("button", name="Retry the same request", exact=True).wait_for()
                    uncertain = delayed("uncertain-plan")["body"]["operation"]["operation_id"]
                    page.get_by_role("button", name="Retry the same request", exact=True).click()
                    page.get_by_role("button", name="Apply reviewed change", exact=True).wait_for()
                    assert stored()["operation_id"] == uncertain
                    retries = [item for item in report["requests"] if item.get("operation_id") == uncertain and item["path"] == "/api/plans"]
                    assert len(retries) == 2 and retries[0] == retries[1]
                    page.get_by_role("button", name="Request cancellation", exact=True).click()
                    page.locator("#operation-content > .badge").filter(has_text="cancelled").wait_for(timeout=40000)
                    close()
                    report["checks"].append("uncertain_prepare_retries_original_id_and_intent_without_new_plan")
                    assert not errors, errors
                    assert "preserve-response-order-fixture" in policy.read_text()
                    page.screenshot(path=str(output / "response-order-complete.png"), full_page=True)
                except Exception as error:
                    report.update(passed=False, error=str(error), browser_errors=errors)
                    page.screenshot(path=str(output / "failure.png"), full_page=True)
                    (output / "failure-view.txt").write_text(page.locator("body").inner_text())
                    raise
                finally:
                    (output / "browser-results.json").write_text(json.dumps(report, indent=2) + "\n")
                    browser.close()
        finally:
            try:
                request(origin, token, csrf, "/api/quiesce", {})
            except Exception:
                pass
            time.sleep(1)
        assert report["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        if app_js:
            assert source == app_js.read_bytes(), "source override changed during the run"
        report["passed"] = True
        (output / "browser-results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"passed":True, "checks":report["checks"], "source_override":report["source_override"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--response-order-only", action="store_true", help="delay real API responses in bounded operation workflows")
    parser.add_argument("--app-js", type=Path, help="explicit source asset override for response-order tests; not embedded-candidate qualification")
    args = parser.parse_args()
    if args.app_js and not args.response_order_only:
        parser.error("--app-js requires --response-order-only")
    if args.response_order_only:
        run_response_order(args.binary.resolve(), args.output.resolve(), args.app_js.resolve() if args.app_js else None)
    else:
        run(args.binary.resolve(), args.output.resolve())
