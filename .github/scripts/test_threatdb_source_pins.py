#!/usr/bin/env python3
"""Deterministic tests for the ThreatDB source-pin watcher."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import ssl


SCRIPT_DIR = Path(__file__).resolve().parent
MANIFEST = SCRIPT_DIR / "fixtures" / "threatdb-source-pins.json"
SPEC = importlib.util.spec_from_file_location(
    "threatdb_source_pins", SCRIPT_DIR / "threatdb_source_pins.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load threatdb_source_pins.py")
PINS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PINS)


def commit(sha: str, timestamp: str, subject: str) -> dict[str, object]:
    return {
        "sha": sha,
        "commit": {
            "committer": {"date": timestamp},
            "message": subject,
        },
    }


class ThreatDbSourcePinsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = PINS.load_manifest(MANIFEST)
        self.old_ossf = self.manifest["sources"]["ossf_malicious_packages"]["commit"]
        self.old_datadog = self.manifest["sources"][
            "datadog_malicious_software_packages"
        ]["commit"]
        self.typosquat = self.manifest["sources"]["ecosystems_typosquatting_dataset"][
            "commit"
        ]
        self.typosquat_timestamp = self.manifest["sources"][
            "ecosystems_typosquatting_dataset"
        ]["commit_timestamp"]
        self.new_ossf = "a" * 40
        self.transient_ossf = "b" * 40
        self.new_datadog = "c" * 40
        self.fixture = {
            "commits": {
                "ossf/malicious-packages": [
                    commit(
                        self.transient_ossf,
                        "2026-09-01T01:10:00Z",
                        "Ingest OSV - Cloud Storage",
                    ),
                    commit(self.new_ossf, "2026-09-01T01:08:00Z", "Assign IDs"),
                ],
                "DataDog/malicious-software-packages-dataset": [
                    commit(self.new_datadog, "2026-09-01T00:30:00Z", "Sync manifests")
                ],
                "ecosyste-ms/typosquatting-dataset": [
                    commit(
                        self.typosquat,
                        self.typosquat_timestamp,
                        "Add tools and API information",
                    )
                ],
            },
            "comparisons": {
                (f"ossf/malicious-packages:{self.old_ossf}...{self.new_ossf}"): {
                    "status": "ahead",
                    "ahead_by": 4,
                    "total_commits": 4,
                    "files": [
                        {"status": "added", "filename": "osv/malicious/npm/a.json"},
                        {"status": "modified", "filename": "config/config.toml"},
                    ],
                },
                (
                    "DataDog/malicious-software-packages-dataset:"
                    f"{self.old_datadog}...{self.new_datadog}"
                ): {
                    "status": "ahead",
                    "ahead_by": 2,
                    "total_commits": 2,
                    "files": [
                        {"status": "modified", "filename": "samples/npm/manifest.json"}
                    ],
                },
            },
        }

    def fixture_client(self, directory: Path):
        fixture_path = directory / "api.json"
        fixture_path.write_text(json.dumps(self.fixture), encoding="utf-8")
        return PINS.FixtureClient(fixture_path)

    def datadog_compare_answers(self, status: int) -> None:
        key = (
            "DataDog/malicious-software-packages-dataset:"
            f"{self.old_datadog}...{self.new_datadog}"
        )
        self.fixture["comparisons"][key] = {"http_status": status}

    def run_cli(self, directory: Path, *arguments: str) -> tuple[int, str]:
        fixture_path = directory / "api.json"
        fixture_path.write_text(json.dumps(self.fixture), encoding="utf-8")
        argv = [
            "threatdb_source_pins.py",
            *arguments,
            "--api-fixture",
            str(fixture_path),
            "--now",
            "2026-09-01T02:00:00Z",
        ]
        stderr = io.StringIO()
        stdout = io.StringIO()
        with patch.object(PINS.sys, "argv", argv), contextlib.redirect_stderr(
            stderr
        ), contextlib.redirect_stdout(stdout):
            try:
                code = PINS.main()
            except SystemExit as error:
                code = error.code
        self.last_stdout = stdout.getvalue()
        return code, stderr.getvalue()

    def test_manifest_resolves_exact_required_sources(self) -> None:
        self.assertEqual(set(self.manifest["sources"]), set(PINS.SOURCE_ORDER))
        for source_name in PINS.SOURCE_ORDER:
            source = self.manifest["sources"][source_name]
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")

    def test_production_manifest_is_valid_independently_of_fixture_revisions(self) -> None:
        PINS.load_manifest(SCRIPT_DIR.parent / "threatdb-source-pins.json")

    def test_update_skips_transient_ossf_ingestion_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            client = self.fixture_client(Path(temporary))
            changed, changes = PINS.update_pins(
                self.manifest, client, "2026-09-01T02:00:00Z"
            )
            self.assertTrue(changed)
            self.assertEqual(
                self.manifest["sources"]["ossf_malicious_packages"]["commit"],
                self.new_ossf,
            )
            self.assertNotEqual(
                self.manifest["sources"]["ossf_malicious_packages"]["commit"],
                self.transient_ossf,
            )
            self.assertEqual(
                self.manifest["sources"]["datadog_malicious_software_packages"][
                    "commit"
                ],
                self.new_datadog,
            )
            self.assertEqual(
                [item["source"] for item in changes if item["changed"]],
                [
                    "ossf_malicious_packages",
                    "datadog_malicious_software_packages",
                ],
            )
            report = PINS.render_report("2026-09-01T02:00:00Z", changes)
            self.assertIn("osv", report)
            self.assertIn("samples", report)
            self.assertIn("Do not auto-merge", report)

            changed_again, _ = PINS.update_pins(
                self.manifest, client, "2026-09-01T02:05:00Z"
            )
            self.assertFalse(changed_again)

    def test_ossf_assign_ids_discovery_paginates_past_transient_commits(self) -> None:
        transient_page = [
            commit(
                f"{index + 1:040x}",
                "2026-09-01T01:10:00Z",
                "Ingest OSV - Cloud Storage",
            )
            for index in range(PINS.COMMITS_PER_PAGE)
        ]
        self.fixture["commits"]["ossf/malicious-packages"] = {
            "1": transient_page,
            "2": [commit(self.new_ossf, "2026-09-01T01:08:00Z", "Assign IDs")],
        }

        with tempfile.TemporaryDirectory() as temporary:
            client = self.fixture_client(Path(temporary))
            candidate = PINS.discover_candidate(
                self.manifest["sources"]["ossf_malicious_packages"], client
            )

        self.assertEqual(candidate["commit"], self.new_ossf)
        self.assertEqual(candidate["subject"], "Assign IDs")

    def test_manifest_rejects_unreviewed_repository_and_bad_metadata(self) -> None:
        wrong_repository = copy.deepcopy(self.manifest)
        wrong_repository["sources"]["ossf_malicious_packages"]["repository"] = (
            "attacker/malicious-packages"
        )
        with self.assertRaises(PINS.PinError):
            PINS.validate_manifest(wrong_repository)

        bad_commit = copy.deepcopy(self.manifest)
        bad_commit["sources"]["ossf_malicious_packages"]["commit"] = "A" * 40
        with self.assertRaises(PINS.PinError):
            PINS.validate_manifest(bad_commit)

        selected_too_early = copy.deepcopy(self.manifest)
        selected_too_early["sources"]["ossf_malicious_packages"]["selected_at"] = (
            "2020-01-01T00:00:00Z"
        )
        with self.assertRaises(PINS.PinError):
            PINS.validate_manifest(selected_too_early)

    def test_comparison_must_be_strictly_ahead(self) -> None:
        with self.assertRaises(PINS.PinError):
            PINS.summarize_comparison(
                "ossf/malicious-packages",
                self.old_ossf,
                self.new_ossf,
                {"status": "diverged", "ahead_by": 1, "total_commits": 1, "files": []},
            )

    def test_observation_does_not_adopt_pins_and_old_unchanged_is_current(self) -> None:
        original = copy.deepcopy(self.manifest)
        with tempfile.TemporaryDirectory() as temporary:
            client = self.fixture_client(Path(temporary))
            _, changes = PINS.update_pins(copy.deepcopy(self.manifest), client, "2026-09-01T02:00:00Z")
        document = PINS.observation_document("2026-09-01T02:00:00Z", changes)
        self.assertEqual(self.manifest, original)
        old = document["sources"]["ecosystems_typosquatting_dataset"]
        self.assertFalse(old["review_required"])
        self.assertEqual(old["ahead_by"], 0)
        pending = document["sources"]["ossf_malicious_packages"]
        self.assertTrue(pending["review_required"])
        self.assertEqual(pending["pinned_commit"], self.old_ossf)

    def test_observe_records_a_compare_github_cannot_generate_and_exits_zero(self) -> None:
        self.datadog_compare_answers(422)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = directory / "observations.json"
            code, stderr = self.run_cli(
                directory, "observe", str(MANIFEST), "--result", str(result)
            )
            self.assertEqual(code, 0, stderr)
            document = json.loads(result.read_text(encoding="utf-8"))
        datadog = document["sources"]["datadog_malicious_software_packages"]
        self.assertIsNone(datadog["ahead_by"])
        self.assertEqual(datadog["comparison_unavailable"], "github_http_422")
        self.assertTrue(datadog["review_required"])
        self.assertEqual(datadog["pinned_commit"], self.old_datadog)
        self.assertEqual(datadog["candidate_commit"], self.new_datadog)
        self.assertEqual(datadog["candidate_timestamp"], "2026-09-01T00:30:00Z")
        ossf = document["sources"]["ossf_malicious_packages"]
        self.assertEqual(ossf["ahead_by"], 4)
        self.assertNotIn("comparison_unavailable", ossf)
        self.assertIn("datadog_malicious_software_packages", stderr)
        self.assertIn("HTTP 422", stderr)
        self.assertNotIn("::warning", self.last_stdout)

    def test_report_keeps_staleness_visible_for_a_skipped_source(self) -> None:
        item = {
            "candidate": {
                "commit": "b" * 40,
                "commit_timestamp": "2026-10-15T08:38:07Z",
                "subject": "update",
            },
            "comparison_unavailable": "github_http_422",
            "lag_hours": 816.0,
            "max_lag_hours": 168,
            "old_commit": "a" * 40,
            "policy": "latest_successful_upstream_commit",
            "proposed": False,
            "repository": "DataDog/malicious-software-packages-dataset",
            "source": "datadog_malicious_software_packages",
            "stale": True,
        }
        rendered = PINS.render_report("2026-10-16T00:00:00Z", [item])
        self.assertIn(
            "| datadog_malicious_software_packages | skipped (stale) |", rendered
        )

    def test_actions_runs_annotate_a_source_github_cannot_compare(self) -> None:
        self.datadog_compare_answers(422)
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            PINS.os.environ, {"GITHUB_ACTIONS": "true"}
        ):
            directory = Path(temporary)
            result = directory / "observations.json"
            code, stderr = self.run_cli(
                directory, "observe", str(MANIFEST), "--result", str(result)
            )
        self.assertEqual(code, 0, stderr)
        annotations = [
            line for line in self.last_stdout.splitlines() if line.startswith("::warning")
        ]
        self.assertEqual(len(annotations), 1, self.last_stdout)
        self.assertTrue(
            annotations[0].startswith("::warning title=ThreatDB source pin not updated::")
        )
        self.assertIn("datadog_malicious_software_packages", annotations[0])
        self.assertIn("HTTP 422", annotations[0])

    def test_watcher_skips_an_uncomparable_source_and_proposes_the_rest(self) -> None:
        self.datadog_compare_answers(422)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = directory / "pins.json"
            shutil.copy(MANIFEST, manifest)
            report = directory / "report.md"
            result = directory / "result.json"
            code, stderr = self.run_cli(
                directory, "update", str(manifest),
                "--report", str(report), "--result", str(result),
            )
            self.assertEqual(code, 0, stderr)
            proposed = PINS.load_manifest(manifest)["sources"]
            outcome = json.loads(result.read_text(encoding="utf-8"))
            rendered = report.read_text(encoding="utf-8")
        self.assertEqual(proposed["ossf_malicious_packages"]["commit"], self.new_ossf)
        self.assertEqual(
            proposed["datadog_malicious_software_packages"],
            self.manifest["sources"]["datadog_malicious_software_packages"],
        )
        self.assertTrue(outcome["changed"])
        self.assertEqual(outcome["changed_sources"], ["ossf_malicious_packages"])
        self.assertEqual(
            outcome["skipped_sources"], ["datadog_malicious_software_packages"]
        )
        self.assertIn("| datadog_malicious_software_packages | skipped |", rendered)
        self.assertIn("not proposed", rendered)
        self.assertIn("github_http_422", rendered)

    def test_watcher_writes_nothing_when_the_only_moved_source_is_uncomparable(self) -> None:
        self.datadog_compare_answers(422)
        self.fixture["commits"]["ossf/malicious-packages"] = [
            commit(
                self.old_ossf,
                self.manifest["sources"]["ossf_malicious_packages"]["commit_timestamp"],
                "Assign IDs",
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = directory / "pins.json"
            shutil.copy(MANIFEST, manifest)
            result = directory / "result.json"
            code, stderr = self.run_cli(
                directory, "update", str(manifest),
                "--report", str(directory / "report.md"), "--result", str(result),
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(manifest.read_bytes(), MANIFEST.read_bytes())
            outcome = json.loads(result.read_text(encoding="utf-8"))
        self.assertFalse(outcome["changed"])
        self.assertEqual(outcome["changed_sources"], [])

    def test_other_compare_failures_and_unproven_candidates_still_fail(self) -> None:
        self.datadog_compare_answers(404)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(PINS.PinError, "HTTP 404") as raised:
                PINS.update_pins(
                    copy.deepcopy(self.manifest),
                    self.fixture_client(directory),
                    "2026-09-01T02:00:00Z",
                )
            self.assertNotIsInstance(raised.exception, PINS.ComparisonUnavailable)
            result = directory / "observations.json"
            code, _ = self.run_cli(
                directory, "observe", str(MANIFEST), "--result", str(result)
            )
            self.assertEqual(code, 2)
            self.assertFalse(result.exists())

        key = (
            "DataDog/malicious-software-packages-dataset:"
            f"{self.old_datadog}...{self.new_datadog}"
        )
        self.fixture["comparisons"][key] = {
            "status": "diverged", "ahead_by": 2, "total_commits": 2, "files": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(PINS.PinError, "strictly ahead"):
                PINS.update_pins(
                    copy.deepcopy(self.manifest),
                    self.fixture_client(Path(temporary)),
                    "2026-09-01T02:00:00Z",
                )

    def test_live_client_treats_only_a_compare_422_as_unavailable(self) -> None:
        def refusal(status: int) -> urllib.error.HTTPError:
            return urllib.error.HTTPError(
                "https://api.github.com/x", status, "refused", {}, None
            )

        with patch.object(PINS.urllib.request, "urlopen", side_effect=refusal(422)) as opener:
            with self.assertRaises(PINS.ComparisonUnavailable) as raised:
                PINS.GitHubClient(None).compare("o/r", "a" * 40, "b" * 40)
            self.assertEqual(raised.exception.reason, "github_http_422")
            self.assertEqual(opener.call_count, 1)
        for status, call in [
            (404, lambda client: client.compare("o/r", "a" * 40, "b" * 40)),
            (422, lambda client: client.commits("o/r")),
        ]:
            with patch.object(PINS.urllib.request, "urlopen", side_effect=refusal(status)):
                with self.assertRaises(PINS.GitHubStatusError) as raised:
                    call(PINS.GitHubClient(None))
                self.assertNotIsInstance(raised.exception, PINS.ComparisonUnavailable)

    def test_retry_obeys_server_backoff_and_overall_deadline(self) -> None:
        self.assertEqual(PINS.retry_delay("4", 0, 10), 4)
        self.assertIsNone(PINS.retry_delay("12", 0, 10))
        self.assertIsNone(PINS.retry_delay("bad", 0, 10))
        self.assertIsNone(PINS.retry_delay("0", 2, 10))
        with patch.object(PINS.time, "time", return_value=0):
            self.assertEqual(PINS.retry_delay("Thu, 01 Jan 1970 00:00:04 GMT", 0, 10), 4)

    def test_rate_limit_recovers_but_schema_and_identity_fail_once(self) -> None:
        response = io.BytesIO(b'{"ok":true}')
        response.status = 200
        limited = urllib.error.HTTPError("https://api.github.com/x", 429, "limited", {"Retry-After": "0"}, None)
        with patch.object(PINS.urllib.request, "urlopen", side_effect=[limited, response]) as opener, patch.object(PINS.time, "sleep"):
            self.assertEqual(PINS.GitHubClient(None)._get("/x"), {"ok": True})
            self.assertEqual(opener.call_count, 2)
        invalid = io.BytesIO(b'<html>not metadata</html>')
        invalid.status = 200
        with patch.object(PINS.urllib.request, "urlopen", return_value=invalid) as opener:
            with self.assertRaisesRegex(PINS.PinError, "schema"):
                PINS.GitHubClient(None)._get("/x")
            self.assertEqual(opener.call_count, 1)
        with patch.object(PINS.urllib.request, "urlopen", side_effect=urllib.error.URLError(ssl.SSLCertVerificationError("untrusted"))) as opener:
            with self.assertRaisesRegex(PINS.PinError, "identity"):
                PINS.GitHubClient(None)._get("/x")
            self.assertEqual(opener.call_count, 1)


if __name__ == "__main__":
    unittest.main()
