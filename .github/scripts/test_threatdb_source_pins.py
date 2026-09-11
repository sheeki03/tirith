#!/usr/bin/env python3
"""Deterministic tests for the ThreatDB source-pin watcher."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
