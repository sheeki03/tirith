#!/usr/bin/env python3
"""Regression tests for retained blocker closure accounting."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "validate_ledger.py"
SPEC = importlib.util.spec_from_file_location("validate_ledger", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

RENDERER_PATH = Path(__file__).resolve().parents[1] / "render_main.py"
RENDERER_SPEC = importlib.util.spec_from_file_location("render_main", RENDERER_PATH)
assert RENDERER_SPEC is not None and RENDERER_SPEC.loader is not None
renderer = importlib.util.module_from_spec(RENDERER_SPEC)
RENDERER_SPEC.loader.exec_module(renderer)


def _history(event: str, date: str, blocker_id: str | None = None) -> dict:
    value = {
        "event": event,
        "lifecycle": "confirmed_open",
        "date": date,
        "reason": f"record {event}",
    }
    if blocker_id is not None:
        value["blocker_id"] = blocker_id
    return value


def _finding(closed_date: str | None = None) -> dict:
    blocker_id = "blocked_external_gate"
    history = [
        _history("imported", "2026-08-01"),
        _history("blocker_added", "2026-08-02", blocker_id),
    ]
    if closed_date is not None:
        history.append(_history("blocker_cleared", closed_date, blocker_id))
    return {
        "finding_id": "TIRITH-SEC-0001",
        "lifecycle": "confirmed_open",
        "blockers": [
            {
                "blocker_id": blocker_id,
                "reason": "external gate is pending",
                "opened_date": "2026-08-02",
                "closed_date": closed_date,
            }
        ],
        "history": history,
        "source_links": [],
    }


class BlockerClosureAccountingTests(unittest.TestCase):
    def test_active_blocker_remains_release_active(self) -> None:
        finding = _finding()
        validator.validate_history(finding, finding["finding_id"])
        self.assertEqual(
            ["blocked_external_gate"],
            [item["blocker_id"] for item in validator.active_blockers(finding)],
        )

    def test_closed_blocker_is_retained_but_not_release_active(self) -> None:
        finding = _finding("2026-08-03")
        validator.validate_history(finding, finding["finding_id"])
        self.assertEqual([], validator.active_blockers(finding))
        self.assertEqual("2026-08-03", finding["blockers"][0]["closed_date"])

    def test_closed_date_without_matching_history_is_rejected(self) -> None:
        finding = _finding("2026-08-03")
        finding["history"].pop()
        with self.assertRaisesRegex(validator.ValidationError, "blocker_cleared"):
            validator.validate_history(finding, finding["finding_id"])

    def test_mismatched_closure_date_is_rejected(self) -> None:
        finding = _finding("2026-08-03")
        finding["history"][-1]["date"] = "2026-08-04"
        with self.assertRaisesRegex(validator.ValidationError, "closed_date differs"):
            validator.validate_history(finding, finding["finding_id"])

    def test_history_cannot_clear_an_unknown_blocker(self) -> None:
        finding = _finding()
        finding["history"].append(
            _history("blocker_cleared", "2026-08-03", "blocked_unknown")
        )
        with self.assertRaisesRegex(validator.ValidationError, "unknown blocker"):
            validator.validate_history(finding, finding["finding_id"])

    def test_history_cannot_clear_before_add(self) -> None:
        finding = _finding("2026-08-03")
        finding["history"][1], finding["history"][2] = (
            finding["history"][2],
            finding["history"][1],
        )
        with self.assertRaisesRegex(validator.ValidationError, "cleared before"):
            validator.validate_history(finding, finding["finding_id"])

    def test_append_only_allows_one_way_closure_and_retains_record(self) -> None:
        base = _finding()
        current = _finding("2026-08-03")
        validator.compare_against_base(
            {"findings": [base]},
            {current["finding_id"]: current},
        )

        deleted = copy.deepcopy(current)
        deleted["blockers"] = []
        with self.assertRaisesRegex(validator.ValidationError, "closure record.*deleted"):
            validator.compare_against_base(
                {"findings": [current]},
                {deleted["finding_id"]: deleted},
            )

        reopened = copy.deepcopy(current)
        reopened["blockers"][0]["closed_date"] = None
        with self.assertRaisesRegex(validator.ValidationError, "blocker closure changed"):
            validator.compare_against_base(
                {"findings": [current]},
                {reopened["finding_id"]: reopened},
            )

    def test_human_status_counts_only_active_blockers(self) -> None:
        merge_commit = "a" * 40
        finding = _finding("2026-08-03")
        finding.update(
            {
                "lifecycle": "merged_verified",
                "resolution_route": "local",
                "verification": {
                    "merge_commit": merge_commit,
                    "attempts": [
                        {
                            "kind": "release",
                            "head_sha": merge_commit,
                            "result": "passed",
                        }
                    ],
                },
            }
        )
        self.assertEqual("FIXED", renderer.display_status(finding))
        finding["blockers"][0]["closed_date"] = None
        self.assertEqual("OPEN", renderer.display_status(finding))


if __name__ == "__main__":
    unittest.main()
