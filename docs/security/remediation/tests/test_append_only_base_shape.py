#!/usr/bin/env python3
"""Regression tests for append-only validation against an unreadable base.

`validate_append_only` reads the ledger as it stood at the base ref and proves
every canonical finding survived and was only extended. It indexes the base
content directly (`old["history"]`, `x["affected_seams"]`, ...), so a base
carrying an older schema or simply malformed content raised KeyError/TypeError.

`main()` only catches ValidationError, OSError and SubprocessError, so that
escaped as a bare traceback: on the one check whose job is rejecting rewritten
history, the failure read as a broken tool rather than as a verdict.

It must fail CLOSED. "Could not check" is not "checked and fine", and rewriting
the base into a shape the validator chokes on must not be a way to skip the
check.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "validate_ledger.py"
SPEC = importlib.util.spec_from_file_location("validate_ledger", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def _finding(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "history": [{"state": "triaged"}],
        "source_links": [
            {
                "source_id": "SRC-1",
                "canonical_root_id": "ROOT-1",
                "mapping_type": "direct",
                "mapped_claims": ["claim"],
                "affected_seams": ["seam"],
                "rationale": "because",
            }
        ],
    }


class AppendOnlyBaseShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.current = {"findings": [_finding("F-1")]}
        self.by_id = {item["finding_id"]: item for item in self.current["findings"]}

    def test_a_well_formed_base_still_validates(self) -> None:
        """The guard must not swallow the ordinary passing path."""
        validator.compare_against_base({"findings": [_finding("F-1")]}, self.by_id)

    def test_a_genuine_violation_is_still_reported_as_a_violation(self) -> None:
        """A deleted finding is a real verdict, not a shape problem."""
        base = {"findings": [_finding("F-1"), _finding("F-2")]}
        with self.assertRaises(validator.ValidationError) as caught:
            validator.compare_against_base(base, self.by_id)
        self.assertIn("canonical finding deleted", str(caught.exception))

    def test_history_rewrite_is_still_reported(self) -> None:
        base = {"findings": [_finding("F-1")]}
        base["findings"][0]["history"] = [{"state": "something-else"}]
        with self.assertRaises(validator.ValidationError) as caught:
            validator.compare_against_base(base, self.by_id)
        self.assertIn("append-only", str(caught.exception))

    def test_every_malformed_base_shape_raises_rather_than_passing(self) -> None:
        """Each of these used to escape as an uncaught traceback.

        `compare_against_base` is allowed to raise the raw exception; what must
        never happen is that it RETURNS, because returning means the caller
        records append-only as proven.
        """
        cases = {
            "findings key absent": {},
            "findings is not a list": {"findings": "nope"},
            "finding is not a mapping": {"findings": ["nope"]},
            "finding_id absent": {"findings": [{"history": []}]},
            "history absent": {"findings": [{"finding_id": "F-1"}]},
            "source_links absent": {
                "findings": [{"finding_id": "F-1", "history": [{"state": "triaged"}]}]
            },
            "source link missing a field": {
                "findings": [
                    {
                        "finding_id": "F-1",
                        "history": [{"state": "triaged"}],
                        "source_links": [{"source_id": "SRC-1"}],
                    }
                ]
            },
            "mapped_claims not iterable": {
                "findings": [
                    {
                        "finding_id": "F-1",
                        "history": [{"state": "triaged"}],
                        "source_links": [
                            {
                                "source_id": "SRC-1",
                                "canonical_root_id": "ROOT-1",
                                "mapping_type": "direct",
                                "mapped_claims": 7,
                                "affected_seams": ["seam"],
                                "rationale": "because",
                            }
                        ],
                    }
                ]
            },
        }
        for label, base in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(
                    (AttributeError, IndexError, KeyError, TypeError, validator.ValidationError),
                    msg=f"{label}: must not report append-only as proven",
                ):
                    validator.compare_against_base(base, self.by_id)


class AppendOnlyRefusalMessageTests(unittest.TestCase):
    """The wrapper must turn a shape problem into a readable REFUSAL."""

    def setUp(self) -> None:
        self.original = validator.git_show_json
        self.ledger = {"findings": [_finding("F-1")]}

    def tearDown(self) -> None:
        validator.git_show_json = self.original

    def test_an_unreadable_base_is_a_refusal_not_a_pass(self) -> None:
        # Malformed findings.json at the base; source-index lookup is irrelevant
        # because the refusal happens first.
        validator.git_show_json = lambda base_ref, relative: {"findings": [{"no": "id"}]}
        with self.assertRaises(validator.ValidationError) as caught:
            validator.validate_append_only("deadbeef", self.ledger)
        message = str(caught.exception)
        self.assertIn("cannot verify append-only", message)
        self.assertIn("refusal, not a pass", message)
        # The exception type is named so an operator can tell a schema drift
        # from a truncated file without re-running under a debugger.
        self.assertIn("KeyError", message)

    def test_an_absent_base_is_still_a_clean_skip(self) -> None:
        # `git_show_json` returning None means the file did not exist at the
        # base ref, which is a legitimate no-op and must stay one.
        validator.git_show_json = lambda base_ref, relative: None
        validator.validate_append_only("deadbeef", self.ledger)


if __name__ == "__main__":
    unittest.main()
