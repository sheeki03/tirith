#!/usr/bin/env python3
"""Focused regression tests for remediation candidate/tree binding."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


VALIDATOR_PATH = Path(__file__).resolve().parents[1] / "validate_ledger.py"
SPEC = importlib.util.spec_from_file_location("validate_ledger", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class CandidateBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.original_root = validator.ROOT
        validator.ROOT = self.repo
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Ledger Test")
        self.git("config", "user.email", "ledger@example.invalid")
        self.write("src/code.txt", "base\n")
        self.base = self.commit("base")

    def tearDown(self) -> None:
        validator.ROOT = self.original_root
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def write(self, relative: str, contents: str) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "--all")
        self.git("commit", "-m", message)
        return self.git("rev-parse", "HEAD")

    def merge_tree(self, base: str, candidate: str) -> str:
        return validator.synthetic_merge_tree(base, candidate)

    @staticmethod
    def ledger(owner: str, fix_commits: list[str]) -> dict[str, object]:
        return {
            "closure_evidence_bundle_path": "docs/security/closure-evidence.json",
            "findings": [
                {
                    "owner": owner,
                    "remediation": {"fix_commits": fix_commits},
                }
            ],
        }

    def test_candidate_may_be_followed_only_by_tracker_changes(self) -> None:
        self.write("src/code.txt", "fixed\n")
        candidate = self.commit("owned fix")
        self.write("main.md", "generated tracker\n")
        self.write("docs/security/remediation/findings.json", "{}\n")
        self.write("docs/security/closure-evidence.json", "{}\n")
        head = self.commit("tracker evidence")

        validator.validate_candidate_checkout(
            candidate,
            head,
            "docs/security/closure-evidence.json",
        )

    def test_candidate_rejects_later_non_tracker_change(self) -> None:
        self.write("src/code.txt", "fixed\n")
        candidate = self.commit("owned fix")
        self.write("src/other.txt", "later code\n")
        head = self.commit("later non-tracker change")

        with self.assertRaisesRegex(
            validator.ValidationError,
            "non-tracker changes after --candidate-sha",
        ):
            validator.validate_candidate_checkout(
                candidate,
                head,
                "docs/security/closure-evidence.json",
            )

    def test_candidate_must_be_ancestor_of_checkout(self) -> None:
        self.write("src/code.txt", "candidate\n")
        candidate = self.commit("candidate")
        self.git("checkout", "-b", "side", self.base)
        self.write("src/code.txt", "side\n")
        head = self.commit("side")

        with self.assertRaisesRegex(validator.ValidationError, "must be an ancestor"):
            validator.validate_candidate_checkout(
                candidate,
                head,
                "docs/security/closure-evidence.json",
            )

    def test_real_delta_and_owned_fix_commit_are_required_together(self) -> None:
        self.write("src/code.txt", "fixed\n")
        candidate = self.commit("owned fix")

        validator.validate_candidate_delta(
            self.base,
            candidate,
            self.merge_tree(self.base, candidate),
            self.ledger("poststack-gateway-runtime", [candidate]),
            "poststack-gateway-runtime",
        )

    def test_tracker_only_candidate_is_not_a_real_layer(self) -> None:
        self.write("main.md", "tracker only\n")
        candidate = self.commit("tracker only")

        with self.assertRaisesRegex(validator.ValidationError, "no non-tracker subject-tree delta"):
            validator.validate_candidate_delta(
                self.base,
                candidate,
                self.merge_tree(self.base, candidate),
                self.ledger("poststack-gateway-runtime", [candidate]),
                "poststack-gateway-runtime",
            )

    def test_fix_commit_must_belong_to_selected_owner_and_range(self) -> None:
        self.write("src/code.txt", "fixed\n")
        candidate = self.commit("unowned code change")

        with self.assertRaisesRegex(validator.ValidationError, "no fix commit owned by"):
            validator.validate_candidate_delta(
                self.base,
                candidate,
                self.merge_tree(self.base, candidate),
                self.ledger("poststack-mcp-identity", [candidate]),
                "poststack-gateway-runtime",
            )

    def test_missing_base_blob_is_bootstrap(self) -> None:
        self.assertIsNone(
            validator.git_show_json(self.base, "docs/security/remediation/findings.json")
        )

    def test_unreadable_base_ref_fails_closed(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "cannot read"):
            validator.git_show_json("not-a-real-commit", "docs/security/remediation/findings.json")


if __name__ == "__main__":
    unittest.main()
