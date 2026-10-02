#!/usr/bin/env python3
"""Tests for check-doc-links.py, plus the check of this repository's docs."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_doc_links", ROOT / ".github/scripts/check-doc-links.py"
)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def repo(files):
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return tmp, root


class Checker(unittest.TestCase):
    def problems(self, files):
        tmp, root = repo(files)
        with tmp:
            return checker.check(root)

    def test_clean_links_pass(self):
        self.assertEqual(
            self.problems({
                "README.md": "# Top\n\nSee [guide](docs/guide.md#first-step), "
                "[dir](docs/), [web](https://example.invalid/x) and [here](#top).\n",
                "docs/guide.md": "# Guide\n\n## First step\n\n[back](../README.md)\n",
            }),
            [],
        )

    def test_missing_file_is_reported(self):
        found = self.problems({"README.md": "[gone](docs/gone.md)\n"})
        self.assertEqual(len(found), 1)
        self.assertIn("README.md:1: broken link", found[0])

    def test_missing_anchor_is_reported(self):
        found = self.problems({
            "README.md": "[x](docs/a.md#nope)\n",
            "docs/a.md": "# A\n",
        })
        self.assertEqual(len(found), 1)
        self.assertIn("broken anchor", found[0])

    def test_duplicate_headings_get_numbered_slugs(self):
        self.assertEqual(
            self.problems({"a.md": "# Run\n\n# Run\n\n[second](#run-1)\n"}), []
        )

    def test_reference_definitions_are_checked(self):
        found = self.problems({"a.md": "[x][ref]\n\n[ref]: missing.md\n"})
        self.assertEqual(len(found), 1)

    def test_code_is_ignored_for_links(self):
        self.assertEqual(
            self.problems({"a.md": "```\n[x](missing.md)\n```\n`[y](missing.md)`\n"}),
            [],
        )

    def test_removed_commands_are_reported_even_in_code(self):
        found = self.problems({
            "a.md": "Run `tirith menu`.\n\n```sh\ntirith pkg install-npm x\n"
            "tirith pkg materialize y\n```\n",
        })
        self.assertEqual(len(found), 3)

    def test_refused_trust_add_examples_are_reported(self):
        found = self.problems({
            "a.md": "```bash\n"
            "tirith trust add example.com  # no rule, no --broad\n"
            "tirith trust add example.com --rule pipe_to_interpreter\n"
            "tirith trust add raw.example.dev/x/get.sh\n"
            "tirith trust add '*.example.dev' --all-rules\n"
            "```\n"
            "Run `tirith trust add example.dev/get.sh`.\n",
        })
        self.assertEqual(len(found), 6, found)
        self.assertIn("a.md:2:", found[0])

    def test_accepted_trust_add_examples_pass(self):
        self.assertEqual(
            self.problems({
                "a.md": "```bash\n"
                "tirith trust add example.dev/x/get.sh --rule pipe_to_interpreter\n"
                "tirith trust add example.com --broad --all-rules --permanent\n"
                "tirith trust add example.com \\\n  --broad --rule=curl_pipe_shell\n"
                "tirith trust add --help\n"
                "```\n"
                "`tirith trust add --help` lists flags; `trust add` needs a rule.\n",
            }),
            [],
        )

    def test_disabled_pkg_examples_are_reported(self):
        found = self.problems({
            "a.md": "```bash\n"
            "tirith pkg approve pip requests==2.31.0 --target .t\n"
            "tirith pkg install pip requests==2.31.0 --target .t\n"
            "tirith pkg install --help\n"
            "tirith pkg verify-env --target .t requests\n"
            "```\n"
            "`tirith pkg install pip` currently refuses.\n",
        })
        self.assertEqual(len(found), 2, found)

    def test_source_comment_doc_paths_are_checked(self):
        found = self.problems({
            "docs/real.md": "# Real\n",
            "src/lib.rs": "//! See docs/real.md and docs/gone.md.\n"
            "let s = \"docs/fixture-data.md\";\n"
            "// e.g. `docs/examples/.claude/skills/demo.md`\n",
        })
        self.assertEqual(len(found), 1)
        self.assertIn("docs/gone.md", found[0])

    def test_links_leaving_the_repository_are_not_checked(self):
        self.assertEqual(self.problems({"SECURITY.md": "[r](../../security/advisories/new)\n"}), [])


class RepositoryDocs(unittest.TestCase):
    def test_repository_docs_have_no_broken_links(self):
        self.assertEqual(checker.check(ROOT), [])


if __name__ == "__main__":
    unittest.main()
