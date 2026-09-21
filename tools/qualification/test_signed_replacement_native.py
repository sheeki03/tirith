#!/usr/bin/env python3
"""Parser/crypto/storage unit controls only; these never qualify a native swap."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import signed_replacement_inputs as inputs
import signed_replacement_native as runner


class SignedReplacementInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="signed-fixture-parser-")
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name, body):
        path = self.root / name
        inputs.write_new(path, body)
        return path

    def test_duplicate_json_and_boolean_size_are_refused(self):
        with self.assertRaises(ValueError):
            inputs.parse_json(b'{"version":1,"version":2}')
        with self.assertRaises(ValueError):
            inputs.valid_identity({"sha256": "a" * 64, "size": True}, 64)

    def test_empty_source_is_valid_but_empty_image_is_not(self):
        path = self.file("empty-source.rs", b"")
        with inputs.HeldFile(path, 64, allow_empty=True) as held:
            self.assertEqual(held.identity, inputs.identity(b""))
        with self.assertRaises(ValueError):
            inputs.HeldFile(path, 64)

    def test_closed_source_capture_accepts_empty_files_and_refuses_directory_symlinks(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        (source / "crates").mkdir(mode=0o700)
        inputs.write_new(source / "crates/empty.rs", b"")
        with patch.object(inputs, "SCOPES", ("crates",)), patch.object(inputs, "OPTIONAL", ()):
            captured = inputs.scan_source(source)
            self.assertEqual(captured["files"], [{"path": "crates/empty.rs", **inputs.identity(b"")}])
            (source / "crates/alias").symlink_to(source, target_is_directory=True)
            with self.assertRaises(ValueError):
                inputs.scan_source(source)

    def test_native_input_generation_change_and_link_are_refused(self):
        path = self.file("input", b"first")
        with inputs.HeldFile(path, 64) as held:
            replacement = self.file("replacement", b"first")
            replacement.replace(path)
            with self.assertRaises(ValueError):
                held.revalidate()
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(OSError):
            inputs.HeldFile(link, 64)

    def test_metadata_permissions_and_extra_hardlink_are_refused(self):
        path = self.file("input", b"body")
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            inputs.HeldFile(path, 64, private=True)
        path.chmod(0o600)
        os.link(path, self.root / "hardlink")
        with self.assertRaises(ValueError):
            inputs.HeldFile(path, 64)

    def test_real_crypto_unit_control_uses_public_vector(self):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        body = b"fixture checksum bytes; not a release\n"
        signature = runner.sign_checksums(body)
        self.assertEqual(len(signature), 64)
        Ed25519PublicKey.from_public_bytes(runner.PUBLIC).verify(signature, body)
        with self.assertRaises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(runner.PUBLIC).verify(signature, body + b" ")

    def test_real_archive_roundtrip_and_appended_gzip_refusal(self):
        # Parser fixture bytes are intentionally not an executable. No native
        # image admission, process invocation, replacement or success is claimed.
        path = self.file("parser-only-payload", b"parser-only payload" * 400)
        archive = self.root / "fixture.tar.gz"
        with inputs.HeldFile(path, 65536) as candidate:
            runner.archive_fixture(candidate, archive, runner.Deadline())
            with inputs.HeldFile(archive, 65536, private=True) as packed:
                runner.admit_archive(packed, candidate.identity, runner.Deadline())
                raw = packed.read()
            extra = self.file("concatenated.tar.gz", raw + raw)
            with inputs.HeldFile(extra, 65536, private=True) as packed:
                with self.assertRaises(ValueError):
                    runner.admit_archive(packed, candidate.identity, runner.Deadline())

    def test_wrong_archive_candidate_and_compressed_cap_refuse(self):
        path = self.file("parser-only-payload", b"payload")
        archive = self.root / "fixture.tar.gz"
        with inputs.HeldFile(path, 64) as candidate:
            runner.archive_fixture(candidate, archive, runner.Deadline())
            with inputs.HeldFile(archive, 65536) as packed:
                with self.assertRaises(ValueError):
                    runner.admit_archive(packed, {"size": 7, "sha256": "0" * 64}, runner.Deadline())
        sink = io.BytesIO()
        writer = runner.BoundedWriter(sink, runner.Deadline(), 3)
        writer.write(b"abc")
        with self.assertRaises(ValueError):
            writer.write(b"d")
        self.assertEqual(sink.getvalue(), b"abc")

    def bind_cargo_source(self, row):
        package = self.root / "crates/tirith"
        row["manifest_path"] = str(package / "Cargo.toml")
        row["package_id"] = "path+" + package.as_uri() + "#0.4.2"
        row["target"]["src_path"] = str(package / "src/main.rs")

    def test_cargo_artifact_from_another_checkout_or_package_refuses(self):
        executable = self.root / "not-executed"
        original = {"reason": "compiler-artifact", "executable": str(executable),
                    "target": {"name": "tirith", "kind": ["bin"]}, "profile": {"test": True}}
        self.bind_cargo_source(original)
        for field in ("manifest_path", "package_id", "src_path", "version", "captured_root"):
            with self.subTest(field=field):
                row = copy.deepcopy(original)
                source_root = self.root
                if field == "captured_root":
                    source_root = self.root / "another-checkout"
                elif field == "src_path":
                    row["target"][field] = str(self.root / "another-main.rs")
                elif field == "version":
                    row["package_id"] = row["package_id"].replace("#0.4.2", "#0.4.1")
                else:
                    row[field] = row[field].replace("crates/tirith", "other-checkout/crates/tirith")
                path = self.file("wrong-source-" + field + ".jsonl", inputs.canonical(row) +
                                 inputs.canonical({"reason": "build-finished", "success": True}))
                with self.assertRaisesRegex(ValueError, "captured source checkout"):
                    inputs.cargo_artifact(path, executable, True, source_root)

    def test_cargo_artifact_cannot_relabel_product_as_test(self):
        executable = self.root / "not-executed"
        row = {"reason": "compiler-artifact", "executable": str(executable),
               "target": {"name": "tirith", "kind": ["bin"]},
               "profile": {"test": False, "debug_assertions": False, "opt_level": "3"}}
        self.bind_cargo_source(row)
        path = self.file("cargo.jsonl", inputs.canonical(row) +
                         inputs.canonical({"reason": "build-finished", "success": True}))
        actual, _ = inputs.cargo_artifact(path, executable, False, self.root)
        self.assertEqual(actual, row)
        with self.assertRaises(ValueError):
            inputs.cargo_artifact(path, executable, True, self.root)

    def test_cargo_binary_test_target_is_admitted_and_library_target_refused(self):
        executable = self.root / "not-executed"
        row = {"reason": "compiler-artifact", "executable": str(executable),
               "target": {"name": "tirith", "kind": ["bin"]}, "profile": {"test": True}}
        self.bind_cargo_source(row)
        path = self.file("binary-test.jsonl", inputs.canonical(row) +
                         inputs.canonical({"reason": "build-finished", "success": True}))
        self.assertEqual(inputs.cargo_artifact(path, executable, True, self.root)[0], row)
        row["target"]["kind"] = ["lib"]
        wrong = self.file("library-test.jsonl", inputs.canonical(row) +
                          inputs.canonical({"reason": "build-finished", "success": True}))
        with self.assertRaises(ValueError):
            inputs.cargo_artifact(wrong, executable, True, self.root)

    def test_cargo_incomplete_or_debug_product_refuses(self):
        executable = self.root / "not-executed"
        row = {"reason": "compiler-artifact", "executable": str(executable),
               "target": {"name": "tirith", "kind": ["bin"]},
               "profile": {"test": False, "debug_assertions": True, "opt_level": "0"}}
        self.bind_cargo_source(row)
        path = self.file("debug.jsonl", inputs.canonical(row) +
                         inputs.canonical({"reason": "build-finished", "success": True}))
        with self.assertRaises(ValueError):
            inputs.cargo_artifact(path, executable, False, self.root)
        partial = self.file("partial.jsonl", inputs.canonical(row))
        with self.assertRaises(ValueError):
            inputs.cargo_artifact(partial, executable, False, self.root)


class CompletionParser(unittest.TestCase):
    def row(self):
        # Synthetic parser input only. The driver also demands actual owned
        # children, native images, signatures, sealed sources and final readback.
        return {"exit": 0, "failure": None,
                "cleanup": {"leader_reaped": True, "group_signaled_or_absent": True,
                            "group_members_exited": True, "output_eof": True},
                "stdout": ("running 1 test\ntest " + runner.TEST + " ... \n" + runner.EXTRACTOR_MARKER + "\n" + runner.MARKER +
                           "\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.1s\n"),
                "stderr": ""}

    def test_clean_parser_shape_and_every_cleanup_failure(self):
        runner.admit_test_output(self.row())
        for field in self.row()["cleanup"]:
            row = self.row()
            row["cleanup"][field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.admit_test_output(row)

    def test_inline_duplicate_or_wrong_marker_and_wrong_case_refuse(self):
        for stdout in (self.row()["stdout"].replace("\n" + runner.MARKER, runner.MARKER),
                       self.row()["stdout"] + runner.MARKER + "\n",
                       self.row()["stdout"].replace(runner.MARKER, "missing"),
                       self.row()["stdout"].replace(runner.TEST, "another_test")):
            row = self.row()
            row["stdout"] = stdout
            with self.subTest(stdout=stdout), self.assertRaises(ValueError):
                runner.admit_test_output(row)

    def test_missing_repeated_or_late_extractor_completion_refuses(self):
        for stdout in (self.row()["stdout"].replace(runner.EXTRACTOR_MARKER, "missing"),
                       self.row()["stdout"] + runner.EXTRACTOR_MARKER + "\n",
                       self.row()["stdout"].replace(runner.EXTRACTOR_MARKER + "\n", "") +
                       runner.EXTRACTOR_MARKER + "\n"):
            row = self.row()
            row["stdout"] = stdout
            with self.subTest(stdout=stdout), self.assertRaises(ValueError):
                runner.admit_test_output(row)

    def test_timeout_nonzero_and_ignored_case_refuse(self):
        for key, value in (("failure", "timeout"), ("exit", 1),
                           ("stdout", self.row()["stdout"].replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"))):
            row = self.row()
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.admit_test_output(row)


if __name__ == "__main__":
    inputs.admit_python()
    unittest.main()
