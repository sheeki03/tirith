#!/usr/bin/env python3
import importlib.util
import ast
import gzip
import io
from pathlib import Path
import tarfile
import tempfile
from unittest.mock import patch
import tomllib
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("compatibility", Path(__file__).with_name("release-compatibility.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROOT = Path(__file__).resolve().parents[2]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.artifacts = Path(self.temp.name)
        for target in MODULE.TARGETS:
            if target.endswith("windows-msvc"):
                with zipfile.ZipFile(self.artifacts / f"tirith-{target}.zip", "w") as archive:
                    archive.writestr("tirith.exe", b"never executed")
            else:
                self.tar(target)

    def tar(self, target, name="tirith", duplicate=False):
        with tarfile.open(self.artifacts / f"tirith-{target}.tar.gz", "w:gz") as archive:
            entry = tarfile.TarInfo(name)
            entry.size = 14
            archive.addfile(entry, io.BytesIO(b"never executed"))
            if duplicate:
                archive.addfile(entry, io.BytesIO(b"never executed"))

    def test_complete_payload_and_version_are_bound_without_execution(self):
        result = MODULE.build(ROOT, self.artifacts, VERSION)
        self.assertEqual(set(result["targets"]), set(MODULE.TARGETS))
        self.assertEqual(result["version"], VERSION)
        self.assertEqual(result["mcp_lock_authorize_versions"], [8])
        self.assertEqual(result["operation_journal_client_rule"], "exact_client_version_required")
        self.assertTrue(all(len(target["binary_sha256"]) == 64 for target in result["targets"].values()))
        self.assertEqual(result, MODULE.build(ROOT, self.artifacts, VERSION))
        with self.assertRaisesRegex(ValueError, "workspace"):
            MODULE.build(ROOT, self.artifacts, "999.0.0")

    def test_persisted_readers_and_recovery_capabilities_are_bound_to_source(self):
        result = MODULE.contract(ROOT, VERSION)
        readers = result["persisted_formats"]
        self.assertEqual(set(readers), {
            "team_connection", "team_enrollment", "team_report", "team_rollout",
            "team_policy_document", "team_policy_semantics", "npm_materialization_intent",
            "npm_materialization_checkpoint", "npm_materialization_inventory",
            "npm_materialization_recovery_rule", "shell_execution_receipt",
        })
        self.assertTrue(all(value == [1] for name, value in readers.items()
                            if name not in ("npm_materialization_recovery_rule", "shell_execution_receipt")))
        self.assertEqual(readers["shell_execution_receipt"], [3, 4])
        self.assertEqual(readers["npm_materialization_recovery_rule"],
                         "linux_only_fresh_policy_and_exact_current_ownership_required")
        self.assertTrue({"team_policy_runtime_v1", "team_policy_recovery_v1",
                         "npm_materialization_recovery_v1"} <= set(result["features"]))
        original = MODULE.source_constant
        for changed in ("SCHEMA_VERSION", "POLICY_SEMANTICS_VERSION", "INTENT_SCHEMA_VERSION",
                        "CHECKPOINT_SCHEMA_VERSION", "RECOVERY_INVENTORY_VERSION",
                        "RECEIPT_SCHEMA_VERSION", "ACKNOWLEDGED_RECEIPT_SCHEMA_VERSION"):
            def replaced(root, path, name):
                return 99 if name == changed else original(root, path, name)
            with self.subTest(changed=changed), patch.object(MODULE, "source_constant", replaced):
                with self.assertRaisesRegex(ValueError, "persisted format implementation changed"):
                    MODULE.contract(ROOT, VERSION)

    def test_signed_fixture_holds_every_literal_generator_source_dependency(self):
        # The fixture invokes this generator only while its declared inputs are
        # held and equal across the test/product builds. A new source_constant
        # call must therefore extend that explicit retained-input contract.
        generator = ast.parse((ROOT / ".github/scripts/release-compatibility.py").read_text())
        required = {"Cargo.toml", ".github/scripts/release-compatibility.py"}
        calls = [node for node in ast.walk(generator) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "source_constant"]
        self.assertTrue(calls, "generator source dependencies disappeared; review capture contract")
        for call in calls:
            self.assertEqual(len(call.args), 3, "review changed source_constant calling convention")
            self.assertFalse(call.keywords, "review dynamic generator dependency arguments")
            path = call.args[1]
            self.assertIsInstance(path, ast.Constant, "generator dependency must remain explicit")
            self.assertIsInstance(path.value, str)
            required.add(path.value)
        capture = ast.parse((ROOT / "tools/qualification/signed_replacement_inputs.py").read_text())
        declarations = [node.value for node in capture.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "GENERATOR_INPUTS"
                                for target in node.targets)]
        self.assertEqual(len(declarations), 1, "review changed capture input declaration")
        declared = ast.literal_eval(declarations[0])
        self.assertIsInstance(declared, tuple)
        self.assertTrue(all(isinstance(path, str) for path in declared))
        self.assertEqual(len(declared), len(set(declared)))
        self.assertFalse(required - set(declared),
                         "signed fixture does not retain generator dependencies: " +
                         repr(sorted(required - set(declared))))

    def test_missing_or_substituted_archive_changes_evidence(self):
        before = MODULE.build(ROOT, self.artifacts, VERSION)
        target = MODULE.TARGETS[-1]
        archive = self.artifacts / f"tirith-{target}.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("tirith.exe", b"substituted")
        after = MODULE.build(ROOT, self.artifacts, VERSION)
        self.assertNotEqual(before["targets"][target], after["targets"][target])
        archive.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            MODULE.build(ROOT, self.artifacts, VERSION)

    def test_ambiguous_and_escaping_tar_members_are_refused(self):
        target = MODULE.TARGETS[0]
        self.tar(target, duplicate=True)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            MODULE.build(ROOT, self.artifacts, VERSION)
        self.tar(target, name="../tirith")
        with self.assertRaisesRegex(ValueError, "escapes"):
            MODULE.build(ROOT, self.artifacts, VERSION)

    def test_zip_symbolic_link_cannot_claim_binary_identity(self):
        target = MODULE.TARGETS[-1]
        with zipfile.ZipFile(self.artifacts / f"tirith-{target}.zip", "w") as archive:
            entry = zipfile.ZipInfo("tirith.exe")
            entry.external_attr = (0o120777 << 16)
            archive.writestr(entry, "elsewhere")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            MODULE.build(ROOT, self.artifacts, VERSION)

    def test_oversized_declared_member_is_refused_before_decompression(self):
        target = MODULE.TARGETS[0]
        entry = tarfile.TarInfo("tirith")
        entry.size = MODULE.BINARY_CAP + 1
        with gzip.open(self.artifacts / f"tirith-{target}.tar.gz", "wb") as stream:
            stream.write(entry.tobuf())
            stream.write(bytes(1024))
        with self.assertRaisesRegex(ValueError, "expands"):
            MODULE.build(ROOT, self.artifacts, VERSION)

    def test_zip_special_file_and_windows_drive_member_are_refused(self):
        target = MODULE.TARGETS[-1]
        path = self.artifacts / f"tirith-{target}.zip"
        with zipfile.ZipFile(path, "w") as archive:
            entry = zipfile.ZipInfo("tirith.exe")
            entry.external_attr = (0o010600 << 16)
            archive.writestr(entry, b"not a regular executable")
        with self.assertRaisesRegex(ValueError, "special file"):
            MODULE.build(ROOT, self.artifacts, VERSION)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("C:/tirith.exe", b"not a root executable")
        with self.assertRaisesRegex(ValueError, "escapes"):
            MODULE.build(ROOT, self.artifacts, VERSION)


if __name__ == "__main__":
    unittest.main()
