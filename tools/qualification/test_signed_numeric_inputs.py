#!/usr/bin/env python3
"""Pure admission controls. No Cargo, product, native service or replacement runs."""
import copy
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import signed_numeric_inputs as numeric
import signed_numeric_native as runner


class NumericAdmission(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tirith-numeric-admission-")
        self.root = Path(self.temporary.name).resolve()
        self.old = self.make_source(self.root / "old", "0.4.2")
        self.new = self.make_source(self.root / "new", "0.4.3")

    def tearDown(self):
        self.temporary.cleanup()

    def make_source(self, root, version):
        contents = {
            "Cargo.toml": '[workspace]\nmembers = ["crates/tirith", "crates/tirith-core"]\n'
                          '[workspace.package]\nversion = "' + version + '"\n'
                          '[workspace.dependencies]\n'
                          'tirith-core = { version = "' + version + '", path = "crates/tirith-core" }\n',
            "Cargo.lock": 'version = 4\n\n[[package]]\nname = "tirith"\nversion = "' + version + '"\n'
                          '\n[[package]]\nname = "tirith-core"\nversion = "' + version + '"\n'
                          '\n[[package]]\nname = "unrelated"\nversion = "0.4.2"\nsource = "registry"\n',
            "crates/tirith/Cargo.toml": '[package]\nname = "tirith"\nversion.workspace = true\n',
            "crates/tirith-core/Cargo.toml": '[package]\nname = "tirith-core"\nversion.workspace = true\n',
            "crates/tirith/src/main.rs": 'fn main() {}\n',
        }
        rows = []
        for relative, text in sorted(contents.items()):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            numeric.base.write_new(path, text.encode())
            rows.append({"path": relative, **numeric.base.identity(text.encode())})
        return {"root": str(root), "scopes": list(numeric.base.SCOPES), "optional_absent": [], "files": rows}

    def replace(self, source, relative, transform):
        path = Path(source["root"]) / relative
        body = transform(path.read_bytes())
        path.write_bytes(body)
        for row in source["files"]:
            if row["path"] == relative:
                row.update(numeric.base.identity(body))

    def artifact(self, version="0.4.3", test=False):
        package = Path(self.new["root"]) / "crates/tirith"
        return {"reason": "compiler-artifact", "executable": "/owned/tirith", "manifest_path": str(package / "Cargo.toml"),
                "package_id": "path+" + package.as_uri() + "#" + version,
                "target": {"name": "tirith", "kind": ["bin"], "src_path": str(package / "src/main.rs")},
                "profile": {"test": test, "opt_level": "3", "debug_assertions": False}}

    def check_artifact(self, row, version="0.4.3", test=False, success=True, duplicate=False):
        path = self.root / ("cargo-" + str(len(list(self.root.glob("cargo-*")))))
        rows = [row] * (2 if duplicate else 1) + [{"reason": "build-finished", "success": success}]
        numeric.base.write_new(path, b"".join(numeric.base.canonical(value) for value in rows))
        return numeric.cargo_artifact(path, Path("/owned/tirith"), test, Path(self.new["root"]), version)

    def test_exact_pair_and_unrelated_lock_version(self):
        self.assertEqual(numeric.admit_source_pair(self.old, self.new), ["Cargo.lock", "Cargo.toml"])
        self.assertIn(b'name = "unrelated"\nversion = "0.4.2"', numeric.version_variant_bytes(self.old)["Cargo.lock"])

    def test_rejects_source_or_unrelated_dependency_change(self):
        for relative, old, new in (("crates/tirith/src/main.rs", b"{}", b"{panic!()}"),
                                   ("Cargo.lock", b'name = "unrelated"\nversion = "0.4.2"', b'name = "unrelated"\nversion = "0.4.3"'),
                                   ("Cargo.toml", b'[workspace]', b'# hidden delta\n[workspace]')):
            with self.subTest(relative=relative):
                source = self.make_source(self.root / ("variant" + str(len(list(self.root.iterdir())))), "0.4.3")
                self.replace(source, relative, lambda raw: raw.replace(old, new))
                with self.assertRaises(ValueError):
                    numeric.admit_source_pair(self.old, source)

    def test_rejects_neighbor_suffix_same_version_and_reversal(self):
        for version in ("0.4.2", "0.4.4", "0.4.3-rc.1", "0.4.30"):
            with self.subTest(version=version):
                source = self.make_source(self.root / version, version)
                with self.assertRaises(ValueError):
                    numeric.admit_source_pair(self.old, source)
        with self.assertRaises(ValueError):
            numeric.admit_source_pair(self.new, self.old)

    def test_rejects_duplicate_missing_and_changed_capture_bytes(self):
        for mutation in (lambda value: value["files"].append(dict(value["files"][0])),
                         lambda value: value["files"].pop(),
                         lambda value: value["optional_absent"].append("build.rs")):
            bad = copy.deepcopy(self.new)
            mutation(bad)
            with self.assertRaises(ValueError):
                numeric.admit_source_pair(self.old, bad)
        (Path(self.new["root"]) / "Cargo.toml").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            numeric.admit_source_pair(self.old, self.new)

    def test_exact_product_cargo_row(self):
        row = self.artifact()
        self.assertEqual(self.check_artifact(row)[0], row)

    def test_rejects_wrong_cargo_version_role_profile_and_source(self):
        variants = []
        for version in ("0.4.2", "0.4.30", "0.4.3-rc.1"):
            variants.append(self.artifact(version))
        for field, value in (("test", True), ("debug_assertions", True), ("opt_level", "2")):
            row = self.artifact()
            row["profile"][field] = value
            variants.append(row)
        row = self.artifact()
        row["target"]["src_path"] = "/borrowed/main.rs"
        variants.append(row)
        for row in variants:
            with self.subTest(row=row), self.assertRaises(ValueError):
                self.check_artifact(row)
        for arguments in ({"success": False}, {"duplicate": True}, {"version": "0.4.3", "test": True}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.check_artifact(self.artifact(), **arguments)

    def test_existing_capture_helper_pin(self):
        numeric.admit_base()

    def test_discovery_waits_only_for_exact_retained_prior_generation(self):
        owned = SimpleNamespace(root=self.root)
        job = SimpleNamespace(process=SimpleNamespace(pid=42, poll=lambda: None))
        startup = str(uuid.uuid4())
        path = self.root / "state/tirith/control/v1/service.json"
        path.parent.mkdir(parents=True)
        record = {"protocol": 1, "pid": 41, "startup_id": str(uuid.uuid4()),
                  "binary_sha256": "a" * 64, "cwd": str(self.root / "workspace"),
                  "port": 23456, "service_id": str(uuid.uuid4()), "token": "b" * 64}
        numeric.base.write_new(path, numeric.base.canonical(record))
        with numeric.base.HeldFile(path, 16384, private=True) as prior:
            self.assertIsNone(runner.read_service(owned, job, startup, "a" * 64, prior))
            with self.assertRaises(ValueError):
                runner.read_service(owned, job, startup, "a" * 64)
            # Another inode with identical stale JSON is not the retained old
            # generation; it cannot be swallowed as a pending startup.
            next_path = path.with_name("next.json")
            numeric.base.write_new(next_path, numeric.base.canonical(record))
            os.replace(next_path, path)
            with self.assertRaises(ValueError):
                runner.read_service(owned, job, startup, "a" * 64, prior)
            record.update(pid=42, startup_id=startup, service_id=str(uuid.uuid4()))
            numeric.base.write_new(next_path, numeric.base.canonical(record))
            os.replace(next_path, path)
            selected, identity = runner.read_service(owned, job, startup, "a" * 64, prior)
            self.assertEqual(selected, record)
            self.assertEqual(identity, numeric.base.identity(numeric.base.canonical(record)))

    def test_expired_case_cannot_start_service_shell_or_http(self):
        deadline = SimpleNamespace(start=0.0)
        native = SimpleNamespace(Job=mock.Mock())
        owned = SimpleNamespace(root=self.root)
        with mock.patch.object(runner.time, "monotonic", return_value=600.0):
            with self.assertRaisesRegex(ValueError, "deadline exceeded"):
                runner.reopened_status(native, [], owned, "a" * 64, str(uuid.uuid4()),
                                       "completed", True, deadline=deadline)
            with self.assertRaisesRegex(ValueError, "deadline exceeded"):
                runner.shell_snapshot(native, [], owned, "expired-shell", deadline)
            opener = mock.Mock()
            with mock.patch.object(runner.urllib.request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(ValueError, "deadline exceeded"):
                    runner.request("http://127.0.0.1:12345", "a" * 64, "", "/api/session", deadline=deadline)
            opener.open.assert_not_called()
        native.Job.assert_not_called()
        self.assertFalse((self.root / "expired-shell.zsh").exists())


if __name__ == "__main__":
    unittest.main()
