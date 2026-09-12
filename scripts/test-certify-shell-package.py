#!/usr/bin/env python3
"""Certificate package identity checks; no native candidate execution."""
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("certificate", Path(__file__).with_name("certify-shell-package.py"))
CERTIFICATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTIFICATE)


class PackageIdentity(unittest.TestCase):
    def test_tar_regular_member_is_hashed_without_extracting_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.tar.gz"
            with tarfile.open(package, "w:gz") as archive:
                info = tarfile.TarInfo("../../never-extracted/tirith")
                info.size = 9
                archive.addfile(info, io.BytesIO(b"candidate"))
            self.assertEqual(CERTIFICATE.packaged_binary_digest(package), hashlib.sha256(b"candidate").hexdigest())
            self.assertEqual(list(Path(temporary).iterdir()), [package])

    def test_duplicate_binaries_and_symlink_only_packages_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.tar.gz"
            with tarfile.open(package, "w:gz") as archive:
                info = tarfile.TarInfo("tirith")
                info.type = tarfile.SYMTYPE
                info.linkname = "/usr/bin/true"
                archive.addfile(info)
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)
            package = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("a/tirith.exe", b"one")
                archive.writestr("b/tirith.exe", b"two")
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)

    def test_zip_hash_is_tied_to_exact_shipped_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("tirith.exe", b"candidate")
            actual = CERTIFICATE.packaged_binary_digest(package)
            self.assertEqual(actual, hashlib.sha256(b"candidate").hexdigest())
            self.assertNotEqual(actual, hashlib.sha256(b"other build").hexdigest())

    def test_archive_link_cannot_shadow_regular_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.tar"
            with tarfile.open(package, "w") as archive:
                info = tarfile.TarInfo("tirith")
                info.size = 9
                archive.addfile(info, io.BytesIO(b"candidate"))
                link = tarfile.TarInfo("tirith")
                link.type = tarfile.SYMTYPE
                link.linkname = "/other/tirith"
                archive.addfile(link)
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)

            package = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(package, "w") as archive:
                link = zipfile.ZipInfo("tirith")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, b"candidate")
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)


if __name__ == "__main__":
    unittest.main()
