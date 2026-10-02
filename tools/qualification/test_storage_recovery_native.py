"""Portable runner contracts; none of these tests mounts or fills a filesystem."""
import base64
import errno
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import owned_full_volume as volume
import storage_recovery_native as runner


class StorageContracts(unittest.TestCase):
    def test_apfs_formatter_uses_fixed_image_size_without_device_or_resize(self):
        with mock.patch.object(volume.os, "geteuid", return_value=501), mock.patch.object(volume.os, "getegid", return_value=20):
            argv = volume.creation_argv("apfs", Path("/owned/new.dmg"), "fixed-label")
        self.assertEqual(argv, ["/usr/bin/hdiutil", "create", "-size", "64m", "-type", "UDIF", "-fs", "APFS",
                               "-uid", "501", "-gid", "20", "-mode", "0700", "-volname", "fixed-label",
                               "-nospotlight", "/owned/new.dmg"])

    def test_apfs_root_admission_requires_actual_ordinary_uid_gid_and_private_ancestor(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(volume.os, "geteuid", return_value=501), mock.patch.object(volume.os, "getegid", return_value=20):
            value = volume.OwnedFullVolume(Path(directory), filesystem="apfs")
            with mock.patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=501, st_mode=0o40700)):
                for mode in (0o40700, 0o40755):
                    value.check_mount_permissions(SimpleNamespace(st_uid=501, st_gid=20, st_mode=mode))
                for uid, gid, mode in ((0, 20, 0o40700), (501, 0, 0o40700), (501, 20, 0o40777), (501, 20, 0o47700)):
                    with self.subTest(uid=uid, gid=gid, mode=mode), self.assertRaises(AssertionError):
                        value.check_mount_permissions(SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode))

    def test_apfs_root_0755_does_not_admit_a_public_or_different_owner_ancestor(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(volume.os, "geteuid", return_value=501), \
             mock.patch.object(volume.os, "getegid", return_value=20):
            value = volume.OwnedFullVolume(Path(directory), filesystem="apfs")
            for uid, mode in ((501, 0o40755), (0, 0o40700), (501, 0o120700)):
                with mock.patch.object(Path, "lstat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)), \
                     self.assertRaisesRegex(AssertionError, "private ancestor"):
                    value.check_mount_permissions(SimpleNamespace(st_uid=501, st_gid=20, st_mode=0o40755))

    def test_hfs_formatter_remains_unchanged_and_unknown_selection_refuses(self):
        argv = volume.creation_argv("hfs", Path("/owned/new.dmg"), "fixed-label")
        self.assertEqual(argv, ["/usr/bin/hdiutil", "create", "-size", "64m", "-type", "UDIF", "-fs", "Journaled HFS+",
                               "-volname", "fixed-label", "-nospotlight", "/owned/new.dmg"])
        with self.assertRaises(AssertionError):
            volume.creation_argv("arbitrary", Path("/owned/new.dmg"), "fixed-label")

    def test_apfs_admission_requires_observed_filesystem_type(self):
        with tempfile.TemporaryDirectory() as directory:
            value = volume.OwnedFullVolume(Path(directory), filesystem="apfs")
            value.check_filesystem({"FilesystemType": "apfs"})
            for observed in ({}, {"FilesystemType": "hfs"}, {"FilesystemType": None}):
                with self.assertRaises(AssertionError):
                    value.check_filesystem(observed)

    def result(self):
        return {"name": "fixture", "failure": None, "exit": 0, "stdout": '{"action":"allow"}',
                "stderr": "audit append failed: No space left on device",
                "cleanup": {"leader_reaped": True, "group_signaled_or_absent": True,
                            "group_members_exited": True, "output_eof": True}}

    def test_geometry_rejects_shared_filesystem_before_filling(self):
        with self.assertRaisesRegex(AssertionError, "host filesystem"):
            volume.volume_geometry({"dev": 1, "total": volume.LIMIT, "block": 4096}, 1)

    def test_geometry_rejects_unbounded_or_tiny_volume(self):
        for size in (0, volume.MIN_VOLUME - 1, volume.LIMIT + 1, 1024 ** 4):
            with self.subTest(size=size), self.assertRaises(AssertionError):
                volume.volume_geometry({"dev": 2, "total": size, "block": 4096}, 1)

    def test_geometry_accepts_only_bounded_separate_volume(self):
        self.assertEqual(volume.volume_geometry({"dev": 2, "total": volume.LIMIT, "block": 4096}, 1)["total"], volume.LIMIT)

    def inventory(self):
        return {"images": [{"image-path": "/owned/test.dmg", "system-entities": [{"mount-point": "/owned/mount"}]}]}

    def test_attachment_requires_exact_image_and_mount(self):
        volume.image_relation(self.inventory(), Path("/owned/test.dmg"), Path("/owned/mount"))
        for image, mount in (("/other/test.dmg", "/owned/mount"), ("/owned/test.dmg", "/other/mount")):
            with self.assertRaises(AssertionError):
                volume.image_relation(self.inventory(), Path(image), Path(mount))

    def test_duplicate_image_or_ambiguous_mount_is_rejected(self):
        for duplicate_image in (True, False):
            value = self.inventory()
            extra = dict(value["images"][0])
            if not duplicate_image:
                extra["image-path"] = "/other.dmg"
            value["images"].append(extra)
            with self.assertRaises(AssertionError):
                volume.image_relation(value, Path("/owned/test.dmg"), Path("/owned/mount"))

    def test_multiple_mounted_entities_are_rejected(self):
        value = self.inventory()
        value["images"][0]["system-entities"].append({"mount-point": "/extra"})
        with self.assertRaises(AssertionError):
            volume.image_relation(value, Path("/owned/test.dmg"), Path("/owned/mount"))

    def test_fill_distinguishes_real_enospc_from_other_errors(self):
        for code in (errno.EFBIG, errno.EACCES, errno.EIO, errno.EDQUOT):
            with self.subTest(errno=code), mock.patch.object(volume.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096)), \
                 mock.patch.object(volume.os, "write", side_effect=OSError(code, "fixture")), \
                 self.assertRaisesRegex(AssertionError, "other than ENOSPC"):
                volume.write_until_enospc(99)

    def test_fill_enospc_requires_final_block_attempt(self):
        with mock.patch.object(volume.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096)), \
             mock.patch.object(volume.os, "write", side_effect=OSError(errno.ENOSPC, "fixture")) as write:
            result = volume.write_until_enospc(99)
        self.assertEqual(result["errno"], errno.ENOSPC)
        self.assertEqual([len(call.args[1]) for call in write.call_args_list], [1024 * 1024, 4096])

    def test_fill_has_hard_aggregate_bound_even_if_filesystem_never_fills(self):
        with mock.patch.object(volume.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096)), \
             mock.patch.object(volume.os, "write", side_effect=lambda fd, body: len(body)) as write, \
             mock.patch.object(volume.os, "fsync"), self.assertRaisesRegex(AssertionError, "bound reached"):
            volume.write_until_enospc(99, limit=8192)
        self.assertEqual(sum(len(call.args[1]) for call in write.call_args_list), 8192)

    def test_fill_tracks_partial_writes_and_fsync_enospc(self):
        with mock.patch.object(volume.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096)), \
             mock.patch.object(volume.os, "write", side_effect=[4096, OSError(errno.ENOSPC, "fixture")]), \
             mock.patch.object(volume.os, "fsync", side_effect=OSError(errno.ENOSPC, "fixture")):
            result = volume.write_until_enospc(99)
        self.assertEqual(result["written_bytes"], 4096)

    def test_fill_refuses_invalid_write_results(self):
        for value in (0, -1, volume.LIMIT + 1):
            with mock.patch.object(volume.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096)), \
                 mock.patch.object(volume.os, "write", return_value=value), self.assertRaisesRegex(AssertionError, "write result"):
                volume.write_until_enospc(99)

    def test_fill_deadline_refuses_without_later_write(self):
        with mock.patch.object(volume.os, "fstatvfs", return_value=SimpleNamespace(f_frsize=4096)), \
             mock.patch.object(volume.time, "monotonic", side_effect=[0, 21]), \
             mock.patch.object(volume.os, "write") as write, self.assertRaisesRegex(AssertionError, "deadline"):
            volume.write_until_enospc(99)
        write.assert_not_called()

    def test_pressure_preserves_exact_exit_and_verdict(self):
        runner.pressure_row(self.result(), "fixture", 0, "allow")
        for change in ({"exit": -signal.SIGSEGV}, {"exit": 1}, {"stdout": '{"action":"block"}'},
                       {"stderr": "No space left on device"}, {"failure": "output-timeout"}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                runner.pressure_row(dict(self.result(), **change), "fixture", 0, "allow")

    def test_pressure_cannot_hide_incomplete_cleanup(self):
        for key in self.result()["cleanup"]:
            value = self.result()
            value["cleanup"][key] = False
            with self.assertRaises(AssertionError):
                runner.pressure_row(value, "fixture", 0, "allow")

    def test_public_rfc8032_key_fixture_is_exact_known_answer(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(runner.shared.FIXTURE_SEED)
        self.assertEqual(key.public_key().public_bytes_raw(), runner.shared.FIXTURE_PUBLIC)
        self.assertEqual(key.sign(b"").hex(), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                         "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def signed(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        value = {"count": 1, "signing_enabled": True, "head_hash": "fixture"}
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        value["sig"] = base64.b64encode(Ed25519PrivateKey.from_private_bytes(runner.shared.FIXTURE_SEED).sign(payload)).decode()
        return value

    def test_signature_verifies_canonical_content_and_rejects_drift(self):
        from cryptography.exceptions import InvalidSignature
        value = self.signed()
        runner.verify_fixture_signature(value)
        value["count"] = 2
        with self.assertRaises(InvalidSignature):
            runner.verify_fixture_signature(value)

    def test_signature_requires_exact_signature_bytes(self):
        for signature in (None, "", "not base64", base64.b64encode(bytes(63)).decode()):
            with self.subTest(signature=signature), self.assertRaises((AssertionError, ValueError)):
                runner.verify_fixture_signature(dict(self.signed(), sig=signature))

    def test_signed_failure_still_removes_only_fixture_key(self):
        with tempfile.TemporaryDirectory() as directory:
            case = runner.SignedCase(Path(directory), "fixture", Path(sys.executable))
            result = case.complete(lambda _: (_ for _ in ()).throw(AssertionError("fixture refusal")))
            self.assertEqual(result["outcome"], "failed")
            self.assertTrue(result["fixture_private_key_removed"])
            self.assertEqual(case.key.with_suffix(".pub").read_bytes(), runner.shared.FIXTURE_PUBLIC)

    def test_candidate_requires_non_test_product_row_not_an_arbitrary_matching_entry(self):
        value = {"path": "/fixed/tirith", "sha256": "a" * 64, "profile_test": False}
        runner.admit_candidate({"tirith_product": value}, Path(value["path"]), value["sha256"])
        for manifest in ({"tirith": value}, {"tirith_product": dict(value, profile_test=True)},
                         {"tirith_product": dict(value, profile_test=0)}, {"tirith_product": dict(value, path="/other")},
                         {"tirith_product": dict(value, sha256="b" * 64)}, {"tirith_product": {}}):
            with self.subTest(manifest=manifest), self.assertRaises(AssertionError):
                runner.admit_candidate(manifest, Path(value["path"]), value["sha256"])

    def test_inventory_absence_requires_explicit_well_formed_images(self):
        for value in ({}, {"images": None}, {"images": {}}, {"images": [None]}, {"images": [{}]},
                      {"images": [{"image-path": "fixed", "system-entities": [None]}]}):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                volume.inventory_images(value)
        self.assertEqual(volume.inventory_images({"images": []}), [])


class VolumeCleanupContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.value = volume.OwnedFullVolume(self.root)
        self.value.create_attempted = self.value.attach_attempted = True
        self.value.create_finished = True
        self.value.image.write_bytes(b"fixture image; never mounted")
        self.value.image_fd = os.open(self.value.image, os.O_RDONLY)
        self.image_fd = self.value.image_fd
        self.value.image_identity = volume.file_identity(os.fstat(self.image_fd))
        self.value.mount.mkdir(mode=0o700)
        self.mount_fd = None
        self.image_info = {"images": [{"image-path": str(self.value.image),
                                      "system-entities": [{"mount-point": str(self.value.mount)}]}]}
        self.volume_info = {"MountPoint": str(self.value.mount), "VolumeName": self.value.label, "VolumeUUID": "01234567-89ab-4def-8123-456789abcdef"}

    def tearDown(self):
        for fd in (self.value.mount_fd, self.value.image_fd):
            if fd is not None:
                os.close(fd)
        self.temp.cleanup()

    def bind_fixture(self, **_):
        self.mount_fd = self.value.mount_fd = os.open(self.value.mount, os.O_RDONLY | os.O_DIRECTORY)
        self.value.mount_identity = volume.file_identity(os.fstat(self.mount_fd))
        self.value.volume_uuid = self.volume_info["VolumeUUID"]

    def assert_closed(self):
        self.assertIsNone(self.value.image_fd)
        self.assertIsNone(self.value.mount_fd)
        for fd in (self.image_fd, self.mount_fd):
            if fd is not None:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_completed_client_with_explicit_absence_needs_no_detach(self):
        self.value.attach_finished = True
        with mock.patch.object(self.value, "info", return_value={"images": []}), mock.patch.object(self.value, "tool") as tool:
            self.value.close()
        tool.assert_not_called()
        self.assertTrue(self.value.detached)
        self.assert_closed()

    def test_identity_only_cleanup_admission_does_not_require_write_eligibility(self):
        self.value.filesystem = "apfs"
        with mock.patch.object(self.value, "info", return_value=self.image_info), \
             mock.patch.object(self.value, "plist", return_value=dict(self.volume_info, FilesystemType="apfs")), \
             mock.patch.object(self.value, "geometry", return_value={"total": volume.LIMIT}), \
             mock.patch.object(self.value, "check_mount_permissions", side_effect=AssertionError("write eligibility")) as check:
            self.value.admit_mount(require_writable=False)
        self.mount_fd = self.value.mount_fd
        check.assert_not_called()
        self.assertEqual(self.value.volume_uuid, self.volume_info["VolumeUUID"])
        self.assertEqual(self.value.mount_identity, volume.file_identity(os.fstat(self.mount_fd)))

    def test_failed_attach_empty_inventory_keeps_system_service_cleanup_unresolved(self):
        with mock.patch.object(self.value, "info", return_value={"images": []}), mock.patch.object(self.value, "tool") as tool, \
             self.assertRaisesRegex(AssertionError, "service operation unresolved"):
            self.value.close()
        tool.assert_not_called()
        self.assertFalse(self.value.detached)
        self.assert_closed()

    def test_failed_formatter_empty_inventory_does_not_invent_service_completion(self):
        self.value.create_finished = self.value.attach_attempted = self.value.attach_finished = False
        with mock.patch.object(self.value, "info", return_value={"images": []}), mock.patch.object(self.value, "tool") as tool, \
             self.assertRaisesRegex(AssertionError, "service operation unresolved"):
            self.value.close()
        tool.assert_not_called()
        self.assertFalse(self.value.detached)
        self.assert_closed()

    def test_partial_attach_can_be_detached_only_after_full_binding(self):
        with mock.patch.object(self.value, "info", side_effect=[self.image_info, self.image_info, {"images": []}]), \
             mock.patch.object(self.value, "admit_mount", side_effect=self.bind_fixture) as admit, \
             mock.patch.object(self.value, "plist", return_value=self.volume_info), mock.patch.object(self.value, "tool") as tool:
            self.value.close()
        admit.assert_called_once_with(require_writable=False)
        tool.assert_called_once_with("image-detach", ["/usr/bin/hdiutil", "detach", str(self.value.mount)])
        self.assertTrue(self.value.detached)
        self.assert_closed()

    def test_partial_admission_error_closes_both_handles_without_guessing_detach(self):
        def fail(**_):
            self.bind_fixture()
            raise AssertionError("missing UUID fixture")
        with mock.patch.object(self.value, "info", return_value=self.image_info), \
             mock.patch.object(self.value, "admit_mount", side_effect=fail), mock.patch.object(self.value, "tool") as tool, \
             self.assertRaisesRegex(AssertionError, "missing UUID"):
            self.value.close()
        tool.assert_not_called()
        self.assertFalse(self.value.detached)
        self.assert_closed()

    def test_detach_error_closes_image_and_never_claims_detached(self):
        with mock.patch.object(self.value, "info", return_value=self.image_info), \
             mock.patch.object(self.value, "admit_mount", side_effect=self.bind_fixture), \
             mock.patch.object(self.value, "plist", return_value=self.volume_info), \
             mock.patch.object(self.value, "tool", side_effect=AssertionError("detach failed")), \
             self.assertRaisesRegex(AssertionError, "detach failed"):
            self.value.close()
        self.assertFalse(self.value.detached)
        self.assert_closed()

    def test_last_uuid_check_refuses_changed_volume(self):
        with mock.patch.object(self.value, "info", return_value=self.image_info), \
             mock.patch.object(self.value, "admit_mount", side_effect=self.bind_fixture), \
             mock.patch.object(self.value, "plist", return_value=dict(self.volume_info, VolumeUUID="other")), \
             mock.patch.object(self.value, "tool") as tool, self.assertRaisesRegex(AssertionError, "immediately before detach"):
            self.value.close()
        tool.assert_not_called()
        self.assert_closed()

    def test_last_mount_identity_check_refuses_changed_directory(self):
        def changed(**_):
            self.bind_fixture()
            self.value.mount_identity[1] += 1
        with mock.patch.object(self.value, "info", return_value=self.image_info), \
             mock.patch.object(self.value, "admit_mount", side_effect=changed), \
             mock.patch.object(self.value, "plist", return_value=self.volume_info), \
             mock.patch.object(self.value, "tool") as tool, self.assertRaisesRegex(AssertionError, "immediately before detach"):
            self.value.close()
        tool.assert_not_called()
        self.assert_closed()

    def test_missing_final_inventory_never_becomes_successful_detach(self):
        with mock.patch.object(self.value, "info", side_effect=[self.image_info, self.image_info, {}]), \
             mock.patch.object(self.value, "admit_mount", side_effect=self.bind_fixture), \
             mock.patch.object(self.value, "plist", return_value=self.volume_info), mock.patch.object(self.value, "tool"), \
             self.assertRaisesRegex(AssertionError, "inventory"):
            self.value.close()
        self.assertFalse(self.value.detached)
        self.assert_closed()

    def test_missing_cleanup_inventory_closes_handles_and_refuses(self):
        self.bind_fixture()
        with mock.patch.object(self.value, "info", return_value={}), mock.patch.object(self.value, "tool") as tool, \
             self.assertRaisesRegex(AssertionError, "inventory"):
            self.value.close()
        tool.assert_not_called()
        self.assert_closed()


if __name__ == "__main__":
    unittest.main()
