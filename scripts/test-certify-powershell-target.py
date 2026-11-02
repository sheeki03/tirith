#!/usr/bin/env python3
"""Negative controls for native target evidence admission; no native claims."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('target', Path(__file__).with_name('certify-powershell-target.py'))
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


class EvidenceControls(unittest.TestCase):
    def report(self):
        return {'passed': True, 'status': 'native_target_matched', 'scope': target.SCOPE,
                'profile_writes': False, 'profile_loaded': False, 'automatic_adapter_qualified': False,
                'profile_unchanged': True, 'profile_before': {'exists': False}, 'profile_after': {'exists': False},
                'test_binary': {'sha256': 'a'*64}, 'native_executable': {'sha256': 'b'*64},
                'child': {'outcome': 'completed', 'success': True, 'supervised_cleanup_confirmed': True}}

    def test_absence_refusal_or_unconfirmed_cleanup_cannot_pass(self):
        for field, value in (('status', 'unsupported'), ('passed', False), ('profile_unchanged', False),
                             ('automatic_adapter_qualified', True)):
            report = self.report(); report[field] = value
            with self.assertRaises(ValueError): target.validate_report(report, 'a'*64, 'b'*64)
        report = self.report(); report['child']['supervised_cleanup_confirmed'] = False
        with self.assertRaises(ValueError): target.validate_report(report, 'a'*64, 'b'*64)

    def test_changed_profile_or_executable_cannot_pass(self):
        report = self.report(); report['profile_after'] = {'exists': True}
        with self.assertRaises(ValueError): target.validate_report(report, 'a'*64, 'b'*64)
        with self.assertRaises(ValueError): target.validate_report(self.report(), 'c'*64, 'b'*64)
        with self.assertRaises(ValueError): target.validate_report(self.report(), 'a'*64, 'c'*64)

    def test_cargo_wrong_or_ambiguous_target_is_rejected(self):
        row = {'reason': 'compiler-artifact', 'executable': '/fixture/tirith-test', 'profile': {'test': True},
               'target': {'name': 'tirith', 'kind': ['bin']}, 'manifest_path': str(target.ROOT/'crates/tirith/Cargo.toml')}
        finished = {'reason': 'build-finished', 'success': True}
        text = lambda rows: '\n'.join(json.dumps(r) for r in rows)
        self.assertEqual(target.select_artifact(text([row, finished]), target.ROOT), row)
        for key, value in (('profile', {'test': False}), ('manifest_path', '/other/Cargo.toml'),
                           ('target', {'name': 'tirith', 'kind': ['test']})):
            changed = copy.deepcopy(row); changed[key] = value
            with self.assertRaises(ValueError): target.select_artifact(text([changed, finished]), target.ROOT)
        with self.assertRaises(ValueError): target.select_artifact(text([row, row, finished]), target.ROOT)
        with self.assertRaises(ValueError): target.select_artifact(text([row]), target.ROOT)


class RuntimeStaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tirith-pwsh-copy-')
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'pwsh').write_bytes(b'fixture executable')
        (self.source / 'pwsh').chmod(0o777)
        (self.source / 'Modules').mkdir()
        (self.source / 'Modules/module').write_bytes(b'public runtime fixture')
        self.destination = self.root / 'private'
        self.destination.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_copy_preserves_bytes_without_changing_installed_permissions(self):
        (self.source / 'alias').symlink_to('pwsh')
        before = target.runtime_inventory(self.source)
        result = target.stage_runtime(self.source, self.destination)
        self.assertEqual(target.runtime_inventory(self.source), before)
        self.assertEqual((self.source / 'pwsh').stat().st_mode & 0o777, 0o777)
        self.assertEqual((self.destination / 'pwsh').read_bytes(), b'fixture executable')
        self.assertEqual((self.destination / 'pwsh').stat().st_mode & 0o777, 0o500)
        self.assertEqual(target.runtime_inventory(self.destination), result['staged_inventory'])
        target.cleanup_runtime(result)
        self.assertTrue(result['cleanup_confirmed'])
        self.assertFalse(self.destination.exists())
        self.assertEqual(target.runtime_inventory(self.source), before)

    def test_cleanup_refuses_replaced_or_changed_runtime(self):
        result = target.stage_runtime(self.source, self.destination)
        original = self.root / 'original'
        self.destination.rename(original)
        self.destination.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'replaced'):
            target.cleanup_runtime(result)
        self.assertTrue(self.destination.is_dir())
        self.destination.rmdir()
        original.rename(self.destination)
        (self.destination / 'unexpected').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'staged runtime changed'):
            target.cleanup_runtime(result)
        self.assertTrue(self.destination.is_dir())

    def test_escaping_links_and_special_files_are_refused_before_copy(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'outside')
        link = self.source / 'escape'
        link.symlink_to('../outside')
        with self.assertRaises(ValueError): target.stage_runtime(self.source, self.destination)
        self.assertFalse(any(self.destination.iterdir()))
        link.unlink()
        os.mkfifo(self.source / 'pipe')
        with self.assertRaises(ValueError): target.runtime_inventory(self.source)

    def test_only_exact_dangling_linux_compatibility_links_are_omitted(self):
        for name, link in target.LINUX_DANGLING_COMPAT_LINKS.items():
            (self.source / name).symlink_to(link)
        with mock.patch.object(target.sys, 'platform', 'linux'), mock.patch.object(target, 'path_is_absent', return_value=True):
            before = target.runtime_inventory(self.source, omit_dangling_linux_compat=True)
            result = target.stage_runtime(self.source, self.destination)
            self.assertEqual(result['source_inventory'], before)
            self.assertEqual(len(result['source_omissions']), 2)
            self.assertTrue(all(row['kind'] == 'omitted_symlink' for row in result['source_omissions']))
            self.assertTrue(all(not (self.destination / name).is_symlink() for name in target.LINUX_DANGLING_COMPAT_LINKS))
            target.cleanup_runtime(result)
            self.assertEqual(target.runtime_inventory(self.source, omit_dangling_linux_compat=True), before)
        self.assertTrue(all((self.source / name).is_symlink() for name in target.LINUX_DANGLING_COMPAT_LINKS))

    def test_compatibility_omission_refuses_other_paths_targets_platforms_and_existing_targets(self):
        name, link = next(iter(target.LINUX_DANGLING_COMPAT_LINKS.items()))
        entry = self.source / name
        for filename, value, platform, absent in (
            ('unexpected', link, 'linux', True),
            (name, '/lib64/unexpected.so', 'linux', True),
            (name, link, 'darwin', True),
            (name, link, 'linux', False),
        ):
            entry = self.source / filename
            entry.symlink_to(value)
            with mock.patch.object(target.sys, 'platform', platform), mock.patch.object(target, 'path_is_absent', return_value=absent):
                with self.assertRaises(ValueError): target.stage_runtime(self.source, self.destination)
            self.assertFalse(any(self.destination.iterdir()))
            entry.unlink()

    def test_omission_target_appearing_during_copy_refuses_and_preserves_partial_tree(self):
        name, link = next(iter(target.LINUX_DANGLING_COMPAT_LINKS.items()))
        (self.source / name).symlink_to(link)
        staging = target.runtime_staging_record(self.destination)
        with mock.patch.object(target.sys, 'platform', 'linux'), mock.patch.object(target, 'path_is_absent', side_effect=[True, False]):
            with self.assertRaisesRegex(ValueError, 'target is present'):
                target.stage_runtime(self.source, self.destination)
        with self.assertRaisesRegex(ValueError, 'partial runtime copy retained'):
            target.cleanup_incomplete_runtime(staging)
        self.assertTrue((self.destination / 'pwsh').exists())
        self.assertFalse(staging['cleanup_confirmed'])

    def test_early_inventory_refusal_removes_only_owned_empty_staging_root(self):
        staging = target.runtime_staging_record(self.destination)
        (self.source / 'unexpected').symlink_to('/outside/unexpected')
        with self.assertRaises(ValueError): target.stage_runtime(self.source, self.destination)
        target.cleanup_incomplete_runtime(staging)
        self.assertTrue(staging['cleanup_confirmed'])
        self.assertFalse(self.destination.exists())
        self.assertTrue((self.source / 'unexpected').is_symlink())

    def test_incomplete_cleanup_refuses_replaced_root(self):
        staging = target.runtime_staging_record(self.destination)
        self.destination.rename(self.root / 'retained')
        self.destination.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'replaced'):
            target.cleanup_incomplete_runtime(staging)
        self.assertTrue(self.destination.exists())
        self.assertFalse(staging['cleanup_confirmed'])

    def test_absence_check_rejects_regular_files_and_dangling_link_entries(self):
        path = self.root / 'external-target'
        self.assertTrue(target.path_is_absent(path))
        path.write_bytes(b'existing target')
        self.assertFalse(target.path_is_absent(path))
        path.unlink()
        path.symlink_to('missing-target')
        self.assertFalse(target.path_is_absent(path))

    def test_inventory_caps_and_nonprivate_destination_refuse(self):
        with mock.patch.object(target, 'RUNTIME_ENTRIES', 2), self.assertRaises(ValueError):
            target.runtime_inventory(self.source)
        with mock.patch.object(target, 'RUNTIME_BYTES', 2), self.assertRaises(ValueError):
            target.runtime_inventory(self.source)
        self.destination.chmod(0o755)
        with self.assertRaises(ValueError): target.stage_runtime(self.source, self.destination)


if __name__ == '__main__':
    unittest.main()
