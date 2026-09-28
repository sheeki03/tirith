#!/usr/bin/env python3
"""Negative controls for native target evidence admission; no native claims."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

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


if __name__ == '__main__':
    unittest.main()
