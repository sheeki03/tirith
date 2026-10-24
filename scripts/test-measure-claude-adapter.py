#!/usr/bin/env python3
"""Pure protocol/filesystem controls; no native child, product, or provider spawn."""
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

PATH = Path(__file__).with_name('measure-claude-adapter.py')
spec = importlib.util.spec_from_file_location('adapter_draft_controls', PATH)
draft = importlib.util.module_from_spec(spec)
spec.loader.exec_module(draft)


class Controls(unittest.TestCase):
    def test_percentiles_keep_exact_count_and_small_sample_maximum(self):
        result = draft.distribution([4_000_000, 1_000_000, 3_000_000, 2_000_000])
        self.assertEqual((result['count'], result['p50'], result['p95']), (4, 2.0, 4.0))
        self.assertTrue(result['p95_is_observed_maximum'])
        measured = draft.distribution([index * 1_000_000 for index in range(1, 25)])
        self.assertEqual((measured['p50'], measured['p95']), (12.0, 23.0))
        self.assertFalse(measured['p95_is_observed_maximum'])
        for values in ([], [True], [-1], [float('nan')], [1.5]):
            with self.assertRaises(ValueError):
                draft.distribution(values)

    def test_ps_units_counter_and_pid_binding(self):
        row = draft.parse_ps(b'123 2048 1-02:03:04.50\n', 123)
        self.assertEqual(row['rss_bytes'], 2 * draft.MIB)
        self.assertEqual(row['cpu_ms'], (26 * 3600 + 3 * 60 + 4.5) * 1000)
        self.assertEqual(row['cpu_display_quantum_ms'], 10)
        short = draft.parse_ps(b'123 1 00:00.01', 123)
        self.assertEqual(short['cpu_ms'], 10)
        for raw in (b'124 2048 00:00.00', b'123 1 00:60.01', b'123 -1 00:00.01', b'123 1 nan', b'123 1 00:00 456 1 00:00'):
            with self.assertRaises(ValueError):
                draft.parse_ps(raw, 123)

    def test_input_pin_and_retained_generation_reject_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / 'input'
            path.write_bytes(b'held bytes')
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                draft.Input(path, '0' * 64)
            with draft.Input(path, draft.identity(b'held bytes')['sha256']) as item:
                replacement = root / 'next'
                replacement.write_bytes(b'held bytes')
                replacement.chmod(0o600)
                replacement.replace(path)
                with self.assertRaisesRegex(ValueError, 'generation'):
                    item.revalidate(full=True)
            alias = root / 'alias'
            alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'canonical'):
                draft.Input(alias)
            os.link(path, root / 'second-name')
            with self.assertRaisesRegex(ValueError, 'ownership'):
                draft.Input(path)

    def test_owned_directory_replacement_and_mode_change_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / 'evidence'
            owner = draft.Owned(output)
            try:
                root = owner.batch(0)
                root.chmod(0o755)
                with self.assertRaisesRegex(ValueError, 'replaced'):
                    owner.revalidate()
                root.chmod(0o700)
                owner.revalidate()
                root.rename(output / 'retained-original')
                root.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, 'replaced'):
                    owner.revalidate()
            finally:
                owner.close()

    def test_timed_turn_excludes_final_force_check(self):
        calls = []
        budget = types.SimpleNamespace(check=lambda **kw: calls.append('check'), remaining=lambda cap: cap)
        runner = draft.Runner(types.SimpleNamespace(BoundedProcess=object), None, budget)
        child = types.SimpleNamespace(send=lambda message: calls.append('send'),
                                      read_turn=lambda **kw: calls.append('result') or [{'type': 'result'}])
        with mock.patch.object(draft.time, 'perf_counter_ns', side_effect=[100, 450]):
            events, elapsed = runner.timed_turn(child, 'inert')
        self.assertEqual(elapsed, 350)
        self.assertEqual(calls, ['check', 'send', 'result', 'check'])
        self.assertEqual(events, [{'type': 'result'}])

    def test_storage_cap_refuses_before_hashing_unbounded_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'oversized'
            with path.open('wb') as stream:
                stream.truncate(draft.STORAGE_CAP + 1)
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, '256MiB'):
                draft.tree_inventory(Path(temporary), hashes=True)

    def setUp(self):
        self.harness = types.SimpleNamespace(
            hook_count=lambda events: sum(event.get('hook', False) for event in events),
            successful_turn=lambda events: sum(event.get('result', False) for event in events) == 1,
        )
        self.events = [{'hook': True}, {'hook': True}, {'result': True}]
        self.facts = {'provider_requests': 2, 'tool_calls_issued': 1,
                      'tool_result_observations': 1, 'rejected_provider_requests': 0}

    def classify(self, action, after, events=None, facts=None):
        return draft.classify_turn(self.events if events is None else events, [], after,
                                   self.facts if facts is None else facts, action, self.harness)

    def test_actual_tool_and_two_hook_events_required(self):
        self.assertTrue(self.classify('block', [])['passed'])
        self.assertFalse(self.classify('block', [], events=[{'result': True}])['passed'])
        self.assertFalse(self.classify('block', [], facts=dict(self.facts, tool_calls_issued=0))['passed'])
        self.assertFalse(self.classify('block', [], facts=dict(self.facts, tool_result_observations=0))['passed'])

    def test_allow_requires_exact_single_marker_not_blanket_deny_or_duplicate(self):
        self.assertTrue(self.classify('allow', ['TIRITH_AGENT_ALLOW_MARKER'])['passed'])
        self.assertFalse(self.classify('allow', [])['passed'])
        self.assertFalse(self.classify('allow', ['TIRITH_AGENT_ALLOW_MARKER'] * 2)['passed'])

    def test_block_marker_and_provider_rejection_never_promote_to_pass(self):
        self.assertFalse(self.classify('block', ['TIRITH_AGENT_BLOCK_MARKER'])['passed'])
        self.assertFalse(self.classify('block', [], facts=dict(self.facts, rejected_provider_requests=1))['passed'])
        self.assertFalse(self.classify('block', [], events=self.events + [{'result': True}])['passed'])

    def test_no_follow_inventory_records_alias_without_importing_target_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned'
            root.mkdir(mode=0o700)
            outside = Path(temporary) / 'outside'
            outside.mkdir(mode=0o700)
            (outside / 'not-evidence').write_bytes(b'never follow this directory')
            (root / 'debug-latest').symlink_to(outside, target_is_directory=True)
            (root / 'empty').touch(mode=0o600)
            result = draft.tree_inventory(root, hashes=True)
            self.assertEqual(result['regular_file_bytes'], 0)
            self.assertEqual([entry['path'] for entry in result['files']], ['empty'])
            self.assertEqual(result['symlinks_not_followed'], [{'path': 'debug-latest', 'target': str(outside), 'followed': False}])

    def test_inventory_refuses_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'one').write_bytes(b'bounded')
            (root / 'one').chmod(0o600)
            os.link(root / 'one', root / 'two')
            with self.assertRaisesRegex(ValueError, 'hardlinked'):
                draft.tree_inventory(root)

    def test_marker_refuses_dangling_or_live_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'marker'
            self.assertEqual(draft.marker_lines(marker), [])
            marker.symlink_to(Path(temporary) / 'missing')
            with self.assertRaises(OSError):
                draft.marker_lines(marker)
            marker.unlink()
            marker.write_bytes(b'TIRITH_AGENT_ALLOW_MARKER\n')
            marker.chmod(0o600)
            self.assertEqual(draft.marker_lines(marker), ['TIRITH_AGENT_ALLOW_MARKER'])
            alias = marker.with_suffix('.alias')
            alias.symlink_to(marker)
            with self.assertRaises(OSError):
                draft.marker_lines(alias)

    def test_cleanup_visits_every_registered_handle_despite_keyboard_interrupt(self):
        called = []
        class Child:
            cleanup_error = None
            cleanup = {'leader_reaped': True, 'output_eof': True, 'process_group_exited': True}
            def __init__(self, name, fail=False):
                self.name, self.fail = name, fail
            def close(self):
                called.append(self.name)
                if self.fail:
                    raise KeyboardInterrupt('owned observer failed')
        entries = [('first', Child('first')), ('middle', Child('middle', True)), ('last', Child('last'))]
        errors = draft.cleanup_all(entries)
        self.assertEqual(called, ['last', 'middle', 'first'])
        self.assertEqual([entry['name'] for entry in errors], ['middle'])

    def test_deadline_expiry_blocks_spawn_before_constructor(self):
        owned = types.SimpleNamespace(root=Path('/unused'), output=Path('/unused'), revalidate=lambda: None)
        budget = draft.Budget(owned, started=0)
        constructed = []
        class Process:
            def __init__(self, *args, **kwargs):
                constructed.append(True)
        runner = draft.Runner(types.SimpleNamespace(BoundedProcess=Process), owned, budget)
        with mock.patch.object(draft.time, 'monotonic', return_value=draft.SECONDS + 1):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                runner.start('unreachable', ['never-execute'], {})
        self.assertFalse(constructed)

    def test_guarded_cleanup_bypasses_expired_work_budget(self):
        calls = []
        class Budget:
            def check(self):
                raise ValueError('expired')
        class Process:
            def pump(self, timeout=0.1):
                calls.append('drain')
            def close(self):
                self.pump()
                calls.append('closed')
        Guard = draft.guarded_process_class(types.SimpleNamespace(BoundedProcess=Process), Budget())
        child = Guard()
        with self.assertRaisesRegex(ValueError, 'expired'):
            child.pump()
        child.close()
        self.assertEqual(calls, ['drain', 'closed'])

    def test_case_refuses_disk_failure_without_spawning(self):
        owned = types.SimpleNamespace(root=Path('/unused'), output=Path('/unused'), revalidate=lambda: None)
        budget = draft.Budget(owned)
        with mock.patch.object(draft.os, 'statvfs', side_effect=OSError('cannot observe free disk')):
            with self.assertRaises(OSError):
                budget.check(force=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
