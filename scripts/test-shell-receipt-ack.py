#!/usr/bin/env python3
"""Finite caller-observed ACK controls using extracted real hook functions.

The child is a recording stub, never Tirith. These controls do not qualify core
receipt authentication, native editor delivery, or long-session capacity.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest

TOKEN = 'a' * 64
COMMAND = 'printf ACK_CONTROL'


def function(source, name, fish=False):
    pattern = (rf'^function {re.escape(name)}\n.*?^end\n' if fish else
               rf'^{re.escape(name)}\(\) \{{\n.*?^\}}\n')
    found = re.search(pattern, source, re.MULTILINE | re.DOTALL)
    if not found:
        raise ValueError('missing actual hook function: ' + name)
    return found.group(0)


class AckControls(unittest.TestCase):
    serial = 0

    def invoke(self, family, operation, channel, operation_exit, ack_exit,
               reconcile_exit=None, discard_exit=None, wrong_cwd=False):
        self.__class__.serial += 1
        case = self.root / str(self.serial)
        case.mkdir()
        hook = self.sources[family]
        env = dict(self.base_env, ACK_LOG=str(case / 'calls.jsonl'), ACK_OPERATION_EXIT=str(operation_exit),
                   ACK_EXIT=str(ack_exit), ACK_RECONCILE_EXIT=str(reconcile_exit or 0),
                   ACK_DISCARD_EXIT=str(discard_exit or 0), ACK_TOKEN=TOKEN, ACK_COMMAND=COMMAND,
                   ACK_CWD=str(case), _TIRITH_BIN=str(self.stub), _TIRITH_ENV_BIN='/usr/bin/env',
                   _TIRITH_SH_BIN='/bin/sh', _TIRITH_RECEIPT_INSTANCE='b' * 64,
                   _TIRITH_RECEIPT_FAMILY=family, _TIRITH_V3_HELPERS_READY='1',
                   _TIRITH_RECEIPT_PROTOCOL='3')
        if family == 'bash':
            names = ['_tirith_fixed_fd_is_valid', '_tirith_open_exact_input_pipe',
                     '_tirith_close_pending_fd', '_tirith_receipt_parent_context_is_valid',
                     '_tirith_receipt_acknowledge_untraced', '_tirith_receipt_' + operation + '_untraced']
            body = '\n'.join(function(hook, name) for name in names)
            body += '\n_TIRITH_RECEIPT_SHELL_PID=$$\n_TIRITH_UNRESOLVED_RECEIPT=untouched\n'
            call = f'_tirith_receipt_{operation}_untraced {channel} "$ACK_TOKEN"'
            if operation == 'consume':
                call += ' "$ACK_COMMAND"'
            body += call + '\nrc=$?\n[[ $_TIRITH_UNRESOLVED_RECEIPT == untouched ]] || exit 90\nexit "$rc"\n'
            argv = [self.shells[family], '--noprofile', '--norc', '-c', body]
        elif operation == 'activation-retire':
            body = '\n'.join(function(hook, name) for name in
                             ['_tirith_activation_acknowledge_receipt', '_tirith_activation_retire_receipt'])
            cwd = '"$ACK_CWD"' if wrong_cwd else '"$PWD"'
            body += f'\nunset _TIRITH_UNRESOLVED_RECEIPT\n_tirith_activation_retire_receipt "$ACK_TOKEN" {cwd}\n'
            body += 'rc=$?\nif (( rc == 0 )); then [[ -z ${_TIRITH_UNRESOLVED_RECEIPT:-} ]] || exit 90; else [[ $_TIRITH_UNRESOLVED_RECEIPT == "$ACK_TOKEN" ]] || exit 91; fi\nexit "$rc"\n'
            argv = [self.shells['zsh'], '-dfc', body]
        else:
            fish = family == 'fish'
            names = ['_tirith_receipt_acknowledge_at', '_tirith_receipt_' + operation + '_at']
            body = '\n'.join(function(hook, name, fish) for name in names)
            call = f'_tirith_receipt_{operation}_at "$ACK_TOKEN"'
            if operation == 'consume':
                call += ' "$ACK_COMMAND"'
            call += ' "$ACK_CWD"'
            if fish:
                body += '\nset -g _TIRITH_UNRESOLVED_RECEIPT untouched\n' + call
                body += '\nset -l receipt_status $status\ntest "$_TIRITH_UNRESOLVED_RECEIPT" = untouched; or exit 90\nexit $receipt_status\n'
                argv = [self.shells[family], '--no-config', '-c', body]
            else:
                body += '\n_TIRITH_UNRESOLVED_RECEIPT=untouched\n' + call
                body += '\nrc=$?\n[[ $_TIRITH_UNRESOLVED_RECEIPT == untouched ]] || exit 90\nexit "$rc"\n'
                argv = [self.shells[family], '-dfc', body]
        result = self.cert.run(argv, env, 5, self.processes)
        self.assertEqual(result.stdout, '', 'ACK diagnostics must stay silent')
        path = case / 'calls.jsonl'
        calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        for call in calls:
            self.assertNotIn(TOKEN, ' '.join(call['argv']), 'token must remain on stdin')
            self.assertEqual(call['argv'][-2:], ['--channel', channel])
        return result.returncode, calls

    def test_ack_is_after_success_and_cannot_replace_observed_operation_status(self):
        for family, channels in [('bash', ['bash-enter', 'bash-preexec']), ('zsh', ['zsh']), ('fish', ['fish'])]:
            for channel in channels:
                for action in ['consume', 'discard', 'reconcile']:
                    for operation_exit, ack_exit in [(0, 0), (0, 99), (7, 0)]:
                        with self.subTest(family=family, channel=channel, action=action, operation_exit=operation_exit, ack_exit=ack_exit):
                            code, calls = self.invoke(family, action, channel, operation_exit, ack_exit)
                            self.assertEqual(code, operation_exit)
                            self.assertEqual([r['argv'][1] for r in calls], [action, 'acknowledge'] if operation_exit == 0 else [action])
                            frame = TOKEN + ('\n' + COMMAND if action == 'consume' else '')
                            self.assertEqual(calls[0]['stdin'], frame)
                            if operation_exit == 0:
                                self.assertEqual(calls[1]['stdin'], TOKEN)

    def test_automatic_retirement_ack_follows_known_result_and_preserves_uncertainty(self):
        cases = [(0, 1, 0, False), (0, 1, 99, False), (1, 0, 0, False),
                 (1, 0, 99, False), (1, 1, 0, False), (0, 0, 0, True)]
        for reconcile, discard, ack, wrong_cwd in cases:
            with self.subTest(reconcile=reconcile, discard=discard, ack=ack, wrong_cwd=wrong_cwd):
                code, calls = self.invoke('zsh', 'activation-retire', 'zsh', 0, ack,
                                          reconcile, discard, wrong_cwd)
                expected = [] if wrong_cwd else ['receipt-reconcile']
                if not wrong_cwd and reconcile:
                    expected.append('receipt-discard')
                successful = not wrong_cwd and (reconcile == 0 or discard == 0)
                if successful:
                    expected.append('receipt-acknowledge')
                self.assertEqual([r['argv'][1] for r in calls], expected)
                self.assertEqual(code, 0 if successful else 1)
                for row in calls:
                    self.assertEqual(row['stdin'], TOKEN + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--runtime-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    cert_path = args.runtime_root / 'scripts/certify-shell-package.py'
    spec = importlib.util.spec_from_file_location('receipt_ack_owner', cert_path)
    cert = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cert)
    native = cert.owner_runtime()
    root = Path(tempfile.mkdtemp(prefix='tirith-receipt-ack-controls-'))
    report = {'schema_version': 1, 'passed': False, 'fixture_root': str(root), 'fixture_removed': False,
              'scope': 'finite recording-stub tests of real extracted hook functions; no product authentication/editor/capacity claim',
              'processes': [], 'source_sha256': {}, 'owner_helper_sha256': cert.OWNER_HELPER_SHA256,
              'certifier_sha256': hashlib.sha256(cert_path.read_bytes()).hexdigest(),
              'python': {'executable': str(Path(sys.executable).resolve()), 'version': sys.version,
                         'sha256': hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()},
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        AckControls.root, AckControls.cert, AckControls.processes = root, cert, report['processes']
        AckControls.base_env = native.isolated_env(root)
        AckControls.sources, AckControls.shells = {}, {}
        for family, name in [('bash', 'bash-hook.bash'), ('zsh', 'zsh-hook.zsh'), ('fish', 'fish-hook.fish')]:
            path = args.source_root / 'shell/lib' / name
            raw = path.read_bytes()
            report['source_sha256'][str(path)] = hashlib.sha256(raw).hexdigest()
            AckControls.sources[family] = raw.decode()
            path = cert.shell_path(family, report['processes'])
            if path is None:
                raise ValueError('required native shell unavailable: ' + family)
            AckControls.shells[family] = str(path)
        stub = root / 'stub-tirith'
        stub.write_text('#!' + str(Path(sys.executable).resolve()) + '\n' + '''import json, os, sys
action = sys.argv[2]
with open(os.environ['ACK_LOG'], 'a') as f:
    f.write(json.dumps({'argv': sys.argv[1:], 'stdin': sys.stdin.read(1048577)}) + '\\n')
if action in ('acknowledge', 'receipt-acknowledge'):
    sys.stderr.write('simulated unsupported ACK route\\n')
    sys.exit(int(os.environ['ACK_EXIT']))
if action == 'receipt-reconcile':
    sys.exit(int(os.environ['ACK_RECONCILE_EXIT']))
if action == 'receipt-discard':
    sys.exit(int(os.environ['ACK_DISCARD_EXIT']))
sys.exit(int(os.environ['ACK_OPERATION_EXIT']))
''')
        stub.chmod(0o700)
        AckControls.stub = stub
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AckControls))
        report['test_methods'] = result.testsRun
        report['subcases_invoked'] = AckControls.serial
        report['test_failures'] = [{'test': str(test), 'detail': detail} for test, detail in result.failures + result.errors]
        for path, expected in report['source_sha256'].items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
                raise ValueError('source changed during controls')
        if hashlib.sha256(cert_path.read_bytes()).hexdigest() != report['certifier_sha256']:
            raise ValueError('owned certifier changed during controls')
        report['passed'] = result.wasSuccessful() and bool(report['processes']) and all(all(r['cleanup'].values()) for r in report['processes'])
        if report['passed']:
            shutil.rmtree(root)
            report['fixture_removed'] = True
    except BaseException as error:
        report['error'] = str(error)
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open('x') as f:
            json.dump(report, f, indent=2)
            f.write('\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
