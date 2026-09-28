#!/usr/bin/env python3
"""Read-only Unix PowerShell target comparisons through a pinned CLI test image.

Windows uses the existing native Job controller in certify-powershell-target.ps1.
Neither route loads a profile, installs a hook, or qualifies an automatic adapter.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tools/qualification/mixed_audit_native.py'
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
TEST = 'cli::shell_target::native_tests::native_powershell_profile_matches_resolver'
SCOPE = 'native_current_user_console_profile_resolution_only'


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path, cap=512*1024*1024):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap, 'input is absent, aliased or oversized')
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def load_json(path, cap=128*1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= cap, 'missing or oversized evidence')
    return json.loads(path.read_bytes())


def select_artifact(messages, root):
    rows = [json.loads(line) for line in messages.splitlines() if line.strip()]
    require(rows and rows[-1].get('reason') == 'build-finished' and rows[-1].get('success') is True,
            'Cargo did not retain successful completion')
    selected = [r for r in rows if r.get('reason') == 'compiler-artifact' and r.get('executable')
                and r.get('profile', {}).get('test') is True and r.get('target', {}).get('name') == 'tirith'
                and r['target'].get('kind') == ['bin']
                and Path(r.get('manifest_path', '')).resolve() == root / 'crates/tirith/Cargo.toml']
    require(len(selected) == 1, 'expected exactly one current Tirith CLI test executable')
    return selected[0]


def validate_report(report, binary_sha, shell_sha):
    require(report.get('passed') is True and report.get('status') == 'native_target_matched'
            and report.get('scope') == SCOPE, 'native resolver did not establish a match')
    require(all(report.get(k) is False for k in ('profile_writes', 'profile_loaded', 'automatic_adapter_qualified')),
            'native resolver scope changed')
    require(report.get('profile_unchanged') is True and report['profile_before'] == report['profile_after'],
            'personal profile changed')
    require(report['test_binary']['sha256'] == binary_sha and report['native_executable']['sha256'] == shell_sha,
            'native resolver executable identity changed')
    require(report['child']['outcome'] == 'completed' and report['child']['success'] is True
            and report['child']['supervised_cleanup_confirmed'] is True, 'native query cleanup is unconfirmed')


def owned(native, name, command, cwd, environment, report):
    job = native.Job(name, command, cwd, environment, timeout=60)
    try:
        native.finish([job])
    finally:
        errors = []
        for operation in (job.kill, job.process.stdout.close, job.process.stderr.close):
            try:
                operation()
            except BaseException as error:
                errors.append(str(error))
        report['owned_process'] = job.result()
        report['cleanup_errors'] = errors
        require(not errors, 'native test image cleanup failed')
    native.success(report['owned_process'])
    require('1 passed; 0 failed; 0 ignored' in report['owned_process']['stdout'], 'native test was skipped or omitted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cargo-messages', type=Path, required=True)
    parser.add_argument('--powershell', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists(), 'fresh absolute evidence directory required')
    args.output.mkdir(mode=0o700)
    report = {'schema_version': 1, 'passed': False, 'status': 'refused', 'scope': SCOPE,
              'cases': [], 'automatic_adapter_qualified': False}
    try:
        require(sys.flags.optimize == 0 and not os.environ.get('PYTHONOPTIMIZE'), 'unoptimized Python required')
        if os.name != 'posix' or sys.platform not in ('linux', 'darwin') or not args.powershell.is_file():
            report['status'] = 'unsupported'
            raise ValueError('native Linux/macOS PowerShell 7 executable is required; absence is not a pass')
        require(args.cargo_messages.stat().st_size <= 64*1024*1024, 'Cargo transcript exceeds bound')
        selected = select_artifact(args.cargo_messages.read_text(), ROOT)
        binary = Path(selected['executable']).resolve(strict=True)
        shell = args.powershell.resolve(strict=True)
        binary_sha, shell_sha = digest(binary), digest(shell, 256*1024*1024)
        require(digest(HELPER) == HELPER_SHA, 'native ownership helper changed')
        spec = importlib.util.spec_from_file_location('powershell_target_owner', HELPER)
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        native.require_process_observation()
        report.update(cargo_artifact=selected, cargo_messages_sha256=digest(args.cargo_messages),
                      test_binary_sha256=binary_sha, powershell_path=str(shell), powershell_sha256=shell_sha,
                      harness_sha256=digest(Path(__file__).resolve()), helper_sha256=HELPER_SHA,
                      workflow_event_revision=os.environ.get('GITHUB_SHA'))
        for name in ('default-xdg', 'private-xdg'):
            case = {'name': name, 'passed': False}
            report['cases'].append(case)
            directory = args.output / name
            directory.mkdir(mode=0o700)
            output = directory / 'native.json'
            # Only child environments differ. HOME remains the current user's
            # home; no personal profile or directory is created or overwritten.
            environment = os.environ.copy()
            environment.pop('XDG_CONFIG_HOME', None)
            if name == 'private-xdg':
                config = directory / 'config'
                config.mkdir(mode=0o700)
                environment['XDG_CONFIG_HOME'] = str(config)
            environment.update(TIRITH_NATIVE_PROFILE_REPORT=str(output), TIRITH_NATIVE_PROFILE_SHELL='pwsh',
                TIRITH_NATIVE_PROFILE_EXECUTABLE=str(shell), TIRITH_NATIVE_PROFILE_SHA256=shell_sha,
                TIRITH_NATIVE_PROFILE_TEST_SHA256=binary_sha)
            try:
                owned(native, name, [str(binary), '--exact', TEST, '--ignored', '--nocapture', '--test-threads=1'],
                      directory, environment, case)
                observed = load_json(output)
                validate_report(observed, binary_sha, shell_sha)
                require(observed['test_binary']['pid'] == case['owned_process']['pid'], 'native report PID differs')
                case.update(passed=True, native_report_sha256=digest(output))
            except BaseException as error:
                case['error'] = str(error)[:4096]
        require(digest(binary) == binary_sha and digest(shell, 256*1024*1024) == shell_sha
                and digest(HELPER) == HELPER_SHA, 'retained native input changed')
        require(len(report['cases']) == 2 and all(c['passed'] for c in report['cases']), 'required native resolver case failed')
        report.update(passed=True, status='native_targets_matched')
    except BaseException as error:
        report['error'] = str(error)[:4096]
    finally:
        with (args.output / 'report.json').open('x') as stream:
            json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps({'passed': report['passed'], 'status': report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
