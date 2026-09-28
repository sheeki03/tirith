#!/usr/bin/env python3
"""Unix PowerShell target comparisons through a pinned CLI test image.

Windows uses the existing native Job controller in certify-powershell-target.ps1.
Neither route loads a profile, installs a hook, or qualifies an automatic adapter.
An optional private runtime copy leaves the installed runtime unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tools/qualification/mixed_audit_native.py'
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
TEST = 'cli::shell_target::native_tests::native_powershell_profile_matches_resolver'
SCOPE = 'native_current_user_console_profile_resolution_only'
RUNTIME_BYTES = 512 * 1024 * 1024
RUNTIME_ENTRIES = 4096


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


def runtime_token(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink)


def runtime_root_identity(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'owned private runtime root required')
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def runtime_inventory(root):
    """Capture the public runtime without following links or special files."""
    require(root.is_absolute() and root.resolve(strict=True) == root, 'canonical runtime root required')
    rows, total = [], 0
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        relative = path.relative_to(root)
        require(len(relative.parts) <= 24 and len(rows) < RUNTIME_ENTRIES, 'runtime inventory exceeds bound')
        row = {'path': relative.as_posix(), 'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISDIR(info.st_mode):
            row['kind'] = 'directory'
            children = []
            with os.scandir(path) as entries:
                for entry in entries:
                    require(len(rows) + len(pending) + len(children) + 1 < RUNTIME_ENTRIES,
                            'runtime entry cap exceeded')
                    children.append(Path(entry.path))
            pending.extend(sorted(children, reverse=True))
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            require(info.st_size <= 64*1024*1024 and total <= RUNTIME_BYTES, 'runtime byte cap exceeded')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                require(runtime_token(before) == runtime_token(info), 'runtime file changed during capture')
                h, count = hashlib.sha256(), 0
                while True:
                    part = os.read(fd, 1024*1024)
                    if not part:
                        break
                    count += len(part)
                    require(count <= info.st_size, 'runtime file grew during capture')
                    h.update(part)
                after = os.fstat(fd)
                require(count == info.st_size and runtime_token(before) == runtime_token(after)
                        and runtime_token(path.lstat()) == runtime_token(info),
                        'runtime file changed during capture')
                row.update(kind='file', size=count, sha256=h.hexdigest())
            finally:
                os.close(fd)
        elif stat.S_ISLNK(info.st_mode):
            link = os.readlink(path)
            require(not os.path.isabs(link) and len(link) <= 4096, 'absolute or oversized runtime link')
            require(path.resolve(strict=True).is_relative_to(root), 'runtime link escapes its source')
            row.update(kind='symlink', target=link)
        else:
            raise ValueError('runtime contains a special file')
        require(runtime_token(path.lstat()) == runtime_token(info), 'runtime entry changed during inventory')
        rows.append(row)
    return sorted(rows, key=lambda row: row['path'])


def stage_runtime(source, destination):
    """Copy observed runtime bytes; never chmod or modify the installed runtime."""
    before = runtime_inventory(source)
    require(destination.is_dir() and not destination.is_symlink() and not any(destination.iterdir())
            and destination.stat().st_uid == os.getuid() and stat.S_IMODE(destination.stat().st_mode) == 0o700,
            'empty owned private staging directory required')
    identity = runtime_root_identity(destination)
    require(shutil.disk_usage(destination).free >= 2*RUNTIME_BYTES, 'insufficient runtime staging space')
    expected = []
    for original in before:
        row = dict(original)
        target = destination / row['path']
        if row['kind'] == 'directory':
            if row['path'] != '.':
                target.mkdir(mode=0o700)
            row['mode'] = 0o700
        elif row['kind'] == 'symlink':
            target.symlink_to(row['target'])
            row['mode'] = stat.S_IMODE(target.lstat().st_mode)
        else:
            origin = source / row['path']
            fd = os.open(origin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as reader, target.open('xb') as writer:
                info = os.fstat(reader.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size == row['size'], 'runtime source type or size changed')
                copied = 0
                h = hashlib.sha256()
                while True:
                    part = reader.read(min(1024*1024, row['size'] + 1 - copied))
                    if not part:
                        break
                    copied += len(part)
                    require(copied <= row['size'], 'runtime source grew while copying')
                    writer.write(part)
                    h.update(part)
                require(copied == row['size'] and h.hexdigest() == row['sha256']
                        and runtime_token(os.fstat(reader.fileno())) == runtime_token(info)
                        and runtime_token(origin.lstat()) == runtime_token(info), 'runtime source changed while copying')
            row['mode'] = 0o500 if row['mode'] & 0o111 else 0o400
            target.chmod(row['mode'])
        expected.append(row)
    require(runtime_inventory(source) == before, 'installed runtime changed during copying')
    require(runtime_inventory(destination) == expected, 'private runtime copy differs from observed source')
    require(runtime_root_identity(destination) == identity, 'staged runtime root changed during copy')
    return {'source': str(source), 'staged': str(destination), 'source_inventory': before,
            'staged_inventory': expected, 'root_identity': identity, 'installed_runtime_modified': False}


def cleanup_runtime(copy):
    staged = Path(copy['staged'])
    require(runtime_root_identity(staged) == copy['root_identity'], 'staged runtime root was replaced')
    require(runtime_inventory(Path(copy['source'])) == copy['source_inventory'], 'installed runtime changed')
    require(runtime_inventory(staged) == copy['staged_inventory'], 'staged runtime changed')
    require(runtime_root_identity(staged) == copy['root_identity'], 'staged runtime root changed before cleanup')
    shutil.rmtree(staged)
    require(not staged.exists(), 'owned runtime cleanup incomplete')
    copy['cleanup_confirmed'] = True


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
    parser.add_argument('--stage-runtime', action='store_true',
                        help='copy the observed public runtime into a private owned root before qualification')
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists(), 'fresh absolute evidence directory required')
    args.output.mkdir(mode=0o700)
    report = {'schema_version': 1, 'passed': False, 'status': 'refused', 'scope': SCOPE,
              'cases': [], 'automatic_adapter_qualified': False}
    staged = None
    try:
        require(sys.flags.optimize == 0 and not os.environ.get('PYTHONOPTIMIZE'), 'unoptimized Python required')
        if os.name != 'posix' or sys.platform not in ('linux', 'darwin') or not args.powershell.is_file():
            report['status'] = 'unsupported'
            raise ValueError('native Linux/macOS PowerShell 7 executable is required; absence is not a pass')
        require(args.cargo_messages.stat().st_size <= 64*1024*1024, 'Cargo transcript exceeds bound')
        selected = select_artifact(args.cargo_messages.read_text(), ROOT)
        binary = Path(selected['executable']).resolve(strict=True)
        shell = args.powershell.resolve(strict=True)
        if args.stage_runtime:
            staged = Path(tempfile.mkdtemp(prefix='.tirith-pwsh-runtime-', dir=Path.home().resolve(strict=True)))
            report['runtime_copy'] = stage_runtime(shell.parent, staged)
            shell = staged / shell.name
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
        if staged is not None:
            try:
                cleanup_runtime(report['runtime_copy'])
            except BaseException as error:
                report.update(passed=False, status='refused', runtime_cleanup_error=str(error)[:4096])
        with (args.output / 'report.json').open('x') as stream:
            json.dump(report, stream, indent=2); stream.write('\n')
    print(json.dumps({'passed': report['passed'], 'status': report['status'], 'report': str(args.output / 'report.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
