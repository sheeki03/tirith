#!/usr/bin/env python3
"""One bounded metadata-only observation. No product, Cargo, npm or sysctl writes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import time
import types

IMAGE = 'node@sha256:2b028cd57303b2761d24173789c85a013558d6cf20e78f51723385f368b6e34d'
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
GUEST = r'''
'use strict';
const fs = require('fs'), os = require('os'), crypto = require('crypto');
function read(path, cap, optional = false) {
  let fd;
  try { fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }
  catch (e) { if (optional && e.code === 'ENOENT') return {path, absent: true}; throw e; }
  const chunks = []; let size = 0;
  try {
    for (;;) {
      const b = Buffer.alloc(Math.min(4096, cap + 1 - size));
      const n = fs.readSync(fd, b, 0, b.length, null);
      if (!n) break;
      size += n; if (size > cap) throw new Error('read cap: ' + path);
      chunks.push(b.subarray(0, n));
    }
  } finally { fs.closeSync(fd); }
  const b = Buffer.concat(chunks);
  return {path, size: b.length, sha256: crypto.createHash('sha256').update(b).digest('hex'), text: b.toString('utf8')};
}
const suid = read('/proc/sys/fs/suid_dumpable', 16);
const memfd = read('/proc/sys/vm/memfd_noexec', 16, true);
const kernel = read('/proc/sys/kernel/osrelease', 256);
const status = read('/proc/self/status', 16384);
const limits = read('/proc/self/limits', 16384);
const passwd = read('/etc/passwd', 65536);
const mountinfo = read('/proc/self/mountinfo', 262144);
const home = fs.lstatSync('/nonexistent');
const record = {
  kind: 'new-runner-metadata-only', uid: process.getuid(), gid: process.getgid(),
  architecture: process.arch, platform: process.platform, kernel_release: os.release(),
  suid_dumpable: suid, memfd_noexec: memfd, kernel, status, limits,
  account: {passwd_sha256: passwd.sha256, passwd_size: passwd.size,
    selected_rows: passwd.text.split('\n').filter(x => x.split(':')[2] === '65534')},
  mounts: {mountinfo_sha256: mountinfo.sha256, mountinfo_size: mountinfo.size,
    selected_rows: mountinfo.text.split('\n').filter(x => ['/nonexistent', '/proc', '/proc/sys'].includes(x.split(' ')[4]))},
  home: {uid: home.uid, gid: home.gid, mode: home.mode & 0o7777, directory: home.isDirectory(),
    canonical: fs.realpathSync('/nonexistent'), entries: fs.readdirSync('/nonexistent')}
};
// Preserve bounded metadata before any policy or fixture assertions.
const output = JSON.stringify(record);
if (Buffer.byteLength(output) > 48 * 1024) throw new Error('metadata output cap');
process.stdout.write(output + '\n');
if (record.uid !== 65534 || record.gid !== 65534 || record.architecture !== 'arm64' || record.platform !== 'linux') throw new Error('runtime identity');
if (record.home.uid !== 65534 || record.home.gid !== 65534 || record.home.mode !== 0o700 || !record.home.directory || record.home.canonical !== '/nonexistent' || record.home.entries.length) throw new Error('owned home identity');
const mount = record.mounts.selected_rows.find(x => x.split(' ')[4] === '/nonexistent');
if (!mount) throw new Error('home mount missing');
const [left, right] = mount.split(' - '), flags = left.split(' ')[5].split(',');
if (right.split(' ')[0] !== 'tmpfs' || !['ro', 'nosuid', 'nodev', 'noexec'].every(x => flags.includes(x))) throw new Error('home mount restrictions');
let probe;
try {
  const fd = fs.openSync('/nonexistent/.tirith-native-readonly-probe', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  fs.closeSync(fd); probe = {created: true};
} catch (error) { probe = {created: false, code: error.code, errno: error.errno}; }
process.stdout.write(JSON.stringify({readonly_probe: probe}) + '\n');
if (probe.created || probe.code !== 'EROFS') throw new Error('home is not observed read-only');
// A nonzero value is a successful observation of an unsuitable environment.
process.stdout.write(JSON.stringify({observation_complete: true,
  npm_dumpability_prerequisite_met: suid.text === '0\n' || suid.text === '0',
  original_v5_runner_value_inferred: false}) + '\n');
'''


def bounded_file(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode), str(path)
        with os.fdopen(fd, 'rb', closefd=False) as source:
            body = source.read(cap + 1)
        assert len(body) <= cap, str(path)
        return body
    finally:
        os.close(fd)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--driver-sha256', required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    script = Path(__file__).resolve()
    controller = script.parents[2]
    helper = controller / 'tools/qualification/mixed_audit_native.py'
    report = {'kind': 'metadata-only', 'new_runner_only': True,
              'product_executed': False, 'cargo_executed': False, 'sysctl_written': False,
              'image': IMAGE, 'children': [], 'cleanup': {}, 'passed': False,
              'controller_event_commit': os.environ.get('GITHUB_SHA'),
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')}
    save = lambda: (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    cid = None
    native = None
    image_id = None
    label = 'tirith-npm-metadata-' + os.urandom(16).hex()
    cidfile = output / 'owned.cid'
    docker = None
    docker_pin = None
    total_started = time.monotonic()
    work_deadline = None

    def command(name, argv, timeout=5, allowed=(0,)):
        assert native is not None
        assert len(report['children']) < 24, 'owned command count cap'
        assert sha(bounded_file(Path(docker).resolve(), 256 * 1024 * 1024)) == docker_pin
        if work_deadline is not None and not name.startswith('cleanup-'):
            timeout = min(timeout, work_deadline - time.monotonic())
            assert timeout > 0, 'runtime work deadline exhausted'
        job = native.Job(name, [docker, *argv], output, os.environ.copy(), timeout=timeout)
        try:
            native.finish([job])
        finally:
            errors = []
            for cleanup in (job.kill, job.process.stdout.close, job.process.stderr.close):
                try:
                    cleanup()
                except BaseException as error:
                    errors.append(str(error))
            row = job.result()
            row['wrapper_cleanup_errors'] = errors
            report['children'].append(row)
            (output / (name + '.stdout')).write_text(row['stdout'])
            (output / (name + '.stderr')).write_text(row['stderr'])
            save()
        assert row['failure'] is None and all(row['cleanup'].values()) and not errors, name
        assert row['exit'] in allowed, (name, row['exit'])
        return row

    def owned(name):
        data = json.loads(command(name, ['inspect', cid])['stdout'])
        assert len(data) == 1
        obj = data[0]
        assert obj['Id'] == cid and obj['Image'] == image_id
        assert obj['Config']['Labels'].get('tirith.native.metadata') == label
        assert obj['Config']['User'] == '65534:65534'
        return obj

    try:
        driver_bytes = bounded_file(script, 128 * 1024)
        helper_bytes = bounded_file(helper, 256 * 1024)
        assert sha(driver_bytes) == args.driver_sha256
        assert sha(helper_bytes) == HELPER_SHA
        report['inputs'] = {'driver_sha256': sha(driver_bytes), 'helper_sha256': sha(helper_bytes), 'guest_sha256': sha(GUEST.encode())}
        native = types.ModuleType('owned_metadata_helper')
        native.__file__ = str(helper)
        exec(compile(helper_bytes, str(helper), 'exec'), native.__dict__)
        native.require_process_observation()
        assert platform.system() == 'Linux' and platform.machine() == 'aarch64'
        assert os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'original attempt only'
        meminfo = Path('/proc/meminfo').read_text()
        available = int(next(x.split()[1] for x in meminfo.splitlines() if x.startswith('MemAvailable:'))) * 1024
        free = shutil.disk_usage(output).free
        report['host'] = {'machine': platform.machine(), 'kernel': platform.release(), 'memory_available_bytes': available, 'disk_free_bytes': free}
        save()
        assert available >= 512 * 1024 * 1024 and free >= 2 * 1024 ** 3, 'metadata resource admission'
        docker = shutil.which('docker')
        assert docker and Path(docker).is_absolute()
        docker_pin = sha(bounded_file(Path(docker).resolve(), 256 * 1024 * 1024))
        report['docker'] = {'path': docker, 'sha256': docker_pin}
        command('docker-version', ['version', '--format', '{{json .Server}}'])
        inspected = command('image-before', ['image', 'inspect', IMAGE], allowed=(0, 1))
        if inspected['exit'] != 0:
            command('image-pull', ['pull', '--platform', 'linux/arm64', IMAGE], timeout=180)
            inspected = command('image-after-pull', ['image', 'inspect', IMAGE])
        images = json.loads(inspected['stdout'])
        assert len(images) == 1
        info = images[0]
        assert info['Architecture'] == 'arm64' and info['Os'] == 'linux' and IMAGE in info['RepoDigests']
        image_id = info['Id']
        report['image_id'] = image_id
        report['image_inspect'] = info
        report['disk_free_after_pull_bytes'] = shutil.disk_usage(output).free
        assert report['disk_free_after_pull_bytes'] >= 512 * 1024 * 1024
        assert time.monotonic() - total_started < 220, 'provisioning total deadline'
        (output / 'guest.js').write_text(GUEST)
        started = time.monotonic()
        work_deadline = started + 30
        report['runtime_deadline_seconds'] = 30
        command('container-create', ['create', '--pull=never', '--cidfile', str(cidfile),
                '--label', 'tirith.native.metadata=' + label, '--user', '65534:65534',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=unconfined', '--read-only',
                '--network', 'none', '--memory', '256m', '--memory-swap', '256m', '--cpus', '1',
                '--pids-limit', '32', '--tmpfs', '/nonexistent:ro,noexec,nosuid,nodev,size=1m,uid=65534,gid=65534,mode=0700',
                '--entrypoint', '/usr/local/bin/node', IMAGE, '--input-type=commonjs', '-e', GUEST], timeout=5)
        cid = cidfile.read_text().strip()
        assert len(cid) == 64 and all(c in '0123456789abcdef' for c in cid)
        report['cid'] = cid
        before = owned('container-before')
        report['container_before'] = before
        h = before['HostConfig']
        assert h['ReadonlyRootfs'] and h['NetworkMode'] == 'none'
        assert h['Memory'] == 268435456 and h['MemorySwap'] == 268435456
        assert h['NanoCpus'] == 1000000000 and h['PidsLimit'] == 32
        assert h['CapDrop'] == ['ALL'] and 'no-new-privileges' in h['SecurityOpt']
        assert 'seccomp=unconfined' in h['SecurityOpt']
        remaining = 30 - (time.monotonic() - started)
        assert remaining > 0
        row = command('container-start', ['start', '--attach', cid], timeout=min(20, remaining), allowed=(0, 1))
        report['guest_exit'] = row['exit']
        report['guest_rows'] = [json.loads(line) for line in row['stdout'].splitlines()]
        report['container_after'] = owned('container-after')
        report['runtime_elapsed_seconds'] = time.monotonic() - started
        assert report['runtime_elapsed_seconds'] <= 35
        assert row['exit'] == 0 and not report['container_after']['State']['Running']
        assert len(report['guest_rows']) == 3 and report['guest_rows'][-1]['observation_complete']
        assert report['guest_rows'][-1]['original_v5_runner_value_inferred'] is False
        report['npm_dumpability_prerequisite_met'] = report['guest_rows'][-1]['npm_dumpability_prerequisite_met']
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if cid is None and cidfile.exists():
            value = cidfile.read_text().strip()
            if len(value) == 64 and all(c in '0123456789abcdef' for c in value):
                cid = value
                report['cid'] = cid
        if cid:
            try:
                obj = owned('cleanup-identity')
                report['cleanup']['identity_verified'] = True
                if obj['State']['Running']:
                    command('cleanup-kill', ['kill', '--signal', 'KILL', cid])
                command('cleanup-remove', ['rm', cid])
                report['cleanup']['removed'] = True
                absent = command('cleanup-absence', ['inspect', cid], allowed=(1,))
                assert any(x in absent['stderr'].lower() for x in ('no such object', 'no such container'))
                report['cleanup']['absence_observed'] = True
            except BaseException as error:
                report['cleanup']['error'] = str(error)
                report['passed'] = False
        try:
            report['inputs_postcheck'] = {'driver_sha256': sha(bounded_file(script, 128 * 1024)), 'helper_sha256': sha(bounded_file(helper, 256 * 1024))}
            assert report['inputs_postcheck']['driver_sha256'] == args.driver_sha256
            assert report['inputs_postcheck']['helper_sha256'] == HELPER_SHA
            if docker:
                assert sha(bounded_file(Path(docker).resolve(), 256 * 1024 * 1024)) == docker_pin
        except BaseException as error:
            report['inputs_postcheck_error'] = str(error)
            report['passed'] = False
        report['elapsed_seconds'] = time.monotonic() - total_started
        save()
    assert report['passed'] and all(report['cleanup'].get(k) for k in ('identity_verified', 'removed', 'absence_observed')), report.get('error', report['cleanup'])
    print(json.dumps({'passed': True, 'npm_dumpability_prerequisite_met': report['npm_dumpability_prerequisite_met'], 'new_runner_only': True, 'cid': cid}))


if __name__ == '__main__':
    main()
