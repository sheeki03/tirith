#!/usr/bin/env python3
"""Build one inert OS probe and run two owned cases; no Tirith/Cargo/sysctl writes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import time
import types

RUST = 'rust@sha256:3ebe98baef5911f8461cf81ba05644374a3c5ef1f8a33db3977bd4175f5ff1fc'
NODE = 'node@sha256:2b028cd57303b2761d24173789c85a013558d6cf20e78f51723385f368b6e34d'
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
GUEST = "\n'use strict';\nconst fs = require('fs'), os = require('os'), crypto = require('crypto');\nfunction read(path, cap, optional = false) {\n  let fd;\n  try { fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW); }\n  catch (e) { if (optional && e.code === 'ENOENT') return {path, absent: true}; throw e; }\n  const chunks = []; let size = 0;\n  try {\n    for (;;) {\n      const b = Buffer.alloc(Math.min(4096, cap + 1 - size));\n      const n = fs.readSync(fd, b, 0, b.length, null);\n      if (!n) break;\n      size += n; if (size > cap) throw new Error('read cap: ' + path);\n      chunks.push(b.subarray(0, n));\n    }\n  } finally { fs.closeSync(fd); }\n  const b = Buffer.concat(chunks);\n  return {path, size: b.length, sha256: crypto.createHash('sha256').update(b).digest('hex'), text: b.toString('utf8')};\n}\nconst suid = read('/proc/sys/fs/suid_dumpable', 16);\nconst memfd = read('/proc/sys/vm/memfd_noexec', 16, true);\nconst kernel = read('/proc/sys/kernel/osrelease', 256);\nconst status = read('/proc/self/status', 16384);\nconst limits = read('/proc/self/limits', 16384);\nconst core_pattern = read('/proc/sys/kernel/core_pattern', 1024);\nconst ptrace_scope = read('/proc/sys/kernel/yama/ptrace_scope', 16, true);\nconst passwd = read('/etc/passwd', 65536);\nconst mountinfo = read('/proc/self/mountinfo', 262144);\nconst home = fs.lstatSync('/nonexistent');\nconst record = {\n  kind: 'new-runner-metadata-only', uid: process.getuid(), gid: process.getgid(),\n  architecture: process.arch, platform: process.platform, kernel_release: os.release(),\n  suid_dumpable: suid, memfd_noexec: memfd, kernel, status, limits, core_pattern, ptrace_scope,\n  account: {passwd_sha256: passwd.sha256, passwd_size: passwd.size,\n    selected_rows: passwd.text.split('\\n').filter(x => x.split(':')[2] === '65534')},\n  mounts: {mountinfo_sha256: mountinfo.sha256, mountinfo_size: mountinfo.size,\n    selected_rows: mountinfo.text.split('\\n').filter(x => ['/nonexistent', '/proc', '/proc/sys'].includes(x.split(' ')[4]))},\n  home: {uid: home.uid, gid: home.gid, mode: home.mode & 0o7777, directory: home.isDirectory(),\n    canonical: fs.realpathSync('/nonexistent'), entries: fs.readdirSync('/nonexistent')}\n};\n// Preserve bounded metadata before any policy or fixture assertions.\nconst output = JSON.stringify(record);\nif (Buffer.byteLength(output) > 48 * 1024) throw new Error('metadata output cap');\nprocess.stdout.write(output + '\\n');\nif (record.uid !== 65534 || record.gid !== 65534 || record.architecture !== 'arm64' || record.platform !== 'linux') throw new Error('runtime identity');\nif (record.home.uid !== 65534 || record.home.gid !== 65534 || record.home.mode !== 0o700 || !record.home.directory || record.home.canonical !== '/nonexistent' || record.home.entries.length) throw new Error('owned home identity');\nconst mount = record.mounts.selected_rows.find(x => x.split(' ')[4] === '/nonexistent');\nif (!mount) throw new Error('home mount missing');\nconst [left, right] = mount.split(' - '), flags = left.split(' ')[5].split(',');\nif (right.split(' ')[0] !== 'tmpfs' || !['ro', 'nosuid', 'nodev', 'noexec'].every(x => flags.includes(x))) throw new Error('home mount restrictions');\nlet probe;\ntry {\n  const fd = fs.openSync('/nonexistent/.tirith-native-readonly-probe', fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);\n  fs.closeSync(fd); probe = {created: true};\n} catch (error) { probe = {created: false, code: error.code, errno: error.errno}; }\nprocess.stdout.write(JSON.stringify({readonly_probe: probe}) + '\\n');\nif (probe.created || probe.code !== 'EROFS') throw new Error('home is not observed read-only');\n// A nonzero value is a successful observation of an unsuitable environment.\nprocess.stdout.write(JSON.stringify({observation_complete: true,\n  npm_dumpability_prerequisite_met: suid.text === '0\\n' || suid.text === '0',\n  original_v5_runner_value_inferred: false}) + '\\n');\n"


def sha(body):
    return hashlib.sha256(body).hexdigest()


def held(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            body = stream.read(cap + 1)
        assert len(body) <= cap
        after = os.fstat(fd)
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        return body
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--driver-sha256', required=True)
    parser.add_argument('--source-sha256', required=True)
    args = parser.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    script = Path(__file__).resolve()
    source = script.with_name('native-arm-dumpability-probe.c')
    helper = script.parents[2] / 'tools/qualification/mixed_audit_native.py'
    report = {'kind': 'inert-kernel-dumpability-controls', 'product_executed': False,
              'cargo_executed': False, 'sysctl_written': False, 'intentional_core_generation': False,
              'passed': False, 'children': [], 'containers': {}, 'run_id': os.environ.get('GITHUB_RUN_ID'),
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'controller_commit': os.environ.get('GITHUB_SHA')}
    def save():
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    native = None
    docker = None
    docker_sha = None
    cid = None
    phase = None
    image_id = None
    cidfile = None
    label = 'tirith-dumpability-' + os.urandom(16).hex()
    deadline = None
    total_start = time.monotonic()

    def command(name, argv, timeout=5, allowed=(0,)):
        assert len(report['children']) < 40, 'owned subprocess count cap'
        assert sha(held(Path(docker).resolve(), 256 * 1024 ** 2)) == docker_sha
        if deadline is not None and '-cleanup-' not in name:
            timeout = min(timeout, deadline - time.monotonic())
            assert timeout > 0, 'phase deadline exhausted'
        job = native.Job(name, [docker, *argv], out, os.environ.copy(), timeout=timeout)
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
            (out / (name + '.stdout')).write_text(row['stdout'])
            (out / (name + '.stderr')).write_text(row['stderr'])
            save()
        assert row['failure'] is None and all(row['cleanup'].values()) and not errors, name
        assert row['exit'] in allowed, (name, row['exit'])
        return row

    def observe(name):
        data = json.loads(command(name, ['inspect', cid])['stdout'])
        assert len(data) == 1
        value = data[0]
        assert value['Id'] == cid and value['Image'] == image_id
        assert value['Config']['User'] == '65534:65534'
        assert value['Config']['Labels'].get('tirith.native.dumpability') == label + '-' + phase
        return value

    def cleanup_current():
        nonlocal cid, cidfile
        if cid is None and cidfile is not None and cidfile.exists():
            value = cidfile.read_text().strip()
            if len(value) == 64 and all(c in '0123456789abcdef' for c in value):
                cid = value
        if cid is None:
            return
        record = report['containers'][phase]
        record['cid'] = cid
        cleanup = record.setdefault('cleanup', {})
        try:
            obj = observe(phase + '-cleanup-identity')
            cleanup['identity_verified'] = True
            record['final_state'] = obj['State']
            if obj['State']['Running']:
                command(phase + '-cleanup-kill', ['kill', '--signal', 'KILL', cid])
            command(phase + '-cleanup-remove', ['rm', cid])
            cleanup['removed'] = True
            absent = command(phase + '-cleanup-absence', ['inspect', cid], allowed=(1,))
            assert any(x in absent['stderr'].lower() for x in ('no such object', 'no such container'))
            cleanup['absence_observed'] = True
            cid = None
            cidfile = None
        except BaseException as error:
            cleanup['error'] = str(error)
            raise
        finally:
            save()

    def create(name, image, mem, seconds, extras, entrypoint, argv):
        nonlocal phase, image_id, cidfile, cid, deadline
        assert cid is None, 'previous owned container must be removed'
        phase = name
        image_id = report['images'][image]['Id']
        cidfile = out / (phase + '.cid')
        deadline = time.monotonic() + seconds
        report['containers'][phase] = {'image': image, 'image_id': image_id, 'phase_seconds': seconds, 'memory_bytes': mem}
        command(phase + '-create', ['create', '--pull=never', '--cidfile', str(cidfile),
                '--label', 'tirith.native.dumpability=' + label + '-' + phase, '--user', '65534:65534',
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--security-opt', 'seccomp=unconfined',
                '--read-only', '--network', 'none', '--memory', str(mem), '--memory-swap', str(mem),
                '--cpus', '1', '--pids-limit', '32', *extras, '--entrypoint', entrypoint, image, *argv])
        cid = cidfile.read_text().strip()
        assert len(cid) == 64 and all(c in '0123456789abcdef' for c in cid)
        report['containers'][phase]['cid'] = cid
        obj = observe(phase + '-before')
        report['containers'][phase]['before'] = obj
        h = obj['HostConfig']
        assert h['ReadonlyRootfs'] and h['NetworkMode'] == 'none'
        assert h['Memory'] == mem and h['MemorySwap'] == mem
        assert h['NanoCpus'] == 1000000000 and h['PidsLimit'] == 32
        assert h['CapDrop'] == ['ALL'] and 'no-new-privileges' in h['SecurityOpt'] and 'seccomp=unconfined' in h['SecurityOpt']

    try:
        source_bytes = held(source, 64 * 1024)
        driver_bytes = held(script, 128 * 1024)
        helper_bytes = held(helper, 256 * 1024)
        assert sha(source_bytes) == args.source_sha256 and sha(driver_bytes) == args.driver_sha256
        assert sha(helper_bytes) == HELPER_SHA
        report['input_pins'] = {'source': sha(source_bytes), 'driver': sha(driver_bytes), 'helper': sha(helper_bytes), 'guest': sha(GUEST.encode())}
        (out / 'probe.c').write_bytes(source_bytes)
        (out / 'guest.js').write_text(GUEST)
        native = types.ModuleType('owned_dumpability_helper')
        native.__file__ = str(helper)
        exec(compile(helper_bytes, str(helper), 'exec'), native.__dict__)
        native.require_process_observation()
        assert platform.system() == 'Linux' and platform.machine() == 'aarch64'
        assert os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
        available = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))) * 1024
        report['host'] = {'kernel': platform.release(), 'machine': platform.machine(), 'memory_available_bytes': available, 'disk_free_bytes': shutil.disk_usage(out).free}
        save()
        assert available >= 1024 ** 3 and report['host']['disk_free_bytes'] >= 3 * 1024 ** 3
        docker = shutil.which('docker')
        assert docker and Path(docker).is_absolute()
        docker_sha = sha(held(Path(docker).resolve(), 256 * 1024 ** 2))
        report['docker'] = {'path': docker, 'sha256': docker_sha}
        command('docker-server', ['version', '--format', '{{json .Server}}'])
        report['images'] = {}
        for index, image in enumerate((RUST, NODE)):
            row = command('image-' + str(index), ['image', 'inspect', image], allowed=(0, 1))
            if row['exit']:
                command('pull-' + str(index), ['pull', '--platform', 'linux/arm64', image], timeout=180)
                row = command('image-pulled-' + str(index), ['image', 'inspect', image])
            images = json.loads(row['stdout'])
            assert len(images) == 1 and image in images[0]['RepoDigests'] and images[0]['Architecture'] == 'arm64' and images[0]['Os'] == 'linux'
            report['images'][image] = images[0]
        assert time.monotonic() - total_start < 420
        assert shutil.disk_usage(out).free >= 1024 ** 3
        build_disk = out.parent / (out.name + '-owned-probe-build')
        build_disk.mkdir(mode=0o1777, exist_ok=False)
        build_disk.chmod(0o1777)
        report['owned_build_directory'] = str(build_disk)
        build = 'umask 077; mkdir /build/owned; chmod 0755 /build/owned; test "$(id -u)" = 65534; cc --version; sha256sum "$(readlink -f "$(command -v cc)")" "$(readlink -f "$(command -v readelf)")" /source/probe.c; cc -std=c11 -O2 -Wall -Wextra -Werror -static -no-pie /source/probe.c -o /build/owned/probe; chmod 0555 /build/owned/probe; test "$(stat -c %s /build/owned/probe)" -le 2097152; readelf -h -l /build/owned/probe; sha256sum /build/owned/probe'
        create('compile', RUST, 512 * 1024 ** 2, 60,
               ['--mount', 'type=bind,src=' + str(source) + ',dst=/source/probe.c,readonly',
                '--mount', 'type=bind,src=' + str(build_disk) + ',dst=/build',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=128m,uid=65534,gid=65534,mode=0700'],
               '/bin/sh', ['-eu', '-c', build])
        command('compile-start', ['start', '--attach', cid], timeout=50)
        completed = observe('compile-after')
        assert not completed['State']['Running'] and completed['State']['ExitCode'] == 0 and not completed['State']['OOMKilled']
        elf_path = build_disk / 'owned/probe'
        elf = held(elf_path, 2 * 1024 ** 2)
        assert elf[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', elf, 16)[0] == 2 and struct.unpack_from('<H', elf, 18)[0] == 183
        phoff = struct.unpack_from('<Q', elf, 32)[0]
        entry, count = struct.unpack_from('<HH', elf, 54)
        assert entry == 56 and 0 < count <= 128 and phoff + entry * count <= len(elf)
        assert all(struct.unpack_from('<I', elf, phoff + n * entry)[0] != 3 for n in range(count)), 'probe must be static without PT_INTERP'
        elf_pin = sha(elf)
        report['elf'] = {'sha256': elf_pin, 'bytes': len(elf), 'architecture': 'aarch64', 'static_without_interpreter': True}
        (out / 'probe.elf').write_bytes(elf)
        (out / 'probe.elf').chmod(0o600)
        assert sha(held(elf_path, 2 * 1024 ** 2)) == elf_pin
        cleanup_current()
        assert all(report['containers']['compile']['cleanup'].get(k) for k in ('identity_verified', 'removed', 'absence_observed'))
        deadline = None
        create('runtime', NODE, 256 * 1024 ** 2, 30,
               ['--mount', 'type=bind,src=' + str(elf_path) + ',dst=/compiled/probe,readonly',
                '--tmpfs', '/nonexistent:ro,noexec,nosuid,nodev,size=1m,uid=65534,gid=65534,mode=0700'],
               '/bin/sleep', ['45'])
        command('runtime-start', ['start', cid])
        metadata = command('runtime-metadata', ['exec', cid, '/usr/local/bin/node', '--input-type=commonjs', '-e', GUEST], timeout=5)
        report['metadata'] = [json.loads(x) for x in metadata['stdout'].splitlines()]
        facts = report['metadata'][0]
        assert facts['suid_dumpable']['text'] == '2\n', 'mode2 control requires observed host mode2'
        assert facts['status']['text'].count('CapEff:\t0000000000000000\n') == 1
        assert facts['status']['text'].count('NoNewPrivs:\t1\n') == 1 and facts['status']['text'].count('Seccomp:\t0\n') == 1
        assert report['metadata'][1]['readonly_probe']['code'] == 'EROFS'
        probe = command('runtime-probe', ['exec', cid, '/compiled/probe'], timeout=20, allowed=(0, 1, 71))
        rows = [json.loads(x) for x in probe['stdout'].splitlines()]
        report['probe_rows'] = rows
        report['probe_exit'] = probe['exit']
        assert probe['exit'] == 0 and rows[-1].get('passed') and rows[-1].get('case_count') == 2
        cases = [x for x in rows if 'case_mode' in x and x.get('passed')]
        assert [x['case_mode'] for x in cases] == [0o500, 0o100]
        assert all(x['normal_exit'] and x['report_eof'] for x in cases)
        children = [x for x in rows if x.get('owned_child_cleanup')]
        assert len(children) == 2 and len({x['pid'] for x in children}) == 2 and all(x['raw_status'] == 0 for x in children)
        report['elf_postcheck_sha256'] = sha(held(elf_path, 2 * 1024 ** 2))
        assert report['elf_postcheck_sha256'] == elf_pin
        cleanup_current()
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            cleanup_current()
        except BaseException as error:
            report['final_cleanup_error'] = str(error)
            report['passed'] = False
        try:
            report['post_pins'] = {'source': sha(held(source, 64 * 1024)), 'driver': sha(held(script, 128 * 1024)), 'helper': sha(held(helper, 256 * 1024))}
            assert report['post_pins'] == {k: report['input_pins'][k] for k in ('source', 'driver', 'helper')}
            if docker:
                assert sha(held(Path(docker).resolve(), 256 * 1024 ** 2)) == docker_sha
        except BaseException as error:
            report['input_postcheck_error'] = str(error)
            report['passed'] = False
        report['elapsed_seconds'] = time.monotonic() - total_start
        save()
    assert report['passed'], report.get('error', report.get('final_cleanup_error'))
    assert len(report['containers']) == 2 and all(all(c['cleanup'].get(k) for k in ('identity_verified', 'removed', 'absence_observed')) for c in report['containers'].values())
    print(json.dumps({'passed': True, 'cases': 2, 'product_qualification': False, 'elf': report['elf']}))


if __name__ == '__main__':
    main()
