#!/usr/bin/env python3
"""Two sequential native ARM qualification phases for a private gate candidate.
The reviewed manifest binds a clean product commit independently of controller.
Each authority phase compiles in Rust then runs held outputs in exact Node.
Compiler and runtime containers are strictly sequential within one phase deadline.
"""
import argparse
import datetime
import base64
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import sys
import tarfile
import time
import tomllib
import urllib.parse
import urllib.request
import uuid

GIB = 1024 ** 3
MIB = 1024 ** 2
RUST_IMAGE = 'rust@sha256:3ebe98baef5911f8461cf81ba05644374a3c5ef1f8a33db3977bd4175f5ff1fc'
NODE_IMAGE = 'node@sha256:2b028cd57303b2761d24173789c85a013558d6cf20e78f51723385f368b6e34d'
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
CAPTURE_SHA = 'd398b167eac3a672aa5996fe93c0a8ba47ab571c6dd747f777fafe02b43fac80'
KEY_PATH = 'crates/tirith-core/assets/keys/threatdb-verify.pub'
KEY_SHA = 'ee65a4cf011b55b19a8bbc6cc64d6b46dbcc5a2e35a690f8cf6f511f6d993db9'
CLIPPY_URL = 'https://static.rust-lang.org/dist/2026-09-03/clippy-1.98.1-aarch64-unknown-linux-gnu.tar.xz'
CLIPPY_SHA = '396e17c0a669399823d0e59073686a4e5f50b2d41f062f1d3afc9210f9d3553d'
CLIPPY_SIZE = 3915700
CLIPPY_TAR_SIZE = 16948736
CLIPPY_TAR_SHA = 'be9a0f90dc9c980b402d41ae10d00b84c17f50ec7ea3c5f48fdc1dcb730ba47a'
CHANNEL_URL = 'https://static.rust-lang.org/dist/channel-rust-1.98.1.toml'
CHANNEL_SHA = 'a7c8774a5fd8441c997d94c029776cbc5eb111e9d72ab5d256fa69866644347e'
TOOLCHAIN = '1.98.1-aarch64-unknown-linux-gnu'
LABEL = 'tirith.wp26.native-fixture'
PENDING_OUTPUT = None

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def decompress_component(source, destination):
    require(source.stat().st_size == CLIPPY_SIZE and sha(source) == CLIPPY_SHA,
            'compressed component identity differs before decompression')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128*MIB)
    total = 0
    deadline = time.monotonic()+120
    with source.open('rb') as compressed, destination.open('xb') as output:
        while not decoder.eof:
            require(time.monotonic() < deadline, 'component decompression deadline exceeded')
            chunk = compressed.read(65536) if decoder.needs_input else b''
            require(chunk or not decoder.needs_input, 'truncated compressed component')
            expanded = decoder.decompress(chunk, max_length=min(65536, 64*MIB-total+1))
            total += len(expanded)
            require(total <= 64*MIB, 'uncompressed component exceeds 64MiB bound')
            output.write(expanded)
        require(decoder.eof and not decoder.unused_data and compressed.read(1) == b'',
                'trailing or unconsumed compressed component bytes')
    require(source.stat().st_size == CLIPPY_SIZE and sha(source) == CLIPPY_SHA,
            'compressed component changed during decompression')
    require(total == CLIPPY_TAR_SIZE and sha(destination) == CLIPPY_TAR_SHA,
            'derived uncompressed tar differs from reviewed bytes')
    destination.chmod(0o644)
    return {'compressed_size': CLIPPY_SIZE, 'compressed_sha256': CLIPPY_SHA,
            'uncompressed_size': total, 'uncompressed_sha256': sha(destination),
            'output_cap_bytes': 64*MIB, 'decoder_memory_cap_bytes': 128*MIB,
            'decoder_eof': True, 'trailing_or_unused_bytes': False,
            'tar_member_bytes_rewritten': False}


def load(path, expected, name):
    require(sha(path) == expected, name + ' changed')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(sha(path) == expected, name + ' changed during load')
    return module


def host_resources(path, facts):
    with Path('/proc/meminfo').open('r') as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536, 'host memory facts exceed bound')
    fields = {line.split(':', 1)[0]: int(line.split(':', 1)[1].split()[0])*1024
              for line in raw.splitlines() if ':' in line}
    available = fields['MemAvailable']
    disk = os.statvfs(path)
    facts.update({'mem_total_bytes': fields['MemTotal'], 'mem_available_bytes': available,
                  'disk_available_bytes': disk.f_bavail*disk.f_frsize,
                  'platform': platform.platform(), 'machine': platform.machine()})
    with Path('/proc/self/cgroup').open('r') as stream:
        memberships = stream.read(4097)
    require(len(memberships) <= 4096, 'cgroup membership facts exceed bound')
    facts['cgroup_membership'] = memberships
    unified = [line[3:] for line in memberships.splitlines() if line.startswith('0::')]
    require(len(unified) == 1, 'unified cgroup membership unavailable')
    relative = PurePosixPath(unified[0])
    require(relative.is_absolute() and '..' not in relative.parts, 'invalid cgroup membership')
    root = Path('/sys/fs/cgroup')
    require((root/'cgroup.controllers').is_file(), 'unified cgroup root mapping unavailable')
    with (root/'cgroup.controllers').open('r') as stream:
        controllers = stream.read(4097)
    require(len(controllers) <= 4096, 'cgroup controller facts exceed bound')
    facts['root_cgroup_controllers'] = controllers
    current = root.joinpath(*relative.parts[1:])
    limits = []
    facts['cgroup_limits'] = limits
    for _ in range(64):
        maximum = current/'memory.max'
        usage = current/'memory.current'
        observation = {'path': str(current), 'memory_max_present': maximum.is_file(),
                       'memory_current_present': usage.is_file()}
        limits.append(observation)
        if current == root and not observation['memory_max_present'] and not observation['memory_current_present']:
            # The unified root normally has no per-cgroup memory limit files.
            # Host MemAvailable and every observed finite ancestor cap still
            # apply. Missing controller files at a nonroot membership refuse.
            observation['classification'] = 'unconstrained_unified_root'
            break
        require(observation['memory_max_present'] and observation['memory_current_present'],
                'cgroup memory controller mapping unavailable or incomplete')
        with maximum.open('r') as stream:
            limit = stream.read(129)
        with usage.open('r') as stream:
            used = stream.read(129)
        require(len(limit) <= 128 and len(used) <= 128, 'memory controller facts exceed bound')
        limit, used = limit.strip(), used.strip()
        require((limit == 'max' or limit.isdecimal()) and used.isdecimal(), 'invalid memory controller facts')
        observation.update({'max': limit, 'current': int(used), 'classification': 'observed_memory_controller'})
        if limit != 'max':
            available = min(available, max(0, int(limit)-int(used)))
        if current == root:
            break
        current = current.parent
    else:
        raise RuntimeError('cgroup hierarchy exceeds bound')
    facts['effective_available_bytes'] = available


def main():
    global PENDING_OUTPUT
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--driver-sha256', required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    PENDING_OUTPUT = output
    base = Path(__file__).resolve().parent
    require(re.fullmatch('[0-9a-f]{64}', args.driver_sha256) and sha(__file__) == args.driver_sha256,
            'driver differs from reviewed pin')
    manifest_path = base/'manifest.json'
    require(re.fullmatch('[0-9a-f]{64}', args.manifest_sha256) and sha(manifest_path) == args.manifest_sha256,
            'manifest differs from reviewed pin')
    manifest = json.loads(manifest_path.read_text())
    require(re.fullmatch('[0-9a-f]{40}', manifest['product_commit']) and
            re.fullmatch('[0-9a-f]{40}', manifest['product_tree']), 'unbound product identity')
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64', 'native ARM Linux required')
    repo = args.source_root.resolve(strict=True)
    helper_path = repo/'tools/qualification/mixed_audit_native.py'
    capture_path = repo/'tools/qualification/signed_replacement_inputs.py'
    native = load(helper_path, HELPER_SHA, 'native_owner')
    capture = load(capture_path, CAPTURE_SHA, 'source_capture')
    paths = [shutil.which(name) for name in ('docker', 'git')]
    require(all(paths), 'host tools missing')
    docker, git = [Path(path).resolve(strict=True) for path in paths]
    inputs = {'driver': sha(__file__), 'manifest': sha(manifest_path), 'helper': sha(helper_path),
              'capture': sha(capture_path), 'docker': sha(docker), 'git': sha(git),
              'python': capture.interpreter_identity()}
    before = capture.scan_source(repo)
    require(before['files'] == manifest['files'] and
            before['optional_absent'] == manifest['source_optional_absent'], 'source closure mismatch')
    require(sha(repo/KEY_PATH) == KEY_SHA, 'normal source does not contain production key')
    lock = tomllib.loads((repo/'Cargo.lock').read_text())
    external = [item for item in lock['package'] if 'source' in item]
    require(all(item['source'] == 'registry+https://github.com/rust-lang/crates.io-index' and
                re.fullmatch('[0-9a-f]{64}', item.get('checksum', '')) for item in external),
            'unadmitted dependency source')
    report = {'classification': 'isolated_test_authority_native_mechanics', 'run_id': str(uuid.uuid4()),
              'inputs': inputs, 'owned_children': [], 'containers': [], 'phases': [],
              'production_feed_evidence': False, 'public_cli_execution_enabled': True,
              'production_key_initial_match': True, 'production_key_changed': None, 'error': None,
              'dependency_admission': {'lock_sha256': sha(repo/'Cargo.lock'),
                 'packages': len(lock['package']), 'public_registry_packages': len(external)}}
    active = None
    source = output/'normal-source'
    fixture_source = output/'fixture-source'
    frozen = None
    fixture_frozen = None

    class DiskBoundJob(native.Job):
        # The reviewed helper remains byte-identical. Its existing timeout path
        # owns/reaps the CLI group; reducing this object's deadline on a disk
        # refusal feeds that same bounded cleanup path without a helper edit.
        def __init__(self, *values, **options):
            self.watch_disk = options.pop('watch_disk')
            self.disk_observations = []
            self.disk_refusal = False
            self.next_disk_observation = 0
            super().__init__(*values, **options)

        @property
        def timeout(self):
            if not self.watch_disk:
                return self.original_timeout
            now = time.monotonic()
            if now >= self.next_disk_observation:
                self.next_disk_observation = now+5
                observation = {'seconds_after_start': round(now-self.started, 3)}
                self.disk_observations.append(observation)
                try:
                    disk = os.statvfs(output)
                    available = disk.f_bavail*disk.f_frsize
                    observation['available_bytes'] = available
                    if available < 5*GIB:
                        self.disk_refusal = True
                except OSError as error:
                    observation['error'] = str(error)
                    self.disk_refusal = True
            return 0 if self.disk_refusal else self.original_timeout

        @timeout.setter
        def timeout(self, value):
            self.original_timeout = value

    def command(name, argv, timeout=30):
        job = DiskBoundJob(name, list(map(str, argv)), output, os.environ.copy(), timeout=timeout,
                           watch_disk=name.endswith('-command'))
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
            row['disk_observations'] = job.disk_observations
            if job.disk_refusal:
                row['disk_refusal'] = True
            if errors:
                row['wrapper_cleanup_errors'] = errors
            report['owned_children'].append(row)
            (output/(name+'.stdout')).write_text(row['stdout'])
            (output/(name+'.stderr')).write_text(row['stderr'])
            require(not errors, name+': wrapper cleanup failed')
        require(not row.get('disk_refusal'), name+': host free-disk guard refused; stopping owned work')
        require(row['failure'] is None and all(row['cleanup'].values()), name+': owned CLI cleanup incomplete')
        return row

    def success(name, argv, timeout=30):
        row = command(name, argv, timeout)
        require(row['exit'] == 0, name+': command failed')
        return row

    def dock(name, argv, timeout=30):
        return success(name, [docker, *argv], timeout)

    def product_identity(stage):
        head = success(stage+'-product-head', [git, '--no-optional-locks', '-C', repo, 'rev-parse', 'HEAD'])['stdout'].strip()
        tree = success(stage+'-product-tree', [git, '--no-optional-locks', '-C', repo, 'rev-parse', 'HEAD^{tree}'])['stdout'].strip()
        status = success(stage+'-product-status', [git, '--no-optional-locks', '-C', repo, 'status', '--porcelain=v1', '--untracked-files=all'])['stdout']
        require(head == manifest['product_commit'] and tree == manifest['product_tree'] and status == '',
                'product revision or cleanliness mismatch')
        report.setdefault('product_identities', []).append({'stage': stage, 'commit': head, 'tree': tree, 'clean': True})

    def copy_source(destination, key=None):
        destination.mkdir(mode=0o755)
        for row in before['files']:
            target = destination/row['path']
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with capture.HeldFile(repo/row['path'], 64*capture.MIB, allow_empty=True) as held:
                require(held.identity == {'sha256': row['sha256'], 'size': row['size']}, 'source changed before copy')
                with target.open('xb') as stream:
                    for part in held.chunks():
                        stream.write(part)
                target.chmod(0o755 if held.token[2] & 0o111 else 0o644)
                held.revalidate()
        require(capture.scan_source(repo) == before, 'product changed during source capture')
        if key is not None:
            require(len(key) == 32 and hashlib.sha256(key).hexdigest() != KEY_SHA, 'invalid isolated fixture key')
            (destination/KEY_PATH).write_bytes(key)
        current = capture.scan_source(destination)
        delta = [row['path'] for row, original in zip(current['files'], before['files']) if row != original]
        require(len(current['files']) == len(before['files']) and
                current['optional_absent'] == before['optional_absent'] and
                delta == ([KEY_PATH] if key is not None else []), 'source variant exceeds sole-key delta')
        (output/(destination.name+'-inputs.json')).write_text(json.dumps(current, indent=2)+'\n')
        return current

    def admit(stage, disk=20*GIB):
        facts = {'stage': stage}
        report.setdefault('host_resources', []).append(facts)
        host_resources(output, facts)
        facts['docker_mem_total_bytes'] = int(dock(stage+'-docker-memory', ['info', '--format', '{{json .MemTotal}}'])['stdout'])
        require(dock(stage+'-other-containers', ['ps', '--no-trunc', '--format', '{{.ID}}'])['stdout'] == '',
                'another container is running; refusing without mutation')
        require(facts['effective_available_bytes'] >= 12*GIB and facts['docker_mem_total_bytes'] >= 12*GIB,
                'insufficient effective memory for bounded 10GiB phase')
        require(facts['disk_available_bytes'] >= disk, 'insufficient disk headroom')

    def retain_id():
        if active and active['id'] is None and active['cidfile'].exists():
            st = active['cidfile'].lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 128, 'invalid CID file')
            value = active['cidfile'].read_text().strip()
            require(re.fullmatch('[0-9a-f]{64}', value), 'invalid CID value')
            active['id'] = value
            active['record']['container_id'] = value

    def inspect(name):
        retain_id()
        require(active and active['id'], 'missing owned container')
        rows = json.loads(dock(name, ['inspect', '--type', 'container', active['id']])['stdout'])
        require(len(rows) == 1, 'ambiguous container')
        item = rows[0]
        require(item['Id'] == active['id'] and item['Config']['Image'] == active['image'] and
                item['Config']['Labels'].get(LABEL) == active['token'], 'container identity mismatch')
        active['record']['cleanup']['identity_verified'] = True
        return item

    def memory(stage):
        item = {'stage': stage, 'files': {}}
        active['record'].setdefault('memory', []).append(item)
        for name in ('memory.events', 'memory.peak', 'memory.max', 'memory.current', 'memory.stat'):
            row = command(stage+'-'+name.replace('.', '-'), [docker, 'exec', active['id'], '/usr/bin/head', '-c', '4097', '/sys/fs/cgroup/'+name])
            within = len(row['stdout'].encode()) <= 4096
            item['files'][name] = {'available': row['exit'] == 0 and within, 'exit': row['exit'],
                                   'contents': row['stdout'] if within else None}
        require(all(row['available'] for row in item['files'].values()), 'memory telemetry incomplete')

    def cleanup():
        nonlocal active
        if active is None:
            return
        retain_id()
        if active['id']:
            item = inspect(active['name']+'-cleanup-inspect')
            if item['State']['Running']:
                try:
                    memory(active['name']+'-cleanup-memory')
                except BaseException as error:
                    active['record']['telemetry_error'] = str(error)
            result = dock(active['name']+'-remove', ['rm', '--force', active['id']])
            require(result['stdout'].strip() == active['id'], 'owned removal did not confirm CID')
            active['record']['cleanup']['removed'] = True
            absent = dock(active['name']+'-absence', ['ps', '-a', '--no-trunc', '--filter', 'id='+active['id'], '--format', '{{.ID}}'])
            require(absent['stdout'] == '', 'owned container still exists')
            active['record']['cleanup']['absence_observed'] = True
        completed = active['record']
        active = None
        require(all(completed['cleanup'].values()) and 'telemetry_error' not in completed,
                completed['name']+': cleanup or telemetry incomplete; subsequent phase refused')

    def create(name, image, arguments, lifetime=2400):
        nonlocal active
        require(active is None, 'container phases must be sequential')
        require(0 < lifetime <= 2400, 'container lifetime exceeds phase bound')
        token = report['run_id']+'-'+name
        cidfile = output/(name+'.cid')
        record = {'name': name, 'image': image, 'container_id': None,
                  'cleanup': {'identity_verified': False, 'removed': False, 'absence_observed': False}}
        report['containers'].append(record)
        active = {'name': name, 'image': image, 'token': token, 'cidfile': cidfile, 'id': None, 'record': record}
        row = command(name+'-create', [docker, 'create', '--name', 'tirith-npm-'+token, '--cidfile', cidfile,
            '--label', LABEL+'='+token, '--init', '--user', '65534:65534', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
            '--memory', '10g', '--memory-swap', '10g', '--cpus', '2', *arguments, image, '/bin/sleep', str(lifetime)])
        retain_id()
        require(row['exit'] == 0 and active['id'] is not None, 'container creation failed')
        item = inspect(name+'-initial-inspect')
        config = item['HostConfig']
        require(not item['State']['Running'] and config['Memory'] == 10*GIB and config['MemorySwap'] == 10*GIB and
            config['NanoCpus'] == 2_000_000_000 and config['PidsLimit'] == 256 and config['ReadonlyRootfs'] and
            config['CapDrop'] == ['ALL'] and 'no-new-privileges' in config['SecurityOpt'] and
            item['Config']['User'] == '65534:65534', 'isolation settings differ')

    def retain_file(name, remote, cap):
        require(remote.startswith('/work/') and '..' not in PurePosixPath(remote).parts, 'unadmitted export path')
        row = dock(name+'-identity', ['exec', active['id'], '/bin/sh', '-c',
            'test -f "$1" && test ! -L "$1" && stat -c %s "$1" && sha256sum "$1"', 'identity', remote])
        lines = row['stdout'].splitlines()
        require(len(lines) == 2 and lines[0].isdigit(), 'bad export identity')
        size = int(lines[0]); expected = lines[1].split('  ')
        require(size <= cap and len(expected) == 2 and expected[1] == remote and
                re.fullmatch('[0-9a-f]{64}', expected[0]), 'export size/hash refused')
        destination = output/name
        deadline = time.monotonic()+120
        with destination.open('xb') as stream:
            for index in range((size+24575)//24576):
                require(time.monotonic() < deadline, 'export deadline exceeded')
                chunk = dock(name+'-chunk-'+str(index), ['exec', active['id'], '/bin/sh', '-c',
                    'dd if="$1" bs=24576 skip="$2" count=1 status=none | base64 -w0', 'copy', remote, str(index)])
                content = base64.b64decode(chunk['stdout'], validate=True)
                require(len(content) == min(24576, size-index*24576), 'export chunk truncated')
                stream.write(content)
        require(destination.stat().st_size == size and sha(destination) == expected[0], 'export changed')
        return {'path': str(destination), 'size': size, 'sha256': expected[0]}

    def stage(phase, name, argv, timeout, test_count=None, expected_exit=0):
        tag = phase['name']+'-'+name
        remote_out, remote_err = '/work/'+tag+'.stdout', '/work/'+tag+'.stderr'
        invocation = shlex.join(list(map(str, argv)))+' > '+remote_out+' 2> '+remote_err
        item = {'name': name, 'exit': None, 'expected_exit': expected_exit, 'requested_timeout_seconds': timeout,
                'phase_seconds_remaining_before': max(0, active['deadline']-time.monotonic()),
                'retention_errors': [], 'container_name': active['name'], 'container_image': active['image']}
        phase['stages'].append(item)
        original_error = None
        try:
            remaining = int(active['deadline']-time.monotonic())
            require(remaining > 0, tag+': bounded phase deadline expired')
            disk = os.statvfs(output)
            item['host_disk_available_bytes'] = disk.f_bavail*disk.f_frsize
            require(item['host_disk_available_bytes'] >= 5*GIB, 'host disk below 5GiB stop threshold')
            item['admitted_timeout_seconds'] = min(timeout, remaining)
            row = command(tag+'-command', [docker, 'exec', active['id'], '/bin/sh', '-c', invocation],
                          item['admitted_timeout_seconds'])
            item['exit'] = row['exit']
        except BaseException as error:
            original_error = error
            item['wrapper_error'] = str(error)
            if report['owned_children'] and report['owned_children'][-1].get('disk_refusal'):
                item['disk_refusal'] = True
                # Stop disk growth immediately. Current tmpfs logs may become
                # unavailable; completed-stage logs and the refusal survive.
                try:
                    observed = inspect(tag+'-disk-stop-inspect')
                    if observed['State']['Running']:
                        dock(tag+'-disk-stop', ['kill', active['id']])
                except BaseException as stop_error:
                    item['retention_errors'].append('disk stop: '+str(stop_error))
        # A failed or timed-out CLI never skips best-effort diagnostics. We only
        # address the same inspected CID; a stopped container cannot export its
        # tmpfs and that limit is recorded rather than hiding the first failure.
        try:
            observed = inspect(tag+'-retention-inspect')
            require(observed['State']['Running'], 'owned container stopped; redirected tmpfs logs unavailable')
            for field, remote, cap in [('stdout', remote_out, 16*MIB), ('stderr', remote_err, 8*MIB)]:
                try:
                    item[field] = retain_file(tag+'.'+field, remote, cap)
                except BaseException as error:
                    item['retention_errors'].append(field+': '+str(error))
            try:
                memory(tag+'-memory')
            except BaseException as error:
                item['retention_errors'].append('memory: '+str(error))
        except BaseException as error:
            item['retention_errors'].append('owned observation: '+str(error))
        item['phase_seconds_remaining_after'] = max(0, active['deadline']-time.monotonic())
        if original_error is not None:
            raise original_error
        require(item['exit'] == expected_exit, tag+': stage failed; no retry')
        require(not item['retention_errors'], tag+': required logs/telemetry incomplete')
        if test_count is not None:
            text = Path(item['stdout']['path']).read_text()
            counts = [int(n) for n in re.findall(r'test result: ok\. (\d+) passed; 0 failed;', text)]
            require(counts == [test_count], tag+': test selection/count differs')
            item['passed_tests'] = test_count
        return item

    def records(item, control):
        text = Path(item['stdout']['path']).read_text()
        rows = []
        for line in text.splitlines():
            start = line.find('{')
            if start >= 0:
                try:
                    value = json.loads(line[start:])
                except ValueError:
                    continue
                if type(value) is dict and value.get('control') == control:
                    rows.append(value)
        return rows

    def public_download(url, name, expected, cap):
        request = urllib.request.Request(url, headers={'User-Agent': 'tirith-native-fixture'})
        destination = output/name
        deadline = time.monotonic()+120
        with urllib.request.urlopen(request, timeout=20) as response, destination.open('xb') as stream:
            require(response.status == 200 and urllib.parse.urlsplit(response.url).hostname == 'static.rust-lang.org',
                    'unadmitted compiler download authority')
            count = 0
            while True:
                require(time.monotonic() < deadline, 'compiler download deadline exceeded')
                chunk = response.read(65536)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= cap, 'compiler download bound exceeded')
                stream.write(chunk)
        require(sha(destination) == expected, 'pinned compiler component changed')
        destination.chmod(0o644)
        report.setdefault('public_compiler_downloads', []).append({'url': url, 'size': count, 'sha256': expected})
        return destination

    def public_cli_case(phase, launcher_path, launcher_sha, public, generated):
        """One real CLI lifecycle under the same isolated fixture authority."""
        case = '/work/fixture/public-cli'
        values = {
            'PATH': '/usr/local/bin:/usr/bin:/bin',
            'HOME': case+'/home', 'XDG_DATA_HOME': case+'/data',
            'XDG_CONFIG_HOME': case+'/config', 'XDG_CACHE_HOME': case+'/cache',
            'XDG_STATE_HOME': case+'/state', 'TMPDIR': case+'/tmp',
            'TIRITH_THREATDB_PATH': case+'/data/threatdb.dat',
            'TIRITH_THREATDB_SUPPLEMENTAL_PATH': case+'/data/supplemental.dat',
        }
        prefix = ['/usr/bin/env', '-i', *[key+'='+value for key, value in values.items()],
                  '/bin/sh', '-c', 'cd "$1" || exit 70; shift; exec "$@"', 'public-cli', case+'/workspace', launcher_path]

        def unique_json(raw):
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    require(key not in result, 'duplicate public CLI JSON key')
                    result[key] = value
                return result
            value = json.loads(raw, object_pairs_hook=unique)
            require(type(value) is dict, 'public CLI did not return one JSON object')
            return value

        def exact_json(item, cap=128*1024):
            raw = Path(item['stdout']['path']).read_bytes()
            require(len(raw) <= cap, 'public CLI JSON exceeds fixed bound')
            return unique_json(raw)

        admitted = stage(phase, 'public-cli-input-admission', ['/bin/sh', '-c',
            'set -eu; test ! -e "$1/installed"; test ! -e "$1/state/tirith/npm-install-intents"; '
            'test ! -e "$1/data/threatdb.dat"; test ! -e "$1/data/supplemental.dat"; '
            'test ! -e "$1/data/supplemental-v2.dat"; '
            'sha256sum "$2" "$1/data/threatdb-v2.dat" "$1/config/tirith/audit-signing.pub"; '
            'stat -c "%u %a" "$1" "$1/workspace"; stat -f -c "%t %T" "$1"',
            'public-cli-admission', case, launcher_path], 30)
        lines = Path(admitted['stdout']['path']).read_text().splitlines()
        require(lines == [launcher_sha+'  '+launcher_path,
                public['source_sha256']+'  '+case+'/data/threatdb-v2.dat',
                generated['audit_public_sha256']+'  '+case+'/config/tirith/audit-signing.pub',
                '65534 700', '65534 700', '1021994 tmpfs'], 'public CLI case or authority differs')
        planned_item = stage(phase, 'public-cli-plan', prefix+['pkg', 'install-npm', 'plan',
            case+'/leaf.tgz', '--target', case+'/installed', '--json'], 120)
        planned = exact_json(planned_item)
        operation, reviewed = planned.get('operation'), planned.get('reviewed_sha256')
        require(type(operation) is str and str(uuid.UUID(operation)) == operation and
                uuid.UUID(operation).int != 0 and type(reviewed) is str and
                re.fullmatch('[0-9a-f]{64}', reviewed), 'public CLI operation/review identity differs')
        require(planned.get('schema') == 1 and planned.get('contract') == 'LocalLeafNoScriptsV1' and
                planned.get('phase') == 'reviewed_intent' and planned.get('target') == case+'/installed' and
                planned.get('execution_available') is True and
                planned.get('execution_availability_scope') == 'native_contract_gate_only; all current apply checks still required' and
                planned.get('execution_state') == 'not_started' and planned.get('execution_authority') is False,
                'public CLI plan does not describe the enabled gate and unstarted intent')
        archive_path = source/'crates/tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz'
        require(archive_path.stat().st_size == 465, 'canonical public CLI archive size differs')
        archive_bytes = archive_path.read_bytes()
        archive_sha = hashlib.sha256(archive_bytes).hexdigest()
        require(archive_sha == '769755af559bda513cfe86d6c433bf8e6c0b2431dbb24955393e0dc69eeb2c0f',
                'canonical public CLI archive pin differs')
        archive_integrity = 'sha512-'+base64.b64encode(hashlib.sha512(archive_bytes).digest()).decode()
        # Independent contract for the four regular members of this exact 465-byte
        # fixture. No general archive extractor or package-selected expectation.
        package = 'installed/node_modules/tirith-local-inspection-fixture/'
        expected_members = {
            package+'index.js': (34, '3c4a78e286981651d3745d5e79e6e4e61940dfb45c44adad547ed04c5f811519'),
            package+'install.js': (30, '670f09b4c235e99f05cef5b46d935ab3f051d3e8bd192f96a75bbcb280bb1b97'),
            package+'long-directory/long-directory-0/long-directory-1/long-directory-2/long-directory-3/'
            'long-directory-4/long-directory-5/long-directory-6/long-directory-7/résumé.js':
                (38, 'bd117eb4b92034950e02803d43cdf2d19a8ebbf62900da7d79a0b079cc7b568b'),
            package+'package.json': (186, 'fee63a19707ec815c72e9a08dda20531cab14f13db358f47a99897ca1379f167'),
        }
        manager_path = 'installed/node_modules/.package-lock.json'
        expected_files = set(expected_members) | {manager_path}
        expected_dirs = {str(parent) for name in expected_files for parent in PurePosixPath(name).parents
                         if str(parent) != '.'}
        journal_name = '.tirith-install-journal-'+hashlib.sha256((case+'/installed').encode()).hexdigest()
        lock_package = '../../../..'+case+'/'+journal_name+'/pending-target/node_modules/tirith-local-inspection-fixture'

        require(planned.get('archives') == [{'path': case+'/leaf.tgz', 'sha256': archive_sha}],
                'public CLI plan archive differs')
        apply_args = prefix+['pkg', 'install-npm', 'apply', operation, '--reviewed', reviewed, '--json']
        applied_item = stage(phase, 'public-cli-apply', apply_args, 120)
        applied = exact_json(applied_item)
        require(applied.get('schema') == 1 and applied.get('contract') == 'LocalLeafNoScriptsV1' and
                applied.get('operation') == operation and applied.get('summary') == planned.get('summary') and
                applied.get('phase') == 'published_verified' and applied.get('execution_state') == 'completed' and
                applied.get('target_publication_crossed') is True and applied.get('cleanup_confirmed') is True and
                applied.get('lifecycle_scripts_executed') is False and applied.get('code_safety') == 'not_established' and
                applied.get('ongoing_immutability') is False,
                'public CLI apply did not complete exact verified publication and cleanup')
        receipts = [applied.get(key) for key in ('private_receipt_id', 'committed_receipt_id')]
        require(all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) for value in receipts) and
                receipts[0] != receipts[1], 'public CLI receipt linkage differs')

        # This independent bounded snapshot emits identities/hashes, never private
        # intent or key bytes. Reading may change atime, which is excluded.
        snapshot_script = r'''
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [root, operation] = process.argv.slice(1);
function need(value, message) { if (!value) throw new Error(message); }
need(root === '/work/fixture/public-cli' && /^[0-9a-f-]{36}$/.test(operation), 'fixed snapshot scope');
let entries = 0, bytes = 0, managerLock = null;
const rows = [];
function identity(st) {
  return ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'].map(key => st[key].toString());
}
function visit(file, label, depth) {
  need(++entries <= 256 && depth <= 16, 'snapshot entry/depth bound');
  const before = fs.lstatSync(file, {bigint:true});
  need(before.uid === 65534n && !before.isSymbolicLink(), 'snapshot ownership/link');
  const row = {path:label, identity:identity(before)};
  if (before.isDirectory()) {
    row.kind = 'directory'; rows.push(row);
    const names = fs.readdirSync(file).sort();
    need(names.length <= 256-entries, 'snapshot directory bound');
    for (const name of names) visit(path.join(file,name), label+'/'+name, depth+1);
  } else {
    need(before.isFile() && before.nlink === 1n && before.size <= 2097152n, 'snapshot regular-file bound');
    bytes += Number(before.size); need(bytes <= 8388608, 'snapshot byte bound');
    const fd = fs.openSync(file, fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try {
      need(JSON.stringify(identity(fs.fstatSync(fd,{bigint:true}))) === JSON.stringify(row.identity), 'snapshot open changed');
      const buffer = Buffer.alloc(Number(before.size)+1); let count=0;
      while (count < buffer.length) { const n=fs.readSync(fd,buffer,count,buffer.length-count,null); if (!n) break; count+=n; }
      need(count === Number(before.size), 'snapshot size changed'); const content=buffer.subarray(0,count);
      row.kind='file'; row.sha256=crypto.createHash('sha256').update(content).digest('hex'); rows.push(row);
      if (label === 'installed/node_modules/.package-lock.json') {
        need(content.length <= 16384, 'manager lock bound');
        managerLock = new TextDecoder('utf-8', {fatal:true}).decode(content);
      }
      need(JSON.stringify(identity(fs.fstatSync(fd,{bigint:true}))) === JSON.stringify(row.identity), 'snapshot held changed');
    } finally { fs.closeSync(fd); }
  }
  need(JSON.stringify(identity(fs.lstatSync(file,{bigint:true}))) === JSON.stringify(row.identity), 'snapshot path changed');
}
visit(root+'/installed','installed',0);
for (const kind of ['intent','started','finished']) {
  visit(root+'/state/tirith/npm-install-intents/'+operation+'.'+kind+'.json', 'records/'+kind, 0);
}
const result={control:'public_cli_state_snapshot',entries,bytes,rows,manager_lock_utf8:managerLock};
const text=JSON.stringify(result); need(Buffer.byteLength(text)<=262144,'snapshot output bound');
process.stdout.write(text+'\n');
'''
        def snapshot(name):
            item = stage(phase, name, ['/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
                '/usr/local/bin/node', '-e', snapshot_script, case, operation], 30)
            value = exact_json(item, 256*1024)
            require(value.get('control') == 'public_cli_state_snapshot' and
                    type(value.get('rows')) is list and len(value['rows']) == value.get('entries'),
                    'public CLI snapshot shape differs')
            installed = [row for row in value['rows'] if row['path'] == 'installed' or row['path'].startswith('installed/')]
            require(len({row['path'] for row in installed}) == len(installed), 'duplicate installed snapshot path')
            files = {row['path']:row for row in installed if row['kind'] == 'file'}
            directories = {row['path'] for row in installed if row['kind'] == 'directory'}
            require(set(files) == expected_files and directories == expected_dirs and
                    len(installed) == len(files)+len(directories), 'public CLI installed member/directory set differs')
            for path, (size, digest) in expected_members.items():
                require(int(files[path]['identity'][6]) == size and files[path]['sha256'] == digest and
                        int(files[path]['identity'][2]) & 0o7777 == 0o644,
                        'public CLI installed fixture member bytes/mode differ: '+path)
            lock_text = value.get('manager_lock_utf8')
            require(type(lock_text) is str and len(lock_text.encode()) <= 16384 and
                    hashlib.sha256(lock_text.encode()).hexdigest() == files[manager_path]['sha256'],
                    'public CLI hidden lock content/hash differs')
            lock = unique_json(lock_text)
            require(set(lock) == {'lockfileVersion','requires','packages'} and
                    type(lock['lockfileVersion']) is int and lock['lockfileVersion'] == 3 and lock['requires'] is True and
                    type(lock['packages']) is dict and set(lock['packages']) == {lock_package},
                    'public CLI hidden lock schema or physical package path differs')
            leaf = lock['packages'][lock_package]
            require(type(leaf) is dict and set(leaf) == {'version','integrity','resolved','hasInstallScript'} and
                    leaf['version'] == '1.0.0' and leaf['integrity'] == archive_integrity and leaf['hasInstallScript'] is True and
                    type(leaf['resolved']) is str and re.fullmatch(r'file:\.\./[1-9][0-9]{0,6}', leaf['resolved']) and
                    3 <= int(leaf['resolved'][8:]) <= 1048575,
                    'public CLI hidden lock fixture metadata differs')
            return value
        before = snapshot('public-cli-before-status-retry')
        status_item = stage(phase, 'public-cli-status', prefix+['pkg', 'install-npm', 'status', operation, '--json'], 120)
        status = exact_json(status_item)
        observation = status.get('transaction_observation', {})
        require(status.get('operation') == operation and status.get('reviewed_sha256') == reviewed and
                status.get('phase') == 'published_verified' and status.get('historical_only') is True and
                status.get('execution_state') == 'not_observed_currently' and
                observation.get('phase') == 'published_verified' and observation.get('succeeded') is True and
                observation.get('execution_state') == 'completed' and observation.get('target_publication_crossed') is True and
                observation.get('cleanup_confirmed') is True and
                [observation.get(key) for key in ('private_receipt_id', 'committed_receipt_id')] == receipts,
                'public CLI status does not preserve truthful historical completion')
        retried_item = stage(phase, 'public-cli-identical-retry', apply_args, 120, expected_exit=1)
        retried = exact_json(retried_item)
        require(retried.get('error') == 'operation already started or ended; never replay apply' and
                retried.get('transaction_observation') is None and retried.get('execution_authority') is False,
                'public CLI retry did not refuse at the durable history guard')
        after = snapshot('public-cli-after-status-retry')
        require(before == after, 'public CLI status/retry changed the published tree or operation records')
        return {'case': 'public-cli-plan-apply-status-retry', 'authority': 'isolated_fixture_key',
            'production_feed_evidence': False, 'public_cli_exercised': True,
            'public_cli_execution_enabled': True, 'native_contract_gate_qualified': True,
            'ordinary_executable_sha256': launcher_sha,
            'fixture_public_key_sha256': public['fixture_public_key_sha256'],
            'threat_source_sha256': public['source_sha256'], 'operation': operation,
            'reviewed_sha256': reviewed, 'archive_sha256': archive_sha, 'receipt_ids': receipts,
            'successful_install_and_exact_tree_verified': True, 'cleanup_confirmed': True,
            'independent_fixture_members_and_directory_set_verified': True,
            'independent_hidden_lock_schema_package_version_integrity_verified': True,
            'hidden_lock_dynamic_source_fd_binding': 'product_verifier_observed; independent canonical descriptor shape only',
            'status_historical_only': True, 'retry_exit': retried_item['exit'],
            'retry_history_refused_before_transaction_dispatch': True,
            'separate_kernel_exec_trace_observed': False, 'tree_and_records_unchanged': True,
            'snapshot_sha256': hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


    def compiler_phase(name, captured_source, phase_two=False, public=None):
        phase = {'name': name, 'authority': 'fixture_key' if phase_two else 'production_key', 'stages': []}
        report['phases'].append(phase)
        admit(name+'-admission', 24*GIB)
        build_disk = output.parent/(output.name+'-'+name+'-build-disk')
        build_disk.mkdir(mode=0o1777, exist_ok=False)
        build_disk.chmod(0o1777)
        phase['owned_build_disk'] = {'host_path': str(build_disk), 'container_private_root': '/build-disk/owned',
            'root_created_by': 'host owner with sticky parent; UID65534 creates mode0700 owned child', 'uploaded': False}
        mounts = ['--network', 'bridge', '--tmpfs', '/work:rw,exec,nosuid,nodev,size=512m,mode=1777',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
            '--mount', 'type=bind,src='+str(build_disk)+',dst=/build-disk',
            '--mount', 'type=bind,src='+str(captured_source)+',dst=/source,readonly',
            '--mount', 'type=bind,src='+str(output/'clippy.tar')+',dst=/clippy.tar,readonly',
            '--env', 'RUSTUP_HOME=/build-disk/owned/rustup', '--env', 'CARGO_HOME=/build-disk/owned/cargo',
            '--env', 'RUSTUP_TOOLCHAIN='+TOOLCHAIN,
            '--env', 'PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            '--env', 'CARGO_TARGET_DIR=/build-disk/owned/target', '--env', 'CARGO_BUILD_JOBS=1',
            '--env', 'CARGO_PROFILE_DEV_DEBUG=0', '--env', 'CARGO_PROFILE_TEST_DEBUG=0',
            '--env', 'CARGO_INCREMENTAL=0', '--env', 'HOME=/work/home', '--workdir', '/source']
        create(name+'-compiler', RUST_IMAGE, mounts)
        dock(name+'-compiler-start', ['start', active['id']])
        phase_deadline = time.monotonic()+2380
        active['deadline'] = phase_deadline
        phase['time_envelope'] = {'compiler_container_lifetime_seconds': 2400, 'shared_compiler_and_runtime_work_deadline_seconds': 2380,
            'deadline_utc': (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=2380)).isoformat(),
            'stage_timeouts_clamped_to_remaining_phase': True, 'retries': 0}
        phase['memory_envelope'] = {'cgroup_memory_max_bytes': 10*GIB, 'memory_swap_max_total_bytes': 10*GIB,
            'tmpfs_maximum_bytes': {'work': 512*MIB, 'tmp': 512*MIB},
            'compiler_target_and_cache_storage': 'separate owned ephemeral runner disk; file cache remains cgroup-charged but reclaimable',
            'runtime_authenticated_home_tmpfs_maximum_bytes': MIB,
            'all_tmpfs_pages_and_process_memory_share_the_same_cgroup_cap': True,
            'prior_rust_image_peak_is_not_a_capacity_prediction_for_this_plan': True}
        # Compiler writes use private UID65534 disk dirs; fixture secrets use
        # verified tmpfs. The official pinned
        # installer only adds Clippy to this copied immutable-version toolchain.
        setup = ('set -eu; mkdir -m 700 /build-disk/owned /build-disk/owned/rustup /build-disk/owned/cargo /build-disk/owned/target /work/home; '
            'test \"$(stat -f -c %t /build-disk/owned)\" != 1021994; '
            'stat -c \"%u %a\" /build-disk/owned /build-disk/owned/rustup /build-disk/owned/cargo /build-disk/owned/target; '
            'cp -a --no-preserve=ownership /usr/local/rustup/. /build-disk/owned/rustup/; '
            'tar -xf /clippy.tar -C /work; '
            '/work/clippy-1.98.1-aarch64-unknown-linux-gnu/install.sh '
            '--prefix=/build-disk/owned/rustup/toolchains/'+TOOLCHAIN+' --disable-ldconfig; '
            'rustc -vV; cargo -V; cargo clippy --version; '
            'sha256sum /build-disk/owned/rustup/toolchains/'+TOOLCHAIN+'/bin/rustc '
            '/build-disk/owned/rustup/toolchains/'+TOOLCHAIN+'/bin/cargo '
            '/build-disk/owned/rustup/toolchains/'+TOOLCHAIN+'/bin/cargo-clippy '
            '/build-disk/owned/rustup/toolchains/'+TOOLCHAIN+'/bin/clippy-driver; '
            'uname -a; cc --version; readelf --version; '
            'for tool in cc ld ar readelf; do path=$(command -v "$tool"); readlink -f "$path"; sha256sum "$(readlink -f "$path")"; done')
        info = stage(phase, 'compiler-provision', ['/bin/sh', '-c', setup], 180)
        tool_text = Path(info['stdout']['path']).read_text()
        require('rustc 1.98.1 ' in tool_text and 'host: aarch64-unknown-linux-gnu' in tool_text and
                'cargo 1.98.1 ' in tool_text and 'clippy ' in tool_text and 'GNU readelf' in tool_text and
                tool_text.splitlines().count('65534 700') == 4,
                'compiler/native/private-disk facts differ')
        compiler_pins = [line for line in tool_text.splitlines() if re.fullmatch('[0-9a-f]{64}  /build-disk/owned/rustup/toolchains/[^\\n]+/bin/(?:rustc|cargo|cargo-clippy|clippy-driver)', line)]
        require(len(compiler_pins) == 4, 'compiler binary pins missing')
        phase['compiler_binary_pins'] = compiler_pins
        inventory_command = ['/bin/bash', '-o', 'pipefail', '-c',
            'set -eu; find \"$1\" -printf \"%y %m %u %g %p %l\\n\" | LC_ALL=C sort; '
            'find \"$1\" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum',
            'toolchain-inventory', '/build-disk/owned/rustup/toolchains/'+TOOLCHAIN]
        compiler_inventory = stage(phase, 'compiler-inventory', inventory_command, 120)
        phase['compiler_complete_inventory'] = compiler_inventory['stdout']
        stage(phase, 'locked-fetch', ['cargo', 'fetch', '--locked', '--target', 'aarch64-unknown-linux-gnu'], 300)
        dock(name+'-compiler-disconnect', ['network', 'disconnect', 'bridge', active['id']])
        require(inspect(name+'-compiler-offline-inspect')['NetworkSettings']['Networks'] == {}, 'network remains attached')
        phase['build_and_execution_offline'] = True
        if not phase_two:
            stage(phase, 'typecheck', ['cargo', 'check', '--locked', '--offline', '-p', 'tirith', '-p', 'tirith-core', '--all-targets'], 900)
            stage(phase, 'strict-clippy', ['cargo', 'clippy', '--locked', '--offline', '-p', 'tirith', '-p', 'tirith-core', '--all-targets', '--', '-D', 'warnings'], 900)
        launcher = stage(phase, 'launcher-build', ['cargo', 'build', '--locked', '--offline', '-p', 'tirith', '--bin', 'tirith', '--message-format=json'], 1200)
        tests = stage(phase, 'libtest-build', ['cargo', 'test', '--locked', '--offline', '-p', 'tirith', '--bin', 'tirith', '--no-run', '--message-format=json'], 1200)
        def executable(item, test):
            rows = []
            for line in Path(item['stdout']['path']).read_text().splitlines():
                value = json.loads(line)
                if value.get('reason') == 'compiler-artifact' and value.get('target', {}).get('name') == 'tirith' and value.get('executable') and value.get('profile', {}).get('test') == test:
                    rows.append(value['executable'])
            require(len(rows) == 1 and rows[0].startswith('/build-disk/owned/target/debug/') and '..' not in PurePosixPath(rows[0]).parts,
                    'ambiguous captured executable')
            return rows[0]
        launcher_path = executable(launcher, False)
        test_path = executable(tests, True)
        pins = stage(phase, 'executable-pins', ['/bin/sh', '-c',
            'set -eu; for file in "$1" "$2"; do test -f "$file"; test ! -L "$file"; '
            'size=$(stat -c %s "$file"); test "$size" -ge 64; test "$size" -le 536870912; done; '
            'sha256sum "$1" "$2"; for file in "$1" "$2"; do '
            'stat -c "%s %a" "$file"; readelf -h "$file"; readelf -l "$file"; readelf --version-info "$file"; done',
            'pins', launcher_path, test_path], 30)
        pin_text = Path(pins['stdout']['path']).read_text()
        first = pin_text.splitlines()[:2]
        require(len(first) == 2 and all(re.fullmatch('[0-9a-f]{64}  /build-disk/owned/target/debug/[^\n]+', line) for line in first) and
                pin_text.count('AArch64') == 2 and pin_text.count('ELF64') == 2 and
                pin_text.count('Requesting program interpreter: /lib/ld-linux-aarch64.so.1') == 2, 'native executable or loader refused')
        launcher_sha, test_sha = [line.split('  ')[0] for line in first]
        phase['executables'] = {'launcher': {'path': launcher_path, 'sha256': launcher_sha},
                                'libtest': {'path': test_path, 'sha256': test_sha}}
        # Finish compiler observations before removing its exact CID. The
        # two retained output files are then mounted read-only into Node; no SDK
        # or build-side library is carried into the characterized runtime.
        compiler_post = stage(phase, 'compiler-postcheck', ['sha256sum', *[line.split('  ')[1] for line in compiler_pins]], 30)
        require(Path(compiler_post['stdout']['path']).read_text().splitlines() == compiler_pins, 'compiler bytes changed')
        inventory_post = stage(phase, 'compiler-inventory-postcheck', inventory_command, 120)
        require(inventory_post['stdout']['sha256'] == compiler_inventory['stdout']['sha256'], 'complete compiler tree changed')
        build_post = stage(phase, 'compiler-output-postcheck', ['sha256sum', launcher_path, test_path], 30)
        require(Path(build_post['stdout']['path']).read_text().splitlines() == first, 'compiler outputs changed before handoff')
        require(capture.scan_source(captured_source) == (fixture_frozen if phase_two else frozen), 'source changed during compiler phase')
        cleanup()
        phase['compiler_cleanup_before_runtime'] = True
        admit(name+'-runtime-admission', 5*GIB)
        remaining = int(phase_deadline-time.monotonic())
        require(remaining > 0, 'shared phase deadline expired before runtime')
        built_launcher_path, built_test_path = launcher_path, test_path
        runtime_launcher_path, runtime_test_path = '/compiled/launcher', '/compiled/libtest'
        runtime_mounts = ['--network', 'none', '--tmpfs', '/work:rw,exec,nosuid,nodev,size=512m,mode=1777',
            '--tmpfs', '/nonexistent:ro,noexec,nosuid,nodev,size=1m,uid=65534,gid=65534,mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
            '--mount', 'type=bind,src='+str(build_disk/Path(built_launcher_path).relative_to('/build-disk'))+',dst='+runtime_launcher_path+',readonly',
            '--mount', 'type=bind,src='+str(build_disk/Path(built_test_path).relative_to('/build-disk'))+',dst='+runtime_test_path+',readonly',
            '--mount', 'type=bind,src='+str(captured_source)+',dst=/source,readonly',
            '--env', 'HOME=/work/home', '--workdir', '/source']
        if phase_two:
            runtime_mounts.extend(['--security-opt', 'seccomp=unconfined',
                '--mount', 'type=bind,src='+str(output/'fixture-signing.pub')+',dst=/fixture-signing.pub,readonly',
                '--mount', 'type=bind,src='+str(output/'fixture-threatdb-v2.dat')+',dst=/fixture-threatdb-v2.dat,readonly'])
        create(name+'-runtime', NODE_IMAGE, runtime_mounts, min(2400, remaining+20))
        dock(name+'-runtime-start', ['start', active['id']])
        active['deadline'] = phase_deadline
        observed_runtime = inspect(name+'-runtime-offline-inspect')
        require(observed_runtime['HostConfig']['NetworkMode'] == 'none' and
                all(network == 'none' for network in observed_runtime['NetworkSettings']['Networks']), 'runtime has a network attachment')
        require(observed_runtime['HostConfig']['Tmpfs'].get('/nonexistent') == 'ro,noexec,nosuid,nodev,size=1m,uid=65534,gid=65534,mode=0700',
                'authenticated home tmpfs configuration differs')
        require(all(any(mount['Destination'] == path and not mount['RW'] for mount in observed_runtime['Mounts'])
                    for path in (runtime_launcher_path, runtime_test_path)), 'compiler output binds are not read-only')
        launcher_path, test_path = runtime_launcher_path, runtime_test_path
        phase['executables']['launcher']['runtime_path'] = launcher_path
        phase['executables']['libtest']['runtime_path'] = test_path
        runtime_setup = stage(phase, 'runtime-setup', ['/bin/sh', '-c',
            'set -eu; mkdir -m 700 /work/home /work/fixture; test "$(stat -f -c %t /work/fixture)" = 1021994; '
            'stat -c "%u %a" /work/home /work/fixture; stat -f -c "%t %T" /work/fixture; '
            'uname -a; node --version; /usr/local/bin/node /usr/local/lib/node_modules/npm/bin/npm-cli.js --version; ldd --version'], 30)
        runtime_text = Path(runtime_setup['stdout']['path']).read_text()
        require(runtime_text.splitlines().count('65534 700') == 2 and '1021994 tmpfs' in runtime_text and
                'v26.7.0' in runtime_text and '11.19.0' in runtime_text, 'runtime identity/tmpfs admission differs')
        phase['fixture_secret_storage_observed_tmpfs'] = True
        account_home_script = r'''
const fs=require('fs'), os=require('os'), crypto=require('crypto');
function need(v,m){if(!v)throw new Error(m);}
function bounded(path,cap){
 const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try { const buffer=Buffer.alloc(cap+1);let count=0;
  while(count<buffer.length){const n=fs.readSync(fd,buffer,count,buffer.length-count,null);if(!n)break;count+=n;}
  need(count<=cap,'account preflight bound');return buffer.subarray(0,count);
 }finally{fs.closeSync(fd);}
}
const passwd=bounded('/etc/passwd',16384), passwdSha=crypto.createHash('sha256').update(passwd).digest('hex');
need(passwdSha==='bad4a17cc56d0e63db7b8d9b41b3ec2e96cde8a4eb0621858121af45093c5d82','pinned passwd changed');
const account=os.userInfo();
need(process.getuid()===65534&&process.getgid()===65534&&account.uid===65534&&account.gid===65534&&account.homedir==='/nonexistent','account identity changed');
const entry=passwd.toString('utf8').split('\n').filter(line=>line.split(':')[2]==='65534');
need(entry.length===1&&entry[0]==='nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin','account record differs');
const home=fs.lstatSync(account.homedir,{bigint:true});
need(home.isDirectory()&&!home.isSymbolicLink()&&home.uid===65534n&&home.gid===65534n&&(home.mode&511n)===448n&&fs.realpathSync(account.homedir)==='/nonexistent','authenticated home is not exact private directory');
need(fs.readdirSync('/nonexistent').length===0,'authenticated fixture home is not empty');
const stats=fs.statfsSync('/nonexistent',{bigint:true});
need(stats.type===0x1021994n&&stats.bsize*stats.blocks<=1048576n,'account home tmpfs bound differs');
const mounts=bounded('/proc/self/mountinfo',1048576).toString('utf8').split('\n').filter(line=>line.split(' ')[4]==='/nonexistent');
need(mounts.length===1,'account home mount missing or duplicated');
const halves=mounts[0].split(' - '), left=halves[0].split(' '), right=halves[1].split(' '), options=left[5].split(',');
need(['ro','nosuid','nodev','noexec'].every(value=>options.includes(value))&&right[0]==='tmpfs'&&right[2].split(',').includes('ro'),'account home mount restrictions differ');
process.stdout.write(JSON.stringify({control:'authenticated_account_home',passwd_sha256:passwdSha,account_entry:entry[0],uid:account.uid,gid:account.gid,home:account.homedir,canonical_home:fs.realpathSync(account.homedir),mode:'0700',tmpfs_size_bytes:String(stats.bsize*stats.blocks),mountinfo:mounts[0],empty:true,read_only:true,noexec:true,nosuid:true,nodev:true})+'\n');
'''
        account_home = stage(phase, 'authenticated-account-home', ['/usr/bin/env', '-i',
            'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/local/bin/node', '-e', account_home_script], 30)
        account_rows = records(account_home, 'authenticated_account_home')
        require(len(account_rows) == 1 and account_rows[0]['home'] == '/nonexistent' and
                account_rows[0]['read_only'] is True and account_rows[0]['empty'] is True,
                'authenticated account home admission missing')
        phase['authenticated_account_home'] = account_rows[0]

        loader = stage(phase, 'runtime-loader-admission', ['/bin/sh', '-c',
            'set -eu; sha256sum "$1" "$2"; ldd "$1"; ldd "$2"; "$1" --version; "$2" --list',
            'runtime-loader', launcher_path, test_path], 60)
        loader_text = Path(loader['stdout']['path']).read_text()
        require(loader_text.splitlines()[:2] == [launcher_sha+'  '+launcher_path, test_sha+'  '+test_path] and 'not found' not in loader_text and
                'fixture_signed_v2_is_refused_by_normal_product_preparation: test' in loader_text and
                'fixture_authority_native_coordinator_publication_and_interruption: test' in loader_text and
                'fixture_authority_native_script_suppression: test' in loader_text,
                'runtime loader, held output identity or native test registration differs')
        phase['runtime_loader_admitted'] = True
        disk_launcher_path = launcher_path
        handoff = stage(phase, 'trusted-launcher-handoff', ['/bin/sh', '-c',
            'set -eu; test -f "$1"; test ! -L "$1"; size=$(stat -c %s "$1"); '
            'test "$size" -ge 64; test "$size" -le 268435456; '
            'test "$(stat -c %u /work)" = 0; test "$(stat -c %a /work)" = 1777; '
            'mkdir -m 700 /work/launcher; install -m 500 "$1" /work/launcher/tirith; '
            'sha256sum "$1" /work/launcher/tirith; stat -c "%u %a" /work/launcher /work/launcher/tirith',
            'launcher-handoff', disk_launcher_path], 60)
        handoff_lines = Path(handoff['stdout']['path']).read_text().splitlines()
        require(handoff_lines == [launcher_sha+'  '+disk_launcher_path,
                launcher_sha+'  /work/launcher/tirith', '65534 700', '65534 500'],
                'trusted launcher handoff bytes or ownership changed')
        launcher_path = '/work/launcher/tirith'
        phase['executables']['admitted_launcher'] = {'path': launcher_path, 'sha256': launcher_sha,
            'same_bytes_as_disk_build': True, 'size_cap_bytes': 256*MIB}

        env = {'TIRITH_NPM_NATIVE_FIXTURE_ROOT': '/work/fixture'}
        if phase_two:
            env.update({'TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_PATH': '/fixture-signing.pub',
                        'TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_SHA256': public['fixture_public_key_sha256'],
                        'TIRITH_NPM_NATIVE_THREATDB': '/fixture-threatdb-v2.dat',
                        'TIRITH_NPM_NATIVE_THREATDB_SHA256': public['source_sha256']})
        def test(name, selection, values):
            return stage(phase, name, ['/usr/bin/env', *[key+'='+value for key,value in values.items()],
                test_path, selection, '--ignored', '--test-threads=1', '--nocapture'], 300, 1)
        provision = test('case-provision', 'provision_native_transaction_fixture_cases' if phase_two else
                         'generate_native_transaction_fixture_inputs', env)
        controls = records(provision, 'fixture_authority_case_provisioning' if phase_two else 'fixture_authority_generation')
        require(len(controls) == 1, 'missing exact fixture provision observation')
        generated = controls[0]
        require(generated['production_feed_evidence'] is False and
                generated['secrets_written_only_under_fixture_root'] is True, 'fixture provenance claim differs')
        if phase_two:
            require(generated['source_sha256'] == public['source_sha256'] and
                    generated['fixture_public_key_sha256'] == public['fixture_public_key_sha256'] and
                    generated['build_sequence'] == public['build_sequence'] and
                    generated['feed_resigned_or_refreshed'] is False, 'phase2 fixture authority changed')
        else:
            for field in ('fixture_public_key_sha256', 'source_sha256', 'audit_public_sha256'):
                require(re.fullmatch('[0-9a-f]{64}', generated[field]), 'invalid fixture pin')
            require(generated['format_version'] == 2 and generated['artifact_hash_records'] > 0 and
                    generated['member_hash_records'] > 0 and generated['independent_fixture_signature_valid'] is True,
                    'fixture authority lacks required v2 coverage')
            for name, cap, field in [('fixture-signing.pub', 32, 'fixture_public_key_sha256'),
                                     ('fixture-threatdb-v2.dat', 64*MIB, 'source_sha256')]:
                exported = retain_file(name, '/work/fixture/'+name, cap)
                require(exported['sha256'] == generated[field], 'fixture public export differs')
                (output/name).chmod(0o644)
        env.update({'TIRITH_NPM_NATIVE_THREATDB': '/work/fixture/fixture-threatdb-v2.dat',
            'TIRITH_NPM_NATIVE_THREATDB_SHA256': generated['source_sha256'],
            'TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_SHA256': generated['fixture_public_key_sha256'],
            'TIRITH_NPM_NATIVE_AUDIT_PUBLIC_SHA256': generated['audit_public_sha256'],
            'TIRITH_NPM_NATIVE_LAUNCHER': launcher_path,
            'TIRITH_NPM_NATIVE_LAUNCHER_SHA256': launcher_sha})
        tested = test('mechanics' if phase_two else 'production-key-negative',
            'fixture_authority_native_coordinator_publication_and_interruption' if phase_two else
            'fixture_signed_v2_is_refused_by_normal_product_preparation', env)
        if phase_two:
            results = records(tested, 'native_transaction_mechanics')
            require([row['case'] for row in results] == ['transaction-success', 'transaction-cancel-before-effects',
                'transaction-private-unwind', 'transaction-published-unwind'], 'mechanics cases missing or reordered')
            require(all(row['authority'] == 'isolated_fixture_key' and row['trusted_public_key_sha256'] == public['fixture_public_key_sha256'] and
                row['production_feed_evidence'] is False and row['public_cli_execution_enabled'] is True and
                row['public_cli_exercised'] is False and row['native_contract_gate_qualified'] is True and
                row['coordinator_seam_only'] is True and row['installation_replayed'] is False for row in results),
                'mechanics scope or authority differs')
            phase['mechanics_cases'] = results
            scripts = test('script-suppression', 'fixture_authority_native_script_suppression', env)
            script_results = records(scripts, 'native_script_suppression')
            require([row['case'] for row in script_results] == ['lifecycle-sentinels', 'implicit-gyp-sentinel'] and
                all(row['authority'] == 'isolated_fixture_key' and row['trusted_public_key_sha256'] == public['fixture_public_key_sha256'] and
                    row['production_feed_evidence'] is False and row['public_cli_execution_enabled'] is True and
                row['public_cli_exercised'] is False and row['native_contract_gate_qualified'] is True and
                    row['successful_install_and_exact_tree_verified'] is True and row['script_sentinels_absent'] is True and
                    row['target_exists'] is True and re.fullmatch('[0-9a-f]{64}', row['archive_sha256']) for row in script_results),
                'lifecycle/implicit-gyp suppression lacks successful verified installation or sentinel absence')
            phase['script_suppression_cases'] = script_results
            phase['public_cli_case'] = public_cli_case(phase, launcher_path, launcher_sha, public, generated)
        else:
            results = records(tested, 'normal_product_rejects_fixture_authority')
            require(len(results) == 1 and results[0]['product_signature_rejected'] is True and
                    results[0]['preparation_refusal'] == 'ThreatDataUnavailable' and
                    results[0]['fallback_slots_absent'] is True and results[0]['intent_or_transaction_effects'] is False,
                    'normal product key boundary not proven')
            phase['production_key_negative'] = results[0]
        post = stage(phase, 'input-postcheck', ['/bin/sh', '-c',
            'set -eu; sha256sum "$1" "$2" "$3" /work/fixture/fixture-signing.pub /work/fixture/fixture-threatdb-v2.dat /source/'+KEY_PATH,
            'pins', launcher_path, test_path, disk_launcher_path], 30)
        post_text = Path(post['stdout']['path']).read_text().splitlines()
        require([line.split('  ')[0] for line in post_text] == [launcher_sha, test_sha, launcher_sha,
                generated['fixture_public_key_sha256'], generated['source_sha256'],
                generated['fixture_public_key_sha256'] if phase_two else KEY_SHA], 'post-run input pins changed')
        phase['input_postcheck_passed'] = True
        cleanup()
        phase['passed'] = True
        return generated

    try:
        product_identity('initial')
        controller = success('controller-head', [git, '--no-optional-locks', '-C', base.parents[1], 'rev-parse', 'HEAD'])['stdout'].strip()
        require(controller == os.environ.get('GITHUB_SHA') and re.fullmatch('[0-9a-f]{40}', controller), 'controller revision mismatch')
        report['controller_commit'] = controller
        frozen = copy_source(source)
        admit('before-provision', 40*GIB)
        channel = public_download(CHANNEL_URL, 'rust-channel.toml', CHANNEL_SHA, 2*MIB)
        clippy = public_download(CLIPPY_URL, 'clippy.tar.xz', CLIPPY_SHA, CLIPPY_SIZE)
        require(clippy.stat().st_size == CLIPPY_SIZE, 'component size differs')
        component = tomllib.loads(channel.read_text())['pkg']['clippy-preview']['target']['aarch64-unknown-linux-gnu']
        require(component['available'] and component['xz_url'] == CLIPPY_URL and component['xz_hash'] == CLIPPY_SHA,
                'component differs from pinned official manifest')
        derived_clippy = decompress_component(clippy, output/'clippy.tar')
        report['public_compiler_decompression'] = derived_clippy
        with tarfile.open(output/'clippy.tar', 'r:') as archive:
            entries = archive.getmembers()
            require(len(entries) <= 128 and sum(entry.size for entry in entries) <= 32*MIB and
                    all(not PurePosixPath(entry.name).is_absolute() and '..' not in PurePosixPath(entry.name).parts and
                        (entry.isdir() or entry.isfile()) for entry in entries), 'component archive layout refused')
        for name, image in [('rust', RUST_IMAGE), ('node', NODE_IMAGE)]:
            dock(name+'-image-pull', ['pull', '--platform', 'linux/arm64', image], 300)
            rows = json.loads(dock(name+'-image-inspect', ['image', 'inspect', image])['stdout'])
            require(len(rows) == 1 and rows[0]['Os'] == 'linux' and rows[0]['Architecture'] == 'arm64' and rows[0]['Size'] <= 4*GIB,
                    'pinned native image differs or exceeds export bound')
            report.setdefault('images', {})[name] = {'digest': image, 'id': rows[0]['Id'], 'size': rows[0]['Size']}
        server = json.loads(dock('docker-server', ['version', '--format', '{{json .Server}}'])['stdout'])
        require(server['Os'] == 'linux' and server['Arch'] == 'arm64', 'native Docker server required')
        public = compiler_phase('normal', source)
        require(sha(output/'fixture-signing.pub') == public['fixture_public_key_sha256'] and
                sha(output/'fixture-threatdb-v2.dat') == public['source_sha256'], 'public handoff changed')
        fixture_frozen = copy_source(fixture_source, (output/'fixture-signing.pub').read_bytes())
        report['sole_fixture_source_delta'] = {'path': KEY_PATH, 'production_sha256': KEY_SHA,
            'fixture_sha256': public['fixture_public_key_sha256']}
        compiler_phase('fixture', fixture_source, True, public)
    except BaseException as error:
        report['error'] = str(error)
    finally:
        try:
            cleanup()
        except BaseException as error:
            report['cleanup_error'] = str(error)
        try:
            product_identity('final')
            require(capture.scan_source(repo) == before, 'product inputs changed')
            require(frozen is None or capture.scan_source(source) == frozen, 'normal captured inputs changed')
            require(fixture_frozen is None or capture.scan_source(fixture_source) == fixture_frozen, 'fixture captured inputs changed')
            report['production_key_changed'] = sha(repo/KEY_PATH) != KEY_SHA
            require(report['production_key_changed'] is False, 'tracked production key changed')
            if 'public_compiler_decompression' in report:
                require(sha(output/'clippy.tar') == report['public_compiler_decompression']['uncompressed_sha256'], 'derived compiler tar changed')
            actual = {'driver': sha(__file__), 'manifest': sha(manifest_path), 'helper': sha(helper_path),
                'capture': sha(capture_path), 'docker': sha(docker), 'git': sha(git), 'python': capture.interpreter_identity()}
            require(actual == inputs, 'controller tooling changed')
            report['final_inputs_match'] = True
        except BaseException as error:
            report['input_error'] = str(error)
        report['passed'] = (report['error'] is None and 'cleanup_error' not in report and 'input_error' not in report and
            len(report['phases']) == 2 and len(report['containers']) == 4 and all(phase.get('passed') for phase in report['phases']) and
            all(all(item['cleanup'].values()) and 'telemetry_error' not in item for item in report['containers']))
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'passed': report['passed'], 'error': report['error'], 'report': str(output/'report.json')}))
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        if PENDING_OUTPUT is not None:
            (PENDING_OUTPUT/'preflight-refusal.json').write_text(json.dumps({'passed': False, 'error': str(error)}, indent=2)+'\n')
        raise
