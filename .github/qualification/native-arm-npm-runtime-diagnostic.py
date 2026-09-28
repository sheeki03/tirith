#!/usr/bin/env python3
"""One retained-V7 public text-apply diagnostic; no compilation or automatic retry."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shlex
import shutil
import stat
import sys
import time
import uuid
import zipfile

GIB = 1024**3
MIB = 1024**2
NODE_IMAGE = 'node@sha256:2b028cd57303b2761d24173789c85a013558d6cf20e78f51723385f368b6e34d'
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
CAPTURE_SHA = 'd398b167eac3a672aa5996fe93c0a8ba47ab571c6dd747f777fafe02b43fac80'
KEY_PATH = 'crates/tirith-core/assets/keys/threatdb-verify.pub'
KEY_SHA = 'ee65a4cf011b55b19a8bbc6cc64d6b46dbcc5a2e35a690f8cf6f511f6d993db9'
LABEL = 'tirith.wp26.retained-diagnostic'
PENDING_OUTPUT = None
sys.dont_write_bytecode = True


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


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
    parser.add_argument('--staging', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--driver-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--runtime-inputs-sha256', required=True)
    parser.add_argument('--download-child', action='store_true')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    runtime_path = base/'runtime-inputs.json'
    require(sha(__file__) == args.driver_sha256 and sha(base/'manifest.json') == args.manifest_sha256 and
            sha(runtime_path) == args.runtime_inputs_sha256, 'reviewed packet pin differs')
    original = json.loads(runtime_path.read_text())
    staging = args.staging.resolve()
    archive_path = staging/'original-artifact.zip'
    if args.download_child:
        resource.setrlimit(resource.RLIMIT_FSIZE, (original['zip_size']+1, original['zip_size']+1))
        fd = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.dup2(fd, 1)
        os.close(fd)
        gh = shutil.which('gh')
        require(gh is not None, 'GitHub CLI unavailable')
        os.execv(gh, [gh, 'api', 'repos/sheeki03/tirith/actions/artifacts/'+str(original['artifact']['id'])+'/zip'])
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    PENDING_OUTPUT = output
    staging.mkdir(mode=0o755, parents=True, exist_ok=False)
    require(not output.is_relative_to(staging) and not staging.is_relative_to(output), 'staging must not enter uploaded evidence')
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64', 'native Linux ARM required')
    outer_deadline = time.monotonic()+2380
    cleanup_deadline = None
    cleaning = False
    report = {'classification': 'retained_v7_single_public_apply_output_diagnostic', 'run_id': str(uuid.uuid4()),
              'original_run_id': original['original_run'], 'original_attempt': 1,
              'owned_children': [], 'containers': [], 'phases': [], 'error': None,
              'production_feed_evidence': False, 'full_seven_case_acceptance': False,
              'new_compilation': False, 'work_deadline_seconds': 2380,
              'runtime_deadline_seconds': 1200, 'cleanup_reserve_seconds': 60,
              'max_work_children': 512, 'max_cleanup_children': 16,
              'max_retained_stage_bytes': 32*MIB, 'guest_log_filesystem_cap_bytes': 512*MIB}
    active = None
    work_children = cleanup_children = retained_stage_bytes = 0
    repo = args.source_root.resolve(strict=True)
    manifest_path = base/'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    require(manifest['product_commit'] == original['original_product'], 'source manifest identity differs')
    helper_path = repo/'tools/qualification/mixed_audit_native.py'
    capture_path = repo/'tools/qualification/signed_replacement_inputs.py'
    native = load(helper_path, HELPER_SHA, 'native_owner')
    capture = load(capture_path, CAPTURE_SHA, 'source_capture')
    paths = [shutil.which(name) for name in ('docker', 'git', 'gh')]
    require(all(paths), 'required host tools missing')
    docker, git, gh = [Path(path).resolve(strict=True) for path in paths]
    inputs = {'driver': sha(__file__), 'manifest': sha(manifest_path), 'runtime_inputs': sha(runtime_path),
              'helper': sha(helper_path), 'capture': sha(capture_path), 'docker': sha(docker),
              'git': sha(git), 'gh': sha(gh), 'python': capture.interpreter_identity()}
    report['inputs'] = inputs
    before = capture.scan_source(repo)
    require(before['files'] == manifest['files'] and before['optional_absent'] == manifest['source_optional_absent'],
            'exact original source closure differs')
    require(sha(repo/KEY_PATH) == KEY_SHA, 'production key differs in original normal source')
    source = staging/'fixture-source'
    frozen = None
    staged = []
    phase = {'name': 'diagnostic', 'stages': [], 'authority': 'isolated_fixture_key'}
    report['phases'].append(phase)



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
        nonlocal work_children, cleanup_children
        require(not any(row['name'] == name for row in report['owned_children']), 'duplicate command name')
        if cleaning:
            require(cleanup_children < 16, 'cleanup command cap exceeded')
            cleanup_children += 1
            remaining = cleanup_deadline-time.monotonic()
        else:
            require(work_children < 512, 'work command cap exceeded')
            work_children += 1
            remaining = outer_deadline-time.monotonic()
        require(remaining > 0, 'bounded owner deadline expired')
        timeout = min(timeout, remaining)
        job = DiskBoundJob(name, list(map(str, argv)), output, os.environ.copy(), timeout=timeout,
                           watch_disk=not cleaning)
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
        require(cleaning or sum(len(r['stdout'].encode())+len(r['stderr'].encode()) for r in report['owned_children']) <= 64*MIB, 'aggregate command output exceeds bound')
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


    def inspect(name, timeout=30):
        retain_id()
        require(active and active['id'], 'missing owned container')
        rows = json.loads(dock(name, ['inspect', '--type', 'container', active['id']], timeout)['stdout'])
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
            inspect(active['name']+'-cleanup-inspect', 10)
            observations = active['record'].get('memory', [])
            required = {'memory.events', 'memory.peak', 'memory.max', 'memory.current', 'memory.stat'}
            valid = [row for row in observations if set(row.get('files', {})) == required and
                     all(value.get('available') for value in row['files'].values())]
            active['record']['teardown_telemetry'] = {
                'new_reads_attempted': False,
                'reason': 'reserve teardown time for exact CID removal and absence',
                'last_retained_valid_stage': valid[-1]['stage'] if valid else None,
            }
            if not valid:
                active['record']['telemetry_error'] = 'no valid stage memory telemetry retained'
            # Optional metadata cannot consume the independently reserved
            # removal budget. Existing stage observations remain explicit.
            result = dock(active['name']+'-remove', ['rm', '--force', active['id']], 20)
            require(result['stdout'].strip() == active['id'], 'owned removal did not confirm CID')
            active['record']['cleanup']['removed'] = True
            absent = dock(active['name']+'-absence', ['ps', '-a', '--no-trunc', '--filter',
                'id='+active['id'], '--format', '{{.ID}}'], 10)
            require(absent['stdout'] == '', 'owned container still exists')
            active['record']['cleanup']['absence_observed'] = True
        completed = active['record']
        active = None
        require(all(completed['cleanup'].values()) and 'telemetry_error' not in completed,
                completed['name']+': cleanup or telemetry incomplete')


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
        nonlocal retained_stage_bytes
        require(remote.startswith('/work/') and '..' not in PurePosixPath(remote).parts, 'unadmitted export path')
        row = dock(name+'-identity', ['exec', active['id'], '/bin/sh', '-c',
            'test -f "$1" && test ! -L "$1" && stat -c %s "$1" && sha256sum "$1"', 'identity', remote])
        lines = row['stdout'].splitlines()
        require(len(lines) == 2 and lines[0].isdigit(), 'bad export identity')
        size = int(lines[0]); expected = lines[1].split('  ')
        require(size <= cap and len(expected) == 2 and expected[1] == remote and
                re.fullmatch('[0-9a-f]{64}', expected[0]), 'export size/hash refused')
        require(retained_stage_bytes+size <= 32*MIB, 'retained stage aggregate exceeds bound')
        retained_stage_bytes += size
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
            for field, remote, cap in [('stdout', remote_out, MIB), ('stderr', remote_err, MIB)]:
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
        allowed_diagnostic_exit = (expected_exit is None and name == 'public-cli-human-apply' and
            type(item['exit']) is int and 0 <= item['exit'] <= 255)
        require(allowed_diagnostic_exit or (expected_exit is not None and item['exit'] == expected_exit),
                tag+': stage failed; no retry')
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


    def artifact_admission():
        run = json.loads(success('original-run-api', [gh, 'api',
            'repos/sheeki03/tirith/actions/runs/'+str(original['original_run'])])['stdout'])
        require(run['id'] == original['original_run'] and run['head_sha'] == original['original_controller'] and
                run['run_attempt'] == 1 and run['status'] == 'completed' and run['conclusion'] == 'failure',
                'original run identity differs')
        item = json.loads(success('original-artifact-api', [gh, 'api',
            'repos/sheeki03/tirith/actions/artifacts/'+str(original['artifact']['id'])])['stdout'])
        for key in ['id', 'name', 'size_in_bytes', 'digest', 'created_at', 'expires_at']:
            require(item[key] == original['artifact'][key], 'original artifact metadata differs: '+key)
        require(not item['expired'] and item['workflow_run']['id'] == original['original_run'] and
                item['workflow_run']['head_sha'] == original['original_controller'], 'artifact expired or identity changed')
        expiration = datetime.datetime.fromisoformat(item['expires_at'].replace('Z', '+00:00')).timestamp()
        require(expiration-time.time() >= 3000, 'artifact expiration too close for bounded transfer')
        require(0 <= time.time()-original['build_timestamp'] <= 604800-3000, 'original signed feed freshness inadequate')
        require(shutil.disk_usage(staging).free >= 5*GIB+original['zip_size']+400*MIB,
                'download plus one selected extraction would cross disk reserve')
        row = success('artifact-download-command', [sys.executable, '-B', __file__, *sys.argv[1:], '--download-child'], 300)
        require(archive_path.stat().st_size == original['zip_size'] and sha(archive_path) == original['zip_sha256'],
                'downloaded original artifact differs')
        expected = {entry['path']: entry for entry in original['files']}
        require(len(expected) == len(original['files']) == 2427, 'original inventory differs')
        source_rows = {row['path']: row for row in manifest['files']}
        selected = {
            'run/fixture-retained-executables/launcher.elf': ('launcher.elf', 0o555),
            'run/fixture-retained-executables/libtest.elf': ('libtest.elf', 0o555),
            'run/fixture-signing.pub': ('fixture-signing.pub', 0o444),
            'run/fixture-threatdb-v2.dat': ('fixture-threatdb-v2.dat', 0o444),
        }
        seen = set()
        deadline = min(outer_deadline, time.monotonic()+180)
        source.mkdir(mode=0o755)
        with zipfile.ZipFile(archive_path) as archive:
            require(len(archive.infolist()) <= 5000, 'ZIP inventory exceeds bound')
            for member in archive.infolist():
                name = member.filename
                path = PurePosixPath(name)
                require(name and not path.is_absolute() and '..' not in path.parts and '\\' not in name and
                        name.casefold() not in seen and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG),
                        'ZIP path or file type refused')
                seen.add(name.casefold())
                require(name in expected and member.file_size == expected[name]['size'] and member.file_size <= 512*MIB,
                        'ZIP member differs from authenticated inventory')
                destination = None
                mode = 0o644
                if name in selected:
                    relative, mode = selected[name]
                    destination = staging/relative
                elif name.startswith('run/fixture-source/'):
                    relative = name.removeprefix('run/fixture-source/')
                    require(relative in source_rows, 'unexpected fixture source member')
                    wanted = dict(source_rows[relative])
                    if relative == KEY_PATH:
                        wanted['sha256'] = original['fixture_public_key_sha256']
                    require(expected[name]['sha256'] == wanted['sha256'] and member.file_size == wanted['size'],
                            'fixture source is not the exact original plus sole public key delta')
                    destination = source/relative
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                target = destination.open('xb') if destination is not None else None
                digest = hashlib.sha256()
                count = 0
                try:
                    with archive.open(member) as stream:
                        while chunk := stream.read(65536):
                            require(time.monotonic() < deadline, 'ZIP validation deadline exceeded')
                            count += len(chunk)
                            require(count <= member.file_size, 'ZIP member exceeded size')
                            digest.update(chunk)
                            if target is not None:
                                target.write(chunk)
                finally:
                    if target is not None:
                        target.close()
                require(count == member.file_size and digest.hexdigest() == expected[name]['sha256'], 'ZIP member hash mismatch')
                if destination is not None:
                    destination.chmod(mode)
                    info = destination.lstat()
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'staged file type/links refused')
                    staged.append({'path': str(destination), 'member': name, 'size': info.st_size,
                        'sha256': digest.hexdigest(), 'mode': mode,
                        'generation': [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]})
            require(seen == {name.casefold() for name in expected}, 'ZIP members missing')
            raw = archive.read('run/report.json')
            require(hashlib.sha256(raw).hexdigest() == original['report_sha256'], 'original report changed')
            previous = json.loads(raw)
            for key, value in original['original_report_acceptance'].items():
                require(previous[key] == value, 'original accepted field differs: '+key)
            require(len(previous['containers']) == 4 and all(all(c['cleanup'].values()) for c in previous['containers']) and
                    all(all(c['cleanup'].values()) and c['failure'] is None for c in previous['owned_children']),
                    'original ownership cleanup incomplete')
            require(previous['phases'][0]['passed'] and previous['phases'][0]['input_postcheck_passed'] and
                    previous['phases'][0]['production_key_negative']['product_signature_rejected'] and
                    previous['phases'][1]['stages'][-1]['name'] == 'mechanics' and
                    previous['phases'][1]['stages'][-1]['exit'] == 101, 'original diagnostic evidence differs')
            (output/'original-report.json').write_bytes(raw)
        require(len(staged) == 664, 'selected source/public/ELF extraction count differs')
        for kind in ['launcher', 'libtest']:
            target = staging/(kind+'.elf')
            wanted = original['executables'][kind]
            require(target.stat().st_size == wanted['bytes'] and sha(target) == wanted['sha256'], 'selected ELF pin differs')
            with target.open('rb') as stream:
                header = stream.read(64)
            require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == 183, 'ELF target differs')
        require(sha(staging/'fixture-signing.pub') == original['fixture_public_key_sha256'] and
                sha(staging/'fixture-threatdb-v2.dat') == original['source_sha256'], 'public authority differs')
        report['original_artifact'] = item
        report['original_zip_sha256'] = sha(archive_path)
        report['original_inventory_stream_verified'] = len(expected)
        report['staged_inputs'] = staged



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
        apply_args = prefix+['pkg', 'install-npm', 'apply', operation, '--reviewed', reviewed]
        applied_item = stage(phase, 'public-cli-human-apply', apply_args, 120, expected_exit=None)
        phase['public_apply_observation'] = {
            'operation': operation, 'reviewed_sha256': reviewed,
            'exit': applied_item['exit'], 'stdout': applied_item['stdout'], 'stderr': applied_item['stderr'],
            'json_output': False, 'presentation': 'ForwardSanitized',
            'apply_invocations': 1, 'no_retry': True, 'full_seven_case_acceptance': False,
            'original_v7_discarded_output_recovered': False,
        }
        report['public_apply_observed'] = True
        # No further product command or case follows the one human-output apply.


        snapshot_script = "\nconst fs = require('fs'), path = require('path'), crypto = require('crypto');\nconst [root, operation] = process.argv.slice(1);\nfunction need(value, message) { if (!value) throw new Error(message); }\nneed(root === '/work/fixture/public-cli' && /^[0-9a-f-]{36}$/.test(operation), 'fixed snapshot scope');\nlet entries = 0, bytes = 0, managerLock = null;\nconst rows = [];\nfunction identity(st) {\n  return ['dev','ino','mode','uid','gid','nlink','size','mtimeNs','ctimeNs'].map(key => st[key].toString());\n}\nfunction visit(file, label, depth) {\n  need(++entries <= 256 && depth <= 16, 'snapshot entry/depth bound');\n  const before = fs.lstatSync(file, {bigint:true});\n  need(before.uid === 65534n && !before.isSymbolicLink(), 'snapshot ownership/link');\n  const row = {path:label, identity:identity(before)};\n  if (before.isDirectory()) {\n    row.kind = 'directory'; rows.push(row);\n    const names = fs.readdirSync(file).sort();\n    need(names.length <= 256-entries, 'snapshot directory bound');\n    for (const name of names) visit(path.join(file,name), label+'/'+name, depth+1);\n  } else {\n    need(before.isFile() && before.nlink === 1n && before.size <= 2097152n, 'snapshot regular-file bound');\n    bytes += Number(before.size); need(bytes <= 8388608, 'snapshot byte bound');\n    const fd = fs.openSync(file, fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);\n    try {\n      need(JSON.stringify(identity(fs.fstatSync(fd,{bigint:true}))) === JSON.stringify(row.identity), 'snapshot open changed');\n      const buffer = Buffer.alloc(Number(before.size)+1); let count=0;\n      while (count < buffer.length) { const n=fs.readSync(fd,buffer,count,buffer.length-count,null); if (!n) break; count+=n; }\n      need(count === Number(before.size), 'snapshot size changed'); const content=buffer.subarray(0,count);\n      row.kind='file'; row.sha256=crypto.createHash('sha256').update(content).digest('hex'); rows.push(row);\n      if (label === 'installed/node_modules/.package-lock.json') {\n        need(content.length <= 16384, 'manager lock bound');\n        managerLock = new TextDecoder('utf-8', {fatal:true}).decode(content);\n      }\n      need(JSON.stringify(identity(fs.fstatSync(fd,{bigint:true}))) === JSON.stringify(row.identity), 'snapshot held changed');\n    } finally { fs.closeSync(fd); }\n  }\n  need(JSON.stringify(identity(fs.lstatSync(file,{bigint:true}))) === JSON.stringify(row.identity), 'snapshot path changed');\n}\nconst absent=[];\nfunction optional(file,label) {\n try {fs.lstatSync(file);} catch(error) {if(error.code==='ENOENT'){absent.push(label);return;} throw error;}\n visit(file,label,0);\n}\noptional(root+'/installed','installed');\nconst journal='.tirith-install-journal-'+crypto.createHash('sha256').update(root+'/installed').digest('hex');\noptional(root+'/'+journal,'journal');\nfor (const kind of ['intent','started','finished']) {\n optional(root+'/state/tirith/npm-install-intents/'+operation+'.'+kind+'.json','records/'+kind);\n}\nconst result={control:'public_cli_diagnostic_snapshot',entries,bytes,rows,absent,manager_lock_utf8:managerLock};\nconst text=JSON.stringify(result); need(Buffer.byteLength(text)<=262144,'snapshot output bound');\nprocess.stdout.write(text+'\\n');\n"
        snapshot_item = stage(phase, 'public-cli-state-snapshot', ['/usr/bin/env', '-i',
            'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/local/bin/node', '-e', snapshot_script, case, operation], 30)
        snapshot = exact_json(snapshot_item, 256*1024)
        require(snapshot.get('control') == 'public_cli_diagnostic_snapshot' and
                type(snapshot.get('rows')) is list and type(snapshot.get('absent')) is list and
                len(snapshot['rows']) == snapshot.get('entries'), 'bounded diagnostic snapshot shape differs')
        phase['public_state_snapshot'] = snapshot
        phase['public_state_snapshot_sha256'] = snapshot_item['stdout']['sha256']


    try:
        product_identity('initial')
        controller = success('controller-head', [git, '--no-optional-locks', '-C', base.parents[1], 'rev-parse', 'HEAD'])['stdout'].strip()
        require(controller == os.environ.get('GITHUB_SHA') and re.fullmatch('[0-9a-f]{40}', controller), 'controller revision mismatch')
        report['controller_commit'] = controller
        admit('before-artifact', 6*GIB)
        artifact_admission()
        frozen = capture.scan_source(source)
        wanted = dict(before)
        wanted['root'] = str(source)
        wanted['files'] = [dict(row) for row in before['files']]
        for row in wanted['files']:
            if row['path'] == KEY_PATH:
                row['sha256'] = original['fixture_public_key_sha256']
        require(frozen == wanted, 'staged fixture source exceeds sole-key variant')
        require(sha(source/KEY_PATH) != KEY_SHA, 'fixture key equals production key')
        dock('node-image-pull-command', ['pull', '--platform', 'linux/arm64', NODE_IMAGE], 300)
        image_rows = json.loads(dock('node-image-inspect', ['image', 'inspect', NODE_IMAGE])['stdout'])
        require(len(image_rows) == 1 and image_rows[0]['Os'] == 'linux' and image_rows[0]['Architecture'] == 'arm64' and
                image_rows[0]['Size'] <= 4*GIB, 'pinned runtime image differs')
        report['image'] = {'digest': NODE_IMAGE, 'id': image_rows[0]['Id'], 'size': image_rows[0]['Size']}
        server = json.loads(dock('docker-server', ['version', '--format', '{{json .Server}}'])['stdout'])
        require(server['Os'] == 'linux' and server['Arch'] == 'arm64', 'native Docker server required')
        admit('before-runtime', 5*GIB)
        remaining = min(1200, int(outer_deadline-time.monotonic()))
        require(remaining >= 900, 'insufficient admitted runtime envelope')
        phase_deadline = time.monotonic()+remaining
        launcher_path, test_path = '/compiled/launcher', '/compiled/libtest'
        launcher_sha = original['executables']['launcher']['sha256']
        test_sha = original['executables']['libtest']['sha256']
        public = {key: original[key] for key in ['fixture_public_key_sha256', 'source_sha256', 'build_sequence']}
        phase['executables'] = {'launcher': {'path': launcher_path, 'sha256': launcher_sha},
                                'libtest': {'path': test_path, 'sha256': test_sha}}
        mounts = ['--network', 'none', '--security-opt', 'seccomp=unconfined',
            '--tmpfs', '/work:rw,exec,nosuid,nodev,size=512m,mode=1777',
            '--tmpfs', '/nonexistent:ro,noexec,nosuid,nodev,size=1m,uid=65534,gid=65534,mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
            '--mount', 'type=bind,src='+str(staging/'launcher.elf')+',dst='+launcher_path+',readonly',
            '--mount', 'type=bind,src='+str(staging/'libtest.elf')+',dst='+test_path+',readonly',
            '--mount', 'type=bind,src='+str(source)+',dst=/source,readonly',
            '--mount', 'type=bind,src='+str(staging/'fixture-signing.pub')+',dst=/fixture-signing.pub,readonly',
            '--mount', 'type=bind,src='+str(staging/'fixture-threatdb-v2.dat')+',dst=/fixture-threatdb-v2.dat,readonly',
            '--env', 'HOME=/work/home', '--workdir', '/source']
        create('diagnostic-runtime', NODE_IMAGE, mounts, remaining+60)
        dock('runtime-start', ['start', active['id']])
        active['deadline'] = phase_deadline
        observed = inspect('runtime-isolation-inspect')
        require(observed['HostConfig']['NetworkMode'] == 'none' and
                all(network == 'none' for network in observed['NetworkSettings']['Networks']) and
                'seccomp=unconfined' in observed['HostConfig']['SecurityOpt'], 'runtime network/seccomp differs')
        require(observed['HostConfig']['Tmpfs'] == {
            '/work': 'rw,exec,nosuid,nodev,size=512m,mode=1777',
            '/tmp': 'rw,nosuid,nodev,size=512m,mode=1777',
            '/nonexistent': 'ro,noexec,nosuid,nodev,size=1m,uid=65534,gid=65534,mode=0700'}, 'tmpfs settings differ')
        require(all(any(m['Destination'] == path and not m['RW'] for m in observed['Mounts'])
                    for path in ['/compiled/launcher', '/compiled/libtest', '/source', '/fixture-signing.pub', '/fixture-threatdb-v2.dat']),
                'runtime public input mounts are not read-only')


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
process.stdout.write(JSON.stringify({control:'authenticated_account_home_observation',passwd_sha256:passwdSha,account_entry:entry[0],uid:account.uid,gid:account.gid,home:account.homedir,mode:'0700',tmpfs_size_bytes:String(stats.bsize*stats.blocks),mountinfo:mounts,empty:true})+'\n');
need(mounts.length===1,'account home mount missing or duplicated');
const halves=mounts[0].split(' - '), left=halves[0].split(' '), right=halves[1].split(' '), options=left[5].split(',');
// Mountinfo field6 carries per-mount read-only; field11 describes the separate superblock.
need(['ro','nosuid','nodev','noexec'].every(value=>options.includes(value))&&right[0]==='tmpfs','account home mount restrictions differ');
const probe='/nonexistent/.tirith-native-readonly-probe';let fd,opened=false,errno=null;
try{fd=fs.openSync(probe,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);opened=true;}
catch(error){errno=error.code;}
finally{if(fd!==undefined)fs.closeSync(fd);}
process.stdout.write(JSON.stringify({control:'authenticated_account_home_readonly_probe',path:probe,opened,errno,flags:['O_WRONLY','O_CREAT','O_EXCL','O_NOFOLLOW']})+'\n');
need(!opened&&errno==='EROFS','account home exclusive create did not refuse with EROFS');
process.stdout.write(JSON.stringify({control:'authenticated_account_home',passwd_sha256:passwdSha,account_entry:entry[0],uid:account.uid,gid:account.gid,home:account.homedir,canonical_home:fs.realpathSync(account.homedir),mode:'0700',tmpfs_size_bytes:String(stats.bsize*stats.blocks),mountinfo:mounts[0],superblock_options:right[2].split(','),exclusive_create_errno:errno,empty:true,read_only:true,noexec:true,nosuid:true,nodev:true})+'\n');
'''
        account_home = stage(phase, 'authenticated-account-home', ['/usr/bin/env', '-i',
            'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/local/bin/node', '-e', account_home_script], 30)
        account_rows = records(account_home, 'authenticated_account_home')
        require(len(account_rows) == 1 and account_rows[0]['home'] == '/nonexistent' and
                account_rows[0]['read_only'] is True and account_rows[0]['empty'] is True and
                account_rows[0]['exclusive_create_errno'] == 'EROFS',
                'authenticated account home admission missing')
        phase['authenticated_account_home'] = account_rows[0]

        kernel_probe = stage(phase, 'private-exec-kernel-policy', ['/usr/local/bin/node', '-e', r'''
const fs=require('fs');
function read(path){const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const b=Buffer.alloc(4097);const n=fs.readSync(fd,b,0,b.length,null);if(n>4096)throw Error('bounded kernel fact exceeds cap');return b.subarray(0,n).toString('utf8');}finally{fs.closeSync(fd);}}
const row={control:'private_exec_kernel_policy',suid_dumpable:read('/proc/sys/fs/suid_dumpable'),memfd_noexec:read('/proc/sys/vm/memfd_noexec'),kernel:read('/proc/sys/kernel/osrelease'),status:read('/proc/self/status'),limits:read('/proc/self/limits')};
process.stdout.write(JSON.stringify(row)+'\n');
if(!['0','0\n','2','2\n'].includes(row.suid_dumpable))throw Error('execute-only protected mode unavailable');
'''], 30)
        policy_rows = records(kernel_probe, 'private_exec_kernel_policy')
        require(len(policy_rows) == 1 and policy_rows[0]['suid_dumpable'] in ('0', '0\n', '2', '2\n'),
                'protected exec kernel policy admission missing')
        phase['private_exec_kernel_policy'] = policy_rows[0]

        loader = stage(phase, 'runtime-loader-admission', ['/bin/sh', '-c',
            'set -eu; sha256sum "$1" "$2"; ldd "$1"; ldd "$2"; "$1" --version; "$2" --list',
            'runtime-loader', launcher_path, test_path], 60)
        loader_text = Path(loader['stdout']['path']).read_text()
        require(loader_text.splitlines()[:2] == [launcher_sha+'  '+launcher_path, test_sha+'  '+test_path] and 'not found' not in loader_text and
                'fixture_signed_v2_is_refused_by_normal_product_preparation: test' in loader_text and
                'fixture_authority_native_first_coordinator_case: test' in loader_text and
                'exec_dump_policy_admits_only_kernel_protected_modes: test' in loader_text and
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



        selection = 'cli::npm_install_transaction::native_tests::native::provision_native_transaction_fixture_cases'
        require(loader_text.splitlines().count(selection+': test') == 1, 'exact fixture provisioner registration differs')
        env = {'TIRITH_NPM_NATIVE_FIXTURE_ROOT': '/work/fixture',
               'TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_PATH': '/fixture-signing.pub',
               'TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_SHA256': public['fixture_public_key_sha256'],
               'TIRITH_NPM_NATIVE_THREATDB': '/fixture-threatdb-v2.dat',
               'TIRITH_NPM_NATIVE_THREATDB_SHA256': public['source_sha256']}
        provision = stage(phase, 'case-provision', ['/usr/bin/env', *[key+'='+value for key,value in env.items()],
            test_path, selection, '--exact', '--ignored', '--test-threads=1', '--nocapture'], 300, 1)
        controls = records(provision, 'fixture_authority_case_provisioning')
        require(len(controls) == 1, 'exact fixture provision result missing')
        generated = controls[0]
        require(generated['source_sha256'] == public['source_sha256'] and
                generated['fixture_public_key_sha256'] == public['fixture_public_key_sha256'] and
                generated['build_sequence'] == public['build_sequence'] and generated['feed_resigned_or_refreshed'] is False and
                generated['production_feed_evidence'] is False and generated['secrets_written_only_under_fixture_root'] is True and
                re.fullmatch('[0-9a-f]{64}', generated['audit_public_sha256']), 'provisioned authority differs')
        phase['fixture_provisioning'] = generated
        public_cli_case(phase, launcher_path, launcher_sha, public, generated)
        require(phase['public_apply_observation']['exit'] in (0, 1), 'public apply returned an unexpected exit')
    except BaseException as error:
        report['error'] = str(error)
    finally:
        # A diagnostic apply failure (ordinary exit1) is retained without retry.
        # All other errors preserve their first reason while final checks run.
        if active is not None and active.get('id') and 'launcher_sha' in locals():
            try:
                post = stage(phase, 'input-postcheck', ['/bin/sh', '-c',
                    'set -eu; sha256sum /compiled/launcher /compiled/libtest /work/launcher/tirith '
                    '/fixture-signing.pub /fixture-threatdb-v2.dat /work/fixture/fixture-signing.pub '
                    '/work/fixture/fixture-threatdb-v2.dat /source/'+KEY_PATH], 30)
                observed_hashes = [line.split('  ')[0] for line in Path(post['stdout']['path']).read_text().splitlines()]
                require(observed_hashes == [launcher_sha, test_sha, launcher_sha, original['fixture_public_key_sha256'],
                    original['source_sha256'], original['fixture_public_key_sha256'], original['source_sha256'],
                    original['fixture_public_key_sha256']], 'runtime public inputs changed')
                report['runtime_input_postcheck_passed'] = True
            except BaseException as error:
                report['runtime_input_postcheck_error'] = str(error)
        cleaning = True
        cleanup_deadline = time.monotonic()+60
        try:
            cleanup()
        except BaseException as error:
            report['cleanup_error'] = str(error)
        try:
            product_identity('final')
            require(capture.scan_source(repo) == before, 'original product source changed')
            require(frozen is None or capture.scan_source(source) == frozen, 'staged fixture source changed')
            for row in staged:
                path = Path(row['path'])
                info = path.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                        [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns] == row['generation'] and
                        stat.S_IMODE(info.st_mode) == row['mode'] and sha(path) == row['sha256'], 'staged input changed')
            require(not archive_path.exists() or sha(archive_path) == original['zip_sha256'], 'original ZIP changed')
            actual = {'driver': sha(__file__), 'manifest': sha(manifest_path), 'runtime_inputs': sha(runtime_path),
                      'helper': sha(helper_path), 'capture': sha(capture_path), 'docker': sha(docker),
                      'git': sha(git), 'gh': sha(gh), 'python': capture.interpreter_identity()}
            require(actual == inputs, 'controller tooling changed')
            report['final_input_postchecks_passed'] = True
        except BaseException as error:
            report['input_error'] = str(error)
        report['diagnostic_completed'] = (report.get('public_apply_observed') is True and report['error'] is None and
            report.get('runtime_input_postcheck_passed') is True and report.get('final_input_postchecks_passed') is True and
            'cleanup_error' not in report and 'input_error' not in report and len(report['containers']) == 1 and
            all(all(c['cleanup'].values()) and 'telemetry_error' not in c for c in report['containers']))
        report['npm_installation_acceptance_claimed'] = False
        report['work_children'] = work_children
        report['cleanup_children'] = cleanup_children
        report['retained_stage_bytes'] = retained_stage_bytes
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'diagnostic_completed': report['diagnostic_completed'], 'error': report['error'],
            'apply_exit': phase.get('public_apply_observation', {}).get('exit'), 'report': str(output/'report.json')}))
    return 0 if report['diagnostic_completed'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        if PENDING_OUTPUT is not None:
            (PENDING_OUTPUT/'preflight-refusal.json').write_text(json.dumps({'diagnostic_completed': False, 'error': str(error)}, indent=2)+'\n')
        raise
