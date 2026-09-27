#!/usr/bin/env python3
"""Qualify the remaining controls from frozen source in one owned ARM64 container.

Core-only typecheck and test controls precede the required signed-v1 CLI test;
strict Clippy covers both packages and all targets. No native npm launch or
installation. Source inputs and container/CLI ownership facts remain separate.
"""
import argparse
import datetime
import platform
import shutil
import tomllib
import urllib.parse
import urllib.request
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import uuid

REPO = None
HELPER = None
HELPER_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
CAPTURE = None
CAPTURE_SHA = 'd398b167eac3a672aa5996fe93c0a8ba47ab571c6dd747f777fafe02b43fac80'
IMAGE = 'rust@sha256:3ebe98baef5911f8461cf81ba05644374a3c5ef1f8a33db3977bd4175f5ff1fc'
SOURCE_DB = None
SOURCE_DB_SHA = '47b867e2b686ce68d38402622fcd27fc54854115743b860a8bc1799c8db48112'
DOCKER = None
GIT = None
OPENSSL = None
PENDING_OUTPUT = None
LABEL = 'tirith.wp26.native-cargo-check'


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



SOURCE_COMMIT = 'e282d038519848caa8328cf32aa05a05daa502d2'
SOURCE_TREE = '71c7f346aefa9de9044c3b358252ab0cfc03dae1'
ASSET_ID = 592645616
ASSET_SIZE = 11977934
ASSET_NAME = 'tirith-threatdb-36311057301-1.dat'
ASSET_API = 'https://api.github.com/repos/sheeki03/tirith/releases/assets/592645616'
ASSET_URL = 'https://github.com/sheeki03/tirith/releases/download/threatdb-current/tirith-threatdb-36311057301-1.dat'
KEY_SHA = 'ee65a4cf011b55b19a8bbc6cc64d6b46dbcc5a2e35a690f8cf6f511f6d993db9'
GIB = 1024 ** 3

class PublicHttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname in
                ('api.github.com', 'github.com', 'release-assets.githubusercontent.com',
                 'objects.githubusercontent.com'), 'unexpected public feed redirect authority')
        return super().redirect_request(request, fp, code, message, headers, url)

def download_feed(output):
    deadline = time.monotonic() + 240
    receipts = []
    opener = urllib.request.build_opener(PublicHttpsRedirect())
    def fetch(url, name, cap, accept):
        request = urllib.request.Request(url, headers={'Accept': accept,
            'User-Agent': 'tirith-native-arm-qualification', 'X-GitHub-Api-Version': '2022-11-28'})
        require(time.monotonic() < deadline, 'feed download deadline expired')
        target = output / name
        count = 0
        with opener.open(request, timeout=min(20, deadline-time.monotonic())) as response:
            require(response.status == 200, 'public feed HTTP status refused')
            announced = response.headers.get('Content-Length')
            require(announced is None or (announced.isdecimal() and int(announced) <= cap),
                    'public feed response exceeds size cap')
            with target.open('xb') as stream:
                while True:
                    require(time.monotonic() < deadline, 'feed download deadline expired')
                    part = response.read(min(65536, cap + 1 - count))
                    if not part:
                        break
                    count += len(part)
                    require(count <= cap, 'public feed response exceeded size cap')
                    stream.write(part)
            target.chmod(0o600)
            receipts.append({'request_url': url, 'path': name, 'size': count, 'sha256': sha(target),
                'final_host': urllib.parse.urlsplit(response.url).hostname})
        return target
    def identity(value):
        require(value['id'] == ASSET_ID and value['name'] == ASSET_NAME and
                value['size'] == ASSET_SIZE and value['digest'] == 'sha256:' + SOURCE_DB_SHA and
                value['browser_download_url'] == ASSET_URL,
                'immutable public asset metadata differs from reviewed identity')
    try:
        metadata = fetch(ASSET_API, 'feed-asset-metadata.json', 1024*1024, 'application/vnd.github+json')
        identity(json.loads(metadata.read_text()))
        response = fetch(ASSET_API, 'feed-asset-response', ASSET_SIZE, 'application/octet-stream')
        if sha(response) == SOURCE_DB_SHA and response.stat().st_size == ASSET_SIZE:
            with (output / 'published-threatdb.dat').open('xb') as stream:
                stream.write(response.read_bytes())
            (output / 'published-threatdb.dat').chmod(0o600)
        else:
            require(response.stat().st_size <= 1024*1024, 'immutable asset bytes changed')
            try:
                identity(json.loads(response.read_text()))
            except (ValueError, UnicodeError, KeyError, TypeError) as error:
                raise RuntimeError('immutable asset response is neither reviewed bytes nor matching metadata') from error
            # Some anonymous API requests return metadata despite the octet-stream
            # header. The recorded browser URL is allowed only after exact asset
            # identity checks, and its bytes must match the immutable SHA below.
            fetch(ASSET_URL, 'published-threatdb.dat', ASSET_SIZE, 'application/octet-stream')
        require((output/'published-threatdb.dat').stat().st_size == ASSET_SIZE and
                sha(output/'published-threatdb.dat') == SOURCE_DB_SHA, 'public feed bytes changed')
        # Public bytes must be readable by the isolated UID through the read-only
        # file mount. The containing evidence directory remains host-private.
        (output/'published-threatdb.dat').chmod(0o644)
    finally:
        (output/'feed-download-report.json').write_text(json.dumps({
            'immutable_asset_id': ASSET_ID, 'expected_size': ASSET_SIZE,
            'expected_sha256': SOURCE_DB_SHA, 'retrievals': receipts}, indent=2)+'\n')

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
    global REPO, HELPER, CAPTURE, SOURCE_DB, DOCKER, GIT, OPENSSL, PENDING_OUTPUT
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--driver-sha256', required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    PENDING_OUTPUT = output
    base = Path(__file__).resolve().parent
    manifest_path = base/'manifest.json'
    require(re.fullmatch(r'[0-9a-f]{64}', args.driver_sha256) and
            sha(Path(__file__)) == args.driver_sha256, 'controller driver pin changed')
    require(re.fullmatch(r'[0-9a-f]{64}', args.manifest_sha256) and
            sha(manifest_path) == args.manifest_sha256, 'candidate manifest changed')
    manifest = json.loads(manifest_path.read_text())
    require(manifest['product_commit'] == SOURCE_COMMIT and manifest['product_tree'] == SOURCE_TREE,
            'product source identity differs from reviewed manifest')
    require(manifest['published_source_sha256'] == SOURCE_DB_SHA, 'public source pin differs')
    require(sha(base/'candidate.patch') == manifest['patch_sha256'], 'candidate patch changed')
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64', 'native ARM Linux host required')
    REPO = args.source_root.resolve(strict=True)
    HELPER = REPO/'tools/qualification/mixed_audit_native.py'
    CAPTURE = REPO/'tools/qualification/signed_replacement_inputs.py'
    executables = [shutil.which(name) for name in ('docker', 'git', 'openssl')]
    require(all(executables), 'required host tools unavailable')
    DOCKER, GIT, OPENSSL = [Path(path).resolve(strict=True) for path in executables]
    capture = load(CAPTURE, CAPTURE_SHA, 'npm_build_capture')
    native = load(HELPER, HELPER_SHA, 'npm_build_owner')
    before = capture.scan_source(REPO)
    require(before['files'] == manifest['files'] and
            before['optional_absent'] == manifest['source_optional_absent'], 'source closure differs from reviewed manifest')
    lock = tomllib.loads((REPO/'Cargo.lock').read_text())
    external = [item for item in lock['package'] if 'source' in item]
    require(all(item['source'] == 'registry+https://github.com/rust-lang/crates.io-index' and
                re.fullmatch(r'[0-9a-f]{64}', item.get('checksum', '')) for item in external),
            'Cargo.lock contains unadmitted dependency sources')
    (output/'dependency-admission.json').write_text(json.dumps({'cargo_lock_sha256': sha(REPO/'Cargo.lock'),
        'package_count': len(lock['package']), 'public_registry_package_count': len(external)}, indent=2)+'\n')
    download_feed(output)
    SOURCE_DB = output/'published-threatdb.dat'
    source = output / 'source'
    source.mkdir(mode=0o755)
    for row in before['files']:
        path = source / row['path']
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with capture.HeldFile(REPO / row['path'], 64 * capture.MIB, allow_empty=True) as held:
            require(held.identity == {'sha256': row['sha256'], 'size': row['size']}, 'source changed before copy')
            with path.open('xb') as target:
                for part in held.chunks():
                    target.write(part)
            path.chmod(0o755 if held.token[2] & 0o111 else 0o644)
            held.revalidate()
    require(capture.scan_source(REPO) == before, 'live source changed during capture')
    # No overlay: this diagnostic must compile the integrated coordinator,
    # intent store and native launcher from one captured live source closure.
    # The frozen native manifest still proves its reviewed bytes were included.
    for row in manifest['files']:
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'invalid native path')
        require(sha(source / relative) == row['sha256'], 'integrated native source differs from reviewed bytes')
    frozen = capture.scan_source(source)
    (output / 'integrated-source-before.json').write_text(json.dumps(before, indent=2) + '\n')
    (output / 'source-inputs.json').write_text(json.dumps(frozen, indent=2) + '\n')
    inputs = {'manifest': sha(manifest_path), 'driver': sha(Path(__file__)),
              'capture': sha(CAPTURE), 'helper': sha(HELPER), 'docker': sha(DOCKER),
              'python': capture.interpreter_identity(), 'source_db': sha(SOURCE_DB),
              'git': sha(GIT), 'openssl': sha(OPENSSL), 'patch': sha(base/'candidate.patch')}
    run_id = str(uuid.uuid4())
    cidfile = output / 'container.cid'
    report = {'classification': 'isolated_ci_native_arm64_remaining_controls', 'run_id': run_id,
              'image': IMAGE, 'source_scope': 'integrated live source captured without overlay; includes coordinator and intent modules', 'inputs': inputs, 'source_manifest_sha256': sha(output / 'source-inputs.json'),
              'owned_children': [], 'container_id': None, 'error': None,
              'container_cleanup': {'identity_verified': False, 'removed': False, 'absence_observed': False},
              'product_execution': False, 'tests_executed': False, 'msrv_qualified': False, 'reproducible_build_attested': False,
              'native_enforcement_qualified': False,
              'dependency_scope': 'Cargo.lock validated public fetch; compiler dependency closure is not independently attested'}
    container_id = None

    def run_command(name, arguments, timeout=15):
        job = native.Job(name, list(map(str, arguments)), output, os.environ.copy(), timeout=timeout)
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
            if errors:
                row['wrapper_cleanup_errors'] = errors
            report['owned_children'].append(row)
            (output / (name + '.stdout')).write_text(row['stdout'])
            (output / (name + '.stderr')).write_text(row['stderr'])
            require(not errors, name + ': wrapper cleanup failed')
        require(row['failure'] is None and all(row['cleanup'].values()), name + ': CLI cleanup incomplete')
        return row

    def run(name, arguments, timeout=15):
        return run_command(name, [str(DOCKER), *arguments], timeout)

    def command_success(name, arguments, timeout=15):
        row = run_command(name, arguments, timeout)
        require(row['exit'] == 0, name + ': owned command failed')
        return row

    def success(name, arguments, timeout=15):
        row = run(name, arguments, timeout)
        require(row['exit'] == 0, name + ': Docker command failed')
        return row

    def retain_id():
        nonlocal container_id
        if container_id is None and cidfile.exists():
            st = cidfile.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 128, 'invalid CID file')
            value = cidfile.read_text().strip()
            require(re.fullmatch(r'[0-9a-f]{64}', value), 'invalid created CID')
            container_id = value
            report['container_id'] = value

    def inspect(name):
        require(container_id is not None, 'missing owned CID')
        rows = json.loads(success(name, ['inspect', '--type', 'container', container_id])['stdout'])
        require(len(rows) == 1, 'ambiguous container identity')
        item = rows[0]
        require(item['Id'] == container_id and item['Config']['Image'] == IMAGE and
                item['Config']['Labels'].get(LABEL) == run_id, 'container identity/label mismatch')
        report['container_cleanup']['identity_verified'] = True
        return item

    def retain_log(name, cap):
        remote = '/work/' + name
        handoff_deadline = time.monotonic() + 120
        row = success(name + '-identity', ['exec', container_id, '/bin/sh', '-c',
            'test -f "$1" && test ! -L "$1" && stat -c %s "$1" && sha256sum "$1"', 'identity', remote])
        lines = row['stdout'].splitlines()
        require(len(lines) == 2 and lines[0].isdigit(), 'invalid build-log identity')
        size = int(lines[0]); expected = lines[1].split('  ')
        require(size <= cap and len(expected) == 2 and expected[1] == remote and
                re.fullmatch(r'[0-9a-f]{64}', expected[0]), 'build log exceeds bound')
        destination = output / name
        # Docker's archive endpoint does not export tmpfs. Every chunk stays
        # below the fixed helper's64KiB output cap, with a finite count derived
        # from the already-bounded log length. No unbounded shell pipeline data.
        require((size + 24575) // 24576 <= 683, 'too many diagnostic log chunks')
        with destination.open('xb') as stream:
            for index in range((size + 24575) // 24576):
                require(time.monotonic() < handoff_deadline, 'diagnostic log handoff deadline exceeded')
                copied = success(name + '-chunk-' + str(index), ['exec', container_id, '/bin/sh', '-c',
                    'dd if="$1" bs=24576 skip="$2" count=1 status=none | base64 -w0',
                    'copy-log', remote, str(index)])
                content = base64.b64decode(copied['stdout'], validate=True)
                require(len(content) == min(24576, size - index * 24576), 'incomplete diagnostic log chunk')
                stream.write(content)
        st = destination.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == size and
                sha(destination) == expected[0], 'build log changed during handoff')
        return {'path': str(destination), 'size': size, 'sha256': expected[0]}

    def observe_memory(name):
        # These cgroup files are kernel-generated counters, not user data. Each
        # read is capped independently; tmpfs compiler/cache pages count toward
        # the same unchanged container memory.max as the compiler process.
        observation = {'checkpoint': name, 'files': {}}
        report.setdefault('memory_observations', []).append(observation)
        for filename in ('memory.events', 'memory.peak', 'memory.max', 'memory.current', 'memory.stat'):
            row = run(name + '-' + filename.replace('.', '-'),
                ['exec', container_id, '/usr/bin/head', '-c', '4097', '/sys/fs/cgroup/' + filename])
            within_cap = len(row['stdout'].encode()) <= 4096
            observation['files'][filename] = {
                'available': row['exit'] == 0 and within_cap,
                'exit': row['exit'], 'within_4096_byte_cap': within_cap,
                'contents': row['stdout'] if within_cap else None,
            }
        observation['complete'] = all(value['available'] for value in observation['files'].values())

    def product_identity(stage):
        head = command_success(stage+'-product-head', [GIT, '--no-optional-locks', '-C', REPO, 'rev-parse', 'HEAD'])['stdout'].strip()
        tree = command_success(stage+'-product-tree', [GIT, '--no-optional-locks', '-C', REPO, 'rev-parse', 'HEAD^{tree}'])['stdout'].strip()
        status = command_success(stage+'-product-status', [GIT, '--no-optional-locks', '-C', REPO, 'status', '--porcelain=v1', '--untracked-files=all'])['stdout']
        require(head == SOURCE_COMMIT and tree == SOURCE_TREE and status == '', 'product checkout identity or cleanliness changed')
        report.setdefault('product_identities', []).append({'stage': stage, 'commit': head, 'tree': tree, 'clean': True})

    def admit_host(stage, minimum_disk):
        facts = {'stage': stage}
        report.setdefault('host_resources', []).append(facts)
        host_resources(output, facts)
        facts['docker_mem_total_bytes'] = int(success(stage+'-docker-memory', ['info', '--format', '{{json .MemTotal}}'])['stdout'])
        running = success(stage+'-docker-containers', ['ps', '--no-trunc', '--format', '{{.ID}}'])['stdout']
        require(running == '', 'isolated qualification requires no existing running containers')
        require(facts['effective_available_bytes'] >= 12*GIB and facts['docker_mem_total_bytes'] >= 12*GIB,
                'isolated host lacks 12 GiB effective available memory for the 10 GiB container')
        require(facts['disk_available_bytes'] >= minimum_disk, 'isolated host lacks required disk headroom')

    def verify_production_feed():
        raw = SOURCE_DB.read_bytes()
        key = (source/'crates/tirith-core/assets/keys/threatdb-verify.pub').read_bytes()
        require(len(key) == 32 and hashlib.sha256(key).hexdigest() == KEY_SHA, 'embedded production verification key changed')
        require(raw[:8] == b'TIRITHDB' and int.from_bytes(raw[8:12], 'little') == 1 and
                raw[76:108] == hashlib.sha256(key).digest(), 'production v1 header or signer fingerprint differs')
        files = {'production-key.der': bytes.fromhex('302a300506032b6570032100')+key,
                 'production-signature.bin': raw[108:172],
                 'production-signed-body.bin': raw[:108]+raw[172:]}
        for name, content in files.items():
            with (output/name).open('xb') as stream:
                stream.write(content)
            (output/name).chmod(0o600)
        command_success('openssl-version', [OPENSSL, 'version'])
        command_success('production-signature-check', [OPENSSL, 'pkeyutl', '-verify', '-pubin',
            '-inkey', output/'production-key.der', '-keyform', 'DER', '-rawin',
            '-in', output/'production-signed-body.bin', '-sigfile', output/'production-signature.bin'])
        report['production_feed'] = {'asset_id': ASSET_ID, 'sha256': sha(SOURCE_DB), 'size': len(raw),
            'format_version': 1, 'production_public_key_sha256': KEY_SHA,
            'independent_embedded_key_signature_verified': True,
            'verification_files': {name: {'sha256': sha(output/name), 'size': (output/name).stat().st_size} for name in files},
            'product_parser_refusal_test_separately_required': True}

    try:
        product_identity('initial')
        controller = command_success('controller-head', [GIT, '--no-optional-locks', '-C', base.parents[1], 'rev-parse', 'HEAD'])['stdout'].strip()
        require(re.fullmatch(r'[0-9a-f]{40}', controller) and controller == os.environ.get('GITHUB_SHA'),
                'controller checkout differs from the dispatched workflow commit')
        report['controller_commit'] = controller
        report['product_commit'] = SOURCE_COMMIT
        admit_host('before-image-pull', 10*GIB)
        verify_production_feed()
        success('image-pull', ['pull', '--platform', 'linux/arm64', IMAGE], timeout=300)
        admit_host('before-container-create', 8*GIB)
        image = json.loads(success('image-inspect', ['image', 'inspect', IMAGE])['stdout'])
        require(len(image) == 1 and image[0]['Os'] == 'linux' and image[0]['Architecture'] == 'arm64', 'pinned ARM compiler image unavailable')
        server = json.loads(success('server-version', ['version', '--format', '{{json .Server}}'])['stdout'])
        require(server['Os'] == 'linux' and server['Arch'] == 'arm64', 'native ARM Docker server required')
        created = run('create', ['create', '--name', 'tirith-npm-cargo-' + run_id, '--label', LABEL + '=' + run_id,
            '--cidfile', str(cidfile), '--init', '--user', '65534:65534', '--network', 'bridge', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
            '--memory', '10g', '--memory-swap', '10g', '--cpus', '2', '--tmpfs', '/work:rw,exec,nosuid,nodev,size=8g,mode=1777',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,mode=1777',
            '--mount', 'type=bind,src=' + str(source) + ',dst=/source,readonly',
            '--mount', 'type=bind,src=' + str(SOURCE_DB) + ',dst=/published-threatdb.dat,readonly',
            '--tmpfs', '/cargo:rw,nosuid,nodev,size=3g,mode=1777',
            '--env', 'CARGO_HOME=/cargo', '--env', 'CARGO_TARGET_DIR=/work/target',
            '--env', 'CARGO_BUILD_JOBS=1', '--env', 'CARGO_PROFILE_DEV_DEBUG=0',
            '--env', 'CARGO_PROFILE_TEST_DEBUG=0', '--env', 'CARGO_INCREMENTAL=0',
            '--env', 'HOME=/work/home', '--workdir', '/source', IMAGE, '/bin/sleep', '2400'])
        retain_id()
        require(created['exit'] == 0 and container_id is not None, 'container creation incomplete')
        initial = inspect('initial-inspect')
        require(not initial['State']['Running'], 'container started before ownership')
        config = initial['HostConfig']
        require(config['Memory'] == 10*GIB and config['MemorySwap'] == 10*GIB and
                config['NanoCpus'] == 2_000_000_000 and config['PidsLimit'] == 256 and
                config['ReadonlyRootfs'] and config['CapDrop'] == ['ALL'] and
                'no-new-privileges' in config['SecurityOpt'] and initial['Config']['User'] == '65534:65534',
                'created container isolation or resource settings differ from reviewed policy')
        success('start', ['start', container_id])
        success('toolchain', ['exec', container_id, '/bin/sh', '-c', 'rustc -vV && cargo -V'])
        fetched = run('cargo-fetch', ['exec', container_id, '/bin/sh', '-c',
            'mkdir -m 700 /work/home && cargo fetch --locked --target aarch64-unknown-linux-gnu > /work/fetch.stdout 2> /work/fetch.stderr'], timeout=300)
        report['fetch_stdout'] = retain_log('fetch.stdout', 8 * 1024 * 1024)
        report['fetch_stderr'] = retain_log('fetch.stderr', 8 * 1024 * 1024)
        require(fetched['exit'] == 0, 'locked public dependency fetch failed')
        inspect('pre-disconnect-inspect')
        success('disconnect-network', ['network', 'disconnect', 'bridge', container_id])
        require(inspect('offline-inspect')['NetworkSettings']['Networks'] == {}, 'compiler still has an attached Docker network')
        report['build_network_disconnected'] = True
        observe_memory('before-cargo-check')
        command = 'cargo check --locked --offline -p tirith-core --lib --tests --message-format=json > /work/cargo.jsonl 2> /work/cargo.stderr'
        result = run('cargo-check', ['exec', container_id, '/bin/sh', '-c', command], timeout=1800)
        report['cargo_exit'] = result['exit']
        report['cargo_json'] = retain_log('cargo.jsonl', 16 * 1024 * 1024)
        report['cargo_stderr'] = retain_log('cargo.stderr', 8 * 1024 * 1024)
        observe_memory('after-cargo-check')
        require(result['exit'] == 0, 'native ARM Cargo check failed; retained diagnostics')
        report['focused_tests'] = []
        controls = [
            ('nested-policy-capture-control', 'tirith-core', '--lib', 'nested_silent_capture_retains_dlp_without_forwarding_diagnostics', ''),
            ('npm-core-controls', 'tirith-core', '--lib', 'artifact::npm_install::', ''),
            ('actual-signed-v1-refusal', 'tirith', '--bin tirith', 'actual_published_v1_is_signed_but_refused_for_npm_install', '--ignored'),
        ]
        success('fixture-root', ['exec', container_id, '/bin/mkdir', '-m', '700', '/work/native-fixtures'])
        for name, package, target, selection, ignored in controls:
            # These fixed filters have no caller-provided shell fragments. The
            # only ignored test invoked is the actual signed-v1 refusal; no npm
            # executable runs and no success qualification is inferred.
            test_command = ('TIRITH_NPM_NATIVE_FIXTURE_ROOT=/work/native-fixtures '
                'TIRITH_NPM_NATIVE_THREATDB=/published-threatdb.dat '
                'cargo test --locked --offline -p ' + package + ' ' + target + ' ' + selection +
                ' -- --test-threads=1 --nocapture ' + ignored +
                ' > /work/' + name + '.stdout 2> /work/' + name + '.stderr')
            command_observation = {'name': name, 'invocation_attempted': True, 'docker_cli_returned': False,
                                   'exit': None, 'result_logs_retained': False}
            report.setdefault('test_commands', []).append(command_observation)
            # CLI transport transcripts and copied in-container test logs must
            # have distinct immutable names; neither may overwrite the other.
            tested = run(name + '-command', ['exec', container_id, '/bin/sh', '-c', test_command], timeout=1800)
            command_observation.update({'docker_cli_returned': True, 'exit': tested['exit']})
            stdout = retain_log(name + '.stdout', 8 * 1024 * 1024)
            stderr = retain_log(name + '.stderr', 8 * 1024 * 1024)
            command_observation['result_logs_retained'] = True
            text = Path(stdout['path']).read_text()
            passed = [int(n) for n in re.findall(r'test result: ok\. (\d+) passed; 0 failed;', text)]
            item = {'name': name, 'exit': tested['exit'], 'passed_tests': sum(passed),
                    'stdout': stdout, 'stderr': stderr}
            report['focused_tests'].append(item)
            report['tests_executed'] |= bool(re.search(r'(?m)^running [1-9][0-9]* tests?$', text))
            observe_memory('after-' + name)
            require(tested['exit'] == 0 and sum(passed) > 0, name + ': focused test failure or empty filter')
        clippy_version = run('clippy-version', ['exec', container_id, 'cargo', 'clippy', '--version'])
        report['clippy_component'] = {'available': clippy_version['exit'] == 0,
            'exit': clippy_version['exit'], 'stdout': clippy_version['stdout'], 'stderr': clippy_version['stderr']}
        require(clippy_version['exit'] == 0, 'pinned compiler image Clippy component unavailable; no lint pass claimed')
        checked = run('strict-clippy', ['exec', container_id, '/bin/sh', '-c',
            'cargo clippy --locked --offline -p tirith -p tirith-core --all-targets -- -D warnings > /work/clippy.stdout 2> /work/clippy.stderr'], timeout=900)
        report['clippy'] = {'exit': checked['exit'],
            'stdout': retain_log('clippy.stdout', 8 * 1024 * 1024),
            'stderr': retain_log('clippy.stderr', 8 * 1024 * 1024)}
        observe_memory('after-clippy')
        require(checked['exit'] == 0, 'strict native Clippy failed or pinned image lacks component; retained diagnostics')
    except BaseException as error:
        report['error'] = str(error)
    finally:
        try:
            retain_id()
            if container_id:
                cleanup_state = inspect('cleanup-inspect')
                if cleanup_state['State']['Running']:
                    try:
                        observe_memory('before-container-removal')
                    except BaseException as error:
                        # Telemetry failure must never skip exact owned cleanup.
                        report['cleanup_telemetry_error'] = str(error)
                row = success('remove', ['rm', '--force', container_id], timeout=30)
                require(row['stdout'].strip() == container_id, 'removal did not confirm exact CID')
                report['container_cleanup']['removed'] = True
                absent = success('absence', ['ps', '-a', '--no-trunc', '--filter', 'id=' + container_id, '--format', '{{.ID}}'])
                require(absent['stdout'] == '', 'owned container is still present')
                report['container_cleanup']['absence_observed'] = True
        except BaseException as error:
            report['cleanup_error'] = str(error)
        try:
            product_identity('final')
            require(capture.scan_source(REPO) == before, 'product source changed during qualification')
            require(capture.scan_source(source) == frozen, 'frozen source changed during compilation')
            require(sha(manifest_path) == inputs['manifest'] and sha(Path(__file__)) == inputs['driver'] and
                    sha(CAPTURE) == inputs['capture'] and sha(HELPER) == inputs['helper'] and sha(DOCKER) == inputs['docker'] and
                    sha(SOURCE_DB) == inputs['source_db'] and sha(base/'candidate.patch') == inputs['patch'] and sha(GIT) == inputs['git'] and sha(OPENSSL) == inputs['openssl'] and
                    capture.interpreter_identity() == inputs['python'], 'build tooling changed')
            for row in manifest['files']:
                require(sha(source / row['path']) == row['sha256'], 'reviewed native source changed during build')
            report['final_inputs_match'] = True
        except BaseException as error:
            report['input_error'] = str(error)
        report['passed'] = report['error'] is None and 'cleanup_error' not in report and 'cleanup_telemetry_error' not in report and 'input_error' not in report and all(report['container_cleanup'].values())
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'error': report['error'], 'report': str(output / 'report.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        status = main()
    except BaseException as error:
        failure = {'classification': 'controller_failure_without_complete_driver_report', 'error_type': type(error).__name__, 'error': str(error)}
        if PENDING_OUTPUT is not None:
            (PENDING_OUTPUT/'admission-error.json').write_text(json.dumps(failure, indent=2)+'\n')
        print(json.dumps(failure), file=sys.stderr)
        status = 1
    raise SystemExit(status)
