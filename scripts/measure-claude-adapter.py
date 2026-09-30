#!/usr/bin/env python3
"""Bounded actual Claude adapter characterization with explicit pinned inputs.

Four independent actual hosts; 24 allow and 24 block turn samples. Scripted
loopback provider only. No universal latency gate or cold-cache/daemon claim.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys
import time
import types

MIB = 1024 * 1024
SECONDS = 600
STORAGE_CAP = 256 * MIB
FREE_FLOOR = 64 * MIB
MAX_CHILDREN = 96
BATCHES = 4
MEASURED_PAIRS = 6
HARNESS_SHA = "bf719549ac06764d81030df808c30ad6e09ca15391d6d15f0806cc2ec6aeee91"
NATIVE_SHA = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
COMMANDS = {action: "printf '%s\\n' TIRITH_AGENT_" + action.upper() + "_MARKER >> execution-marker.txt" for action in ("allow", "block")}

def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def token(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def tree_inventory(root, hashes=False):
    """Bounded no-follow evidence tree; aliases are data, never input authority."""
    total, count, files, aliases = 0, 0, [], []
    for directory, names, leaves in os.walk(root, followlinks=False):
        for name in names + leaves:
            path = Path(directory) / name
            st = path.lstat()
            count += 1
            require(count <= 4096 and st.st_uid == os.getuid(), 'fixture inventory ownership/count differs')
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(path)
                require(len(os.fsencode(target)) <= 4096, 'fixture link text exceeds bound')
                aliases.append({'path': relative, 'target': target, 'followed': False})
                if name in names:
                    names.remove(name)
                continue
            require(st.st_mode & 0o022 == 0, 'fixture entry is writable by another identity')
            if stat.S_ISDIR(st.st_mode):
                continue
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 512 * MIB,
                    'fixture special/oversized/hardlinked file')
            total += st.st_size
            require(total <= STORAGE_CAP, 'fixture storage exceeds 256MiB')
            row = {'path': relative, 'size': st.st_size}
            if hashes:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    require(token(os.fstat(fd)) == token(st), 'inventory generation changed')
                    h, size = hashlib.sha256(), 0
                    while True:
                        part = os.read(fd, MIB)
                        if not part:
                            break
                        h.update(part)
                        size += len(part)
                        require(size <= st.st_size, 'inventory file grew')
                    require(size == st.st_size and token(os.fstat(fd)) == token(st) == token(path.lstat()),
                            'inventory bytes/generation changed')
                    row['sha256'] = h.hexdigest()
                finally:
                    os.close(fd)
            files.append(row)
    return {'entries': count, 'regular_file_bytes': total, 'ceiling_bytes': STORAGE_CAP,
            'files': sorted(files, key=lambda row: row['path']), 'symlinks_not_followed': aliases}


class Budget:
    def __init__(self, owned, started=None):
        self.start, self.owned, self.last_scan = time.monotonic() if started is None else started, owned, 0
        self.lowest_free, self.largest_tree = None, 0

    def remaining(self, cap):
        left = SECONDS - (time.monotonic() - self.start)
        require(left > 0, '600-second work deadline; no new work')
        return min(cap, left)

    def check(self, force=False):
        self.remaining(1)
        self.owned.revalidate()
        if force or time.monotonic() - self.last_scan >= 0.5:
            info = os.statvfs(self.owned.output)
            free = info.f_bavail * info.f_frsize
            require(free >= FREE_FLOOR, 'free disk below 64MiB reserve')
            self.lowest_free = free if self.lowest_free is None else min(free, self.lowest_free)
            current = tree_inventory(self.owned.output)
            self.largest_tree = max(self.largest_tree, current['regular_file_bytes'])
            self.last_scan = time.monotonic()


def classify_turn(events, before, after, facts, action, harness):
    hooks = harness.hook_count(events)
    common = (harness.successful_turn(events) and facts['tool_calls_issued'] == 1
              and facts['tool_result_observations'] >= 1 and facts['rejected_provider_requests'] == 0)
    marker_ok = after == (before + ['TIRITH_AGENT_ALLOW_MARKER'] if action == 'allow' else before)
    observed = common and hooks >= 2 and marker_ok
    return {'passed': observed, 'action': action, 'host_hook_events': hooks,
            'additional_marker_executions': len(after) - len(before),
            'classification': ('observed_hook_and_' + ('allowed_once' if action == 'allow' else 'blocked')) if observed else 'inconclusive_or_different_behavior',
            **facts}


def event_evidence(events):
    return {**identity(canonical(events)), 'count': len(events),
            'system_init_count': sum(event.get('type') == 'system' and event.get('subtype') == 'init' for event in events),
            'raw_source': 'matching owned child stdout log; consecutive records through this turn result'}


def marker_lines(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                and before.st_mode & 0o022 == 0 and before.st_size <= 4096, 'marker is not a bounded owned regular file')
        raw = os.read(fd, 4097)
        require(len(raw) == before.st_size and token(before) == token(os.fstat(fd)) == token(path.lstat()), 'marker changed while reading')
        return raw.decode('utf-8').splitlines()
    finally:
        os.close(fd)


def cleanup_all(entries):
    errors = []
    for label, child in reversed(entries):
        try:
            child.close()  # Idempotent; never resets ownership/closed flags.
            require(not child.cleanup_error and all(child.cleanup.values()), 'owned cleanup incomplete')
        except BaseException as error:
            errors.append({'name': label, 'error': type(error).__name__ + ': ' + str(error)[:1000]})
    return errors


def guarded_process_class(harness, budget):
    class GuardedProcess(harness.BoundedProcess):
        cleaning = False

        def pump(self, timeout=0.1):
            if not self.cleaning:
                budget.check()
                timeout = min(timeout, budget.remaining(timeout))
            answer = super().pump(timeout)
            if not self.cleaning:
                budget.check()
            return answer

        def close(self):
            self.cleaning = True
            return super().close()
    return GuardedProcess


class Runner:
    def __init__(self, harness, owned, budget):
        self.h, self.owned, self.budget, self.children = harness, owned, budget, []
        self.Process = guarded_process_class(harness, budget)

    def start(self, name, argv, env, interactive=False, cap=256 * 1024):
        self.budget.check(force=True)
        require(len(self.children) < MAX_CHILDREN, 'owned child count exceeds finite plan')
        child = self.Process(list(map(str, argv)), self.owned.root / 'workspace', env,
                             interactive=interactive, output_limit=cap)
        child.fixture_launch = {'argv': list(map(str, argv)), 'cwd': str(self.owned.root / 'workspace'),
                                'environment': dict(env), 'output_cap_bytes': cap}
        self.children.append((name, child))
        return child

    def pump(self, child, seconds):
        self.budget.check()
        child.pump(min(seconds, self.budget.remaining(seconds)))
        self.budget.check()

    def execute(self, name, argv, env, cap_seconds=45, expected=0):
        child = self.start(name, argv, env)
        until = time.monotonic() + self.budget.remaining(cap_seconds)
        try:
            while child.process.poll() is None:
                require(time.monotonic() < until, name + ' deadline')
                self.pump(child, min(0.05, max(0.001, until - time.monotonic())))
            code = child.process.poll()
        finally:
            child.close()
        self.budget.check(force=True)
        require(code == expected and child.failure is None and not child.cleanup_error
                and all(child.cleanup.values()), name + ' process outcome/cleanup differs')
        return bytes(child.stdout), bytes(child.stderr)

    def turn(self, child, message):
        # The unchanged send() has a fixed five-second pipe deadline; require
        # those five seconds to remain before entering it, then clamp reads.
        require(self.budget.remaining(5) == 5, 'too little case time for bounded host send')
        child.send(message)
        events = child.read_turn(timeout=self.budget.remaining(90))
        self.budget.check(force=True)
        return events

    def timed_turn(self, child, message):
        self.budget.check(force=True)
        require(self.budget.remaining(5) == 5, 'too little time for bounded host send')
        started = time.perf_counter_ns()
        child.send(message)
        events = child.read_turn(timeout=self.budget.remaining(90))
        elapsed = time.perf_counter_ns() - started
        self.budget.check(force=True)
        return events, elapsed

    def records(self):
        rows = []
        for index, (name, child) in enumerate(self.children):
            row = {'name': name, 'pid': child.process.pid, 'exit': child.process.returncode,
                   'failure': child.failure, 'cleanup': child.cleanup,
                   'cleanup_error': child.cleanup_error, 'group_observation': child.group_observation,
                   'launch': child.fixture_launch}
            for key in ('stdout', 'stderr'):
                raw = bytes(getattr(child, key))
                path = self.owned.output / (f'child-{index:02d}-' + key + '.log')
                with path.open('xb') as stream:
                    stream.write(raw)
                row[key] = {'path': path.name, **identity(raw)}
            rows.append(row)
        return rows


class Input:
    """A canonical no-follow generation, pinned before any native execution."""
    def __init__(self, path, expected=None, cap=512 * MIB, system_launcher=False):
        self.path, self.cap, self.fd = Path(path), cap, None
        require(self.path.is_absolute() and self.path.resolve(strict=True) == self.path,
                'input path must be absolute and canonical')
        before = self.path.lstat()
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(self.fd)
            # APFS system-volume Python may have multiple links. Only this
            # root-owned OS launcher, explicitly pinned by its CLI digest,
            # admits that exception; the full link count stays in its token.
            links = st.st_nlink == 1 or (system_launcher and self.path == Path('/usr/bin/python3')
                                        and st.st_uid == 0 and expected is not None)
            require(token(st) == token(before) and stat.S_ISREG(st.st_mode)
                    and st.st_uid in (0, os.getuid()) and st.st_mode & 0o022 == 0
                    and links and 0 < st.st_size <= cap, 'input ownership/type/size differs')
            self.generation = token(st)
            self.identity = self.hash()
            require(expected is None or self.identity['sha256'] == expected, 'input SHA-256 differs')
            self.revalidate()
        except BaseException:
            self.close()
            raise

    def hash(self):
        os.lseek(self.fd, 0, os.SEEK_SET)
        digest, size = hashlib.sha256(), 0
        while part := os.read(self.fd, MIB):
            size += len(part)
            require(size <= self.cap, 'input exceeded bound')
            digest.update(part)
        return {'sha256': digest.hexdigest(), 'size': size}

    def read(self, cap=2 * MIB):
        require(self.identity['size'] <= cap, 'input too large for bounded document read')
        os.lseek(self.fd, 0, os.SEEK_SET)
        raw = os.read(self.fd, cap + 1)
        require(identity(raw) == self.identity, 'input document changed')
        self.revalidate()
        return raw

    def revalidate(self, full=False):
        require(token(os.fstat(self.fd)) == self.generation == token(self.path.lstat()), 'input generation changed')
        if full:
            require(self.hash() == self.identity, 'input bytes changed')
            require(token(os.fstat(self.fd)) == self.generation == token(self.path.lstat()), 'input changed while hashing')

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def directory_token(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid)


class Owned:
    """Retain all evidence; only newly created directories are ever writable."""
    def __init__(self, output):
        self.output, self.root, self.held = Path(output), None, []
        require(self.output.is_absolute() and self.output.parent.resolve(strict=True) == self.output.parent,
                'output parent must be canonical')
        try:
            self.hold_directory(self.output.parent, private=False)
            self.output.mkdir(mode=0o700)
            self.hold_directory(self.output)
        except BaseException:
            self.close()
            raise

    def hold_directory(self, path, private=True):
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            require(directory_token(st) == directory_token(before) and stat.S_ISDIR(st.st_mode)
                    and st.st_uid == os.getuid() and st.st_mode & (0o077 if private else 0o022) == 0,
                    'directory ownership/mode differs')
            self.held.append((path, fd, directory_token(st)))
        except BaseException:
            os.close(fd)
            raise

    def batch(self, index):
        self.revalidate()
        require(0 <= index < BATCHES, 'batch outside fixed plan')
        self.root = self.output / f'case-{index + 1:02d}'
        self.root.mkdir(mode=0o700)
        self.hold_directory(self.root)
        (self.root / 'workspace').mkdir(mode=0o700)
        self.hold_directory(self.root / 'workspace')
        return self.root

    def revalidate(self):
        for path, fd, saved in self.held:
            require(directory_token(os.fstat(fd)) == saved == directory_token(path.lstat()), 'owned directory replaced')

    def close(self):
        for _, fd, _ in reversed(self.held):
            os.close(fd)
        self.held.clear()


def load_module(name, item):
    require(name not in sys.modules, 'module already loaded')
    module = types.ModuleType(name)
    module.__file__ = str(item.path)
    sys.modules[name] = module
    exec(compile(item.read(), str(item.path), 'exec'), module.__dict__)
    item.revalidate(full=True)
    return module


def distribution(values):
    require(values and all(type(value) is int and value >= 0 for value in values), 'invalid timing samples')
    ordered = sorted(values)
    return {'count': len(values), 'unit': 'milliseconds', 'method': 'nearest_rank_ceil_p_times_n',
            'p50': ordered[math.ceil(0.50 * len(values)) - 1] / 1_000_000,
            'p95': ordered[math.ceil(0.95 * len(values)) - 1] / 1_000_000,
            'minimum': ordered[0] / 1_000_000, 'maximum': ordered[-1] / 1_000_000,
            'p95_is_observed_maximum': math.ceil(0.95 * len(values)) == len(values)}


def parse_ps(raw, pid):
    fields = raw.decode('ascii').split()
    require(len(fields) == 3 and fields[0] == str(pid) and fields[1].isdigit(), 'ps PID/shape differs')
    matched = re.fullmatch(r'(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)(?:\.(\d+))?', fields[2])
    require(matched is not None, 'ps CPU format differs')
    days, hours, minutes, seconds, fraction = matched.groups()
    days, hours, minutes, seconds = map(int, (days or '0', hours or '0', minutes, seconds))
    require(minutes < 60 and seconds < 60, 'ps CPU range differs')
    fraction = fraction or ''
    cpu_ms = (((days * 24 + hours) * 60 + minutes) * 60 + seconds) * 1000
    cpu_ms += int(fraction or '0') * 1000 / (10 ** len(fraction))
    return {'pid': pid, 'rss_bytes': int(fields[1]) * 1024, 'cpu_ms': cpu_ms,
            'cpu_display_quantum_ms': 1000 / (10 ** len(fraction)), 'raw_cpu': fields[2],
            'rss_source_unit': 'ps_KiB', 'scope': 'direct_retained_host_only_sampled_not_peak_or_tree'}


MANAGED = ('/Library/Application Support/ClaudeCode/managed-settings.json',
           '/Library/Application Support/ClaudeCode/managed-mcp.json',
           '/etc/claude-code/managed-settings.json', '/etc/claude-code/managed-mcp.json')


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tirith', 'claude', 'python', 'python-runtime', 'harness'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--claude-version', required=True)
    parser.add_argument('--claude-invocation', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(all(re.fullmatch(r'[0-9a-f]{64}', getattr(args, name + '_sha256'))
                for name in ('tirith', 'claude', 'python', 'python_runtime', 'harness')), 'digest format differs')
    require(re.fullmatch(r'\d+\.\d+\.\d+', args.claude_version), 'Claude version must be exact numeric version')
    require(args.harness_sha256 == HARNESS_SHA, 'only the reviewed unchanged harness is supported')
    return args


def run(args):
    started, owned, runner, h = time.monotonic(), None, None, None
    result = {'schema_version': 1, 'status': 'refused', 'scope': 'actual_host_scripted_loopback_adapter_characterization',
              'batches': [], 'samples': [], 'children': []}
    original_umask = os.umask(0o077)
    handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    def interrupted(number, _frame):
        raise RuntimeError('received signal ' + str(number))
    for number in handlers:
        signal.signal(number, interrupted)
    inputs = []
    with contextlib.ExitStack() as stack:
        def hold(path, expected=None, cap=512 * MIB, **kw):
            item = stack.enter_context(Input(path, expected, cap, **kw))
            inputs.append(item)
            return item
        try:
            require(sys.platform == 'darwin' and platform.machine() == 'arm64', 'current protocol is native macOS ARM64')
            hold(Path(__file__).resolve(strict=True), cap=2 * MIB)
            hold(Path(sys.executable).resolve(strict=True), system_launcher=True)
            selected = {name: hold(getattr(args, name), getattr(args, name + '_sha256'),
                                  system_launcher=name == 'python')
                        for name in ('tirith', 'claude', 'python', 'python_runtime', 'harness')}
            harness = selected['harness']
            h = load_module('adapter_owned_claude_harness', harness)
            helper = hold(h.NATIVE_PATH, NATIVE_SHA, 2 * MIB)
            require(h.NATIVE_SHA256 == NATIVE_SHA, 'native helper pin differs')
            h.owned_native().require_process_observation()
            helper.revalidate(full=True)
            alias = args.claude_invocation
            require(alias.is_absolute() and alias.parent.resolve(strict=True) == alias.parent
                    and alias.resolve(strict=True) == args.claude, 'invocation alias differs')
            alias_token, alias_text = token(alias.lstat()), os.readlink(alias) if alias.is_symlink() else None
            def check_inputs(full=False):
                for item in inputs:
                    item.revalidate(full=full)
                require(token(alias.lstat()) == alias_token and alias.resolve(strict=True) == args.claude
                        and (os.readlink(alias) if alias.is_symlink() else None) == alias_text, 'invocation generation differs')
                require(not any(os.path.lexists(path) for path in MANAGED), 'managed configuration prevents host isolation')
            check_inputs(full=True)
            result['inputs'] = [{'path': str(item.path), **item.identity, 'generation': item.generation} for item in inputs]
            result['claude_invocation'] = {'path': str(alias), 'generation': alias_token, 'link_text': alias_text}
            owned = Owned(args.output)
            budget = Budget(owned, started)
            budget.check(force=True)
            disk = os.statvfs(owned.output)
            require(disk.f_bavail * disk.f_frsize >= STORAGE_CAP + FREE_FLOOR, 'insufficient fixed storage reserve')
            runner = Runner(h, owned, budget)
            result['context'] = {'platform': platform.platform(), 'machine': platform.machine(),
                                 'outer_python': sys.version, 'clock': 'perf_counter_ns', 'work_deadline_seconds': SECONDS,
                                 'storage_ceiling_bytes': STORAGE_CAP, 'free_floor_bytes': FREE_FLOOR,
                                 'registered_child_ceiling': MAX_CHILDREN, 'planned_children': 75,
                                 'provider_requests_per_host_expected': 29, 'provider_requests_per_host_hard_cap': 32}
            for index in range(BATCHES):
                root = owned.batch(index)
                h._ACTIVE_FIXTURES.add(root)
                batch = {'batch': index + 1, 'root': str(root), 'warmup': [], 'resource_samples': []}
                result['batches'].append(batch)
                child = None
                try:
                    env = h.isolated_env(root, args.tirith, args.python, alias)
                    if index == 0:
                        version, _ = runner.execute('claude-version', [args.claude, '--version'], env)
                        require(version.decode().strip() == args.claude_version + ' (Claude Code)', 'actual host version differs')
                        runtime, _ = runner.execute('python-runtime', [args.python, '-I', '-S', '-c', 'import sys;print(sys.executable)'], env)
                        require(Path(runtime.decode().strip()).resolve(strict=True) == args.python_runtime, 'actual Python runtime differs')
                        raw, _ = runner.execute('product-provenance', [args.tirith, 'version', '--provenance', '--json'], env)
                        provenance = json.loads(raw)
                        require(provenance['binary_sha256'] == args.tirith_sha256
                                and provenance['binary_path'] == str(args.tirith)
                                and provenance['target'] == 'aarch64-apple-darwin'
                                and provenance['build_profile'] == 'release' and provenance['dev_build'] is False,
                                'ordinary release product identity differs')
                        result['product_provenance'] = provenance
                        result['actual_host_version'] = version.decode().strip()
                    begin = time.perf_counter_ns()
                    raw, _ = runner.execute(f'setup-{index + 1}', [args.tirith, 'setup', 'recommended', '--shell', 'zsh', '--agent', 'claude-code', '--json'], env, 120)
                    batch['setup_ns'] = time.perf_counter_ns() - begin
                    setup = json.loads(raw)
                    require(setup.get('kind') == 'recommended-setup' and setup.get('state') in ('completed', 'completed-with-recovery')
                            and setup.get('steps') and all(step.get('state') in ('applied', 'applied-with-recovery') for step in setup['steps']),
                            'actual recommended setup did not finish all steps')
                    batch['setup'] = setup
                    settings = root / 'home/.claude/settings.json'
                    h.installed_recommended_identity(settings, args.python)
                    with contextlib.ExitStack() as config_stack:
                        configs = [config_stack.enter_context(Input(path, cap=MIB)) for path in
                                   (settings, settings.parent / 'hooks/tirith-check.py', root / 'config/tirith/policy.yaml')]
                        batch['configuration'] = [{'path': str(item.path.relative_to(root)), **item.identity} for item in configs]
                        def check_config():
                            check_inputs()
                            for item in configs:
                                item.revalidate(full=True)
                            h.installed_recommended_identity(settings, args.python)
                        def preflights(pair):
                            for action, command in COMMANDS.items():
                                raw, _ = runner.execute(f'preflight-{index + 1}-{pair}-{action}',
                                    [args.tirith, 'check', '--json', '--non-interactive', '--shell', 'posix', '--', command], env,
                                    expected=0 if action == 'allow' else 1)
                                require(json.loads(raw).get('action') == action, 'independent ordinary checker semantics differ')
                        budget.check(force=True)
                        provider = h.Provider('printf inert-unused-initial-command')
                        try:
                            with h.running_provider(provider, env):
                                host_argv = [args.claude, '--print', '--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose',
                                    '--no-session-persistence', '--setting-sources', 'user,project,local', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
                                    '--tools', 'Bash', '--allowedTools', 'Bash', '--permission-mode', 'dontAsk', '--permission-prompts', 'none',
                                    '--include-hook-events', '--system-prompt', 'Execute only the inert local fixture tool call provided.']
                                h.begin_provider_turn(provider, 'FixtureNoTool')
                                check_config()
                                begin = time.perf_counter_ns()
                                child = runner.start(f'actual-host-{index + 1}', host_argv, env, interactive=True, cap=4 * MIB)
                                events = runner.turn(child, 'Initialize the inert fixture and finish this turn without invoking a tool.')
                                batch['startup_ns'] = time.perf_counter_ns() - begin
                                require(h.successful_turn(events) and any(event.get('type') == 'system' and event.get('subtype') == 'init' for event in events)
                                        and provider.tool_issued == 0 and child.process.poll() is None, 'actual host initialization differs')
                                batch['pid'], batch['init_events'] = child.process.pid, event_evidence(events)
                                marker = root / 'workspace/execution-marker.txt'
                                def resources():
                                    require(child.process.poll() is None, 'retained host ended before resource observation')
                                    raw, _ = runner.execute(f'host-ps-{index + 1}', ['/bin/ps', '-p', str(child.process.pid), '-o', 'pid=', '-o', 'rss=', '-o', 'time='], env, 2)
                                    require(child.process.poll() is None, 'retained host ended during resource observation')
                                    sample = parse_ps(raw, child.process.pid)
                                    sample['monotonic_ns'] = time.monotonic_ns()
                                    batch['resource_samples'].append(sample)
                                resources()
                                batch['disk_bytes_after_setup_and_init'] = tree_inventory(root)['regular_file_bytes']
                                for pair in range(MEASURED_PAIRS + 1):
                                    preflights(pair)
                                    for action, command in COMMANDS.items():
                                        check_config()
                                        before = marker_lines(marker)
                                        with provider.lock:
                                            provider.command = command
                                            provider.tool_input = {'command': command, 'description': 'Execute the inert local certification marker once'}
                                        h.begin_provider_turn(provider, 'Bash')
                                        require(child.process.poll() is None, 'retained host ended before turn')
                                        events, elapsed = runner.timed_turn(child, 'Run the single inert local certification command, then finish.')
                                        observation = classify_turn(events, before, marker_lines(marker), h.provider_facts(provider), action, h)
                                        observation.update(batch=index + 1, repeat=pair, pid=child.process.pid, events=event_evidence(events),
                                                           command_sha256=identity(command.encode())['sha256'], elapsed_ns=elapsed,
                                                           elapsed_ms=elapsed / 1_000_000, sample_unit='send_through_result_return_including_guard_observations')
                                        (batch['warmup'] if pair == 0 else result['samples']).append(observation)
                                        check_config()
                                        require(observation['passed'] and child.process.poll() is None, 'actual host semantics failed; no substitute sample')
                                resources()
                                before_cpu, after_cpu = [sample['cpu_ms'] for sample in batch['resource_samples']]
                                require(after_cpu >= before_cpu, 'CPU cumulative counter decreased')
                                batch['host_cpu_ms_sampled_delta'] = after_cpu - before_cpu
                                batch['host_rss_bytes_sampled_maximum'] = max(sample['rss_bytes'] for sample in batch['resource_samples'])
                                batch['disk_bytes_after_turns'] = tree_inventory(root)['regular_file_bytes']
                                batch['provider'] = h.provider_facts(provider)
                                require(provider.requests == 29 and provider.rejected == 0, 'fixed provider request plan differs')
                                child.close()
                                require(not child.cleanup_error and all(child.cleanup.values()), 'host cleanup incomplete')
                            batch['provider_cleanup_complete'] = True
                        finally:
                            if child is not None:
                                child.close()
                        check_config()
                    check_inputs(full=True)
                finally:
                    if child is not None:
                        child.close()
                    h._ACTIVE_FIXTURES.discard(root)
                budget.check(force=True)
            require(len(runner.children) == 75 and len(result['samples']) == 48, 'fixed sample/child plan differs')
            result['distributions'] = {action: distribution([row['elapsed_ns'] for row in result['samples'] if row['action'] == action])
                                       for action in COMMANDS}
            result['distributions']['setup_with_owner_cleanup'] = distribution([batch['setup_ns'] for batch in result['batches']])
            result['distributions']['startup_with_owner_guards'] = distribution([batch['startup_ns'] for batch in result['batches']])
            check_inputs(full=True)
            budget.check(force=True)
            result['input_generations_and_bytes_unchanged'] = True
            result['status'] = 'observed_actual_host_adapter_samples_passed'
        except BaseException as error:
            result['error'] = type(error).__name__ + ': ' + str(error)[:2048]
            result['status'] = 'refused'
        finally:
            for number in handlers:
                signal.signal(number, signal.SIG_IGN)
            if runner is not None:
                errors = cleanup_all(runner.children)
                if errors:
                    result['cleanup_errors'], result['status'] = errors, 'refused'
                try:
                    owned.revalidate()
                    result['children'] = runner.records()
                except BaseException as error:
                    result['log_retention_error'], result['status'] = str(error)[:1000], 'refused'
            postcheck_errors = []
            for item in inputs:
                try:
                    item.revalidate(full=True)
                except BaseException as error:
                    postcheck_errors.append({'path': str(item.path), 'error': str(error)[:1000]})
            result['input_postchecks'] = {'count': len(inputs), 'errors': postcheck_errors}
            if postcheck_errors:
                result['status'] = 'refused'
            result['limitations'] = [
                '24 allow and 24 block turns across four serial actual hosts; no confidence interval or universal latency gate.',
                'Scripted loopback provider; excludes remote model inference and remote service latency.',
                'Setup/startup and adapter turns have separate units; turn clocks include finite owner guards during pipe pumping.',
                'CPU/RSS covers the direct retained host only at two points; CPU display precision and sampled RSS are not kernel peaks or descendant totals.',
                'Isolated harness policy/data state; no production DB freshness, cold OS cache, or daemon-route claim.',
                'Storage checks are bounded observations, not a filesystem quota; retained evidence is never recursively deleted.',
                'Owned original group cleanup does not attest escaped process groups or recovery after kernel/process death.'
            ]
            if owned is not None:
                try:
                    owned.revalidate()
                    result['storage'] = tree_inventory(owned.output, hashes=True)
                    result['elapsed_seconds'] = time.monotonic() - started
                    if runner is not None:
                        result['lowest_observed_free_bytes'] = budget.lowest_free
                        result['largest_observed_tree_bytes'] = budget.largest_tree
                    rendered = canonical(result)
                    require(len(rendered) <= 4 * MIB, 'result exceeded 4MiB')
                    with (owned.output / 'result.json').open('xb') as stream:
                        stream.write(rendered)
                except BaseException as error:
                    result['retention_error'], result['status'] = str(error)[:1000], 'refused'
                finally:
                    owned.close()
            for number, handler in handlers.items():
                signal.signal(number, handler)
            os.umask(original_umask)
    print(canonical({'status': result['status'], 'output': str(args.output), 'error': result.get('error'),
                     'retention_error': result.get('retention_error')}).decode(), end='')
    return 0 if result['status'] == 'observed_actual_host_adapter_samples_passed' else 1


if __name__ == '__main__':
    sys.exit(run(parse_args()))
