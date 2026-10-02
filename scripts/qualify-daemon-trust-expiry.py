#!/usr/bin/env python3
"""One bounded retained-daemon trust expiry/renewal/revoke sequence; analysis only."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import stat
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
WORKLOAD_SHA = 'a1e41ba7dcf93e751180940dc42b1797f27555e06ccbe77b07f08d7e7fbca4aa'
NATIVE_SHA = '913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75'
DEADLINE = 150
MAX_CHILDREN = 12
MAX_REQUESTS = 16
CAPTURE = 65536
URL = 'https://bit.ly/tirith-owned-expiry-control'
COMMAND = 'curl --head ' + URL
POLICY = b'threat_intel:\n  auto_update_hours: 0\nseverity_overrides:\n  shortened_url: high\n'


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def pin(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, expected, name):
    require(path.is_absolute() and pin(expected), 'module path/pin admission')
    cap = 1024 * 1024
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= cap, 'module file bound/type')
        raw = handle.read(cap + 1)
        after = os.fstat(handle.fileno())
        stable = lambda s: tuple(getattr(s, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        require(len(raw) == before.st_size and stable(before) == stable(after) == stable(path.lstat()), 'module changed during read')
    require(sha(raw) == expected, 'module hash mismatch')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Execute only the held, hashed bytes; do not reopen a mutable module path.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def canonical_uuid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value, 'noncanonical grant UUID')
    return value


def timestamp(value):
    require(type(value) is str and 20 <= len(value) <= 40, 'expiry timestamp shape')
    dt = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(dt.tzinfo is not None, 'expiry lacks timezone')
    return dt.timestamp()


def clock_record(origin=None):
    mono_before = time.monotonic()
    wall = time.time()
    mono = time.monotonic()
    require(mono - mono_before <= .05, 'clock sample scheduling gap')
    row = {'wall_seconds': wall, 'monotonic_seconds': mono, 'sample_span_seconds': mono - mono_before}
    if origin is not None:
        clock_delta(origin, row)
    return row


def clock_delta(origin, row):
    wall_delta = row['wall_seconds'] - origin['wall_seconds']
    mono_delta = row['monotonic_seconds'] - origin['monotonic_seconds']
    require(wall_delta >= 0 and mono_delta >= 0 and abs(wall_delta - mono_delta) <= .25,
            'wall/monotonic clock jump')


def expiry_window(grant, before, after):
    expiry = timestamp(grant['expires_at'])
    require(before['wall_seconds'] + 59 <= expiry <= after['wall_seconds'] + 61,
            'CLI grant does not carry actual one-minute TTL')
    require(expiry - after['wall_seconds'] >= 40, 'grant already near expiry after mutation')
    return expiry


def semantic(w, value, exit_code, policy, allowed):
    observed = w.semantic(value, exit_code, policy)
    require(observed['action'] == ('allow' if allowed else 'block'), 'unexpected trust decision')
    require(observed['findings'] == ([] if allowed else [('shortened_url', 'HIGH', None)]),
            'different or additional findings; refuse independent blocker')
    require(type(observed['urls']) is int and observed['urls'] == 1 and observed['tier'] >= 2,
            'URL analysis not observed')
    return observed


def store_record(w, path, grant_id):
    raw = w.held_bytes(path, CAPTURE)
    s = path.lstat()
    require(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1,
            'private grant store ownership/mode')
    obj = w.decode(raw)
    require(type(obj) is dict and set(obj) == {'schema_version', 'grants'} and obj.get('schema_version') == 1 and type(obj.get('grants')) is list
            and len(obj['grants']) == 1 and 'entries' not in obj, 'exact single-grant store expected')
    grant = obj['grants'][0]
    require(type(grant) is dict and canonical_uuid(grant.get('id')) == grant_id
            and grant.get('pattern') == URL and grant.get('rule_id') == 'shortened_url'
            and grant.get('scope') == {'kind': 'user'}, 'grant identity or scope differs')
    timestamp(grant.get('created_at')); timestamp(grant.get('expires_at'))
    return {'sha256': sha(raw), 'bytes': len(raw), 'generation': {key: getattr(s, key) for key in
            ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')},
            'grant': grant}


def mutation(value, row, kind, state, grant_id=None):
    require(row['exit'] == 0 and value.get('schema_version') == 1 and value.get('kind') == kind
            and value.get('state') == state and not value.get('error') and not value.get('no_op'),
            'trust mutation did not apply')
    actual = canonical_uuid(value.get('grant_id'))
    require(grant_id is None or actual == grant_id, 'mutation changed grant identity')
    canonical_uuid(value.get('operation_id'))
    return actual


def run(args):
    require(__debug__ and sys.platform in ('darwin', 'linux'), 'native nonoptimized Unix Python required')
    require(pin(args.sha256) and pin(args.database_sha256), 'input pins')
    w = load(args.workload_helper, WORKLOAD_SHA, 'retained_daemon_transport')
    native = load(args.native_helper, NATIVE_SHA, 'retained_daemon_owner')
    native.require_process_observation()
    native.OUTPUT_LIMIT = CAPTURE  # tighter retained output bound; process ownership is unchanged.
    w.JOURNAL_LIMIT = 2 * 1024 * 1024
    inputs = {}
    for label, path, cap, expected in (
        ('binary', args.binary, 128 * w.MIB, args.sha256),
        ('database', args.database, 64 * w.MIB, args.database_sha256),
        ('workload_helper', args.workload_helper, w.MIB, WORKLOAD_SHA),
        ('native_helper', args.native_helper, w.MIB, NATIVE_SHA),
        ('binding', args.source_binding, CAPTURE, None),
        ('producer', Path(__file__).resolve(), w.MIB, None),
        ('python', Path(sys.executable).resolve(), 64 * w.MIB, None)):
        require(path.is_absolute(), 'input path must be absolute')
        raw = w.held_bytes(path, cap)
        require(expected is None or sha(raw) == expected, label + ' hash mismatch')
        inputs[label] = {'path': str(path), 'sha256': sha(raw), 'bytes': len(raw), 'cap': cap}
    binding = w.decode(w.held_bytes(args.source_binding, CAPTURE)); w.admit_binding(binding, args.sha256)
    database = w.held_bytes(args.database, 64 * w.MIB)
    args.output.mkdir(mode=0o700)
    journal = w.Journal(args.output / 'observations.jsonl')
    root = Path(tempfile.mkdtemp(prefix='tdex-', dir='/tmp')).resolve()
    root_identity = w.identity(root)
    deadline = time.monotonic() + DEADLINE

    class Runner(w.Runner):
        daemon = None

        def cli(self, fixture, name, arguments):
            require(len(self.jobs) < MAX_CHILDREN, 'direct child limit')
            self.check_disk(fixture.root)
            socket_path = None if self.daemon is None or self.daemon.cleanup_result is not None else fixture.socket
            if socket_path is not None: self.daemon.verify()
            w.storage(fixture.root, allowed_socket=socket_path)
            start = time.monotonic()
            job = self.native.Job(name, [self.binary, *arguments], fixture.cwd, fixture.env,
                                  timeout=w.remaining(self.deadline, 15))
            self.jobs.append(job)
            try:
                row = self.native.finish([job])[0]
            except BaseException:
                self.journal.add({'kind': 'cli-owner-failure', **job.result()}); raise
            row['elapsed_ms'] = (time.monotonic() - start) * 1000
            self.journal.add({'kind': 'cli', **row})
            require(row['failure'] is None and all(row['cleanup'].get(k) is True for k in w.CLEANUP_KEYS),
                    'CLI owner cleanup incomplete')
            require(len(row['stdout'].encode()) <= CAPTURE and len(row['stderr'].encode()) <= CAPTURE,
                    'CLI retained output bound')
            if socket_path is not None: self.daemon.verify()
            w.storage(fixture.root, allowed_socket=socket_path)
            w.remaining(self.deadline, 1)
            return w.decode(row['stdout']), row

    class Daemon(w.Daemon):
        request_count = 0

        def exchange(self, requests):
            require(self.request_count + len(requests) <= MAX_REQUESTS, 'daemon request limit')
            self.request_count += len(requests)
            rows = super().exchange(requests)
            for row in rows: self.runner.journal.add({'kind': 'daemon-response', **row})
            return rows

    runner = Runner(native, args.binary, deadline, journal)
    daemon = None
    report = {'status': 'failed', 'inputs': inputs, 'source_binding': binding, 'host': platform.platform(),
              'machine': platform.machine(), 'scope': 'offline analysis only; no analyzed command execution',
              'work_deadline_seconds': DEADLINE, 'max_direct_children': MAX_CHILDREN,
              'max_daemon_requests': MAX_REQUESTS, 'fixture_root': str(root), 'cases': [],
              'clock_jump_bound_seconds': .25, 'changes_permitted': ['actual trust add', 'actual trust expiry', 'actual trust revoke']}
    try:
        runner.check_disk(root)
        fixture = w.Fixture(root, 1, database)
        fixture.policy.write_bytes(POLICY)
        fixture.inputs[str(fixture.policy)] = sha(POLICY)
        store = fixture.policy.with_name('trust-grants.json')
        require(not os.path.lexists(store) and not os.path.lexists(fixture.policy.with_name('trust.json')),
                'trust state not initially absent')
        report['policy_sha256'] = sha(POLICY);report['analysis_string'] = COMMAND
        value, row = runner.cli(fixture, 'database-before', ['threat-db', 'status', '--json'])
        require(row['exit'] == 0, 'database status refused')
        report['database'] = w.admitted_database(value, fixture.db)
        daemon = Daemon(runner, fixture);runner.daemon = daemon
        report['daemon_start'] = daemon.start()
        origin = clock_record();report['clock_origin'] = origin

        def observe(name, allowed):
            fixture.verify()
            row = daemon.exchange([w.request(COMMAND, fixture.cwd)])[0]
            result = semantic(w, row['response'], row['response']['exit_code'], fixture.policy, allowed)
            case = {'name': name, 'clock': clock_record(origin), 'semantic': result,
                    'daemon_generation': daemon.record, 'peer_pid': row['peer_pid']}
            report['cases'].append(case);journal.add({'kind': 'case', **case})
            return case

        observe('baseline-block', False)
        add_before = clock_record(origin)
        value, row = runner.cli(fixture, 'trust-add', ['trust', 'add', URL, '--rule', 'shortened_url', '--scope', 'user', '--ttl', '1m', '--json'])
        add_after = clock_record(origin)
        grant_id = mutation(value, row, 'trust_change', 'effective')
        initial = store_record(w, store, grant_id)
        require(initial['grant'].get('revoked_at') is None, 'new grant already revoked')
        expires = expiry_window(initial['grant'], add_before, add_after)
        report['grant_id'] = grant_id;report['grant_added'] = initial
        journal.add({'kind': 'store-added', **initial})
        observe('same-daemon-grant-allow', True)
        require(store_record(w, store, grant_id) == initial, 'grant changed during allow check')
        waits = 0;next_ping = time.monotonic() + 10
        while True:
            now = clock_record(origin)
            require(waits <= 256, 'expiry wait observation bound')
            daemon.verify();runner.check_disk(root);fixture.verify()
            current = store_record(w, store, grant_id)
            require(current == initial, 'grant bytes or generation changed during natural expiry')
            journal.add({'kind': 'expiry-wait', 'clock': now, 'store_sha256': current['sha256'], 'store_generation': current['generation']})
            if now['wall_seconds'] >= expires + .25: break
            if time.monotonic() >= next_ping:
                response = daemon.exchange([{'command': 'ping', 'input': ''}])[0]['response']
                require(response.get('exit_code') == 0 and response.get('error') is None, 'retained daemon ping refused')
                next_ping = time.monotonic() + 10
            time.sleep(min(.5, w.remaining(deadline, .5), max(.001, expires + .25 - now['wall_seconds'])))
            waits += 1
        report['natural_expiry_observations'] = waits + 1
        observe('same-daemon-natural-expiry-block', False)
        require(store_record(w, store, grant_id) == initial, 'expiry mutated grant store')
        value, row = runner.cli(fixture, 'ordinary-expired-check', ['check', '--no-daemon', '--offline', '--non-interactive', '--shell', 'posix', '--json', '--json-schema', '3', '--', COMMAND])
        report['ordinary_expired_check'] = semantic(w, value, row['exit'], fixture.policy, False)
        require(store_record(w, store, grant_id) == initial, 'ordinary expiry check mutated grant store')
        renew_before = clock_record(origin)
        value, row = runner.cli(fixture, 'trust-renew-same-id', ['trust', 'expiry', grant_id, '--ttl', '1m', '--json'])
        renew_after = clock_record(origin);mutation(value, row, 'trust_expiry_change', 'effective', grant_id)
        renewed = store_record(w, store, grant_id);expiry_window(renewed['grant'], renew_before, renew_after)
        require(renewed['sha256'] != initial['sha256'] and renewed['grant'].get('revoked_at') is None, 'renewal did not change expiry')
        expected = dict(initial['grant']);expected['expires_at'] = renewed['grant']['expires_at']
        require(renewed['grant'] == expected and timestamp(expected['expires_at']) > expires,
                'renewal changed fields beyond expiry or did not extend deadline')
        report['grant_renewed'] = renewed;observe('same-daemon-renewed-allow', True)
        require(store_record(w, store, grant_id) == renewed, 'allow changed renewed grant')
        value, row = runner.cli(fixture, 'trust-revoke-same-id', ['trust', 'revoke', grant_id, '--json'])
        mutation(value, row, 'trust_revocation', 'revoked', grant_id)
        revoked = store_record(w, store, grant_id);timestamp(revoked['grant'].get('revoked_at'))
        expected = dict(renewed['grant']);expected['revoked_at'] = revoked['grant']['revoked_at']
        require(revoked['grant'] == expected and revoked['sha256'] != renewed['sha256'], 'revocation changed unrelated grant fields')
        report['grant_revoked'] = revoked;observe('same-daemon-revoked-block', False)
        require(store_record(w, store, grant_id) == revoked, 'revocation check changed grant')
        value, row = runner.cli(fixture, 'database-after', ['threat-db', 'status', '--json'])
        require(row['exit'] == 0 and w.admitted_database(value, fixture.db) == report['database'], 'database postcheck mismatch')
        fixture.verify();clock_record(origin);w.remaining(deadline, 1)
        for item in inputs.values():
            require(sha(w.held_bytes(Path(item['path']), item['cap'])) == item['sha256'], 'input postcheck failed')
        report['input_postchecks'] = True;report['status'] = 'completed'
    except BaseException as error:
        report['failure'] = {'kind': type(error).__name__, 'message': str(error)[:1024]}
    finally:
        if daemon is not None:
            try: daemon.finish()
            except BaseException as error:
                report['status'] = 'failed';report['daemon_cleanup_error'] = str(error)[:1024]
            report['daemon_cleanup'] = daemon.cleanup_result;report['daemon_request_count'] = daemon.request_count
        errors = w.cleanup_registered(runner)
        if errors: report['status'] = 'failed';report['final_cleanup_errors'] = errors
        report['owned_children'] = [{'name': j.name, 'pid': j.process.pid, 'exit': j.process.returncode,
                                    'failure': j.failure, 'cleanup': dict(j.cleanup), 'group_observation': j.group_observation}
                                   for j in runner.jobs]
        report['fixture_cleanup'] = False
        try:
            require(len(runner.jobs) <= MAX_CHILDREN and all(j.process.reaped and all(j.cleanup.get(k) is True for k in w.CLEANUP_KEYS) for j in runner.jobs), 'owned child cleanup incomplete')
        except BaseException as error:
            report['status'] = 'failed';report['owned_cleanup_error'] = str(error)[:1024]
        try:
            journal.close()
            report['observations'] = {'rows': journal.count, 'bytes': journal.size, 'sha256': sha(w.held_bytes(journal.path, w.JOURNAL_LIMIT, allow_empty=True))}
            require(w.identity(root) == root_identity, 'fixture root identity changed')
            report['final_storage'] = w.storage(root)
            if report['status'] == 'completed':
                shutil.rmtree(root);report['fixture_cleanup'] = not root.exists()
            else: report['fixture_retained_for_failure'] = True
        except BaseException as error:
            report['status'] = 'failed';report['finalization_error'] = str(error)[:1024]
        try:
            for item in inputs.values():
                require(sha(w.held_bytes(Path(item['path']), item['cap'])) == item['sha256'], 'final input postcheck failed')
            report['final_input_postchecks'] = True
        except BaseException as error:
            report['status'] = 'failed';report['final_input_postcheck_error'] = str(error)[:1024]
        report['elapsed_work_seconds'] = time.monotonic() - (deadline - DEADLINE)
        raw = (json.dumps(report, indent=2, allow_nan=False) + '\n').encode()
        require(len(raw) <= 2 * w.MIB, 'report bound')
        with (args.output / 'report.json').open('xb') as handle: handle.write(raw)
    return 0 if report['status'] == 'completed' and report.get('fixture_cleanup') else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'database', 'native-helper', 'workload-helper', 'source-binding', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sha256', required=True);parser.add_argument('--database-sha256', required=True)
    arguments = parser.parse_args()
    for field in ('binary', 'database', 'native_helper', 'workload_helper', 'source_binding', 'output'):
        require(getattr(arguments, field).is_absolute(), field + ' must be absolute')
    raise SystemExit(run(arguments))
