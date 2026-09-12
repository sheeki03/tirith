#!/usr/bin/env python3
"""Exercise a pinned PowerShell hook in disposable native processes and terminals."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import time
import traceback

MAX_OUTPUT = 2 * 1024 * 1024


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def fixture(root, name, binary):
    path = root / name
    path.mkdir(mode=0o700)
    (path / 'bin').mkdir()
    executable = path / 'bin' / ('tirith.exe' if os.name == 'nt' else 'tirith')
    if os.name == 'nt':
        import shutil
        shutil.copyfile(binary, executable)
    else:
        executable.symlink_to(binary)
    env = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT') if k in os.environ}
    env.update({
        'HOME': str(path), 'USERPROFILE': str(path),
        'PATH': str(path / 'bin') + os.pathsep + (str(Path(env.get('SystemRoot', 'C:/Windows')) / 'System32') if os.name == 'nt' else '/usr/bin:/bin'),
        'TMPDIR': str(path), 'TEMP': str(path), 'TMP': str(path),
        'XDG_CONFIG_HOME': str(path / 'config'), 'XDG_DATA_HOME': str(path / 'data'),
        'XDG_STATE_HOME': str(path / 'state'), 'XDG_CACHE_HOME': str(path / 'cache'),
        'APPDATA': str(path / 'appdata'), 'LOCALAPPDATA': str(path / 'localappdata'),
        'TIRITH_LOG': '0', 'TIRITH_OFFLINE': '1', 'TERM': 'xterm-256color',
        'POWERSHELL_TELEMETRY_OPTOUT': '1', 'POWERSHELL_UPDATECHECK': 'Off',
    })
    return path, env, executable


def state_script(hook, output):
    return (
        "Import-Module PSReadLine -ErrorAction Stop; "
        "$before=(Get-PSReadLineKeyHandler -Chord Enter).Function; . " + quote(hook) + "; "
        "[pscustomobject]@{version=$PSVersionTable.PSVersion.ToString();"
        "user_interactive=[Environment]::UserInteractive;input_redirected=[Console]::IsInputRedirected;output_redirected=[Console]::IsOutputRedirected;before=$before;"
        "after=(Get-PSReadLineKeyHandler -Chord Enter).Function;"
        "status=$global:TIRITH_STATUS;loaded=$global:_TIRITH_PS_LOADED;"
        "integration=$env:TIRITH_INTEGRATION_SHELL;session=$env:TIRITH_SESSION_ID} "
        "| ConvertTo-Json -Compress | Set-Content -Encoding UTF8 " + quote(output)
    )


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def run_bounded(command, cwd, env, log, timeout=45):
    with log.open('wb') as sink:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=sink, stderr=subprocess.STDOUT,
                                start_new_session=os.name == 'posix')
        deadline = time.monotonic() + timeout
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline or log.stat().st_size > MAX_OUTPUT:
                    raise AssertionError('native process exceeded time/output limit')
                time.sleep(.1)
            assert log.stat().st_size <= MAX_OUTPUT, 'native process exceeded output limit'
            assert proc.returncode == 0, f'native process exit {proc.returncode}; see {log.name}'
        finally:
            # A completed shell may still own background jobs. Close its
            # disposable process group even when the direct child has exited.
            if os.name == 'posix':
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)


def inactive_cases(root, pwsh, binary, hook, results=None):
    if results is None:
        results = []
    for mode in ('noninteractive', 'command', 'file', 'encoded', 'noexit-redirected', 'payload-noexit'):
        path, env, _ = fixture(root, mode, binary)
        code = state_script(hook, path / 'state.json')
        if mode == 'file':
            (path / 'init.ps1').write_text(code)
            args = ['-File', str(path / 'init.ps1')]
        elif mode == 'encoded':
            args = ['-EncodedCommand', base64.b64encode(code.encode('utf-16-le')).decode()]
        elif mode == 'payload-noexit':
            args = ['-Command', "$unused='-NoExit'; " + code]
        elif mode == 'noexit-redirected':
            args = ['-NoExit', '-Command', code + '; exit 0']
        else:
            args = (['-NonInteractive'] if mode == 'noninteractive' else []) + ['-Command', code]
        run_bounded([str(pwsh), '-NoLogo', '-NoProfile', *args], path, env, path / 'process.log')
        state = read_json(path / 'state.json')
        assert state['after'] == state['before'], state
        assert state['loaded'] is False and state['status'] == 'off', state
        assert state['integration'] is None and state['session'] is None, state
        assert not (path / 'state/tirith/env_snapshot.json').exists()
        results.append({'case': mode, 'passed': True, 'state': state})
    return results


class Terminal:
    def __init__(self, pwsh, path, env, args):
        import fcntl
        import pty
        import struct
        import termios
        self.path, self.trace = path, bytearray()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(path)
            os.execve(pwsh, [str(pwsh), '-NoLogo', '-NoProfile', *args], env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 140, 0, 0))
        self.response_tail = b''

    def pump(self, seconds=.2):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not select.select([self.fd], [], [], min(.1, max(0, deadline-time.monotonic())))[0]:
                continue
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                return
            if not data:
                return
            self.trace.extend(data)
            combined = self.response_tail + data
            for _ in range(combined.count(b'\x1b[6n')):
                self.send(b'\x1b[1;1R')
            self.response_tail = combined[-3:]
            assert len(self.trace) <= MAX_OUTPUT, 'native terminal output exceeded limit'

    def send(self, value):
        os.write(self.fd, value if isinstance(value, bytes) else value.encode())

    def wait(self, predicate, description, seconds=60):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            self.pump()
        raise AssertionError('native event not observed: ' + description)

    def output(self, text, start):
        self.wait(lambda: text in self.trace[start:], repr(text))

    def cancel(self):
        generation = read_json(self.path / 'prompt.json')['generation']
        self.send(b'\x03')
        self.wait(lambda: read_json(self.path / 'prompt.json')['generation'] > generation, 'fresh prompt')
        self.pump(.3)

    def buffer(self):
        result = self.path / 'buffer.json'
        result.unlink(missing_ok=True)
        self.send(b'\x07')
        self.wait(result.exists, 'buffer snapshot')
        return read_json(result)

    def close(self):
        deadline = time.monotonic() + 3
        try:
            while True:
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    # Darwin can return EPERM while a PTY child is exiting,
                    # before it becomes waitable. Require our child's exit;
                    # a signal error alone never establishes cleanup.
                    pass
                if os.waitpid(self.pid, os.WNOHANG)[0] == self.pid:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError('native terminal cleanup was not confirmed')
                time.sleep(.01)
        finally:
            os.close(self.fd)
            (self.path / 'terminal.log').write_bytes(self.trace)


def inactive_terminal_cases(root, pwsh, binary, hook, results=None):
    if results is None:
        results = []
    for mode in ('noninteractive', 'command', 'file-payload-noexit', 'encoded', 'noexit-noninteractive'):
        path, env, _ = fixture(root, 'terminal-' + mode, binary)
        code = state_script(hook, path / 'state.json')
        if mode == 'file-payload-noexit':
            (path / 'init.ps1').write_text(code)
            args = ['-File', str(path / 'init.ps1'), '-NoExit']
        elif mode == 'encoded':
            args = ['-EncodedCommand', base64.b64encode(code.encode('utf-16-le')).decode()]
        else:
            prefix = ['-NoExit', '-NonInteractive'] if mode == 'noexit-noninteractive' else ['-NonInteractive'] if mode == 'noninteractive' else []
            args = prefix + ['-Command', code + '; exit 0']
        tty = Terminal(pwsh, path, env, args)
        try:
            tty.wait((path / 'state.json').exists, 'inactive terminal state')
            state = read_json(path / 'state.json')
            assert state['input_redirected'] is False and state['output_redirected'] is False, state
            assert state['after'] == state['before'] and state['loaded'] is False, state
            assert state['status'] == 'off' and state['integration'] is None and state['session'] is None, state
            assert not (path / 'state/tirith/env_snapshot.json').exists()
            results.append({'case': 'terminal-' + mode, 'passed': True, 'state': state})
        finally:
            tty.close()
    return results


def interactive_case(root, pwsh, binary, hook, results=None):
    if results is None:
        results = []
    path, env, executable = fixture(root, 'interactive', binary)
    clip = path / 'clipboard.txt'
    clip.write_text('')
    code = 'function global:Get-Clipboard { param([switch]$Raw) if ($Raw) { Get-Content -Raw ' + quote(clip) + ' } else { Get-Content ' + quote(clip) + ' } }; '
    code += state_script(hook, path / 'ready.json')
    code += "; function global:prompt { $global:ProbeGeneration++; [pscustomobject]@{generation=$global:ProbeGeneration;status=$global:TIRITH_STATUS;last_exit=$global:LASTEXITCODE} | ConvertTo-Json -Compress | Set-Content " + quote(path / 'prompt.json') + "; 'PROBE> ' }; "
    code += "Set-PSReadLineKeyHandler -Key Ctrl+g -ScriptBlock { $line=$null; $cursor=$null; [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line,[ref]$cursor); [pscustomobject]@{line=$line;status=$global:TIRITH_STATUS;last_exit=$global:LASTEXITCODE} | ConvertTo-Json -Compress | Set-Content " + quote(path / 'buffer.json') + ' }'
    code += "; Set-PSReadLineKeyHandler -Key Ctrl+t -ScriptBlock { if (Test-Path " + quote(path / 'temp-failure.flag') + ") { $env:TMPDIR=" + quote(path / 'unavailable-temp') + " } else { $env:TMPDIR=" + quote(path) + " }; [System.IO.File]::WriteAllText(" + quote(path / 'temp-control.txt') + ", 'configured') }"
    (path / 'init.ps1').write_text(code)
    tty = Terminal(pwsh, path, env, ['-NoExit', '-File', str(path / 'init.ps1')])
    try:
        tty.wait((path / 'ready.json').exists, 'interactive setup')
        tty.wait((path / 'prompt.json').exists, 'initial prompt')
        assert read_json(path / 'ready.json')['after'] == 'CustomAction'
        tty.send('/usr/bin/true; Add-Content allowed.txt ran\r')
        tty.wait((path / 'allowed.txt').exists, 'allowed command')
        tty.wait(lambda: read_json(path / 'prompt.json')['generation'] >= 2, 'allowed prompt')
        assert (path / 'allowed.txt').read_text().splitlines() == ['ran']
        results.append({'case': 'allowed-once', 'passed': True})
        start = len(tty.trace)
        tty.send("Write-Output 'Write-Output safe' | Invoke-Expression; Add-Content blocked.txt ran\r")
        tty.output(b'tirith: BLOCKED', start)
        tty.pump(1)
        tty.cancel()
        assert not (path / 'blocked.txt').exists()
        results.append({'case': 'blocked-never', 'passed': True})
        executable.unlink()
        start = len(tty.trace)
        tty.send('Add-Content missing-checker.txt ran\r')
        tty.output(b'checker or temporary storage unavailable', start)
        tty.cancel()
        state = read_json(path / 'prompt.json')
        assert not (path / 'missing-checker.txt').exists() and state['status'] == 'degraded', state
        assert state['last_exit'] == 0, state
        results.append({'case': 'missing-checker-no-execution', 'passed': True, 'state': state})
        executable.symlink_to(binary)
        tty.send('Add-Content recovered.txt ran\r')
        tty.wait((path / 'recovered.txt').exists, 'recovered command')
        tty.wait(lambda: read_json(path / 'prompt.json')['status'] == 'blocks', 'recovered status')
        assert (path / 'recovered.txt').read_text().splitlines() == ['ran']
        results.append({'case': 'checker-recovery', 'passed': True})
        executable.unlink()
        executable.write_text('#!/bin/sh\nexit 77\n')
        executable.chmod(0o700)
        tty.send('Add-Content unexpected.txt ran\r')
        tty.wait((path / 'unexpected.txt').exists, 'existing unexpected-exit fallback')
        tty.wait(lambda: read_json(path / 'prompt.json')['status'] == 'degraded', 'unexpected-exit degraded status')
        assert (path / 'unexpected.txt').read_text().splitlines() == ['ran']
        results.append({'case': 'unexpected-exit-existing-enter-fallback', 'passed': True})
        clip.write_text('Add-Content paste-unexpected.txt ran')
        start = len(tty.trace)
        tty.send(b'\x16')
        tty.output(b'paste blocked for safety', start)
        state = tty.buffer()
        assert state['line'] == '' and state['status'] == 'degraded', state
        assert not (path / 'paste-unexpected.txt').exists()
        results.append({'case': 'unexpected-exit-paste-not-inserted', 'passed': True})
        executable.unlink()
        start = len(tty.trace)
        tty.send(b'\x16')
        tty.output(b'paste was not inserted', start)
        state = tty.buffer()
        assert state['line'] == '' and state['status'] == 'degraded', state
        results.append({'case': 'missing-checker-paste-not-inserted', 'passed': True})
        executable.symlink_to(binary)
        clip.write_text('Add-Content paste-allowed.txt ran')
        tty.send(b'\x16')
        tty.wait(lambda: tty.buffer()['line'] == clip.read_text(), 'allowed paste insertion')
        assert not (path / 'paste-allowed.txt').exists()
        tty.send(b'\r')
        tty.wait((path / 'paste-allowed.txt').exists, 'allowed pasted command')
        assert (path / 'paste-allowed.txt').read_text().splitlines() == ['ran']
        results.append({'case': 'paste-inserts-before-enter-executes-once', 'passed': True})
        tty.wait(lambda: read_json(path / 'prompt.json')['status'] == 'blocks', 'paste recovery status')
        clip.write_text('Add-Content multiline.txt first\nAdd-Content multiline.txt second')
        tty.send(b'\x16')
        tty.wait(lambda: tty.buffer()['line'] == clip.read_text(), 'exact multiline clipboard text')
        assert not (path / 'multiline.txt').exists()
        tty.send(b'\r')
        tty.wait(lambda: (path / 'multiline.txt').read_text().splitlines() == ['first', 'second'], 'multiline execution')
        results.append({'case': 'multiline-paste-retains-exact-text', 'passed': True})
        tty.cancel()
        (path / 'temp-failure.flag').touch()
        tty.send(b'\x14')
        tty.wait((path / 'temp-control.txt').exists, 'temporary storage fault control')
        start = len(tty.trace)
        tty.send('Add-Content storage-unavailable.txt ran\r')
        tty.output(b'checker or temporary storage unavailable', start)
        tty.cancel()
        state = read_json(path / 'prompt.json')
        assert not (path / 'storage-unavailable.txt').exists() and state['status'] == 'degraded', state
        results.append({'case': 'missing-temporary-storage-no-execution', 'passed': True})
        (path / 'temp-failure.flag').unlink()
        (path / 'temp-control.txt').unlink()
        tty.send(b'\x14')
        tty.wait((path / 'temp-control.txt').exists, 'temporary storage restoration')
        tty.send('Add-Content storage-recovered.txt ran\r')
        tty.wait((path / 'storage-recovered.txt').exists, 'storage recovery command')
        tty.wait(lambda: read_json(path / 'prompt.json')['status'] == 'blocks', 'storage recovery status')
        assert (path / 'storage-recovered.txt').read_text().splitlines() == ['ran']
        results.append({'case': 'temporary-storage-recovery', 'passed': True})
    finally:
        tty.close()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--powershell', type=Path, required=True)
    parser.add_argument('--hook', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--noninteractive-only', action='store_true')
    group.add_argument('--interactive-only', action='store_true')
    args = parser.parse_args()
    binary, pwsh, hook = (p.resolve(strict=True) for p in (args.binary, args.powershell, args.hook))
    if not args.noninteractive_only and os.name != 'posix':
        parser.error('the interactive terminal runner currently requires a native POSIX PTY')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema_version': 1, 'platform': platform.platform(),
              'binary_sha256': digest(binary), 'powershell_sha256': digest(pwsh),
              'hook_sha256': digest(hook), 'harness_sha256': digest(Path(__file__)),
              'scope': 'posix-terminal-only' if args.interactive_only else 'noninteractive-only' if args.noninteractive_only else 'noninteractive-and-posix-terminal',
              'results': [], 'passed': False}
    try:
        if not args.interactive_only:
            inactive_cases(args.output, pwsh, binary, hook, report['results'])
        if not args.noninteractive_only:
            if not args.interactive_only:
                inactive_terminal_cases(args.output, pwsh, binary, hook, report['results'])
            interactive_case(args.output, pwsh, binary, hook, report['results'])
        assert digest(binary) == report['binary_sha256'] and digest(pwsh) == report['powershell_sha256'] and digest(hook) == report['hook_sha256']
        report['passed'] = True
    except Exception as error:
        report['failure'] = str(error)
        report['failure_trace'] = traceback.format_exc(limit=8)
    finally:
        write_json(args.output / 'report.json', report)
    print(json.dumps({'passed': report['passed'], 'cases': len(report['results']), 'report': str(args.output / 'report.json')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
