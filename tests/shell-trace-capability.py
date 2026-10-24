#!/usr/bin/env python3
"""Exercise real hook functions with fake capabilities under native shell tracing.

No hook initialization, real Tirith process, receipt, or user configuration is
loaded. The transferred capability is a test sentinel and the executable only
records that it was called in a private temporary directory.
"""

import argparse
from contextlib import contextmanager
import importlib.util
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import sys
from types import SimpleNamespace
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
CAPABILITY = "controlled-trace-capability-4537106a-do-not-use"
LOADED_STATE = "controlled-loaded-state-23616330-do-not-use"
NATIVE_ROWS = []
RETAINED_ROOTS = []
OWNER_SHA256 = "913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75"
FILES = {"bash": "bash-hook.bash", "zsh": "zsh-hook.zsh", "fish": "fish-hook.fish"}


def owner_runtime():
    path = ROOT / "tools/qualification/mixed_audit_native.py"
    if hashlib.sha256(path.read_bytes()).hexdigest() != OWNER_SHA256:
        raise ValueError("native owner helper differs from reviewed implementation")
    spec = importlib.util.spec_from_file_location("trace_owned", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if hashlib.sha256(path.read_bytes()).hexdigest() != OWNER_SHA256:
        raise ValueError("native owner helper changed while loading")
    module.require_process_observation()
    return module


def run_native(name, argv, directory, env, timeout):
    owned = owner_runtime()
    job = None
    error = None
    try:
        job = owned.Job(name, argv, directory, env, timeout=timeout)
        owned.finish([job])
    except BaseException as caught:
        error = caught
    finally:
        if job is not None:
            try:
                job.kill()
            except BaseException as caught:
                error = error or caught
            for stream in (job.process.stdout, job.process.stderr):
                try:
                    stream.close()
                except BaseException as caught:
                    error = error or caught
            row = job.result()
            NATIVE_ROWS.append(row)
    if error is not None:
        raise error
    owned.require(all(row['cleanup'].values()) and row['failure'] is None,
                  'native fixture cleanup/execution incomplete')
    return SimpleNamespace(returncode=row['exit'], stdout=row['stdout'], stderr=row['stderr'])


@contextmanager
def retained_directory(prefix, admission):
    directory = pathlib.Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    first = len(NATIVE_ROWS)
    passed = False
    try:
        yield str(directory)
        passed = True
    finally:
        rows = NATIVE_ROWS[first:]
        if passed and admission['passed'] and rows and all(all(row['cleanup'].values()) for row in rows):
            shutil.rmtree(directory)
        else:
            RETAINED_ROOTS.append(str(directory))
            print(json.dumps({"retained_fixture_root": str(directory)}), file=sys.stderr, flush=True)



def extract(text, family, name):
    if family == "fish":
        pattern = rf"^function {re.escape(name)}(?:\s[^\n]*)?\n.*?^end\s*$"
    else:
        pattern = rf"^{re.escape(name)}\(\) \{{\n.*?^\}}\s*$"
    match = re.search(pattern, text, re.M | re.S)
    if not match and family != "fish":
        match = re.search(rf"^{re.escape(name)}\(\) \{{[^\n]+\}}$", text, re.M)
    if not match:
        raise ValueError(f"cannot find standalone function {name}")
    return match.group(0)


def shells():
    found = []
    for family in FILES:
        candidates = [shutil.which(family)]
        if family == "bash":
            candidates += ["/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash"]
        seen = set()
        for candidate in candidates:
            if candidate and os.access(candidate, os.X_OK):
                real = str(pathlib.Path(candidate).resolve())
                if real not in seen:
                    found.append((family, real))
                    seen.add(real)
    return found


def body(family, definition, invocation, executable, calls, trace):
    # All generated paths are private temporary fixtures. Shell quoting is
    # intentional; JSON quoting is never used to interpolate shell programs.
    exe = shlex.quote(str(executable))
    call_path = shlex.quote(str(calls))
    if family == "fish":
        setup = f"""
set -g _TIRITH_RECEIPT_PROTOCOL 3
set -g _TIRITH_V3_HELPERS_READY 1
set -g _TIRITH_RECEIPT_INSTANCE {CAPABILITY}
set -g _TIRITH_RECEIPT_SHELL_PID 123
set -g _TIRITH_RECEIPT_FAMILY fish
set -g _TIRITH_BIN {exe}
set -g _TIRITH_ENV_BIN /usr/bin/env
set -g _TIRITH_SH_BIN /bin/sh
set -gx TIRITH_TRACE_TEST_CALLS {call_path}
function _tirith_verification_state
    builtin printf 'tirith-loaded-shell-v1\\n{LOADED_STATE}\\nprotocol=3 protection=blocks bypass=1\\n'
end
{definition}
set -e fish_trace
{'set -g fish_trace 1' if trace else ''}
{invocation}
set -l test_result $status
if set -q fish_trace; and test -n "$fish_trace"
    builtin printf 'TIRITH_TEST_TRACE_STATE=on\\n'
else
    builtin printf 'TIRITH_TEST_TRACE_STATE=off\\n'
end
set -e fish_trace
builtin printf 'TIRITH_TEST_RESULT=%s\\n' "$test_result"
"""
    else:
        setup = f"""
_TIRITH_RECEIPT_PROTOCOL=3
_TIRITH_V3_HELPERS_READY=1
_TIRITH_RECEIPT_INSTANCE={CAPABILITY}
_TIRITH_RECEIPT_SHELL_PID=123
_TIRITH_RECEIPT_FAMILY={family}
_TIRITH_BIN={exe}
_TIRITH_ENV_BIN=/usr/bin/env
_TIRITH_SH_BIN=/bin/sh
TIRITH_TRACE_TEST_CALLS={call_path}
export TIRITH_TRACE_TEST_CALLS
_tirith_verification_state() {{ builtin printf 'tirith-loaded-shell-v1\\n{LOADED_STATE}\\nprotocol=3 protection=blocks bypass=1\\n'; }}
_tirith_receipt_parent_context_is_valid() {{ return 0; }}
_tirith_open_exact_input_pipe() {{ exec 9</dev/null; _TIRITH_OPENED_FD=9; }}
_tirith_close_pending_fd() {{ exec 9<&-; }}
{definition}
set {'-x' if trace else '+x'}
{invocation}
test_result=$?
if [[ $- == *x* ]]; then builtin printf 'TIRITH_TEST_TRACE_STATE=on\\n'; else builtin printf 'TIRITH_TEST_TRACE_STATE=off\\n'; fi
set +x
builtin printf 'TIRITH_TEST_RESULT=%s\\n' "$test_result"
"""
    return setup


def run_case(family, shell, tree, function, trace, operation_exit=0, ack_exit=0):
    source = (tree / FILES[family]).read_text()
    definition = extract(source, family, function)
    if family == "bash":
        definition = "\n".join([
            extract(source, family, "_tirith_trace_preserve_status"),
            extract(source, family, function + "_untraced"), definition,
        ])
    if function != "_tirith_verification_probe":
        ack_name = "_tirith_receipt_acknowledge_untraced" if family == "bash" else "_tirith_receipt_acknowledge_at"
        definition += "\n" + extract(source, family, ack_name)
    if function == "_tirith_verification_probe":
        invocation = f"{function} start"
    elif family == "bash":
        invocation = f"{function} bash-preexec ordinary-test-token"
        if function == "_tirith_receipt_consume":
            invocation += " true"
    else:
        invocation = f"{function} ordinary-test-token"
        if function == "_tirith_receipt_consume_at":
            invocation += " true"
        invocation += " /"
    admission = {"passed": False}
    with retained_directory(prefix="tirith-shell-trace-", admission=admission) as temp:
        directory = pathlib.Path(temp)
        executable = directory / "fake-tirith"
        calls = directory / "calls"
        executable.write_text(
            "#!/bin/sh\n"
            "test \"$_TIRITH_RECEIPT_INSTANCE\" = " + shlex.quote(CAPABILITY) + " || exit 91\n"
            "printf '%s\\n' \"$2\" >> \"$TIRITH_TRACE_TEST_CALLS\"\n"
            "if test \"$2\" = acknowledge; then exit " + str(ack_exit) + "; fi\n"
            "exit " + str(operation_exit) + "\n"
        )
        executable.chmod(0o700)
        script = body(family, definition, invocation, executable, calls, trace)
        result = run_native("trace-helper", [shell, "-c", script], directory,
                            {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(directory), "LC_ALL": "C"}, 10)
        expected_calls = ["start"] if function == "_tirith_verification_probe" else [function.split("_receipt_")[1].split("_")[0]]
        if function != "_tirith_verification_probe" and operation_exit == 0:
            expected_calls.append("acknowledge")
        invoked = calls.exists() and calls.read_text().splitlines() == expected_calls
        output = result.stdout + result.stderr
        expected_state = "on" if trace else "off"
        status = re.search(r"^TIRITH_TEST_RESULT=(\d+)$", result.stdout, re.M)
        checks = {
            "shell_completed": result.returncode == 0,
            "capability_absent": CAPABILITY not in output,
            "loaded_state_absent_from_trace": LOADED_STATE not in result.stderr,
            "trace_restored": f"TIRITH_TEST_TRACE_STATE={expected_state}" in result.stdout,
            "exact_calls_in_order": invoked,
            "result": bool(status) and status[1] == str(operation_exit),
        }
        admission["passed"] = all(checks.values())
        return {"shell": shell, "family": family, "source": str(tree.relative_to(ROOT)),
                "function": function, "trace": trace, "operation_exit": operation_exit, "ack_exit": ack_exit,
                "passed": all(checks.values()), "checks": checks}


def run_registration(family, shell, tree, trace, inherited_export=False):
    capability = "45bcb43f30d36c8e1b50d2ecfc3c3ffb8fce9bced081bd331e572e49232402fa"
    admission = {"passed": False}
    with retained_directory(prefix="tirith-shell-registration-trace-", admission=admission) as temp:
        directory = pathlib.Path(temp)
        calls = directory / "register-calls"
        executable = directory / "fake-tirith"
        executable.write_text(
            "#!/bin/sh\ncase \"$1 $2\" in\n"
            "'__execution-receipt capability') printf 'TIRITH_EXECUTION_RECEIPT_PROTOCOL=3\\n';;\n"
            "'__execution-receipt register') printf '%s\\n' " + shlex.quote(capability) + "; "
            "printf 'registered\\n' >> " + shlex.quote(str(calls)) + ";;\n"
            "'check-export ') if test \"${_TIRITH_RECEIPT_INSTANCE+x}\" = x; then "
            "printf 'TIRITH_TEST_CAPABILITY_EXPORTED=yes\\n'; else printf 'TIRITH_TEST_CAPABILITY_EXPORTED=no\\n'; fi;;\n"
            "*) :;;\nesac\n"
        )
        executable.chmod(0o700)
        source = shlex.quote(str(tree / FILES[family]))
        executable_arg = shlex.quote(str(executable))
        if family == "fish":
            options = ["--no-config", "-i", "-c"]
            script = f"""
set -e fish_trace
{'set -g fish_trace 1' if trace else ''}
source {source} --tirith-executable {executable_arg}
command {executable_arg} check-export
builtin printf 'TIRITH_TEST_REGISTRATION=%s\\n' "$_TIRITH_RECEIPT_PROTOCOL"
if set -q fish_trace; and test -n "$fish_trace"
    builtin printf 'TIRITH_TEST_TRACE_STATE=on\\n'
else
    builtin printf 'TIRITH_TEST_TRACE_STATE=off\\n'
end
set -e fish_trace
builtin true
"""
        else:
            options = ["--noprofile", "--norc", "-i", "-c"] if family == "bash" else ["-d", "-f", "-i", "-c"]
            script = f"""
set {'-x' if trace else '+x'}
source {source} --tirith-executable {executable_arg}
command {executable_arg} check-export
builtin printf 'TIRITH_TEST_REGISTRATION=%s\\n' "$_TIRITH_RECEIPT_PROTOCOL"
if [[ $- == *x* ]]; then builtin printf 'TIRITH_TEST_TRACE_STATE=on\\n'; else builtin printf 'TIRITH_TEST_TRACE_STATE=off\\n'; fi
set +x
"""
        env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(directory),
               "XDG_CONFIG_HOME": str(directory / "config"), "XDG_DATA_HOME": str(directory / "data"),
               "XDG_STATE_HOME": str(directory / "state"), "TMPDIR": str(directory),
               "ZDOTDIR": str(directory), "TERM": "xterm", "LC_ALL": "C"}
        if inherited_export:
            env["_TIRITH_RECEIPT_INSTANCE"] = "preexported-controlled-placeholder"
        result = run_native("trace-registration", [shell, *options, script], directory, env, 15)
        expected_state = "on" if trace else "off"
        checks = {
            "shell_completed": result.returncode == 0,
            "capability_absent": capability not in result.stdout + result.stderr,
            "registered_once": calls.exists() and calls.read_text() == "registered\n",
            "protocol_active": "TIRITH_TEST_REGISTRATION=3" in result.stdout,
            "not_globally_exported": "TIRITH_TEST_CAPABILITY_EXPORTED=no" in result.stdout,
            "trace_restored": f"TIRITH_TEST_TRACE_STATE={expected_state}" in result.stdout,
        }
        admission["passed"] = all(checks.values())
        return {"shell": shell, "family": family, "source": str(tree.relative_to(ROOT)),
                "function": "full_source_registration", "trace": trace, "inherited_export": inherited_export,
                "passed": all(checks.values()), "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-shell", action="append", choices=FILES, default=[])
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    available = shells()
    missing = set(args.require_shell) - {family for family, _ in available}
    if missing:
        parser.error("required native shells missing: " + ", ".join(sorted(missing)))
    if not available:
        parser.error("no supported native shells available")
    failures = 0
    cases = 0
    values = []
    snapshots = {p: owner_runtime().file_sha(p) for p in [pathlib.Path(__file__), ROOT / "tools/qualification/mixed_audit_native.py", *[ROOT / tree / file for tree in ("shell/lib", "crates/tirith/assets/shell/lib") for file in FILES.values()], *[pathlib.Path(path) for _, path in available]]}
    for family, shell in available:
        functions = ["_tirith_verification_probe"]
        functions += [f"_tirith_receipt_{kind}{'' if family == 'bash' else '_at'}"
                      for kind in ["consume", "reconcile", "discard"]]
        for tree in [ROOT / "shell/lib", ROOT / "crates/tirith/assets/shell/lib"]:
            for function in functions:
                for trace in [False, True]:
                    outcomes = [(0, 0)] if function == "_tirith_verification_probe" else [(0, 0), (0, 99), (7, 0)]
                    for operation_exit, ack_exit in outcomes:
                        value = run_case(family, shell, tree, function, trace, operation_exit, ack_exit)
                        print(json.dumps(value), flush=True)
                        values.append(value)
                        cases += 1
                        failures += not value["passed"]
            for trace in [False, True]:
                for inherited in [False, True]:
                    value = run_registration(family, shell, tree, trace, inherited)
                    print(json.dumps(value), flush=True)
                    values.append(value)
                    cases += 1
                    failures += not value["passed"]
    for path, digest in snapshots.items():
        owner_runtime().require(owner_runtime().file_sha(path) == digest, "trace input changed during run")
    if args.report:
        args.report.write_text(json.dumps({"cases": values, "failures": failures, "native_processes": NATIVE_ROWS, "retained_roots": RETAINED_ROOTS, "inputs": {str(p): d for p, d in snapshots.items()}}, indent=2) + "\n")
    print(json.dumps({"cases": cases, "failures": failures,
                      "capabilities": "controlled_fake_values_only"}))
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
