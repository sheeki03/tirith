#!/usr/bin/env python3
"""Native privacy regressions using inert endpoints and isolated startup roots.

These exercise actual hook source/functions, not receipt authority or interception.
No Tirith binary, user startup files, signing keys, or services are used.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


owned = load("private_owned_process", ROOT / "tools/qualification/mixed_audit_native.py")
trace = load("private_hook_extract", ROOT / "tests/shell-trace-capability.py")
CAP = "c" * 64
TOKEN = "d" * 64
STATE = "inert-private-state-8e52ae99"
COMMAND = "printf inert-private-command-e320ce6e"
OBSERVED_EVENTS = []
PLACEHOLDERS = ("buf", "scan_target", "pending_eval", "pending_command", "pending_receipt", "expected",
                "command_text", "line", "state", "token", "receipt_token", "candidate_token",
                "receipt_line", "_tirith_verification_capture", "verification_capture",
                "output", "check_stdout", "bash_cmd", "history_line", "history_key", "entry",
                "dedupe_key", "_tirith_last_cmd", "_TIRITH_PREEXEC_BLOCK_HISTORY_KEY",
                "_user_bash_command", "_TIRITH_RECEIPT_INSTANCE", "_TIRITH_CAPTURE_LINE",
                "_TIRITH_PARSED_RECEIPT", "_TIRITH_PENDING_RECEIPT", "_TIRITH_PENDING_COMMAND")
CLEANUP = {"leader_reaped", "group_signaled_or_absent", "group_members_exited", "output_eof"}


class Fixture:
    def __init__(self, root, family, shell, source, mode="allow", verification=False, operation_exit=0, ack_exit=0):
        self.root, self.family, self.shell, self.source = root, family, shell, source
        self.mode, self.verification = mode, verification
        self.operation_exit, self.ack_exit = operation_exit, ack_exit
        self.command = "_tirith_verification_probe inert-private-command-e320ce6e allowed" if verification else COMMAND
        interpreter = str(Path(sys.executable).resolve())
        owned.require(not any(c.isspace() for c in interpreter), "fixture interpreter needs a simple shebang path")
        observer = root / "observer"
        observer.write_text("#!" + interpreter + "\n" + f'''import json,os,sys,tempfile
from pathlib import Path
root=Path({str(root)!r});role=Path(sys.argv[0]).name;args=sys.argv[1:]
cap={CAP!r};token={TOKEN!r};state={STATE!r};command={self.command!r};issues=[]
receipt=role=='tirith' and args[:1]==['__execution-receipt'] and len(args)>1 and args[1] in ('consume','discard','reconcile','acknowledge')
checker=role=='tirith' and args[:1]==['check']
module_check=role=='tirith' and args==['__setup-activation','modules','--channel','zsh']
intended=receipt or checker or module_check
for name,value in os.environ.items():
 if cap in value and not (intended and name=='_TIRITH_RECEIPT_INSTANCE' and value==cap):issues.append(name)
 if token in value or state in value or command in value:issues.append(name)
if intended and os.environ.get('_TIRITH_RECEIPT_INSTANCE')!=cap:issues.append('missing-instance')
data=sys.stdin.buffer.read(262145) if role=='wc' or receipt or (checker and {verification!r}) else b''
with open(root/'events','a') as out:out.write(json.dumps({{'role':role,'args':args,'issues':issues,'stdin':data.decode()}})+'\\n')
if role=='mktemp':
 fd,name=tempfile.mkstemp(dir=root);os.close(fd);print(name)
elif role=='rm':
 for arg in args:
  if arg.startswith('-'):continue
  path=Path(arg)
  if path.parent!=root:raise SystemExit(71)
  path.unlink(missing_ok=True)
elif role=='wc':
 if args==['-c']:print(len(data))
 elif args==['-l']:print(data.count(b'\\n'))
 else:raise SystemExit(72)
elif role=='tirith':
 if checker:
  if args[-1]!=command:raise SystemExit(73)
  if {mode!r}!='block':print('TIRITH_EXECUTION_RECEIPT='+token)
  raise SystemExit({{'allow':0,'block':1,'malformed':42}}[{mode!r}])
 if args[:2]==['__execution-receipt','capability']:print('TIRITH_EXECUTION_RECEIPT_PROTOCOL=3')
 elif args[:2]==['__execution-receipt','register']:print(cap)
 elif module_check:raise SystemExit(74) # Inert endpoint never qualifies or loads native modules.
 elif receipt:raise SystemExit({ack_exit!r} if args[1]=='acknowledge' else {operation_exit!r})
 elif args[:2]==['env','snapshot']:pass
 else:raise SystemExit(74)
elif role!='ordinary':raise SystemExit(75)
''')
        observer.chmod(0o700)
        for role in ("tirith", "wc", "rm", "mktemp", "ordinary"):
            os.link(observer, root / role)

    def q(self, value):
        return shlex.quote(str(value))

    def definitions(self, names):
        return "\n".join(trace.extract(self.source, self.family, name) for name in names)

    def run(self, name, script, interactive=False):
        if self.family == "fish":
            options = ["--no-config"]
        else:
            options = ["--noprofile", "--norc"] if self.family == "bash" else ["-d", "-f"]
        if interactive:
            options.append("-i")
        environment = {"HOME": str(self.root), "ZDOTDIR": str(self.root), "TMPDIR": str(self.root),
                       "PATH": "/usr/bin:/bin", "TERM": "xterm", "LANG": "C", "LC_ALL": "C"}
        environment.update({"XDG_" + kind + "_HOME": str(self.root / kind.lower())
                            for kind in ("CONFIG", "STATE", "DATA", "CACHE")})
        environment.update({name: "inert-exported-placeholder" for name in PLACEHOLDERS})
        trace.run_native(name, [self.shell, *options, "-c", script], self.root, environment, 8)
        row = trace.NATIVE_ROWS[-1]
        owned.require(set(row.get("cleanup", {})) == CLEANUP and
                      all(value is True for value in row["cleanup"].values()), "owned cleanup incomplete")
        owned.success(row)
        events = [json.loads(line) for line in (self.root / "events").read_text().splitlines()]
        OBSERVED_EVENTS.append({"fixture_root": str(self.root), "name": name, "events": events})
        owned.require(all(not item["issues"] for item in events),
                      "private environment or intended instance mismatch: " +
                      str([(item["role"], item["issues"]) for item in events if item["issues"]]))
        owned.require(all(value not in row["stdout"] + row["stderr"] for value in (CAP, TOKEN, STATE)),
                      "private sentinel reached output")
        return row, events

    def ordinary(self):
        return "command " + self.q(self.root / "ordinary")

    def setup(self):
        values = {"_TIRITH_RECEIPT_PROTOCOL": "3", "_TIRITH_RECEIPT_INSTANCE": CAP,
                  "_TIRITH_RECEIPT_FAMILY": self.family, "_TIRITH_V3_HELPERS_READY": "1",
                  "_TIRITH_BIN": self.root / "tirith", "_TIRITH_WC_BIN": self.root / "wc",
                  "_TIRITH_RM_BIN": self.root / "rm", "_TIRITH_MKTEMP_BIN": self.root / "mktemp",
                  "_TIRITH_ENV_BIN": "/usr/bin/env", "_TIRITH_SH_BIN": "/bin/sh"}
        if self.family == "fish":
            return "\n".join("set -gu " + key + " " + self.q(value) for key, value in values.items()) + "\nset -g _TIRITH_RECEIPT_SHELL_PID $fish_pid\n"
        return ("builtin unset _TIRITH_RECEIPT_INSTANCE _TIRITH_CAPTURE_LINE _TIRITH_PARSED_RECEIPT\n" +
                "\n".join(key + "=" + self.q(value) for key, value in values.items()) +
                "\n_TIRITH_RECEIPT_SHELL_PID=$$\n")


def startup(fixture):
    path = fixture.root / trace.FILES[fixture.family]
    path.write_text(fixture.source)
    source = "source " + fixture.q(path) + " --tirith-executable " + fixture.q(fixture.root / "tirith")
    if fixture.family == "fish":
        script = f"{source}\n{fixture.ordinary()}\n{source}\n{fixture.ordinary()}\nbuiltin printf 'PROTOCOL=%s\\n' $_TIRITH_RECEIPT_PROTOCOL\nbuiltin true\n"
    else:
        script = f"set -a\n{source}\n{fixture.ordinary()}\n{source}\n{fixture.ordinary()}\nbuiltin printf 'PROTOCOL=%s\\n' $_TIRITH_RECEIPT_PROTOCOL\n[[ $- == *a* ]] && builtin printf 'EXPORT=on\\n'\nbuiltin true\n"
    row, events = fixture.run("startup", script, interactive=True)
    owned.require(row["stdout"].splitlines() == (["PROTOCOL=3"] if fixture.family == "fish" else ["PROTOCOL=3", "EXPORT=on"]), "startup option/protocol changed")
    owned.require(sum(item["args"][:2] == ["__execution-receipt", "register"] for item in events) == 1, "missing or duplicate registration")
    owned.require(sum(item["role"] == "ordinary" for item in events) == 2, "ordinary child observers missing")


def module_consumer_boundary(fixture):
    """Only the exact module-qualification argv may receive the instance."""
    attempts = [
        ["__setup-activation", "modules", "--channel", "zsh", "extra"],
        ["__setup-activation", "modules", "--channel", "bash"],
        ["__setup-activation", "probe", "allowed"],
    ]
    for index, args in enumerate(attempts):
        directory = fixture.root / str(index)
        directory.mkdir(mode=0o700)
        negative = Fixture(directory, fixture.family, fixture.shell, fixture.source)
        command = "command " + negative.q(directory / "tirith") + " " + " ".join(negative.q(arg) for arg in args)
        script = "_TIRITH_RECEIPT_INSTANCE=" + negative.q(CAP) + " " + command + "\nbuiltin true\n"
        try:
            negative.run("module-consumer-negative", script)
        except AssertionError as error:
            owned.require("private environment or intended instance mismatch" in str(error)
                          and "_TIRITH_RECEIPT_INSTANCE" in str(error),
                          "negative control failed for an unrelated reason")
        else:
            raise AssertionError("non-exact automatic argv accepted a private instance")


def checker(fixture, outer_preexec=False):
    if fixture.family == "bash":
        names = ["_tirith_trace_preserve_status", "_tirith_preexec_receipt_check", "_tirith_preexec_receipt_check_untraced",
                 "_tirith_new_capture_file", "_tirith_capture_file_is_private", "_tirith_remove_capture_file",
                 "_tirith_read_single_capture_line", "_tirith_parse_v3_receipt_response",
                 "_tirith_fixed_fd_is_valid", "_tirith_open_exact_input_pipe", "_tirith_close_pending_fd"]
        names.append("_tirith_receipt_acknowledge_untraced")
        names += ["_tirith_receipt_" + kind + suffix for kind in ("consume", "discard", "reconcile") for suffix in ("", "_untraced")]
        if outer_preexec:
            names.append("_tirith_preexec")
        stubs = f"""_tirith_receipt_parent_context_is_valid() {{ return 0; }}
_tirith_verification_state() {{ builtin printf '%s\\n' {fixture.q(STATE)}; }}
_tirith_read_history_entry() {{ builtin printf '2|%s\\n' {fixture.q(fixture.command)}; }}
_tirith_output() {{ :; }}
_TIRITH_PREEXEC_PHASE=user
_TIRITH_PREEXEC_ENFORCE=0
_TIRITH_PREEXEC_RECEIPTS_TRUSTED=1
"""
        invoke = "_tirith_preexec 12 1 " + fixture.q(fixture.command) if outer_preexec else "_tirith_preexec_receipt_check " + fixture.q(fixture.command) + " no"
    elif fixture.family == "zsh":
        names = ["_tirith_accept_line", "_tirith_v3_new_capture_file", "_tirith_v3_remove_capture_files",
                 "_tirith_receipt_acknowledge_at", "_tirith_receipt_consume_at", "_tirith_receipt_discard_at", "_tirith_receipt_reconcile_at",
                 "_tirith_receipt_discard_or_retain", "_tirith_unresolved_receipt_cleanup"]
        stubs = f"""BUFFER={fixture.q(fixture.command)}
unset _TIRITH_UNRESOLVED_RECEIPT
_tirith_verification_state() {{ builtin printf '%s\\n' {fixture.q(STATE)}; }}
_tirith_output() {{ :; }}
_tirith_escape_preview() {{ builtin printf '%s' "$1"; }}
zle() {{ builtin printf '%s\\n' "$*" >> {fixture.q(fixture.root / 'editor')}; }}
"""
        invoke = "_tirith_accept_line"
    else:
        names = ["_tirith_check_command", "_tirith_receipt_acknowledge_at", "_tirith_receipt_consume_at", "_tirith_receipt_discard_at", "_tirith_receipt_reconcile_at", "_tirith_receipt_discard_or_retain", "_tirith_unresolved_receipt_cleanup"]
        stubs = f"""function commandline
 if test (count $argv) -eq 0; builtin printf '%s\\n' {fixture.q(fixture.command)}
 else; builtin printf '%s\\n' "$argv" >> {fixture.q(fixture.root / 'editor')}; end
end
function _tirith_v3_new_capture_file; command {fixture.q(fixture.root / 'mktemp')}; end
function _tirith_v3_remove_capture_files; command {fixture.q(fixture.root / 'rm')} -f -- $argv; end
function _tirith_output; return 0; end
function _tirith_escape_preview; builtin printf '%s' "$argv[1]"; end
function _tirith_verification_state; builtin printf '%s\\n' {fixture.q(STATE)}; end
"""
        invoke = "_tirith_check_command"
    if fixture.family == "fish":
        tail = f"{invoke}\nset -l result $status\n{fixture.ordinary()}\nbuiltin printf 'RESULT=%s\\n' $result\nbuiltin true\n"
    else:
        tail = f"set -a\n{invoke}\nresult=$?\n[[ $- == *a* ]] && builtin printf 'EXPORT=on\\n'\n{fixture.ordinary()}\nbuiltin printf 'RESULT=%s\\n' $result\nbuiltin true\n"
    row, events = fixture.run("checker", fixture.setup() + fixture.definitions(names) + "\n" + stubs + tail)
    code = 0 if fixture.family == "zsh" or fixture.mode == "allow" or outer_preexec else 1
    expected = (["EXPORT=on"] if fixture.family != "fish" else []) + ["RESULT=" + str(code)]
    owned.require(row["stdout"].splitlines() == expected, "checker status/export changed")
    checks = [item for item in events if item["role"] == "tirith" and item["args"][:1] == ["check"]]
    owned.require(len(checks) == 1 and checks[0]["args"][-1] == fixture.command and checks[0]["stdin"] == (STATE + "\n" if fixture.verification else ""), "checker command/state bytes changed")
    expected_wc = 2 if fixture.family != "bash" else 0 if fixture.mode == "block" else 1
    counts = {role: sum(item["role"] == role for item in events) for role in ("mktemp", "wc", "rm", "ordinary")}
    owned.require(counts == {"mktemp": 1 if fixture.family == "bash" else 2, "wc": expected_wc, "rm": 1, "ordinary": 1}, "required helper observers missing: " + str(counts))
    receipts = [(item["args"][1], item["stdin"]) for item in events if item["role"] == "tirith" and item["args"][:1] == ["__execution-receipt"]]
    expected = [] if fixture.mode == "block" else [("consume", TOKEN + "\n" + fixture.command), ("acknowledge", TOKEN)] if fixture.mode == "allow" else [("discard", TOKEN), ("acknowledge", TOKEN)]
    owned.require(receipts == expected, "receipt operation/bytes changed: " + repr(receipts))
    if fixture.family != "bash":
        editor = (fixture.root / "editor").read_text()
        expected = (".accept-line\n" if fixture.mode == "allow" else "send-break\n") if fixture.family == "zsh" else ("-f execute\n" if fixture.mode == "allow" else "-r \n-f repaint\n")
        owned.require(editor == expected, "inert editor effect changed")


def receipt_operation(fixture, operation):
    if fixture.family == "bash":
        names = ["_tirith_trace_preserve_status", "_tirith_fixed_fd_is_valid", "_tirith_open_exact_input_pipe", "_tirith_close_pending_fd",
                 "_tirith_receipt_acknowledge_untraced", "_tirith_receipt_" + operation, "_tirith_receipt_" + operation + "_untraced"]
        body = "_tirith_receipt_parent_context_is_valid() { return 0; }\nset -a\n"
        call = "_tirith_receipt_" + operation + " bash-preexec " + fixture.q(TOKEN)
    else:
        names = ["_tirith_receipt_acknowledge_at", "_tirith_receipt_" + operation + "_at"]
        body = "set -a\n" if fixture.family == "zsh" else ""
        call = "_tirith_receipt_" + operation + "_at " + fixture.q(TOKEN)
    if operation == "consume":
        call += " " + fixture.q(COMMAND)
    if fixture.family != "bash":
        call += " " + fixture.q(fixture.root)
    tail = ("set -l result $status\n" if fixture.family == "fish" else "result=$?\n")
    script = fixture.setup() + fixture.definitions(names) + "\n" + body + call + "\n" + tail + fixture.ordinary() + "\nbuiltin printf 'RESULT=%s\\n' $result\nbuiltin true\n"
    row, events = fixture.run("receipt-operation", script)
    owned.require(row["stdout"].splitlines() == ["RESULT=" + str(fixture.operation_exit)], "ACK changed original receipt status")
    receipts = [(item["args"][1], item["stdin"]) for item in events if item["role"] == "tirith"]
    expected = [(operation, TOKEN + ("\n" + COMMAND if operation == "consume" else ""))]
    if fixture.operation_exit == 0:
        expected.append(("acknowledge", TOKEN))
    owned.require(receipts == expected, "ACK order or frame mismatch")
    owned.require(sum(item["role"] == "ordinary" for item in events) == 1, "ordinary child missing")


def prompt(fixture, initial, choice):
    final = initial if choice == "unchanged" else choice == "on"
    user = (("set -a; " if final else "set +a; ") if choice != "unchanged" else "")
    user += "TIRITH_USER_VALUE=inert-user-value; command " + fixture.q(fixture.root / "user-observer")
    (fixture.root / "user-observer").write_text('#!/bin/sh\ncase "${pending_eval:-}|${pending_command:-}|${pending_receipt:-}" in *inert-user-value*) exit 71;;esac\nif test "${TIRITH_USER_VALUE+x}" = x; then printf "USER=present\\n";else printf "USER=absent\\n";fi\n')
    (fixture.root / "user-observer").chmod(0o700)
    defs = fixture.definitions(("_tirith_trace_preserve_status", "_tirith_prompt_hook_untraced", "_tirith_prompt_hook"))
    script = f"_TIRITH_RECEIPT_PROTOCOL=0\nunset _TIRITH_PENDING_RECEIPT\n_TIRITH_PENDING_EVAL={fixture.q(user)}\n_TIRITH_PENDING_COMMAND={fixture.q(user)}\n{defs}\nset {'-a' if initial else '+a'}\n_tirith_prompt_hook\nresult=$?\nif [[ $- == *a* ]];then builtin printf 'EXPORT=on\\n';else builtin printf 'EXPORT=off\\n';fi\n{fixture.ordinary()}\nbuiltin printf 'RESULT=%s\\n' $result\nbuiltin true\n"
    row, events = fixture.run("deferred-eval", script)
    owned.require(row["stdout"].splitlines() == ["USER=" + ("present" if final else "absent"), "EXPORT=" + ("on" if final else "off"), "RESULT=0"], "user assignment or option behavior changed")
    owned.require(len(events) == 1 and events[0]["role"] == "ordinary", "ordinary observer missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-shell", action="append", choices=trace.FILES, default=[])
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    available = trace.shells()
    missing = set(args.require_shell) - {family for family, _ in available}
    if not available or missing:
        parser.error("required native shells missing: " + ", ".join(sorted(missing)))
    owned.require_process_observation()
    sources = {}
    snapshots = {p: owned.file_sha(p) for p in (Path(__file__), ROOT / "tests/shell-trace-capability.py", ROOT / "tools/qualification/mixed_audit_native.py", Path(sys.executable).resolve())}
    for family, filename in trace.FILES.items():
        source = ROOT / "shell/lib" / filename
        embedded = ROOT / "crates/tirith/assets/shell/lib" / filename
        data = owned.read_bytes(source)
        owned.require(data == owned.read_bytes(embedded), "source/embedded hook mismatch: " + family)
        sources[family] = data.decode()
        snapshots.update({source: owned.sha(data), embedded: owned.sha(data)})
    snapshots.update({Path(path): owned.file_sha(Path(path)) for _, path in available})
    cases, failures = 0, []
    admission = {"passed": False}
    with trace.retained_directory(prefix="tirith-private-env-", admission=admission) as temporary:
        parent = Path(temporary).resolve()
        for family, shell in available:
            plans = [("startup", startup, {})]
            plans += [(f"checker-{mode}-{verify}", checker, {"mode": mode, "verification": verify})
                      for mode in ("allow", "block", "malformed") for verify in (False, True)]
            plans += [(f"receipt-{operation}-{operation_exit}-{ack_exit}", lambda f, op=operation: receipt_operation(f, op), {"operation_exit": operation_exit, "ack_exit": ack_exit})
                      for operation in ("consume", "discard", "reconcile") for operation_exit, ack_exit in ((0, 0), (0, 99), (7, 0))]
            if family == "zsh":
                plans.append(("module-consumer-boundary", module_consumer_boundary, {}))
            if family == "bash":
                plans.append(("preexec-command-cache", lambda f: checker(f, outer_preexec=True), {}))
                plans += [(f"deferred-{initial}-{choice}", lambda f, i=initial, c=choice: prompt(f, i, c), {})
                          for initial in (False, True) for choice in ("unchanged", "on", "off")]
            for name, run, options in plans:
                cases += 1
                directory = parent / str(cases)
                directory.mkdir(mode=0o700)
                try:
                    run(Fixture(directory, family, shell, sources[family], **options))
                    print(json.dumps({"shell": shell, "case": name, "passed": True}), flush=True)
                except (AssertionError, RuntimeError, OSError, ValueError) as error:
                    failures.append({"shell": shell, "case": name, "error": str(error)[:2000]})
        admission["passed"] = not failures
    for path, digest in snapshots.items():
        owned.require(owned.file_sha(path) == digest, "source/executable changed during regression run")
    if args.report:
        args.report.write_text(json.dumps({"cases": cases, "failures": failures, "native_processes": trace.NATIVE_ROWS, "observed_events": OBSERVED_EVENTS, "retained_roots": trace.RETAINED_ROOTS, "inputs": {str(p): d for p, d in snapshots.items()}}, indent=2) + "\n")
    print(json.dumps({"cases": cases, "failures": failures, "scope": "inert privacy fixtures only"}), flush=True)
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
