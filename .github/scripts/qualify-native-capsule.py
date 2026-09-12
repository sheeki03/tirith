#!/usr/bin/env python3
"""Native installed-binary checks, separate from filter-only and QEMU evidence."""
import argparse, hashlib, json, os, pathlib, re, subprocess, time

IMAGE = "debian:12-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"
WRAPPER = r'''
set -u
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/home" "$fixture/config" "$fixture/data" "$fixture/state" "$fixture/project" "$fixture/outside"
cp /usr/bin/tirith-qualification-probe "$fixture/project/probe"
printf 'reviewed project\n' > "$fixture/project/README.md"
printf 'must remain\n' > "$fixture/outside/protected"
case_name=$1
shift
if [ "$case_name" = filesystem ]; then set -- "$@" "$fixture/project/README.md" "$fixture/outside/protected"; fi
cd "$fixture/project"
if [ "$case_name" = inherited ]; then
  set -- /usr/bin/tirith-qualification-probe driver-inherit "$fixture/outside/protected" /binary/tirith capsule run --format json --project "$fixture/project" -- "$@"
else
  set -- /binary/tirith capsule run --format json --project "$fixture/project" -- "$@"
fi
HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/config" XDG_DATA_HOME="$fixture/data" XDG_STATE_HOME="$fixture/state" TIRITH_OFFLINE=1 TIRITH_LOG=0 GITHUB_TOKEN=qualification_secret_must_not_reach_child \
 "$@"
code=$?
if [ -e "$fixture/project/written.txt" ]; then echo 'ERROR: original project changed' >&2; exit 98; fi
if [ "$(cat "$fixture/outside/protected")" != 'must remain' ]; then echo 'ERROR: outside target changed' >&2; exit 99; fi
exit "$code"
'''

def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',type=pathlib.Path,required=True)
    parser.add_argument('--probe',type=pathlib.Path,required=True)
    parser.add_argument('--cancellation-probe',type=pathlib.Path,required=True)
    parser.add_argument('--snapshot-sha256',required=True)
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--artifact-sha256')
    parser.add_argument('--target', choices=['aarch64-unknown-linux-gnu','aarch64-unknown-linux-musl'])
    args=parser.parse_args()
    for digest in [args.snapshot_sha256, args.artifact_sha256]:
        if digest is not None and re.fullmatch(r'[0-9a-f]{64}', digest) is None:
            raise SystemExit('source and artifact digests must be lowercase SHA256 values')
    engine_arch=subprocess.check_output(['docker','info','--format','{{.Architecture}}'],text=True).strip()
    if engine_arch not in {'aarch64','arm64'}:
        raise SystemExit('requires a native ARM Docker engine; QEMU is not qualification')
    binary=args.binary.resolve(); probe=args.probe.resolve()
    base=['docker','run','--rm','--platform','linux/arm64','--network','none','--user','65534:65534','--tmpfs','/nonexistent:rw,nosuid,nodev,mode=0700,uid=65534,gid=65534','--cpus','1','--memory','768m','--pids-limit','512','-v',f'{binary}:/binary/tirith:ro','-v',f'{probe}:/usr/bin/tirith-qualification-probe:ro',IMAGE]
    kernel=subprocess.check_output(base+['uname','-m','-r'],text=True).strip()
    if not kernel.endswith('aarch64'): raise SystemExit('requires native aarch64 Docker kernel')
    version=subprocess.check_output(base+['/binary/tirith','--version'],text=True).strip()
    results=[]
    tests=[('clean',['/bin/sh','-c','set -C; printf marker > written.txt'],0,0),('child_status',['/bin/sh','-c','exit 7'],3,7),('sleep',['/bin/sleep','0.01'],0,0)]
    tests.extend((case,['./probe',case],0,0) for case in ['network','escape','filesystem','resources','process_limit','readiness','fork','inherited'])
    tests.append(('output',['./probe','output'],None,None))
    for name,command,expected_status,child_status in tests:
        started=time.monotonic()
        result=subprocess.run(base+['/bin/sh','-c',WRAPPER,'qualification',name,*command],capture_output=True,text=True,timeout=180)
        try: value=json.loads(result.stdout)
        except Exception: value={'invalid_stdout':result.stdout[-4000:]}
        checks={
            'status':value.get('status')==('partial' if name=='output' else 'contained'),
            'cleanup_confirmed':value.get('cleanup_confirmed') is True,
            'raw_network_denied':value.get('achieved_coverage',{}).get('network_raw_denied') is True,
            'required_controls':all(value.get('achieved_coverage',{}).get(key) is True for key,required in value.get('requested_coverage',{}).items() if required),
            'native_backend':value.get('backend')=='landlock-seccomp' and value.get('platform')=='linux/aarch64',
        }
        if name=='output':
            checks['output_terminated']=value.get('termination_kind')=='OutputLimit' and value.get('tirith_decision')=='terminated_by_tirith' and result.returncode==1
        else:
            checks['exit_status']=result.returncode==expected_status
            checks['child_status']=value.get('child_exit_code')==child_status
            checks['target_completed']=value.get('tirith_decision')=='target_completed'
        item={'case':name,'passed':all(checks.values()),'checks':checks,'returncode':result.returncode,'seconds':round(time.monotonic()-started,3),'receipt':value,'stderr':result.stderr[-4000:]}
        results.append(item)
        print(json.dumps({'case':name,'passed':item['passed'],'checks':checks}),flush=True)
        args.output.write_text(json.dumps({'snapshot_sha256':args.snapshot_sha256,'harness_sha256':sha(pathlib.Path(__file__)),'binary_sha256':sha(binary),'probe_sha256':sha(probe),'kernel':kernel,'version':version,'operator_uid':65534,'image':IMAGE,'docker_engine_architecture':engine_arch,'source_revision':os.environ.get('GITHUB_SHA'),'artifact_sha256':args.artifact_sha256,'build_target':args.target,'results':results},indent=2)+'\n')
        if not item['passed']: raise SystemExit(1)
    cancellation_probe = args.cancellation_probe.resolve()
    cancellation_base = base[:-1] + ['-v', f'{cancellation_probe}:/usr/bin/tirith-cancellation-probe:ro', IMAGE]
    cancellation_wrapper = r'''set -eu
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/home" "$fixture/config" "$fixture/data" "$fixture/state" "$fixture/project"
printf 'protected original\n' > "$fixture/project/README.md"
cp /usr/bin/tirith-cancellation-probe "$fixture/project/cancel-probe"
cd "$fixture/project"
HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/config" XDG_DATA_HOME="$fixture/data" XDG_STATE_HOME="$fixture/state" TIRITH_OFFLINE=1 TIRITH_LOG=0 \
 /usr/bin/tirith-cancellation-probe "$1" /binary/tirith "$fixture/project"
test -z "$(find "$fixture/project" -name 'tirith-qualification-running-*.pid' -print -quit)"
test "$(cat "$fixture/project/README.md")" = 'protected original'
'''
    for case in ['before_exec', 'parent_term', 'parent_kill', 'guard_kill']:
        result = subprocess.run(cancellation_base + ['/bin/sh', '-c', cancellation_wrapper, 'cancellation', case], capture_output=True, text=True, timeout=180)
        try:
            value = json.loads(result.stdout)
        except ValueError:
            value = {'invalid_stdout': result.stdout[-4000:]}
        item = {'case': 'cancellation_' + case, 'passed': result.returncode == 0 and value.get('passed') is True,
                'returncode': result.returncode, 'evidence': value, 'stderr': result.stderr[-4000:]}
        results.append(item)
        report = json.loads(args.output.read_text())
        report['results'] = results
        report['cancellation_probe_sha256'] = sha(cancellation_probe)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(item), flush=True)
        if not item['passed']:
            raise SystemExit(1)
    print('Native installed-binary and cancellation checks passed; final release qualification remains separate.')
if __name__=='__main__': main()
