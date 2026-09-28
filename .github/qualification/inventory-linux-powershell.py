#!/usr/bin/env python3
"""Read-only, bounded inventory of the installed Linux PowerShell runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

MAX_ENTRIES=4096
MAX_BYTES=512*1024*1024
MAX_FILE=64*1024*1024
MAX_DEPTH=24

def require(condition, message):
    if not condition:
        raise ValueError(message)

def token(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_uid,info.st_gid)

def kind(info):
    for name,predicate in [('directory',stat.S_ISDIR),('regular',stat.S_ISREG),('symlink',stat.S_ISLNK),('fifo',stat.S_ISFIFO),('socket',stat.S_ISSOCK),('character',stat.S_ISCHR),('block',stat.S_ISBLK)]:
        if predicate(info.st_mode):
            return name
    return 'other'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    require(os.name=='posix' and os.uname().sysname=='Linux','native Linux required')
    require(args.output.is_absolute() and not args.output.exists(),'fresh absolute evidence directory required')
    args.output.mkdir(mode=0o700)
    report={'schema_version':1,'status':'refused','scope':'installed_runtime_metadata_only','runtime_executed':False,'runtime_modified':False,'profile_loaded':False,'entries':[],'links':[]}
    try:
        selected=shutil.which('pwsh')
        require(selected is not None,'PowerShell not installed')
        executable=Path(selected).resolve(strict=True)
        runtime=executable.parent
        require(runtime.is_absolute() and runtime.resolve(strict=True)==runtime,'canonical runtime required')
        report.update(selected_path=selected,executable=str(executable),runtime=str(runtime),kernel=os.uname().release,architecture=os.uname().machine)
        initial=runtime.stat()
        report['runtime_identity']=token(initial)
        pending=[runtime]
        total=0
        while pending:
            path=pending.pop()
            info=path.lstat()
            relative=path.relative_to(runtime)
            require(len(relative.parts)<=MAX_DEPTH and len(report['entries'])<MAX_ENTRIES,'runtime entry/depth cap exceeded')
            row={'path':relative.as_posix(),'kind':kind(info),'mode':stat.S_IMODE(info.st_mode),'size':info.st_size,'uid':info.st_uid,'gid':info.st_gid}
            if stat.S_ISDIR(info.st_mode):
                children=[]
                with os.scandir(path) as scan:
                    for entry in scan:
                        require(len(report['entries'])+len(pending)+len(children)+1<MAX_ENTRIES,'runtime inventory cap exceeded')
                        children.append(Path(entry.path))
                pending.extend(sorted(children,reverse=True))
            elif stat.S_ISREG(info.st_mode):
                total+=info.st_size
                require(info.st_size<=MAX_FILE and total<=MAX_BYTES,'runtime regular file byte cap exceeded')
            elif stat.S_ISLNK(info.st_mode):
                target=os.readlink(path)
                require(len(target)<=4096,'runtime link exceeds byte cap')
                row.update(target=target,absolute_target=os.path.isabs(target))
                try:
                    resolved=path.resolve(strict=True)
                    resolved_info=resolved.lstat()
                    row.update(resolved_path=str(resolved),resolved_within_runtime=resolved.is_relative_to(runtime),resolved_kind=kind(resolved_info),resolved_size=resolved_info.st_size,resolved_uid=resolved_info.st_uid,resolved_gid=resolved_info.st_gid)
                except (OSError,RuntimeError) as error:
                    row.update(resolution_error=str(error)[:2048])
                report['links'].append(dict(row))
            require(token(path.lstat())==token(info),'runtime entry changed during inventory')
            report['entries'].append(row)
        require(token(runtime.stat())==token(initial),'runtime root changed during inventory')
        report['entry_count']=len(report['entries'])
        report['regular_bytes']=total
        report['absolute_links']=[row['path'] for row in report['links'] if row['absolute_target']]
        # Only the observed public executable is read; no other file contents or
        # environment values are collected and no runtime object is executed.
        fd=os.open(executable,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=MAX_FILE,'executable read bound')
            digest=hashlib.sha256();count=0
            while True:
                part=os.read(fd,min(1024*1024,before.st_size+1-count))
                if not part:break
                count+=len(part)
                require(count<=before.st_size,'executable grew while reading')
                digest.update(part)
            require(count==before.st_size and token(os.fstat(fd))==token(before) and token(executable.lstat())==token(before),'executable changed while reading')
            report['executable_sha256']=digest.hexdigest()
        finally:os.close(fd)
        report['status']='inventory_complete_not_runtime_qualification'
    except BaseException as error:
        report['error']=str(error)[:4096]
    with (args.output/'report.json').open('x') as destination:
        json.dump(report,destination,indent=2);destination.write('\n')
    print(json.dumps({'status':report['status'],'report':str(args.output/'report.json')}))
    return 0 if report['status']=='inventory_complete_not_runtime_qualification' else 1

if __name__=='__main__':
    raise SystemExit(main())
