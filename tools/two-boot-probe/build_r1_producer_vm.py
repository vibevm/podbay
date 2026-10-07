#!/usr/bin/env python3
"""Separate offline-only Type=notify producer-refusal fixture. Never launches a VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
sys.dont_write_bytecode=True
import build_r1_systemd_vm as base

offline=base.offline
closed=base.closed
origin=base.origin
HERE=Path(__file__).resolve().parent
BASE=Path('/home/olegchir/podbay-r1-producer-vm-build')
PRODUCER='podbay-r1-boot-producer-v2.service'
MONITOR='r1-producer-monitor.service'
ISSUER='r1-producer-issuer.service'
SUCCESS='PRODUCER_REFUSED_BEFORE_READY_ISSUER_BLOCKED_NO_PRODUCTION_ORIGIN'
OFFLINE='OFFLINE_PRODUCER_NOTIFY_CANDIDATE_UNBOOTED'
MAX_EVENT=base.MAX_EVENT
DIGEST=base.DIGEST
TEMPLATES=HERE.parent/'r1-enforcement/systemd'
SOURCE_PATHS={n:HERE/n for n in ('build_r1_producer_vm.py','r1_producer_monitor.c','r1_producer_watch.h',
 'init.r1_systemd.c','r1_systemd_runtime.json','build_r1_systemd_vm.py','offline.py','run_closed_vm.py','run_closed_origin_vm.py')}
SOURCE_PATHS.update({n:TEMPLATES/n for n in ('podbay-r1-boot-producer-v2.service.in','issuer-producer-v2.conf.in')})
SOURCE_PATHS.update({n:HERE.parent.parent/'crates/podbay-r1-linux'/n for n in ('Cargo.toml','src/producer_main.rs','src/producer_lifecycle.rs')})

def source_pins():return {n:offline.sha(p.read_bytes()) for n,p in SOURCE_PATHS.items()}
strict_json=base.strict_json
pinned=base.pinned
planned_qemu=base.planned_qemu


def units():
    result={PRODUCER:(TEMPLATES/'podbay-r1-boot-producer-v2.service.in').read_text().format(vault_path='/fixture/vault',issuer_units=ISSUER).encode()}
    result[PRODUCER+'.d/90-fixture.conf']=('[Unit]\nRequires='+MONITOR+'\nAfter='+MONITOR+'\n[Service]\nStandardOutput=file:/run/r1-producer.out\nStandardError=file:/run/r1-producer.err\n').encode()
    result[ISSUER]=b'[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nUser=1000\nGroup=1000\nExecStart=/bin/busybox touch /tmp/r1-producer-issuer-ran\nRestart=no\n'
    result[ISSUER+'.d/50-producer.conf']=(TEMPLATES/'issuer-producer-v2.conf.in').read_bytes()
    result[MONITOR]=('[Unit]\nDefaultDependencies=no\nBefore='+PRODUCER+'\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/local/libexec/r1-producer-monitor\nTimeoutStartSec=30s\nRestart=no\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n').encode()
    result['r1-test.target']=('[Unit]\nDefaultDependencies=no\nWants='+MONITOR+' '+PRODUCER+' '+ISSUER+'\n').encode()
    for n in ('local-fs.target','sysinit.target','basic.target','shutdown.target','umount.target','final.target','system.slice'):
        result[n]=b'[Unit]\nDefaultDependencies=no\n'
    result['poweroff.target']=b'[Unit]\nDefaultDependencies=no\nRequires=systemd-poweroff.service\nAfter=systemd-poweroff.service\n'
    result['systemd-poweroff.service']=b'[Unit]\nDefaultDependencies=no\nRequires=shutdown.target umount.target final.target\nAfter=shutdown.target umount.target final.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl --force poweroff\nRestart=no\n'
    verify_graph(result)
    return result


def verify_graph(unit_bytes):
    parsed={n:base.parse_unit(d) for n,d in unit_bytes.items() if '.d/' not in n}
    for path,data in unit_bytes.items():
        if '.d/' not in path:continue
        name=path.split('.d/')[0]
        if name not in parsed:raise ValueError('orphan fixture drop-in')
        for key,value in base.parse_unit(data).items():
            if key in parsed[name] and key[0]=='Unit' and key[1] in ('After','Before','Requires','BindsTo'):
                parsed[name][key]+=' '+value
            elif key in parsed[name]:raise ValueError('unexpected fixture override')
            else:parsed[name][key]=value
    graph={n:set() for n in parsed}
    for name,u in parsed.items():
        for (section,key),value in u.items():
            if key.startswith(('Condition','Assert','ExecStartPre','ExecStartPost','ExecStop','OnFailure')):raise ValueError('unsafe skip/hook')
            if key=='Restart' and value!='no':raise ValueError('restart forbidden')
            if section=='Unit' and key in ('After','Before','Requires','Wants','BindsTo'):
                if not set(value.split())<=set(parsed):raise ValueError('unresolved unit')
                if key=='After':graph[name].update(value.split())
                if key=='Before':
                    for dep in value.split():graph[dep].add(name)
    for name in (PRODUCER,MONITOR):
        if parsed[name].get(('Service','Type'))!='notify' or parsed[name].get(('Service','NotifyAccess'))!='main':raise ValueError('not actual main notify unit')
    if parsed[PRODUCER].get(('Service','ExecStart'))!='/usr/local/libexec/podbay-r1-boot-producer':raise ValueError('producer command replaced')
    for name,dependency in ((PRODUCER,MONITOR),(ISSUER,PRODUCER)):
        for key in ('Requires','After'):
            if dependency not in parsed[name].get(('Unit',key),'').split():raise ValueError('missing arming/issuer gate')
    if PRODUCER not in parsed[ISSUER].get(('Unit','BindsTo'),'').split():raise ValueError('missing issuer binding')
    active=set();done=set()
    def visit(n):
        if n in active:raise ValueError('cyclic producer graph')
        if n in done:return
        active.add(n)
        for d in graph[n]:visit(d)
        active.remove(n);done.add(n)
    for n in graph:visit(n)
    return parsed


def parse_events(raw,pins):
    prefix=b'R1_PRODUCER_V2 '
    if not 0<len(raw)<MAX_EVENT or raw.count(b'\n')!=1 or not raw.endswith(b'\n') or b'\r' in raw or b'\0' in raw or b'\x1b' in raw or not raw.startswith(prefix):
        raise ValueError('invalid producer event channel')
    event=strict_json(raw[len(prefix):-1].decode('utf8','strict'))
    expected={'schema':1,'event':SUCCESS,'pid1':1,'producer_exit':2,'producer_ready':False,'issuer_starts':0,
              'source_events':0,'lock_events':0,'watch_control_passed':True,'outside_denials':4,
              'production_origin':'UNAVAILABLE','admission':'UNAVAILABLE',
              **{k:pins[k] for k in ('producer_sha256','systemd_sha256','archive_generation')}}
    dynamic={'boot_id','monitor_pid','producer_pid','armed_us','producer_start_us','producer_exit_us','window_end_us'}
    if not isinstance(event,dict) or set(event)!=set(expected)|dynamic or any(type(event[k]) is not type(v) or event[k]!=v for k,v in expected.items()):raise ValueError('foreign producer observation')
    if not isinstance(event['boot_id'],str) or not origin.BOOT_ID.fullmatch(event['boot_id']):raise ValueError('invalid actual boot')
    for k in dynamic-{'boot_id'}:
        if type(event[k]) is not int or event[k]<1:raise ValueError('invalid observation identity/time')
    if event['monitor_pid']<2 or event['producer_pid']<2 or event['monitor_pid']==event['producer_pid']:raise ValueError('monitor/producer alias')
    if not event['armed_us']<=event['producer_start_us']<=event['producer_exit_us']<=event['window_end_us']:raise ValueError('producer ran before monitor armed')
    return event


def native_receipt(events,pins,exit_code,exact_reaped,pidfd_verified,stderr=b'',console=None):
    if type(exit_code) is not int or exit_code!=0 or exact_reaped is not True or pidfd_verified is not True or stderr:raise ValueError('producer VM lifecycle failure')
    if console is None or b'R1_PRODUCER_V2' in console:raise ValueError('producer event leaked into console')
    base.verify_console(console)
    return parse_events(events,pins)


def prepare(name,producer,producer_sha):
    if os.getuid()==0 or os.geteuid()==0:raise ValueError('ordinary host UID required')
    if not re.fullmatch(r'producer-[a-z0-9][a-z0-9-]{0,21}',name):raise ValueError('fresh producer- name required')
    binary=pinned(producer,producer_sha)
    runtime_pins=strict_json((HERE/'r1_systemd_runtime.json').read_bytes())
    files=base.runtime_bytes(runtime_pins);files['/usr/local/libexec/podbay-r1-boot-producer']=binary
    closure=base.verify_elf_closure(files);unit_bytes=units();sources=source_pins()
    schema=origin.SCHEMA.read_text();seed=origin.seed_database(schema,base.LINEAGE)
    generation=offline.sha(json.dumps({'sources':sources,'producer':producer_sha,'seed':offline.sha(seed),
                                      'units':{n:offline.sha(d) for n,d in unit_bytes.items()}},sort_keys=True).encode())
    with offline.TrustedOutput(BASE,create=True) as out:
        out.create_dir(name)
        for n in ('init.r1_systemd.c','r1_producer_monitor.c','r1_producer_watch.h'):out.write(n,(HERE/n).read_bytes())
        header=''.join('#define '+key+' "'+value+'"\n' for key,value in (('PRODUCER_SHA',producer_sha),('SYSTEMD_SHA',runtime_pins['/usr/lib/systemd/systemd']),('GENERATION',generation)))
        out.write('r1_producer_pins.h',header.encode())
        offline.trusted_tool(origin.GCC);pinned(origin.GCC,origin.GCC_SHA256)
        for src,target in (('init.r1_systemd.c','init'),('r1_producer_monitor.c','monitor')):
            out.write(target,b'')
            args=[str(origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror','-Wl,--build-id=none','-ffile-prefix-map='+str(out.out)+'=.',str(out.out/src),'-o',str(out.out/target)]
            r=subprocess.run(args,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SOURCE_DATE_EPOCH':str(offline.EPOCH)})
            os.fchmod(out.pins[out.out/target],0o600);out.check();out.write(target+'.compiler.log',r.stdout+r.stderr)
            if r.returncode:raise ValueError('static compile failed: '+target)
            offline.static_elf(out.read(target))
        files['/init']=out.read('init');files['/usr/local/libexec/r1-producer-monitor']=out.read('monitor')
        for n,d in unit_bytes.items():files['/etc/systemd/system/'+n]=d
        files['/etc/passwd']=b'root:x:0:0:root:/:/bin/false\nfixture:x:1000:1000:fixture:/:/bin/false\n'
        files['/etc/group']=b'root:x:0:\nfixture:x:1000:\n';files['/etc/machine-id']=b''
        files['/etc/os-release']=b'ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Producer negative fixture"\n'
        checks=''.join(offline.sha(files[p])+'  '+p+'\n' for p in ('/usr/local/libexec/podbay-r1-boot-producer','/usr/lib/systemd/systemd'))
        checks+=runtime_pins['/usr/lib/systemd/systemd']+'  /proc/1/exe\n'+offline.sha(seed)+'  /fixture/vault/state/db.sqlite\n'
        files['/etc/r1-producer-artifacts.sha256']=checks.encode()
        archive,entries=base.archive(files);syntax=base.verify_systemd(out,entries)
        out.write('initramfs.cpio.gz',archive)
        out.write('archive-manifest.json',(json.dumps([{'path':n,'mode':m,'sha256':offline.sha(d),'bytes':len(d)} for n,m,d,a,b in entries],sort_keys=True,indent=2)+'\n').encode())
        with offline.TrustedOutput(origin.INPUT) as inputs:
            for n,h in (('vmlinuz',offline.KERNEL[2]),('kernel.config',offline.CONFIG_HASH),('modules.builtin',offline.BUILTIN_HASH)):
                fd=closed.attach(inputs,n,h);out.write(n,os.pread(fd,os.fstat(fd).st_size,0))
        cfg=out.read('kernel.config').decode().splitlines()
        if any('CONFIG_'+x+'=y' not in cfg for x in (*offline.REQUIRED_CONFIG,'UNIX','INOTIFY_USER','CGROUPS','SERIAL_8250','SERIAL_CORE')):raise ValueError('kernel missing producer fixture primitive')
        base.disk_build(out,seed);origin.verify_seed(out.out/'source24.sqlite',schema,base.LINEAGE)
        report={'schema':1,'profile':'R1_PRODUCER_NOTIFY_NEGATIVE_V1','status':OFFLINE,'boot_executed':False,'native_execution_supported':False,
                'output':str(out.out),'producer_sha256':producer_sha,'systemd_sha256':runtime_pins['/usr/lib/systemd/systemd'],'archive_generation':generation,
                'source_pins':sources,'builder_sha256':offline.sha(Path(__file__).read_bytes()),'runtime_pins':runtime_pins,'elf_closure':closure,
                'systemd_syntax':syntax,'source_sha256':offline.sha(seed),'unit_pins':{n:offline.sha(d) for n,d in unit_bytes.items()},
                'artifacts':{n:offline.sha(out.read(n)) for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw')},
                'limits':['Unbooted producer-negative fixture; no production origin','Inotify covers watched inode open/access window, not universal FD/mmap/raw-device exclusion',
                          'Trusted monitor reads/hash-controls source before/after measured producer window','Producer no-READY means no systemd ActiveEnter plus exact refusal; no syscall trace claim']}
        for fd in out.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode):os.fsync(fd)
        closed.durable_receipt(out,'plan.json',report);return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True);p.add_argument('--producer',required=True);p.add_argument('--producer-sha256',required=True);a=p.parse_args()
    try:r=prepare(a.name,a.producer,a.producer_sha256);print(json.dumps(r,sort_keys=True));return 0
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print(json.dumps({'status':'PRODUCER_OFFLINE_REFUSED','boot_executed':False,'error':str(e)}),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
