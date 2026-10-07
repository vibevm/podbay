#!/usr/bin/env python3
"""Separate offline-only Type=notify appliance read-custody fixture. Never launches a VM."""
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
BASE=Path('/home/olegchir/podbay-r1-positive-origin-build')
KEEPER='r1-appliance-keeper.service'
MONITOR='r1-appliance-monitor.service'
ISSUER='r1-appliance-issuer.service'
SUCCESS='DISPOSABLE_READ_CUSTODY_ESTABLISHED_AND_LOST_NO_MIGRATION'
OFFLINE='OFFLINE_APPLIANCE_READ_CUSTODY_UNBOOTED'
MAX_EVENT=8192
DIGEST=base.DIGEST
SOURCE_PATHS={n:HERE/n for n in ('build_r1_appliance_vm.py','run_r1_appliance_vm.py','r1_appliance_monitor.c','r1_producer_watch.h','init.r1_appliance.c','r1_systemd_runtime.json','build_r1_systemd_vm.py','offline.py','run_closed_vm.py','run_closed_origin_vm.py')}
SOURCE_PATHS.update({n:HERE.parent.parent/'crates/podbay-r1-linux'/n for n in ('Cargo.toml','src/appliance_keeper_main.rs','src/appliance_custodian_main.rs','src/appliance.rs','src/appliance_sys.rs','src/appliance_protocol.rs')})

def source_pins():return {n:offline.sha(p.read_bytes()) for n,p in SOURCE_PATHS.items()}
strict_json=base.strict_json
pinned=base.pinned
planned_qemu=base.planned_qemu


def units():
    result={}
    result[KEEPER]=('[Unit]\nDefaultDependencies=no\nRequires='+MONITOR+'\nAfter='+MONITOR+'\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/local/libexec/podbay-r1-appliance-keeper\nRestart=no\nKillMode=process\nTimeoutStartSec=80s\nUMask=0077\nStandardOutput=file:/run/r1-appliance/keeper.log\nStandardError=file:/run/r1-appliance/keeper.err\n').encode()
    result[MONITOR]=('[Unit]\nDefaultDependencies=no\nBefore='+KEEPER+'\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/local/libexec/r1-appliance-monitor\nTimeoutStartSec=30s\nRestart=no\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n').encode()
    result[ISSUER]=('[Unit]\nDefaultDependencies=no\nRequires='+KEEPER+'\nAfter='+KEEPER+'\nBindsTo='+KEEPER+'\n[Service]\nType=oneshot\nUser=1000\nGroup=1000\nExecStart=/bin/busybox touch /tmp/r1-appliance-issuer-ran\nRestart=no\n').encode()
    result['r1-test.target']=('[Unit]\nDefaultDependencies=no\nWants='+MONITOR+' '+KEEPER+' '+ISSUER+'\n').encode()
    for n in ('local-fs.target','sysinit.target','basic.target','shutdown.target','umount.target','final.target','system.slice'):
        result[n]=b'[Unit]\nDefaultDependencies=no\n'
    result['poweroff.target']=b'[Unit]\nDefaultDependencies=no\nRequires=systemd-poweroff.service\nAfter=systemd-poweroff.service\n'
    result['systemd-poweroff.service']=b'[Unit]\nDefaultDependencies=no\nRequires=shutdown.target umount.target final.target\nAfter=shutdown.target umount.target final.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl --force poweroff\nRestart=no\n'
    verify_graph(result)
    return result

def verify_graph(units):
    names={KEEPER,MONITOR,ISSUER,'r1-test.target','local-fs.target','sysinit.target','basic.target','shutdown.target','umount.target','final.target','system.slice','poweroff.target','systemd-poweroff.service'}
    if set(units)!=names:raise ValueError('unreviewed launch closure')
    parsed={n:base.parse_unit(d) for n,d in units.items()}
    for name,u in parsed.items():
        for (section,key),value in u.items():
            if key.startswith(('Condition','Assert','ExecStartPre','ExecStartPost','ExecStop','OnFailure')):raise ValueError('skip/auxiliary entrypoint')
            if key=='Restart' and value!='no':raise ValueError('restart forbidden')
            if section=='Unit' and key in ('After','Before','Requires','Wants','BindsTo') and not set(value.split())<=names:raise ValueError('unknown graph edge')
    for name,path in ((KEEPER,'podbay-r1-appliance-keeper'),(MONITOR,'r1-appliance-monitor')):
        u=parsed[name]
        if u.get(('Service','Type'))!='notify' or u.get(('Service','NotifyAccess'))!='main' or u.get(('Service','ExecStart'))!='/usr/local/libexec/'+path or u.get(('Service','Restart'))!='no':raise ValueError('wrong notify actor')
    for name,dep in ((KEEPER,MONITOR),(ISSUER,KEEPER)):
        for key in ('Requires','After'):
            if parsed[name].get(('Unit',key))!=dep:raise ValueError('missing exact pre-issuer gate')
    if parsed[KEEPER].get(('Service','KillMode'))!='process':raise ValueError('systemd must not substitute child death')
    if parsed[ISSUER].get(('Unit','BindsTo'))!=KEEPER or parsed[ISSUER].get(('Service','User'))!='1000':raise ValueError('wrong issuer gate/uid')
    return parsed


def disk_build(output,seed):
    for key in ('mke2fs','debugfs'):
        path,digest=offline.PINS[key];offline.trusted_tool(path);pinned(path,digest)
    output.write('source24.sqlite',seed);output.write('manager.lock',b'')
    output.write('fixture.raw',b'');disk=output.pins[output.out/'fixture.raw'];os.ftruncate(disk,offline.SIZE)
    output.write('mke2fs.conf',b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','E2FSPROGS_FAKE_TIME':str(offline.EPOCH),'SOURCE_DATE_EPOCH':str(offline.EPOCH),'MKE2FS_CONFIG':str(output.out/'mke2fs.conf')}
    def call(args,tag,binary=False):
        output.check();r=subprocess.run(args,capture_output=True,timeout=60,env=env,pass_fds=(disk,));output.check()
        output.write(tag+'.log',r.stdout+r.stderr)
        if r.returncode or re.search(rb'File not found|Filesystem not open|Usage:|while |Command not found|Could not|Error|not a directory',r.stderr if binary else r.stdout+r.stderr,re.I):raise ValueError('disk tool failed '+tag)
        return r.stdout
    call([offline.PINS['mke2fs'][0],'-q','-t','ext4','-b','4096','-I','256','-N','2048','-m','0','-U',base.UUID,'-O','none,extent,filetype,sparse_super,large_file','-E','lazy_itable_init=0,hash_seed='+base.UUID,f'/proc/self/fd/{disk}'],'mkfs')
    commands=f'rmdir /lost+found\nmkdir /vault\nmkdir /vault/state\nwrite {output.out}/source24.sqlite /vault/state/db.sqlite\nwrite {output.out}/manager.lock /vault/state/db.sqlite.manager.lock\n'
    paths={'/':(0,'040700'),'/vault':(0,'040700'),'/vault/state':(1000,'040700'),'/vault/state/db.sqlite':(1000,'0100600'),'/vault/state/db.sqlite.manager.lock':(1000,'0100600')}
    for path,(uid,mode) in paths.items():
        for key,value in (('uid',uid),('gid',uid),('mode',mode),('atime',offline.EPOCH),('ctime',offline.EPOCH),('mtime',offline.EPOCH),('crtime',offline.EPOCH)):
            commands+=f'set_inode_field {path} {key} {value}\n'
    output.write('populate.debugfs',commands.encode())
    call([offline.PINS['debugfs'][0],'-w','-f',str(output.out/'populate.debugfs'),f'/proc/self/fd/{disk}'],'populate')
    output.write('inspect.debugfs',(''.join('stat '+p+'\n' for p in paths)+'ls -p /\nls -p /vault\nls -p /vault/state\n').encode())
    inspection=call([offline.PINS['debugfs'][0],'-f',str(output.out/'inspect.debugfs'),f'/proc/self/fd/{disk}'],'inspect').decode()
    for path,(uid,mode) in paths.items():
        block=inspection.split('debugfs: stat '+path+'\n',1)[1].split('debugfs:',1)[0]
        if not re.search(r'Mode:\s+'+mode[-4:]+r'\b',block) or not re.search(r'User:\s+'+str(uid)+r'\s+Group:\s+'+str(uid)+r'\b',block) or 'File ACL: 0' not in block:raise ValueError('disk metadata readback differs')
        if 'db.sqlite' in path and not re.search(r'Links: 1\s',block):raise ValueError('disk subject link count')
    data=call([offline.PINS['debugfs'][0],'-R','cat /vault/state/db.sqlite',f'/proc/self/fd/{disk}'],'readback',binary=True)
    if data!=seed:raise ValueError('disk source mismatch')
    identities={}
    for key,path in (('source_inode','/vault/state/db.sqlite'),('lock_inode','/vault/state/db.sqlite.manager.lock')):
        info=call([offline.PINS['debugfs'][0],'-R','stat '+path,f'/proc/self/fd/{disk}'],key).decode()
        m=re.search(r'Inode: (\d+)',info)
        if not m:raise ValueError('missing disk inode')
        identities[key]=int(m[1])
    return identities


def prepare(name,keeper,keeper_sha,custodian,custodian_sha):
    if os.getuid()==0 or os.geteuid()==0:raise ValueError('ordinary host UID required')
    if not re.fullmatch(r'appliance-[a-z0-9][a-z0-9-]{0,22}',name):raise ValueError('fresh appliance name required')
    keeper_data=pinned(keeper,keeper_sha);custodian_data=pinned(custodian,custodian_sha)
    runtime_pins=strict_json((HERE/'r1_systemd_runtime.json').read_bytes())
    files=base.runtime_bytes(runtime_pins)
    files['/usr/local/libexec/podbay-r1-appliance-keeper']=keeper_data
    files['/usr/local/libexec/podbay-r1-appliance-custodian']=custodian_data
    closure=base.verify_elf_closure(files);unit_bytes=units();verify_graph(unit_bytes);sources=source_pins()
    schema=origin.SCHEMA.read_text();seed=origin.seed_database(schema,base.LINEAGE)
    generation=offline.sha(json.dumps({'sources':sources,'keeper':keeper_sha,'custodian':custodian_sha,'seed':offline.sha(seed),'units':{n:offline.sha(d) for n,d in unit_bytes.items()}},sort_keys=True).encode())
    with offline.TrustedOutput(BASE,create=True) as out:
        out.create_dir(name)
        identities=disk_build(out,seed)
        for n in ('init.r1_appliance.c','r1_appliance_monitor.c','r1_producer_watch.h'):out.write(n,(HERE/n).read_bytes())
        out.write('r1_appliance_pins.h',(''.join('#define '+k+' "'+v+'"\n' for k,v in (('GENERATION',generation),('SOURCE_SHA',offline.sha(seed))))).encode())
        offline.trusted_tool(origin.GCC);pinned(origin.GCC,origin.GCC_SHA256)
        for src,target in (('init.r1_appliance.c','init'),('r1_appliance_monitor.c','monitor')):
            out.write(target,b'')
            args=[str(origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror','-Wl,--build-id=none','-ffile-prefix-map='+str(out.out)+'=.',str(out.out/src),'-o',str(out.out/target)]
            r=subprocess.run(args,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SOURCE_DATE_EPOCH':str(offline.EPOCH)})
            os.fchmod(out.pins[out.out/target],0o600);out.check();out.write(target+'.compiler.log',r.stdout+r.stderr)
            if r.returncode:raise ValueError('static compile failed: '+target)
            offline.static_elf(out.read(target))
        files['/init']=out.read('init');files['/usr/local/libexec/r1-appliance-monitor']=out.read('monitor')
        for n,d in unit_bytes.items():files['/etc/systemd/system/'+n]=d
        files['/etc/passwd']=b'root:x:0:0:root:/:/bin/false\nfixture:x:1000:1000:fixture:/:/bin/false\n'
        files['/etc/group']=b'root:x:0:\nfixture:x:1000:\n';files['/etc/machine-id']=b''
        files['/etc/os-release']=b'ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Disposable read custody appliance"\n'
        manifest=''.join(offline.sha(d)+'  '+n+'\n' for n,d in sorted(files.items()) if n=='/init' or n.startswith(('/usr/','/bin/','/lib64/','/etc/systemd/')))
        files['/etc/r1-appliance/image-files']=manifest.encode()
        pins={'generation':generation,'keeper_sha256':keeper_sha,'custodian_sha256':custodian_sha,'systemd_sha256':runtime_pins['/usr/lib/systemd/systemd'],'source_sha256':offline.sha(seed),'source_bytes':len(seed),**identities}
        files['/etc/r1-appliance/pins']=''.join(k+'='+str(v)+'\n' for k,v in pins.items()).encode()
        archive,entries=base.archive(files);syntax=base.verify_systemd(out,entries)
        out.write('initramfs.cpio.gz',archive)
        out.write('archive-manifest.json',(json.dumps([{'path':n,'mode':m,'sha256':offline.sha(d),'bytes':len(d)} for n,m,d,a,b in entries],sort_keys=True,indent=2)+'\n').encode())
        with offline.TrustedOutput(origin.INPUT) as inputs:
            for n,h in (('vmlinuz',offline.KERNEL[2]),('kernel.config',offline.CONFIG_HASH),('modules.builtin',offline.BUILTIN_HASH)):
                fd=closed.attach(inputs,n,h);out.write(n,os.pread(fd,os.fstat(fd).st_size,0))
        cfg=out.read('kernel.config').decode().splitlines()
        if any('CONFIG_'+x+'=y' not in cfg for x in (*offline.REQUIRED_CONFIG,'UNIX','INOTIFY_USER','CGROUPS','SERIAL_8250','SERIAL_CORE','SECCOMP','SECCOMP_FILTER','NAMESPACES')):raise ValueError('kernel missing appliance primitive')
        origin.verify_seed(out.out/'source24.sqlite',schema,base.LINEAGE)
        report={'schema':1,'profile':'R1_APPLIANCE_READ_CUSTODY_V1','status':OFFLINE,'boot_executed':False,'native_execution_supported':False,'output':str(out.out),**pins,'archive_generation':generation,'source_pins':sources,'builder_sha256':offline.sha(Path(__file__).read_bytes()),'runtime_pins':runtime_pins,'elf_closure':closure,'systemd_syntax':syntax,'unit_pins':{n:offline.sha(d) for n,d in unit_bytes.items()},'artifacts':{n:offline.sha(out.read(n)) for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw')},'limits':['Unbooted disposable appliance only; no production origin or migration admission','Host-pinned launch closure is an explicit trust assumption','Inotify is inode-window observation, not universal inherited-holder proof','Only UID1000 custodian reads source bytes; observer performs metadata and later lock contention probes']}
        for fd in out.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode):os.fsync(fd)
        closed.durable_receipt(out,'plan.json',report);return report


def parse_events(raw,pins):
    prefix=b'R1_APPLIANCE_READ_V1 '
    if not 0<len(raw)<MAX_EVENT or raw.count(b'\n')!=1 or not raw.endswith(b'\n') or any(x in raw for x in (b'\r',b'\0',b'\x1b')) or not raw.startswith(prefix):raise ValueError('invalid appliance event channel')
    e=strict_json(raw[len(prefix):-1].decode('utf8','strict'))
    fixed={'schema':1,'event':SUCCESS,'watch_control':True,'fd_seal':True,'outside_denials':8,'lock_contended':True,'loss_observed':True,'spent_retry_refused':True,'issuer_starts':0,'production_origin':'UNAVAILABLE','migration_admission':'UNAVAILABLE'}
    if not isinstance(e,dict) or set(e)!=set(fixed)|{'read','armed_us','killed_us','finished_us'} or any(type(e[k]) is not type(v) or e[k]!=v for k,v in fixed.items()):raise ValueError('foreign appliance observation')
    for k in ('armed_us','killed_us','finished_us'):
        if type(e[k]) is not int or e[k]<1:raise ValueError('invalid observation time')
    if not e['armed_us']<e['killed_us']<=e['finished_us']:raise ValueError('observation order')
    r=e['read'];fixed_read={'schema':1,'generation':pins['archive_generation'],'source_sha256':pins['source_sha256'],'source_inode':pins['source_inode'],'lock_inode':pins['lock_inode'],'bytes':pins['source_bytes'],'migration_admission':'UNAVAILABLE','ready':False}
    dynamic={'boot_id','keeper_pid','keeper_birth','custodian_pid','custodian_birth','device','nonce','bound_sha256'}
    if not isinstance(r,dict) or set(r)!=set(fixed_read)|dynamic or any(type(r[k]) is not type(v) or r[k]!=v for k,v in fixed_read.items()):raise ValueError('foreign read custody subject')
    if not isinstance(r['boot_id'],str) or not origin.BOOT_ID.fullmatch(r['boot_id']):raise ValueError('invalid actual boot')
    for k in ('keeper_pid','keeper_birth','custodian_pid','custodian_birth','device'):
        if type(r[k]) is not int or r[k]<1:raise ValueError('invalid read actor identity')
    if min(r['keeper_pid'],r['custodian_pid'])<2 or r['keeper_pid']==r['custodian_pid']:raise ValueError('aliased actor')
    for k in ('nonce','bound_sha256'):
        if not isinstance(r[k],str) or not DIGEST.fullmatch(r[k]):raise ValueError('invalid response hash')
    expected=hashlib.sha256(b'podbay.appliance.read/1\0'+bytes.fromhex(r['nonce'])+bytes.fromhex(pins['source_sha256'])).hexdigest()
    if r['bound_sha256']!=expected:raise ValueError('nonce/source result not bound')
    return e


def native_receipt(events,pins,exit_code,exact_reaped,pidfd_verified,stderr=b'',console=None):
    if type(exit_code) is not int or exit_code!=0 or exact_reaped is not True or pidfd_verified is not True or stderr:raise ValueError('appliance VM lifecycle failure')
    if console is None or b'R1_APPLIANCE_READ_V1' in console:raise ValueError('event leaked into console')
    base.verify_console(console)
    return parse_events(events,pins)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True);p.add_argument('--keeper',required=True);p.add_argument('--keeper-sha256',required=True);p.add_argument('--custodian',required=True);p.add_argument('--custodian-sha256',required=True);a=p.parse_args()
    try:print(json.dumps(prepare(a.name,a.keeper,a.keeper_sha256,a.custodian,a.custodian_sha256),sort_keys=True));return 0
    except (ValueError,OSError,subprocess.SubprocessError) as e:print(json.dumps({'status':'APPLIANCE_OFFLINE_REFUSED','error':str(e)}),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
