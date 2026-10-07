#!/usr/bin/env python3
"""Fixed disposable warm-custodian-loss diagnostic. Default builds, never boots."""
import argparse
import errno
import gzip
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import run_closed_origin_vm as origin

BASE = Path('/home/olegchir/podbay-r1-warm-custodian-build')
SOURCE = Path(__file__).resolve().parent
POLICY = b'guest-r1-warm-v1;closed-before-source;custodian-loss;held-fd;no-admission'
SUCCESS = 'DISPOSABLE_WARM_CUSTODIAN_LOSS_CLOSED_NO_PRODUCTION_ADMISSION'
OFFLINE = 'OFFLINE_WARM_CUSTODIAN_CANDIDATE_UNBOOTED'
SOURCE_NAMES = ('closed_origin_shared.h', 'r1_warm_shared.h', 'r1_warm_probe.c', 'init.r1_warm.c')
KEYS = {'schema','event','sequence','nonce','fixture_uuid','boot_id','gate','admission','warm_adoption',
        'origin_restored','source_pinned','source_device','source_inode','source_uid','source_bytes',
        'expected_source_sha256','source_sha256','lineage','policy_sha256','pid1_sha256','probe_sha256',
        'lock_inode','custodian_pid','custodian_birth','custodian_state','broker_pid','broker_birth',
        'broker_state','broker_fd','broker_sequence','actor_pid','actor_birth','actor_parent','rc','errno'}
DENIALS = ('source','wal','shm','journal','proc_root','proc_fd','namespace','unshare')


def expected_sequence():
    def outside(point):
        return [(f'outside_{point}_{name}',-1,point) for name in DENIALS]+[('outside_reaped',0,point)]
    return [('closed_before_source',0,'pid1'),('vault_closed_created',0,'pid1'),('seed_read_started',0,'pid1'),
            ('source24_verified',24,'pid1')] + outside('before_custodian') + [
            ('custodian_lock_held',0,'custodian'),('broker_clean_exec_sealed',0,'broker'),
            ('broker_source_opened',100,'broker'),('broker_fd_before_loss',100,'broker')] + outside('custodian_alive') + [
            ('custodian_killed_reaped',-signal.SIGKILL,'custodian'),('broker_same_fd_after_loss',100,'broker'),
            ('replacement_custodian_refused',-1,'pid1'),('broker_seal_persists',0,'broker')] + outside('after_custodian_loss') + [
            ('broker_fd_still_held',100,'broker'),('broker_killed_reaped',-signal.SIGKILL,'broker')] + outside('after_broker_death') + [
            ('source_preserved_no_children',24,'pid1'),('warm_loss_closed_no_admission',0,'pid1')]


def parse_events(raw, pins):
    if len(raw)>closed.MAX_SERIAL or not raw.endswith(b'\n') or b'\0' in raw: raise ValueError('partial/NUL/oversized serial')
    text=raw.decode('utf-8',errors='strict')
    if re.search(r'kernel panic|not syncing|oops:|BUG:|segmentation fault',text,re.I): raise ValueError('fatal guest diagnostic')
    lines=text.splitlines();encoded=[line for line in lines if line.startswith('{')]
    if any(len(line.encode())>=2048 for line in encoded): raise ValueError('oversized event')
    events=[json.loads(line,object_pairs_hook=closed.strict_object) for line in encoded];expected=expected_sequence()
    if len(events)!=len(expected): raise ValueError('missing/extra warm-loss events')
    if not isinstance(events[0],dict): raise ValueError('nonobject event')
    boot=events[0].get('boot_id')
    if not isinstance(boot,str) or not origin.BOOT_ID.fullmatch(boot): raise ValueError('invalid boot identity')
    actors={};source=None;custodian=None;broker=None
    source_known=children_known=lost=dead=False;fd=-1;protocol=0
    advances={'broker_clean_exec_sealed':1,'broker_source_opened':2,'broker_fd_before_loss':3,
              'broker_same_fd_after_loss':4,'broker_seal_persists':5,'broker_fd_still_held':6}
    for i,(e,(name,rc,role)) in enumerate(zip(events,expected),1):
        if (not isinstance(e,dict) or set(e)!=KEYS or e['schema']!=1 or e['event']!=name or e['sequence']!=i or e['rc']!=rc
            or e['boot_id']!=boot or e['gate']!='CLOSED' or e['admission']!='UNIMPLEMENTED' or e['warm_adoption']!='UNAVAILABLE'
            or e['origin_restored'] is not False or e['expected_source_sha256']!=pins['db_sha256']
            or any(e[k]!=pins[k] for k in ('nonce','fixture_uuid','lineage','policy_sha256','pid1_sha256','probe_sha256'))):
            raise ValueError('foreign/out-of-order/authority-claim event')
        for k in ('schema','sequence','source_device','source_inode','source_uid','source_bytes','lock_inode','custodian_pid',
                  'custodian_birth','broker_pid','broker_birth','broker_fd','broker_sequence','actor_pid','actor_birth','actor_parent','rc','errno'):
            if type(e[k]) is not int: raise ValueError('noninteger identity')
        if type(e['source_pinned']) is not bool: raise ValueError('nonboolean source state')
        source_known |= name=='source24_verified'
        values=(e['source_device'],e['source_inode'],e['source_uid'],e['source_bytes'],e['source_sha256'],e['lock_inode'])
        if e['source_pinned']!=source_known: raise ValueError('source claimed before verification')
        if not source_known:
            if values!=(0,0,0,0,'',0): raise ValueError('source fabricated before read boundary')
        else:
            if values[0]<=0 or values[1]<=0 or values[2]!=1000 or values[3]!=pins['db_bytes'] or values[4]!=pins['db_sha256'] or values[5]<=0 or values[5]==values[1]:
                raise ValueError('source/lock identity mismatch')
            if source is None: source=values
            if source!=values: raise ValueError('source or lock changed')
        children_known |= name=='custodian_lock_held'
        lost |= name=='custodian_killed_reaped';dead |= name=='broker_killed_reaped'
        ids=(e['custodian_pid'],e['custodian_birth'],e['broker_pid'],e['broker_birth'])
        if not children_known:
            if ids!=(0,0,0,0) or e['custodian_state']!='NOT_STARTED' or e['broker_state']!='NOT_STARTED': raise ValueError('children claimed before launch')
        else:
            if ids[0]<=1 or ids[1]<=0 or ids[2]<=1 or ids[3]<=0 or ids[0]==ids[2]: raise ValueError('bad custodian/broker identity')
            if custodian is None:custodian=ids[:2];broker=ids[2:]
            if ids!=custodian+broker or e['custodian_state']!=('LOST' if lost else 'LIVE') or e['broker_state']!=('DEAD' if dead else 'LIVE'):
                raise ValueError('actor replaced or loss reversed')
        if name=='broker_source_opened':fd=3
        protocol=advances.get(name,protocol)
        if e['broker_fd']!=fd or e['broker_sequence']!=protocol: raise ValueError('FD substitution or protocol replay')
        if e['actor_pid']<1 or e['actor_birth']<1: raise ValueError('missing actor birth')
        actor=(e['actor_pid'],e['actor_birth'])
        if actors.setdefault(role,actor)!=actor: raise ValueError('actor changed during phase/reap')
        if role=='pid1':
            if actor[0]!=1 or e['actor_parent']!=0: raise ValueError('wrong PID1 observer')
        elif role=='custodian':
            if actor!=custodian or e['actor_parent']!=1: raise ValueError('wrong root custodian')
        elif role=='broker':
            if actor!=broker or e['actor_parent']!=(1 if lost else custodian[0]): raise ValueError('not the same surviving orphan broker')
        elif actor[0]<=1 or e['actor_parent']!=1: raise ValueError('wrong outside probe')
        denied=name.startswith('outside_') and name!='outside_reaped'
        allowed=(errno.EACCES,errno.EPERM) if denied else (errno.EOWNERDEAD,) if name=='replacement_custodian_refused' else (0,)
        if e['errno'] not in allowed or (name.endswith('_unshare') and e['errno']!=errno.EPERM): raise ValueError('unobserved denial/refusal')
    if len(set(actors.values()))!=len(actors): raise ValueError('independent actors alias')
    for line in lines:
        if line.strip() and not line.startswith('{') and not re.match(r'^\[\s*\d+\.\d+\]',line): raise ValueError('unexpected non-kernel output')
    normalized=[];remaining=len(encoded)
    for line in lines:
        if line.startswith('{'):
            remaining-=1
            if not remaining:normalized.append(json.dumps(closed.EXPECTED_EVENT))
        else:normalized.append(line)
    closed.parse_serial(('\n'.join(normalized)+'\n').encode())
    return {'boot_id':boot,'events':events,'source':list(source),'custodian':list(custodian),'broker':list(broker),'pid1':list(actors['pid1'])}


def qemu_argv(kernel,initramfs,image):
    args=origin.qemu_argv(kernel,initramfs,image)
    args[args.index('-append')+1]+=' loglevel=4 r1.warm=1'
    return args


def run_guest(output,report,qemu_hash,latch):
    child=pidfd=None
    report.update(boot_executed=False,exact_child_reaped=False,pidfd_exit_verified=False)
    for name in ('serial.raw','qemu.stderr','guest-events.jsonl'):output.write(name,b'')
    try:
        output.check();latch.check();offline.trusted_tool(closed.QEMU);offline.read_pinned(closed.QEMU,qemu_hash)
        fds=tuple(output.pins[output.out/n] for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw'))
        args=qemu_argv(*(f'/proc/self/fd/{fd}' for fd in fds))
        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               close_fds=True,pass_fds=fds,cwd=output.out,env={'LC_ALL':'C','TZ':'UTC'},start_new_session=True)
        report.update(boot_executed=True,pid=child.pid,executed_argv=args)
        pidfd=os.pidfd_open(child.pid,0);report['process_birth_ticks']=closed.process_birth(child.pid)
        closed.capture(child,pidfd,output.pins[output.out/'serial.raw'],output.pins[output.out/'qemu.stderr'],output,latch)
        report['exit_code']=closed.reap_exact(child,pidfd);report.update(exact_child_reaped=True,pidfd_exit_verified=True)
        latch.check();output.check()
        if report['exit_code']!=0:raise ValueError('guest did not power off normally')
        observation=parse_events(output.read('serial.raw'),report)
        closed.write_all(output.pins[output.out/'guest-events.jsonl'],b''.join((json.dumps(e,sort_keys=True)+'\n').encode() for e in observation['events']))
        report.update(status=SUCCESS,observation=observation,event_count=len(observation['events']))
    except BaseException as error:
        report.update(status='FAILED_NO_ADMISSION',error=str(error))
        if child is not None and not report['exact_child_reaped']:
            try:
                if pidfd is not None:
                    report['exit_code']=closed.reap_exact(child,pidfd,kill=True);report['pidfd_exit_verified']=True
                else:child.kill();report['exit_code']=child.wait(timeout=closed.REAP_TIMEOUT)
                report['exact_child_reaped']=True
            except BaseException as error:report['teardown_error']=str(error)
    finally:
        if child is not None:
            for stream in (child.stdout,child.stderr):
                if stream is not None:stream.close()
        if pidfd is not None:os.close(pidfd)
        report.update(received_signal=latch.signum,disk_retained=True)
        try:
            for name in ('serial.raw','qemu.stderr','guest-events.jsonl'):os.fsync(output.pins[output.out/name])
            if report['exact_child_reaped']:
                os.fsync(output.pins[output.out/'fixture.raw']);output.check()
                report['post_reap_disk_sha256']=offline.fd_hash(output.pins[output.out/'fixture.raw'])
            closed.durable_receipt(output,'result.json',report)
        except BaseException as error:raise closed.LifecycleReceiptError(report,error) from error
    return report


def prepare(name,execute=False,qemu_hash=None):
    if os.getuid()==0 or os.geteuid()==0:raise ValueError('ordinary host UID required')
    if not re.fullmatch(r'warm-[a-z0-9][a-z0-9-]{0,24}',name):raise ValueError('fresh warm- output name required')
    if execute:
        if not qemu_hash or not re.fullmatch('[a-f0-9]{64}',qemu_hash):raise ValueError('reviewed QEMU SHA256 required')
        if not callable(getattr(os,'pidfd_open',None)) or not callable(getattr(signal,'pidfd_send_signal',None)):raise ValueError('pidfd lifecycle APIs required')
        offline.trusted_tool(closed.QEMU);offline.read_pinned(closed.QEMU,qemu_hash)
    schema=origin.SCHEMA.read_text()
    with offline.TrustedOutput(origin.INPUT) as inputs,offline.TrustedOutput(BASE,create=True) as output:
        fds={n:closed.attach(inputs,n,h) for n,h in (('vmlinuz',offline.KERNEL[2]),('kernel.config',offline.CONFIG_HASH),('modules.builtin',offline.BUILTIN_HASH))}
        cfg=os.pread(fds['kernel.config'],os.fstat(fds['kernel.config']).st_size,0).decode().splitlines()
        builtin=os.pread(fds['modules.builtin'],os.fstat(fds['modules.builtin']).st_size,0).decode().splitlines()
        if any('CONFIG_'+x+'=y' not in cfg for x in (*offline.REQUIRED_CONFIG,'UNIX')) or any(x not in builtin for x in offline.REQUIRED_BUILTIN):raise ValueError('kernel closure mismatch')
        for path,digest in ((origin.GCC,origin.GCC_SHA256),offline.PINS['mke2fs']):offline.trusted_tool(path);offline.read_pinned(path,digest)
        output.create_dir(name);nonce,lineage,fs_uuid=secrets.token_hex(16),secrets.token_hex(16),str(uuid.uuid4())
        output.write('source24.sqlite',origin.seed_database(schema,lineage));origin.verify_seed(output.out/'source24.sqlite',schema,lineage)
        output.write('schema_v24.sql',schema.encode());output.write('vmlinuz',os.pread(fds['vmlinuz'],os.fstat(fds['vmlinuz']).st_size,0))
        sources={n:(SOURCE/n).read_bytes() for n in SOURCE_NAMES}
        for n,data in sources.items():output.write(n,data)
        commands=[]
        for src,target in (('init.r1_warm.c','init.bin'),('r1_warm_probe.c','probe.bin')):
            output.write(target,b'');args=[str(origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',str(output.out/src),'-o',str(output.out/target)]
            result=subprocess.run(args,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
            os.fchmod(output.pins[output.out/target],0o600);output.check();output.write(target+'.compiler.log',result.stdout+result.stderr)
            commands.append({'argv':args,'exit':result.returncode})
            if result.returncode:raise ValueError('static compile failed: '+target)
            offline.static_elf(output.read(target))
        report={'schema':1,'status':OFFLINE,'boot_executed':False,'nonce':nonce,'fixture_uuid':fs_uuid,'lineage':lineage,
          'db_sha256':offline.sha(output.read('source24.sqlite')),'db_bytes':len(output.read('source24.sqlite')),
          'policy_sha256':offline.sha(POLICY),'pid1_sha256':offline.sha(output.read('init.bin')),'probe_sha256':offline.sha(output.read('probe.bin')),
          'source_pins':{n:offline.sha(v) for n,v in sources.items()},'runner_sha256':offline.sha(Path(__file__).read_bytes()),
          'schema_sha256':offline.sha(schema.encode()),'compiler_commands':commands,'disk_retained':True,
          'limits':['Fixed disposable PID1/custodian/broker only; no production constructor or admission',
                    'PID1 remains alive as pre-established observer; no PID1/kernel-loss claim',
                    'Custodian alone holds manager lock; no post-loss lock reacquisition or warm origin adoption',
                    'Scoped issued broker FD intentionally remains readable until exact broker death',
                    'Canonical fixture source24; no live data, migration, pending/final or runtime readiness',
                    'Root/kernel/hypervisor/invoking UID/toolchain trusted; no arbitrary hostile broker proof']}
        fields=('nonce','fixture_uuid','db_sha256','lineage','policy_sha256','pid1_sha256','probe_sha256')
        config=('\n'.join(report[k] for k in fields)+'\n').encode()
        entries=[(p,stat.S_IFDIR|(0o700 if p=='fixture' else 0o755),b'',0,0) for p in ('bin','dev','etc','fixture','proc','run','sys')]
        entries += [('run/sealed',stat.S_IFDIR|0o700,b'',0,0),('dev/console',stat.S_IFCHR|0o600,b'',5,1),
                    ('init',stat.S_IFREG|0o700,output.read('init.bin'),0,0),('bin/r1-warm-probe',stat.S_IFREG|0o755,output.read('probe.bin'),0,0),
                    ('etc/r1-warm.config',stat.S_IFREG|0o600,config,0,0),('etc/source24.sqlite',stat.S_IFREG|0o600,output.read('source24.sqlite'),0,0)]
        output.write('initramfs.cpio.gz',gzip.compress(offline.newc(sorted(entries)),mtime=0));output.write('fixture.raw',b'')
        disk=output.pins[output.out/'fixture.raw'];os.ftruncate(disk,offline.SIZE)
        output.write('mke2fs.conf',b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
        args=[offline.PINS['mke2fs'][0],'-q','-t','ext4','-b','4096','-I','256','-N','2048','-m','0','-U',fs_uuid,'-O','none,extent,filetype,sparse_super,large_file','-E','lazy_itable_init=0',f'/proc/self/fd/{disk}']
        result=subprocess.run(args,pass_fds=(disk,),capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','MKE2FS_CONFIG':str(output.out/'mke2fs.conf')})
        output.check();output.write('mke2fs.log',result.stdout+result.stderr)
        if result.returncode:raise ValueError('fresh disposable image creation failed')
        report.update(output=str(output.out),disk_device=os.fstat(disk).st_dev,disk_inode=os.fstat(disk).st_ino,
                      artifacts={n:offline.sha(output.read(n)) for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw')})
        for fd in output.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode):os.fsync(fd)
        os.fsync(output.pins[output.out]);inputs.check();closed.durable_receipt(output,'plan.json',report)
        if execute:
            with closed.SignalLatch() as latch:return run_guest(output,report,qemu_hash,latch)
        closed.durable_receipt(output,'result.json',report);return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True);p.add_argument('--run',action='store_true');p.add_argument('--qemu-sha256')
    a=p.parse_args()
    try:report=prepare(a.name,a.run,a.qemu_sha256);print(json.dumps(report,sort_keys=True))
    except closed.LifecycleReceiptError as error:
        print(json.dumps({'status':'LIFECYCLE_OR_REPORTING_FAILED','error':str(error),'boot_executed':error.report['boot_executed'],
                          'pid':error.report.get('pid'),'exact_child_reaped':error.report['exact_child_reaped'],
                          'pidfd_exit_verified':error.report['pidfd_exit_verified']}),file=sys.stderr);return 2
    except BaseException as error:
        print(json.dumps({'status':'REFUSED_OR_FAILED_INSPECT_RETAINED_ARTIFACTS','error':str(error)}),file=sys.stderr);return 2
    return 0 if report['status'] in (OFFLINE,SUCCESS) else 2


if __name__=='__main__':sys.exit(main())
