#!/usr/bin/env python3
"""Separate fixed two-boot CLOSED diagnostic. Default only builds offline artifacts."""
import argparse
import errno
import gzip
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import run_closed_origin_vm as origin

BASE = Path('/home/olegchir/podbay-r1-two-boot-origin-build')
SOURCE = Path(__file__).resolve().parent
POLICY = b'guest-r1-two-boot-v1;closed-before-source;owner1000;fresh-lock;no-admission'
SUCCESS = 'DISPOSABLE_TWO_BOOT_CLOSED_RECOVERY_NO_PRODUCTION_ADMISSION'
A_SUCCESS = 'BOOT_A_CRASHED_WITH_LIVE_BROKER_AT_DURABLE_CLOSED_CHECKPOINT'
B_SUCCESS = 'BOOT_B_FRESH_CLOSED_RECOVERY_NO_AUTHORITY_RESTORED'
SOURCE_NAMES = ('closed_origin_shared.h', 'r1_two_boot_checkpoint.h', 'r1_two_boot_probe.c', 'init.r1_two_boot.c')
KEYS = {'schema', 'event', 'phase', 'sequence', 'nonce', 'fixture_uuid', 'boot_id', 'boot_a', 'gate',
        'admission', 'origin_restored', 'source_pinned', 'source_device', 'source_inode', 'source_uid',
        'source_bytes', 'expected_source_sha256', 'source_sha256', 'lineage', 'policy_sha256',
        'pid1_sha256', 'probe_sha256', 'checkpoint_sha256', 'checkpoint_inode', 'old_broker_pid',
        'old_broker_birth', 'actor_pid', 'actor_birth', 'rc', 'errno'}
DENIAL_NAMES = ('source', 'wal', 'shm', 'journal', 'proc_root', 'proc_fd', 'namespace', 'unshare')


def expected_sequence(phase):
    def outside(point):
        return [(f'outside_{point}_{name}', -1, point) for name in DENIAL_NAMES] + [('outside_reaped', 0, point)]
    if phase == 'A':
        return [('closed_before_source', 0, 'pid1'), ('vault_closed_created', 0, 'pid1'),
                ('fresh_lock_custody', 0, 'pid1'), ('seed_read_started', 0, 'pid1'),
                ('source24_verified', 24, 'pid1'), ('clean_exec_sealed', 0, 'broker'),
                ('broker_source_opened', 100, 'broker')] + outside('broker_alive') + [
                ('checkpoint_durable', 0, 'pid1'), ('broker_fd_confirmed', 0, 'broker'),
                ('crash_ready_live_broker_closed', 0, 'broker')]
    if phase == 'B':
        return [('closed_before_source', 0, 'pid1'), ('vault_closed_recovered', 0, 'pid1'),
                ('historical_checkpoint_verified_no_authority', 0, 'pid1'), ('fresh_lock_custody', 0, 'pid1'),
                ('source_read_started', 0, 'pid1'), ('source24_verified', 24, 'pid1')] + outside('before_broker') + [
                ('clean_exec_sealed', 0, 'broker'), ('broker_source_opened', 0, 'broker')] + outside('broker_alive') + [
                ('broker_fd_confirmed', 0, 'broker'), ('broker_killed_reaped', -signal.SIGKILL, 'broker')] + outside('after_broker_death') + [
                ('source_checkpoint_preserved', 24, 'pid1'), ('recovered_closed_no_admission', 0, 'pid1')]
    raise ValueError('fixed A/B phase required')


def parse_phase(raw, phase, pins, prior=None, prefix=False):
    if len(raw) > closed.MAX_SERIAL or b'\0' in raw or (raw and not raw.endswith(b'\n')):
        raise ValueError('partial/NUL/oversized phase capture')
    text = raw.decode('utf-8', errors='strict')
    if re.search(r'kernel panic|not syncing|oops:|BUG:|segmentation fault', text, re.I):
        raise ValueError('fatal guest diagnostic')
    lines = text.splitlines()
    encoded = [line for line in lines if line.startswith('{')]
    if any(len(line) > 4096 for line in encoded): raise ValueError('oversized event')
    events = [json.loads(line, object_pairs_hook=closed.strict_object) for line in encoded]
    expected = expected_sequence(phase)
    if len(events) > len(expected) or (not prefix and len(events) != len(expected)):
        raise ValueError('missing/extra phase events')
    if not events:
        if prefix: return None
        raise ValueError('no guest events')
    boot = events[0].get('boot_id')
    if not isinstance(boot, str) or not origin.BOOT_ID.fullmatch(boot): raise ValueError('invalid guest boot identity')
    if phase == 'B' and (not prior or boot == prior['boot_id']): raise ValueError('Boot B is not a fresh kernel')
    actors, source, checkpoint = {}, None, None
    known = checkpoint_known = False
    expected_hashes = {key: pins[key] for key in ('nonce', 'fixture_uuid', 'lineage', 'policy_sha256', 'pid1_sha256', 'probe_sha256')}
    for i, (e, (name, rc, role)) in enumerate(zip(events, expected), 1):
        if (set(e) != KEYS or type(e['schema']) is not int or e['schema'] != 1 or e['event'] != name
                or e['phase'] != phase or e['sequence'] != i or e['rc'] != rc or e['boot_id'] != boot
                or e['gate'] != 'CLOSED' or e['admission'] != 'UNIMPLEMENTED' or e['origin_restored'] is not False
                or any(e[k] != v for k, v in expected_hashes.items())
                or e['expected_source_sha256'] != pins['db_sha256']):
            raise ValueError('foreign/out-of-order/authority-claim event')
        for key in ('sequence', 'source_device', 'source_inode', 'source_uid', 'source_bytes', 'checkpoint_inode',
                    'old_broker_pid', 'old_broker_birth', 'actor_pid', 'actor_birth', 'rc', 'errno'):
            if type(e[key]) is not int: raise ValueError('noninteger event identity')
        if type(e['source_pinned']) is not bool: raise ValueError('nonboolean source state')
        if e['actor_pid'] < 1 or e['actor_birth'] < 1: raise ValueError('missing actor birth')
        if (role == 'pid1') != (e['actor_pid'] == 1): raise ValueError('wrong actual PID1/child identity')
        if actors.setdefault(role, (e['actor_pid'], e['actor_birth'])) != (e['actor_pid'], e['actor_birth']):
            raise ValueError('actor changed between phase and reap')
        denial = name.startswith('outside_') and name != 'outside_reaped'
        if e['errno'] not in ((errno.EPERM, errno.EACCES) if denial else (0,)):
            raise ValueError('path denial was not a permission failure')
        if name.endswith('_unshare') and e['errno'] != errno.EPERM: raise ValueError('unshare not denied')
        known |= name == 'source24_verified'
        if e['source_pinned'] != known: raise ValueError('source claimed before validated access boundary')
        values = (e['source_device'], e['source_inode'], e['source_uid'], e['source_bytes'], e['source_sha256'])
        if not known:
            if values != (0, 0, 0, 0, ''): raise ValueError('source pin fabricated before access')
        else:
            if values[0] <= 0 or values[1] <= 0 or values[2] != 1000 or values[3] != pins['db_bytes'] or values[4] != pins['db_sha256']:
                raise ValueError('source fixture identity/bytes differ')
            if source is None: source = values
            if source != values or (phase == 'B' and list(values) != prior['source']):
                raise ValueError('source changed across boot/phase')
        checkpoint_known |= name in ('checkpoint_durable', 'historical_checkpoint_verified_no_authority')
        state = (e['checkpoint_sha256'], e['checkpoint_inode'], e['boot_a'], e['old_broker_pid'], e['old_broker_birth'])
        if not checkpoint_known:
            if state != ('', 0, '', 0, 0): raise ValueError('checkpoint claimed before verification')
        else:
            if not re.fullmatch('[a-f0-9]{64}', state[0]) or state[1] <= 0 or state[2] != (boot if phase == 'A' else prior['boot_id']) or state[3] <= 1 or state[4] <= 0:
                raise ValueError('invalid historical checkpoint binding')
            if checkpoint is None: checkpoint = state
            if checkpoint != state or (phase == 'B' and list(state) != prior['checkpoint']):
                raise ValueError('checkpoint changed across boot/phase')
            if phase == 'A' and tuple(state[3:]) != actors.get('broker'):
                raise ValueError('checkpoint does not bind held Boot A broker')
    if len(set(actors.values())) != len(actors): raise ValueError('independent actors alias an identity')
    # During an incomplete prefix, allow only kernel diagnostics besides strict JSON.
    for line in lines:
        line = line.strip()
        if line and not line.startswith('{') and not re.match(r'^\[\s*\d+\.\d+\]', line):
            raise ValueError('unexpected non-kernel phase output')
    if len(events) != len(expected): return None
    normalized = []
    remaining = len(encoded)
    for line in lines:
        if line.startswith('{'):
            remaining -= 1
            if remaining == 0: normalized.append(json.dumps(closed.EXPECTED_EVENT))
        else: normalized.append(line)
    closed.parse_serial(('\n'.join(normalized)+'\n').encode())
    if phase == 'A' and any('reboot: Power down' in line for line in lines):
        raise ValueError('Boot A ended gracefully instead of holding the broker')
    return {'boot_id': boot, 'source': list(source), 'checkpoint': list(checkpoint), 'events': events,
            'broker': list(actors['broker']), 'pid1': list(actors['pid1'])}


def argv(kernel, initramfs, disk, phase):
    expected_sequence(phase)
    args = origin.qemu_argv(kernel, initramfs, disk)
    # The serial console carries a strict PID1 event stream. Suppress ordinary
    # informational printk chatter; error output still causes strict refusal
    # if it corrupts a record. Never repair or ignore an interleaved record.
    args[args.index('-append')+1] += ' loglevel=4 r1.phase='+phase
    return args


def capture_a(child, pidfd, logs, pins, latch):
    deadline = time.monotonic()+closed.TIMEOUT
    sizes = {'serial': 0, 'stderr': 0}
    accepted = None
    with selectors.DefaultSelector() as selector:
        for stream, name, cap in ((child.stdout, 'serial', closed.MAX_SERIAL), (child.stderr, 'stderr', closed.MAX_STDERR)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (name, cap))
        while accepted is None:
            latch.check()
            left = deadline-time.monotonic()
            if left <= 0: raise TimeoutError('Boot A crash-ready deadline')
            if not selector.get_map(): raise ValueError('QEMU streams ended before crash-ready')
            for key, _ in selector.select(min(left, 1)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data: selector.unregister(key.fileobj); continue
                name, cap = key.data; sizes[name] += len(data)
                if sizes[name] > cap: raise ValueError('Boot A capture bound')
                target = 'serial.raw' if name == 'serial' else 'qemu.stderr'
                logs.check(); closed.write_all(logs.pins[logs.out/target], data); logs.check()
                if name == 'serial':
                    raw = logs.read('serial.raw'); complete = raw[:raw.rfind(b'\n')+1]
                    accepted = parse_phase(complete, 'A', pins, prefix=True)
    latch.check()
    if child.poll() is not None: raise ValueError('Boot A exited before exact crash signal')
    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    code = closed.reap_exact(child, pidfd)
    if code != -signal.SIGKILL: raise ValueError('Boot A termination was not exact SIGKILL')
    closed.capture(child, pidfd, logs.pins[logs.out/'serial.raw'], logs.pins[logs.out/'qemu.stderr'], logs, latch)
    if os.fstat(logs.pins[logs.out/'serial.raw']).st_size > closed.MAX_SERIAL or os.fstat(logs.pins[logs.out/'qemu.stderr']).st_size > closed.MAX_STDERR:
        raise ValueError('aggregate Boot A capture bound')
    return parse_phase(logs.read('serial.raw'), 'A', pins)


def run_boot(output, phase, pins, qemu_hash, latch, report, prior=None):
    child = pidfd = None
    report.update(phase=phase, status='NOT_STARTED', boot_executed=False, exact_child_reaped=False, pidfd_exit_verified=False)
    with offline.TrustedOutput(output.out) as logs:
        logs.create_dir('boot-'+phase.lower())
        for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'): logs.write(name, b'')
        try:
            output.check(); logs.check(); latch.check()
            offline.trusted_tool(closed.QEMU); offline.read_pinned(closed.QEMU, qemu_hash)
            fds = tuple(output.pins[output.out/n] for n in ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw'))
            args = argv(*(f'/proc/self/fd/{fd}' for fd in fds), phase)
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     close_fds=True, pass_fds=fds, cwd=output.out, env={'LC_ALL':'C', 'TZ':'UTC'}, start_new_session=True)
            report.update(boot_executed=True, pid=child.pid, executed_argv=args)
            pidfd = os.pidfd_open(child.pid, 0); report['process_birth_ticks'] = closed.process_birth(child.pid)
            if phase == 'A':
                observation = capture_a(child, pidfd, logs, pins, latch)
                code = -signal.SIGKILL
            else:
                closed.capture(child, pidfd, logs.pins[logs.out/'serial.raw'], logs.pins[logs.out/'qemu.stderr'], logs, latch)
                code = closed.reap_exact(child, pidfd)
                if code != 0: raise ValueError('Boot B did not power off normally')
                observation = parse_phase(logs.read('serial.raw'), 'B', pins, prior)
            report.update(exit_code=code, exact_child_reaped=True, pidfd_exit_verified=True, observation=observation)
            latch.check(); output.check()
            closed.write_all(logs.pins[logs.out/'guest-events.jsonl'], b''.join((json.dumps(e, sort_keys=True)+'\n').encode() for e in observation['events']))
            report['status'] = A_SUCCESS if phase == 'A' else B_SUCCESS
        except BaseException as error:
            report.update(status='FAILED_OR_LIFECYCLE_UNVERIFIED', error=str(error))
            if child is not None and not report['exact_child_reaped']:
                try:
                    if pidfd is not None:
                        report['exit_code'] = closed.reap_exact(child, pidfd, kill=True); report['pidfd_exit_verified'] = True
                    else:
                        child.kill(); report['exit_code'] = child.wait(timeout=closed.REAP_TIMEOUT)
                    report['exact_child_reaped'] = True
                except BaseException as error: report['teardown_error'] = str(error)
        finally:
            if child is not None:
                for stream in (child.stdout, child.stderr):
                    if stream is not None: stream.close()
            if pidfd is not None: os.close(pidfd)
            report['received_signal'] = latch.signum
            for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'): os.fsync(logs.pins[logs.out/name])
            closed.durable_receipt(logs, 'result.json', report)
    return report


def run_pair(output, report, qemu_hash):
    with closed.SignalLatch() as latch:
        try:
            for phase in ('A', 'B'):
                latch.check(); boot = {}; report['boots'].append(boot)
                prior = report['boots'][0]['observation'] if phase == 'B' else None
                run_boot(output, phase, report, qemu_hash, latch, boot, prior)
                if boot['status'] != (A_SUCCESS if phase == 'A' else B_SUCCESS) or not boot['exact_child_reaped'] or not boot['pidfd_exit_verified']:
                    raise ValueError('phase failed; no further boot is permitted')
                disk = output.pins[output.out/'fixture.raw']; os.fsync(disk); output.check()
                boot['post_reap_disk_sha256'] = offline.fd_hash(disk)
            report['status'] = SUCCESS
        except BaseException as error: report.update(status='FAILED_NO_ADMISSION', error=str(error))
        finally:
            report['received_signal'] = latch.signum
            report['disk_retained'] = True
            closed.durable_receipt(output, 'result.json', report)
    return report


def prepare(name, execute=False, qemu_hash=None):
    if os.getuid()==0 or os.geteuid()==0: raise ValueError('ordinary host UID required')
    if not re.fullmatch(r'r1-[a-z0-9][a-z0-9-]{0,26}', name): raise ValueError('new r1- output name required')
    if execute:
        if not qemu_hash or not re.fullmatch('[a-f0-9]{64}', qemu_hash): raise ValueError('reviewed QEMU SHA-256 required')
        if not callable(getattr(os,'pidfd_open',None)) or not callable(getattr(signal,'pidfd_send_signal',None)): raise ValueError('pidfd lifecycle APIs required')
        offline.trusted_tool(closed.QEMU); offline.read_pinned(closed.QEMU,qemu_hash)
    schema = origin.SCHEMA.read_text()
    with offline.TrustedOutput(origin.INPUT) as inputs, offline.TrustedOutput(BASE, create=True) as output:
        fds={n:closed.attach(inputs,n,h) for n,h in (('vmlinuz',offline.KERNEL[2]),('kernel.config',offline.CONFIG_HASH),('modules.builtin',offline.BUILTIN_HASH))}
        cfg=os.pread(fds['kernel.config'],os.fstat(fds['kernel.config']).st_size,0).decode().splitlines()
        builtin=os.pread(fds['modules.builtin'],os.fstat(fds['modules.builtin']).st_size,0).decode().splitlines()
        if any('CONFIG_'+x+'=y' not in cfg for x in (*offline.REQUIRED_CONFIG,'UNIX')) or any(x not in builtin for x in offline.REQUIRED_BUILTIN): raise ValueError('kernel closure mismatch')
        for path,digest in ((origin.GCC,origin.GCC_SHA256),offline.PINS['mke2fs']): offline.trusted_tool(path);offline.read_pinned(path,digest)
        output.create_dir(name); nonce,lineage,fs_uuid=secrets.token_hex(16),secrets.token_hex(16),str(uuid.uuid4())
        output.write('source24.sqlite',origin.seed_database(schema,lineage));origin.verify_seed(output.out/'source24.sqlite',schema,lineage)
        output.write('schema_v24.sql',schema.encode());output.write('vmlinuz',os.pread(fds['vmlinuz'],os.fstat(fds['vmlinuz']).st_size,0))
        sources={n:(SOURCE/n).read_bytes() for n in SOURCE_NAMES}
        for n,data in sources.items():output.write(n,data)
        commands=[]
        for src,target in (('init.r1_two_boot.c','init.bin'),('r1_two_boot_probe.c','probe.bin')):
            output.write(target,b'');args=[str(origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',str(output.out/src),'-o',str(output.out/target)]
            r=subprocess.run(args,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
            os.fchmod(output.pins[output.out/target],0o600);output.check();output.write(target+'.compiler.log',r.stdout+r.stderr)
            commands.append({'argv':args,'exit':r.returncode})
            if r.returncode:raise ValueError('static compile failed: '+target)
            offline.static_elf(output.read(target))
        report={'schema':1,'status':'OFFLINE_TWO_BOOT_CANDIDATE_UNBOOTED','boots':[], 'nonce':nonce,'fixture_uuid':fs_uuid,'lineage':lineage,
          'db_sha256':offline.sha(output.read('source24.sqlite')),'db_bytes':len(output.read('source24.sqlite')),
          'policy_sha256':offline.sha(POLICY),'pid1_sha256':offline.sha(output.read('init.bin')),'probe_sha256':offline.sha(output.read('probe.bin')),
          'source_pins':{n:offline.sha(v) for n,v in sources.items()},'runner_sha256':offline.sha(Path(__file__).read_bytes()),
          'schema_sha256':offline.sha(schema.encode()),'compiler_commands':commands,'disk_retained':True,
          'limits':['Fixture-only cold-boot launch closure; no production constructor or admission',
                    'Selected abrupt QEMU crash at durable checkpoint; not arbitrary power-loss durability',
                    'Boot B acquires new lock custody; prior handles never restore authority',
                    'Canonical source24 only; no migration, pending, activation or terminal proof',
                    'Host root/invoking UID/toolchain/kernel/hypervisor remain trusted']}
        fields=('nonce','fixture_uuid','db_sha256','lineage','policy_sha256','pid1_sha256','probe_sha256')
        config=('\n'.join(report[k] for k in fields)+'\n').encode()
        entries=[(p,stat.S_IFDIR|(0o700 if p=='fixture' else 0o755),b'',0,0) for p in ('bin','dev','etc','fixture','proc','run','sys')]
        entries += [('run/sealed',stat.S_IFDIR|0o700,b'',0,0),('dev/console',stat.S_IFCHR|0o600,b'',5,1),
                    ('init',stat.S_IFREG|0o700,output.read('init.bin'),0,0),('bin/r1-probe',stat.S_IFREG|0o755,output.read('probe.bin'),0,0),
                    ('etc/r1.config',stat.S_IFREG|0o600,config,0,0),('etc/source24.sqlite',stat.S_IFREG|0o600,output.read('source24.sqlite'),0,0)]
        output.write('initramfs.cpio.gz',gzip.compress(offline.newc(sorted(entries)),mtime=0));output.write('fixture.raw',b'')
        disk=output.pins[output.out/'fixture.raw'];os.ftruncate(disk,offline.SIZE)
        output.write('mke2fs.conf',b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
        args=[offline.PINS['mke2fs'][0],'-q','-t','ext4','-b','4096','-I','256','-N','2048','-m','0','-U',fs_uuid,'-O','none,extent,filetype,sparse_super,large_file','-E','lazy_itable_init=0',f'/proc/self/fd/{disk}']
        r=subprocess.run(args,pass_fds=(disk,),capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','MKE2FS_CONFIG':str(output.out/'mke2fs.conf')})
        output.check();output.write('mke2fs.log',r.stdout+r.stderr)
        if r.returncode:raise ValueError('new disposable image creation failed')
        report.update(output=str(output.out),disk_device=os.fstat(disk).st_dev,disk_inode=os.fstat(disk).st_ino,
                      artifacts={n:offline.sha(output.read(n)) for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw')})
        for fd in output.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode):os.fsync(fd)
        os.fsync(output.pins[output.out]);inputs.check();closed.durable_receipt(output,'plan.json',report)
        if execute:return run_pair(output,report,qemu_hash)
        closed.durable_receipt(output,'result.json',report);return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--name',required=True);p.add_argument('--run',action='store_true');p.add_argument('--qemu-sha256')
    a=p.parse_args()
    try:report=prepare(a.name,a.run,a.qemu_sha256);print(json.dumps(report,sort_keys=True))
    except BaseException as error:
        print(json.dumps({'status':'REFUSED_OR_FAILED_INSPECT_RETAINED_ARTIFACTS','error':str(error)}),file=sys.stderr);return 2
    return 0 if report['status'] in ('OFFLINE_TWO_BOOT_CANDIDATE_UNBOOTED',SUCCESS) else 2


if __name__=='__main__':sys.exit(main())
