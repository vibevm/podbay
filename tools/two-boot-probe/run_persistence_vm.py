#!/usr/bin/env python3
"""Disposable CLOSED marker across two fresh VMs; never v25 migration/admission."""
import argparse
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

BASE = Path('/home/olegchir/podbay-two-boot-persistence-build')
INPUT = offline.BASE / 'final-a'
GCC = Path('/usr/bin/x86_64-linux-gnu-gcc-15')
GCC_SHA256 = 'b5f1b773a7c733738352000c92a077dc5852a1a2fc6d836b1e411be1e9ec5f88'
SUCCESS = 'TWO_BOOT_CLOSED_MARKER_PERSISTED_NO_ADMISSION'
NEGATIVE_SUCCESS = 'BOOT_B_PARTIAL_GATE_REFUSED_NO_ADMISSION'
PARTIAL = b'PODBAY-PERSISTENCE/1\nstate=CLO'
DEBUGFS = Path(offline.PINS['debugfs'][0])
PREFIX = b'PODBAY-PERSISTENCE/1\nstate=CLOSED\nadmission=UNIMPLEMENTED\nnonce='
SUFFIX = b'\npayload=DISPOSABLE-CLOSED-MARKER-NOT-V25-AUTHORITY\n'
BOOT_ID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')


def marker(nonce, boot_a):
    if not re.fullmatch(r'[a-f0-9]{32}', nonce) or not BOOT_ID.fullmatch(boot_a):
        raise ValueError('invalid exact marker subject')
    return PREFIX + nonce.encode() + b'\nboot_a=' + boot_a.encode() + SUFFIX


def argv(kernel, initramfs, disk, phase):
    if phase not in ('A', 'B'):
        raise ValueError('closed phase set')
    args = closed.qemu_argv(kernel, initramfs, disk)
    args[args.index('-append') + 1] += ' persistence.phase=' + phase
    args[args.index('-drive') + 1] = f'file={disk},if=none,id=closedfixture,format=raw,readonly=off,cache=none'
    return args


def parse_event(raw, phase, nonce, prior=None):
    # Reuse the reviewed shutdown-chatter parser with the independently validated exact event.
    if not raw.endswith(b'\n') or b'\0' in raw or len(raw) > closed.MAX_SERIAL:
        raise ValueError('incomplete/NUL/oversized capture')
    text = raw.decode('utf-8', errors='strict')
    lines = [line for line in text.splitlines() if line.startswith('{')]
    if len(lines) != 1 or len(lines[0]) > 4096:
        raise ValueError('one bounded guest event required')
    event = json.loads(lines[0], object_pairs_hook=closed.strict_object)
    keys = {'event', 'phase', 'gate', 'admission', 'nonce', 'boot_id', 'boot_a', 'inode', 'marker_hex'}
    if set(event) != keys or event['event'] != 'closed_marker_persistence' or event['phase'] != phase:
        raise ValueError('unexpected/failed/foreign guest event')
    if event['gate'] != 'CLOSED' or event['admission'] != 'UNIMPLEMENTED' or event['nonce'] != nonce:
        raise ValueError('not the exact disposable CLOSED subject')
    if not isinstance(event['boot_id'], str) or not BOOT_ID.fullmatch(event['boot_id']):
        raise ValueError('invalid guest boot ID')
    if type(event['inode']) is not int or event['inode'] <= 0:
        raise ValueError('invalid persistent inode')
    expected_a = event['boot_id'] if phase == 'A' else prior['boot_id'] if prior else None
    if event['boot_a'] != expected_a or (phase == 'B' and event['boot_id'] == expected_a):
        raise ValueError('foreign/non-fresh boot lineage')
    if event['marker_hex'] != marker(nonce, expected_a).hex():
        raise ValueError('malformed/partial/foreign marker bytes')
    if phase == 'B' and (event['inode'] != prior['inode'] or event['marker_hex'] != prior['marker_hex']):
        raise ValueError('persistent marker identity/bytes changed')
    # No global parser mutation: replace only the exact validated event line in this capture.
    normalized = raw.replace(lines[0].encode(), json.dumps(closed.EXPECTED_EVENT).encode(), 1)
    closed.parse_serial(normalized)
    return event


def parse_partial_refusal(raw, nonce, prior):
    if not raw.endswith(b'\n') or b'\0' in raw or len(raw) > closed.MAX_SERIAL:
        raise ValueError('incomplete/NUL/oversized refusal capture')
    lines = [line for line in raw.decode('utf-8', errors='strict').splitlines() if line.startswith('{')]
    if len(lines) != 1 or len(lines[0]) > 4096:
        raise ValueError('one bounded refusal event required')
    event = json.loads(lines[0], object_pairs_hook=closed.strict_object)
    expected = {'event':'persistence_refused', 'gate':'CLOSED', 'admission':'UNIMPLEMENTED',
                'reason':'existing_or_partial_gate', 'phase':'B', 'nonce':nonce,
                'boot_id':event.get('boot_id')}
    if event != expected or not isinstance(event['boot_id'],str) or not BOOT_ID.fullmatch(event['boot_id']) or event['boot_id'] == prior['boot_id']:
        raise ValueError('not the exact fresh-B partial-gate refusal')
    normalized = raw.replace(lines[0].encode(),json.dumps(closed.EXPECTED_EVENT).encode(),1)
    closed.parse_serial(normalized)
    return event


def debugfs_command(output, command, tag, writable=False, extra_fds=(), missing=False):
    output.check(); offline.trusted_tool(DEBUGFS); offline.read_pinned(*offline.PINS['debugfs'])
    disk = output.pins[output.out/'fixture.raw']
    args=[str(DEBUGFS)] + (['-w'] if writable else []) + ['-R',command,f'/proc/self/fd/{disk}']
    result=subprocess.run(args,pass_fds=(disk,*extra_fds),capture_output=True,timeout=30,
                          env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
    output.check()
    output.write('negative-'+tag+'.log',result.stdout+result.stderr)
    os.fsync(output.pins[output.out/('negative-'+tag+'.log')])
    text=(result.stdout+result.stderr).decode('utf-8',errors='strict')
    if len(text)>65536 or result.returncode:
        raise ValueError('debugfs failed/oversized output: '+tag)
    if missing:
        if not re.search(r'File not found by ext2_lookup',text) or re.search(r'Inode:',text):
            raise ValueError('partial gate is not proved absent')
    elif re.search(r'File not found|already exists|Filesystem not open|Usage:|while |Command not found|Could not|Error|not a directory',text,re.I):
        raise ValueError('debugfs command failed: '+tag)
    return text


def disk_file(output,path,tag):
    text=debugfs_command(output,'stat '+path,tag+'-stat')
    patterns={'inode':r'Inode:\s*(\d+)', 'mode':r'Mode:\s*0*([0-7]+)',
              'uid':r'User:\s*(\d+)', 'gid':r'Group:\s*(\d+)',
              'links':r'Links:\s*(\d+)', 'size':r'Size:\s*(\d+)'}
    values={}
    for key,pattern in patterns.items():
        found=re.search(pattern,text)
        if found is None: raise ValueError('missing debugfs identity '+key)
        values[key]=int(found[1],8 if key=='mode' else 10)
    if not re.search(r'Type:\s*regular',text) or values['uid'] or values['gid'] or values['mode']!=0o600 or values['links']!=1 or not 0<values['size']<=512:
        raise ValueError('foreign disk file identity')
    name='negative-'+tag+'.bin'; output.write(name,b''); fd=output.pins[output.out/name]
    debugfs_command(output,f'dump {path} /proc/self/fd/{fd}',tag+'-dump',extra_fds=(fd,))
    os.fsync(fd)
    data=output.read(name)
    if len(data)!=values['size']: raise ValueError('disk readback length mismatch')
    values['sha256']=offline.sha(data)
    return values,data


def verify_partial(output, prior, expected, tag):
    record,record_bytes=disk_file(output,'/closed/gate.record',tag+'-record')
    partial,partial_bytes=disk_file(output,'/closed/gate.writing',tag+'-partial')
    if record != expected['record'] or record_bytes.hex()!=prior['marker_hex'] or partial != expected['partial'] or partial_bytes != PARTIAL:
        raise ValueError('original record or injected partial identity/bytes changed')
    return {'record':record,'partial':partial}


def inject_partial(output, boot_a):
    if (boot_a.get('status')!='CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION' or
        boot_a.get('boot_executed') is not True or boot_a.get('exact_child_reaped') is not True or
        boot_a.get('pidfd_exit_verified') is not True or type(boot_a.get('exit_code')) is not int or boot_a['exit_code']!=0):
        raise ValueError('injection requires validated exact Boot-A exit/reap/fsync')
    prior=boot_a['event']
    parse_event((json.dumps(prior)+'\n').encode(),'A',prior['nonce'])
    disk=output.pins[output.out/'fixture.raw']; os.fsync(disk); output.check()
    debugfs_command(output,'stat /closed/gate.writing','before-partial-absence',missing=True)
    record,record_bytes=disk_file(output,'/closed/gate.record','before-record')
    if record['inode']!=prior['inode'] or record_bytes.hex()!=prior['marker_hex']:
        raise ValueError('Boot-A record identity/bytes not preserved before injection')
    output.write('partial-gate.bin',PARTIAL); fd=output.pins[output.out/'partial-gate.bin']; os.fsync(fd)
    debugfs_command(output,f'write /proc/self/fd/{fd} /closed/gate.writing','create-partial',True,(fd,))
    for field,value in (('uid','0'),('gid','0'),('mode','0100600')):
        debugfs_command(output,f'set_inode_field /closed/gate.writing {field} {value}','partial-'+field,True)
    os.fsync(disk); output.check()
    after,after_bytes=disk_file(output,'/closed/gate.record','after-record')
    partial,partial_bytes=disk_file(output,'/closed/gate.writing','after-partial')
    if after!=record or after_bytes!=record_bytes or partial_bytes!=PARTIAL or partial['inode']==record['inode']:
        raise ValueError('injection changed original record or failed exact exclusive partial readback')
    receipt={'case':'partial-writing','debugfs_sha256':offline.PINS['debugfs'][1],
             'record':record,'partial':partial,'original_marker_hex':record_bytes.hex(),
             'injected_hex':PARTIAL.hex(),'disk_device':os.fstat(disk).st_dev,'disk_inode':os.fstat(disk).st_ino}
    closed.durable_receipt(output,'negative-injection.json',receipt)
    return receipt


def run_boot(inputs, output, phase, nonce, qemu_hash, latch, prior=None, partial_refusal=False):
    report = {'phase': phase, 'boot_executed': False, 'exact_child_reaped': False,
              'pidfd_exit_verified': False, 'status': 'NOT_STARTED'}
    with offline.TrustedOutput(output.out) as logs:
        logs.create_dir('boot-' + phase.lower())
        for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'):
            logs.write(name, b'')
        child = pidfd = None
        try:
            inputs.check(); output.check(); latch.check()
            offline.trusted_tool(closed.QEMU); offline.read_pinned(closed.QEMU, qemu_hash)
            fds = tuple(output.pins[output.out / name] for name in ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw'))
            command = argv(*(f'/proc/self/fd/{fd}' for fd in fds), phase)
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, close_fds=True, pass_fds=fds,
                                     cwd=output.out, env={'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
            report.update(boot_executed=True, pid=child.pid, executed_argv=command)
            pidfd = os.pidfd_open(child.pid, 0)
            report['process_birth_ticks'] = closed.process_birth(child.pid)
            closed.capture(child, pidfd, logs.pins[logs.out / 'serial.raw'],
                           logs.pins[logs.out / 'qemu.stderr'], logs, latch)
            report['exit_code'] = closed.reap_exact(child, pidfd)
            report.update(exact_child_reaped=True, pidfd_exit_verified=True)
            latch.check(); inputs.check(); output.check()
            if report['exit_code'] != 0:
                raise ValueError('QEMU nonzero exit')
            if partial_refusal and phase != 'B': raise ValueError('refusal oracle only for Boot B')
            report['event'] = parse_partial_refusal(logs.read('serial.raw'),nonce,prior) if partial_refusal else parse_event(logs.read('serial.raw'), phase, nonce, prior)
            closed.write_all(logs.pins[logs.out / 'guest-events.jsonl'],
                             (json.dumps(report['event'], sort_keys=True) + '\n').encode())
            report['status'] = 'CLOSED_PARTIAL_GATE_REFUSAL_OBSERVED_NO_ADMISSION' if partial_refusal else 'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION'
        except BaseException as error:
            report.update(status='FAILED_OR_LIFECYCLE_UNVERIFIED', error=str(error))
            if child is not None:
                try:
                    if pidfd is not None:
                        report['exit_code'] = closed.reap_exact(child, pidfd, kill=True)
                        report['pidfd_exit_verified'] = True
                    else:
                        child.kill(); report['exit_code'] = child.wait(timeout=closed.REAP_TIMEOUT)
                    report['exact_child_reaped'] = True
                except BaseException as teardown:
                    report['teardown_error'] = str(teardown)
        finally:
            if child is not None:
                for stream in (child.stdout, child.stderr):
                    if stream is not None: stream.close()
            if pidfd is not None: os.close(pidfd)
            report['received_signal'] = latch.signum
            for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'):
                os.fsync(logs.pins[logs.out / name])
            closed.durable_receipt(logs, 'result.json', report)
    return report


def prepare(name, execute=False, qemu_hash=None, negative=None):
    if negative not in (None, 'partial-writing'): raise ValueError('closed negative case set')
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('ordinary host UID required')
    if not re.fullmatch(r'persist-[a-z0-9][a-z0-9-]{0,22}', name):
        raise ValueError('new persist- name required')
    if execute:
        if not qemu_hash or not re.fullmatch(r'[a-f0-9]{64}', qemu_hash):
            raise ValueError('explicit installed QEMU hash required')
        offline.trusted_tool(closed.QEMU); offline.read_pinned(closed.QEMU, qemu_hash)
        if not callable(getattr(os, 'pidfd_open', None)) or not callable(getattr(signal, 'pidfd_send_signal', None)):
            raise ValueError('pidfd APIs required before launch')
    with offline.TrustedOutput(INPUT) as inputs, offline.TrustedOutput(BASE, create=True) as output:
        kernel = closed.attach(inputs, 'vmlinuz', offline.KERNEL[2])
        cfg = closed.attach(inputs, 'kernel.config', offline.CONFIG_HASH)
        builtin = closed.attach(inputs, 'modules.builtin', offline.BUILTIN_HASH)
        config = os.pread(cfg, os.fstat(cfg).st_size, 0).decode().splitlines()
        builtins = os.pread(builtin, os.fstat(builtin).st_size, 0).decode().splitlines()
        if any('CONFIG_' + x + '=y' not in config for x in offline.REQUIRED_CONFIG) or any(x not in builtins for x in offline.REQUIRED_BUILTIN):
            raise ValueError('matching built-in kernel closure missing')
        for tool in (GCC, Path(offline.PINS['mke2fs'][0])): offline.trusted_tool(tool)
        offline.read_pinned(GCC, GCC_SHA256)
        offline.read_pinned(*offline.PINS['mke2fs'])
        nonce = secrets.token_hex(16)
        output.create_dir(name)
        output.write('vmlinuz', os.pread(kernel, os.fstat(kernel).st_size, 0))
        source = Path(__file__).with_name('init.persistence.c').read_bytes()
        output.write('init.persistence.c', source); output.write('init.bin', b'')
        command = [str(GCC), '-std=c11', '-static', '-Os', '-Wall', '-Wextra', '-Werror',
                   str(output.out / 'init.persistence.c'), '-o', str(output.out / 'init.bin')]
        compile_result = subprocess.run(command, capture_output=True, timeout=60,
                                        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})
        os.fchmod(output.pins[output.out / 'init.bin'], 0o600)
        output.check(); output.write('compiler.log', compile_result.stdout + compile_result.stderr)
        if compile_result.returncode: raise ValueError('static PID1 build failed')
        init = output.read('init.bin'); offline.static_elf(init)
        entries = [(p, stat.S_IFDIR | 0o755, b'', 0, 0) for p in ('dev', 'etc', 'fixture', 'proc', 'sys')]
        entries += [('dev/console', stat.S_IFCHR | 0o600, b'', 5, 1),
                    ('etc/nonce', stat.S_IFREG | 0o600, nonce.encode(), 0, 0),
                    ('init', stat.S_IFREG | 0o700, init, 0, 0)]
        output.write('initramfs.cpio.gz', gzip.compress(offline.newc(sorted(entries)), mtime=0))
        output.write('fixture.raw', b''); diskfd = output.pins[output.out / 'fixture.raw']
        os.ftruncate(diskfd, offline.SIZE)
        output.write('mke2fs.conf', b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
        fs_uuid = str(uuid.uuid4())
        mkfs = [offline.PINS['mke2fs'][0], '-q', '-t', 'ext4', '-b', '4096', '-I', '256', '-N', '2048', '-m', '0',
                '-U', fs_uuid, '-O', 'none,extent,filetype,sparse_super,large_file', '-E', 'lazy_itable_init=0',
                f'/proc/self/fd/{diskfd}']
        result = subprocess.run(mkfs, pass_fds=(diskfd,), capture_output=True, timeout=60,
                                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'MKE2FS_CONFIG': str(output.out / 'mke2fs.conf')})
        output.check(); output.write('mke2fs.log', result.stdout + result.stderr)
        if result.returncode: raise ValueError('new ext4 build failed')
        for fd in output.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode): os.fsync(fd)
        os.fsync(output.pins[output.out])
        report = {'schema': 1, 'status': 'DRY_RUN_UNBOOTED_NO_ADMISSION', 'admission': 'UNIMPLEMENTED', 'gate': 'CLOSED',
                  'nonce': nonce, 'fs_uuid': fs_uuid, 'negative_case':negative, 'disk_inode': os.fstat(diskfd).st_ino,
                  'disk_device': os.fstat(diskfd).st_dev, 'disk_retained': True, 'boots': [],
                  'source_sha256': offline.sha(Path(__file__).read_bytes()), 'pid1_source_sha256': offline.sha(source),
                  'compiler_sha256': offline.sha(GCC.read_bytes()), 'compile_argv': command, 'mkfs_argv': mkfs,
                  'artifacts': {n: offline.sha(output.read(n)) for n in ('vmlinuz', 'initramfs.cpio.gz', 'init.bin', 'fixture.raw')},
                  'limitations': ['No actual v25 migration/admission', 'No broker/sealing/Owner issuer',
                                  'Orderly two-boot marker persistence only; no crash durability matrix',
                                  'Trusted host root/invoking UID/toolchain/firmware; no execution-inode attestation']}
        closed.durable_receipt(output, 'plan.json', report)
        if execute:
            with closed.SignalLatch() as latch:
                for phase in ('A', 'B'):
                    latch.check()
                    prior = report['boots'][0]['event'] if phase == 'B' else None
                    if phase == 'B' and negative:
                        try:
                            report['negative_injection']=inject_partial(output,report['boots'][0])
                            latch.check()
                        except BaseException as error:
                            report.update(status='FAILED_NO_ADMISSION',negative_error=str(error)); break
                    if phase == 'B' and negative:
                        boot = run_boot(inputs,output,phase,nonce,qemu_hash,latch,prior,partial_refusal=True)
                    else:
                        boot = run_boot(inputs,output,phase,nonce,qemu_hash,latch,prior)
                    report['boots'].append(boot)
                    expected_status='CLOSED_PARTIAL_GATE_REFUSAL_OBSERVED_NO_ADMISSION' if phase=='B' and negative else 'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION'
                    if boot['status'] != expected_status or not boot['exact_child_reaped'] or not boot['pidfd_exit_verified']:
                        report['status'] = 'FAILED_NO_ADMISSION'; break
                    os.fsync(diskfd)
                    if phase == 'B':
                        if negative:
                            try:
                                report['negative_post_boot']=verify_partial(output,prior,report['negative_injection'],'post-b')
                                report['status']=NEGATIVE_SUCCESS
                            except BaseException as error:
                                report.update(status='FAILED_NO_ADMISSION',negative_error=str(error))
                        else: report['status'] = SUCCESS
                report['final_disk_sha256'] = offline.fd_hash(diskfd)
        closed.durable_receipt(output, 'result.json', report)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--qemu-sha256')
    parser.add_argument('--negative',choices=['partial-writing'])
    args = parser.parse_args()
    try:
        report = prepare(args.name, args.run, args.qemu_sha256,args.negative)
    except BaseException as error:
        # Never label uncertain postlaunch receipt failures as 'not started'. Artifacts remain.
        print(json.dumps({'status':'REFUSED_OR_FAILED_LAUNCH_STATE_MUST_BE_INSPECTED', 'error':str(error), 'admission':'UNIMPLEMENTED'}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] in (SUCCESS, NEGATIVE_SUCCESS, 'DRY_RUN_UNBOOTED_NO_ADMISSION') else 2


if __name__ == '__main__': sys.exit(main())
