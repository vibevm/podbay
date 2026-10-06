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


def run_boot(inputs, output, phase, nonce, qemu_hash, latch, prior=None):
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
            report['event'] = parse_event(logs.read('serial.raw'), phase, nonce, prior)
            closed.write_all(logs.pins[logs.out / 'guest-events.jsonl'],
                             (json.dumps(report['event'], sort_keys=True) + '\n').encode())
            report['status'] = 'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION'
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


def prepare(name, execute=False, qemu_hash=None):
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
                  'nonce': nonce, 'fs_uuid': fs_uuid, 'disk_inode': os.fstat(diskfd).st_ino,
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
                    boot = run_boot(inputs, output, phase, nonce, qemu_hash, latch, prior)
                    report['boots'].append(boot)
                    if boot['status'] != 'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION' or not boot['exact_child_reaped'] or not boot['pidfd_exit_verified']:
                        report['status'] = 'FAILED_NO_ADMISSION'; break
                    os.fsync(diskfd)
                    if phase == 'B': report['status'] = SUCCESS
                report['final_disk_sha256'] = offline.fd_hash(diskfd)
        closed.durable_receipt(output, 'result.json', report)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--qemu-sha256')
    args = parser.parse_args()
    try:
        report = prepare(args.name, args.run, args.qemu_sha256)
    except BaseException as error:
        # Never label uncertain postlaunch receipt failures as 'not started'. Artifacts remain.
        print(json.dumps({'status':'REFUSED_OR_FAILED_LAUNCH_STATE_MUST_BE_INSPECTED', 'error':str(error), 'admission':'UNIMPLEMENTED'}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] in (SUCCESS, 'DRY_RUN_UNBOOTED_NO_ADMISSION') else 2


if __name__ == '__main__': sys.exit(main())
