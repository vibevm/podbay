#!/usr/bin/env python3
"""Build a private CLOSED-origin guest; VM execution requires explicit reviewed opt-in."""
import argparse
from contextlib import closing
import errno
import gzip
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed

BASE = Path('/home/olegchir/podbay-closed-origin-vm-build')
INPUT = offline.BASE / 'final-a'
GCC = Path('/usr/bin/x86_64-linux-gnu-gcc-15')
GCC_SHA256 = 'b5f1b773a7c733738352000c92a077dc5852a1a2fc6d836b1e411be1e9ec5f88'
POLICY = b'guest-root-vault-v1;source24;stage-absent;owner1000;no-admission'
SUCCESS = 'CLOSED_ORIGIN_GUEST_MECHANICS_OBSERVED_NO_PRODUCTION_ADMISSION'
SOURCE = Path(__file__).resolve().parent
SCHEMA = SOURCE.parent.parent / 'crates/podbay-store/src/schema_v24.sql'
BOOT_ID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
EVENT_KEYS = {'schema', 'event', 'nonce', 'boot_id', 'sequence', 'case', 'gate', 'admission',
              'policy_sha256', 'pid1_sha256', 'probe_sha256', 'lineage', 'db_sha256',
              'db_device', 'db_inode', 'db_uid', 'pid', 'birth_ticks', 'rc', 'errno', 'late'}


def sequence():
    result = [('none', 'pid1_first_closed', 0, False)]
    clean = [('source24_pinned', 24), ('origin_acquired', 0), ('clean_exec_sealed', 0),
             ('sealed_source_opened', 100)]
    clean += [(f'outside_{name}_denied_before_death', -1)
              for name in ('raw_path', 'proc_root', 'proc_fd', 'namespace_handle', 'unshare')]
    clean += [('child_reaped', 0), ('broker_killed_reaped', -signal.SIGKILL)]
    clean += [(f'outside_{name}_denied_after_death', -1)
              for name in ('raw_path', 'proc_root', 'proc_fd', 'namespace_handle', 'unshare')]
    clean += [('child_reaped', 0), ('pid1_closed_retained', 0), ('source24_preserved_stage_absent', 24)]
    result += [('clean', name, rc, False) for name, rc in clean]
    for case in ('fd', 'dirfd', 'mmap', 'scm'):
        result.append((case, 'source24_pinned', 24, False))
        result += [(case, name, rc, True) for name, rc in (
            ('issuer_started_before_origin', 0), ('old_capability_ready', 0),
            ('dirty_new_path_denied', -1), ('old_capability_access_proved', 0 if case == 'mmap' else 100),
            ('late_refusal', -1), ('child_reaped', 0), ('late_refusal_after_reap', -1),
            ('source24_preserved_stage_absent', 24))]
    result.append(('scm', 'all_cases_verified_no_admission', 0, True))
    return result


def parse_events(raw, expected):
    if not raw.endswith(b'\n') or b'\0' in raw or len(raw) > closed.MAX_SERIAL:
        raise ValueError('incomplete/NUL/oversized guest capture')
    lines = raw.decode('utf-8', errors='strict').splitlines()
    event_lines = [line for line in lines if line.startswith('{')]
    if any(len(line) > 2048 for line in event_lines):
        raise ValueError('guest event exceeds bound')
    events = [json.loads(line, object_pairs_hook=closed.strict_object) for line in event_lines]
    if len(events) != len(sequence()):
        raise ValueError('missing/extra CLOSED-origin events')
    boot = events[0].get('boot_id')
    if not isinstance(boot, str) or not BOOT_ID.fullmatch(boot):
        raise ValueError('invalid actual guest boot ID')
    pins = {key: expected[key] for key in ('nonce', 'policy_sha256', 'pid1_sha256',
                                          'probe_sha256', 'lineage', 'db_sha256')}
    ids, children = {}, {}
    root_birth = events[0].get('birth_ticks')
    for index, (event, (case, name, rc, late)) in enumerate(zip(events, sequence()), 1):
        if (set(event) != EVENT_KEYS or event['schema'] != 1 or event['event'] != name
                or event['case'] != case or event['sequence'] != index or event['rc'] != rc
                or type(event['late']) is not bool or event['late'] != late
                or event['boot_id'] != boot or event['gate'] != 'CLOSED'
                or event['admission'] != 'UNIMPLEMENTED'
                or any(event[key] != value for key, value in pins.items())):
            raise ValueError('foreign/out-of-order/failed guest event')
        for key in ('sequence', 'rc', 'errno', 'pid', 'birth_ticks', 'db_device', 'db_inode', 'db_uid'):
            if type(event[key]) is not int:
                raise ValueError('noninteger guest identity/result')
        denied = name.startswith('outside_') or name == 'dirty_new_path_denied'
        if event['errno'] not in ((errno.EACCES, errno.EPERM) if denied else (0,)):
            raise ValueError('unexpected syscall errno')
        if 'unshare' in name and event['errno'] != errno.EPERM:
            raise ValueError('namespace syscall denial not observed')
        if event['pid'] < 1 or event['birth_ticks'] < 1:
            raise ValueError('missing process birth identity')
        child_event = (name.startswith('outside_') or name.startswith('old_capability_')
                       or name in ('clean_exec_sealed', 'sealed_source_opened', 'dirty_new_path_denied',
                                   'issuer_started_before_origin', 'child_reaped', 'broker_killed_reaped'))
        if child_event:
            if event['pid'] == 1:
                raise ValueError('diagnostic child is not an actual child')
            role = 'broker' if name in ('clean_exec_sealed', 'sealed_source_opened', 'broker_killed_reaped') else (
                'before' if name.endswith('before_death') else 'after' if name.endswith('after_death') else 'dirty')
            if name == 'child_reaped':
                role = ('before' if index < 15 else 'after') if case == 'clean' else 'dirty'
            prior = children.setdefault((case, role), (event['pid'], event['birth_ticks']))
            if prior != (event['pid'], event['birth_ticks']):
                raise ValueError('child identity changed across phase/reap')
        elif event['pid'] != 1 or event['birth_ticks'] != root_birth:
            raise ValueError('origin authority is not the same guest PID1')
        if case == 'none':
            if event['db_inode'] or event['db_device'] or event['db_uid']:
                raise ValueError('store claimed before provisioning')
        else:
            if event['db_inode'] < 1 or event['db_device'] < 1 or event['db_uid'] != 1000:
                raise ValueError('owner store identity missing')
            pair = (event['db_device'], event['db_inode'])
            if ids.setdefault(case, pair) != pair:
                raise ValueError('source inode changed within case')
    if len(set(ids.values())) != 5:
        raise ValueError('independent cases alias a store')
    if len(set(children.values())) != len(children):
        raise ValueError('independent diagnostic children alias an identity')
    # The established parser rejects fatal/trailing shutdown noise. Every other
    # JSON event has already been parsed and matched before this normalization.
    normalized = []
    remaining = len(event_lines)
    for line in lines:
        if line.startswith('{'):
            remaining -= 1
            if remaining == 0:
                normalized.append(json.dumps(closed.EXPECTED_EVENT))
        else:
            normalized.append(line)
    closed.parse_serial(('\n'.join(normalized) + '\n').encode())
    return events


def schema_objects(connection):
    return connection.execute("SELECT type,name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name").fetchall()


def seed_database(schema, lineage):
    with closing(sqlite3.connect(':memory:')) as db:
        db.executescript('PRAGMA page_size=4096; ' + schema)
        db.execute('UPDATE store_identity SET lineage=? WHERE singleton=1', (lineage,))
        db.execute('PRAGMA user_version=24')
        db.commit()
        return db.serialize()


def verify_seed(path, schema, lineage):
    with closing(sqlite3.connect(':memory:')) as canonical:
        canonical.executescript(schema)
        wanted = schema_objects(canonical)
    with closing(sqlite3.connect(Path(path).as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
        if (db.execute('PRAGMA user_version').fetchone() != (24,)
                or schema_objects(db) != wanted
                or db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]
                or db.execute('PRAGMA foreign_key_check').fetchall()
                or db.execute('SELECT lineage FROM store_identity WHERE singleton=1').fetchone() != (lineage,)):
            raise ValueError('canonical read-only schema24 specimen verification failed')
        try:
            db.execute("UPDATE metadata SET value=1 WHERE key='owner_epoch'")
        except sqlite3.OperationalError as error:
            if 'readonly' not in str(error):
                raise
        else:
            raise ValueError('fixture verifier unexpectedly writable')


def qemu_argv(kernel, initramfs, image):
    args = closed.qemu_argv(kernel, initramfs, image)
    args[args.index('-drive') + 1] = f'file={image},if=none,id=closedfixture,format=raw,readonly=off,cache=none'
    return args


def run_guest(output, report, qemu_hash, latch):
    child = pidfd = None
    for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'):
        output.write(name, b'')
    try:
        output.check(); latch.check()
        offline.trusted_tool(closed.QEMU); offline.read_pinned(closed.QEMU, qemu_hash)
        fds = tuple(output.pins[output.out / name] for name in ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw'))
        args = qemu_argv(*(f'/proc/self/fd/{fd}' for fd in fds))
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True, pass_fds=fds,
                                 cwd=output.out, env={'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
        report.update(boot_executed=True, pid=child.pid, executed_argv=args)
        pidfd = os.pidfd_open(child.pid, 0)
        report['process_birth_ticks'] = closed.process_birth(child.pid)
        closed.capture(child, pidfd, output.pins[output.out/'serial.raw'],
                       output.pins[output.out/'qemu.stderr'], output, latch)
        report['exit_code'] = closed.reap_exact(child, pidfd)
        report.update(exact_child_reaped=True, pidfd_exit_verified=True)
        latch.check(); output.check()
        if report['exit_code'] != 0:
            raise ValueError('guest/QEMU did not power off normally')
        events = parse_events(output.read('serial.raw'), report)
        closed.write_all(output.pins[output.out/'guest-events.jsonl'],
                         b''.join((json.dumps(e, sort_keys=True)+'\n').encode() for e in events))
        report.update(status=SUCCESS, event_count=len(events), guest_boot_id=events[0]['boot_id'])
    except BaseException as error:
        report.update(status='FAILED_OR_LIFECYCLE_UNVERIFIED', error=str(error))
        if child is not None and not report.get('exact_child_reaped'):
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
            os.fsync(output.pins[output.out/name])
        os.fsync(output.pins[output.out/'fixture.raw'])
        report['final_disk_sha256'] = offline.fd_hash(output.pins[output.out/'fixture.raw'])
        closed.durable_receipt(output, 'result.json', report)
    return report


def prepare(name, execute=False, qemu_hash=None):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('ordinary host UID required; no host root run')
    if not re.fullmatch(r'origin-[a-z0-9][a-z0-9-]{0,23}', name):
        raise ValueError('new simple origin- name required')
    if execute:
        if not qemu_hash or not re.fullmatch(r'[a-f0-9]{64}', qemu_hash):
            raise ValueError('reviewed QEMU SHA-256 required before launch')
        if not callable(getattr(os, 'pidfd_open', None)) or not callable(getattr(signal, 'pidfd_send_signal', None)):
            raise ValueError('pidfd lifecycle support required')
        offline.trusted_tool(closed.QEMU); offline.read_pinned(closed.QEMU, qemu_hash)
    schema = SCHEMA.read_text()
    with offline.TrustedOutput(INPUT) as inputs, offline.TrustedOutput(BASE, create=True) as output:
        pins = [('vmlinuz', offline.KERNEL[2]), ('kernel.config', offline.CONFIG_HASH), ('modules.builtin', offline.BUILTIN_HASH)]
        fds = {n: closed.attach(inputs, n, h) for n, h in pins}
        config = os.pread(fds['kernel.config'], os.fstat(fds['kernel.config']).st_size, 0).decode().splitlines()
        builtin = os.pread(fds['modules.builtin'], os.fstat(fds['modules.builtin']).st_size, 0).decode().splitlines()
        if any('CONFIG_'+x+'=y' not in config for x in (*offline.REQUIRED_CONFIG, 'UNIX')) or any(x not in builtin for x in offline.REQUIRED_BUILTIN):
            raise ValueError('pinned kernel closure lacks required guest mechanisms')
        for path, digest in ((GCC, GCC_SHA256), offline.PINS['mke2fs']):
            offline.trusted_tool(path); offline.read_pinned(path, digest)
        output.create_dir(name)
        nonce, lineage = secrets.token_hex(16), secrets.token_hex(16)
        output.write('source24.sqlite', seed_database(schema, lineage))
        verify_seed(output.out/'source24.sqlite', schema, lineage)
        output.write('schema_v24.sql', schema.encode())
        output.write('vmlinuz', os.pread(fds['vmlinuz'], os.fstat(fds['vmlinuz']).st_size, 0))
        files = ('closed_origin_shared.h', 'init.closed_origin.c', 'closed_origin_probe.c')
        sources = {n: (SOURCE/n).read_bytes() for n in files}
        for n, data in sources.items(): output.write(n, data)
        commands = []
        for src, target in (('init.closed_origin.c', 'init.bin'), ('closed_origin_probe.c', 'probe.bin')):
            output.write(target, b'')
            args = [str(GCC), '-std=c11', '-static', '-Os', '-Wall', '-Wextra', '-Werror',
                    str(output.out/src), '-o', str(output.out/target)]
            r = subprocess.run(args, capture_output=True, timeout=60,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})
            os.fchmod(output.pins[output.out/target], 0o600); output.check()
            output.write(target+'.compiler.log', r.stdout+r.stderr)
            commands.append({'argv': args, 'exit': r.returncode})
            if r.returncode: raise ValueError('static build failed: '+target)
            offline.static_elf(output.read(target))
        expected = {'nonce': nonce, 'lineage': lineage, 'db_sha256': offline.sha(output.read('source24.sqlite')),
                    'pid1_sha256': offline.sha(output.read('init.bin')), 'probe_sha256': offline.sha(output.read('probe.bin')),
                    'policy_sha256': offline.sha(POLICY)}
        config_bytes = '\n'.join(expected[k] for k in ('nonce', 'db_sha256', 'pid1_sha256', 'probe_sha256', 'policy_sha256', 'lineage')).encode()+b'\n'
        entries = [(p, stat.S_IFDIR|0o755, b'', 0, 0) for p in ('bin', 'dev', 'etc', 'fixture', 'proc', 'run', 'sys')]
        entries += [('run/sealed', stat.S_IFDIR|0o700, b'', 0, 0), ('dev/console', stat.S_IFCHR|0o600, b'', 5, 1),
                    ('init', stat.S_IFREG|0o700, output.read('init.bin'), 0, 0),
                    ('bin/origin-probe', stat.S_IFREG|0o755, output.read('probe.bin'), 0, 0),
                    ('etc/source24.sqlite', stat.S_IFREG|0o600, output.read('source24.sqlite'), 0, 0),
                    ('etc/origin.config', stat.S_IFREG|0o600, config_bytes, 0, 0)]
        output.write('initramfs.cpio.gz', gzip.compress(offline.newc(sorted(entries)), mtime=0))
        output.write('fixture.raw', b''); disk = output.pins[output.out/'fixture.raw']; os.ftruncate(disk, offline.SIZE)
        output.write('mke2fs.conf', b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
        args = [offline.PINS['mke2fs'][0], '-q', '-t', 'ext4', '-b', '4096', '-I', '256', '-N', '2048', '-m', '0',
                '-U', str(uuid.uuid4()), '-O', 'none,extent,filetype,sparse_super,large_file', '-E', 'lazy_itable_init=0', f'/proc/self/fd/{disk}']
        r = subprocess.run(args, pass_fds=(disk,), capture_output=True, timeout=60,
                           env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'MKE2FS_CONFIG': str(output.out/'mke2fs.conf')})
        output.check(); output.write('mke2fs.log', r.stdout+r.stderr)
        if r.returncode: raise ValueError('new private ext4 image creation failed')
        for fd in output.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode): os.fsync(fd)
        os.fsync(output.pins[output.out]); inputs.check()
        report = dict(expected, schema=1, status='OFFLINE_BUILT_UNBOOTED_NO_ADMISSION', boot_executed=False,
                      exact_child_reaped=False, pidfd_exit_verified=False, disk_retained=True,
                      output=str(output.out), compiler_commands=commands,
                      source_hashes={n: offline.sha(v) for n, v in sources.items()}, schema_sha256=offline.sha(schema.encode()),
                      runner_sha256=offline.sha(Path(__file__).read_bytes()),
                      disk_device=os.fstat(disk).st_dev, disk_inode=os.fstat(disk).st_ino,
                      artifacts={n: offline.sha(output.read(n)) for n in ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw')},
                      limits=['Fixture-only canonical fresh schema24, no live data or migration',
                              'One guest boot with five disjoint cases, not production boot census',
                              'Host root/invoking UID/kernel/toolchain/hypervisor trusted',
                              'No live constructor, terminal proof, Owner readiness or issuer release'])
        closed.durable_receipt(output, 'plan.json', report)
        if execute:
            with closed.SignalLatch() as latch:
                return run_guest(output, report, qemu_hash, latch)
        closed.durable_receipt(output, 'result.json', report)
        return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--name', required=True)
    p.add_argument('--run', action='store_true', help='only after independent parent source review')
    p.add_argument('--qemu-sha256')
    a = p.parse_args()
    try:
        report = prepare(a.name, a.run, a.qemu_sha256)
        print(json.dumps(report, sort_keys=True))
    except BaseException as error:
        print(json.dumps({'status': 'REFUSED_OR_FAILED_INSPECT_RETAINED_ARTIFACTS', 'error': str(error)}), file=sys.stderr)
        return 2
    return 0 if report['status'] in ('OFFLINE_BUILT_UNBOOTED_NO_ADMISSION', SUCCESS) else 2


if __name__ == '__main__':
    sys.exit(main())
