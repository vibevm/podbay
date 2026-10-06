#!/usr/bin/env python3
"""Offline only: compile/pure self-tests, strict oracle tests, fake-child lifecycle."""
from contextlib import ExitStack, closing
import copy
import io
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import run_closed_origin_vm as runner

PINS = {'nonce': '1'*32, 'lineage': '2'*32, 'db_sha256': '3'*64,
        'pid1_sha256': '4'*64, 'probe_sha256': '5'*64, 'policy_sha256': '6'*64}


def events():
    result = []
    for index, (case, name, rc, late) in enumerate(runner.sequence(), 1):
        child = (name.startswith('outside_') or name.startswith('old_capability_')
                 or name in ('clean_exec_sealed', 'sealed_source_opened', 'dirty_new_path_denied',
                             'issuer_started_before_origin', 'child_reaped', 'broker_killed_reaped'))
        pid = 1
        if child:
            if case == 'clean':
                pid = 2 if name in ('clean_exec_sealed', 'sealed_source_opened', 'broker_killed_reaped') else 3 if index < 13 else 4
            else:
                pid = {'fd': 5, 'dirfd': 6, 'mmap': 7, 'scm': 8}[case]
        number = {'none': 0, 'clean': 101, 'fd': 102, 'dirfd': 103, 'mmap': 104, 'scm': 105}[case]
        result.append(dict(PINS, schema=1, event=name, sequence=index, case=case, rc=rc,
                           late=late, boot_id='12345678-1234-1234-1234-123456789abc',
                           gate='CLOSED', admission='UNIMPLEMENTED', pid=pid, birth_ticks=pid+10,
                           db_device=0 if case == 'none' else 200, db_inode=number,
                           db_uid=0 if case == 'none' else 1000,
                           errno=1 if 'unshare' in name else 13 if name.startswith('outside_') or name == 'dirty_new_path_denied' else 0))
    return result


def serial(rows=None):
    return b'[ 0.1] disposable kernel text\n' + b''.join((json.dumps(e)+'\n').encode() for e in (events() if rows is None else rows)) + b'[ 9.1] reboot: Power down\n'


def private_output():
    guard = offline.TrustedOutput(runner.BASE, create=True)
    guard.create_dir('test-'+secrets.token_hex(8))
    return guard


class OracleTests(unittest.TestCase):
    def test_complete_clean_dirty_and_reap_oracle(self):
        self.assertEqual(runner.parse_events(serial(), PINS), events())

    def test_missing_extra_reordered_foreign_and_false_identity_refuse(self):
        for mutate in ('missing', 'extra', 'order', 'nonce', 'boot', 'schema', 'late', 'inode', 'uid', 'pid1', 'child', 'errno', 'rc', 'bool_integer'):
            rows = copy.deepcopy(events())
            if mutate == 'missing': rows.pop()
            elif mutate == 'extra': rows.append(rows[-1])
            elif mutate == 'order': rows[2], rows[3] = rows[3], rows[2]
            elif mutate == 'nonce': rows[3]['nonce'] = 'a'*32
            elif mutate == 'boot': rows[3]['boot_id'] = 'a'*36
            elif mutate == 'schema': rows[3]['schema'] = 2
            elif mutate == 'late': rows[3]['late'] = True
            elif mutate == 'inode': rows[3]['db_inode'] += 1
            elif mutate == 'uid': rows[3]['db_uid'] = 0
            elif mutate == 'pid1': rows[1]['pid'] = 9
            elif mutate == 'child': rows[6]['birth_ticks'] += 1
            elif mutate == 'errno': rows[6]['errno'] = 2
            elif mutate == 'rc': rows[6]['rc'] = 0
            else: rows[1]['sequence'] = True
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                runner.parse_events(serial(rows), PINS)

    def test_truncated_duplicate_keys_fatal_trailing_and_oversized_refuse(self):
        good = serial()
        wrong = [good[:-1], good+b'foreign output\n', b'', b'\0\n', good.replace(b'"schema": 1', b'"schema":1,"schema":1', 1),
                 good.replace(b'disposable kernel text', b'Kernel panic - not syncing'),
                 b'x'*(closed.MAX_SERIAL+1), good.replace(b'"event"', b'"unknown"', 1)]
        for raw in wrong:
            with self.assertRaises(ValueError): runner.parse_events(raw, PINS)

    def test_qemu_has_only_disposable_descriptor_inputs(self):
        args = runner.qemu_argv('/proc/self/fd/3', '/proc/self/fd/4', '/proc/self/fd/5')
        for flag in ('-monitor', '-display', '-nic'): self.assertEqual(args[args.index(flag)+1], 'none')
        for forbidden in ('-enable-kvm', '-virtfs', '-fsdev', '-netdev', '-daemonize', '-snapshot', '-qmp'):
            self.assertNotIn(forbidden, args)
        self.assertIn('pc,accel=tcg', args)
        self.assertEqual(args[args.index('-drive')+1], 'file=/proc/self/fd/5,if=none,id=closedfixture,format=raw,readonly=off,cache=none')

    def test_canonical_seed_is_checked_read_only_and_corruption_refuses(self):
        with private_output() as output:
            schema = runner.SCHEMA.read_text()
            output.write('source24.sqlite', runner.seed_database(schema, PINS['lineage']))
            path = output.out/'source24.sqlite'
            before = path.read_bytes()
            runner.verify_seed(path, schema, PINS['lineage'])
            self.assertEqual(path.read_bytes(), before)
            with closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA user_version=25')
                db.commit()
            with self.assertRaises(ValueError): runner.verify_seed(path, schema, PINS['lineage'])

    def test_static_programs_compile_and_pure_selftests_do_not_enter_guest(self):
        with private_output() as output:
            offline.trusted_tool(runner.GCC); offline.read_pinned(runner.GCC, runner.GCC_SHA256)
            for name in ('closed_origin_shared.h', 'init.closed_origin.c', 'closed_origin_probe.c'):
                output.write(name, (runner.SOURCE/name).read_bytes())
            # Executable scratch copies are separate from TrustedOutput's retained
            # mode0600 artifacts and are never entered without --self-test.
            for source in ('init.closed_origin.c', 'closed_origin_probe.c'):
                binary = output.out/(source+'.test-bin')
                command = [str(runner.GCC), '-static', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
                           str(output.out/source), '-o', str(binary)]
                r = subprocess.run(command, capture_output=True, timeout=60)
                self.assertEqual(r.returncode, 0, (r.stdout+r.stderr).decode())
                os.chmod(binary, 0o700)
                offline.static_elf(binary.read_bytes())
                result = subprocess.run([str(binary), '--self-test'], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, (result.stdout+result.stderr).decode())
                refused = subprocess.run([str(binary)], capture_output=True, timeout=5)
                self.assertEqual(refused.returncode, 3, 'ordinary UID must never enter PID1/probe path')
                os.chmod(binary, 0o600)


class FakeChild:
    pid = 424242
    def __init__(self):
        self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
        self.returncode, self.killed, self.waited = None, False, False
    def poll(self): return self.returncode
    def wait(self, timeout):
        self.waited = True
        self.returncode = -9 if self.killed else 0
        return self.returncode
    def kill(self): self.killed = True


class LifecycleTests(unittest.TestCase):
    def exercise(self, fault):
        with private_output() as output:
            for name in ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw'): output.write(name, b'fake retained input')
            report = dict(PINS, status='NOT_STARTED', boot_executed=False, exact_child_reaped=False,
                          pidfd_exit_verified=False, disk_retained=True, evidence_kind='OFFLINE_FAKE_CHILD_TEST')
            child = FakeChild()
            def launch(*args, **kwargs):
                self.assertTrue(kwargs['close_fds'])
                self.assertEqual(len(kwargs['pass_fds']), 3)
                if fault == 'signal': latch.handle(signal.SIGTERM, None)
                return child
            def capture(proc, pidfd, outfd, errfd, guard, live_latch):
                live_latch.check()
                if fault == 'timeout': raise TimeoutError('offline injected timeout')
                if fault == 'overflow': raise ValueError('offline capture cap')
                closed.write_all(outfd, b'bad\n' if fault == 'parser' else serial())
            def pidfd(pid, flags):
                if fault == 'pidfd': raise OSError('offline injected pidfd failure')
                return os.dup(output.pins[output.out])
            def kill(fd, sig):
                self.assertEqual(sig, signal.SIGKILL); child.killed = True
            with ExitStack() as stack:
                stack.enter_context(patch.object(runner.subprocess, 'Popen', side_effect=launch))
                stack.enter_context(patch.object(offline, 'trusted_tool'))
                stack.enter_context(patch.object(offline, 'read_pinned'))
                stack.enter_context(patch.object(runner.os, 'pidfd_open', side_effect=pidfd))
                stack.enter_context(patch.object(closed, 'process_birth', return_value=999))
                stack.enter_context(patch.object(closed, 'capture', side_effect=capture))
                stack.enter_context(patch.object(closed.signal, 'pidfd_send_signal', side_effect=kill))
                poller = stack.enter_context(patch.object(closed.select, 'poll'))
                poller.return_value.poll.return_value = [(1, 1)]
                if fault == 'receipt': stack.enter_context(patch.object(closed, 'durable_receipt', side_effect=OSError('offline receipt failure')))
                with closed.SignalLatch() as latch:
                    if fault == 'receipt':
                        with self.assertRaises(OSError): runner.run_guest(output, report, '0'*64, latch)
                    else:
                        result = runner.run_guest(output, report, '0'*64, latch)
                        self.assertEqual(result['status'], runner.SUCCESS if fault is None else 'FAILED_OR_LIFECYCLE_UNVERIFIED')
            self.assertTrue(report['boot_executed'])
            self.assertTrue(report['exact_child_reaped'])
            self.assertTrue(child.waited)
            self.assertTrue((output.out/'fixture.raw').exists())
            self.assertEqual(output.read('fixture.raw'), b'fake retained input')
            if fault in ('timeout', 'overflow', 'pidfd', 'signal'): self.assertTrue(child.killed)

    def test_success_and_all_failures_reap_exact_child_and_retain_disk(self):
        for fault in (None, 'timeout', 'overflow', 'pidfd', 'signal', 'parser', 'receipt'):
            with self.subTest(fault=fault): self.exercise(fault)

    def test_missing_pidfd_and_bad_name_refuse_before_launch(self):
        with patch.object(runner.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError): runner.prepare('../bad')
            with patch.object(runner.os, 'pidfd_open', None):
                with self.assertRaises(ValueError): runner.prepare('origin-no-pidfd', True, '0'*64)
            launch.assert_not_called()


if __name__ == '__main__':
    if os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit('ordinary UID required for offline tests')
    unittest.main(verbosity=2)
