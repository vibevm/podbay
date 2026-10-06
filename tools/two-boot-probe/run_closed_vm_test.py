#!/usr/bin/env python3
"""Dry-run/refusal and fake-child lifecycle tests; never launch a VM/process substitute."""
from contextlib import ExitStack
import io
from types import SimpleNamespace
import signal
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import offline
from offline_test import private_fixture
import run_closed_vm as runner


class ClosedVMPreparation(unittest.TestCase):
    def test_dry_run_fresh_copy_no_launch_and_preexisting_refusal(self):
        with private_fixture() as (root, rootfd, record, file):
            with patch.object(runner, 'BASE', root), patch.object(runner.subprocess, 'Popen') as launch:
                result = runner.prepare('vm-dry')
                out = root / 'vm-dry'
                record(out)
                record(out / 'fixture.raw')
                record(out / 'plan.json')
                self.assertEqual(result['status'], 'DRY_RUN_NOT_BOOTED')
                self.assertFalse(result['boot_executed'])
                image = out / 'fixture.raw'
                self.assertEqual(offline.sha(image.read_bytes()), runner.PINS['fixture.raw'])
                baseline = runner.INPUT / 'fixture.raw'
                self.assertNotEqual((image.stat().st_dev, image.stat().st_ino),
                                    (baseline.stat().st_dev, baseline.stat().st_ino))
                self.assertEqual(image.stat().st_nlink, 1)
                self.assertEqual(image.stat().st_mode & 0o777, 0o600)
                argv = result['argv']
                for option in ('-monitor', '-nic', '-display'):
                    self.assertEqual(argv[argv.index(option) + 1], 'none')
                self.assertIn('pc,accel=tcg', argv)
                self.assertIn('-nodefaults', argv)
                self.assertIn('readonly=on', argv[argv.index('-drive') + 1])
                for forbidden in ('-enable-kvm', '-daemonize', '-snapshot', '-virtfs', '-fsdev', '-qmp', '-netdev'):
                    self.assertNotIn(forbidden, argv)
                with self.assertRaises(FileExistsError):
                    runner.prepare('vm-dry')
                launch.assert_not_called()

    def test_wrong_hash_refuses_before_output(self):
        with private_fixture() as (root, rootfd, record, file):
            pins = dict(runner.PINS)
            pins['vmlinuz'] = '0' * 64
            with patch.object(runner, 'BASE', root), patch.object(runner, 'PINS', pins), patch.object(runner.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                    runner.prepare('vm-wrong-hash')
                self.assertFalse((root / 'vm-wrong-hash').exists())
                launch.assert_not_called()

    def test_symlink_output_and_input_refuse_without_clobber(self):
        with private_fixture() as (root, rootfd, record, file):
            sentinel = file('sentinel', b'unchanged')
            link = root / 'vm-linked'
            link.symlink_to(sentinel)
            record(link)
            with patch.object(runner, 'BASE', root), patch.object(runner.subprocess, 'Popen') as launch:
                with self.assertRaises(FileExistsError):
                    runner.prepare('vm-linked')
                self.assertEqual(sentinel.read_bytes(), b'unchanged')
                launch.assert_not_called()
            inputlink = root / 'vmlinuz'
            inputlink.symlink_to(runner.INPUT / 'vmlinuz')
            record(inputlink)
            with offline.TrustedOutput(root) as guarded:
                with self.assertRaises(OSError):
                    runner.attach(guarded, 'vmlinuz', runner.PINS['vmlinuz'])

    def test_missing_qemu_refuses_before_output_or_launch(self):
        with private_fixture() as (root, rootfd, record, file):
            absent = root / 'not-installed-qemu'
            with patch.object(runner, 'BASE', root), patch.object(runner, 'QEMU', absent), patch.object(runner.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'MISSING_QEMU'):
                    runner.prepare('vm-missing-qemu', execute=True, qemu_sha256='0' * 64)
                self.assertFalse((root / 'vm-missing-qemu').exists())
                launch.assert_not_called()

    def test_serial_validation_never_a_proof(self):
        valid = (json.dumps(runner.EXPECTED_EVENT) + '\n').encode()
        self.assertEqual(runner.parse_serial(b'[ 0.123] kernel console text\n' + valid), [runner.EXPECTED_EVENT])
        bad = [b'', valid[:-1], b'{broken}\n', valid + valid,
               b'{"event":"fixture_stub","gate":"OPEN"}\n',
               b'{"event":"fixture_stub","event":"fixture_stub"}\n',
               b'{"status":"PASS"}\n', b'Kernel panic\n', b'{"event":\xff}\n']
        bad += [valid + suffix for suffix in (b'[]\n', b'[broken]\n', b'\0\n', b'Kernel panic - not syncing\n', b'{broken}\n', b'garbage\n')]
        self.assertEqual(runner.parse_serial(valid + b'[ 1.234] reboot: Power down\n'), [runner.EXPECTED_EVENT])
        observed_shutdown = (b'[    3.026277] tsc: Refined TSC clocksource calibration: 3493.418 MHz\n'
                             b'[    3.026791] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x325b070d116, max_idle_ns: 440795280169 ns\n'
                             b'[    3.027111] clocksource: Switched to clocksource tsc\n'
                             b'[    3.032936] ACPI: PM: Preparing to enter system sleep state S5\n'
                             b'[    3.033832] reboot: Power down\n')
        self.assertEqual(runner.parse_serial(valid + observed_shutdown), [runner.EXPECTED_EVENT])
        self.assertEqual(runner.parse_serial(valid +
                         b'[    3.006808] ACPI: PM: Preparing to enter system sleep state S5\n'
                         b'[    3.007849] reboot: Power down\n'), [runner.EXPECTED_EVENT])
        bad += [valid + observed_shutdown + b'late output\n',
                valid + observed_shutdown.replace(b'ACPI: PM:', b'BUG: PM:'),
                valid + observed_shutdown.replace(b'3493.418', b'not-a-number')]
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    runner.parse_serial(raw)

    def test_cleanup_refuses_without_exact_reap(self):
        with private_fixture() as (root, rootfd, record, file):
            with offline.TrustedOutput(root) as guarded:
                out = guarded.create_dir('vm-no-reap')
                record(out)
                guarded.write('fixture.raw', b'unchanged')
                record(out / 'fixture.raw')
                with self.assertRaisesRegex(ValueError, 'verified exact child exit/reap'):
                    runner.cleanup_image(guarded, False)
                self.assertEqual((out / 'fixture.raw').read_bytes(), b'unchanged')


class FakeChild:
    pid = 424242
    def __init__(self):
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.returncode = None
        self.killed = False
        self.waits = []
    def poll(self):
        return self.returncode
    def wait(self, timeout):
        self.waits.append(timeout)
        self.returncode = -9 if self.killed else 0
        return self.returncode
    def kill(self):
        self.killed = True


class MockLifecycle(unittest.TestCase):
    def case(self, fault=None):
        with private_fixture() as (root, rootfd, record, file):
            child = FakeChild()
            prior = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
            def fake_capture(proc, pidfd, serialfd, stderrfd, output, latch):
                if fault == 'signal-capture':
                    latch.handle(signal.SIGHUP, None)
                    latch.check()
                if fault == 'timeout':
                    raise TimeoutError('mock capture timeout')
                if fault == 'overflow':
                    raise ValueError('mock serial capture limit exceeded')
                runner.write_all(serialfd, (json.dumps(runner.EXPECTED_EVENT) + '\n').encode())
                return 0
            def fake_launch(*args, **kwargs):
                if fault == 'signal-launch':
                    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                return child
            def fake_pidfd(pid, flags):
                self.assertEqual(pid, child.pid)
                if fault == 'pidfd':
                    raise OSError('mock pidfd-open failure')
                return os.dup(rootfd)
            def fake_signal(fd, sig):
                self.assertEqual(sig, signal.SIGKILL)
                child.killed = True
            original_fsync = os.fsync
            def checked_fsync(fd):
                if fault == 'receipt-sync' and os.readlink(f'/proc/self/fd/{fd}').endswith('/result.json'):
                    raise OSError('mock durable receipt fsync failure')
                return original_fsync(fd)
            original_write = offline.TrustedOutput.write
            def checked_write(output, name, data):
                if fault == 'receipt' and name == 'result.json':
                    raise OSError('mock receipt write failure')
                return original_write(output, name, data)
            with ExitStack() as stack:
                stack.enter_context(patch.object(runner, 'BASE', root))
                stack.enter_context(patch.object(runner, 'QEMU', Path('/usr/bin/busybox')))
                launch = stack.enter_context(patch.object(runner.subprocess, 'Popen', side_effect=fake_launch))
                stack.enter_context(patch.object(runner.os, 'pidfd_open', side_effect=fake_pidfd))
                stack.enter_context(patch.object(runner.signal, 'pidfd_send_signal', side_effect=fake_signal))
                birth = stack.enter_context(patch.object(runner, 'process_birth', return_value=55))
                poll = stack.enter_context(patch.object(runner.select, 'poll'))
                poll.return_value.poll.return_value = [(1, 1)]
                stack.enter_context(patch.object(runner, 'capture', side_effect=fake_capture))
                stack.enter_context(patch.object(offline.TrustedOutput, 'write', checked_write))
                stack.enter_context(patch.object(runner.os, 'fsync', side_effect=checked_fsync))
                if fault == 'immediate-exit':
                    child.returncode = 0
                    birth.side_effect = FileNotFoundError('mock immediate process exit')
                stack.enter_context(patch('builtins.print', side_effect=BrokenPipeError('mock stdout closed') if fault == 'stdout' else None))
                try:
                    if fault in ('receipt', 'receipt-sync', 'stdout'):
                        with self.assertRaises(runner.LifecycleReceiptError) as caught:
                            runner.prepare('vm-mock', True, offline.PINS['busybox'][1])
                        result = caught.exception.report
                        self.assertTrue(result['boot_executed'])
                    else:
                        result = runner.prepare('vm-mock', True, offline.PINS['busybox'][1])
                finally:
                    out = root / 'vm-mock'
                    if out.exists():
                        record(out)
                        for entry in out.iterdir():
                            record(entry)
                launch.assert_called_once()
                self.assertTrue(result['boot_executed'])
                self.assertTrue(result['exact_child_reaped'])
                self.assertTrue(result['disk_retained'])
                self.assertTrue((out / 'fixture.raw').exists())
                self.assertEqual(offline.sha((out / 'fixture.raw').read_bytes()), runner.PINS['fixture.raw'])
                if fault not in ('receipt',):
                    receipt = json.loads((out / 'result.json').read_text())
                    self.assertTrue(receipt['boot_executed'])
                    self.assertTrue(receipt['disk_retained'])
                if fault in ('signal-launch', 'signal-capture', 'timeout', 'overflow', 'pidfd'):
                    self.assertTrue(child.killed)
                    self.assertEqual(result['status'], 'VM_FAILED_OR_LIFECYCLE_UNVERIFIED')
                self.assertTrue(child.waits)
            self.assertEqual({sig: signal.getsignal(sig) for sig in prior}, prior)

    def test_fake_launch_success_retains_after_durable_receipt(self):
        self.case()

    def test_signal_during_launch_and_capture(self):
        for fault in ('signal-launch', 'signal-capture'):
            with self.subTest(fault=fault):
                self.case(fault)

    def test_timeout_overflow_immediate_exit_pidfd_failure(self):
        for fault in ('timeout', 'overflow', 'immediate-exit', 'pidfd'):
            with self.subTest(fault=fault):
                self.case(fault)

    def test_receipt_failure_and_broken_stdout_preserve_launch_state_disk(self):
        for fault in ('receipt', 'receipt-sync', 'stdout'):
            with self.subTest(fault=fault):
                self.case(fault)

    def test_actual_capture_code_with_fake_streams_timeout_and_overflow(self):
        with private_fixture() as (root, rootfd, record, file):
            with offline.TrustedOutput(root) as output:
                out = output.create_dir('vm-capture')
                record(out)
                output.write('serial.raw', b'')
                record(out / 'serial.raw')
                output.write('qemu.stderr', b'')
                record(out / 'qemu.stderr')
                for fault in ('timeout', 'overflow'):
                    streams = []
                    for data in (b'123456789', b''):
                        readfd, writefd = os.pipe()
                        os.write(writefd, data)
                        os.close(writefd)
                        streams.append(os.fdopen(readfd, 'rb'))
                    fake = SimpleNamespace(stdout=streams[0], stderr=streams[1])
                    try:
                        with patch.object(runner, 'TIMEOUT', 0 if fault == 'timeout' else 1), patch.object(runner, 'MAX_SERIAL', 8):
                            with self.assertRaises((TimeoutError, ValueError)):
                                runner.capture(fake, rootfd, output.pins[out / 'serial.raw'],
                                               output.pins[out / 'qemu.stderr'], output, runner.SignalLatch())
                    finally:
                        for stream in streams:
                            stream.close()

    def test_main_postlaunch_reporting_failure_never_labels_unstarted(self):
        report = {'boot_executed': True, 'pid': 424242, 'exact_child_reaped': True}
        err = runner.LifecycleReceiptError(report, BrokenPipeError('fake closed stdout'))
        with patch.object(runner, 'prepare', side_effect=err), patch.object(sys, 'argv', ['runner', '--name', 'vm-mock']), patch.object(sys, 'stderr', io.StringIO()) as stderr:
            self.assertEqual(runner.main(), 2)
            result = json.loads(stderr.getvalue())
            self.assertTrue(result['boot_executed'])
            self.assertEqual(result['status'], 'LIFECYCLE_OR_REPORTING_FAILED')

    def test_missing_pidfd_api_refuses_before_fake_launch(self):
        with private_fixture() as (root, rootfd, record, file):
            with patch.object(runner, 'BASE', root), patch.object(runner, 'QEMU', Path('/usr/bin/busybox')), patch.object(runner.signal, 'pidfd_send_signal', None), patch.object(runner.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(ValueError, 'pidfd lifecycle support required'):
                    runner.prepare('vm-no-pidfd', True, offline.PINS['busybox'][1])
                self.assertFalse((root / 'vm-no-pidfd').exists())
                launch.assert_not_called()

    def test_exact_cleanup_requires_receipt_and_preserves_unrelated_file(self):
        with private_fixture() as (root, rootfd, record, file):
            with offline.TrustedOutput(root) as output:
                out = output.create_dir('vm-cleanup')
                record(out)
                output.write('fixture.raw', (runner.INPUT / 'fixture.raw').read_bytes())
                output.write('sentinel', b'untouched')
                record(out / 'sentinel')
                try:
                    with self.assertRaisesRegex(ValueError, 'durable receipt'):
                        runner.cleanup_image(output, True)
                    report = {'status': 'CLOSED_STUB_OBSERVED_UNIMPLEMENTED', 'exact_child_reaped': True,
                              'pidfd_exit_verified': True, 'disk_retained': True}
                    fsync = None
                    original_fsync = os.fsync
                    with patch.object(runner.os, 'fsync', wraps=original_fsync) as fsync:
                        runner.durable_receipt(output, 'result.json', report)
                        self.assertGreaterEqual(fsync.call_count, 2)
                    record(out / 'result.json')
                    runner.cleanup_image(output, True, True)
                    self.assertFalse((out / 'fixture.raw').exists())
                    self.assertEqual((out / 'sentinel').read_bytes(), b'untouched')
                finally:
                    if (out / 'fixture.raw').exists():
                        record(out / 'fixture.raw')


if __name__ == '__main__':
    unittest.main(verbosity=2)
