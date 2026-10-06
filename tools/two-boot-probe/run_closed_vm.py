#!/usr/bin/env python3
"""Prepare a fixed CLOSED-stub QEMU test; default is dry-run, never a two-boot proof."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import select
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import offline

BASE = offline.BASE
INPUT = BASE / 'final-a'
QEMU = Path('/usr/bin/qemu-system-x86_64')
PINS = {
    'vmlinuz': '0ad39b13e289e1a5cf806d14541ac8f221eefe849017f5915e0846917ed67785',
    'initramfs.cpio.gz': '6e165bdb31bf18a2b4770a06320c34928890cda279c3fe12a329985d31dcbc27',
    'fixture.raw': '130c08335016f58fcbba1828f59be14a07d26719d0c4201f4dd58e8581125e8c',
}
TIMEOUT = 120
REAP_TIMEOUT = 10
MAX_SERIAL = 2 * 1024 * 1024
MAX_STDERR = 128 * 1024
EXPECTED_EVENT = {'event': 'fixture_stub', 'status': 'BLOCKED_NOT_BOOTED_PROOF',
                  'gate': 'CLOSED', 'reason': 'persistent_broker_and_two_boot_protocol_unimplemented'}


class LifecycleReceiptError(RuntimeError):
    def __init__(self, report, error):
        super().__init__(str(error))
        self.report = report


def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError('short output write')
        view = view[count:]


def attach(guard, name, expected=None):
    path = guard.root / name
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=guard.pins[guard.root])
    guard.pins[path] = fd
    guard.check()
    if expected is not None and offline.fd_hash(fd) != expected:
        raise ValueError('input SHA-256 mismatch: ' + name)
    guard.check()
    return fd


def validate_inputs(guard):
    fds = {name: attach(guard, name, digest) for name, digest in PINS.items()}
    reportfd = attach(guard, 'build-report.json')
    if os.fstat(reportfd).st_size > 65536:
        raise ValueError('oversized build report')
    report = json.loads(os.pread(reportfd, os.fstat(reportfd).st_size, 0))
    if (report.get('boot_executed') is not False or report.get('gate') != 'CLOSED'
            or report.get('admission') != 'UNIMPLEMENTED'
            or report.get('status') != 'OFFLINE_ASSEMBLED_UNBOOTED_STUB'
            or any(report.get('artifacts', {}).get(name) != digest for name, digest in PINS.items())):
        raise ValueError('build report does not describe the fixed unbooted CLOSED stub')
    return fds


def qemu_argv(kernel, initramfs, image):
    """No caller-selected QEMU options; TCG only, no KVM or host devices."""
    return [str(QEMU), '-no-user-config', '-nodefaults', '-machine', 'pc,accel=tcg',
            '-cpu', 'qemu64', '-smp', '1', '-m', '512', '-display', 'none',
            '-monitor', 'none', '-nic', 'none', '-no-reboot',
            '-chardev', 'stdio,id=closedserial,signal=off', '-serial', 'chardev:closedserial',
            '-kernel', str(kernel), '-initrd', str(initramfs),
            '-append', 'console=ttyS0,115200 rdinit=/init panic=-1',
            '-drive', f'file={image},if=none,id=closedfixture,format=raw,readonly=on,cache=none',
            '-device', 'virtio-blk-pci,drive=closedfixture']


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate serial JSON key')
        result[key] = value
    return result


def parse_serial(raw):
    """Require the exact event followed only by bounded observed shutdown chatter."""
    if len(raw) > MAX_SERIAL or not raw.endswith(b'\n') or b'\0' in raw:
        raise ValueError('oversized, incomplete or NUL-containing serial capture')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise ValueError('invalid serial UTF-8') from error
    events = []
    shutdown_seen = False
    shutdown_chatter = (
        r'tsc: Refined TSC clocksource calibration: [0-9]+(?:\.[0-9]+)? MHz',
        r'clocksource: tsc: mask: 0x[0-9a-f]+ max_cycles: 0x[0-9a-f]+, max_idle_ns: [0-9]+ ns',
        r'clocksource: Switched to clocksource tsc',
        r'ACPI: PM: Preparing to enter system sleep state S5',
    )
    chatter_index = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.search(r'kernel panic|not syncing|oops:|BUG:|segmentation fault', line, re.I):
            raise ValueError('fatal serial diagnostic')
        if events:
            if not shutdown_seen and re.fullmatch(r'(?:\[\s*\d+\.\d+\]\s*)?reboot: Power down', line):
                shutdown_seen = True
                continue
            if not shutdown_seen:
                for index in range(chatter_index, len(shutdown_chatter)):
                    if re.fullmatch(r'\[\s*\d+\.\d+\]\s*' + shutdown_chatter[index], line):
                        chatter_index = index + 1
                        break
                else:
                    raise ValueError('unexpected serial suffix after CLOSED-stub event')
                continue
            raise ValueError('unexpected serial suffix after CLOSED-stub event')
        if line.startswith('{'):
            if len(line) > 4096:
                raise ValueError('oversized serial JSON line')
            try:
                event = json.loads(line, object_pairs_hook=strict_object)
            except ValueError as error:
                raise ValueError('malformed serial JSON: ' + str(error)) from error
            if event != EXPECTED_EVENT:
                raise ValueError('unexpected or failed CLOSED-stub event')
            events.append(event)
        elif line.startswith('[') and not re.match(r'^\[\s*\d+\.\d+\]', line):
            raise ValueError('unexpected JSON array/non-kernel bracketed serial line')
    if events != [EXPECTED_EVENT]:
        raise ValueError('missing CLOSED-stub event')
    return events


def process_birth(pid):
    # proc stat comm may contain spaces/parentheses; field 22 follows its final ')'.
    data = Path(f'/proc/{pid}/stat').read_text()
    fields = data[data.rfind(')') + 2:].split()
    return int(fields[19])


def reap_exact(child, pidfd, kill=False):
    if kill and child.poll() is None:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    code = child.wait(timeout=REAP_TIMEOUT)
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    if not poller.poll(0):
        raise ValueError('child wait completed without pidfd exit readiness')
    return code


def capture(child, pidfd, serialfd, stderrfd, output, latch):
    deadline = time.monotonic() + TIMEOUT
    sizes = {'serial': 0, 'stderr': 0}
    with selectors.DefaultSelector() as selector:
        for stream, kind, fd, limit in ((child.stdout, 'serial', serialfd, MAX_SERIAL),
                                        (child.stderr, 'stderr', stderrfd, MAX_STDERR)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (kind, fd, limit))
        while selector.get_map():
            latch.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('QEMU capture deadline exceeded')
            for key, _ in selector.select(min(remaining, 1)):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                kind, fd, limit = key.data
                sizes[kind] += len(data)
                if sizes[kind] > limit:
                    raise ValueError('QEMU ' + kind + ' capture limit exceeded')
                output.check()
                write_all(fd, data)
                output.check()
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        while child.poll() is None:
            latch.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('QEMU exit deadline exceeded')
            poller.poll(max(1, min(1000, int(remaining * 1000))))
        return child.wait(timeout=REAP_TIMEOUT)


def durable_receipt(output, name, report):
    output.write(name, (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    os.fsync(output.pins[output.out / name])
    os.fsync(output.pins[output.out])
    output.check()


class SignalLatch:
    """Handlers only record intent, including during Popen and exact-child teardown."""
    def __init__(self):
        self.signum = None
        self.previous = {}

    def handle(self, signum, frame):
        self.signum = signum

    def __enter__(self):
        try:
            for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                self.previous[sig] = signal.signal(sig, self.handle)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *unused):
        for sig, handler in self.previous.items():
            signal.signal(sig, handler)

    def check(self):
        if self.signum is not None:
            raise InterruptedError('runner received signal ' + str(self.signum))


def cleanup_image(output, child_exited_and_reaped, receipt_durable=False):
    # Separate follow-up helper; launch/report transaction never calls it.
    if not child_exited_and_reaped or not receipt_durable:
        raise ValueError('fixture cleanup requires verified exact child exit/reap and durable receipt')
    output.check()
    receipt = json.loads(output.read('result.json'))
    if (receipt.get('status') != 'CLOSED_STUB_OBSERVED_UNIMPLEMENTED'
            or receipt.get('exact_child_reaped') is not True
            or receipt.get('pidfd_exit_verified') is not True
            or receipt.get('disk_retained') is not True):
        raise ValueError('fixture cleanup requires successful retained-image receipt')
    os.fsync(output.pins[output.out / 'result.json'])
    os.fsync(output.pins[output.out])
    path = output.out / 'fixture.raw'
    fd = output.pins[path]
    if offline.fd_hash(fd) != PINS['fixture.raw']:
        raise ValueError('fixture changed; preserve image for inspection')
    output.check()
    os.unlink('fixture.raw', dir_fd=output.pins[output.out])
    os.close(output.pins.pop(path))
    os.fsync(output.pins[output.out])
    output.check()


def execute_fixture(inputs, output, inputfds, report, qemu_sha256):
    out = output.out
    imagefd = output.pins[out / 'fixture.raw']
    child, pidfd, reaped = None, None, False
    with SignalLatch() as latch:
        try:
            inputs.check()
            output.check()
            offline.trusted_tool(QEMU)
            offline.read_pinned(QEMU, qemu_sha256)
            latch.check()
            fds = (inputfds['vmlinuz'], inputfds['initramfs.cpio.gz'], imagefd)
            argv = qemu_argv(*(f'/proc/self/fd/{fd}' for fd in fds))
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, close_fds=True, pass_fds=fds,
                                     cwd=out, env={'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
            # Record launch before any pidfd/proc/reporting operation can fail.
            report.update({'boot_executed': True, 'pid': child.pid, 'executed_argv': argv})
            pidfd = os.pidfd_open(child.pid, 0)
            report['process_birth_ticks'] = process_birth(child.pid)
            latch.check()
            capture(child, pidfd, output.pins[out / 'serial.raw'],
                    output.pins[out / 'qemu.stderr'], output, latch)
            report['exit_code'] = reap_exact(child, pidfd)
            reaped = True
            report['pidfd_exit_verified'] = True
            latch.check()
            inputs.check()
            output.check()
            if report['exit_code'] != 0:
                raise ValueError('QEMU exited nonzero: ' + str(report['exit_code']))
            events = parse_serial(output.read('serial.raw'))
            write_all(output.pins[out / 'guest-events.jsonl'],
                      b''.join((json.dumps(event, sort_keys=True) + '\n').encode() for event in events))
            os.fsync(output.pins[out / 'guest-events.jsonl'])
            latch.check()
            report['status'] = 'CLOSED_STUB_OBSERVED_UNIMPLEMENTED'
        except BaseException as error:
            report.update({'status': 'VM_FAILED_OR_LIFECYCLE_UNVERIFIED', 'error': str(error)})
            if child is not None:
                try:
                    if pidfd is not None:
                        report['exit_code'] = reap_exact(child, pidfd, kill=True)
                        report['pidfd_exit_verified'] = True
                    else:
                        # Popen still owns this unreaped child; no reused PID is targeted.
                        child.kill()
                        report['exit_code'] = child.wait(timeout=REAP_TIMEOUT)
                        report['pidfd_exit_verified'] = False
                    reaped = True
                except BaseException as teardown_error:
                    report['teardown_error'] = str(teardown_error)
        finally:
            report.update({'exact_child_reaped': reaped, 'disk_retained': True,
                           'cleanup_policy': 'RETAIN_FOR_SEPARATE_VERIFIED_FOLLOWUP',
                           'received_signal': latch.signum})
            try:
                if child is not None:
                    for stream in (child.stdout, child.stderr):
                        if stream is not None:
                            stream.close()
                if pidfd is not None:
                    os.close(pidfd)
                for name in ('serial.raw', 'qemu.stderr'):
                    os.fsync(output.pins[out / name])
                durable_receipt(output, 'result.json', report)
                # Broken stdout is a reporting failure with launch state preserved.
                print(json.dumps({'status': report['status'], 'output': str(out),
                                  'boot_executed': report['boot_executed'], 'disk_retained': True}), flush=True)
            except BaseException as receipt_error:
                raise LifecycleReceiptError(report, receipt_error) from receipt_error
    return report


def _prepare(name, execute=False, qemu_sha256=None, state=None):
    if not re.fullmatch(r'vm-[a-z0-9][a-z0-9-]{0,27}', name):
        raise ValueError('run name must start vm- and contain only lowercase letters/digits/hyphens')
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('ordinary UID required')
    with offline.TrustedOutput(INPUT) as inputs, offline.TrustedOutput(BASE) as output:
        inputfds = validate_inputs(inputs)
        if execute:
            if not QEMU.exists():
                raise ValueError('MISSING_QEMU: installation approval/executable required; nothing started')
            if not qemu_sha256 or not re.fullmatch(r'[a-f0-9]{64}', qemu_sha256):
                raise ValueError('explicit reviewed QEMU SHA-256 required')
            offline.trusted_tool(QEMU)
            offline.read_pinned(QEMU, qemu_sha256)
            if not callable(getattr(os, 'pidfd_open', None)) or not callable(getattr(signal, 'pidfd_send_signal', None)):
                raise ValueError('pidfd lifecycle support required before VM launch')
        out = output.create_dir(name)
        output.write('fixture.raw', b'')
        imagefd = output.pins[out / 'fixture.raw']
        sourcefd = inputfds['fixture.raw']
        for offset in range(0, os.fstat(sourcefd).st_size, 1024 * 1024):
            write_all(imagefd, os.pread(sourcefd, 1024 * 1024, offset))
        os.fsync(imagefd)
        inputs.check()
        output.check()
        if offline.fd_hash(imagefd) != PINS['fixture.raw']:
            raise ValueError('fresh exclusive disk copy SHA-256 mismatch')
        # Fresh inode and single link; never a reflink/hardlink to the baseline.
        if (os.fstat(imagefd).st_dev, os.fstat(imagefd).st_ino) == (
                os.fstat(sourcefd).st_dev, os.fstat(sourcefd).st_ino):
            raise ValueError('fixture copy aliases baseline inode')
        planned = qemu_argv(INPUT / 'vmlinuz', INPUT / 'initramfs.cpio.gz', out / 'fixture.raw')
        report = {'schema': 1, 'status': 'DRY_RUN_NOT_BOOTED', 'boot_executed': False,
                  'gate': 'CLOSED', 'admission': 'UNIMPLEMENTED', 'qemu_available': QEMU.exists(),
                  'argv': planned, 'stdin': 'DEVNULL', 'environment': {'LC_ALL': 'C', 'TZ': 'UTC'},
                  'timeout_seconds': TIMEOUT, 'artifact_pins': PINS,
                  'source_sha256': offline.sha(Path(__file__).read_bytes()),
                  'fresh_disk_inode': os.fstat(imagefd).st_ino, 'disk_retained': True,
                  'limits': ['CLOSED stub observation only; no two-boot proof',
                             'guest stub lacks campaign nonce/boot-id/sequence attestation',
                             'host root/invoking UID and installed QEMU are trusted']}
        if state is not None:
            state.update(report)
            report = state
        output.write('plan.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
        if not execute:
            print(json.dumps({'status': report['status'], 'output': str(out), 'qemu_available': report['qemu_available']}))
            return report
        output.write('serial.raw', b'')
        output.write('qemu.stderr', b'')
        output.write('guest-events.jsonl', b'')
        return execute_fixture(inputs, output, inputfds, report, qemu_sha256)


def prepare(name, execute=False, qemu_sha256=None):
    state = {}
    try:
        return _prepare(name, execute, qemu_sha256, state)
    except LifecycleReceiptError:
        raise
    except BaseException as error:
        if state.get('boot_executed'):
            raise LifecycleReceiptError(state, error) from error
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--run', action='store_true', help='explicit VM start; requires separately approved installed QEMU')
    parser.add_argument('--qemu-sha256', help='reviewed root-owned installed QEMU hash, required with --run')
    args = parser.parse_args()
    try:
        report = prepare(args.name, args.run, args.qemu_sha256)
    except LifecycleReceiptError as error:
        print(json.dumps({'status': 'LIFECYCLE_OR_REPORTING_FAILED',
                          'boot_executed': error.report['boot_executed'],
                          'pid': error.report.get('pid'),
                          'exact_child_reaped': error.report.get('exact_child_reaped'),
                          'error': str(error)}), file=sys.stderr)
        return 2
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'REFUSED_NOT_STARTED', 'boot_executed': False, 'error': str(error)}), file=sys.stderr)
        return 2
    return 0 if report['status'] in ('DRY_RUN_NOT_BOOTED', 'CLOSED_STUB_OBSERVED_UNIMPLEMENTED') else 2


if __name__ == '__main__':
    sys.exit(main())
