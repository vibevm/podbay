#!/usr/bin/env python3
"""Prepare a pinned disposable systemd run. Execution needs explicit reviewed --run."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import build_r1_systemd_vm as builder

BASE = builder.BASE
ARTIFACTS = ('vmlinuz', 'initramfs.cpio.gz', 'fixture.raw')
DRY = 'SYSTEMD_RUN_PREPARED_UNBOOTED_NO_PRODUCTION_ADMISSION'
FAILED = 'SYSTEMD_RUN_FAILED_NO_PRODUCTION_ADMISSION'
SYNTHETIC = 'SYNTHETIC_LIFECYCLE_VERIFIED_NO_VM_PROOF'
NATIVE_KIND = 'QEMU_NATIVE'
TEST_KIND = 'SYNTHETIC_TEST_ONLY'
MAX_PLAN = 256 * 1024
MAX_ARTIFACT = 128 * 1024 * 1024


def validate_plan(plan):
    if (not isinstance(plan, dict) or type(plan.get('schema')) is not int or plan['schema'] != 1
            or plan.get('status') != builder.OFFLINE or plan.get('boot_executed') is not False
            or plan.get('native_execution_supported') is not False):
        raise ValueError('input is not an unbooted systemd candidate')
    if not isinstance(plan.get('artifacts'), dict) or set(plan['artifacts']) != set(ARTIFACTS):
        raise ValueError('input artifact set differs')
    for digest in plan['artifacts'].values():
        if not isinstance(digest, str) or not builder.DIGEST.fullmatch(digest):
            raise ValueError('invalid artifact digest')
    for key in ('archive_generation', 'enforcer_sha256', 'manifest_sha256', 'systemd_sha256'):
        if not isinstance(plan.get(key), str) or not builder.DIGEST.fullmatch(plan[key]):
            raise ValueError('missing native parser pin: ' + key)
    builder_hash = plan.get('builder_sha256')
    if (not isinstance(builder_hash, str) or not builder.DIGEST.fullmatch(builder_hash)
            or builder_hash != offline.sha((builder.HERE/'build_r1_systemd_vm.py').read_bytes())):
        raise ValueError('builder source hash differs from pinned input generation')
    if plan['artifacts']['vmlinuz'] != offline.KERNEL[2]:
        raise ValueError('unreviewed kernel')
    syntax = plan.get('systemd_syntax')
    if not isinstance(syntax, dict) or type(syntax.get('exit')) is not int or syntax['exit'] != 0:
        raise ValueError('staged systemd syntax gate missing')
    # This also refuses the earlier unsafe /init rather than executing a stale
    # candidate with a newer parser/helper source generation.
    if plan.get('source_pins') != {n: offline.sha((builder.HERE/n).read_bytes()) for n in builder.PIN_NAMES}:
        raise ValueError('builder/helper/parser source differs from pinned input generation')


def validate_qemu(digest):
    if not isinstance(digest, str) or not builder.DIGEST.fullmatch(digest):
        raise ValueError('reviewed QEMU SHA256 required')
    if not callable(getattr(os, 'pidfd_open', None)) or not callable(getattr(signal, 'pidfd_send_signal', None)):
        raise ValueError('pidfd lifecycle unavailable')
    offline.trusted_tool(closed.QEMU)
    offline.read_pinned(closed.QEMU, digest)


def attach_bounded(inputs, name, digest, limit):
    fd = closed.attach(inputs, name)
    if os.fstat(fd).st_size > limit:
        raise ValueError('oversized input: '+name)
    if offline.fd_hash(fd) != digest:
        raise ValueError('input SHA256 mismatch: '+name)
    inputs.check()
    return fd


def _execute(inputs, output, report, qemu_hash, latch):
    """One attempt, always retain first capture/image; tests mark synthetic explicitly."""
    child = pidfd = None
    report.update(status=FAILED, boot_executed=False, process_launched=False,
                  exact_child_reaped=False, pidfd_exit_verified=False, disk_retained=True)
    for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'):
        output.write(name, b'')
    try:
        if report.get('evidence_kind') not in (NATIVE_KIND, TEST_KIND):
            raise ValueError('unknown evidence kind')
        inputs.check(); output.check(); latch.check(); validate_qemu(qemu_hash)
        for name, expected in report['artifact_pins'].items():
            if offline.fd_hash(output.pins[output.out/name]) != expected:
                raise ValueError('run artifact changed before launch: ' + name)
        fds = tuple(output.pins[output.out/n] for n in ARTIFACTS)
        argv = builder.planned_qemu(*(f'/proc/self/fd/{fd}' for fd in fds))
        # argv is constructed locally; no argv from a JSON plan is executed.
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, close_fds=True, pass_fds=fds,
                                 cwd=output.out, env={'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
        report.update(process_launched=True, boot_executed=report['evidence_kind'] == NATIVE_KIND,
                      pid=child.pid, executed_argv=argv)
        pidfd = os.pidfd_open(child.pid, 0)
        report['process_birth_ticks'] = closed.process_birth(child.pid)
        if type(report['process_birth_ticks']) is not int or report['process_birth_ticks'] < 1:
            raise ValueError('missing exact child birth')
        latch.check()
        closed.capture(child, pidfd, output.pins[output.out/'serial.raw'],
                       output.pins[output.out/'qemu.stderr'], output, latch)
        report['exit_code'] = closed.reap_exact(child, pidfd)
        report.update(exact_child_reaped=True, pidfd_exit_verified=True)
        latch.check(); inputs.check(); output.check()
        observation = builder.native_receipt(output.read('serial.raw'), report,
                                             report['exit_code'], report['exact_child_reaped'],
                                             report['pidfd_exit_verified'], output.read('qemu.stderr'))
        # Readonly=on is fixed in argv. Check exact retained image bytes too.
        for name, expected in report['artifact_pins'].items():
            if offline.fd_hash(output.pins[output.out/name]) != expected:
                raise ValueError('readonly run artifact changed: ' + name)
        closed.write_all(output.pins[output.out/'guest-events.jsonl'],
                         (json.dumps(observation, sort_keys=True)+'\n').encode())
        latch.check()
        report.update(observation=observation,
                      status=builder.SUCCESS if report['evidence_kind'] == NATIVE_KIND else SYNTHETIC)
    except BaseException as error:
        # Never replace the first failure with a later cleanup error.
        report.update(status=FAILED, error_type=type(error).__name__, error=str(error))
        if child is not None and not report['exact_child_reaped']:
            try:
                if pidfd is not None:
                    report['exit_code'] = closed.reap_exact(child, pidfd, kill=True)
                    report['pidfd_exit_verified'] = True
                else:
                    # Popen owns an unreaped child, so no reused PID is targeted.
                    child.kill(); report['exit_code'] = child.wait(timeout=closed.REAP_TIMEOUT)
                report['exact_child_reaped'] = True
            except BaseException as teardown:
                report['teardown_error'] = str(teardown)
    finally:
        report['received_signal'] = latch.signum
        if latch.signum is not None and report['status'] in (builder.SUCCESS, SYNTHETIC):
            report.update(status=FAILED, error_type='InterruptedError',
                          error='runner received signal '+str(latch.signum))
        if child is not None:
            for stream in (child.stdout, child.stderr):
                if stream is not None: stream.close()
        if pidfd is not None: os.close(pidfd)
        try:
            for name in ('serial.raw', 'qemu.stderr', 'guest-events.jsonl'):
                os.fsync(output.pins[output.out/name])
            # Unknown reap means the image might still be in use; preserve it
            # without claiming a stable post-exit digest.
            if report['exact_child_reaped']:
                os.fsync(output.pins[output.out/'fixture.raw'])
                output.check()
                report['post_reap_disk_sha256'] = offline.fd_hash(output.pins[output.out/'fixture.raw'])
            closed.durable_receipt(output, 'result.json', report)
        except BaseException as receipt:
            raise closed.LifecycleReceiptError(report, receipt) from receipt
    return report


def prepare(name, input_dir, input_plan_sha256, execute=False, qemu_sha256=None):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('ordinary host UID required')
    if not re.fullmatch(r'systemd-run-[a-z0-9][a-z0-9-]{0,19}', name):
        raise ValueError('fresh systemd-run- name required')
    source = Path(input_dir)
    if source.parent != BASE or not re.fullmatch(r'systemd-[a-z0-9][a-z0-9-]{0,22}', source.name):
        raise ValueError('input must be one private systemd build under fixed base')
    if not isinstance(input_plan_sha256, str) or not builder.DIGEST.fullmatch(input_plan_sha256):
        raise ValueError('explicit reviewed offline plan SHA256 required')
    if execute:
        validate_qemu(qemu_sha256)
    with offline.TrustedOutput(source) as inputs, offline.TrustedOutput(BASE) as output:
        planfd = attach_bounded(inputs, 'plan.json', input_plan_sha256, MAX_PLAN)
        plan_size = os.fstat(planfd).st_size
        if plan_size > MAX_PLAN:
            raise ValueError('offline plan grew beyond capture bound')
        plan_bytes = os.pread(planfd, plan_size, 0)
        if len(plan_bytes) != plan_size or offline.sha(plan_bytes) != input_plan_sha256:
            raise ValueError('captured offline plan differs from reviewed SHA256')
        plan = builder.strict_json(plan_bytes); validate_plan(plan)
        descriptors = {}
        for artifact in ARTIFACTS:
            fd = attach_bounded(inputs, artifact, plan['artifacts'][artifact], MAX_ARTIFACT)
            descriptors[artifact] = fd
        output.create_dir(name)
        output.write('input-plan.json', plan_bytes)
        for artifact, sourcefd in descriptors.items():
            output.write(artifact, b'')
            target = output.pins[output.out/artifact]
            for offset in range(0, os.fstat(sourcefd).st_size, 1024*1024):
                closed.write_all(target, os.pread(sourcefd, 1024*1024, offset))
            inputs.check(); output.check()
            if ((os.fstat(target).st_dev, os.fstat(target).st_ino) ==
                    (os.fstat(sourcefd).st_dev, os.fstat(sourcefd).st_ino)
                    or offline.fd_hash(target) != plan['artifacts'][artifact]):
                raise ValueError('exclusive artifact copy identity/hash mismatch')
            os.fsync(target)
        report = {key: plan[key] for key in ('archive_generation', 'enforcer_sha256', 'manifest_sha256', 'systemd_sha256')}
        report.update(schema=1, status=DRY, boot_executed=False, process_launched=False,
                      evidence_kind=NATIVE_KIND, input=str(source), input_plan_sha256=input_plan_sha256,
                      artifact_pins=plan['artifacts'], output=str(output.out), disk_retained=True,
                      exact_child_reaped=False, pidfd_exit_verified=False,
                      enforcer_gate='UNESTABLISHED', admission='UNAVAILABLE',
                      timeout_seconds=closed.TIMEOUT, max_serial=closed.MAX_SERIAL, max_stderr=closed.MAX_STDERR,
                      qemu_sha256=qemu_sha256, runner_sha256=offline.sha(Path(__file__).read_bytes()),
                      argv=builder.planned_qemu(*(str(output.out/n) for n in ARTIFACTS)),
                      limits=['Fixed single-issuer negative smoke only; no production origin/custody/admission',
                              'Root/kernel/invoking UID/installed hypervisor trusted',
                              'No automatic retries, cleanup, guest mutation or positive-enforcer acceptance'])
        closed.durable_receipt(output, 'run-plan.json', report)
        if not execute:
            closed.durable_receipt(output, 'result.json', report)
            return report
        with closed.SignalLatch() as latch:
            return _execute(inputs, output, report, qemu_sha256, latch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--input-plan-sha256', required=True)
    parser.add_argument('--run', action='store_true', help='only after independent source review and fresh-name go')
    parser.add_argument('--qemu-sha256')
    args = parser.parse_args()
    try:
        report = prepare(args.name, args.input, args.input_plan_sha256, args.run, args.qemu_sha256)
        try:
            print(json.dumps(report, sort_keys=True), flush=True)
        except BaseException as error:
            raise closed.LifecycleReceiptError(report, error) from error
    except closed.LifecycleReceiptError as error:
        print(json.dumps({'status': 'LIFECYCLE_OR_REPORTING_FAILED', 'error': str(error),
                          'boot_executed': error.report.get('boot_executed'), 'pid': error.report.get('pid'),
                          'exact_child_reaped': error.report.get('exact_child_reaped'),
                          'pidfd_exit_verified': error.report.get('pidfd_exit_verified'),
                          'disk_retained': True}), file=sys.stderr)
        return 2
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'REFUSED_BEFORE_LAUNCH', 'boot_executed': False, 'error': str(error)}), file=sys.stderr)
        return 2
    return 0 if report['status'] in (DRY, builder.SUCCESS) else 2


if __name__ == '__main__':
    sys.exit(main())
