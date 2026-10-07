#!/usr/bin/env python3
"""Synthetic host-runner tests. Never invoke QEMU or produce native VM proof."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
import build_r1_systemd_vm as builder
import run_r1_systemd_vm as runner
import r1_systemd_test as fixture

REAL_POPEN = subprocess.Popen
REAL_REAP = runner.closed.reap_exact
BASELINE = builder.BASE/'systemd-safe-a'
PLAN_SHA = '18e57d75af50118c7d9a5304bf6461e0f9ee4e928ee23f02e51628d010a807a6'


class InputValidation(unittest.TestCase):
    def test_exact_corrected_plan_and_artifacts(self):
        with runner.offline.TrustedOutput(BASELINE) as guard:
            fd=runner.closed.attach(guard,'plan.json',PLAN_SHA)
            plan=builder.strict_json(os.pread(fd,os.fstat(fd).st_size,0))
            runner.validate_plan(plan)
            for name in runner.ARTIFACTS:runner.closed.attach(guard,name,plan['artifacts'][name])
    def test_plan_mutations_refuse(self):
        plan=builder.strict_json(builder.pinned(BASELINE/'plan.json',PLAN_SHA))
        for key,value in (('schema',True),('status',builder.SUCCESS),('boot_executed',True),('source_pins',{}),('artifacts',{}),('archive_generation','x'),('builder_sha256','0'*64),('builder_sha256',None),('builder_sha256','x')):
            altered=copy.deepcopy(plan);altered[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):runner.validate_plan(altered)
    def test_invalid_request_starts_nothing(self):
        with patch.object(runner.subprocess,'Popen',side_effect=AssertionError('unexpected launch')):
            for name,path,digest in (('../bad',BASELINE,PLAN_SHA),('systemd-run-input','/tmp/foreign',PLAN_SHA),('systemd-run-input',BASELINE,'x')):
                with self.assertRaises(ValueError):runner.prepare(name,path,digest)
    def test_same_inode_plan_rewrite_refuses_before_output(self):
        if os.getuid()==0 or os.geteuid()==0:
            self.skipTest('ordinary-UID fixture only')
        original=builder.pinned(BASELINE/'plan.json',PLAN_SHA)
        # Valid JSON, same length, different digest. Keep the reviewed pin.
        replacement=original.replace(b'"boot_executed": false',b'"boot_executed": true ',1)
        self.assertEqual(len(original),len(replacement));self.assertNotEqual(original,replacement)
        suffix=str(time.monotonic_ns())[-9:]
        source_name='systemd-race-'+suffix;output_name='systemd-run-race-'+suffix
        with runner.offline.TrustedOutput(builder.BASE) as fixture_output:
            fixture_output.create_dir(source_name);fixture_output.write('plan.json',original)
            source=fixture_output.out;writefd=fixture_output.pins[source/'plan.json']
            identity=(os.fstat(writefd).st_dev,os.fstat(writefd).st_ino)
            original_attach=runner.attach_bounded
            rewritten=[]
            def rewrite_after_hash(inputs,name,digest,limit):
                fd=original_attach(inputs,name,digest,limit)
                if name=='plan.json':
                    self.assertEqual(digest,PLAN_SHA)
                    os.pwrite(writefd,replacement,0);os.fsync(writefd)
                    self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),identity)
                    rewritten.append(True)
                return fd
            with patch.object(runner,'attach_bounded',side_effect=rewrite_after_hash), \
                 patch.object(runner.subprocess,'Popen',side_effect=AssertionError('unexpected launch')):
                with self.assertRaisesRegex(ValueError,'captured offline plan differs'):
                    runner.prepare(output_name,source,PLAN_SHA)
            self.assertEqual(rewritten,[True])
            self.assertFalse((builder.BASE/output_name).exists())
            self.assertEqual(fixture_output.read('plan.json'),replacement)


class SyntheticLifecycle(unittest.TestCase):
    def exercise(self,case,code,timeout=2,pidfd_error=False,birth_error=False,receipt_error=False,reap_error=False):
        name='runner-test-'+case+'-'+str(time.monotonic_ns())[-9:]
        with runner.offline.TrustedOutput(builder.BASE) as output:
            output.create_dir(name)
            data={n:('synthetic '+n+'\n').encode() for n in runner.ARTIFACTS}
            for n,raw in data.items():output.write(n,raw)
            report=dict(fixture.fake_pins(),evidence_kind=runner.TEST_KIND,
                        artifact_pins={n:runner.offline.sha(raw) for n,raw in data.items()})
            starts=[];children=[]
            def fake_start(argv,**kwargs):
                self.assertEqual(argv[0],str(runner.closed.QEMU))
                self.assertEqual(argv[argv.index('-nic')+1],'none')
                self.assertEqual(argv[argv.index('-monitor')+1],'none')
                self.assertIn('pc,accel=tcg',argv)
                self.assertIn('readonly=on',argv[argv.index('-drive')+1])
                self.assertEqual(kwargs['pass_fds'],tuple(output.pins[output.out/n] for n in runner.ARTIFACTS))
                starts.append(argv)
                child=REAL_POPEN([sys.executable,'-B','-c',code],stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                children.append(child);return child
            with ExitStack() as stack:
                stack.enter_context(patch.object(runner,'validate_qemu',return_value=None))
                stack.enter_context(patch.object(runner.subprocess,'Popen',side_effect=fake_start))
                stack.enter_context(patch.object(runner.closed,'TIMEOUT',timeout))
                if pidfd_error:stack.enter_context(patch.object(runner.os,'pidfd_open',side_effect=OSError('synthetic pidfd unavailable')))
                if birth_error:stack.enter_context(patch.object(runner.closed,'process_birth',side_effect=OSError('synthetic birth unavailable')))
                if receipt_error:stack.enter_context(patch.object(runner.closed,'durable_receipt',side_effect=OSError('synthetic receipt failure')))
                if reap_error:stack.enter_context(patch.object(runner.closed,'reap_exact',side_effect=OSError('synthetic uncertain reap')))
                try:
                    with runner.closed.SignalLatch() as latch:
                        if receipt_error:
                            with self.assertRaises(runner.closed.LifecycleReceiptError) as error:
                                runner._execute(output,output,report,'a'*64,latch)
                            self.assertIs(error.exception.report,report)
                        else:runner._execute(output,output,report,'a'*64,latch)
                finally:
                    for child in children:
                        if child.poll() is None:child.kill()
                        child.wait(timeout=2)
            self.assertEqual(len(starts),1,'no automatic retry')
            self.assertFalse(report['boot_executed'])
            self.assertEqual(report['evidence_kind'],runner.TEST_KIND)
            self.assertNotEqual(report['status'],builder.SUCCESS)
            self.assertTrue(report['disk_retained'])
            for n,raw in data.items():self.assertEqual(output.read(n),raw)
            self.assertIn(output.out/'serial.raw',output.pins)
            if not receipt_error:
                saved=builder.strict_json(output.read('result.json'))
                self.assertEqual(saved['status'],report['status'])
                self.assertFalse(saved['boot_executed'])
            return report,output.read('serial.raw')
    @staticmethod
    def valid_code(suffix=''):
        return 'import sys;sys.stdout.buffer.write('+repr(fixture.serial())+');sys.stdout.flush();'+suffix
    def test_fake_pass_is_not_native_proof(self):
        report,raw=self.exercise('valid',self.valid_code())
        self.assertEqual(report['status'],runner.SYNTHETIC)
        self.assertTrue(report['pidfd_exit_verified']);self.assertTrue(report['exact_child_reaped'])
        self.assertEqual(raw,fixture.serial())
    def test_timeout_retains_prefix_and_reaps(self):
        report,raw=self.exercise('timeout','import time;print("first-timeout-byte",flush=True);time.sleep(10)',timeout=.2)
        self.assertEqual(report['status'],runner.FAILED);self.assertEqual(report['error_type'],'TimeoutError')
        self.assertIn(b'first-timeout-byte',raw);self.assertTrue(report['exact_child_reaped'])
    def test_pidfd_failure_kills_owned_child_without_claiming_pidfd(self):
        report,raw=self.exercise('pidfd','import time;time.sleep(10)',pidfd_error=True)
        self.assertEqual(report['status'],runner.FAILED);self.assertTrue(report['exact_child_reaped'])
        self.assertFalse(report['pidfd_exit_verified'])
    def test_birth_failure_refuses(self):
        report,raw=self.exercise('birth','import time;time.sleep(10)',birth_error=True)
        self.assertEqual(report['status'],runner.FAILED);self.assertTrue(report['exact_child_reaped'])
    def test_parser_failure_retains_first_raw(self):
        report,raw=self.exercise('parser','print("first-invalid-record")')
        self.assertEqual(report['status'],runner.FAILED);self.assertEqual(raw,b'first-invalid-record\n')
    def test_nonzero_refuses_valid_fake_record(self):
        report,raw=self.exercise('nonzero',self.valid_code('sys.exit(7)'))
        self.assertEqual(report['status'],runner.FAILED);self.assertEqual(report['exit_code'],7)
        self.assertEqual(raw,fixture.serial())
    def test_stderr_refuses_valid_fake_record(self):
        report,raw=self.exercise('stderr',self.valid_code('sys.stderr.write("unexpected warning\\n")'))
        self.assertEqual(report['status'],runner.FAILED)
    def test_receipt_failure_retains_first_error_and_raw(self):
        report,raw=self.exercise('receipt','print("first-invalid-record")',receipt_error=True)
        self.assertEqual(report['status'],runner.FAILED);self.assertIn('unexpected guest output',report['error'])
        self.assertTrue(report['exact_child_reaped']);self.assertEqual(raw,b'first-invalid-record\n')
    def test_unknown_reap_cannot_claim_stable_image(self):
        report,raw=self.exercise('reap',self.valid_code(),reap_error=True)
        self.assertEqual(report['status'],runner.FAILED);self.assertFalse(report['exact_child_reaped'])
        self.assertIn('teardown_error',report);self.assertNotIn('post_reap_disk_sha256',report)


if __name__=='__main__':unittest.main()
