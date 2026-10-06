#!/usr/bin/env python3
"""Offline markers, actual C decoder, fresh-image and fake-child tests. No VM launch."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid
sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import run_persistence_vm as runner

NONCE = 'a' * 32
A = '12345678-1234-1234-1234-123456789abc'
B = 'abcdef12-1234-1234-1234-123456789abc'
QEMU_HASH = offline.sha(closed.QEMU.read_bytes())
TEST_ROOT = runner.BASE / ('tests-' + uuid.uuid4().hex[:12])


def event(phase):
    return {'event':'closed_marker_persistence','phase':phase,'gate':'CLOSED','admission':'UNIMPLEMENTED',
            'nonce':NONCE,'boot_id': A if phase == 'A' else B,'boot_a':A,'inode':12,
            'marker_hex':runner.marker(NONCE,A).hex()}


def raw(record):
    return (json.dumps(record) + '\n[ 3.123] reboot: Power down\n').encode()


class Persistence(unittest.TestCase):
    def test_valid_pair_and_exact_marker_controls(self):
        first = runner.parse_event(raw(event('A')), 'A', NONCE)
        self.assertEqual(runner.parse_event(raw(event('B')), 'B', NONCE, first), event('B'))
        corrupt = [dict(event('B'),boot_id=A), dict(event('B'),nonce='b'*32),
                   dict(event('B'),boot_a=B), dict(event('B'),inode=13), dict(event('B'),inode=True),
                   dict(event('B'),marker_hex=event('B')['marker_hex'][:-2]),
                   dict(event('B'),gate='OPEN'), dict(event('B'),extra=True)]
        for record in corrupt:
            with self.subTest(record=record), self.assertRaises(ValueError):
                runner.parse_event(raw(record), 'B', NONCE, first)
        for capture in (b'', raw(event('A'))[:-1], raw(event('A')) + raw(event('A')),
                        raw(event('A')) + b'foreign\n', raw(event('A')) + b'\0\n',
                        raw(event('A')).replace(b'"phase": "A"', b'"phase":"A","phase":"A"')):
            with self.subTest(capture=capture), self.assertRaises(ValueError):
                runner.parse_event(capture, 'A', NONCE)
        refused = {'event':'persistence_refused','gate':'CLOSED','admission':'UNIMPLEMENTED','reason':'existing_or_partial_gate'}
        with self.assertRaises(ValueError): runner.parse_event(raw(refused),'B',NONCE,first)

    def test_argv_has_only_one_new_writable_disk_no_network_or_resume(self):
        command = runner.argv('/proc/self/fd/11','/proc/self/fd/12','/proc/self/fd/13','B')
        self.assertIn('readonly=off', command[command.index('-drive')+1])
        self.assertEqual(command.count('-drive'),1)
        for key in ('-nic','-monitor','-display'): self.assertEqual(command[command.index(key)+1],'none')
        for key in ('-snapshot','-virtfs','-fsdev','-qmp','-enable-kvm','-daemonize'): self.assertNotIn(key,command)
        with self.assertRaises(ValueError): runner.argv('a','b','c','C')

    def prepare(self, name):
        with patch.object(runner,'BASE',TEST_ROOT): return runner.prepare(name)

    def test_fresh_image_dry_run_refuses_preexisting_and_retains(self):
        report = self.prepare('persist-dry-test')
        path = TEST_ROOT/'persist-dry-test'/'fixture.raw'
        self.assertEqual(report['boots'],[])
        self.assertEqual(report['status'],'DRY_RUN_UNBOOTED_NO_ADMISSION')
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertEqual(path.stat().st_nlink,1)
        self.assertNotEqual((path.stat().st_dev,path.stat().st_ino),
                            ((runner.INPUT/'fixture.raw').stat().st_dev,(runner.INPUT/'fixture.raw').stat().st_ino))
        digest = offline.sha(path.read_bytes())
        with self.assertRaises(FileExistsError): self.prepare('persist-dry-test')
        self.assertEqual(offline.sha(path.read_bytes()),digest)

    def test_actual_c_decoder_refuses_truncation_open_state_and_same_boot(self):
        report = self.prepare('persist-c-decoder')
        directory = TEST_ROOT/'persist-c-decoder'
        source = directory/'decoder.c'
        source.write_text('#define main guest_main\n#include "init.persistence.c"\n#undef main\n'
            'int main(void){char data[512],prior[37];size_t n=marker(data,sizeof(data),"'+NONCE+'","'+A+'");'
            'if(!validate_marker(data,n,"'+NONCE+'","'+B+'",prior))return 1;'
            'for(size_t k=0;k<n;k++)if(validate_marker(data,k,"'+NONCE+'","'+B+'",prior))return 2;'
            'if(validate_marker(data,n,"'+NONCE+'","'+A+'",prior))return 3;'
            'data[0]^=1;if(validate_marker(data,n,"'+NONCE+'","'+B+'",prior))return 4;'
            'return 0;}')
        command=[str(runner.GCC),'-std=c11','-Wall','-Wextra','-Werror',str(source),'-o',str(directory/'decoder')]
        compiled = subprocess.run(command,capture_output=True,timeout=60)
        self.assertEqual(compiled.returncode,0,compiled.stderr.decode())
        self.assertEqual(subprocess.run([str(directory/'decoder')],timeout=5).returncode,0)

    def test_failure_of_boot_a_never_starts_boot_b(self):
        failed={'phase':'A','boot_executed':True,'exact_child_reaped':True,'pidfd_exit_verified':True,'status':'FAILED_OR_LIFECYCLE_UNVERIFIED'}
        with patch.object(runner,'BASE',TEST_ROOT), patch.object(runner,'run_boot',return_value=failed) as boot:
            report=runner.prepare('persist-fail-a',True,QEMU_HASH)
        self.assertEqual(boot.call_count,1)
        self.assertEqual(report['status'],'FAILED_NO_ADMISSION')
        self.assertTrue((TEST_ROOT/'persist-fail-a'/'fixture.raw').exists())

    def test_two_fake_fresh_boot_calls_share_exact_disk_descriptor(self):
        calls=[]
        def boot(inputs, output, phase, nonce, qemu_hash, latch, prior):
            fd=output.pins[output.out/'fixture.raw']; st=os.fstat(fd)
            calls.append((phase,st.st_dev,st.st_ino,prior))
            record=event(phase); record['nonce']=nonce;record['marker_hex']=runner.marker(nonce,A).hex()
            return {'phase':phase,'boot_executed':True,'exact_child_reaped':True,'pidfd_exit_verified':True,
                    'status':'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION','event':record}
        with patch.object(runner,'BASE',TEST_ROOT), patch.object(runner,'run_boot',side_effect=boot):
            report=runner.prepare('persist-fake-pair',True,QEMU_HASH)
        self.assertEqual(report['status'],runner.SUCCESS)
        self.assertEqual([call[0] for call in calls],['A','B'])
        self.assertEqual(calls[0][1:3],calls[1][1:3])
        self.assertIsNone(calls[0][3]);self.assertEqual(calls[1][3]['boot_id'],A)

    def test_actual_run_boot_control_flow_with_fake_child_and_timeout(self):
        for failure in (False,True):
            name='persist-child-bad' if failure else 'persist-child-ok'
            report=self.prepare(name); path=TEST_ROOT/name
            with offline.TrustedOutput(runner.INPUT) as inputs, offline.TrustedOutput(path) as output:
                output.out=path
                for file in ('vmlinuz','initramfs.cpio.gz','fixture.raw'):closed.attach(output,file)
                child=type('Child',(),{'pid':424242,'stdout':io.BytesIO(),'stderr':io.BytesIO()})()
                def capture(child,pidfd,serialfd,stderrfd,logs,latch):
                    if failure: raise TimeoutError('injected capture deadline')
                    record=event('A');record['nonce']=report['nonce'];record['marker_hex']=runner.marker(report['nonce'],A).hex()
                    closed.write_all(serialfd,raw(record))
                with patch.object(runner.subprocess,'Popen',return_value=child) as launch, \
                     patch.object(os,'pidfd_open',side_effect=lambda *_:os.dup(output.pins[path])), \
                     patch.object(closed,'process_birth',return_value=100), \
                     patch.object(closed,'capture',side_effect=capture), \
                     patch.object(closed,'reap_exact',return_value=0) as reap:
                    result=runner.run_boot(inputs,output,'A',report['nonce'],QEMU_HASH,closed.SignalLatch())
                launch.assert_called_once();self.assertTrue(result['exact_child_reaped'])
                self.assertTrue(result['pidfd_exit_verified']);self.assertTrue((path/'fixture.raw').exists())
                self.assertEqual(reap.call_args.kwargs.get('kill',False),failure)
                self.assertEqual(result['status'],'FAILED_OR_LIFECYCLE_UNVERIFIED' if failure else 'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION')


if __name__=='__main__':
    print('retained offline test root: '+str(TEST_ROOT),flush=True)
    unittest.main(verbosity=2)
