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

    def test_bound_partial_refusal_is_exact_and_never_accepts_success(self):
        expected={'event':'persistence_refused','gate':'CLOSED','admission':'UNIMPLEMENTED',
                  'reason':'existing_or_partial_gate','phase':'B','nonce':NONCE,'boot_id':B}
        self.assertEqual(runner.parse_partial_refusal(raw(expected),NONCE,event('A')),expected)
        for bad in (dict(expected,nonce='b'*32),dict(expected,boot_id=A),dict(expected,phase='A'),
                    dict(expected,reason='gate_absence_unobserved'),dict(expected,extra=True),
                    dict(expected,gate='OPEN'),event('B'),
                    {'event':'persistence_refused','gate':'CLOSED','admission':'UNIMPLEMENTED','reason':'existing_or_partial_gate'}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                runner.parse_partial_refusal(raw(bad),NONCE,event('A'))
        for bad in (raw(expected)+raw(expected),raw(expected)+raw(event('B')),raw(expected)+b'foreign\n'):
            with self.assertRaises(ValueError):runner.parse_partial_refusal(bad,NONCE,event('A'))

    def test_real_offline_ext4_partial_injection_is_exclusive_and_preserves_original(self):
        report=self.prepare('persist-partial-image');path=TEST_ROOT/'persist-partial-image'
        with offline.TrustedOutput(path) as output:
            output.out=path;closed.attach(output,'fixture.raw')
            data=runner.marker(report['nonce'],A);output.write('seed-marker.bin',data)
            seedfd=output.pins[path/'seed-marker.bin']
            runner.debugfs_command(output,'mkdir /closed','seed-directory',True)
            runner.debugfs_command(output,'set_inode_field /closed mode 040700','seed-directory-mode',True)
            runner.debugfs_command(output,f'write /proc/self/fd/{seedfd} /closed/gate.record','seed-record',True,(seedfd,))
            for field,value in (('mode','0100600'),('uid','0'),('gid','0')):
                runner.debugfs_command(output,f'set_inode_field /closed/gate.record {field} {value}','seed-record-'+field,True)
            record,record_bytes=runner.disk_file(output,'/closed/gate.record','seed-readback')
            prior=event('A');prior.update(nonce=report['nonce'],inode=record['inode'],marker_hex=data.hex())
            boot={'status':'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION','boot_executed':True,'exact_child_reaped':True,
                  'pidfd_exit_verified':True,'exit_code':0,'event':prior}
            for field in ('boot_executed','exact_child_reaped','pidfd_exit_verified'):
                with self.assertRaises(ValueError):runner.inject_partial(output,dict(boot,**{field:False}))
            injected=runner.inject_partial(output,boot)
            self.assertEqual(injected['record'],record);self.assertEqual(record_bytes,data)
            self.assertEqual(injected['injected_hex'],runner.PARTIAL.hex())
            before=offline.fd_hash(output.pins[path/'fixture.raw'])
            with self.assertRaises((ValueError,FileExistsError)):runner.inject_partial(output,boot)
            self.assertEqual(offline.fd_hash(output.pins[path/'fixture.raw']),before)
            self.assertEqual(runner.verify_partial(output,prior,injected,'offline-after'),
                             {'record':injected['record'],'partial':injected['partial']})
            # Exercise the pinned tool itself: its write refuses an existing guest path.
            with self.assertRaises(ValueError):runner.debugfs_command(output,f'write /proc/self/fd/{seedfd} /closed/gate.writing','direct-exclusive-retry',True,(seedfd,))
            self.assertEqual(offline.fd_hash(output.pins[path/'fixture.raw']),before)

    def test_injection_failure_prevents_boot_b_and_unexpected_success_fails_negative(self):
        first={'phase':'A','boot_executed':True,'exact_child_reaped':True,'pidfd_exit_verified':True,
               'exit_code':0,'status':'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION','event':event('A')}
        with patch.object(runner,'BASE',TEST_ROOT),patch.object(runner,'run_boot',return_value=first) as boot, \
             patch.object(runner,'inject_partial',side_effect=ValueError('injected failure')):
            report=runner.prepare('persist-inject-fail',True,QEMU_HASH,'partial-writing')
        self.assertEqual(boot.call_count,1);self.assertEqual(report['status'],'FAILED_NO_ADMISSION')
        with patch.object(runner,'BASE',TEST_ROOT),patch.object(runner,'run_boot',side_effect=[first,dict(first,phase='B')]) as boot, \
             patch.object(runner,'inject_partial',return_value={'case':'partial-writing'}), \
             patch.object(runner,'verify_partial') as verify:
            report=runner.prepare('persist-neg-success-fail',True,QEMU_HASH,'partial-writing')
        self.assertEqual(boot.call_count,2);self.assertTrue(boot.call_args.kwargs['partial_refusal'])
        self.assertEqual(report['status'],'FAILED_NO_ADMISSION');verify.assert_not_called()

    def test_negative_success_requires_refusal_and_post_boot_preservation(self):
        first={'phase':'A','boot_executed':True,'exact_child_reaped':True,'pidfd_exit_verified':True,
               'exit_code':0,'status':'CLOSED_MARKER_BOOT_OBSERVED_NO_ADMISSION','event':event('A')}
        second={'phase':'B','boot_executed':True,'exact_child_reaped':True,'pidfd_exit_verified':True,
                'exit_code':0,'status':'CLOSED_PARTIAL_GATE_REFUSAL_OBSERVED_NO_ADMISSION',
                'event':{'event':'persistence_refused','reason':'existing_or_partial_gate','gate':'CLOSED','admission':'UNIMPLEMENTED','phase':'B','nonce':NONCE,'boot_id':B}}
        for fail in (False,True):
            name='persist-neg-post-fail' if fail else 'persist-neg-mock-ok'
            with patch.object(runner,'BASE',TEST_ROOT),patch.object(runner,'run_boot',side_effect=[first,second]), \
                 patch.object(runner,'inject_partial',return_value={'case':'partial-writing'}), \
                 patch.object(runner,'verify_partial',side_effect=ValueError('changed original') if fail else None,return_value={'preserved':True}):
                report=runner.prepare(name,True,QEMU_HASH,'partial-writing')
            self.assertEqual(report['status'],'FAILED_NO_ADMISSION' if fail else runner.NEGATIVE_SUCCESS)
            self.assertTrue((TEST_ROOT/name/'fixture.raw').exists())

    def test_fake_child_refusal_flows_through_real_run_boot_parser_and_teardown(self):
        report=self.prepare('persist-refusal-child');path=TEST_ROOT/'persist-refusal-child'
        with offline.TrustedOutput(runner.INPUT) as inputs,offline.TrustedOutput(path) as output:
            output.out=path
            for file in ('vmlinuz','initramfs.cpio.gz','fixture.raw'):closed.attach(output,file)
            child=type('Child',(),{'pid':424243,'stdout':io.BytesIO(),'stderr':io.BytesIO()})()
            def capture(child,pidfd,serialfd,stderrfd,logs,latch):
                refusal={'event':'persistence_refused','gate':'CLOSED','admission':'UNIMPLEMENTED',
                         'reason':'existing_or_partial_gate','phase':'B','nonce':report['nonce'],'boot_id':B}
                closed.write_all(serialfd,raw(refusal))
            with patch.object(runner.subprocess,'Popen',return_value=child), \
                 patch.object(os,'pidfd_open',side_effect=lambda *_:os.dup(output.pins[path])), \
                 patch.object(closed,'process_birth',return_value=101), \
                 patch.object(closed,'capture',side_effect=capture),patch.object(closed,'reap_exact',return_value=0):
                result=runner.run_boot(inputs,output,'B',report['nonce'],QEMU_HASH,closed.SignalLatch(),event('A'),partial_refusal=True)
            self.assertEqual(result['status'],'CLOSED_PARTIAL_GATE_REFUSAL_OBSERVED_NO_ADMISSION')
            self.assertTrue(result['exact_child_reaped']);self.assertTrue(result['pidfd_exit_verified'])
            self.assertEqual(result['event']['reason'],'existing_or_partial_gate')


if __name__=='__main__':
    print('retained offline test root: '+str(TEST_ROOT),flush=True)
    unittest.main(verbosity=2)
