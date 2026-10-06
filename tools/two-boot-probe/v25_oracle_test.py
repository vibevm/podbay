"""Offline v25 packaging/oracle/fake QEMU gates; never starts a VM."""
import copy
import gzip
import io
import json
import os
from pathlib import Path
import signal
import sys
import unittest
from unittest.mock import patch
import uuid
sys.dont_write_bytecode=True
import offline
import run_closed_vm as closed
import run_persistence_vm as runner
import v25_oracle as oracle

N='a'*32; A='12345678-1234-1234-1234-123456789abc';B='abcdef12-1234-1234-1234-123456789abc';H='b'*64
ROOT=runner.BASE/('v25-tests-'+uuid.uuid4().hex[:12])
QHASH=offline.sha(closed.QEMU.read_bytes())


def transcript(phase,nonce=N):
    names=oracle.A_EVENTS if phase=='A' else oracle.B_EVENTS
    boot=A if phase=='A' else B
    details=[{'root':'/fixture/podbay-v25-fixture-'+nonce},{'authority_revision':2},{'constructed_control':True},
             {'manifest_sha256':H,'authority_revision':2,'files':16,'next':'host may kill and reap exact QEMU'}] if phase=='A' else [
             {'cold_boot_verified':True,'boot_a':A,'manifest_sha256':H},
             {'authority_revision':2,'ordinary_write':'UnsupportedSchema(25)','ordinary_read':'UnsupportedSchema(25)','frozen_exchange':'refused','foreign_key':'refused'},
             {'cold_boot_verified':True,'manifest_sha256':H,'authority_revision':2,'partial_control':'refused_and_unchanged','scope':'disposable persistence and refusal only'}]
    records=[{'schema':oracle.SCHEMA,'event':name,'gate':'CLOSED','admission':'UNIMPLEMENTED','domain':'guest','nonce':nonce,
              'boot_id':boot,'sequence':i,'executable_sha256':oracle.ELF_SHA256,'details':data}
             for i,(name,data) in enumerate(zip(names,details),1)]
    marker={'event':'closed_marker_persistence','phase':phase,'gate':'CLOSED','admission':'UNIMPLEMENTED','nonce':nonce,
            'boot_id':boot,'boot_a':A,'inode':13,'marker_hex':runner.marker(nonce,A).hex(),
            'workload':'v25-fixture/1','child_pid':2,'child_birth_ticks':123,'child_exit_code':0,'child_reaped':True}
    return records,marker


def encode(records,marker):
    return (''.join(oracle.PREFIX+json.dumps(item)+'\n' for item in records)+json.dumps(marker)+'\n').encode()


class V25(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ROOT.mkdir(mode=0o700,exist_ok=False)
    def test_valid_pair(self):
        prior=oracle.parse_phase(encode(*transcript('A')),'A',N,runner)
        current=oracle.parse_phase(encode(*transcript('B')),'B',N,runner,prior)
        self.assertEqual(current['manifest_sha256'],prior['manifest_sha256']);self.assertNotEqual(current['marker']['boot_id'],prior['marker']['boot_id'])

    def test_all_common_fields_and_a_ack_controls(self):
        for field,value in [('schema','foreign'),('event','FIXTURE_FAILED'),('gate','OPEN'),('admission','READY'),('domain','host-process-control'),
                            ('nonce','c'*32),('boot_id',B),('sequence',True),('executable_sha256','c'*64)]:
            rows,marker=transcript('A');rows[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):oracle.parse_phase(encode(rows,marker),'A',N,runner)
        for field,value in [('child_pid',1),('child_birth_ticks',0),('child_exit_code',2),('child_reaped',False),('workload','foreign')]:
            rows,marker=transcript('A');marker[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):oracle.parse_phase(encode(rows,marker),'A',N,runner)
        rows,marker=transcript('A')
        for bad in (encode(rows[:-1],marker),encode(rows+rows,marker),encode(list(reversed(rows)),marker),encode(rows,marker)+b'foreign\n',
                    json.dumps(marker).encode()+b'\n'+encode(rows,marker),encode(rows,marker)[:-1],encode(rows,marker)+b'\0\n'):
            with self.assertRaises(ValueError):oracle.parse_phase(bad,'A',N,runner)

    def test_boot_b_hash_anchor_revision_and_refusals(self):
        prior=oracle.parse_phase(encode(*transcript('A')),'A',N,runner)
        changes=[(0,'manifest_sha256','c'*64),(2,'manifest_sha256','c'*64),(0,'boot_a',B),(0,'cold_boot_verified',False),
                 (1,'authority_revision',3),(1,'ordinary_write','accepted'),(1,'ordinary_read','accepted'),(1,'frozen_exchange','accepted'),
                 (1,'foreign_key','accepted'),(2,'partial_control','accepted'),(2,'cold_boot_verified',1),(2,'authority_revision',True)]
        for index,field,value in changes:
            rows,marker=transcript('B');rows[index]['details'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):oracle.parse_phase(encode(rows,marker),'B',N,runner,prior)
        rows,marker=transcript('B');marker['boot_id']=A
        for row in rows:row['boot_id']=A
        with self.assertRaises(ValueError):oracle.parse_phase(encode(rows,marker),'B',N,runner,prior)
        with self.assertRaises(ValueError):oracle.parse_phase(encode(*transcript('B')),'B',N,runner)

    def test_exact_payload_packaging_and_marker_defaults(self):
        with patch.object(runner,'BASE',ROOT):report=runner.prepare('persist-v25-dry',v25=True)
        path=ROOT/'persist-v25-dry'
        self.assertEqual(report['boots'],[]);self.assertTrue(report['v25_workload'])
        self.assertEqual(offline.sha((path/'v25_two_boot_fixture').read_bytes()),oracle.ELF_SHA256)
        archive=gzip.decompress((path/'initramfs.cpio.gz').read_bytes());offset=0;files={}
        while True:
            self.assertEqual(archive[offset:offset+6],b'070701')
            fields=[int(archive[offset+6+i*8:offset+14+i*8],16) for i in range(13)]
            offset+=110;name=archive[offset:offset+fields[11]-1].decode();offset+=fields[11];offset=(offset+3)&~3
            data=archive[offset:offset+fields[6]];offset+=fields[6];offset=(offset+3)&~3
            if name=='TRAILER!!!':break
            files[name]=(fields,data)
        fields,payload=files['bin/v25_two_boot_fixture']
        self.assertEqual(offline.sha(payload),oracle.ELF_SHA256);self.assertEqual(fields[1]&0o7777,0o700);self.assertEqual(fields[2:4],[0,0])
        self.assertEqual(files['etc/v25-workload'][1],b'v25-fixture/1')
        self.assertEqual((path/'fixture.raw').stat().st_size,32*1024*1024)
        with self.assertRaises(ValueError):runner.prepare('persist-v25-invalid',negative='partial-writing',v25=True)
        with patch.object(runner,'V25_ELF',Path('/not-present')):
            with self.assertRaises(OSError):runner.prepare('persist-v25-no-elf',v25=True)

    def test_fake_v25_two_boot_status_and_prior(self):
        calls=[]
        def boot(inputs,output,phase,nonce,qhash,latch,prior,v25=False):
            self.assertTrue(v25);calls.append((phase,os.fstat(output.pins[output.out/'fixture.raw']).st_ino,prior))
            payload=oracle.parse_phase(encode(*transcript(phase,nonce)),phase,nonce,runner,prior)
            return {'status':'DISPOSABLE_V25_PHASE_OBSERVED_NO_PRODUCTION_ADMISSION','event':payload['marker'],'v25':payload,
                    'exact_child_reaped':True,'pidfd_exit_verified':True,'exit_code':-9 if phase=='A' else 0}
        with patch.object(runner,'BASE',ROOT),patch.object(runner,'run_boot',side_effect=boot):report=runner.prepare('persist-v25-fake',True,QHASH,v25=True)
        self.assertEqual(report['status'],runner.V25_SUCCESS);self.assertEqual([item[0] for item in calls],['A','B']);self.assertEqual(calls[0][1],calls[1][1])

    def test_ack_capture_validates_before_exact_kill_and_refuses_foreign(self):
        for valid in (True,False):
            path=ROOT/('capture-ok' if valid else 'capture-foreign')
            with offline.TrustedOutput(ROOT) as output:
                output.create_dir(path.name)
                for name in ('serial.raw','qemu.stderr'):output.write(name,b'')
                rows,marker=transcript('A')
                if not valid:rows[-1]['details']['manifest_sha256']='foreign'
                streams=[]
                for data in (encode(rows,marker),b''):
                    rd,wr=os.pipe();os.write(wr,data);os.close(wr);streams.append(os.fdopen(rd,'rb'))
                child=type('Child',(),{'stdout':streams[0],'stderr':streams[1]})()
                try:
                    with patch.object(runner.signal,'pidfd_send_signal') as kill,patch.object(closed,'reap_exact',return_value=-signal.SIGKILL),patch.object(closed,'capture'):
                        if valid:
                            runner.capture_v25_a(child,77,output.pins[path/'serial.raw'],output.pins[path/'qemu.stderr'],output,closed.SignalLatch(),N)
                            kill.assert_called_once_with(77,signal.SIGKILL)
                        else:
                            with self.assertRaises(ValueError):runner.capture_v25_a(child,77,output.pins[path/'serial.raw'],output.pins[path/'qemu.stderr'],output,closed.SignalLatch(),N)
                            kill.assert_not_called()
                finally:
                    for stream in streams:stream.close()

    def test_failed_a_or_kill_reporting_error_keeps_disk_and_blocks_b(self):
        failed={'status':'FAILED_OR_LIFECYCLE_UNVERIFIED','exact_child_reaped':True,'pidfd_exit_verified':True}
        with patch.object(runner,'BASE',ROOT),patch.object(runner,'run_boot',return_value=failed) as boot:
            report=runner.prepare('persist-v25-fail-a',True,QHASH,v25=True)
        self.assertEqual(boot.call_count,1);self.assertEqual(report['status'],'FAILED_NO_ADMISSION')
        self.assertTrue((ROOT/'persist-v25-fail-a'/'fixture.raw').exists())
        with patch.object(runner,'BASE',ROOT):runner.prepare('persist-v25-kill-error',v25=True)
        path=ROOT/'persist-v25-kill-error'
        with offline.TrustedOutput(runner.INPUT) as inputs,offline.TrustedOutput(path) as output:
            output.out=path
            for file in ('vmlinuz','initramfs.cpio.gz','fixture.raw'):closed.attach(output,file)
            child=type('Child',(),{'pid':424244,'stdout':io.BytesIO(),'stderr':io.BytesIO()})()
            with patch.object(runner.subprocess,'Popen',return_value=child),patch.object(os,'pidfd_open',side_effect=lambda *_:os.dup(output.pins[path])), \
                 patch.object(closed,'process_birth',return_value=100),patch.object(runner,'capture_v25_a',side_effect=OSError('injected kill/report failure')), \
                 patch.object(closed,'reap_exact',return_value=-signal.SIGKILL) as reap:
                result=runner.run_boot(inputs,output,'A',N,QHASH,closed.SignalLatch(),v25=True)
            self.assertEqual(result['status'],'FAILED_OR_LIFECYCLE_UNVERIFIED');self.assertTrue(result['exact_child_reaped'])
            self.assertTrue(reap.call_args.kwargs['kill']);self.assertTrue((path/'fixture.raw').exists())

if __name__=='__main__':
    print('retained v25 offline root: '+str(ROOT),flush=True)
    unittest.main(verbosity=2)
