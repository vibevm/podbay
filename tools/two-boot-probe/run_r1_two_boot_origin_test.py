#!/usr/bin/env python3
"""Offline compiler/codec/oracle/fake-child tests. Never launches a VM."""
from contextlib import ExitStack
import copy
import io
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import run_r1_two_boot_origin as runner

PINS={'nonce':'a'*32,'fixture_uuid':'12345678-1234-1234-1234-123456789abc','lineage':'b'*32,
      'policy_sha256':'1'*64,'pid1_sha256':'2'*64,'probe_sha256':'3'*64,'db_sha256':'4'*64,'db_bytes':8192}
BOOTS={'A':'aaaaaaaa-1111-1111-1111-111111111111','B':'bbbbbbbb-2222-2222-2222-222222222222'}


def events(phase):
    known=checkpoint=False;result=[]
    actors={'pid1':(1,10 if phase=='A' else 20),'broker':(2,30) if phase=='A' else (3,40),
            'broker_alive':(3,31) if phase=='A' else (4,41),'before_broker':(2,39),'after_broker_death':(5,42)}
    for index,(name,rc,role) in enumerate(runner.expected_sequence(phase),1):
        known |= name=='source24_verified'
        checkpoint |= name in ('checkpoint_durable','historical_checkpoint_verified_no_authority')
        pid,birth=actors[role]
        result.append({'schema':1,'event':name,'phase':phase,'sequence':index,'nonce':PINS['nonce'],
          'fixture_uuid':PINS['fixture_uuid'],'boot_id':BOOTS[phase],'boot_a':BOOTS['A'] if checkpoint else '',
          'gate':'CLOSED','admission':'UNIMPLEMENTED','origin_restored':False,'source_pinned':known,
          'source_device':9 if known else 0,'source_inode':12 if known else 0,'source_uid':1000 if known else 0,
          'source_bytes':PINS['db_bytes'] if known else 0,'expected_source_sha256':PINS['db_sha256'],
          'source_sha256':PINS['db_sha256'] if known else '', 'lineage':PINS['lineage'],
          'policy_sha256':PINS['policy_sha256'],'pid1_sha256':PINS['pid1_sha256'],'probe_sha256':PINS['probe_sha256'],
          'checkpoint_sha256':'c'*64 if checkpoint else '', 'checkpoint_inode':50 if checkpoint else 0,
          'old_broker_pid':2 if checkpoint else 0,'old_broker_birth':30 if checkpoint else 0,
          'actor_pid':pid,'actor_birth':birth,'rc':rc,
          'errno':1 if name.endswith('_unshare') else 13 if name.startswith('outside_') and name!='outside_reaped' else 0})
    return result


def serial(phase, rows=None):
    return b'[ 0.1] kernel boot\n'+b''.join((json.dumps(e)+'\n').encode() for e in (events(phase) if rows is None else rows))+(b'[ 8.1] reboot: Power down\n' if phase=='B' else b'')


def output_fixture():
    output=offline.TrustedOutput(runner.BASE,create=True);output.create_dir('test-'+secrets.token_hex(8));return output


class OracleTests(unittest.TestCase):
    def test_exact_a_crash_prefix_and_fresh_b_recovery(self):
        first=runner.parse_phase(serial('A'),'A',PINS)
        second=runner.parse_phase(serial('B'),'B',PINS,first)
        self.assertNotEqual(first['boot_id'],second['boot_id'])
        self.assertEqual(first['source'],second['source'])
        self.assertEqual(first['checkpoint'],second['checkpoint'])
        for n in range(len(events('A'))):
            self.assertIsNone(runner.parse_phase(serial('A',events('A')[:n]),'A',PINS,prefix=True))

    def test_wrong_order_source_before_closed_and_historical_replay_refuse(self):
        prior=runner.parse_phase(serial('A'),'A',PINS)
        for change in ('source_early','reused_boot','nonce','checkpoint','inode','actor','restored','missing','extra','boolean','preclosure','partial_record'):
            rows=copy.deepcopy(events('B'))
            if change=='source_early':rows[0]['source_pinned']=True
            elif change=='reused_boot':
                for e in rows:e['boot_id']=BOOTS['A']
            elif change=='nonce':rows[2]['nonce']='d'*32
            elif change=='checkpoint':rows[2]['checkpoint_sha256']='d'*64
            elif change=='inode':rows[5]['source_inode']+=1
            elif change=='actor':rows[-1]['actor_birth']+=1
            elif change=='restored':rows[2]['origin_restored']=True
            elif change=='missing':rows.pop()
            elif change=='extra':rows.append(rows[-1])
            elif change=='boolean':rows[0]['schema']=True
            elif change=='preclosure':rows[0]['gate']='PRE_CLOSURE'
            else:rows[2]['event']='refused_partial_checkpoint'
            with self.subTest(change=change),self.assertRaises(ValueError):runner.parse_phase(serial('B',rows),'B',PINS,prior)
        with self.assertRaises(ValueError):runner.parse_phase(serial('A')+b'[ 5.2] reboot: Power down\n','A',PINS)

    def test_closed_serial_rejects_partial_trailing_overflow_and_duplicate(self):
        for raw in (serial('A')[:-1],serial('A')+b'garbage\n',serial('A').replace(b'"schema": 1',b'"schema":1,"schema":1',1),
                    serial('A')+b'\0\n',b'x'*(closed.MAX_SERIAL+1),serial('A').replace(b'kernel boot',b'Kernel panic')):
            with self.assertRaises(ValueError):runner.parse_phase(raw,'A',PINS)

    def test_qemu_only_changes_explicit_a_b_mode_on_same_disk(self):
        a=runner.argv('kernel','initrd','/proc/self/fd/9','A');b=runner.argv('kernel','initrd','/proc/self/fd/9','B')
        self.assertEqual(a[a.index('-drive')+1],b[b.index('-drive')+1])
        self.assertIn('r1.phase=A',a[a.index('-append')+1]);self.assertIn('r1.phase=B',b[b.index('-append')+1])
        for args in (a,b):self.assertEqual(args[args.index('-append')+1].split().count('loglevel=4'),1)
        for forbidden in ('-enable-kvm','-virtfs','-fsdev','-netdev','-daemonize','-snapshot','-qmp'):
            self.assertNotIn(forbidden,a)
        for flag in ('-nic','-monitor','-display'):self.assertEqual(a[a.index(flag)+1],'none')

    def test_actual_pid1_event_emits_bounded_complete_json_lines(self):
        with output_fixture() as out:
            offline.trusted_tool(runner.origin.GCC);offline.read_pinned(runner.origin.GCC,runner.origin.GCC_SHA256)
            for name in runner.SOURCE_NAMES:out.write(name,(runner.SOURCE/name).read_bytes())
            # Invoke only the actual formatter/output function as an ordinary
            # UID. The guest entry is renamed and never called; no bootstrap,
            # mount, child, sync or reboot path is executed by this control.
            code=r'''#define main guest_pid1_entry_not_called
#include "init.r1_two_boot.c"
#undef main
static void fill_text(char *p,size_t n,char value){memset(p,value,n);p[n]=0;}
int main(void){
 if(getuid()==0)return 3;
 event("pre_closure_control",1,0,-1,EINVAL);
 fill_text(config.nonce,32,'a');fill_text(config.lineage,32,'b');fill_text(config.source_hash,64,'c');
 fill_text(config.policy_hash,64,'d');fill_text(config.init_hash,64,'e');fill_text(config.probe_hash,64,'f');
 strcpy(config.fixture,"12345678-1234-1234-1234-123456789abc");strcpy(current_boot,"aaaaaaaa-1111-1111-1111-111111111111");
 strcpy(saved.boot_a,current_boot);fill_text(checkpoint_hash,64,'a');
 saved.broker_pid=INT_MAX;saved.broker_birth=UINT64_MAX;checkpoint_stat.st_ino=UINT64_MAX;
 source_stat.st_dev=UINT64_MAX;source_stat.st_ino=UINT64_MAX;source_stat.st_size=ORIGIN_FILE_CAP;source_stat.st_uid=1000;
 boot_phase='A';source_pinned=1;closure_established=1;
 char name[96];fill_text(name,95,'x');event(name,INT_MAX,UINT64_MAX,INT_MIN,INT_MAX);
 return 0;
}
'''
            out.write('event_test.c',code.encode());binary=out.out/'event-test.bin'
            result=subprocess.run([str(runner.origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',str(out.out/'event_test.c'),'-o',str(binary)],capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode());os.chmod(binary,0o700)
            result=subprocess.run([str(binary)],capture_output=True,timeout=5);os.chmod(binary,0o600)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,b'')
            lines=result.stdout.splitlines(keepends=True);self.assertEqual(len(lines),2)
            for line in lines:self.assertTrue(line.endswith(b'\n'));self.assertLess(len(line),2048);self.assertNotIn(b'\0',line)
            first,second=(json.loads(line) for line in lines)
            for line,value in zip(lines,(first,second)):
                encoded=(json.dumps(value,separators=(',',':'))+'\n').encode()
                self.assertEqual(len(line),len(encoded));self.assertEqual(line,encoded)
            self.assertEqual(set(first),runner.KEYS);self.assertEqual(set(second),runner.KEYS)
            self.assertEqual(first['gate'],'PRE_CLOSURE');self.assertEqual(second['gate'],'CLOSED')
            self.assertEqual(first['sequence'],1);self.assertEqual(second['sequence'],2)
            self.assertEqual(second['event'],'x'*95);self.assertEqual(second['actor_birth'],2**64-1)

    def test_c_codec_compilation_partial_foreign_and_nonroot_guards(self):
        with output_fixture() as out:
            offline.trusted_tool(runner.origin.GCC);offline.read_pinned(runner.origin.GCC,runner.origin.GCC_SHA256)
            for name in runner.SOURCE_NAMES:out.write(name,(runner.SOURCE/name).read_bytes())
            code=r'''#include "r1_two_boot_checkpoint.h"
#include <assert.h>
static void filled(char *p,size_t n,char value){memset(p,value,n);p[n]=0;}
int main(void){
 if(getuid()==0)return 3;
 assert(!strcmp(r1_gate_label(0),"PRE_CLOSURE"));assert(!strcmp(r1_gate_label(1),"CLOSED"));
 /* Real /proc/cmdline has a final newline; exercise the actual PID1 helper. */
 char command[256];
 const char *valid[]={"r1.phase=A","console=ttyS0 rdinit=/init r1.phase=A\n","r1.phase=A console=ttyS0\n","\tr1.phase=A\r\n"};
 for(unsigned i=0;i<sizeof(valid)/sizeof(valid[0]);i++){strcpy(command,valid[i]);assert(r1_command_phase(command)=='A');}
 strcpy(command,"console=ttyS0 r1.phase=B\n");assert(r1_command_phase(command)=='B');
 const char *invalid[]={"","console=ttyS0\n","r1.phase=","r1.phase=AA\n","r1.phase=C\n","r1.phase=A r1.phase=A\n","r1.phase=A r1.phase=B\n"};
 for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++){strcpy(command,invalid[i]);assert(!r1_command_phase(command));}
 struct r1_checkpoint r={.device=1,.root_inode=2,.vault_inode=3,.state_inode=4,.source_inode=5,.lock_inode=6,
   .source_bytes=8192,.custodian_birth=2,.broker_pid=7,.broker_birth=8,.broker_fd=3},decoded;
 filled(r.nonce,32,'a');filled(r.lineage,32,'b');filled(r.source_hash,64,'c');filled(r.policy_hash,64,'d');filled(r.init_hash,64,'e');filled(r.probe_hash,64,'f');
 strcpy(r.fixture,"12345678-1234-1234-1234-123456789abc");strcpy(r.boot_a,"aaaaaaaa-1111-1111-1111-111111111111");
 char bytes[R1_RECORD_CAP],bad[R1_RECORD_CAP];size_t n=r1_encode(&r,bytes);assert(n>0);assert(r1_decode(bytes,n,&decoded));
 for(size_t i=0;i<n;i++)assert(!r1_decode(bytes,i,&decoded));
 for(size_t i=0;i<n;i++){memcpy(bad,bytes,n);bad[i]^=1;assert(!r1_decode(bad,n,&decoded));}
 memcpy(bad,bytes,n);bad[n]='\n';assert(!r1_decode(bad,n+1,&decoded));
 assert(r1_same_pins(&r,&r,"bbbbbbbb-2222-2222-2222-222222222222"));assert(!r1_same_pins(&r,&r,r.boot_a));
 struct r1_checkpoint foreign=r;foreign.nonce[0]='f';size_t m=r1_encode(&foreign,bad);assert(m==n&&r1_decode(bad,m,&decoded));
 assert(!r1_same_pins(&decoded,&r,"bbbbbbbb-2222-2222-2222-222222222222"));
 memcpy(bad,bytes,n);char *uid=strstr(bad,"source_uid=1000");assert(uid);uid[14-1]='1';
 struct sha256_state s;char hash[65];sha_init(&s);sha_update(&s,bad,n-72);sha_finish(&s,hash);memcpy(bad+n-72+7,hash,64);
 assert(!r1_decode(bad,n,&decoded));
 struct r1_message msg={.magic=R1_MAGIC,.phase=R1_READY,.flags=7,.pid=7,.device=1,.inode=5};
 strcpy(msg.nonce,r.nonce);strcpy(msg.boot,r.boot_a);
 assert(r1_message_matches(&msg,r.nonce,r.boot_a,7,R1_READY,7,1,5));
 assert(!r1_message_matches(&msg,r.nonce,"bbbbbbbb-2222-2222-2222-222222222222",7,R1_READY,7,1,5));
 assert(!r1_message_matches(&msg,r.nonce,r.boot_a,8,R1_READY,7,1,5));
 msg.nonce[0]='f';assert(!r1_message_matches(&msg,r.nonce,r.boot_a,7,R1_READY,7,1,5));
 r.source_bytes=ORIGIN_FILE_CAP+1;assert(!r1_encode(&r,bad));return 0;}
'''
            out.write('codec_test.c',code.encode())
            for source in ('codec_test.c','init.r1_two_boot.c','r1_two_boot_probe.c'):
                binary=out.out/(source+'.bin')
                result=subprocess.run([str(runner.origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',str(out.out/source),'-o',str(binary)],capture_output=True,timeout=60)
                self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode())
                os.chmod(binary,0o700);offline.static_elf(binary.read_bytes())
                command=[str(binary)] if source=='codec_test.c' else [str(binary),'--self-test']
                result=subprocess.run(command,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode())
                if source!='codec_test.c':self.assertEqual(subprocess.run([str(binary)],timeout=5).returncode,3)
                os.chmod(binary,0o600)


class FakeChild:
    pid=424242
    def __init__(self):self.stdout=io.BytesIO();self.stderr=io.BytesIO();self.returncode=None;self.killed=False;self.waited=False
    def poll(self):return self.returncode
    def wait(self,timeout):self.waited=True;self.returncode=-9 if self.killed else 0;return self.returncode
    def kill(self):self.killed=True


class LifecycleTests(unittest.TestCase):
    def test_actual_crash_capture_refuses_interleaved_kernel_record(self):
        with output_fixture() as out:
            for name in ('serial.raw','qemu.stderr'):out.write(name,b'')
            source=serial('A',events('A')[:4]).replace(b'UNIMPLEMENTED',b'UNIM[ 2.9] tsc: calibration\nPLEMENTED',1)
            readfd,writefd=os.pipe();errfd,errwrite=os.pipe();os.close(errwrite)
            child=FakeChild();child.stdout=os.fdopen(readfd,'rb');child.stderr=os.fdopen(errfd,'rb')
            def feed():
                try:closed.write_all(writefd,source)
                finally:os.close(writefd)
            writer=threading.Thread(target=feed);writer.start()
            with patch.object(runner.signal,'pidfd_send_signal') as kill:
                with self.assertRaises(ValueError):runner.capture_a(child,out.pins[out.out],out,PINS,closed.SignalLatch())
                kill.assert_not_called()
            writer.join(timeout=2);self.assertFalse(writer.is_alive());child.stdout.close();child.stderr.close()
            self.assertEqual(out.read('serial.raw'),source)

    def test_actual_crash_capture_validates_before_exact_kill(self):
        with output_fixture() as out:
            for name in ('serial.raw','qemu.stderr'):out.write(name,b'')
            source=serial('A');readfd,writefd=os.pipe();errfd,errwrite=os.pipe();os.close(errwrite)
            child=FakeChild();child.stdout=os.fdopen(readfd,'rb');child.stderr=os.fdopen(errfd,'rb')
            def feed():
                try:closed.write_all(writefd,source)
                finally:os.close(writefd)
            writer=threading.Thread(target=feed);writer.start()
            checked=[]
            def exact_signal(fd,sig):
                self.assertEqual(sig,signal.SIGKILL)
                # Full retained capture must already have passed the real parser.
                self.assertEqual(runner.parse_phase(out.read('serial.raw'),'A',PINS)['boot_id'],BOOTS['A'])
                checked.append(True);child.killed=True
            with patch.object(runner.signal,'pidfd_send_signal',side_effect=exact_signal),patch.object(closed.select,'poll') as poller:
                poller.return_value.poll.return_value=[(1,1)]
                observed=runner.capture_a(child,out.pins[out.out],out,PINS,closed.SignalLatch())
            writer.join(timeout=2);self.assertFalse(writer.is_alive())
            child.stdout.close();child.stderr.close()
            self.assertEqual(checked,[True]);self.assertTrue(child.waited)
            self.assertEqual(observed['events'][-1]['event'],'crash_ready_live_broker_closed')
            self.assertEqual(out.read('serial.raw'),source)

    def test_pair_never_starts_b_after_bad_or_unreaped_a(self):
        for failure in ('parser','unreaped','receipt'):
            with output_fixture() as out:
                out.write('fixture.raw',b'fixed disposable disk');report=dict(PINS,boots=[],evidence_kind='OFFLINE_FAKE_CHILD_TEST')
                def boot(output,phase,pins,qemu,latch,value,prior):
                    self.assertEqual(phase,'A')
                    value.update(status='FAILED_OR_LIFECYCLE_UNVERIFIED',boot_executed=True,exact_child_reaped=failure!='unreaped',pidfd_exit_verified=failure!='unreaped')
                    if failure=='receipt':raise OSError('offline receipt failure')
                with patch.object(runner,'run_boot',side_effect=boot) as call:
                    result=runner.run_pair(out,report,'0'*64)
                self.assertEqual(call.call_count,1);self.assertEqual(result['status'],'FAILED_NO_ADMISSION')
                self.assertEqual(out.read('fixture.raw'),b'fixed disposable disk')

    def test_pair_reuses_same_image_only_after_verified_a_exit(self):
        with output_fixture() as out:
            out.write('fixture.raw',b'fixed disposable disk');report=dict(PINS,boots=[],evidence_kind='OFFLINE_FAKE_CHILD_TEST')
            seen=[]
            def boot(output,phase,pins,qemu,latch,value,prior):
                fd=output.pins[output.out/'fixture.raw'];seen.append(os.fstat(fd).st_ino)
                if phase=='B':self.assertEqual(prior['boot_id'],BOOTS['A'])
                value.update(status=runner.A_SUCCESS if phase=='A' else runner.B_SUCCESS,boot_executed=True,
                             exact_child_reaped=True,pidfd_exit_verified=True,exit_code=-9 if phase=='A' else 0,
                             observation=runner.parse_phase(serial(phase),phase,PINS,prior))
            with patch.object(runner,'run_boot',side_effect=boot):result=runner.run_pair(out,report,'0'*64)
            self.assertEqual(result['status'],runner.SUCCESS);self.assertEqual(len(seen),2);self.assertEqual(seen[0],seen[1])

    def test_phase_failure_reaps_and_retains_raw_first_failure(self):
        for failure in ('timeout','pidfd','signal','parser','receipt'):
            with output_fixture() as out:
                for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw'):out.write(n,b'fake private artifact')
                child=FakeChild();report={'evidence_kind':'OFFLINE_FAKE_CHILD_TEST'}
                def capture(c,pidfd,serialfd,stderrfd,logs,latch):
                    if failure=='signal':latch.handle(signal.SIGTERM,None);latch.check()
                    if failure=='timeout':raise TimeoutError('offline phase timeout')
                    closed.write_all(serialfd,b'first malformed serial\n' if failure=='parser' else serial('B'))
                def pidfd(pid,flags):
                    if failure=='pidfd':raise OSError('offline pidfd failure')
                    return os.dup(out.pins[out.out])
                def kill(fd,sig):child.killed=True
                with ExitStack() as stack:
                    stack.enter_context(patch.object(runner.subprocess,'Popen',return_value=child))
                    stack.enter_context(patch.object(offline,'trusted_tool'));stack.enter_context(patch.object(offline,'read_pinned'))
                    stack.enter_context(patch.object(runner.os,'pidfd_open',side_effect=pidfd))
                    stack.enter_context(patch.object(closed,'process_birth',return_value=99));stack.enter_context(patch.object(closed,'capture',side_effect=capture))
                    stack.enter_context(patch.object(closed.signal,'pidfd_send_signal',side_effect=kill))
                    poll=stack.enter_context(patch.object(closed.select,'poll'));poll.return_value.poll.return_value=[(1,1)]
                    if failure=='receipt':stack.enter_context(patch.object(closed,'durable_receipt',side_effect=OSError('offline receipt failure')))
                    with closed.SignalLatch() as latch:
                        if failure=='receipt':
                            with self.assertRaises(OSError):runner.run_boot(out,'B',PINS,'0'*64,latch,report,runner.parse_phase(serial('A'),'A',PINS))
                        else:runner.run_boot(out,'B',PINS,'0'*64,latch,report,runner.parse_phase(serial('A'),'A',PINS))
                self.assertTrue(report['boot_executed']);self.assertTrue(report['exact_child_reaped']);self.assertTrue(child.waited)
                self.assertEqual(out.read('fixture.raw'),b'fake private artifact')
                if failure=='parser':self.assertEqual((out.out/'boot-b/serial.raw').read_bytes(),b'first malformed serial\n')


if __name__=='__main__':
    if os.getuid()==0 or os.geteuid()==0:raise SystemExit('ordinary UID only')
    unittest.main(verbosity=2)
