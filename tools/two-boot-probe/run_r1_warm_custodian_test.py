#!/usr/bin/env python3
"""Offline C/protocol/parser/fake-child controls; never launches QEMU or boots."""
from contextlib import ExitStack
import copy
import io
import json
import os
import secrets
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
import offline
import run_closed_vm as closed
import run_r1_warm_custodian as runner

PINS={'nonce':'a'*32,'fixture_uuid':'12345678-1234-1234-1234-123456789abc','lineage':'b'*32,
      'policy_sha256':'1'*64,'pid1_sha256':'2'*64,'probe_sha256':'3'*64,'db_sha256':'4'*64,'db_bytes':8192}
BOOT='aaaaaaaa-1111-1111-1111-111111111111'


def events():
    source=children=lost=dead=False;fd=-1;protocol=0;rows=[]
    actors={'pid1':(1,10),'custodian':(3,30),'broker':(4,40),'before_custodian':(2,20),
            'custodian_alive':(5,50),'after_custodian_loss':(6,60),'after_broker_death':(7,70)}
    advances={'broker_clean_exec_sealed':1,'broker_source_opened':2,'broker_fd_before_loss':3,
              'broker_same_fd_after_loss':4,'broker_seal_persists':5,'broker_fd_still_held':6}
    for sequence,(name,rc,role) in enumerate(runner.expected_sequence(),1):
        source |= name=='source24_verified';children |= name=='custodian_lock_held'
        lost |= name=='custodian_killed_reaped';dead |= name=='broker_killed_reaped'
        if name=='broker_source_opened':fd=3
        protocol=advances.get(name,protocol);pid,birth=actors[role]
        rows.append({'schema':1,'event':name,'sequence':sequence,'nonce':PINS['nonce'],'fixture_uuid':PINS['fixture_uuid'],
          'boot_id':BOOT,'gate':'CLOSED','admission':'UNIMPLEMENTED','warm_adoption':'UNAVAILABLE','origin_restored':False,
          'source_pinned':source,'source_device':9 if source else 0,'source_inode':12 if source else 0,'source_uid':1000 if source else 0,
          'source_bytes':PINS['db_bytes'] if source else 0,'source_sha256':PINS['db_sha256'] if source else '',
          'expected_source_sha256':PINS['db_sha256'],'lineage':PINS['lineage'],'policy_sha256':PINS['policy_sha256'],
          'pid1_sha256':PINS['pid1_sha256'],'probe_sha256':PINS['probe_sha256'],'lock_inode':13 if source else 0,
          'custodian_pid':3 if children else 0,'custodian_birth':30 if children else 0,'custodian_state':'LOST' if lost else 'LIVE' if children else 'NOT_STARTED',
          'broker_pid':4 if children else 0,'broker_birth':40 if children else 0,'broker_state':'DEAD' if dead else 'LIVE' if children else 'NOT_STARTED',
          'broker_fd':fd,'broker_sequence':protocol,'actor_pid':pid,'actor_birth':birth,
          'actor_parent':0 if role=='pid1' else 3 if role=='broker' and not lost else 1,
          'rc':rc,'errno':runner.errno.EOWNERDEAD if name=='replacement_custodian_refused' else 1 if name.endswith('_unshare') else 13 if name.startswith('outside_') and name!='outside_reaped' else 0})
    return rows


def serial(rows=None):
    return b'[ 0.1] kernel boot\n'+b''.join((json.dumps(e)+'\n').encode() for e in (events() if rows is None else rows))+b'[ 9.9] reboot: Power down\n'


def fixture():
    out=offline.TrustedOutput(runner.BASE,create=True);out.create_dir('test-'+secrets.token_hex(8));return out


def compile_program(out,name,code):
    offline.trusted_tool(runner.origin.GCC);offline.read_pinned(runner.origin.GCC,runner.origin.GCC_SHA256)
    for source in runner.SOURCE_NAMES:
        if out.out/source not in out.pins:out.write(source,(runner.SOURCE/source).read_bytes())
    out.write(name+'.c',code.encode());binary=out.out/(name+'.bin')
    result=subprocess.run([str(runner.origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',str(out.out/(name+'.c')),'-o',str(binary)],capture_output=True,timeout=60)
    out.write(name+'.compiler.log',result.stdout+result.stderr)
    if result.returncode:raise AssertionError(result.stderr.decode())
    offline.static_elf(binary.read_bytes());os.chmod(binary,0o700);return binary


class OracleTests(unittest.TestCase):
    def test_exact_warm_loss_sequence_same_kernel_and_same_issued_fd(self):
        result=runner.parse_events(serial(),PINS)
        self.assertEqual(len(result['events']),52);self.assertEqual(result['boot_id'],BOOT)
        self.assertEqual(result['custodian'],[3,30]);self.assertEqual(result['broker'],[4,40])
        self.assertEqual([e['actor_parent'] for e in result['events'] if e['event'] in ('broker_fd_before_loss','broker_same_fd_after_loss')],[3,1])

    def test_wrong_subject_replay_release_or_adoption_never_passes(self):
        edits=[('closed_before_source','source_pinned',True),('closed_before_source','gate','PRE_CLOSURE'),
          ('closed_before_source','schema',True),('source24_verified','source_inode',99),('source24_verified','lock_inode',12),
          ('custodian_lock_held','custodian_pid',1),('custodian_lock_held','custodian_birth',0),('broker_fd_before_loss','actor_parent',1),
          ('broker_same_fd_after_loss','actor_parent',3),('broker_same_fd_after_loss','actor_birth',41),
          ('broker_same_fd_after_loss','boot_id','bbbbbbbb-2222-2222-2222-222222222222'),('broker_same_fd_after_loss','broker_fd',4),
          ('broker_same_fd_after_loss','broker_sequence',3),('broker_same_fd_after_loss','custodian_state','LIVE'),
          ('broker_same_fd_after_loss','broker_state','DEAD'),('replacement_custodian_refused','errno',0),
          ('replacement_custodian_refused','warm_adoption','ADOPTED'),('broker_seal_persists','origin_restored',True),
          ('outside_after_custodian_loss_source','errno',2),('outside_after_custodian_loss_unshare','errno',13),
          ('source_preserved_no_children','nonce','f'*32),('warm_loss_closed_no_admission','admission','READY')]
        for name,key,value in edits:
            rows=copy.deepcopy(events());next(e for e in rows if e['event']==name)[key]=value
            with self.subTest(name=name,key=key),self.assertRaises(ValueError):runner.parse_events(serial(rows),PINS)
        rows=events();rows[26],rows[27]=rows[27],rows[26]
        with self.assertRaises(ValueError):runner.parse_events(serial(rows),PINS)
        rows=events();rows[5]['actor_pid']=1;rows[5]['actor_birth']=10
        with self.assertRaises(ValueError):runner.parse_events(serial(rows),PINS)

    def test_closed_framing_rejects_truncation_duplicate_interleaving_and_fatal_noise(self):
        for raw in (serial()[:-1],serial()+b'garbage\n',serial()+b'{}\n',serial()+b'\0\n',serial()+b'\xff\n',
                    b'x'*(closed.MAX_SERIAL+1),serial().replace(b'"schema": 1',b'"schema":1,"schema":1',1),
                    serial().replace(b'UNIMPLEMENTED',b'UNIM[ 2.9] tsc: calibration\nPLEMENTED',1),
                    serial().replace(b'kernel boot',b'Kernel panic'),serial().replace(b'[ 0.1] kernel boot',b'[]'),
                    serial(events()[:-1])):
            with self.assertRaises((ValueError,UnicodeError)):runner.parse_events(raw,PINS)

    def test_fixed_qemu_and_unreviewed_run_refusal(self):
        args=runner.qemu_argv('kernel','initrd','/proc/self/fd/9')
        for flag in ('-nic','-monitor','-display'):self.assertEqual(args[args.index(flag)+1],'none')
        self.assertEqual(args[args.index('-append')+1].split().count('loglevel=4'),1)
        self.assertEqual(args[args.index('-append')+1].split().count('r1.warm=1'),1)
        for value in ('-enable-kvm','-virtfs','-fsdev','-netdev','-daemonize','-snapshot','-qmp'):self.assertNotIn(value,args)
        with patch.object(runner.subprocess,'Popen') as launch:
            for name in ('old','../warm-a','warm-a/b'):
                with self.assertRaises(ValueError):runner.prepare(name)
            with self.assertRaises(ValueError):runner.prepare('warm-no-review',True,None)
            launch.assert_not_called()

    def test_actual_c_protocol_and_phase_parser_reject_replay_and_wrong_parent(self):
        code=r'''#include "r1_warm_shared.h"
#include <assert.h>
int main(void){
 if(getuid()==0)return 3;
 char line[256];const char *valid[]={"r1.warm=1","console=ttyS0 r1.warm=1\n","\tr1.warm=1\r\n"};
 for(unsigned i=0;i<3;i++){strcpy(line,valid[i]);assert(w_cmdline(line));}
 const char *bad[]={"","r1.warm=0\n","r1.warm=11\n","r1.warm=1 r1.warm=1\n"};
 for(unsigned i=0;i<4;i++){strcpy(line,bad[i]);assert(!w_cmdline(line));}
 assert(w_can_launch(0,0));assert(!w_can_launch(1,0));assert(!w_can_launch(0,1));assert(!w_can_launch(1,1));
 struct w_context x={.magic=W_MAGIC,.self_pid=4,.parent_pid=3,.self_birth=40,.device=9,.inode=12};
 memset(x.nonce,'a',32);strcpy(x.boot,"aaaaaaaa-1111-1111-1111-111111111111");
 struct w_command c={.magic=W_MAGIC,.sequence=3,.kind=W_HOLD_AFTER,.target_pid=4};memcpy(c.nonce,x.nonce,33);memcpy(c.boot,x.boot,37);
 assert(w_command_matches(&c,&x,3,W_HOLD_AFTER));assert(!w_command_matches(&c,&x,2,W_HOLD_AFTER));
 c.target_pid=5;assert(!w_command_matches(&c,&x,3,W_HOLD_AFTER));c.target_pid=4;c.boot[0]='b';assert(!w_command_matches(&c,&x,3,W_HOLD_AFTER));
 struct w_message m={.magic=W_MAGIC,.sequence=4,.phase=W_AFTER,.flags=15,.pid=4,.parent_pid=1,.birth=40,.device=9,.inode=12};
 memcpy(m.nonce,x.nonce,33);memcpy(m.boot,x.boot,37);assert(w_message_matches(&m,&x,4,W_AFTER,15,1));
 assert(!w_message_matches(&m,&x,3,W_AFTER,15,1));assert(!w_message_matches(&m,&x,4,W_AFTER,15,3));
 m.birth++;assert(!w_message_matches(&m,&x,4,W_AFTER,15,1));m.birth--;m.inode++;assert(!w_message_matches(&m,&x,4,W_AFTER,15,1));
 m.inode--;m.nonce[0]='f';assert(!w_message_matches(&m,&x,4,W_AFTER,15,1));return 0;
}
'''
        with fixture() as out:
            binary=compile_program(out,'protocol-test',code);result=subprocess.run([str(binary)],capture_output=True,timeout=5);os.chmod(binary,0o600)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_actual_pid1_no_io_warm_refusal_and_bounded_event_lines(self):
        code=r'''#define main guest_entry_not_called
#include "init.r1_warm.c"
#undef main
#include <assert.h>
static void fill_text(char *p,size_t n,char value){memset(p,value,n);p[n]=0;}
int main(void){
 if(getuid()==0)return 3;
 /* Actual launcher, before any bootstrap or filesystem/process operation. */
 custodian_started=1;custodian_lost=1;errno=0;assert(begin_custodian()==-1&&errno==EOWNERDEAD);
 custodian_started=0;errno=0;assert(begin_custodian()==-1&&errno==EOWNERDEAD);
 custodian_lost=0;errno=0;assert(begin_custodian()==-1&&errno==EPERM);
 event("pre_closure_control",1,0,0,-1,EINVAL);
 fill_text(config.nonce,32,'a');fill_text(config.lineage,32,'b');fill_text(config.source_hash,64,'c');
 fill_text(config.policy_hash,64,'d');fill_text(config.init_hash,64,'e');fill_text(config.probe_hash,64,'f');
 strcpy(config.fixture,"12345678-1234-1234-1234-123456789abc");strcpy(current_boot,"aaaaaaaa-1111-1111-1111-111111111111");
 custodian.pid=INT_MAX;custodian.birth=UINT64_MAX;custodian_lost=1;broker.pid=INT_MAX-1;broker.birth=UINT64_MAX;
 source_stat.st_dev=UINT64_MAX;source_stat.st_ino=UINT64_MAX;source_stat.st_size=ORIGIN_FILE_CAP;source_stat.st_uid=1000;lock_stat.st_ino=UINT64_MAX;
 source_pinned=closed_established=1;broker_data_fd=3;broker_sequence=6;
 char name[96];fill_text(name,95,'x');event(name,INT_MAX-1,UINT64_MAX,1,INT_MIN,INT_MAX);return 0;
}
'''
        with fixture() as out:
            binary=compile_program(out,'event-test',code);result=subprocess.run([str(binary)],capture_output=True,timeout=5);os.chmod(binary,0o600)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,b'')
            lines=result.stdout.splitlines(keepends=True);self.assertEqual(len(lines),2)
            values=[json.loads(line) for line in lines]
            for line,value in zip(lines,values):
                self.assertLess(len(line),2048);self.assertEqual(set(value),runner.KEYS)
                encoded=(json.dumps(value,separators=(',',':'))+'\n').encode();self.assertEqual(len(line),len(encoded));self.assertEqual(line,encoded)
            self.assertEqual(values[0]['gate'],'PRE_CLOSURE');self.assertEqual(values[1]['gate'],'CLOSED')
            self.assertEqual(values[1]['custodian_state'],'LOST');self.assertEqual(values[1]['warm_adoption'],'UNAVAILABLE')

    def test_static_guest_binary_selftest_and_normal_entry_guards(self):
        with fixture() as out:
            for source in ('init.r1_warm.c','r1_warm_probe.c'):
                # The source contains the real guarded entry, not a fake guest.
                binary=compile_program(out,'entry-'+str(len(out.pins)),(runner.SOURCE/source).read_text())
                result=subprocess.run([str(binary),'--self-test'],capture_output=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(subprocess.run([str(binary)],capture_output=True,timeout=5).returncode,3);os.chmod(binary,0o600)


class FakeChild:
    pid=424242
    def __init__(self):self.stdout=io.BytesIO();self.stderr=io.BytesIO();self.returncode=None;self.killed=False;self.waited=False
    def poll(self):return self.returncode
    def wait(self,timeout):self.waited=True;self.returncode=-9 if self.killed else (self.returncode or 0);return self.returncode
    def kill(self):self.killed=True


class LifecycleTests(unittest.TestCase):
    def exercise(self,failure=None):
        with fixture() as out:
            for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw'):out.write(n,b'private fake fixture')
            child=FakeChild();report=dict(PINS,evidence_kind='OFFLINE_FAKE_CHILD_TEST')
            def capture(c,pidfd,serialfd,stderrfd,output,latch):
                closed.write_all(serialfd,b'first malformed raw\n' if failure=='parser' else serial())
                if failure=='timeout':raise TimeoutError('offline timeout')
                if failure=='signal':latch.handle(signal.SIGTERM,None);latch.check()
                if failure=='nonzero':child.returncode=7
            def pidfd(pid,flags):
                self.assertEqual(pid,child.pid)
                if failure=='pidfd':raise OSError('offline pidfd error')
                return os.dup(out.pins[out.out])
            def kill(fd,sig):self.assertEqual(sig,signal.SIGKILL);child.killed=True
            with ExitStack() as stack:
                launched=stack.enter_context(patch.object(runner.subprocess,'Popen',return_value=child))
                stack.enter_context(patch.object(offline,'trusted_tool'));stack.enter_context(patch.object(offline,'read_pinned'))
                stack.enter_context(patch.object(runner.os,'pidfd_open',side_effect=pidfd))
                stack.enter_context(patch.object(closed,'process_birth',return_value=99));stack.enter_context(patch.object(closed,'capture',side_effect=capture))
                stack.enter_context(patch.object(closed.signal,'pidfd_send_signal',side_effect=kill))
                poll=stack.enter_context(patch.object(closed.select,'poll'));poll.return_value.poll.return_value=[(1,1)]
                if failure=='reap':stack.enter_context(patch.object(closed,'reap_exact',side_effect=OSError('offline reap failure')))
                if failure=='receipt':stack.enter_context(patch.object(closed,'durable_receipt',side_effect=OSError('offline receipt failure')))
                with closed.SignalLatch() as latch:
                    if failure=='receipt':
                        with self.assertRaises(closed.LifecycleReceiptError) as caught:runner.run_guest(out,report,'0'*64,latch)
                        self.assertIs(caught.exception.report,report)
                    else:runner.run_guest(out,report,'0'*64,latch)
                self.assertEqual(launched.call_count,1)
            self.assertTrue(report['boot_executed']);self.assertEqual(report['pid'],child.pid)
            self.assertEqual(out.read('fixture.raw'),b'private fake fixture')
            if failure=='reap':
                self.assertFalse(report['exact_child_reaped']);self.assertNotIn('post_reap_disk_sha256',report)
            else:self.assertTrue(report['exact_child_reaped']);self.assertTrue(child.waited)
            if failure=='pidfd':self.assertFalse(report['pidfd_exit_verified'])
            if failure=='parser':self.assertEqual(out.read('serial.raw'),b'first malformed raw\n')
            if failure not in (None,'receipt'):self.assertEqual(report['status'],'FAILED_NO_ADMISSION')
            if failure is None:
                self.assertEqual(report['status'],runner.SUCCESS);self.assertEqual(report['event_count'],52)
                self.assertEqual(out.read('serial.raw'),serial());self.assertTrue(report['pidfd_exit_verified'])

    def test_fake_success_is_explicitly_marked_and_reaped(self):self.exercise()
    def test_failure_teardown_retains_first_raw_and_never_retries(self):
        for failure in ('timeout','pidfd','signal','parser','nonzero','reap','receipt'):
            with self.subTest(failure=failure):self.exercise(failure)


if __name__=='__main__':
    if os.getuid()==0 or os.geteuid()==0:raise SystemExit('ordinary UID only')
    unittest.main(verbosity=2)
