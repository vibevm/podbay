#!/usr/bin/env python3
"""Offline producer fixture checks; no QEMU/root/service invocation."""
import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import unittest
sys.dont_write_bytecode=True
import build_r1_producer_vm as b
import run_r1_producer_vm as runner
import r1_systemd_test as existing

def pins():return {k:'a'*64 for k in ('producer_sha256','systemd_sha256','archive_generation')}
def event():return dict(schema=1,event=b.SUCCESS,boot_id='00000000-0000-0000-0000-000000000001',pid1=1,monitor_pid=30,producer_pid=31,armed_us=100,producer_start_us=101,producer_exit_us=102,window_end_us=103,producer_exit=2,producer_ready=False,issuer_starts=0,source_events=0,lock_events=0,watch_control_passed=True,outside_denials=4,production_origin='UNAVAILABLE',admission='UNAVAILABLE',**pins())
def raw(e=None):return ('R1_PRODUCER_V2 '+json.dumps(e or event())+'\n').encode()

fake_pins=pins
serial=raw
console=existing.console

class Protocol(unittest.TestCase):
    def test_exact_negative_event_is_synthetic_only(self):self.assertEqual(b.parse_events(raw(),pins()),event())
    def test_every_field_mutation_refuses(self):
        for key in event():
            changed=event();changed[key]=None
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):b.parse_events(raw(changed),pins())
    def test_false_arming_ready_access_and_identity_claims_refuse(self):
        for key,value in (('armed_us',102),('producer_ready',True),('source_events',1),('lock_events',1),('watch_control_passed',False),('producer_exit',0),('issuer_starts',1),('producer_pid',30),('window_end_us',100),('admission','READY')):
            changed=event();changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):b.parse_events(raw(changed),pins())
    def test_channel_and_shutdown_failures_refuse(self):
        for data in (raw()+raw(),raw()+b'noise\n',raw()[:-1],b'\x1b[0m'+raw(),raw().replace(b'\n',b'\r\n'),raw().replace(b'"schema": 1',b'"schema":1,"schema":1')):
            with self.assertRaises(ValueError):b.parse_events(data,pins())
        for console in (b'',b'Failed at step EXEC\n'+existing.console(),raw()+existing.console()):
            with self.assertRaises(ValueError):b.native_receipt(raw(),pins(),0,True,True,console=console)
        self.assertEqual(b.native_receipt(raw(),pins(),0,True,True,console=existing.console()),event())
    def test_arming_graph_failures(self):
        b.verify_graph(b.units())
        for path,old,new in ((b.PRODUCER+'.d/90-fixture.conf',b'Requires=',b'Wants='),(b.PRODUCER+'.d/90-fixture.conf',b'After=',b'Before='),(b.ISSUER+'.d/50-producer.conf',b'Requires=',b'Wants='),(b.ISSUER+'.d/50-producer.conf',b'BindsTo=',b'Wants='),(b.PRODUCER,b'Type=notify',b'Type=oneshot'),(b.PRODUCER,b'Restart=no',b'Restart=always')):
            units=b.units();units[path]=units[path].replace(old,new)
            with self.subTest(path=path,new=new),self.assertRaises(ValueError):b.verify_graph(units)
    def test_default_builder_has_no_run_option(self):
        p=subprocess.run([sys.executable,'-B',str(b.HERE/'build_r1_producer_vm.py'),'--run'],capture_output=True)
        self.assertEqual(p.returncode,2)
    def test_watch_mechanics_and_error_controls_ordinary_uid(self):
        if os.getuid()==0 or os.geteuid()==0:self.skipTest('ordinary UID only')
        with b.offline.TrustedOutput(b.BASE,create=True) as output:
            output.create_dir('watch-test-'+str(time.monotonic_ns())[-10:])
            output.write('r1_producer_watch.h',(b.HERE/'r1_producer_watch.h').read_bytes())
            output.write('source',b'fixture');output.write('lock',b'')
            source=r'''#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include "r1_producer_watch.h"
int main(int argc,char **argv){
 if(getuid()==0||geteuid()==0)return 90;
 struct watches fake={.fd=-1,.source=1,.lock=2};uint32_t flags[2]={0,0};
 struct inotify_event e={.wd=-1,.mask=IN_Q_OVERFLOW};
 if(watch_decode(fake,(unsigned char *)&e,sizeof e,flags)!=-1||errno!=EOVERFLOW)return 8;
 e.wd=999;e.mask=IN_OPEN;if(watch_decode(fake,(unsigned char *)&e,sizeof e,flags)!=-1)return 9;
 if(watch_decode(fake,(unsigned char *)&e,1,flags)!=-1)return 10;
 e.wd=fake.source;e.mask=IN_IGNORED;if(watch_decode(fake,(unsigned char *)&e,sizeof e,flags)!=-1)return 11;
 if(argc==2 && !strcmp(argv[1],"parser"))return 0;
 if(argc!=3)return 91;
 struct watches w=watch_start(argv[1],argv[2]);if(w.fd<0){int error=errno;perror("watch_start");return error==ENOSPC?77:1;}
 if(watch_drain(w,flags)||flags[0]||flags[1])return 2;
 int fd=open(argv[1],O_RDONLY|O_CLOEXEC);char x;if(fd<0||read(fd,&x,1)!=1||close(fd))return 3;
 fd=open(argv[2],O_RDONLY|O_CLOEXEC);if(fd<0||close(fd))return 4;
 if(watch_drain(w,flags)||(flags[0]&(IN_OPEN|IN_ACCESS))!=(IN_OPEN|IN_ACCESS)||!(flags[1]&IN_OPEN))return 5;
 flags[0]=flags[1]=0;if(watch_drain(w,flags)||flags[0]||flags[1])return 6;
 fd=open(argv[1],O_RDONLY|O_CLOEXEC);if(fd<0||close(fd)||watch_drain(w,flags)||!(flags[0]&IN_OPEN))return 7;
 if(close(w.fd)||watch_drain(w,flags)!=-1)return 12;
 return 0;
}'''
            output.write('watch.c',source.encode());output.write('watch.bin',b'')
            args=[str(b.origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',str(output.out/'watch.c'),'-o',str(output.out/'watch.bin')]
            r=subprocess.run(args,capture_output=True,timeout=30);fd=output.pins[output.out/'watch.bin'];os.fchmod(fd,0o600);output.check()
            self.assertEqual(r.returncode,0,r.stderr.decode());b.offline.static_elf(output.read('watch.bin'))
            readonly=os.open(output.out/'watch.bin',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);os.close(fd);output.pins[output.out/'watch.bin']=readonly
            try:
                os.fchmod(readonly,0o700)
                parser=subprocess.run([str(output.out/'watch.bin'),'parser'],capture_output=True,timeout=3)
                self.assertEqual(parser.returncode,0,parser.stderr)
                r=subprocess.run([str(output.out/'watch.bin'),str(output.out/'source'),str(output.out/'lock')],capture_output=True,timeout=3)
                os.fchmod(readonly,0o600)
                output.write('native-watch-result.json',(json.dumps({'parser_exit':parser.returncode,'watch_exit':r.returncode,'stderr':r.stderr.decode()})+'\n').encode())
                if r.returncode==77:self.skipTest('host inotify ENOSPC; parser controls passed, guest arming self-test remains mandatory')
                self.assertEqual(r.returncode,0,r.stderr)
            finally:os.fchmod(readonly,0o600);output.check()


def verify_builds(first,second):
    reports=[json.loads((Path(p)/'plan.json').read_bytes()) for p in (first,second)]
    assert reports[0]['artifacts']==reports[1]['artifacts']
    for directory,report in zip((Path(first),Path(second)),reports):
        assert report['status']==b.OFFLINE and report['boot_executed'] is False
        runner.validate_plan(report)
        for name,digest in report['artifacts'].items():assert b.offline.sha((directory/name).read_bytes())==digest
        entries=existing.decode((directory/'initramfs.cpio.gz').read_bytes())
        manifest=json.loads((directory/'archive-manifest.json').read_bytes())
        assert set(entries)=={row['path'] for row in manifest}
        for row in manifest:
            mode,data,_=entries[row['path']];assert mode==row['mode'] and b.offline.sha(data)==row['sha256']
        for name in ('usr/local/libexec/podbay-r1-boot-producer','usr/local/libexec/r1-producer-monitor','usr/lib/systemd/systemd-executor','usr/bin/umount'):
            assert entries[name][0]==stat.S_IFREG|0o755
        assert b.offline.sha(entries['usr/local/libexec/podbay-r1-boot-producer'][1])==report['producer_sha256']
        b.offline.static_elf(entries['usr/local/libexec/r1-producer-monitor'][1]);b.offline.static_elf(entries['init'][1])
        b.base.verify_elf_closure({'/'+n:data for n,(mode,data,_) in entries.items() if stat.S_ISREG(mode)})
        assert 'usr/local/libexec/podbay-r1-linux' not in entries
        units={n.removeprefix('etc/systemd/system/'):data for n,(mode,data,_) in entries.items() if n.startswith('etc/systemd/system/') and stat.S_ISREG(mode)}
        b.verify_graph(units)
        assert (directory/'systemd-verify.log').read_bytes()==b''
        raw=subprocess.run([b.offline.PINS['debugfs'][0],'-R','cat /vault/state/db.sqlite',str(directory/'fixture.raw')],capture_output=True,check=True).stdout
        assert b.offline.sha(raw)==report['source_sha256']
        for path,uid,mode in (('/',0,'0700'),('/vault',0,'0700'),('/vault/state',1000,'0700'),('/vault/state/db.sqlite',1000,'0600'),('/vault/manager.lock',0,'0600')):
            text=subprocess.run([b.offline.PINS['debugfs'][0],'-R','stat '+path,str(directory/'fixture.raw')],capture_output=True,check=True).stdout.decode()
            assert __import__('re').search(r'Mode:\s+'+mode+r'\b',text)
            assert __import__('re').search(r'User:\s+'+str(uid)+r'\s+Group:\s+'+str(uid)+r'\b',text)
        for path,names in {'/':{'.','..','vault'},'/vault':{'.','..','state','manager.lock'},'/vault/state':{'.','..','db.sqlite'}}.items():
            text=subprocess.run([b.offline.PINS['debugfs'][0],'-R','ls -p '+path,str(directory/'fixture.raw')],capture_output=True,check=True).stdout.decode()
            assert {line.split('/')[5] for line in text.splitlines() if line.startswith('/')}==names
    print('Two producer candidates: exact artifact equality, archive/ELF/graph/source readback passed; unbooted.')
if __name__=='__main__':
    if len(sys.argv)==3:verify_builds(*sys.argv[1:])
    else:unittest.main()
