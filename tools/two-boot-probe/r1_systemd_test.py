#!/usr/bin/env python3
"""Offline parser/closure/archive/disk/lifecycle checks; never starts QEMU."""
import copy
import gzip
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
import build_r1_systemd_vm as b


def decode(data):
    data=gzip.decompress(data);offset=0;entries={};prior='';ino=0
    while True:
        if data[offset:offset+6]!=b'070701':raise ValueError('bad newc header')
        f=[int(data[offset+6+i*8:offset+14+i*8],16) for i in range(13)]
        offset+=110;name=data[offset:offset+f[11]]
        if not name.endswith(b'\0') or b'\0' in name[:-1]:raise ValueError('invalid archive name')
        name=name[:-1].decode('ascii');offset+=f[11];offset=(offset+3)//4*4
        body=data[offset:offset+f[6]];offset+=f[6];offset=(offset+3)//4*4
        ino+=1
        if f[0]!=ino or f[2:4]!=[0,0] or f[5]!=b.offline.EPOCH or len(body)!=f[6]:raise ValueError('noncanonical archive identity')
        if name=='TRAILER!!!':
            if any(data[offset:]):raise ValueError('archive suffix')
            break
        if name<=prior or name.startswith('/') or '..' in Path(name).parts:raise ValueError('unsafe/duplicate/unsorted archive path')
        prior=name;entries[name]=(f[1],body,f[9:11])
    return entries


def fake_pins():return {k:'a'*64 for k in ('enforcer_sha256','manifest_sha256','systemd_sha256','archive_generation')}
def fake_event():
    return dict(schema=1,event=b.SUCCESS,boot_id='00000000-0000-0000-0000-000000000001',pid1=1,observer_pid=12,bootstrap_exit=2,custodian_exit=2,issuer_starts=0,outside_denials=4,enforcer_gate='UNESTABLISHED',admission='UNAVAILABLE',**fake_pins())
def serial(e=None):return ('R1_SYSTEMD '+json.dumps(e or fake_event())+'\n').encode()
def console():return b'[ 1.000] reboot: Power down\n'
def synthetic_units():
    # Explicit fake fixture for graph negatives, never assembly input.
    return {b.BOOTSTRAP:('[Unit]\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=sysinit.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=no\nExecStart=/usr/local/libexec/podbay-r1-linux bootstrap --manifest /etc/podbay/r1-install-manifest.json\n').encode(),b.CUSTODIAN:('[Unit]\nDefaultDependencies=no\nRequires='+b.BOOTSTRAP+'\nAfter='+b.BOOTSTRAP+'\n[Service]\nType=notify\nRestart=no\nExecStart=/usr/local/libexec/podbay-r1-linux custodian --manifest /etc/podbay/r1-install-manifest.json\n').encode()}


class PureTests(unittest.TestCase):
    def test_local_runtime_closure(self):
        files=b.runtime_bytes(b.strict_json((b.HERE/'r1_systemd_runtime.json').read_bytes()))
        self.assertIn('/usr/lib/systemd/systemd',b.verify_elf_closure(files))
        del files['/usr/lib/x86_64-linux-gnu/libc.so.6']
        with self.assertRaises(ValueError):b.verify_elf_closure(files)
    def test_malformed_elf(self):
        for data in (b'',b'\x7fELF',b'\x7fELF\x02\x01\x01'+b'\0'*90):
            with self.assertRaises(ValueError):b.elf_info(data)
    def test_required_executor_missing_or_mutated_refuses_build_gate(self):
        pins=b.strict_json((b.HERE/'r1_systemd_runtime.json').read_bytes())
        for value in (None,'0'*64):
            changed=dict(pins)
            if value is None:del changed[b.EXECUTOR]
            else:changed[b.EXECUTOR]=value
            with self.assertRaisesRegex(ValueError,'executor pin'):
                b.runtime_bytes(changed)
        files=b.runtime_bytes(pins)
        for value in (None,files[b.EXECUTOR][:-1]+bytes([files[b.EXECUTOR][-1]^1])):
            changed=dict(files)
            if value is None:del changed[b.EXECUTOR]
            else:changed[b.EXECUTOR]=value
            with self.assertRaisesRegex(ValueError,'executor bytes'):
                b.verify_elf_closure(changed)
    def test_graph(self):b.verify_units(b.fixed_units(synthetic_units()))
    def test_umount_callout_and_exec_failure_veto(self):
        pins=b.strict_json((b.HERE/'r1_systemd_runtime.json').read_bytes())
        for value in (None,'0'*64):
            changed=dict(pins)
            if value is None:del changed[b.UMOUNT]
            else:changed[b.UMOUNT]=value
            with self.assertRaisesRegex(ValueError,'umount pin'):b.runtime_bytes(changed)
        files=b.runtime_bytes(pins)
        for value in (None,files[b.UMOUNT][:-1]+bytes([files[b.UMOUNT][-1]^1])):
            changed=dict(files)
            if value is None:del changed[b.UMOUNT]
            else:changed[b.UMOUNT]=value
            with self.assertRaisesRegex(ValueError,'umount bytes'):b.verify_elf_closure(changed)
        failure=b'[    5.986807] (umount)[95]: fixture.mount: fixture.mount: Failed at step EXEC spawning /usr/bin/umount: No such file or directory\r\n'
        with self.assertRaisesRegex(ValueError,'fatal raw'):b.verify_console(failure+console())
    def test_graph_failures(self):
        changes=[(b.ISSUER,b'Requires=',b'Wants='),(b.ISSUER,b'After=',b'Before='),(b.BOOTSTRAP,b'[Unit]',b'[Unit]\nConditionPathExists=/absent'),(b.CUSTODIAN,b'Restart=no',b'Restart=always'),(b.CUSTODIAN,b'ExecStart=',b'ExecStartPre='),(b.BOOTSTRAP,b'After=local-fs.target',b'After=unreviewed.target')]
        for name,old,new in changes:
            with self.subTest(new=new):
                u=b.fixed_units(synthetic_units());u[name]=u[name].replace(old,new)
                with self.assertRaises(ValueError):b.verify_units(u)
    def test_archive(self):
        data,entries=b.archive({'/etc/test':b'fixture'})
        decoded=decode(data);self.assertEqual(decoded['fixture'][0],stat.S_IFDIR|0o700)
        self.assertEqual(decoded['dev/console'][2],[5,1]);self.assertEqual(decoded['etc/test'][1],b'fixture')
        self.assertEqual(data,b.archive({'/etc/test':b'fixture'})[0])
    def test_serial_positive_is_synthetic_only(self):self.assertEqual(b.parse_events(serial(),fake_pins()),fake_event())
    def test_mutated_every_field(self):
        for key in fake_event():
            e=fake_event();e[key]=None
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):b.parse_events(serial(e),fake_pins())
    def test_forgeries(self):
        for raw in (serial()+b'x\n',serial()[:-1],serial().replace(b'"schema": 1',b'"schema":true'),serial().replace(b'"schema": 1',b'"schema":1,"schema":1'),serial().replace(b'R1_SYSTEMD ',b'x R1_SYSTEMD '),serial().replace(b'\n',b'\0\n',1),serial().replace(b'UNAVAILABLE',b'READY'),serial()+serial(),b'R1_SYSTEMD {}\n',serial().replace(b'R1_SYSTEMD ',b'kernel panic\nR1_SYSTEMD ')):
            with self.assertRaises(ValueError):b.parse_events(raw,fake_pins())
    def test_separate_console_and_event_channels(self):
        self.assertEqual(b.native_receipt(serial(),fake_pins(),0,True,True,console=console()),fake_event())
        diagnostics=b'\x1bP+q6E616D65\x1b\\\x1b[0mOptional feature warning\r\r\n'+console()
        self.assertTrue(b.verify_console(diagnostics))
        bad=(b'',console()+console(),console()+b'late\n',serial()+console(),
             b'\x1b]0;kernel panic\x07\n'+console(),
             b'\x1b]0;kernel \x1b[0mpanic\x07\n'+console(),
             b'\x1bPkernel \x1b[0mpanic\x1b\\\n'+console(),
             b'\x1b]0;Failed to allocate \x1b[0mmanager\x1b\\\n'+console(),
             b'\x1bPFreezing \x1b[0mexecution\x1b\\\n'+console(),
             b'\x1bPkernel \x1b]0;x\x07panic\x1b\\\n'+console(),
             b'\x1b]0;kernel \rpanic\x07\n'+console(),
             b'\x1bPFailed to allocate \rmanager\x1b\\\n'+console(),
             b'\x1bPbenign \x1b]0;x\x07payload\x1b\\\n'+console(),
             b'kernel \x1b]0;x\x07panic\n'+console(),
             b'kernel \x1bPbenign\x1b\\panic\n'+console(),
             b'Failed to allocate \x1b[0mmanager\n'+console(),
             b'\x1b[?\n'+console())
        for raw in bad:
            with self.assertRaises(ValueError):b.verify_console(raw)
        for raw in (b'\x1b[0m'+serial(),b'noise\n'+serial(),serial()+console(),serial().replace(b'\n',b'\r\n')):
            with self.assertRaises(ValueError):b.parse_events(raw,fake_pins())
    def test_lifecycle_gate(self):
        for rc,reap,pidfd,stderr in ((1,True,True,b''),(0,False,True,b''),(0,True,False,b''),(0,True,True,b'warning'),(False,True,True,b'')):
            with self.assertRaises(ValueError):b.native_receipt(serial(),fake_pins(),rc,reap,pidfd,stderr)
    def test_plan_is_tcg_networkless_readonly(self):
        a=b.planned_qemu('kernel','archive','disk');self.assertIn('pc,accel=tcg',a)
        self.assertEqual(a[a.index('-nic')+1],'none');self.assertIn('readonly=on',a[a.index('-drive')+1])
        self.assertNotIn('-enable-kvm',a)
    def test_no_run_option(self):
        r=subprocess.run([sys.executable,'-B',str(b.HERE/'build_r1_systemd_vm.py'),'--run'],capture_output=True)
        self.assertEqual(r.returncode,2)


class HostLifecycle(unittest.TestCase):
    def test_static_init_wrong_entry_returns(self):
        if os.getuid()==0 or os.geteuid()==0:
            self.skipTest('ordinary-UID native test only; never invoke helper as host root')
        with b.offline.TrustedOutput(b.BASE,create=True) as out:
            out.create_dir('wrong-entry-'+str(os.getpid())+'-'+str(time.monotonic_ns())[-8:])
            out.write('init.c',(b.HERE/'init.r1_systemd.c').read_bytes())
            out.write('init',b'')
            b.offline.trusted_tool(b.origin.GCC)
            b.pinned(b.origin.GCC,b.origin.GCC_SHA256)
            result=subprocess.run([str(b.origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror',
                                   str(out.out/'init.c'),'-o',str(out.out/'init')],
                                  capture_output=True,timeout=30,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            fd=out.pins[out.out/'init']
            os.fchmod(fd,0o600);out.check()
            self.assertEqual(result.returncode,0,result.stderr.decode())
            b.offline.static_elf(out.read('init'))
            # Exec refuses an inode still held open for writing (ETXTBSY).
            # Retain the same inode through a read-only descriptor for execution.
            readonly=os.open(out.out/'init',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
            self.assertEqual((os.fstat(fd).st_dev,os.fstat(fd).st_ino),
                             (os.fstat(readonly).st_dev,os.fstat(readonly).st_ino))
            os.close(fd);fd=readonly;out.pins[out.out/'init']=fd
            try:
                os.fchmod(fd,0o700)
                result=subprocess.run([str(out.out/'init')],stdin=subprocess.DEVNULL,
                                      capture_output=True,timeout=2,env={'LC_ALL':'C'})
                self.assertEqual(result.returncode,125)
                self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')
            finally:
                os.fchmod(fd,0o600);out.check()

    def test_bounded_non_vm_children(self):
        # Actual ordinary-UID Python children exercise shared host lifecycle.
        # They are never guest execution evidence.
        with b.offline.TrustedOutput(b.BASE,create=True) as out:
            out.create_dir('test-'+str(os.getpid())+'-'+str(time.monotonic_ns())[-8:])
            for case,code,limit in (('normal','print("synthetic lifecycle only")',2),('timeout','import time;time.sleep(10)',0.05),('overflow','print("x"*4096)',2)):
                out.write(case+'.out',b'');out.write(case+'.err',b'')
                child=subprocess.Popen([sys.executable,'-B','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                fd=os.pidfd_open(child.pid)
                try:
                    with b.closed.SignalLatch() as latch,patch.object(b.closed,'TIMEOUT',limit),patch.object(b.closed,'MAX_SERIAL',1024):
                        if case=='normal':b.closed.capture(child,fd,out.pins[out.out/(case+'.out')],out.pins[out.out/(case+'.err')],out,latch)
                        else:
                            with self.assertRaises((TimeoutError,ValueError)):b.closed.capture(child,fd,out.pins[out.out/(case+'.out')],out.pins[out.out/(case+'.err')],out,latch)
                    rc=b.closed.reap_exact(child,fd,kill=case!='normal')
                    if case=='normal':self.assertEqual(rc,0)
                finally:
                    if child.poll() is None:b.closed.reap_exact(child,fd,kill=True)
                    child.stdout.close();child.stderr.close();os.close(fd)


def verify_builds(first,second):
    a,bpath=Path(first),Path(second)
    reports=[json.loads((p/'plan.json').read_bytes()) for p in (a,bpath)]
    for r in reports:
        assert r['boot_executed'] is False and r['status']==b.OFFLINE
    assert reports[0]['artifacts']==reports[1]['artifacts'],'deployable bytes differ'
    for p,r in zip((a,bpath),reports):
        for n,h in r['artifacts'].items():assert b.offline.sha((p/n).read_bytes())==h
        decoded=decode((p/'initramfs.cpio.gz').read_bytes())
        manifest=json.loads((p/'archive-manifest.json').read_bytes())
        assert set(decoded)=={x['path'] for x in manifest}
        for x in manifest:
            mode,data,dev=decoded[x['path']];assert mode==x['mode'] and len(data)==x['bytes'] and b.offline.sha(data)==x['sha256']
        assert not any('generator' in x or 'initrd-release' in x or 'host' in x for x in decoded)
        b.offline.static_elf(decoded['init'][1]);b.offline.static_elf(decoded['usr/local/libexec/r1-observer'][1])
        executor_mode,executor_data,_=decoded['usr/lib/systemd/systemd-executor']
        assert executor_mode==stat.S_IFREG|0o755,'executor is not root archive regular0755'
        assert b.offline.sha(executor_data)==b.EXECUTOR_SHA,'executor archive bytes differ'
        umount_mode,umount_data,_=decoded['usr/bin/umount']
        assert umount_mode==stat.S_IFREG|0o755,'umount is not root archive regular0755'
        assert b.offline.sha(umount_data)==b.UMOUNT_SHA,'umount archive bytes differ'
        b.verify_elf_closure({'/'+n:d for n,(m,d,v) in decoded.items() if stat.S_ISREG(m)})
        image=p/'fixture.raw'
        for path,uid,mode in (('/',0,'0700'),('/vault',0,'0700'),('/vault/state',1000,'0700'),('/vault/state/db.sqlite',1000,'0600'),('/vault/manager.lock',0,'0600')):
            stattext=subprocess.run([b.offline.PINS['debugfs'][0],'-R','stat '+path,str(image)],capture_output=True,check=True).stdout.decode()
            assert __import__('re').search(r'Mode:\s+0?'+mode.lstrip('0')+r'\b',stattext),stattext
            assert __import__('re').search(r'User:\s+'+str(uid)+r'\s+Group:\s+'+str(uid)+r'\b',stattext),stattext
        expected={'/':{'.','..','vault'},'/vault':{'.','..','state','manager.lock'},'/vault/state':{'.','..','db.sqlite'}}
        for path,names in expected.items():
            listing=subprocess.run([b.offline.PINS['debugfs'][0],'-R','ls -p '+path,str(image)],capture_output=True,check=True).stdout.decode()
            observed={line.split('/')[5] for line in listing.splitlines() if line.startswith('/') and len(line.split('/'))>5}
            assert observed==names,(path,observed)
        readback=subprocess.run([b.offline.PINS['debugfs'][0],'-R','cat /vault/state/db.sqlite',str(image)],capture_output=True,check=True).stdout
        assert b.offline.sha(readback)==r['source_sha256']
    print('Two fresh builds: archive/ELF/disk metadata/tree/source and deployable byte identity passed; unbooted.')

if __name__=='__main__':
    if len(sys.argv)==3:verify_builds(*sys.argv[1:])
    else:unittest.main()
