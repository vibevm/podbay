#!/usr/bin/env python3
"""Ordinary-UID negative executable checks. No service/VM/root invocation."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest

BINARY=None
TRACE=None
EXPECTED={'schema':'podbay.r1.producer-refusal/2','lifecycle_schema':'podbay.r1.producer-lifecycle/2',
          'code':'COLD_BOOT_PROVENANCE_UNAVAILABLE','production_origin':'UNAVAILABLE',
          'admission':'UNAVAILABLE','ready':False,'retry':False}

class ScaffoldTests(unittest.TestCase):
    def setUp(self):
        if os.getuid()==0 or os.geteuid()==0:self.skipTest('ordinary UID only, never host root')
    def invoke(self,args=(),**kwargs):
        r=subprocess.run([str(BINARY),*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=3,**kwargs)
        self.assertEqual(r.returncode,2);self.assertEqual(r.stderr,b'')
        self.assertLess(len(r.stdout),512);self.assertEqual(r.stdout.count(b'\n'),1)
        expected=dict(EXPECTED);expected['code']='INVALID_ARGUMENTS' if args else EXPECTED['code']
        self.assertEqual(json.loads(r.stdout),expected)
        return r
    def test_zero_argument_normal_binary_refuses(self):self.invoke()
    def test_overrides_candidate_paths_and_packets_refuse(self):
        for args in (('--ready',),('--force',),('--cold',),('--manifest','/etc/podbay/r1-install-manifest.json'),
                     ('--candidate','/must-not-open'),('--fd','3'),('schema=podbay.r1.producer-lifecycle/2',)):
            with self.subTest(args=args):self.invoke(args)
    def test_notify_environment_and_sentinels_have_no_effect(self):
        with tempfile.TemporaryDirectory(prefix='r1-producer-test-',dir=Path.home()) as temporary:
            root=Path(temporary);root.chmod(0o700)
            source=root/'db.sqlite';lock=root/'db.sqlite.manager.lock';marker=root/'runtime-marker.json'
            for p in (source,lock,marker):p.write_bytes(b'untouched inert sentinel');p.chmod(0o600)
            before={p.name:(p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns,p.read_bytes()) for p in (source,lock,marker)}
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as receiver:
                receiver.bind(str(root/'notify.sock'));receiver.settimeout(.1)
                env=dict(os.environ,NOTIFY_SOCKET=str(root/'notify.sock'),R1_FORCE='1',R1_COLD='1',R1_READY='1',R1_MANIFEST=str(marker))
                self.invoke(cwd=root,env=env)
                with self.assertRaises(socket.timeout):receiver.recv(4096)
            after={p.name:(p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns,p.read_bytes()) for p in (source,lock,marker)}
            self.assertEqual(before,after)
            self.assertEqual({p.name for p in root.iterdir()},{source.name,lock.name,marker.name,'notify.sock'})
    def test_notify_template_is_fail_closed_and_v2_only(self):
        directory=Path(__file__).parent/'systemd'
        unit=(directory/'podbay-r1-boot-producer-v2.service.in').read_text()
        required=('Type=notify','NotifyAccess=main','Restart=no','KillMode=control-group',
                  'ExecStart=/usr/local/libexec/podbay-r1-boot-producer','RefuseManualStart=yes')
        for line in required:self.assertIn(line+'\n',unit)
        for prefix in ('ExecStartPre=','ExecStartPost=','ExecStop=','OnFailure=','Condition','SuccessExitStatus='):
            self.assertFalse(any(line.startswith(prefix) for line in unit.splitlines()))
        gate=(directory/'issuer-producer-v2.conf.in').read_text()
        for directive in ('Requires','After','BindsTo'):
            self.assertIn(directive+'=podbay-r1-boot-producer-v2.service\n',gate)
        # Template text and exit2 are not native ordering or keeper-lifetime proof.
    def test_optional_retained_syscall_trace_has_no_application_effects(self):
        if TRACE is None:self.skipTest('no retained syscall trace supplied')
        self.assertLessEqual(TRACE.stat().st_size,65536)
        text=TRACE.read_text();rows=[]
        for line in text.splitlines():
            match=re.match(r'^(\d+)\s+([A-Za-z0-9_]+)\(',line)
            self.assertIsNotNone(match,line);rows.append((match[1],match[2],line))
        self.assertEqual(len({pid for pid,_,_ in rows}),1)
        calls=[call for _,call,_ in rows]
        self.assertEqual(calls.count('execve'),1)
        for forbidden in ('clone','clone3','fork','vfork','execveat','socket','socketpair','connect',
                          'sendto','sendmsg','sendmmsg','flock','mount','umount2','chmod','fchmod',
                          'chown','fchown','unlink','unlinkat','mkdir','mkdirat','openat2'):
            self.assertNotIn(forbidden,calls)
        allowed={'/etc/ld.so.cache','/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
                 '/usr/lib/x86_64-linux-gnu/libc.so.6','/proc/self/maps'}
        for _,call,line in rows:
            if call=='openat':
                self.assertIn(re.search(r'"([^"]+)"',line)[1],allowed)
                self.assertIn('O_RDONLY',line);self.assertNotIn('O_CREAT',line)
            if call=='fcntl':self.assertNotRegex(line,r'F_(?:OFD_)?SETLK')
        writes=[line for _,call,line in rows if call in ('write','writev','pwrite64')]
        self.assertEqual(len(writes),1);self.assertRegex(writes[0],r'write\(1,')
        self.assertIn('exit_group(2)',text)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',required=True)
    parser.add_argument('--trace')
    args,rest=parser.parse_known_args();BINARY=Path(args.binary)
    TRACE=Path(args.trace) if args.trace else None
    if not BINARY.is_absolute():parser.error('absolute normal-built binary required')
    unittest.main(argv=[__file__,*rest])
