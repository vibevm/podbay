#!/usr/bin/env python3
"""Offline fixture gates; synthetic records never constitute VM evidence."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import unittest
sys.dont_write_bytecode=True
import build_r1_appliance_vm as b
import run_r1_appliance_vm as runner
import r1_systemd_test as old

def pins():
    return dict(archive_generation='a'*64,source_sha256=hashlib.sha256(b'fixture').hexdigest(),source_inode=13,lock_inode=14,source_bytes=7)
def event():
    p=pins();nonce='b'*64
    read=dict(schema=1,generation=p['archive_generation'],source_sha256=p['source_sha256'],source_inode=13,lock_inode=14,bytes=7,migration_admission='UNAVAILABLE',ready=False,boot_id='00000000-0000-0000-0000-000000000001',keeper_pid=30,keeper_birth=10,custodian_pid=31,custodian_birth=11,device=253,nonce=nonce,bound_sha256=hashlib.sha256(b'podbay.appliance.read/1\0'+bytes.fromhex(nonce)+bytes.fromhex(p['source_sha256'])).hexdigest())
    return dict(schema=1,event=b.SUCCESS,read=read,armed_us=100,killed_us=200,finished_us=300,watch_control=True,fd_seal=True,outside_denials=8,lock_contended=True,loss_observed=True,spent_retry_refused=True,issuer_starts=0,production_origin='UNAVAILABLE',migration_admission='UNAVAILABLE')
def raw(e=None):return b'R1_APPLIANCE_READ_V1 '+json.dumps(e or event()).encode()+b'\n'

class Gates(unittest.TestCase):
    def test_synthetic_parser_only(self):self.assertEqual(b.parse_events(raw(),pins()),event())
    def test_all_outer_mutants_refuse(self):
        for key in event():
            e=event();e[key]=None
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):b.parse_events(raw(e),pins())
    def test_all_read_mutants_refuse(self):
        for key in event()['read']:
            e=event();e['read'][key]=None
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):b.parse_events(raw(e),pins())
    def test_binding_nonce_generation_subject_and_surplus_refuse(self):
        for key,value in (('nonce','c'*64),('bound_sha256','d'*64),('generation','e'*64),('source_inode',14),('ready',True)):
            e=event();e['read'][key]=value
            with self.assertRaises(ValueError):b.parse_events(raw(e),pins())
        for r in (raw()+b'x',raw()+raw(),b'\x1b'+raw(),raw().replace(b'"schema": 1',b'"schema":1,"schema":1')):
            with self.assertRaises(ValueError):b.parse_events(r,pins())
    def test_native_lifecycle_and_console_mandatory(self):
        for code,reaped,pidfd,console in ((2,True,True,old.console()),(0,False,True,old.console()),(0,True,False,old.console()),(0,True,True,b'Failed at step EXEC\n'+old.console())):
            with self.assertRaises(ValueError):b.native_receipt(raw(),pins(),code,reaped,pidfd,console=console)
    def test_graph_mutants_refuse(self):
        b.verify_graph(b.units())
        for name,oldbytes,new in ((b.KEEPER,b'Requires=',b'Wants='),(b.KEEPER,b'Type=notify',b'Type=oneshot'),(b.KEEPER,b'Restart=no',b'Restart=always'),(b.ISSUER,b'After=',b'Before='),(b.ISSUER,b'BindsTo=',b'Wants='),(b.ISSUER,b'User=1000',b'User=0')):
            units=b.units();units[name]=units[name].replace(oldbytes,new)
            with self.assertRaises(ValueError):b.verify_graph(units)
        units=b.units();units['evil.service']=b'[Service]\nExecStart=/bin/busybox\n'
        with self.assertRaises(ValueError):b.verify_graph(units)
    def test_keeper_never_reads_source_and_rechecks_transfer(self):
        source=b.SOURCE_PATHS['src/appliance.rs'].read_text();keeper=source.split('pub fn keeper()',1)[1].split('pub fn custodian()',1)[0]
        self.assertNotIn('sys::pread',keeper)
        self.assertGreaterEqual(keeper.count('recheck_subject('),4)
        self.assertIn('drop(source)',keeper)
        self.assertIn('pair.1 != expected_bound',source)
        self.assertIn('impl Drop for ReadCustody',source)
    def test_second_boot_requires_fresh_identity_nonce_and_same_subject(self):
        a=event()['read'];z=copy.deepcopy(a)
        with self.assertRaises(ValueError):runner.verify_independent_boots(a,z)
        z['boot_id']='00000000-0000-0000-0000-000000000002'
        with self.assertRaises(ValueError):runner.verify_independent_boots(a,z)
        z['nonce']='c'*64;runner.verify_independent_boots(a,z)
        z['source_inode']=99
        with self.assertRaises(ValueError):runner.verify_independent_boots(a,z)
    def test_init_wrong_entry_guard_precedes_mount(self):
        text=(b.HERE/'init.r1_appliance.c').read_text().split('int main(void)',1)[1]
        self.assertLess(text.index('return 125'),text.index('mount('))
        self.assertIn('mkdir("/run/r1-appliance",0700)',text)

def verify_builds(first,second):
    reports=[json.loads((Path(p)/'plan.json').read_bytes()) for p in (first,second)]
    assert reports[0]['artifacts']==reports[1]['artifacts']
    for path,r in zip((Path(first),Path(second)),reports):
        runner.validate_plan(r)
        entries=old.decode((path/'initramfs.cpio.gz').read_bytes())
        manifest=json.loads((path/'archive-manifest.json').read_bytes())
        assert set(entries)=={x['path'] for x in manifest}
        for row in manifest:
            mode,data,_=entries[row['path']];assert mode==row['mode'] and b.offline.sha(data)==row['sha256']
        for name in ('usr/local/libexec/podbay-r1-appliance-keeper','usr/local/libexec/podbay-r1-appliance-custodian','usr/local/libexec/r1-appliance-monitor','usr/lib/systemd/systemd-executor','usr/bin/umount'):
            assert entries[name][0]==stat.S_IFREG|0o755
        for name,h in r['artifacts'].items():assert b.offline.sha((path/name).read_bytes())==h
        assert r['source_inode']==13 and r['lock_inode']==14
    return reports[0]['artifacts']
if __name__=='__main__':unittest.main()
