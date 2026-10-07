#!/usr/bin/env python3
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import validate_boot_candidate as candidate

common=candidate.common
ISSUER='podbay-source-issuer.service'
PRODUCER_BYTES=('''[Unit]
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target basic.target podbay-source-issuer.service
[Service]
Type=oneshot
User=0
Group=0
Restart=no
ExecStart=/usr/local/libexec/podbay-r1-boot-producer
''').encode()
ISSUER_BYTES=('''[Unit]
DefaultDependencies=no
Requires=podbay-r1-boot-producer.service
After=podbay-r1-boot-producer.service
[Service]
Type=exec
User=1000
Group=1000
Restart=no
ExecStart=/usr/local/libexec/podbay-r1/issuer-000
''').encode()


class CandidateTests(unittest.TestCase):
    def setUp(self):
        if os.getuid()==0 or os.geteuid()==0:self.skipTest('ordinary UID only')
        self.base=Path(tempfile.mkdtemp(prefix='r1-candidate-test-',dir=Path.home()))
        self.base.chmod(0o700);self.path=self.base/'candidate.json'
        self.doc=self.fixture()
    def tearDown(self):
        if hasattr(self,'base'):shutil.rmtree(self.base)
    def write(self,name,data):
        p=self.base/name;p.write_bytes(data);p.chmod(0o600);return p
    def artifact(self,ident,role,filename,destination,mode,data):
        self.write(filename,data)
        return dict(id=ident,role=role,filename=filename,install_path=destination,mode=mode,
                    uid=0,gid=0,sha256=common.sha(data),bytes=len(data),generation='candidate-1')
    def fixture(self):
        artifacts=[self.artifact(role,role,name,path,mode,('INERT TEST ARTIFACT '+role).encode())
                   for role,(name,path,mode) in candidate.CORE.items()]
        artifacts += [self.artifact('issuer-000','issuer-program','issuer-000.bin','/usr/local/libexec/podbay-r1/issuer-000',0o755,b'INERT TEST ISSUER'),
                      self.artifact('unit-000','unit','unit-000.service','/etc/systemd/system/'+candidate.PRODUCER_UNIT,0o644,PRODUCER_BYTES),
                      self.artifact('unit-001','unit','unit-001.service','/etc/systemd/system/'+ISSUER,0o644,ISSUER_BYTES)]
        return {'schema':candidate.SCHEMA,'generation':'candidate-1','domain':'DECLARED_BOOT_IMAGE',
                'subject':{'vault_path':'/unopened/production/vault','device':7,'owner_uid':1000,'owner_gid':1000,
                           'vault':dict(inode=2,uid=0,gid=0,mode=0o700),'state':dict(inode=3,uid=1000,gid=1000,mode=0o700),
                           'source':dict(path='state/db.sqlite',device=7,inode=4,uid=1000,gid=1000,mode=0o600,nlink=1,bytes=397312,sha256='1'*64,schema_sha256='2'*64,lineage='0'*31+'1'),
                           'lock':dict(path='state/db.sqlite.manager.lock',device=7,inode=5,uid=1000,gid=1000,mode=0o600,nlink=1,bytes=0),
                           'companions_absent_declared':list(candidate.COMPANIONS),'aliases_absent_declared':True},
                'artifacts':artifacts,
                'producer':dict(unit=candidate.PRODUCER_UNIT,artifact='producer',live_evidence='UNAVAILABLE',attempt_policy='ONE_ATTEMPT_PER_BOOT',late_entry='REFUSE',custody_loss='REFUSE_NO_RETRY',before_source_lock_child=True,deferred_native_predicates=list(candidate.PREDICATES)),
                'issuer_inventory':dict(scope='DECLARED_BOOT_IMAGE',complete_declared=True,unresolved=[],expected_units=[candidate.PRODUCER_UNIT,ISSUER],issuers=[dict(unit=ISSUER,artifact='issuer-000',uid=1000)],routes=[dict(route=r,disposition='GATED_DECLARED' if r=='manual-owner-code' else 'ABSENT_DECLARED',units=[ISSUER] if r=='manual-owner-code' else []) for r in common.ROUTES])}
    def validate(self,doc=None):
        raw=common.encoded(self.doc if doc is None else doc);self.write('candidate.json',raw)
        return candidate.validate(str(self.path),common.sha(raw),str(self.base))
    def changed_unit(self,old,new):
        doc=copy.deepcopy(self.doc);raw=ISSUER_BYTES.replace(old,new);self.write('unit-001.service',raw)
        a=next(a for a in doc['artifacts'] if a['id']=='unit-001');a['sha256']=common.sha(raw);a['bytes']=len(raw)
        return doc
    def refuse(self,doc):
        with self.assertRaises(candidate.Refusal):self.validate(doc)
    def test_valid_is_unattested_and_only_captured_bytes_are_verified(self):
        result=self.validate()
        self.assertEqual(result['status'],'PREPARED_UNATTESTED');self.assertEqual(result['production_origin'],'UNAVAILABLE')
        self.assertEqual(result['admission'],'UNAVAILABLE');self.assertTrue(result['deployment_blocked'])
        self.assertEqual(result['capture_semantics'],'PINNED_CAPTURED_BYTES_NOT_A_LIVE_OR_ATOMIC_SNAPSHOT')
        self.assertFalse(any(result['declarations'].values()));self.assertFalse(result['graph']['native_order_verified'])
        self.assertEqual(len(result['captured_artifacts']),len(self.doc['artifacts']))
        self.assertNotIn('permit',json.dumps(result).lower());self.assertEqual(result,self.validate())
    def test_foreign_fixture_marker_request_and_receipt_refuse(self):
        for d in (dict(schema='podbay.r1.install-manifest/1',deployment_blocked=True,availability='UNAVAILABLE',reason='COLD_BOOT_PROVENANCE_UNAVAILABLE'),
                  dict(schema='podbay.r1.install-plan/1'),dict(schema=1,event='BOOTSTRAP_REFUSED_ISSUERS_BLOCKED_NO_PRODUCTION_ADMISSION')):self.refuse(d)
        for key,value in (('schema','podbay.r1.install-plan-request/1'),('domain','DISPOSABLE_SYSTEMD_IMAGE_ONLY')):
            d=copy.deepcopy(self.doc);d[key]=value;self.refuse(d)
    def test_closed_keys_at_every_shape(self):
        paths=[(),('subject',),('subject','vault'),('subject','state'),('subject','source'),('subject','lock'),('producer',),('issuer_inventory',),('artifacts',0),('issuer_inventory','issuers',0),('issuer_inventory','routes',0)]
        for path in paths:
            for mutation in ('add','remove'):
                d=copy.deepcopy(self.doc);node=d
                for key in path:node=node[key]
                if mutation=='add':node['authority']=True
                else:node.pop(next(iter(node)))
                with self.subTest(path=path,mutation=mutation):self.refuse(d)
    def test_duplicate_unknown_type_size_json_refuse(self):
        for raw in (b'{"schema":1,"schema":2}',b'{"x":NaN}',b'{"x":1.0}',b'\xff',b'['*1000+b'0'+b']'*1000,b' '*(common.MAX_REQUEST+1)):
            self.write('candidate.json',raw)
            with self.assertRaises(candidate.Refusal):candidate.validate(str(self.path),common.sha(raw),str(self.base))
    def test_fixed_subject_and_lock_layout(self):
        mutations=[('source','path','state/other.sqlite'),('lock','path','manager.lock'),('lock','uid',0),('lock','gid',0),('lock','device',8),('lock','inode',4),('source','nlink',2),('source','mode',0o644),('state','uid',0),('vault','mode',0o755),('source','bytes',True)]
        for field,key,value in mutations:
            d=copy.deepcopy(self.doc);d['subject'][field][key]=value
            with self.subTest(field=field,key=key):self.refuse(d)
        d=copy.deepcopy(self.doc);d['subject']['companions_absent_declared'].pop();self.refuse(d)
        d=copy.deepcopy(self.doc);d['subject']['aliases_absent_declared']=False;self.refuse(d)
    def test_artifact_path_generation_hash_and_role_refuse(self):
        for key,value in (('filename','../source'),('filename','/etc/passwd'),('generation','foreign'),('role','authority'),('install_path','/unopened/production/vault/x'),('sha256','0'*64),('bytes',1),('uid',True)):
            d=copy.deepcopy(self.doc);d['artifacts'][0][key]=value
            with self.subTest(key=key):self.refuse(d)
        self.write('enforcer.bin',b'changed actual bytes')
        with self.assertRaises(candidate.Refusal):self.validate()
    def test_regular_artifact_and_vault_ancestor_overlap_refuses_both_directions(self):
        for path in ('/usr/lib/systemd/systemd/vault','/usr/lib/systemd','/usr/lib/systemd/systemd'):
            d=copy.deepcopy(self.doc);d['subject']['vault_path']=path
            with self.subTest(vault=path),self.assertRaisesRegex(candidate.Refusal,'ARTIFACT_SUBJECT_OVERLAP'):
                self.validate(d)
    def test_regular_artifact_destination_overlap_refuses_both_input_orders(self):
        # Both individually valid library paths: one regular file would have
        # to become the other's parent directory.
        a=self.artifact('lib-000','library','lib-000.bin','/usr/lib/x86_64-linux-gnu/systemd',0o755,b'INERT A')
        b=self.artifact('lib-001','library','lib-001.bin','/usr/lib/x86_64-linux-gnu/systemd/libcandidate.so',0o755,b'INERT B')
        for pair in ([a,b],[b,a]):
            d=copy.deepcopy(self.doc);d['artifacts']+=pair
            with self.subTest(order=[x['id'] for x in pair]),self.assertRaisesRegex(candidate.Refusal,'ARTIFACT_DESTINATION_OVERLAP'):
                self.validate(d)
    def test_component_boundary_lexical_siblings_remain_supported(self):
        d=copy.deepcopy(self.doc);d['subject']['vault_path']='/usr/lib/systemd/systemd-vault'
        d['artifacts'] += [self.artifact('lib-000','library','lib-000.bin','/usr/lib/x86_64-linux-gnu/libcandidate.so',0o755,b'INERT A'),
                           self.artifact('lib-001','library','lib-001.bin','/usr/lib/x86_64-linux-gnu/libcandidate.so.1',0o755,b'INERT B')]
        self.assertEqual(self.validate(d)['status'],'PREPARED_UNATTESTED')
    def test_issuer_gap_routes_and_live_claims_refuse(self):
        for field,value in (('complete_declared',False),('complete_declared',1),('unresolved',['ssh']),('issuers',[]),('expected_units',[candidate.PRODUCER_UNIT]),('routes',[])):
            d=copy.deepcopy(self.doc);d['issuer_inventory'][field]=value;self.refuse(d)
        d=copy.deepcopy(self.doc)
        for r in d['issuer_inventory']['routes']:r.update(disposition='ABSENT_DECLARED',units=[])
        self.refuse(d)
        for field,value in (('live_evidence','VERIFIED'),('late_entry','ALLOW'),('custody_loss','RESTART'),('before_source_lock_child',1),('deferred_native_predicates',[])):
            d=copy.deepcopy(self.doc);d['producer'][field]=value;self.refuse(d)
    def test_real_unit_skip_restart_gap_and_cycles_refuse(self):
        for old,new in ((b'Restart=no',b'Restart=always'),(b'Restart=no',b'ConditionPathExists=/tmp/x\nRestart=no'),(b'Restart=no',b'ExecCondition=/bin/true\nRestart=no'),(b'Requires=',b'Wants='),(b'After=',b'Before='),(b'After=podbay-r1-boot-producer.service',b'After=missing.service'),(b'User=1000',b'User=0')):
            with self.subTest(new=new):self.refuse(self.changed_unit(old,new))
    def test_same_inode_rewrite_during_capture_refuses(self):
        raw=common.encoded(self.doc);self.write('candidate.json',raw);identity=self.path.stat().st_ino
        replacement=raw.replace(b'candidate-1',b'candidate-2')
        original=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            data=original(fd,count)
            if not changed:
                changed=True
                with self.path.open('r+b') as stream:stream.write(replacement);stream.flush();os.fsync(stream.fileno())
                self.assertEqual(self.path.stat().st_ino,identity)
            return data
        with patch.object(os,'read',side_effect=read),self.assertRaises(candidate.Refusal):
            candidate.validate(str(self.path),common.sha(raw),str(self.base))
    def test_named_path_replacement_during_capture_refuses(self):
        raw=common.encoded(self.doc);self.write('candidate.json',raw);original=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            data=original(fd,count)
            if not changed:
                changed=True;self.path.rename(self.base/'old-candidate.json');self.write('candidate.json',raw)
            return data
        with patch.object(os,'read',side_effect=read),self.assertRaises(candidate.Refusal):
            candidate.validate(str(self.path),common.sha(raw),str(self.base))
    def test_bundle_replacement_between_captures_refuses(self):
        raw=common.encoded(self.doc);self.write('candidate.json',raw);original=common.captured_file;old=self.base.with_name(self.base.name+'-old')
        def capture(path,digest,limit):
            result=original(path,digest,limit)
            if path==str(self.path):
                self.base.rename(old);self.base.mkdir(mode=0o700)
            return result
        try:
            with patch.object(common,'captured_file',side_effect=capture),self.assertRaises(candidate.Refusal):
                candidate.validate(str(self.path),common.sha(raw),str(self.base))
        finally:
            if old.exists():shutil.rmtree(old)
    def test_earlier_artifact_rewrite_or_replacement_during_later_capture_refuses(self):
        for replace in (False,True):
            self.doc=self.fixture();raw=common.encoded(self.doc);self.write('candidate.json',raw)
            original=common.captured_file;seen=[];modified=False
            def capture(path,digest,limit):
                nonlocal modified
                data=original(path,digest,limit)
                if Path(path).name!='candidate.json':
                    if seen and not modified:
                        modified=True;earlier=self.base/seen[0]
                        if replace:
                            earlier.rename(self.base/'replaced-artifact');self.write(earlier.name,b'changed captured artifact')
                        else:
                            with earlier.open('r+b') as f:f.write(b'changed');f.flush();os.fsync(f.fileno())
                    seen.append(Path(path).name)
                return data
            with self.subTest(replace=replace),patch.object(common,'captured_file',side_effect=capture):
                with self.assertRaisesRegex(candidate.Refusal,'BUNDLE_FILE_CHANGED'):
                    candidate.validate(str(self.path),common.sha(raw),str(self.base))
            self.assertTrue(modified)
    def test_no_source_lock_manifest_child_or_output_effects(self):
        before=set(self.base.iterdir());seen=[];original=common.captured_file
        def capture(path,digest,limit):
            self.assertEqual(Path(path).parent,self.base);self.assertNotIn('/state/',path);seen.append(Path(path).name)
            return original(path,digest,limit)
        with patch.object(common,'captured_file',side_effect=capture),patch.object(subprocess,'run',side_effect=AssertionError('launch')),patch.object(subprocess,'Popen',side_effect=AssertionError('launch')),patch.object(os,'system',side_effect=AssertionError('shell')):
            result=self.validate()
        self.assertEqual(set(seen),{'candidate.json'}|{a['filename'] for a in self.doc['artifacts']})
        self.assertEqual(set(self.base.iterdir()),before|{self.path});self.assertFalse(result['declarations']['subject_opened'])
        with patch.object(os,'geteuid',return_value=0),patch.object(common,'captured_file',side_effect=AssertionError('root read')):
            with self.assertRaisesRegex(candidate.Refusal,'ROOT_VALIDATION_REFUSED'):candidate.validate('/unused','0'*64,'/unused')
    def test_symlink_hardlink_writable_inputs_refuse(self):
        self.write('candidate.json',common.encoded(self.doc));target=self.base/'producer.bin'
        os.link(target,self.base/'producer-hardlink')
        with self.assertRaises(candidate.Refusal):self.validate()
        (self.base/'producer-hardlink').unlink();target.chmod(0o660)
        with self.assertRaises(candidate.Refusal):self.validate()
        target.chmod(0o600);target.rename(self.base/'producer-original');target.symlink_to(self.base/'producer-original')
        with self.assertRaises(OSError):self.validate()
    def test_bundle_must_remain_private(self):
        self.base.chmod(0o755)
        try:
            with self.assertRaisesRegex(candidate.Refusal,'PRIVATE_BUNDLE_REQUIRED'):self.validate()
        finally:self.base.chmod(0o700)
    def test_cli_is_offline_and_has_no_install_option(self):
        raw=common.encoded(self.doc);self.write('candidate.json',raw)
        r=subprocess.run([sys.executable,'-B',candidate.__file__,'--candidate',str(self.path),'--candidate-sha256',common.sha(raw),'--bundle',str(self.base)],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['status'],'PREPARED_UNATTESTED')
        r=subprocess.run([sys.executable,'-B',candidate.__file__,'--install'],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,2)
    def test_versioned_structural_schema_matches_closed_shapes(self):
        schema=json.loads(Path(candidate.__file__).with_name('boot_deployment_candidate_v1.schema.json').read_bytes())
        self.assertEqual(schema['properties']['schema']['const'],candidate.SCHEMA)
        self.assertEqual(set(schema['required']),set(candidate.FIELDS['candidate']))
        self.assertFalse(schema['additionalProperties'])
        for kind in ('directory','source','lock','artifact','subject','producer','inventory','issuer','route'):
            self.assertEqual(set(schema['$defs'][kind]['required']),set(candidate.FIELDS[kind]))
            self.assertEqual(set(schema['$defs'][kind]['properties']),set(candidate.FIELDS[kind]))
            self.assertFalse(schema['$defs'][kind]['additionalProperties'])
if __name__=='__main__':unittest.main()
