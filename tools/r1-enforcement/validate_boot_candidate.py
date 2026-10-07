#!/usr/bin/env python3
"""Data-only offline validation. No production constructor, installation or launch."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import plan_install as common

SCHEMA = 'podbay.r1.boot-deployment-candidate/1'
RESULT_SCHEMA = 'podbay.r1.boot-deployment-candidate-result/1'
PRODUCER_UNIT = 'podbay-r1-boot-producer.service'
MAX_ARTIFACTS = 96
MAX_TOTAL_BYTES = 134_217_728
MAX_ARTIFACT_BYTES = 67_108_864
ANCHORS = ('local-fs.target', 'sysinit.target', 'basic.target', 'shutdown.target')
COMPANIONS = ('state/stage.sqlite', 'state/db.sqlite-wal', 'state/db.sqlite-shm', 'state/db.sqlite-journal')
PREDICATES = ('trusted-pre-issuer-producer', 'complete-native-issuer-exclusion',
              'protected-source-provisioning', 'source-alias-exclusion',
              'private-live-capability-transfer', 'one-attempt-and-custody-loss',
              'two-boot-new-custody', 'production-migration-release')
CORE = {
    'kernel': ('kernel.bin', '/boot/podbay/vmlinuz', 0o644),
    'setup': ('setup.bin', '/usr/local/libexec/podbay-r1-setup', 0o755),
    'manager': ('manager.bin', '/usr/lib/systemd/systemd', 0o755),
    'executor': ('executor.bin', '/usr/lib/systemd/systemd-executor', 0o755),
    'shutdown': ('shutdown.bin', '/usr/lib/systemd/systemd-shutdown', 0o755),
    'umount': ('umount.bin', '/usr/bin/umount', 0o755),
    'enforcer': ('enforcer.bin', '/usr/local/libexec/podbay-r1-linux', 0o755),
    'producer': ('producer.bin', '/usr/local/libexec/podbay-r1-boot-producer', 0o755),
    'policy': ('policy.json', '/etc/podbay/r1-boot-policy.json', 0o600),
}
FIELDS = {
    'candidate': ('schema', 'generation', 'domain', 'subject', 'artifacts', 'producer', 'issuer_inventory'),
    'subject': ('vault_path', 'device', 'owner_uid', 'owner_gid', 'vault', 'state', 'source', 'lock',
                'companions_absent_declared', 'aliases_absent_declared'),
    'directory': ('inode', 'uid', 'gid', 'mode'),
    'source': ('path', 'device', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes', 'sha256', 'schema_sha256', 'lineage'),
    'lock': ('path', 'device', 'inode', 'uid', 'gid', 'mode', 'nlink', 'bytes'),
    'artifact': ('id', 'role', 'filename', 'sha256', 'bytes', 'install_path', 'uid', 'gid', 'mode', 'generation'),
    'producer': ('unit', 'artifact', 'live_evidence', 'attempt_policy', 'late_entry', 'custody_loss',
                 'before_source_lock_child', 'deferred_native_predicates'),
    'inventory': ('scope', 'complete_declared', 'unresolved', 'expected_units', 'issuers', 'routes'),
    'issuer': ('unit', 'artifact', 'uid'),
    'route': ('route', 'disposition', 'units'),
}
Refusal = common.Refusal
require = common.require


def shape(value, name):
    return common.keys(value, FIELDS[name])


def unique_strings(value, maximum=96):
    require(type(value) is list and len(value) <= maximum and all(type(x) is str for x in value), 'INVALID_LIST')
    require(len(value) == len(set(value)), 'DUPLICATE_LIST_ITEM')
    return value


def exact_int(value, expected):
    require(type(value) is int and value == expected, 'INVALID_FIXED_METADATA')


def paths_overlap(first, second):
    """Regular destinations cannot contain another destination or the vault."""
    return first == second or first.startswith(second+'/') or second.startswith(first+'/')


def declared_subject(value):
    s = shape(value, 'subject')
    vault = common.absolute(s['vault_path'])
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', vault) is not None and len(vault.split('/')) <= 65, 'INVALID_VAULT_PATH')
    require(vault not in ('/proc', '/sys', '/dev', '/run') and not any(vault.startswith(x+'/') for x in ('/proc','/sys','/dev')), 'INVALID_VAULT_PATH')
    device = common.integer(s['device'], 1, 2**64-1)
    owner = common.integer(s['owner_uid'], 1, 2**32-2)
    exact_int(s['owner_gid'], owner)
    identities = []
    for field, uid in (('vault',0), ('state',owner)):
        d = shape(s[field], 'directory')
        identities.append(common.integer(d['inode'],1,2**64-1))
        exact_int(d['uid'],uid);exact_int(d['gid'],uid);exact_int(d['mode'],0o700)
    for field, path in (('source','state/db.sqlite'), ('lock','state/db.sqlite.manager.lock')):
        d = shape(s[field], field)
        require(d['path'] == path, 'INCOMPATIBLE_SUBJECT_LAYOUT')
        exact_int(d['device'],device);exact_int(d['uid'],owner);exact_int(d['gid'],owner)
        exact_int(d['mode'],0o600);exact_int(d['nlink'],1)
        identities.append(common.integer(d['inode'],1,2**64-1))
        common.integer(d['bytes'], 1 if field=='source' else 0, 268_435_456 if field=='source' else 1_048_576)
    require(len(set(identities)) == 4, 'ALIASED_SUBJECT_IDENTITIES')
    common.digest(s['source']['sha256']);common.digest(s['source']['schema_sha256'])
    require(type(s['source']['lineage']) is str and re.fullmatch('[0-9a-f]{32}',s['source']['lineage']), 'INVALID_LINEAGE')
    require(sorted(unique_strings(s['companions_absent_declared'])) == sorted(COMPANIONS)
            and s['aliases_absent_declared'] is True, 'UNRESOLVED_SOURCE_ALIASES')
    return s


def artifact_declarations(values, generation, vault):
    require(type(values) is list and len(CORE)+2 <= len(values) <= MAX_ARTIFACTS, 'ARTIFACT_BOUNDS')
    records = {}; filenames = set(); destinations = set(); total = 0
    for a in values:
        shape(a,'artifact')
        ident = common.literal(a['id'],64);role = a['role']
        require(ident not in records and type(role) is str, 'DUPLICATE_ARTIFACT')
        common.digest(a['sha256']);total += common.integer(a['bytes'],1,MAX_ARTIFACT_BYTES)
        require(total <= MAX_TOTAL_BYTES, 'ARTIFACT_TOTAL_BOUNDS')
        require(a['generation'] == generation, 'FOREIGN_ARTIFACT_GENERATION')
        exact_int(a['uid'],0);exact_int(a['gid'],0)
        destination = common.absolute(a['install_path'])
        require(not paths_overlap(destination,vault), 'ARTIFACT_SUBJECT_OVERLAP')
        require(not any(paths_overlap(destination,other) for other in destinations),
                'ARTIFACT_DESTINATION_OVERLAP')
        if role in CORE:
            require(ident==role, 'INVALID_ARTIFACT_ROLE')
            filename,path,mode = CORE[role]
            require(a['filename']==filename and destination==path, 'INVALID_ARTIFACT_PATH')
            exact_int(a['mode'],mode)
        elif role == 'unit':
            require(re.fullmatch(r'unit-[0-9]{3}',ident) is not None and a['filename']==ident+'.service', 'INVALID_ARTIFACT_PATH')
            name = destination.removeprefix('/etc/systemd/system/')
            require(destination=='/etc/systemd/system/'+name and name.endswith('.service'), 'INVALID_ARTIFACT_PATH')
            common.unit_name(name);exact_int(a['mode'],0o644)
            require(a['bytes']<=common.MAX_UNIT,'UNIT_BOUNDS')
        elif role == 'library':
            require(re.fullmatch(r'lib-[0-9]{3}',ident) is not None and a['filename']==ident+'.bin', 'INVALID_ARTIFACT_PATH')
            require(re.fullmatch(r'/usr/lib/x86_64-linux-gnu/(?:systemd/)?[A-Za-z0-9_.+-]+',destination) is not None
                    or destination=='/lib64/ld-linux-x86-64.so.2', 'INVALID_ARTIFACT_PATH')
            exact_int(a['mode'],0o755)
        elif role == 'issuer-program':
            require(re.fullmatch(r'issuer-[0-9]{3}',ident) is not None and a['filename']==ident+'.bin'
                    and destination=='/usr/local/libexec/podbay-r1/'+ident, 'INVALID_ARTIFACT_PATH')
            exact_int(a['mode'],0o755)
        else:raise Refusal('INVALID_ARTIFACT_ROLE')
        require(a['filename'] not in filenames and destination not in destinations, 'ALIASED_ARTIFACT')
        filenames.add(a['filename']);destinations.add(destination);records[ident]=a
    require(set(CORE)<=set(records), 'MISSING_CORE_ARTIFACT')
    return records


def declaration(raw):
    candidate = common.parse_json(raw)
    shape(candidate,'candidate')
    require(candidate['schema']==SCHEMA and candidate['domain']=='DECLARED_BOOT_IMAGE', 'CANDIDATE_SCHEMA_OR_DOMAIN')
    generation = common.literal(candidate['generation'])
    s = declared_subject(candidate['subject'])
    records = artifact_declarations(candidate['artifacts'],generation,s['vault_path'])
    p = shape(candidate['producer'],'producer')
    require(p['unit']==PRODUCER_UNIT and p['artifact']=='producer'
            and p['live_evidence']=='UNAVAILABLE' and p['attempt_policy']=='ONE_ATTEMPT_PER_BOOT'
            and p['late_entry']=='REFUSE' and p['custody_loss']=='REFUSE_NO_RETRY'
            and p['before_source_lock_child'] is True
            and sorted(unique_strings(p['deferred_native_predicates']))==sorted(PREDICATES), 'UNAVAILABLE_PRODUCER_REQUIRED')
    inventory = shape(candidate['issuer_inventory'],'inventory')
    require(inventory['scope']=='DECLARED_BOOT_IMAGE' and inventory['complete_declared'] is True
            and inventory['unresolved']==[], 'INCOMPLETE_ISSUER_INVENTORY')
    expected = unique_strings(inventory['expected_units'],33)
    require(2<=len(expected)<=33 and PRODUCER_UNIT in expected, 'INCOMPLETE_ISSUER_INVENTORY')
    for name in expected:
        common.unit_name(name);require(name.endswith('.service'),'INVALID_UNIT_NAME')
    require(type(inventory['issuers']) is list and len(inventory['issuers'])==len(expected)-1,'INCOMPLETE_ISSUER_INVENTORY')
    issuers = {}
    for item in inventory['issuers']:
        shape(item,'issuer');name=common.unit_name(item['unit'])
        require(name!=PRODUCER_UNIT and name in expected and name not in issuers,'INCOMPLETE_ISSUER_INVENTORY')
        uid=common.integer(item['uid'],0,2**32-2)
        require(type(item['artifact']) is str and item['artifact'] in records
                and records[item['artifact']]['role'] in ('issuer-program','enforcer'), 'INVALID_ISSUER_ARTIFACT')
        issuers[name]=(item['artifact'],uid)
    require(set(issuers)==set(expected)-{PRODUCER_UNIT},'INCOMPLETE_ISSUER_INVENTORY')
    require(type(inventory['routes']) is list and len(inventory['routes'])==len(common.ROUTES),'INCOMPLETE_ROUTE_INVENTORY')
    routes = set();covered=set()
    for route in inventory['routes']:
        shape(route,'route')
        require(type(route['route']) is str and route['route'] in common.ROUTES and route['route'] not in routes,'INCOMPLETE_ROUTE_INVENTORY')
        routes.add(route['route']);units=unique_strings(route['units'],32)
        if route['disposition']=='GATED_DECLARED':
            require(bool(units) and set(units)<=set(issuers),'INCOMPLETE_ROUTE_INVENTORY');covered.update(units)
        else:require(route['disposition']=='ABSENT_DECLARED' and units==[],'INCOMPLETE_ROUTE_INVENTORY')
    require(covered==set(issuers),'ISSUER_ROUTE_GAP')
    unit_records={a['install_path'].rsplit('/',1)[1]:ident for ident,a in records.items() if a['role']=='unit'}
    require(set(unit_records)==set(expected),'UNIT_INVENTORY_GAP')
    return candidate,records,issuers,unit_records


def declared_graph(records, issuers, unit_records, captured):
    nodes=set(unit_records)|set(ANCHORS)
    edges={('local-fs.target','sysinit.target'),('sysinit.target','basic.target')}
    requirements={};commands=[]
    for name,ident in unit_records.items():
        parsed=common.parse_unit(captured[ident]);unit=parsed['Unit'];service=parsed['Service']
        # Require explicit refusal of automatic restart, even though systemd's
        # default currently matches. Conditions/hooks are rejected by parser.
        require(service.get('Restart')=='no','UNSAFE_SERVICE')
        artifact,uid=('producer',0) if name==PRODUCER_UNIT else issuers[name]
        require(service.get('User')==str(uid) and service.get('Group')==str(uid),'UNIT_IDENTITY_MISMATCH')
        command=service['ExecStart'].split(' ')
        require(command[0]==records[artifact]['install_path'],'UNIT_EXECUTABLE_MISMATCH')
        if name==PRODUCER_UNIT:
            require(command==[CORE['producer'][1]] and unit.get('DefaultDependencies')=='no'
                    and service.get('Type')=='oneshot','UNSUPPORTED_PRODUCER_DECLARATION')
        else:
            require(PRODUCER_UNIT in unit.get('Requires','').split()
                    and PRODUCER_UNIT in unit.get('After','').split(),'ISSUER_GATE_MISSING')
        commands.append({'unit':name,'executable_artifact':artifact})
        if unit.get('DefaultDependencies','yes')=='yes':
            edges.update({('basic.target',name),('sysinit.target',name),(name,'shutdown.target')})
        for key in ('After','Before','Requires','Wants'):
            deps=unit.get(key,'').split()
            require(set(deps)<=nodes,'UNRESOLVED_DEPENDENCY')
            if key=='After':edges.update((d,name) for d in deps)
            if key=='Before':edges.update((name,d) for d in deps)
        requirements[name]=unit.get('Requires','').split()
        for key in ('WantedBy','RequiredBy'):
            require(set(parsed.get('Install',{}).get(key,'').split())<=nodes,'UNRESOLVED_DEPENDENCY')
    remaining=set(nodes);ordered=[]
    while remaining:
        ready=sorted(n for n in remaining if not any(y==n and x in remaining for x,y in edges))
        require(bool(ready),'CYCLIC_DECLARED_GRAPH');ordered.extend(ready);remaining.difference_update(ready)
    return {'nodes':sorted(nodes),'ordering_edges':sorted([list(x) for x in edges]),'requires':requirements,
            'topological_order':ordered,'commands':sorted(commands,key=lambda x:x['unit']),
            'scope':'DECLARED_GRAPH_ONLY','native_order_verified':False,'complete_image_verified':False}


def validate(candidate_path, expected_sha256, bundle):
    require(sys.platform=='linux','UNSUPPORTED_PLATFORM')
    require(os.getuid()!=0 and os.geteuid()!=0,'ROOT_VALIDATION_REFUSED')
    candidate_path=common.absolute(candidate_path);bundle=common.absolute(bundle)
    require(str(Path(candidate_path).parent)==bundle,'CANDIDATE_OUTSIDE_BUNDLE')
    with common.DirectoryChain(bundle) as chain:
        return _validate_bundle(candidate_path,expected_sha256,bundle,chain)


def _validate_bundle(candidate_path,expected_sha256,bundle,chain):
    snapshots={}
    def verify_captures():
        chain.verify()
        directory=os.fstat(chain.fd)
        require(directory.st_uid==os.geteuid() and stat.S_IMODE(directory.st_mode)==0o700,
                'PRIVATE_BUNDLE_REQUIRED')
        for name,identity in snapshots.items():
            named=os.stat(name,dir_fd=chain.fd,follow_symlinks=False)
            require(common.identity(named)==identity,'BUNDLE_FILE_CHANGED')
    def capture(name,digest,limit):
        verify_captures()
        before=os.stat(name,dir_fd=chain.fd,follow_symlinks=False)
        data=common.captured_file(bundle+'/'+name,digest,limit)
        named=os.stat(name,dir_fd=chain.fd,follow_symlinks=False)
        require(common.identity(before)==common.identity(named),'BUNDLE_FILE_CHANGED')
        snapshots[name]=common.identity(named)
        verify_captures()
        return data
    raw=capture(Path(candidate_path).name,expected_sha256,common.MAX_REQUEST)
    candidate,records,issuers,units=declaration(raw)
    # The candidate can select only closed-role flat filenames below the
    # explicitly supplied bundle; subject/vault/lock paths never reach I/O.
    captured={}
    for ident,a in sorted(records.items()):
        require(a['filename']!=Path(candidate_path).name,'CANDIDATE_ARTIFACT_COLLISION')
        data=capture(a['filename'],a['sha256'],min(a['bytes'],MAX_ARTIFACT_BYTES))
        require(len(data)==a['bytes'],'ARTIFACT_SIZE_MISMATCH');captured[ident]=data
    graph=declared_graph(records,issuers,units,captured)
    verify_captures()
    return {'schema':RESULT_SCHEMA,'status':'PREPARED_UNATTESTED','production_origin':'UNAVAILABLE',
            'admission':'UNAVAILABLE','deployment_blocked':True,'generation':candidate['generation'],
            'candidate_sha256':common.sha(raw),
            'capture_semantics':'PINNED_CAPTURED_BYTES_NOT_A_LIVE_OR_ATOMIC_SNAPSHOT',
            'captured_artifacts':[{'id':ident,'sha256':common.sha(captured[ident]),'bytes':len(captured[ident]),
                                   'install_path':records[ident]['install_path']} for ident in sorted(captured)],
            'declarations':{'subject_opened':False,'subject_metadata_observed':False,
                            'issuer_completeness_verified':False,'source_provisioning_verified':False,
                            'artifact_runtime_closure_verified':False,'live_producer_verified':False},
            'graph':graph,'deferred_native_predicates':list(PREDICATES)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',required=True);parser.add_argument('--candidate-sha256',required=True)
    parser.add_argument('--bundle',required=True)
    args=parser.parse_args()
    try:result=validate(args.candidate,args.candidate_sha256,args.bundle)
    except (Refusal,OSError,UnicodeError,ValueError,TypeError) as error:
        code=str(error) if isinstance(error,Refusal) else 'INPUT_OR_VALIDATION_FAILURE'
        print(json.dumps({'status':'REFUSED','production_origin':'UNAVAILABLE','code':code}),file=sys.stderr);return 2
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':sys.exit(main())
