"""Closed serial oracle for the independently reviewed disposable v25 ELF only."""
import json
import re

ELF_SHA256 = '53ca9879fbb11e999c8f1a690c4c5096976f3e8e42e20a823f0260f639fd510c'
SCHEMA = 'podbay.disposable-v25-two-boot-fixture/1'
PREFIX = 'PODBAY_V25_FIXTURE '
A_EVENTS = ['BOOT_A_STARTED','ACTIVATED_REVISION_SYNCED','PARTIAL_CONTROL_SYNCED','BOOT_A_DURABLE']
B_EVENTS = ['BOOT_B_PINNED','CLEAN_RECOVERY_AND_REFUSALS','BOOT_B_VERIFIED']
SHA = re.compile('[a-f0-9]{64}')


def positive(value, bound=(1 << 63)-1):
    return type(value) is int and 0 < value <= bound


def parse_phase(raw, phase, nonce, persistence, prior=None):
    if phase not in ('A','B') or not raw.endswith(b'\n') or b'\0' in raw or len(raw)>persistence.closed.MAX_SERIAL:
        raise ValueError('invalid bounded v25 capture')
    records=[]; kept=[]; markers=[]
    names=A_EVENTS if phase=='A' else B_EVENTS
    for line in raw.decode('utf-8',errors='strict').splitlines():
        if line.startswith(PREFIX):
            if markers:raise ValueError('v25 event after final acknowledgement')
            if len(line)>4096: raise ValueError('v25 event bound')
            item=json.loads(line[len(PREFIX):],object_pairs_hook=persistence.closed.strict_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
            if not isinstance(item,dict): raise ValueError('v25 event must be object')
            records.append(item)
        elif 'PODBAY_V25_FIXTURE' in line:
            raise ValueError('corrupt v25 event prefix')
        else:
            if line.startswith('{'):
                if len(records)!=len(names):raise ValueError('acknowledgement before complete phase events')
                item=json.loads(line,object_pairs_hook=persistence.closed.strict_object)
                markers.append(item)
                extras={'workload','child_pid','child_birth_ticks','child_exit_code','child_reaped'}
                basekeys={'event','phase','gate','admission','nonce','boot_id','boot_a','inode','marker_hex'}
                if not isinstance(item,dict) or set(item)!=basekeys|extras or item['workload']!='v25-fixture/1' or not positive(item['child_pid']) or item['child_pid']==1 or not positive(item['child_birth_ticks']) or type(item['child_exit_code']) is not int or item['child_exit_code']!=0 or item['child_reaped'] is not True:
                    raise ValueError('missing exact reaped v25 child acknowledgement')
                kept.append(json.dumps({key:item[key] for key in basekeys}))
            else: kept.append(line)
    if len(markers)!=1 or len(records)!=len(names): raise ValueError('exact phase event count required')
    marker=persistence.parse_event(('\n'.join(kept)+'\n').encode(),phase,nonce,prior['marker'] if prior else None)
    for sequence,(record,name) in enumerate(zip(records,names),1):
        if set(record)!={'schema','event','gate','admission','domain','nonce','boot_id','sequence','executable_sha256','details'} or record['schema']!=SCHEMA or record['event']!=name or record['gate']!='CLOSED' or record['admission']!='UNIMPLEMENTED' or record['domain']!='guest' or record['nonce']!=nonce or record['boot_id']!=marker['boot_id'] or type(record['sequence']) is not int or record['sequence']!=sequence or record['executable_sha256']!=ELF_SHA256 or not isinstance(record['details'],dict):
            raise ValueError('foreign, missing or out-of-order v25 event')
    if phase=='A':
        started,activated,partial,durable=(item['details'] for item in records)
        root='/fixture/podbay-v25-fixture-'+nonce
        if started!={'root':root} or set(activated)!={'authority_revision'} or not positive(activated['authority_revision']) or partial!={'constructed_control':True} or set(durable)!={'manifest_sha256','authority_revision','files','next'} or durable['authority_revision']!=activated['authority_revision'] or not positive(durable['authority_revision']) or not positive(durable['files'],64) or durable['next']!='host may kill and reap exact QEMU' or not isinstance(durable['manifest_sha256'],str) or not SHA.fullmatch(durable['manifest_sha256']):
            raise ValueError('invalid Boot-A durable assertions')
        digest=durable['manifest_sha256'];revision=durable['authority_revision']
    else:
        if prior is None: raise ValueError('Boot A provenance required')
        pinned,refused,verified=(item['details'] for item in records)
        digest=prior['manifest_sha256'];revision=prior['authority_revision']
        if pinned!={'cold_boot_verified':True,'boot_a':prior['marker']['boot_id'],'manifest_sha256':digest} or type(pinned.get('cold_boot_verified')) is not bool:
            raise ValueError('Boot-B manifest not anchored to observed Boot A')
        expected={'authority_revision':revision,'ordinary_write':'UnsupportedSchema(25)','ordinary_read':'UnsupportedSchema(25)','frozen_exchange':'refused','foreign_key':'refused'}
        if refused!=expected or type(refused.get('authority_revision')) is not int:
            raise ValueError('missing exact v25 recovery/refusal assertions')
        expected={'cold_boot_verified':True,'manifest_sha256':digest,'authority_revision':revision,'partial_control':'refused_and_unchanged','scope':'disposable persistence and refusal only'}
        if verified!=expected or type(verified.get('cold_boot_verified')) is not bool or type(verified.get('authority_revision')) is not int:
            raise ValueError('Boot-B final manifest/revision/refusal mismatch')
    return {'marker':marker,'events':records,'ack':markers[0],'manifest_sha256':digest,'authority_revision':revision}
