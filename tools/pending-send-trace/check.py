#!/usr/bin/env python3
"""Strict checker for the first three bootstrap scenarios, not a general SQL decoder."""
import hashlib
import copy
import json
from pathlib import Path
import re
import sys

FORMAT = 'podbay.disposable-pending-send-sql-trace/1'
FINAL_FORMAT = 'podbay.disposable-pending-send-sql-trace/final-recorded/1'
LATER_FORMAT = 'podbay.disposable-pending-send-sql-trace/later-pending/1'
CAP = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected.split()), 'unknown/missing fields')


def integer(value, positive=False):
    require(type(value) is str and re.fullmatch(r'0|-?[1-9][0-9]*', value), 'noncanonical integer')
    n = int(value)
    require(-(2**63) <= n < 2**63 and (not positive or n > 0), 'integer bounds')
    return n


def raw(value):
    require(type(value) is str and len(value) <= 2 * 1024 * 1024 and re.fullmatch(r'(?:[0-9a-f]{2})*', value), 'hex byte bounds')
    return bytes.fromhex(value)


def cell(value):
    require(type(value) is dict and 'type' in value, 'cell type')
    if value['type'] == 'Null':
        keys(value, 'type')
        return None
    if value['type'] == 'Integer':
        keys(value, 'type decimal')
        return integer(value['decimal'])
    require(value['type'] in ('Text', 'Blob'), 'unsupported cell type')
    keys(value, 'type hex')
    b = raw(value['hex'])
    return b.decode('utf-8') if value['type'] == 'Text' else b


def snapshot(s):
    keys(s, 'schema_version tables')
    require(s['schema_version'] == '25', 'schema version')
    require(len(json.dumps(s, separators=(',', ':')).encode()) <= CAP, 'snapshot byte cap')
    require(type(s['tables']) is list and len(s['tables']) <= 129, 'table count cap')
    tables = {}
    names = []
    for t in s['tables']:
        keys(t, 'name columns rows')
        require(type(t['name']) is str and len(t['name'].encode()) <= 256, 'table name')
        require(t['name'] not in tables, 'duplicate table')
        require(type(t['columns']) is list and 1 <= len(t['columns']) <= 64, 'column count')
        require(all(type(c) is str and len(c.encode()) <= 256 for c in t['columns']), 'column names')
        # SQLite may name SELECT rowid after its INTEGER PRIMARY KEY alias.
        require(len(t['columns']) >= 2 and len(t['columns'][1:]) == len(set(t['columns'][1:])), 'positional column identity')
        require('__implicit_rowid' not in t['columns'], 'reserved implicit rowid name')
        require(type(t['rows']) is list and len(t['rows']) <= 1024, 'row count')
        rows = []
        order = []
        for row in t['rows']:
            require(type(row) is list and len(row) == len(t['columns']), 'row width')
            values = [cell(c) for c in row]
            require(type(values[0]) is int, 'rowid type')
            if t['columns'][0] in t['columns'][1:]:
                alias_index = t['columns'][1:].index(t['columns'][0]) + 1
                require(row[0] == row[alias_index], 'typed implicit rowid alias mismatch')
            order.append(values[0])
            # Decoded lookup views never overwrite the leading implicit rowid.
            # Preservation below compares original typed positional rows, not this view.
            record = dict(zip(t['columns'][1:], values[1:]))
            record['__implicit_rowid'] = values[0]
            rows.append(record)
        require(order == sorted(set(order)), 'row order/uniqueness')
        tables[t['name']] = rows
        names.append(t['name'])
    require(names[0] == 'sqlite_schema' and names[1:] == sorted(names[1:]), 'table order')
    inventory = [row['name'] for row in tables['sqlite_schema'] if row['type'] == 'table']
    require(len(inventory) == len(set(inventory)) and set(names) == set(inventory) | {'sqlite_schema'}, 'complete schema table inventory')
    return tables


def positional(s):
    return {t['name']: t for t in s['tables']}


def integer_cell(n):
    integer(str(n))
    return {'type': 'Integer', 'decimal': str(n)}


def final_seed(a, b, pa, pb):
    require(len(a['external_death_pending']) == 1 and not a['external_death_final'] and len(b['external_death_final']) == 1, 'final seed row count/linkage')
    pending = a['external_death_pending'][0]
    final = b['external_death_final'][0]
    require(final['pending_rowid'] == pending['pending_rowid'], 'final pending linkage')
    require(type(final['proof_digest']) is str and re.fullmatch('[0-9a-f]{64}', final['proof_digest']), 'final digest shape')
    require(final['proof_digest'] == 'a' * 64 and final['native_outcome'] == 'uncertain', 'final placeholder/outcome')
    before_seq = [x for x in a['sqlite_sequence'] if x['name'] == 'external_death_final']
    require(len(before_seq) <= 1, 'duplicate final sequence')
    prior = before_seq[0]['seq'] if before_seq else 0
    require(type(prior) is int and 0 <= prior < 2**63 - 1 and final['final_rowid'] == prior + 1, 'final next rowid')
    columns = pa['external_death_final']['columns']
    require(columns[0] in ('rowid', 'final_rowid') and columns[1:] == ['final_rowid', 'pending_rowid', 'proof_digest', 'native_outcome'], 'final column identity')
    fields = {'rowid': integer_cell(prior + 1), 'final_rowid': integer_cell(prior + 1),
              'pending_rowid': integer_cell(pending['pending_rowid']),
              'proof_digest': {'type': 'Text', 'hex': ('a' * 64).encode().hex()},
              'native_outcome': {'type': 'Text', 'hex': b'uncertain'.hex()}}
    expected_final = copy.deepcopy(pa['external_death_final'])
    expected_final['rows'] = [[fields[c] for c in columns]]
    require(expected_final == pb['external_death_final'], 'exact typed final insertion')
    for name in pa:
        if name not in ('external_death_final', 'sqlite_sequence'):
            require(pa[name] == pb[name], 'final seed changed unrelated typed table ' + name)
    expected_sequence = copy.deepcopy(pa['sqlite_sequence'])
    columns = expected_sequence['columns']
    if before_seq:
        row = only(expected_sequence['rows'], lambda x: cell(x[columns.index('name')]) == 'external_death_final')
        row[columns.index('seq')] = integer_cell(prior + 1)
    else:
        rowid = max((x['__implicit_rowid'] for x in a['sqlite_sequence']), default=0) + 1
        fields = {'rowid': integer_cell(rowid), 'name': {'type': 'Text', 'hex': b'external_death_final'.hex()}, 'seq': integer_cell(prior + 1)}
        require(set(columns) == set(fields), 'sequence column identity')
        expected_sequence['rows'].append([fields[c] for c in columns])
    require(expected_sequence == pb['sqlite_sequence'], 'exact final sequence transition')


def only(rows, predicate):
    chosen = [r for r in rows if predicate(r)]
    require(len(chosen) == 1, 'missing/ambiguous exact row')
    return chosen[0]


def metadata(t, key):
    return only(t['metadata'], lambda r: r['key'] == key)['value']


def duplicate_guard(pairs):
    d = {}
    for key, value in pairs:
        require(key not in d, 'duplicate JSON key')
        d[key] = value
    return d


def canonical_request(hex_value):
    b = raw(hex_value)
    require(0 < len(b) <= 1048576, 'canonical request cap')
    c = json.loads(b, object_pairs_hook=duplicate_guard)
    keys(c, 'version author author_scope request')
    require(c['version'] == 'podbay.external-death-pending-request/1', 'request version')
    r = c['request']
    keys(r, 'recovery_key store_lineage scope_id pod_id pod_incarnation session_id run_id attempt_id launch_command_rowid activated_rebind_rowid checkpoint_digest resources expected_owner_epoch expected_manager_credential_epoch expected_authority_revision')
    for k in ('recovery_key', 'store_lineage', 'scope_id', 'pod_id', 'session_id', 'run_id', 'attempt_id'):
        v = r[k]
        require(type(v) is str and 0 < len(v.encode()) <= 256 and not any(ord(ch) < 32 or ord(ch) == 127 for ch in v), 'identity bounds')
    require(c['author_scope'] == r['scope_id'] and c['author'] == 'owner.fixture', 'canonical author')
    for k in ('pod_incarnation', 'launch_command_rowid', 'activated_rebind_rowid', 'expected_owner_epoch', 'expected_manager_credential_epoch', 'expected_authority_revision'):
        require(type(r[k]) is int and 0 < r[k] < 2**63, 'request counter bounds')
    require(re.fullmatch('[0-9a-f]{64}', r['checkpoint_digest']), 'checkpoint digest')
    require(type(r['resources']) is list and 1 <= len(r['resources']) <= 64, 'resource count')
    ids = []
    for resource in r['resources']:
        keys(resource, 'resource_id resource_epoch input_epoch')
        require(type(resource['resource_id']) is str and 0 < len(resource['resource_id'].encode()) <= 256, 'resource identity')
        ids.append(resource['resource_id'])
        require(all(type(resource[k]) is int and 0 < resource[k] < 2**63 for k in ('resource_epoch', 'input_epoch')), 'resource epochs')
    require(ids == sorted(set(ids)), 'resource order')
    require(json.dumps(c, separators=(',', ':'), ensure_ascii=False).encode() == b, 'canonical JSON bytes')
    return b, r


def subject(t, r):
    require(only(t['store_identity'], lambda x: x['singleton'] == 1)['lineage'] == r['store_lineage'], 'lineage')
    launch = only(t['launch_slots'], lambda x: x['command_rowid'] == r['launch_command_rowid'])
    require(all(launch[k] == r[k] for k in ('scope_id', 'pod_id', 'pod_incarnation')), 'launch slot binding')
    rebind = only(t['manager_rebinds'], lambda x: x['rebind_rowid'] == r['activated_rebind_rowid'])
    require(rebind['phase'] == 'activated' and rebind['pod_checkpoint_ref'] == r['checkpoint_digest'], 'activated checkpoint')
    require(all(rebind[k] == r[k] for k in ('store_lineage', 'scope_id', 'pod_id', 'pod_incarnation', 'attempt_id')), 'rebind subject')
    resources = sorted((x for x in t['authority_resources'] if x['pod_id'] == r['pod_id']), key=lambda x: x['resource_id'])
    require([{k: x[k] for k in ('resource_id', 'resource_epoch', 'input_epoch')} for x in resources] == r['resources'], 'complete resource binding')
    session = only(t['runtime_sessions'], lambda x: x['session_id'] == r['session_id'])
    run = only(t['runtime_runs'], lambda x: x['run_id'] == r['run_id'])
    require(session['scope_id'] == r['scope_id'] and session['current_run_id'] == r['run_id'], 'session binding')
    require(run['session_id'] == r['session_id'] and run['current_attempt_id'] == r['attempt_id'], 'run/attempt binding')


def later_authority(t, r):
    owner, credential, revision = r['expected_owner_epoch'], r['expected_manager_credential_epoch'], r['expected_authority_revision']
    require(metadata(t, 'owner_epoch') == owner, 'later current Owner')
    require(metadata(t, 'authority_revision') == revision + bool(t['external_death_pending']), 'later current authority revision')
    claim = only(t['manager_credential_claims'], lambda x: x['singleton'] == 1)
    require(claim['store_lineage'] == r['store_lineage'] and claim['owner_epoch'] == owner and claim['credential_epoch'] == credential and credential >= owner, 'later manager claim authority')
    actor = only(t['authority_actors'], lambda x: x['actor_id'] == 'owner.fixture')
    require([actor[k] for k in ('scope_id','role','origin','parent_actor_id','pod_id','pod_incarnation','credential_generation')] == [r['scope_id'],'coordinator','owner_cli',None,None,None,1], 'later authenticated Owner row')
    pod = only(t['authority_pods'], lambda x: x['pod_id'] == r['pod_id'])
    epoch = only(t['target_epochs'], lambda x: x['scope_id'] == r['scope_id'] and x['target_id'] == r['pod_id'])
    require(pod['scope_id'] == r['scope_id'] and pod['incarnation'] == r['pod_incarnation'] and epoch['epoch'] == r['pod_incarnation'], 'later Pod incarnation authority')
    session = only(t['runtime_sessions'], lambda x: x['session_id'] == r['session_id'])
    run = only(t['runtime_runs'], lambda x: x['run_id'] == r['run_id'])
    require(session['state'] == 'open' and run['scope_id'] == r['scope_id'] and run['admission_state'] == 'admitted' and run['desired_mode'] == 'run' and run['execution_state'] in ('starting','running') and run['last_attempt_ordinal'] == 1, 'later runtime authority state')
    resources = [x for x in t['authority_resources'] if x['pod_id'] == r['pod_id']]
    require(all(x['scope_id'] == r['scope_id'] and x['pod_incarnation'] == r['pod_incarnation'] for x in resources), 'later resource association')
    rebinds = [x for x in t['manager_rebinds'] if x['scope_id'] == r['scope_id'] and x['pod_id'] == r['pod_id'] and x['pod_incarnation'] == r['pod_incarnation']]
    current = only(rebinds, lambda x: x['rebind_rowid'] == r['activated_rebind_rowid'])
    require(type(current['next_owner_epoch']) is int and type(current['next_credential_epoch']) is int and 0 < current['next_owner_epoch'] <= owner and 0 < current['next_credential_epoch'] <= credential, 'later rebind ahead of admitted authority')
    require(current['resource_count'] == len(r['resources']), 'later rebind resource count')
    require(all(x['phase'] == 'activated' and x['rebind_rowid'] <= current['rebind_rowid'] and x['next_owner_epoch'] <= current['next_owner_epoch'] for x in rebinds), 'later latest activated rebind')
    require(not any(x['scope_id'] == r['scope_id'] and x['pod_id'] == r['pod_id'] and x['pod_incarnation'] == r['pod_incarnation'] for x in t['rebind_supersession_attempts']), 'later rebind supersession')
    prior = only(t['manager_rebind_prior_observations'], lambda x: x['rebind_rowid'] == r['activated_rebind_rowid'])
    require(prior['checkpoint_digest'] == r['checkpoint_digest'], 'later prior checkpoint')
    next_resources = sorted((x for x in t['manager_rebind_resources'] if x['rebind_rowid'] == r['activated_rebind_rowid']), key=lambda x: x['resource_id'])
    require([(x['resource_id'],x['next_input_epoch']) for x in next_resources] == [(x['resource_id'],x['input_epoch']) for x in r['resources']], 'later rebind input vector')


def later_anchor(t, r, cmd):
    require(cmd['scope_id'] == r['scope_id'] and cmd['target_id'] == r['session_id'], 'later command scope/Session anchor')
    binding = only(t['codex_later_turns'], lambda x: x['command_rowid'] == cmd['command_rowid'])
    for k in ('store_lineage','scope_id','session_id','run_id','attempt_id','pod_id','pod_incarnation'):
        require(binding[k] == r[k], 'later stored subject anchor')
    require(any(binding['resource_id'] == x['resource_id'] and binding['resource_epoch'] == x['resource_epoch'] and binding['resource_input_epoch'] == x['input_epoch'] for x in r['resources']), 'later resource input anchor')
    require(binding['owner_epoch'] == r['expected_owner_epoch'] and binding['manager_credential_epoch'] == r['expected_manager_credential_epoch'] and binding['authority_revision'] == r['expected_authority_revision'] and cmd['owner_epoch'] == binding['owner_epoch'], 'later admitted authority')
    require(binding['holder_actor_id'] == cmd['principal'] == 'owner.fixture' and binding['holder_credential_generation'] == 1, 'later holder identity')
    session = only(t['runtime_sessions'], lambda x: x['session_id'] == r['session_id'])
    require(binding['session_revision'] == cmd['target_epoch'] == session['revision'], 'later Session revision anchor')
    # Bounded independent decoder for the five-field immutable later payload.
    payload = cmd['canonical_request']
    domain = b'podbay.codex.later-send/1\0'
    require(type(payload) is bytes and len(payload) <= 128000 and payload.startswith(domain), 'later payload domain/budget')
    at, fields = len(domain), []
    for _ in range(5):
        require(at + 4 <= len(payload), 'later payload field length')
        length = int.from_bytes(payload[at:at+4], 'big')
        at += 4
        require(at + length <= len(payload), 'later payload truncated')
        fields.append(payload[at:at+length].decode('utf-8'))
        at += length
    require(at == len(payload), 'later payload trailing bytes')
    wire, deadline, text, bootstrap_id, thread = fields
    require(re.fullmatch('[0-9a-f]{64}', wire) and 0 < len(text.encode()) <= 64000, 'later payload digest/text')
    require(thread == binding['native_thread_id'] == 'thread.native.fixture', 'later native thread anchor')
    require(binding['wire_payload_digest'] == wire and binding['prompt_digest'] == hashlib.sha256(text.encode()).hexdigest(), 'later prompt digest anchor')
    bootstrap = only(t['commands'], lambda x: x['command_rowid'] == binding['bootstrap_command_rowid'])
    require(bootstrap['command_id'] == bootstrap_id and bootstrap['namespace'] == 'podbay.session.send.bootstrap' and bootstrap['command_key'] == 'key.native.bootstrap' and bootstrap['scope_id'] == cmd['scope_id'] and bootstrap['target_id'] == cmd['target_id'], 'later bootstrap command anchor')
    bb = only(t['codex_bootstrap_sends'], lambda x: x['command_rowid'] == bootstrap['command_rowid'])
    require(all(bb[k] == binding[k] for k in ('store_lineage','scope_id','session_id','run_id','attempt_id','pod_id','pod_incarnation','resource_id','resource_epoch','holder_actor_id','holder_credential_generation')) and bb['resource_input_epoch'] <= binding['resource_input_epoch'], 'later bootstrap resource anchor')
    bo = only(t['outbox'], lambda x: x['outbox_id'] == bootstrap['outbox_id'])
    require(bo['command_rowid'] == bootstrap['command_rowid'], 'later bootstrap outbox back-link')
    require(bo['state'] == 'claimed_uncertain' and bo['claim_key'] == 'claim.' + bootstrap_id and bo['claim_owner_epoch'] == bootstrap['owner_epoch'], 'later claimed bootstrap anchor')
    numbers = [binding[k] for k in ('session_revision','pod_incarnation','resource_epoch','resource_input_epoch','holder_credential_generation','owner_epoch','manager_credential_epoch','authority_revision','writer_epoch','lease_expires_at_unix_seconds')]
    require(all(type(n) is int and 0 < n < 2**63 for n in numbers), 'later admitted integer bounds')
    strings = [binding[k] for k in ('store_lineage','scope_id','session_id','run_id','attempt_id','pod_id','resource_id')] + [bootstrap_id,thread,binding['holder_actor_id'],wire,binding['prompt_digest']]
    body = b'podbay.codex.later-binding/1\0'
    for s in strings:
        raw_field = s.encode()
        body += len(raw_field).to_bytes(4, 'big') + raw_field
    body += b''.join(n.to_bytes(8, 'big') for n in numbers)
    require(binding['binding_digest'] == hashlib.sha256(body).hexdigest(), 'later immutable binding digest')
    outbox = only(t['outbox'], lambda x: x['outbox_id'] == cmd['outbox_id'])
    require(outbox['command_rowid'] == cmd['command_rowid'] and outbox['kind'] == 'codex.turn' and outbox['payload'] == payload and outbox['effect_digest'] == hashlib.sha256(payload).hexdigest() and outbox['claim_key'] == 'claim.' + cmd['command_id'] and outbox['claim_owner_epoch'] == cmd['owner_epoch'], 'later original outbox anchor')
    require(outbox['scope_id'] == cmd['scope_id'] and outbox['target_id'] == cmd['target_id'] and outbox['owner_epoch'] == cmd['owner_epoch'] and outbox['target_epoch'] == cmd['target_epoch'] and all(outbox[k] is None for k in ('observation_key','observation_payload','observation_stage','observation_event_sequence')), 'later outbox scalar/observation anchor')
    event = only(t['events'], lambda x: x['sequence'] == cmd['event_sequence'] and x['command_rowid'] == cmd['command_rowid'])
    expected = {'kind': 'session.send.later.admitted', 'payload': binding['binding_digest'].encode(), 'scope_id': cmd['scope_id'], 'target_id': cmd['target_id'], 'owner_epoch': cmd['owner_epoch'], 'target_epoch': cmd['target_epoch'], 'source_id': cmd['command_id'], 'source_kind': 'manager.admission', 'source_digest': cmd['request_digest'], 'source_epoch': cmd['owner_epoch'], 'source_sequence': 1, 'provenance': 'authenticated.manager.admission'}
    require(all(event[k] == v for k,v in expected.items()), 'later original event anchor')


def check_file(path):
    require(path.stat().st_size <= 16 * 1024 * 1024, 'trace file cap')
    trace = json.loads(path.read_bytes(), object_pairs_hook=duplicate_guard)
    keys(trace, 'format pending_request_cap snapshot_cap row_cap cell_cap fixtures')
    require(trace['format'] in (FORMAT, FINAL_FORMAT, LATER_FORMAT), 'trace format')
    require([trace[k] for k in ('pending_request_cap', 'snapshot_cap', 'row_cap', 'cell_cap')] == ['4194304', '8388608', '1024', '1048576'], 'pinned resource bounds')
    scenarios = ['PreparedPending', 'ClaimedPending', 'Rollback']
    if trace['format'] in (FINAL_FORMAT, LATER_FORMAT):
        scenarios.append('FinalRecorded')
    if trace['format'] == LATER_FORMAT:
        scenarios.append('LaterClaimedPending')
    require(type(trace['fixtures']) is list and len(trace['fixtures']) == len(scenarios), 'profile fixture count')
    require([f['scenario'] for f in trace['fixtures']] == scenarios, 'scenario coverage/order')
    for f in trace['fixtures']:
        keys(f, 'scenario subject_request_hex command_id original_receipt original_effect_state operations')
        canonical, r = canonical_request(f['subject_request_hex'])
        expected_ops = ['RollbackClaim'] if f['scenario'] == 'Rollback' else ['PreparePending', 'Claim', 'CurrentInspect', 'PassiveExactReceipt']
        if f['scenario'] == 'FinalRecorded':
            expected_ops.insert(1, 'SeedFinalRecorded')
        later = f['scenario'] == 'LaterClaimedPending'
        if later:
            expected_ops.insert(0, 'CurrentInspect')
        require([o['kind'] for o in f['operations']] == expected_ops, 'operation coverage/order')
        previous = None
        for index, o in enumerate(f['operations'], 1):
            keys(o, 'sequence kind mode fence result finish before after')
            require(o['sequence'] == str(index), 'operation sequence')
            if previous is not None:
                require(o['before'] == previous, 'snapshot continuity')
            a, b = snapshot(o['before']), snapshot(o['after'])
            pa, pb = positional(o['before']), positional(o['after'])
            require(set(pa) == set(pb), 'table inventory drift')
            subject(a, r)
            subject(b, r)
            cmd = only(a['commands'], lambda x: x['command_id'] == f['command_id'])
            require(cmd['principal'] == 'owner.fixture' and cmd['command_key'] == ('key.native.later' if later else 'key.native.bootstrap') and cmd['namespace'] == ('podbay.session.send.later' if later else 'podbay.session.send.bootstrap'), 'original exact key')
            if later:
                later_authority(a, r)
                later_authority(b, r)
                later_anchor(a, r, cmd)
                later_anchor(b, r, only(b['commands'], lambda x: x['command_id'] == f['command_id']))
            require(f['original_receipt'] == [cmd['command_id'], str(cmd['event_sequence']), str(cmd['outbox_id']), cmd['digest_version'], cmd['request_digest']], 'original receipt')
            outbox = only(a['outbox'], lambda x: x['outbox_id'] == cmd['outbox_id'])
            expected_state = 'ClaimedUncertain' if f['scenario'] in ('ClaimedPending', 'FinalRecorded', 'LaterClaimedPending') else 'Prepared'
            require(f['original_effect_state'] == expected_state and outbox['state'] == ('claimed_uncertain' if expected_state == 'ClaimedUncertain' else 'prepared'), 'original uncertainty')
            if later and index == 1:
                require((o['mode'],o['fence'],o['result'],o['finish']) == ('Deferred','Live','CurrentRecord','CommitSucceeded'), 'later initial Live current inspection')
                require(not a['external_death_pending'] and not a['external_death_final'] and o['before'] == o['after'], 'later initial Live snapshot')
            elif o['kind'] == 'PreparePending':
                require((o['mode'], o['fence'], o['result'], o['finish']) == ('Immediate', 'NotReached', 'PendingCommitted', 'CommitSucceeded'), 'prepare outcome')
                require(not a['external_death_pending'] and len(b['external_death_pending']) == 1, 'pending insertion')
                pending = b['external_death_pending'][0]
                require(pending['canonical_request'] == canonical and pending['request_digest'] == hashlib.sha256(canonical).hexdigest(), 'canonical pending bytes/digest')
                require(all(pending[k] == r[k] for k in ('recovery_key','store_lineage','scope_id','pod_id','pod_incarnation','launch_command_rowid','activated_rebind_rowid')), 'exact pending binding')
                require(pending['authenticated_author'] == 'owner.fixture' and pending['request_version'] == 'podbay.external-death-pending-request/1', 'pending author/version')
                require(pending['preparing_owner_epoch'] == r['expected_owner_epoch'] and pending['preparing_authority_revision'] == r['expected_authority_revision'] + 1, 'pending counters')
                require(pending['__implicit_rowid'] == pending['pending_rowid'], 'pending rowid alias')
                require(metadata(a, 'authority_revision') == r['expected_authority_revision'] and metadata(b, 'authority_revision') == r['expected_authority_revision'] + 1, 'revision CAS delta')
                for name in a:
                    if name not in ('metadata','external_death_pending','sqlite_sequence'):
                        require(pa[name] == pb[name], 'prepare changed unrelated typed table ' + name)
                require(pa['external_death_pending']['columns'] == pb['external_death_pending']['columns'], 'pending columns drift')
                # Only the exact authority_revision value cell may change in metadata.
                expected_metadata = copy.deepcopy(pa['metadata'])
                columns = expected_metadata['columns']
                row = only(expected_metadata['rows'], lambda x: cell(x[columns.index('key')]) == 'authority_revision')
                row[columns.index('value')] = integer_cell(r['expected_authority_revision'] + 1)
                require(expected_metadata == pb['metadata'], 'prepare typed metadata drift')
                # Empty pending table plus AUTOINCREMENT implies one exact next rowid/high-water.
                before_seq = [x for x in a['sqlite_sequence'] if x['name'] == 'external_death_pending']
                require(len(before_seq) <= 1, 'duplicate pending sequence')
                prior = before_seq[0]['seq'] if before_seq else 0
                require(type(prior) is int and 0 <= prior < 2**63 - 1 and pending['pending_rowid'] == prior + 1, 'pending next rowid')
                expected_sequence = copy.deepcopy(pa['sqlite_sequence'])
                columns = expected_sequence['columns']
                if before_seq:
                    row = only(expected_sequence['rows'], lambda x: cell(x[columns.index('name')]) == 'external_death_pending')
                    row[columns.index('seq')] = integer_cell(prior + 1)
                else:
                    rowid = max((x['__implicit_rowid'] for x in a['sqlite_sequence']), default=0) + 1
                    values = {'rowid': integer_cell(rowid), 'name': {'type': 'Text', 'hex': b'external_death_pending'.hex()}, 'seq': integer_cell(prior + 1)}
                    require(set(columns) == set(values), 'sequence column identity')
                    expected_sequence['rows'].append([values[k] for k in columns])
                require(expected_sequence == pb['sqlite_sequence'], 'exact pending sequence transition')
            elif o['kind'] == 'SeedFinalRecorded':
                require(f['scenario'] == 'FinalRecorded' and (o['mode'], o['fence'], o['result'], o['finish']) == ('Immediate', 'NotReached', 'FinalRecordedSeeded', 'CommitSucceeded'), 'private final seed outcome')
                final_seed(a, b, pa, pb)
            elif o['kind'] == 'RollbackClaim':
                require((o['mode'], o['fence'], o['result'], o['finish']) == ('Immediate','Live','NewClaim','RollbackSucceeded'), 'transaction-local NewClaim requires rollback, not claimed commit')
                require(not a['external_death_pending'] and not a['external_death_final'] and not b['external_death_pending'] and not b['external_death_final'], 'rollback Live contradicted by committed Pending/Final rows')
                require(o['before'] == o['after'], 'rollback durable delta')
            else:
                require(o['before'] == o['after'], 'read/refusal durable delta')
                require(len(a['external_death_pending']) == 1, 'pending snapshot')
                final_recorded = f['scenario'] == 'FinalRecorded'
                if final_recorded:
                    require(len(a['external_death_final']) == 1, 'final snapshot')
                    final = a['external_death_final'][0]
                    require(final['pending_rowid'] == a['external_death_pending'][0]['pending_rowid'] and final['proof_digest'] == 'a' * 64 and final['native_outcome'] == 'uncertain', 'final snapshot linkage/placeholder')
                else:
                    require(not a['external_death_final'], 'pending snapshot')
                if o['kind'] == 'PassiveExactReceipt':
                    require((o['mode'],o['fence'],o['result'],o['finish']) == ('Deferred','NotReached','ExactReceipt','CommitSucceeded'), 'passive receipt outcome')
                else:
                    expected = ('FinalRecorded', 'DeniedFinalRecorded', 'CommitSucceeded') if final_recorded else ('Pending','DeniedPending','CommitSucceeded')
                    require((o['fence'],o['result'],o['finish']) == expected, 'fence must deny FinalRecorded before retry/current checks' if final_recorded else 'fence must deny Pending before retry/current checks')
                    require(o['mode'] == ('Deferred' if o['kind'] == 'CurrentInspect' else 'Immediate'), 'transaction mode')
            previous = o['after']
    return trace


if __name__ == '__main__':
    try:
        trace = check_file(Path(sys.argv[1]))
    except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as e:
        print(f'REJECT: {e}', file=sys.stderr)
        sys.exit(1)
    count = len(trace['fixtures'])
    operations = sum(len(f['operations']) for f in trace['fixtures'])
    label = 'native-send' if trace['format'] == LATER_FORMAT else 'bootstrap'
    print(f'PASS: {count} {label} fixtures, {operations} operations; bounded SQL evidence only')
