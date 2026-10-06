#!/usr/bin/env python3
"""Strict checker for the first three bootstrap scenarios, not a general SQL decoder."""
import hashlib
import json
from pathlib import Path
import re
import sys

FORMAT = 'podbay.disposable-pending-send-sql-trace/1'
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


def check_file(path):
    require(path.stat().st_size <= 16 * 1024 * 1024, 'trace file cap')
    trace = json.loads(path.read_bytes(), object_pairs_hook=duplicate_guard)
    keys(trace, 'format pending_request_cap snapshot_cap row_cap cell_cap fixtures')
    require(trace['format'] == FORMAT, 'trace format')
    require([trace[k] for k in ('pending_request_cap', 'snapshot_cap', 'row_cap', 'cell_cap')] == ['4194304', '8388608', '1024', '1048576'], 'pinned resource bounds')
    require(type(trace['fixtures']) is list and len(trace['fixtures']) == 3, 'first-scope fixture count')
    require([f['scenario'] for f in trace['fixtures']] == ['PreparedPending', 'ClaimedPending', 'Rollback'], 'scenario coverage/order')
    for f in trace['fixtures']:
        keys(f, 'scenario subject_request_hex command_id original_receipt original_effect_state operations')
        canonical, r = canonical_request(f['subject_request_hex'])
        expected_ops = ['RollbackClaim'] if f['scenario'] == 'Rollback' else ['PreparePending', 'Claim', 'CurrentInspect', 'PassiveExactReceipt']
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
            require(cmd['principal'] == 'owner.fixture' and cmd['command_key'] == 'key.native.bootstrap' and cmd['namespace'] == 'podbay.session.send.bootstrap', 'original exact key')
            require(f['original_receipt'] == [cmd['command_id'], str(cmd['event_sequence']), str(cmd['outbox_id']), cmd['digest_version'], cmd['request_digest']], 'original receipt')
            outbox = only(a['outbox'], lambda x: x['outbox_id'] == cmd['outbox_id'])
            expected_state = 'ClaimedUncertain' if f['scenario'] == 'ClaimedPending' else 'Prepared'
            require(f['original_effect_state'] == expected_state and outbox['state'] == ('claimed_uncertain' if expected_state == 'ClaimedUncertain' else 'prepared'), 'original uncertainty')
            if o['kind'] == 'PreparePending':
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
                import copy
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
            elif o['kind'] == 'RollbackClaim':
                require((o['mode'], o['fence'], o['result'], o['finish']) == ('Immediate','Live','NewClaim','RollbackSucceeded'), 'transaction-local NewClaim requires rollback, not claimed commit')
                require(not a['external_death_pending'] and not a['external_death_final'] and not b['external_death_pending'] and not b['external_death_final'], 'rollback Live contradicted by committed Pending/Final rows')
                require(o['before'] == o['after'], 'rollback durable delta')
            else:
                require(o['before'] == o['after'], 'read/refusal durable delta')
                require(len(a['external_death_pending']) == 1 and not a['external_death_final'], 'pending snapshot')
                if o['kind'] == 'PassiveExactReceipt':
                    require((o['mode'],o['fence'],o['result'],o['finish']) == ('Deferred','NotReached','ExactReceipt','CommitSucceeded'), 'passive receipt outcome')
                else:
                    require((o['fence'],o['result'],o['finish']) == ('Pending','DeniedPending','CommitSucceeded'), 'fence must deny Pending before retry/current checks')
                    require(o['mode'] == ('Deferred' if o['kind'] == 'CurrentInspect' else 'Immediate'), 'transaction mode')
            previous = o['after']
    return trace


if __name__ == '__main__':
    try:
        check_file(Path(sys.argv[1]))
    except (ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as e:
        print(f'REJECT: {e}', file=sys.stderr)
        sys.exit(1)
    print('PASS: 3 bootstrap fixtures, 9 operations; bounded SQL evidence only')
