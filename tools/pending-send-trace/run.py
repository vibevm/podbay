#!/usr/bin/env python3
"""Offline scratch-only producer and negative controls. Never touches a live store."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = Path('/fast/git/v/research/2026-10-06-podbay-pending-trace')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scratch', type=Path, default=BASE / 'bootstrap-first')
    parser.add_argument('--profile', choices=('bootstrap', 'final-recorded'), default='bootstrap')
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    if BASE.resolve() not in scratch.parents:
        raise SystemExit('scratch must be a fresh child of the authorized research directory')
    if scratch.exists():
        raise SystemExit('scratch exists; choose a fresh --scratch child')
    scratch.mkdir(parents=True)
    source = scratch / 'source'
    # Build inputs are copied verbatim; no worker inspection or edits outside the named seams.
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', 'target', '__pycache__'))
    rel = Path('crates/podbay-store/src/external_death_v25.rs')
    bootstrap = Path('crates/podbay-store/src/bootstrap_send.rs')
    inputs = [rel, bootstrap, Path('crates/podbay-store/src/later_turn.rs'),
              Path('crates/podbay-store/src/migration_v25.rs'), Path('crates/podbay-store/src/schema_v25_delta.sql')]
    hashes = {str(p): digest(ROOT / p) for p in inputs}
    original = (source / rel).read_text()
    assert original.rstrip().endswith('}')
    snippet = (HERE / 'producer.rs').read_text()
    injected = original.rstrip()[:-1] + '\n    mod pending_trace {\n' + snippet + '\n    }\n}\n'
    (source / rel).write_text(injected)
    (scratch / 'instrumentation.patch').write_text(
        ''.join(__import__('difflib').unified_diff(original.splitlines(True), injected.splitlines(True),
                                                 fromfile=str(rel), tofile=str(rel))))
    env = os.environ.copy()
    env['CARGO_TARGET_DIR'] = str(scratch / 'target')
    env['PODBAY_PENDING_TRACE_OUTPUT'] = str(scratch / 'trace.json')
    env['PODBAY_PENDING_TRACE_PROFILE'] = args.profile
    command = ['cargo', 'test', '--offline', '--locked', '-p', 'podbay-store', '--lib',
               'pending_trace::produce_bootstrap_pending_trace', '--', '--nocapture']
    results = {}

    def cargo(label):
        with (scratch / (label + '.log')).open('wb') as log:
            p = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        results[label] = p.returncode
        print(f'{label}: cargo exit={p.returncode}', flush=True)
        if p.returncode:
            raise RuntimeError(f'{label} failed; inspect {scratch / (label + ".log")}')

    cargo('baseline')

    def checker(label, path, expected, rejection=None):
        p = subprocess.run([sys.executable, str(HERE / 'check.py'), str(path)],
                           capture_output=True, text=True)
        results[label] = p.returncode
        (scratch / (label + '.log')).write_text(p.stdout + p.stderr)
        print(f'{label}: checker exit={p.returncode}: {(p.stdout + p.stderr).strip()}', flush=True)
        if p.returncode != expected:
            raise RuntimeError(f'{label}: expected exit {expected}, got {p.returncode}')
        if rejection is not None and f'REJECT: {rejection}' not in p.stderr:
            raise RuntimeError(f'{label}: wrong rejection invariant: {p.stderr.strip()}')

    checker('baseline_checker', scratch / 'trace.json', 0)
    # Mutation changes only the scratch bootstrap body, moving its actual fence below retry.
    b = (source / bootstrap).read_text()
    start = b.index('pub(crate) fn claim_bootstrap_send_in_transaction(')
    end = b.index('pub(crate) fn inspect_claimed_bootstrap_send_in_transaction(', start)
    body = b[start:end]
    fence_start = body.index('    fence(\n')
    fence_end = body.index('    )?;\n', fence_start) + len('    )?;\n')
    fence = body[fence_start:fence_end]
    mutated = body[:fence_start] + body[fence_end:]
    anchor = '    check_current_record(transaction, lineage, &record)?;'
    assert mutated.count(anchor) == 1
    mutated = mutated.replace(anchor, fence + anchor)
    (source / bootstrap).write_text(b[:start] + mutated + b[end:])
    env['PODBAY_PENDING_TRACE_OUTPUT'] = str(scratch / 'fence-after-retry.json')
    cargo('fence-after-retry')
    checker('fence_after_retry_checker', scratch / 'fence-after-retry.json', 1)
    (source / bootstrap).write_text(b)
    baseline = json.loads((scratch / 'trace.json').read_text())
    if args.profile == 'final-recorded':
        # Isolate the actual code mutant's final fixture: keep original fixtures
        # from the passing baseline so an earlier Pending failure cannot mask it.
        observed = json.loads((scratch / 'fence-after-retry.json').read_text())
        observed['fixtures'][:3] = copy.deepcopy(baseline['fixtures'][:3])
        isolated = scratch / 'fence-after-retry-final-isolated.json'
        isolated.write_text(json.dumps(observed, separators=(',', ':')))
        checker('fence_after_retry_final_checker', isolated, 1,
                'fence must deny FinalRecorded before retry/current checks')

    def table(snapshot, name):
        return next(t for t in snapshot['tables'] if t['name'] == name)

    def set_cell(t, row, column, value):
        row[t['columns'].index(column)] = value

    def int_cell(n):
        return {'type': 'Integer', 'decimal': str(n)}

    def text_cell(s):
        return {'type': 'Text', 'hex': s.encode().hex()}

    def after_prepare(trace):
        ops = trace['fixtures'][0]['operations']
        yield ops[0]['after']
        for op in ops[1:]:
            yield op['before']
            yield op['after']

    def negative(name, mutate, rejection=None):
        trace = copy.deepcopy(baseline)
        mutate(trace)
        path = scratch / (name + '.json')
        path.write_text(json.dumps(trace, separators=(',', ':')))
        # No hashes are embedded in traces. Canonical hashes affected by a mutation
        # are recomputed below; evidence.json hashes each final artifact's actual bytes.
        checker(name + '_checker', path, 1, rejection)

    negative('rollback-as-commit', lambda t: t['fixtures'][2]['operations'][0].update(finish='CommitSucceeded'))

    def missing_inventory(trace):
        for f in trace['fixtures']:
            for op in f['operations']:
                for side in ('before', 'after'):
                    op[side]['tables'] = [t for t in op[side]['tables'] if t['name'] != 'native_writer_leases']

    negative('missing-lease-table', missing_inventory)

    def implicit_rowids(trace):
        for s in after_prepare(trace):
            for row in table(s, 'commands')['rows']:
                row[0] = int_cell(int(row[0]['decimal']) + 100)

    negative('implicit-command-rowids', implicit_rowids, 'typed implicit rowid alias mismatch')

    def all_snapshot_alias(trace):
        for f in trace['fixtures']:
            for op in f['operations']:
                for side in ('before', 'after'):
                    for row in table(op[side], 'commands')['rows']:
                        row[0] = int_cell(int(row[0]['decimal']) + 100)

    negative('all-snapshot-command-alias', all_snapshot_alias, 'typed implicit rowid alias mismatch')

    def sequence_999(trace):
        for s in after_prepare(trace):
            t = table(s, 'sqlite_sequence')
            row = next(row for row in t['rows'] if row[t['columns'].index('name')] == text_cell('external_death_pending'))
            set_cell(t, row, 'seq', int_cell(999))

    negative('pending-sequence-999', sequence_999)

    def blocked_rollback(trace, final=False):
        f = trace['fixtures'][2]
        canonical = bytes.fromhex(f['subject_request_hex'])
        request = json.loads(canonical)['request']
        template = baseline['fixtures'][0]['operations'][0]['after']
        for side in ('before', 'after'):
            s = f['operations'][0][side]
            pending = table(s, 'external_death_pending')
            pending['rows'] = copy.deepcopy(table(template, 'external_death_pending')['rows'])
            row = pending['rows'][0]
            for key in ('recovery_key', 'store_lineage', 'scope_id', 'pod_id'):
                set_cell(pending, row, key, text_cell(request[key]))
            for key in ('pod_incarnation', 'launch_command_rowid', 'activated_rebind_rowid'):
                set_cell(pending, row, key, int_cell(request[key]))
            set_cell(pending, row, 'canonical_request', {'type': 'Blob', 'hex': canonical.hex()})
            set_cell(pending, row, 'request_digest', text_cell(hashlib.sha256(canonical).hexdigest()))
            metadata = table(s, 'metadata')
            rev = next(row for row in metadata['rows'] if row[metadata['columns'].index('key')] == text_cell('authority_revision'))
            set_cell(metadata, rev, 'value', int_cell(request['expected_authority_revision'] + 1))
            table(s, 'sqlite_sequence')['rows'] = copy.deepcopy(table(template, 'sqlite_sequence')['rows'])
            if final:
                ft = table(s, 'external_death_final')
                fields = {'rowid': int_cell(1), 'final_rowid': int_cell(1), 'pending_rowid': int_cell(1),
                          'proof_digest': text_cell('a' * 64), 'native_outcome': text_cell('uncertain')}
                ft['rows'] = [[fields[c] for c in ft['columns']]]
                seq = table(s, 'sqlite_sequence')
                rowid = max(int(row[0]['decimal']) for row in seq['rows']) + 1
                fields = {'rowid': int_cell(rowid), 'name': text_cell('external_death_final'), 'seq': int_cell(1)}
                seq['rows'].append([fields[c] for c in seq['columns']])

    negative('rollback-pending-rows', blocked_rollback)
    negative('rollback-final-rows', lambda t: blocked_rollback(t, final=True))
    if args.profile == 'final-recorded':
        def after_final(trace):
            ops = trace['fixtures'][3]['operations']
            yield ops[1]['after']
            for op in ops[2:]:
                yield op['before']
                yield op['after']

        def final_field(trace, column, value):
            for s in after_final(trace):
                t = table(s, 'external_death_final')
                set_cell(t, t['rows'][0], column, value)

        negative('final-orphan-link', lambda t: final_field(t, 'pending_rowid', int_cell(999)), 'final pending linkage')
        negative('final-wrong-outcome', lambda t: final_field(t, 'native_outcome', text_cell('dead')), 'final placeholder/outcome')
        negative('final-malformed-digest', lambda t: final_field(t, 'proof_digest', text_cell('g' * 64)), 'final digest shape')

        def final_alias(trace):
            for s in after_final(trace):
                table(s, 'external_death_final')['rows'][0][0] = int_cell(101)

        negative('final-rowid-alias', final_alias, 'typed implicit rowid alias mismatch')

        def final_sequence(trace):
            for s in after_final(trace):
                t = table(s, 'sqlite_sequence')
                row = next(row for row in t['rows'] if row[t['columns'].index('name')] == text_cell('external_death_final'))
                set_cell(t, row, 'seq', int_cell(999))

        negative('final-sequence-999', final_sequence, 'exact final sequence transition')

        def final_unrelated(trace):
            for s in after_final(trace):
                t = table(s, 'outbox')
                row = next(row for row in t['rows'] if row[t['columns'].index('outbox_id')] == int_cell(2))
                set_cell(t, row, 'claim_key', text_cell('native.changed'))

        negative('final-unrelated-outbox', final_unrelated, 'final seed changed unrelated typed table outbox')

        def final_pending_label(trace):
            trace['fixtures'][3]['operations'][2].update(fence='Pending', result='DeniedPending')

        negative('final-as-pending-label', final_pending_label, 'fence must deny FinalRecorded before retry/current checks')

        def final_current_label(trace):
            trace['fixtures'][3]['operations'][3].update(result='CurrentRecord')

        negative('final-as-current-proof', final_current_label, 'fence must deny FinalRecorded before retry/current checks')

        def final_receipt(trace):
            trace['fixtures'][3]['original_receipt'][1] = '999'

        negative('final-changed-original-receipt', final_receipt, 'original receipt')

        def final_uncertainty(trace):
            trace['fixtures'][3]['original_effect_state'] = 'Prepared'

        negative('final-changed-original-uncertainty', final_uncertainty, 'original uncertainty')
    assert hashes == {str(p): digest(ROOT / p) for p in inputs}, 'accepted sources changed'
    artifacts = {p.name: digest(p) for p in scratch.iterdir() if p.is_file()}
    evidence = {'profile': args.profile, 'source_hashes': hashes,
                'tool_hashes': {name: digest(HERE / name) for name in ('producer.rs', 'run.py', 'check.py')},
                'artifacts': artifacts, 'command': command,
                'private_target': env['CARGO_TARGET_DIR'], 'results': results}
    (scratch / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(evidence, indent=2), flush=True)


if __name__ == '__main__':
    main()
