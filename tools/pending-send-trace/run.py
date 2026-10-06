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
    parser.add_argument('--profile', choices=('bootstrap', 'final-recorded', 'later-pending'), default='bootstrap')
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

    def cargo(label, expected=0, test=None, rejection=None):
        actual = command.copy()
        if test is not None:
            actual[7] = test
        with (scratch / (label + '.log')).open('wb') as log:
            p = subprocess.run(actual, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
        results[label] = p.returncode
        print(f'{label}: cargo exit={p.returncode}', flush=True)
        if p.returncode != expected:
            raise RuntimeError(f'{label} failed; inspect {scratch / (label + ".log")}')
        output = (scratch / (label + '.log')).read_text()
        if expected == 0 and '1 passed; 0 failed' not in output:
            raise RuntimeError(f'{label}: the intended test did not execute')
        if rejection is not None and rejection not in output:
            raise RuntimeError(f'{label}: intended invariant did not fail')

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
    if args.profile in ('final-recorded', 'later-pending'):
        # Isolate the actual code mutant's final fixture: keep original fixtures
        # from the passing baseline so an earlier Pending failure cannot mask it.
        observed = json.loads((scratch / 'fence-after-retry.json').read_text())
        observed['fixtures'][:3] = copy.deepcopy(baseline['fixtures'][:3])
        if args.profile == 'later-pending':
            observed['fixtures'][4] = copy.deepcopy(baseline['fixtures'][4])
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
    if args.profile in ('final-recorded', 'later-pending'):
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
    if args.profile == 'later-pending':
        later_path = source / 'crates/podbay-store/src/later_turn.rs'
        original_later = later_path.read_text()
        start = original_later.index('pub(crate) fn claim_later_codex_send_in_transaction(')
        end = original_later.index('pub(crate) fn inspect_claimed_later_codex_send_in_transaction(', start)
        body = original_later[start:end]
        fence_start = body.index('    fence(\n')
        fence_end = body.index('    )?;\n', fence_start) + len('    )?;\n')
        fence = body[fence_start:fence_end]
        changed = body[:fence_start] + body[fence_end:]
        changed = changed.replace(anchor, fence + anchor)
        later_path.write_text(original_later[:start] + changed + original_later[end:])
        env['PODBAY_PENDING_TRACE_OUTPUT'] = str(scratch / 'later-fence-after-retry.json')
        cargo('later-fence-after-retry')
        observed = json.loads((scratch / 'later-fence-after-retry.json').read_text())
        observed['fixtures'][:4] = copy.deepcopy(baseline['fixtures'][:4])
        isolated = scratch / 'later-fence-after-retry-isolated.json'
        isolated.write_text(json.dumps(observed, separators=(',', ':')))
        checker('later_fence_after_retry_checker', isolated, 1, 'fence must deny Pending before retry/current checks')
        later_path.write_text(original_later)
        cargo('later-current-authority-probe', test='pending_trace::later_current_authority_probe')
        start = original_later.index('pub(crate) fn inspect_claimed_later_codex_send_in_transaction(')
        end = original_later.index('impl PodBayStore', start)
        body = original_later[start:end]
        assert body.count(anchor) == 1
        later_path.write_text(original_later[:start] + body.replace(anchor, '    // scratch mutant: omitted current authority check') + original_later[end:])
        cargo('later-current-authority-omitted', expected=101,
              test='pending_trace::later_current_authority_probe',
              rejection='current authority revision must be rechecked')
        later_path.write_text(original_later)

        def later_snapshots(trace):
            for op in trace['fixtures'][4]['operations']:
                yield op['before']
                yield op['after']

        def later_field(trace, table_name, key, value, selection=None):
            for s in later_snapshots(trace):
                t = table(s, table_name)
                rows = t['rows'] if selection is None else [row for row in t['rows'] if row[t['columns'].index(selection[0])] == selection[1]]
                assert rows
                for row in rows:
                    set_cell(t, row, key, value)

        negative('later-Owner-epoch', lambda t: later_field(t, 'metadata', 'value', int_cell(999), ('key',text_cell('owner_epoch'))), 'later current Owner')
        negative('later-current-revision', lambda t: later_field(t, 'metadata', 'value', int_cell(999), ('key',text_cell('authority_revision'))), 'later current authority revision')
        negative('later-manager-Owner', lambda t: later_field(t, 'manager_credential_claims', 'owner_epoch', int_cell(999)), 'later manager claim authority')
        negative('later-manager-credential', lambda t: later_field(t, 'manager_credential_claims', 'credential_epoch', int_cell(999)), 'later manager claim authority')
        negative('later-manager-lineage', lambda t: later_field(t, 'manager_credential_claims', 'store_lineage', text_cell('foreign.lineage')), 'later manager claim authority')
        negative('later-Owner-role', lambda t: later_field(t, 'authority_actors', 'role', text_cell('worker'), ('actor_id',text_cell('owner.fixture'))), 'later authenticated Owner row')
        negative('later-Owner-generation', lambda t: later_field(t, 'authority_actors', 'credential_generation', int_cell(999), ('actor_id',text_cell('owner.fixture'))), 'later authenticated Owner row')
        negative('later-rebind-Owner-ahead', lambda t: later_field(t, 'manager_rebinds', 'next_owner_epoch', int_cell(999)), 'later rebind ahead of admitted authority')
        negative('later-rebind-credential-ahead', lambda t: later_field(t, 'manager_rebinds', 'next_credential_epoch', int_cell(999)), 'later rebind ahead of admitted authority')
        negative('later-prior-checkpoint', lambda t: later_field(t, 'manager_rebind_prior_observations', 'checkpoint_digest', text_cell('a' * 64)), 'later prior checkpoint')
        negative('later-rebind-input', lambda t: later_field(t, 'manager_rebind_resources', 'next_input_epoch', int_cell(999)), 'later rebind input vector')
        def later_rebind_conflict(trace):
            for s in later_snapshots(trace):
                t = table(s, 'manager_rebinds')
                row = copy.deepcopy(t['rows'][0])
                for i, column in enumerate(t['columns']):
                    if column in ('rowid', 'rebind_rowid'):
                        row[i] = int_cell(99)
                set_cell(t, row, 'phase', text_cell('pending'))
                set_cell(t, row, 'command_key', text_cell('rebind.conflicting.fixture'))
                t['rows'].append(row)
        negative('later-latest-rebind-conflict', later_rebind_conflict, 'later latest activated rebind')
        negative('later-bootstrap-anchor', lambda t: later_field(t, 'codex_later_turns', 'bootstrap_command_rowid', int_cell(2)), 'later bootstrap command anchor')
        def bootstrap_outbox_backlink(trace, orphan=False):
            launch_rowid = int_cell(json.loads(bytes.fromhex(trace['fixtures'][4]['subject_request_hex']))['request']['launch_command_rowid'])
            for s in later_snapshots(trace):
                commands = table(s, 'commands')
                key_index = commands['columns'].index('command_key')
                bootstrap_row = next(row for row in commands['rows'] if row[key_index] == text_cell('key.native.bootstrap'))
                rowid_index = commands['columns'].index('command_rowid')
                launch_row = next(row for row in commands['rows'] if row[rowid_index] == launch_rowid)
                bootstrap_rowid = bootstrap_row[rowid_index]
                wrong_rowid = int_cell(999) if orphan else launch_rowid
                assert bootstrap_rowid != wrong_rowid
                outbox = table(s, 'outbox')
                bootstrap_outbox_id = bootstrap_row[commands['columns'].index('outbox_id')]
                bo = next(row for row in outbox['rows'] if row[outbox['columns'].index('outbox_id')] == bootstrap_outbox_id)
                assert bo[outbox['columns'].index('command_rowid')] == bootstrap_rowid
                if not orphan:
                    launch_outbox_id = launch_row[commands['columns'].index('outbox_id')]
                    launch_outbox = next(row for row in outbox['rows'] if row[outbox['columns'].index('outbox_id')] == launch_outbox_id)
                    assert launch_outbox[outbox['columns'].index('command_rowid')] == launch_rowid
                    set_cell(outbox, launch_outbox, 'command_rowid', bootstrap_rowid)
                set_cell(outbox, bo, 'command_rowid', wrong_rowid)
        negative('later-bootstrap-outbox-existing-command', bootstrap_outbox_backlink, 'later bootstrap outbox back-link')
        negative('later-bootstrap-outbox-orphan-command', lambda t: bootstrap_outbox_backlink(t, orphan=True), 'later bootstrap outbox back-link')
        negative('later-thread-anchor', lambda t: later_field(t, 'codex_later_turns', 'native_thread_id', text_cell('thread.foreign.fixture')), 'later native thread anchor')
        negative('later-admitted-Owner', lambda t: later_field(t, 'codex_later_turns', 'owner_epoch', int_cell(999)), 'later admitted authority')
        negative('later-admitted-revision', lambda t: later_field(t, 'codex_later_turns', 'authority_revision', int_cell(999)), 'later admitted authority')
        negative('later-binding-digest', lambda t: later_field(t, 'codex_later_turns', 'binding_digest', text_cell('a' * 64)), 'later immutable binding digest')
        def later_command_target(trace):
            later_field(trace, 'commands', 'target_id', text_cell('session.foreign.fixture'), ('command_id',text_cell(trace['fixtures'][4]['command_id'])))
        negative('later-command-Session', later_command_target, 'later command scope/Session anchor')
        negative('later-event-anchor', lambda t: later_field(t, 'events', 'source_digest', text_cell('a' * 64), ('kind',text_cell('session.send.later.admitted'))), 'later original event anchor')
        def later_retry_label(trace):
            trace['fixtures'][4]['operations'][2].update(fence='NotReached', result='ExistingUncertain')
        negative('later-retry-before-fence-label', later_retry_label, 'fence must deny Pending before retry/current checks')
        def later_stale_label(trace):
            trace['fixtures'][4]['operations'][3].update(result='StaleEpoch')
        negative('later-stale-refusal-label', later_stale_label, 'fence must deny Pending before retry/current checks')
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
