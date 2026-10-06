# Disposable bootstrap SQL trace producer

This is a test-only implementation of the first acceptance slice in
`crates/podbay-cli/V25-PENDING-SEND-TRACE-DESIGN.md`. It creates private
disposable fixtures and instruments a scratch copy; accepted source files
are never edited. Run from the repository root:

```sh
python3 tools/pending-send-trace/run.py
```

The default scratch directory must not exist. For another run choose a fresh
child of `/fast/git/v/research/2026-10-06-podbay-pending-trace/` with `--scratch`.
The runner copies build inputs, adds one private nested test module, builds
offline/locked with its own Cargo target, and records logs, instrumentation
diff, source/tool/artifact SHA-256 hashes and exit results in `evidence.json`.
It restores the scratch bootstrap code after the mutant run. No network,
installation, live store/service, public v25 opener or authority is involved.

## Implemented acceptance

The default `/1` profile retains three bootstrap fixtures and nine operations
through the real shared claim
and current-inspection bodies, actual rebound-V2 fence and original-key
passive receipt API:

- Prepared command, then committed Pending, then exact Pending refusal for
  fresh claim and Deferred current inspection, then passive original receipt.
- Preseeded ClaimedUncertain, then committed Pending, then exact Pending
  refusal before retry/current inspection and unchanged original uncertainty.
- Live Prepared claim returns transaction-local NewClaim, explicitly rolls
  back, and reopened committed snapshot remains exactly Prepared.

`NativeHarness::history` also executes its existing wrong-principal/key and
changed-payload negative checks. Every operation captures before/after rows
through a fresh read-only connection and consistent transaction. Snapshots
include exact DDL, every fixture table and SQLite sequence state, ordered by
table name and rowid. TEXT/BLOB bytes are lowercase hex; integer cells are
strict signed decimal strings; REAL cells are outside this first format.
Canonical request bytes remain exact original JSON with bounded integer
fields. The passive receipt retains original command/event/outbox/digest
identity; it is not a current executable proof.

Bounds: three fixtures, nine operations, 128 table names (plus schema), 64
columns/table, 1,024 rows/table, 1 MiB/cell, 8 MiB/snapshot and 16 MiB/trace.
SQLite cell lengths/counts and aggregate byte expansion are checked before
materialization, followed by a serialized snapshot cap. The actual Pending
request aggregate cap is published as 4,194,304 bytes. Unknown fields,
duplicate JSON keys, invalid cell variants, noncanonical/overflowing integers,
byte overflows, row disorder and incomplete scenario coverage refuse.

The independent checker verifies the bounded scenario grammar, exact row
continuity, original command key/receipt, stored lineage/launch-slot/rebind/
runtime/resource associations, canonical Pending bytes/digest/counters,
Pending insertion plus revision delta, refusal preservation and rollback.
It requires the complete table inventory listed by captured schema. Preserved
tables compare lossless typed positional rows, including the leading implicit
rowid separately from any explicit rowid alias. The checker requires
typed equality when SQLite repeats the leading rowid alias among actual
columns; a coherently changed leading rowid is still an impossible row.
Pending insertion requires
the exact next AUTOINCREMENT rowid and matching sqlite_sequence high-water;
all other sequence cells remain exact. Live rollback requires no committed
Pending/final rows in this restricted fixture. It compares exact snapshots
for refusal/rollback. It uses neither
`total_changes` nor the frozen migration-baseline decoder after claim.

The following controls must fail the checker:

1. Scratch bootstrap code moves the actual fence below ExistingUncertain.
   The retry returns ExistingUncertain with NotReached fence; the producer
   still emits the observation and the checker rejects it.
2. A baseline trace relabels the rolled-back NewClaim as CommitSucceeded.
   The checker rejects that boundary; an unchanged snapshot is not committed
   claim evidence.
3. Remove native_writer_leases from every snapshot while retaining its schema
   entry. Complete inventory rejects the coherently omitted evidence.
4. Change implicit command rowids after Pending prepare and propagate through
   every subsequent snapshot. Typed alias equality rejects the impossible row.
   Also change only the leading command rowid by +100 in every before/after
   snapshot: unchanged deltas cannot excuse a mismatched INTEGER PRIMARY KEY
   alias. Both controls require the typed alias rejection.
5. Set Pending's sqlite_sequence to 999 and propagate through later snapshots.
   Exact high-water transition rejects it.
6. Insert canonical Pending, or Pending plus linked FinalRecorded, into both
   rollback snapshots while retaining Live/NewClaim/RollbackSucceeded labels.
   Canonical request digests and artifact hashes are recomputed; committed rows
   contradict Live even though rollback snapshots remain identical.

The runner executes baseline, code mutant and trace controls sequentially,
recording actual checker subprocess exit codes and rejection logs. Traces have
no embedded hashes; evidence.json hashes the final bytes of every artifact,
so a stale hash is never the negative-control rejection reason.

To check an artifact directly:

```sh
python3 tools/pending-send-trace/check.py /absolute/path/to/trace.json
```

## FinalRecorded extension profile

```sh
python3 tools/pending-send-trace/run.py --profile final-recorded --scratch /fast/git/v/research/2026-10-06-podbay-pending-trace/a-fresh-final-run
```

The extension format is
`podbay.disposable-pending-send-sql-trace/final-recorded/1`. It retains the
original three fixtures and appends one preseeded ClaimedUncertain bootstrap
fixture: private Pending prepare, committed private final-row seed, Immediate
retry refusal, separate Deferred current-inspection refusal and original-key
passive receipt readback. Four fixtures emit fourteen operations within the
same byte/table/cell bounds. The original format still requires exactly its
three fixtures/nine operations; unknown profiles or missing extension coverage
refuse.

The seed transaction enables foreign keys and synchronous FULL, resolves its
exact Pending key/lineage, inserts a linked final row with placeholder digest
`a` repeated 64 times and `native_outcome='uncertain'`, then commits. Reopened
snapshots establish only the durable recorded row. This seed is not an
authenticated finalization API and the placeholder proves no external death.

The checker requires the exact typed final insertion, Pending linkage,
rowid/alias and sqlite_sequence transition, with every other table unchanged.
Retry and current inspection must report FinalRecorded/DeniedFinalRecorded,
not Pending, ExistingUncertain or current executable proof. Passive readback
preserves the original receipt and native uncertainty with no snapshot delta.

The extension reruns every original control. It additionally rejects orphan
final linkage, wrong outcome, malformed digest, mismatched final-rowid alias,
sequence 999, unrelated outbox drift during the seed, FinalRecorded relabeled
as Pending/current proof, and changed original receipt/uncertainty. Mutated
snapshot evidence propagates coherently through later operations and final
artifact hashes are recomputed. The fence-after-retry code mutant also has a
separate final-specific gate: use its actually observed final fixture with
the passing baseline's first three fixtures, so an earlier Pending rejection
cannot mask a broken final fence. This composite is negative-control evidence
only, not the positive producer trace.

## Explicit omissions

Neither profile has a later-turn producer, successful committed Live claim,
lost-response retry, Owner advancement, unverified scenarios, unrelated A/B
or competing-writer handshake. FinalRecorded fresh-Prepared denial is also
outside the extension; only preseeded claimed retry/current/readback is covered.
The checker is a bounded fixture
monitor, not a complete independent replacement for the private disposition
decoder: it does not revalidate every launch descriptor, immutable send
binding digest, canonical schema against a separately pinned DDL catalogue,
or every malformed recovery case. Trace/source hashes identify evidence, not
authentication or an adversarial provenance proof.

The full design's remaining scenarios and negative controls are future atoms.
No Lean correspondence, universal ControllerCore/RestartOwnership refinement,
readiness, terminal retirement, verified death or physical no-late-use claim
follows from this producer. Previously admitted effects are not drained and
there is no maintained OS/native use gate.
