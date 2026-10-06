# Disposable v25 pending send SQL traces

Status: next-atom contract, 2026-10-06. This extends the evidence described in
[the pending claim guard design](V25-PENDING-CLAIM-GUARD-DESIGN.md); it does not
implement a producer or approve production v25 support. The atom produces
bounded traces from the actual private disposable claim/current-inspection
bodies and checks their committed SQLite deltas independently.

## Execution seam

Keep the accepted implementation unchanged. In a scratch copy, add a nested
test-only module under `podbay-store/src/external_death_v25.rs:1148`, reusing
`NativeHarness` (`:1932`), its claim/inspection calls (`:1984`, `:2001`) and
private fixture/Owner-author construction. Do not reproduce claim SQL in a
mock, add a public v25 opener, or expose the private policy in production.
Source anchors in this document are relative to `crates/`.

Call the real shared bodies at `podbay-store/src/bootstrap_send.rs:1257` and
`:1295`, and `podbay-store/src/later_turn.rs:1239` and `:1279`. Capture the
stored target and admission counters at the passed fence closure, invoke the
actual `require_live_native_send` (`external_death_v25.rs:731`), and retain its
exact Pending/FinalRecorded/Unverified conflict result. The guard must precede
fresh/retry classification; an arbitrary `StaleEpoch` refusal is insufficient.

The policy resolves an exact stored rebound-V2 subject (`:656`) and validates
it in the caller's transaction (`:517`). Even `Live` requires activated
rebind/checkpoint/resource bindings. Ordinary unrebound fresh sends are outside
this policy. `Live` also leaves all existing current-authority checks required.

Claim order is:

`BEGIN IMMEDIATE -> selected stored command -> actual v25 fence -> fresh/retry branch -> COMMIT or ROLLBACK -> reopened snapshot`.

Current inspection uses its own Deferred read transaction, with selection,
fence and current checks in the same snapshot. Passive exact-key readback uses
the existing lookup APIs (`bootstrap_send.rs:553`, `later_turn.rs:434`), plus
historical later-turn inspection (`later_turn.rs:306`). It retains original
principal/scope/key/payload checks and protected-input handling, without
turning historical uncertainty into current executable proof.

## Minimal trace contract

Use a versioned typed format, `podbay.disposable-pending-send-sql-trace/1`.
Reject unknown fields/enums and missing fields. Each fixture declares send
type, exact subject, immutable original command/receipt, schema identity and
explicit byte/count limits. Each operation records:

`sequence, fixture, transaction, operation, mode, subject, before, fence, result, finish, after`.

Operations distinguish claim, current inspection, passive exact receipt,
Pending prepare, private FinalRecorded seed, fixture Owner advancement and
competing Immediate begin. Fence values are Live/Pending/FinalRecorded/
Unverified/NotReached. Results distinguish NewClaim, ExistingUncertain,
current record, original receipt, each exact fence refusal, other store error
and SQLite DatabaseBusy. Finish records successful commit, successful rollback
or no transaction; attempted/failed commit is not a successful commit.

Canonical subject includes lineage, scope, Pod ID/incarnation, Session, Run,
Attempt, launch command rowid, latest applicable activated rebind rowid,
checkpoint digest and the complete sorted resource vector with resource/input
epochs. Retain the selected native target's exact resource anchor. Keep
original admitted Owner/manager-credential/authority counters separate from
current counters and from canonical Pending author/request bytes and digest.
Matching caller Pod fields alone cannot establish the subject.

Snapshots use a fresh connection and one consistent read transaction after
commit/rollback. Record actual schema/version and all bounded fixture
user-table rows, including command/event/outbox/lease, identity/authority/
runtime, launch/rebind and Pending/final state; retain SQLite sequence rows
where present. Encode cells by SQLite type with exact bytes and deterministic
table/column/row order. Compare canonical rows; hashes identify artifacts and
do not replace row evidence. The checker derives disposition and allowed
deltas from these rows, not solely from the producer's labels.

`NewClaim` is initially a transaction-local return. Only successful commit
and reopened row evidence establish a durable claim: precisely the selected
outbox's Prepared-to-ClaimedUncertain transition and exact claim fields.
Rollback must restore the committed Prepared snapshot. Never use SQLite
`total_changes` as durable proof: the existing test explicitly counts
rolled-back writes (`external_death_v25.rs:2296`). Do not use the frozen
migration-baseline decoder (`:750`) for post-claim snapshots or whitelist
outbox drift to make it pass. Seed commands/existing claims before staging;
positive committed-claim fixtures remain separate from later Pending prepare.

## Bounds

Retain the real decoder limits (`external_death_v25.rs:7-14`, `:121`, `:390`,
`:521`, `:586`): at most 128 Pending/final rows; canonical request at most
1,048,576 bytes individually and `INTENT_MAX_BYTES` in aggregate; identities
at most 256 UTF-8 bytes, nonempty without control characters; 1-64 strictly
sorted resources; lowercase hexadecimal digests exactly 64 bytes. Pending
aggregate row bytes are bounded by `INTENT_MAX_BYTES + 128 * (5 * 256 +
REQUEST_VERSION.len() + 64)`; final digest/outcome bytes by `128 * (64 + 9)`.
Schema 25 and every actual schema object must match the canonical schema;
schema SQL bytes must fit the existing aggregate cap. Fetch numeric byte
lengths before materializing rows; use BLOB lengths for TEXT, including
multibyte/NUL tails.

Counters and positive rowids must fit `1..=i64::MAX`; allow zero only in fields
whose actual contract allows it. Use checked increments/sums. Encode integers
losslessly, for example strict decimal strings; reject overflow, fractional
values and malformed representations. The producer must publish the compiled
numeric value of `INTENT_MAX_BYTES`, not guess it. For this atom cap fixtures
at 32, operations at 256, rows at 1,024 per table and each serialized snapshot
at 8 MiB. Check limits before allocation, including byte-encoding expansion.
Any over-limit evidence refuses; never truncate.

## Decisive scenarios

Run every applicable scenario for bootstrap and later-turn sends.

| Scenario | Required observation and durable evidence |
| --- | --- |
| Prepared then Pending | Existing private prepare commits canonical Pending plus authority revision increment; claim and separate current inspection return exact Pending refusal; refusal changes no rows. |
| Preseeded ClaimedUncertain then Pending | Retry returns Pending refusal before ExistingUncertain; current inspection also refuses; original receipt/claim key/Owner and uncertainty survive unchanged. |
| Owner advancement | After Pending, advance fixture Owner/revision/manager counters in one explicit transaction. Exact original-key passive receipt and historical uncertainty survive; retry/current inspection still give Pending refusal. This seed is not an authenticated recovery API. |
| FinalRecorded | Private final row links to validated Pending, lowercase digest and `native_outcome='uncertain'`; fresh/retry/current inspection deny with exact FinalRecorded result. No death/terminal/readiness result is emitted. |
| Valid unrelated A/B | Use the existing historical B seed (`:2231`), placing B Pending before A's admission revision. B is Pending/FinalRecorded while A is Live; A commits only its exact outbox claim transition; retry/inspection and B history have no further delta. |
| Rollback/lost response | Real body returns NewClaim, then rollback leaves reopened Prepared state identical. Separately commit and discard response; reopened exact retry returns ExistingUncertain with no delta. |
| Competing writer/order | Hold real Immediate claim transaction; explicit channel handshake and zero busy timeout produce peer DatabaseBusy. Roll back and prove no durable delta, then prepare Pending and deny. Separately signal claim entry only after Pending commit/readback; it must deny. |
| Unverified evidence | Alter digest/author/version/DDL, remove a table, corrupt final linkage or exceed budgets; exact Unverified refusal preserves rows. |

For every refusal compare committed snapshots and original passive receipt,
not only the chosen outbox. Wrong historical actor/key must not return an exact
hit; changed canonical payload must conflict. Handshakes establish database
transaction order; elapsed sleeps are not ordering evidence.

## Negative controls and acceptance

Use isolated scratch mutations and malformed traces. The suite must reject:

- Retry moved before fence; current-inspection fence omitted; decoder failure
  changed to Live. Specific Pending/Unverified outcomes catch failures that an
  incidental revision mismatch could conceal.
- Subject reduced to Pod or wrong lineage/Session/Run/Attempt/resource/input
  binding accepted; global Pending applied to unrelated A.
- Rolled-back NewClaim reported as committed; swapped snapshots; dropped,
  duplicated or reordered operation; wrong transaction finish or missing
  competing-writer Busy evidence.
- Altered original actor/key/payload treated as the same receipt;
  ExistingUncertain treated as a new claim; passive receipt treated as current
  executable proof; FinalRecorded treated as verified terminal retirement.
- Integer overflow, duplicate/unsorted resource vector, byte-budget overflow
  or multibyte/NUL-tail evidence accepted by the trace decoder.

Acceptance requires traces from the unchanged real bodies, independent exact
snapshot/delta checks, and failing negative controls for the named mutations.
Record the scratch source identity and instrumentation diff so review can
verify this boundary. The next atom is the private producer plus a bounded
trace checker, not a new v25 API or live-store experiment.

## Formal and physical boundary

Zap `ControllerCore.lean:100` has Claimable, but no Pending/FinalRecorded or
passive-receipt alphabet; it also requires ready-owner premises absent from
these SQL facts. `RestartOwnership.lean:91` requires an exact terminal
retirement record. Use a separately named bounded pending-send monitor;
do not claim universal ControllerCore/RestartOwnership refinement or fabricate
owner readiness/terminal events to fit those models.

These traces establish only the tested database order, deny behavior and
preservation of original receipts/uncertainty. They cannot establish physical
no-late-use: a previously admitted effect may already be running, and no
maintained native/OS use gate, drain or authenticated death proof exists here.
No production v25 opening, finalization, deployment, activation or live-state
mutation is authorized by this atom.
