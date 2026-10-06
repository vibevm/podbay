# Disposable v25 pending claim guard

Status: restricted disposable integration, 2026-10-06, following `333d282`.
The private transaction-local disposition decoder and both bootstrap/later
native-send claim/current-inspection bodies are implemented for rebound V2
recovery candidates. The guard runs before fresh and `ExistingUncertain`
classification; passive exact-key receipts remain separate. Parent full
`podbay-store` suite passed 236/236 and independent review closed the
latest-activated-rebind P2. A valid unrelated A subject remains Live while B
is Pending/FinalRecorded in the private fixture. No production v25 opener,
authority, finalizer or maintained effect-use gate exists. Anchors are relative
to `crates/` and name
the inspected source. This bounds the next atom from
[the claim/use fence map](EXTERNAL-DEATH-CLAIM-FENCE-MAP.md).

## Transaction-local disposition

The internal decoder takes the caller's `&Transaction` and an exact rebound
V2 recovery subject. Ordinary fresh native-send subject resolution remains to
be implemented before claim integration. Its results are store
facts, with no native permission:

| Result | Meaning at the selected snapshot |
| --- | --- |
| `Live` | Supported schema and exact binding validated; no applicable pending/final record. The claim's existing current-authority checks must still pass. |
| `Pending` | One canonical pending record binds this exact subject. Refuse claim/current executable proof. |
| `FinalRecorded` | A structurally valid final record links to the validated pending subject. Refuse claim/current executable proof; this does not verify death. |
| `Unverified` | Missing, malformed, unsupported, inconsistent, inaccessible or over-budget evidence. Refuse; never fall back to `Live`. |

Validate schema 25 and exact schema objects using the canonical schema at
`podbay-store/src/migration_v25.rs:1705`; read the actual schema through the
caller's transaction. Refactor the bounded pending-row validation at
`podbay-store/src/external_death_v25.rs:385` to retain its validated request and
subject. Check canonical author/request bytes and digest, lineage, row
uniqueness, launch/rebind/checkpoint linkage, complete resource/input binding,
counter consistency and final-to-pending linkage in that snapshot. Resolve
Session/Run/resource targets through stored rows; caller Pod fields alone do
not establish the subject. Multiple pending records for one subject refuse.

The final table already exists at `podbay-store/src/schema_v25_delta.sql:28`.
It has a pending reference, proof digest and `native_outcome='uncertain'`, but
no proof-format verifier or authenticated finalization API. `FinalRecorded`
therefore means only a blocking recorded fact. If a caller requires verified
final proof semantics, return `Unverified` for that unsupported proof instead.
No finalization constructor is needed for these negative tests. The private
Owner-author boundary at `podbay-store/src/external_death_v25.rs:14` stays
private; disposable tests may use its existing private construction path.

## Claim and readback seams

The implementation extracts shared transaction bodies for
`podbay-store/src/bootstrap_send.rs:1249` and
`podbay-store/src/later_turn.rs:1238`. Their order must be:

`BEGIN IMMEDIATE -> resolve stored command/subject -> require_live_subject -> fresh/existing branch -> commit`

The private v25 guard is before `ExistingUncertain`, not only inside
`check_current_record`: the existing returns at
`podbay-store/src/bootstrap_send.rs:1262` and
`podbay-store/src/later_turn.rs:1253` precede that helper. Guard the current
claimed inspections at `podbay-store/src/bootstrap_send.rs:1285` and
`podbay-store/src/later_turn.rs:1276` in their own read transactions as well.
`selected_record` at `podbay-store/src/bootstrap_send.rs:1188` and
`podbay-store/src/later_turn.rs:1167` supplies the checked stored binding.

Keep production wrappers explicitly schema-24-only (`podbay-store/src/store.rs:21`).
Exercise the shared bodies with an explicitly private disposable v25 test
policy/harness. Add no public v25 writer opener or authority constructor.

Preserve passive exact-key receipt lookup at
`podbay-store/src/bootstrap_send.rs:543` and `podbay-store/src/later_turn.rs:431`,
plus historical claimed inspection at `podbay-store/src/later_turn.rs:306`.
Keep principal/scope/key/payload comparisons and protected-input rules. Do not
insert the live guard into their shared immutable record decoder: original
receipts and uncertainty remain readable after pending or Owner recovery, but
readback cannot return a current executable proof or invoke an effect.

## Existing baseline decoder is not this guard

`podbay-store/src/external_death_v25.rs:478` compares every table except
metadata, pending and manager credentials against the migration baseline. A
successful claim changes `outbox` and violates that restricted contract.
Calling this filesystem decoder would also open a different connection.

Keep the new guard transaction-local. Seed commands/existing claims before
staging and use separate disposable fixtures for positive v25 claims. Do not
whitelist arbitrary outbox drift to obtain a passing test. Continuing the full
pending recovery protocol after new claim mutations requires a separately
defined supported-change contract.

## Required tests

- Preserve v24 claim/retry behavior and schema-25 refusal by ordinary/raw
  witness opens. Reuse fixture patterns from
  `podbay-store/tests/bound_launch_v2.rs:1700` and
  `podbay-store/tests/bound_launch_v2.rs:2507`.
- For both send types, exercise disposable `Live` fresh claim and exact retry;
  assert one claim mutation. Exercise pending/final/unverified refusal for
  fresh claims, `ExistingUncertain`, and current claimed inspections.
- Cover wrong lineage/subject/resource binding, duplicate pending subject,
  orphan/malformed final, altered author/digest/version/DDL, missing tables,
  and decoder row/byte budgets. Include a valid unrelated subject case.
- Assert the specific fence result so pending's revision increment cannot
  mask a missing guard. Refusal preserves command/event/outbox/lease rows,
  original receipts, and native uncertainty. Changed historical payload,
  actor or key refuses; exact readback survives Owner-epoch advancement.
- Use explicit handshakes between competing SQLite transactions: pending
  committed before claim entry denies; a held claim transaction excludes a
  competing writer until completion. Test rollback before claim commit and
  lost-response retry. This establishes database order only, not effect order.

## Acceptance boundary

The principal P1 risks are retry-before-guard ordering and treating decoder
failure as `Live`. The atom covers only the named disposable claim/current
inspection paths. It does not fence every admission or lease path, drain
previously admitted effects, maintain an OS/native use gate, verify Linux
death, establish readiness, or provide production v25 support. No live store,
migration, broker deployment or activation is authorized by this document.
