# Local writer lease renewal wire atom

Status: implemented for a fresh v24 store. Commit `8a66a69` supplied the
initial store CAS; the keyed wire path is the follow-up atom. No v23 migration
is provided for this preproduction local MVP.

## Contract

Add `session.writerLease.renew` as a PodBay/1 mutation targeting the current
Session. Its strict body has two decimal strings:
`expectedWriterEpoch` and `expectedLeaseExpiresAtUnixSeconds`. The existing
command `key` is the idempotency key. The request has no prompt, pod selector,
actor selector, TTL, grant selector or provider input. The trusted manager
policy supplies `writerLeaseSeconds` (1 through 3600) and its installed
SendSession grant. A successful receipt reports `writerEpoch`,
`leaseExpiresAtUnixSeconds`, the current Resource guard and `duplicate`.
It does not report a provider turn or imply pod liveness. An expired lease,
changed owner/actor/target/epoch, or wrong expiry must fail without mutation.

Zap calls this on the authenticated manager socket before expiry, using the
current epoch and expiry from `bootstrapGuard` or the previous renewal receipt.
Use a fresh key for each extension. If the reply is lost, repeat the **same**
key and exact body; the manager returns the original committed expiry. Zap
must retain that key until it receives the receipt. No native frame is sent.

## Atomic durable receipt

Use a fresh v24 schema with a dedicated `native_writer_renewals` table. Add one
specialized `PodBayStore::renew_native_writer_lease_with_receipt` transaction
in `writer_lease.rs`; do not compose `admit()` with the existing CAS, because
that would leave a crash interval between the command receipt and expiry.

In one SQLite `IMMEDIATE` transaction:

1. Validate the authenticated principal, exact canonical wire intent, namespace
   `session.writerLease.renew`, key, scope/Session target, current manager,
   actor generation, SendSession-authorized host witness, current Session graph,
   and exact lease target, writer epoch and expected expiry. The host performs
   authentication and grant checks before and after its store call.
2. Look up `(principal, namespace, key)` first. If present, verify its stored
   canonical request and digest, target, owner/target epochs, admission event,
   outbox, and renewal result bytes. Return the **original** receipt and expiry
   without touching the lease. This replay works after the lease expires; the
   current authenticated actor and grant are still required. A changed body
   under the key is a conflict.
3. For a new key, reject expiry `<= SQLite now`; calculate `now + trusted TTL`
   with overflow checks and require it to exceed the current expiry. Update
   the exact lease row with CAS on full current identity, epoch and expiry.
4. Insert a `commands` row, one admission `events` row and one `outbox` row
   containing the resulting epoch/expiry, all in the same transaction. Mark
   the outbox `observed` in that transaction: renewal has no dispatchable pod
   effect. Set `commands.event_sequence` and `commands.outbox_id`; read back
   the exact result; commit once. Its observation means **lease row committed**,
   never provider completion.

The present `lookup_command()` requires an observed outbox to carry claim and
observation keys plus a matching second event, and its `ObservedStage` enum
knows only `host_accepted`/`legacy_unverified`. Add a distinct `lease_renewed`
stage and its verifier/projection rather than labeling the renewal
`host_accepted`. Its claim key is the original command key and its observation
event is written in the same transaction; no later claim/observe call occurs.

Command inspection recognizes the recorded renewal kind. `claim_effect()`
refuses it, and its outbox is already observed so `pending_effects()` does not
offer it for dispatch. The dedicated table stores the exact expected and
renewed expiries with a foreign key to the command row.

## Routing and binding

- `podbay-wire/src/command.rs`: strict operation/body enum, validation,
  Session target, digest coverage, and decoding tests.
- `podbay-wire/src/typescript.rs`, `templates/client.ts.in`, and
  `generate-ts`: add the discriminated union and body validator, then
  regenerate committed `bindings/typescript/src/generated.ts`, contract JSON
  and one canonical command fixture. Run generator `--check` afterward.
- `podbay-host/src/authority.rs`: route through current authenticated actor,
  exact SendSession grant, current Session target and trusted TTL. Return a
  typed durable receipt. The wire route never calls the unreceipted store CAS.
- `podbay-server/src/host_launch_handler.rs`: opt-in only on the trusted manager
  listener; project committed epoch/expiry and duplicate flag. A post-commit
  projection error must report uncertain with the CommandId, never retry a
  fresh key. Read operations remain pure.
- Manager policy and listener already carry the trusted SendSession grant and
  writer TTL; reuse those values per authenticated exchange. No new policy
  field or Zap process restart is needed.

## Focused gates

Test Rust and generated TypeScript strict shape/digest; successful renewal
preserves writer epoch and extends expiry; same-key replay returns byte-for-byte
original receipt after a simulated lost reply; changed body/key conflict;
concurrent different keys with the same expected expiry yield exactly one
extension; expired lease, wrong actor/grant/manager, rebind target change and
different Resource epoch are refused; `commands.get` sees the committed
renewal while `pending_effects` and effect claim never expose it; no port or
native frame call occurs. A disposable manager socket test should authenticate
the same process-owned key Zap uses.

## Expired A→B recovery

Renewal cannot resurrect an expired lease. The reported A→B startup failure
returns `Host(StaleGuard)` from `prepare_current_codex_v2_rebind`, before
writer takeover. That path checks committed policy, current manager/rebind
vectors, and OS-observed supervisor/child evidence; it does not inspect writer
lease expiry directly. Capture the exact failed comparison or port observation
in a disposable fixture before changing it. Once PodActive is proven, the
existing `takeover_initial_writer_after_active_rebind` is the separate fenced
path that can replace an expired prior writer without a native turn.
