# External-death claim and use fence map

Status: candidate implementation map, 2026-10-06. Read-only source research;
no production fence, Linux death proof, final disposition, readiness result,
live migration or deployment authorization is established by this document.
It complements [the recovery design](EXTERNAL-DEATH-RECOVERY-DESIGN.md) and
[the migration draft](STORE-V25-MIGRATION-DRAFT.md). Source anchors below are
relative to `crates/` and describe the inspected checkout; later edits can move
the line numbers.

## Observed implementation boundary

Production `PodBayStore` requires schema 24 (`podbay-store/src/store.rs:21`).
Its ordinary readonly and writer opens refuse another version (`:490`, `:497`,
`:561`, `:566`). Disposable migration stages schema 25
(`podbay-store/src/migration_v25.rs:17-18`). The restricted pending API has no
production authentication constructor, dispatch, rebind, lease, readiness,
Linux proof or finalization API (`podbay-store/src/external_death_v25.rs:1-2`).
Its author fields are private (`:14-17`). Host disposable exclusion is a test
`RwLockWriteGuard` with deliberately no production constructor
(`podbay-host/src/authority.rs:3569-3576`); activated/pending handles borrow
that barrier and manager lock (`:3580`, `:3602`).

Schema refusal is an observed limitation, not a complete runtime fence. The
raw Owner and Manager witnesses now reuse the production schema-24 read-only
validator in their own snapshots, so they refuse unsupported schema 25 before
issuing authority evidence. Other runtime paths and direct adapters still lack
a v25 pending/final decoder and maintained effect-use gate. No inspected
production module outside migration/pending reads `external_death_pending` or
`external_death_final`.

## Production entry points and effect boundaries

The subject is the exact `(store_lineage, scope_id, pod_id, pod_incarnation)`.
Session/Run/Attempt, launch row, activated rebind/checkpoint and complete
resource/input vector establish its binding. An operation targeting a Session,
Run or resource must resolve this subject in the same transaction as its fence
check; caller-supplied Pod fields are insufficient.

| Path | Source anchors | Required coverage |
| --- | --- | --- |
| Manager startup/replay and automatic recovery | `podbay-host/src/authority.rs:4060,4080,4093`; `podbay-cli/src/main.rs:364` | Decode pending/final before actionable hydration or startup rebind; fenced/unknown candidates block readiness. |
| New V2 root launch admission | `podbay-host/src/authority.rs:8263,8495`; `podbay-store/src/bound_launch.rs:1650` | Check within transaction before authority, runtime, command or outbox mutation. Also cover generic/operator admissions and delegation/parent subjects. |
| Prepared launch claim, dispatch and resume | `podbay-host/src/authority.rs:8795,8883,8930,9144,9562`; `podbay-store/src/store.rs:1481` | Check new and retry classifications; hold use gate through port call. |
| Linux launch/preflight and systemd admission | `podbay-launch-linux/src/linux.rs:655,689`; `podbay-launch-linux/src/codex_v2.rs:357`; `podbay-pod/src/codex_launch.rs:52,241,247,349,365` | Gate the actual `systemd-run` admission and settlement, not just its preceding SQL recheck. |
| Retained-manifest `serve` and native child startup | `podbay-pod/src/runtime.rs:2471,2520,2588,2610`; `podbay-pod/src/codex_resource.rs:131` | Gate service/socket/checkpoint/credential effects and native spawn; direct service restart must not bypass manager admission. |
| Rebind, acknowledgement and activation | `podbay-host/src/authority.rs:4994,5379`; `podbay-store/src/rebind.rs:208,307,389,515,531,548,565`; `podbay-pod/src/runtime.rs:3151,3254,3288,3344`; `podbay-launch-linux/src/linux.rs:1499` | Check each store mutation and Pod checkpoint fsync/activation boundary, including exact retries. |
| Pending-rebind recovery, supersession and writer takeover | `podbay-host/src/authority.rs:4750,4818,4902,5542`; `podbay-store/src/supersession.rs:856,1007`; `podbay-launch-linux/src/linux.rs:1483,3225,3309` | A recovery must not reactivate, adopt or install a writer for pending/final/unknown subjects. |
| Writer acquisition, renewal and current-use proof | `podbay-host/src/authority.rs:7188,7316,7360`; `podbay-store/src/writer_lease.rs:24,206,404,511` | Check every admission/renewal and current lease inspection; existing lease expiry is not the pending fence. |
| Bootstrap admission, claim and current claimed inspection | `podbay-host/src/authority.rs:7441`; `podbay-store/src/bootstrap_send.rs:593,1249,1285` | Check before both new claim and retry classification; keep historical lookup non-authorizing. |
| Bootstrap thread/start and first turn/start | `podbay-launch-linux/src/linux.rs:909,965,1067,1125`; `podbay-pod/src/runtime.rs:3724,3759,3773`; `podbay-pod/src/codex_resource.rs:783,790,815` | Hold use authorization through each native write; retain journal at-most-once semantics and prior uncertainty. |
| Later-turn admission, claim and submission | `podbay-host/src/authority.rs:7770`; `podbay-store/src/later_turn.rs:514,1238,1276`; `podbay-launch-linux/src/linux.rs:1724`; `podbay-pod/src/runtime.rs:3492,3529,3559` | Resolve exact native target and fence admission, claim and actual native send. |
| Deferred/nonblocking native writes and observation pumps | `podbay-pod/src/codex_later_turn.rs:134,138,142,260,276`; `podbay-pod/src/runtime.rs:2666` | Every future write tick needs maintained use authorization; an earlier submission check cannot authorize delayed writes. Distinguish passive history from RPCs that write to native input. |
| Generic and inner stop | `podbay-store/src/store.rs:731,1481`; `podbay-host/src/authority.rs:7984,8036,8058,8183,8215`; `podbay-server/src/host_launch_handler.rs:65`; `podbay-server/src/inner_stop.rs:662,687`; `podbay-pod/src/runtime.rs:3867,3897,3934` | Fence ordinary stop admission, claim and actual kill. External-death maintenance uses separate exact authorization and does not manufacture `pod.stop`. |
| Raw owner/manager/rebind witnesses | `podbay-store/src/peer_witness.rs:26,33`; `podbay-store/src/manager_peer.rs:183`; `podbay-store/src/rebind.rs:1423,1471` | Owner/Manager now refuse non-v24 schemas; a future v25 runtime must replace that refusal with the canonical pending/final decoder before any authority proof. Other direct adapters still require audit. |
| Authority mutation, incarnation/resource changes and input leases | `podbay-host/src/authority.rs:10360,10392,10409,10421,10463,10487`; `podbay-store/src/authority.rs:910` | Prevent a mutation from erasing/rebinding around the old subject's fence. A successor incarnation requires a separately reviewed allocation policy; final never restores the old one. |

## Concrete bypasses and uncertainty

* `SqliteOwnerEpochWitness` and `SqliteManagerPeerWitness` now check the same
  supported schema-24 read-only contract before lineage, Owner or manager
  claim. A disposable v25 store refuses both before and after pending. They do
  not interpret v25 death records or establish an effect-use gate. Runtime
  ordinary stop still calls these witnesses before `child.kill()`
  (`runtime.rs:3934`); its additional `active_codex_binding` predicate applies
  only to V3 (`:3909`). A future v25 V2 stop cannot rely on these old witnesses
  for pending/final authorization.
* Bootstrap claim's non-Prepared branch (`bootstrap_send.rs:1259`) and later
  claim's equivalent (`later_turn.rs:1248`) return `ExistingUncertain` before
  `check_current_record`. Adding a guard only to that helper misses retries.
* Pending prepare rejects unresolved `pod.offer`/`pod.stop`
  (`external_death_v25.rs:780`) and deliberately preserves independent native
  uncertainty (test comment `:1019`). It does not settle a previously claimed
  bootstrap/later native effect or prove no native write occurred.
* Authority revision advances with pending (`external_death_v25.rs:809-820`),
  but a fresh revision can be obtained later and raw witnesses do not depend
  on it. Revision alone cannot replace an exact persistent subject fence.
* Fresh SQL recheck followed by systemd admission, native spawn, pipe write,
  checkpoint fsync or kill has a check-to-effect window. Transaction isolation
  does not hold after transaction completion.

## Required decoder, transaction fence and maintained use gate

Use one versioned, bounded canonical decoder. It verifies supported runtime
schema and exact pending/final schema, lineage, canonical request/author digest,
row uniqueness, subject/binding consistency, final-to-pending linkage and
supported proof/disposition. Its result is `Live`, `Pending`,
`ExternallyDead`, or `Unverified`. Absent table, unsupported schema/format,
corruption, inconsistent binding, decode/budget failure or inaccessible store
is `Unverified`, never a fallback to `Live`. A historical decoder may retain
exact committed requests across later Owner epochs without turning them into
current authorization.

**Transaction responsibility:** a shared
`require_live_subject(transaction, subject, operation)` guards every new
admission, effect claim, lease acquisition/renewal, rebind/recovery mutation and
current executable proof in its own transaction. It runs before retry branches
that could authorize work. Session/Run/resource resolution and pending/final
query share the snapshot. `ExistingUncertain` and `AlreadyObserved` can be
returned by an explicit historical API, but cannot mint launch/writer/rebind/
stop capability or invoke a port. Final disposition permanently fences the old
incarnation; do not delete pending to regain liveness.

**Use-gate responsibility:** trusted broker admission serializes pending with
actual OS/native effects. A nonforgeable per-subject use capability is tied to
the exact identity, boot/process birth, broker policy/gate generation and
maintained access domain. Hold authorization through each actual admission,
spawn, native write, checkpoint activation or kill boundary. Delayed native
RPC ticks need authorization at their own future effect boundaries.

Pending preparation closes new admission, drains admitted effect sections,
then commits pending while the same manager/access/use gate stays held. Either
an already admitted section completes before pending commit or its entry is
denied; no effect starts after that commit. Broker death/disconnect/restart,
unknown publication orientation or gate loss defaults closed. Durable gate
metadata remains outside SQLite migration state and recovery never reopens
admission by guessing. An ordinary user-owned advisory lock or bearer JSON
receipt is not this gate.

The clean access/issuer domain must be established before opening the store
and maintained through publication, activation, pending and final disposition.
Inherited DB/directory descriptors, queued SCM_RIGHTS and writable mappings
survive later path denial, as measured by the separate disposable FD oracle.
A late path-only gate cannot revoke them. Cold-boot admission and the sealed
broker deployment remain separate unproved prerequisites; there is no automatic
production gate-release path in the current disposable atom.

## Exhaustive acceptance matrix for this map

Run the following dimensions against **every applicable path in the entry-point
table**, including direct public adapters rather than only server endpoints.
Use explicit phase handshakes and call counters, not scheduling sleeps.

| Dimension | Cases | Required outcome |
| --- | --- | --- |
| Canonical disposition | Live; pending; final; malformed row; missing table; unsupported schema/format; unavailable decoder/gate | Only verified Live can authorize ordinary effects; all other cases deny. No missing-table compatibility fallback. |
| Exact subject | Wrong lineage, scope, Pod, incarnation, Session/Run/Attempt, launch/rebind/checkpoint, resource/input vector | Refuse mismatches; establish explicit behavior for unrelated subjects without pod-ID-only matches. |
| Effect history | Fresh, Prepared, claimed-uncertain, observed, exact duplicate, changed-key/payload/actor retry | New/retry effect authority stays fenced. Exact history may be read without a port call or capability. Preserve uncertain native outcomes. |
| Identity/epoch movement | Owner replay, credential advancement, fresh authority revision, input/resource epoch changes | No renewed authority bypasses pending/final; no mutation erases the old fence. |
| Startup/reanimation | Manager replay/auto-rebind, retained manifest serve, existing/recreated unit, delayed launch, direct Pod adapter | No startup readiness or native child/effect authorization for fenced subjects; typed blocking state persists. |
| Native continuation | thread/start, bootstrap turn/start, later turn/start, delayed nonblocking write, RPC-writing inspection/poll | Fence each write boundary, including future ticks; no duplicate/resumed write is inferred safe from journal history. |
| Rebind/use | Prepare, acknowledge, activate, supersede, adopt recovered Active, writer takeover/acquire/renew | No active checkpoint, new lease or use capability for pending/final/unknown. |
| Stop | Generic/inner admission, claim, retry, direct Pod stop/kill | Zero ordinary kill calls after fencing; death maintenance remains separately authorized. No fabricated stop receipt. |
| Race | Pause just before systemd admission, child spawn, thread/start, initial/later turn/start, deferred write, checkpoint fsync, kill; close/commit pending | Already admitted sections drain before commit or are denied. Zero new effects after commit. SQL-only recheck must fail this test if not serialized. |
| Crash/restart | Kill broker/manager/Pod at close, drain, pending commit, publication/activation, finalization | Gate remains closed; exact-key recovery; no second exchange, native resend, rebind activation or guessed readiness. |
| Access-domain failure | Preissued DB/directory FD, mmap, queued rights; late engagement; wrong policy/birth/gate generation; export attempt | Typed refusal before production publication/admission. Fixture cleanup success is not a live-domain receipt. |

For each refusal assert zero newly admitted outbox/lease/rebind mutations where
applicable and zero launcher, spawn, native-write, checkpoint-activation and
kill calls. Separately assert original exact receipts/history remain readable
and original native uncertainty is unchanged. Positive tests establish the same
operation still works for verified Live subjects under the maintained gate.

## No-live claim

This map proposes implementation and tests; it implements none of them.
Disposable schema-25 pending tests cannot establish production runtime fencing,
clean handle/issuer admission, Linux death proof, final disposition or manager
readiness. No real state relocation, boot policy, service installation, live
launcher inhibition, migration or activation is authorized here. Parent review
and separate deployment acceptance remain required.
