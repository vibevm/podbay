# Exact external-death and Zap restart recovery

Status: revised candidate design, 2026-10-06. The live reboot evidence is in
[BACKLOG.md](../../BACKLOG.md) P1-003/P1-005/P1-006. This is not an implemented
command, a signed `pod.stop` receipt or permission to touch the live store.
The two operations below have separate durable authorities: (A) recovering an
inner current V2 Pod after external death, and (B) allocating a fresh outer
Zap Service generation after a terminal stop.
The current live store is schema 24; the reviewed candidate path to add
pending/final records is the separate
[v24→v25 staged migration](STORE-V25-MIGRATION-DRAFT.md). No live migration is
authorized by either design document.

## Observed boundary

The old inner Coordinator unit became inactive/MainPID0 and its processes
vanished after an owner-requested reboot, but no `pod.stop` command or terminal
receipt was committed. The old Pod remains in `current_codex_v2_rebind_page`.
Manager startup recovered Owner credentials, then attempted only live rebind;
`PodClient::inspect_rebind` returned connection refused and the port collapsed
that cause to `Host(StaleGuard)`. Repeated startup advanced Owner epochs without
making manager ready. The original native turn remains uncertain.

The current inventory query also **omits** current Pods whose `pod.stop`
outbox is `claimed_uncertain` or `observed`. Those states must not silently
count as physically stopped. A new typed inventory returns each exact
candidate with a disposition: `needs_live_rebind`, `stop_claimed_uncertain`,
`stop_observed_with_terminal_proof`, `stop_observed_unverified`, or
`externally_dead`. Startup may become ready only after every candidate has
an active authenticated rebind or a verified terminal/external-death outcome.
`stop_claimed_uncertain` remains blocking until original-key reconciliation.

## Durable evidence available for the old Pod

The current bound launch row alone lacks systemd/process identity. However,
the live store also has an **activated** `manager_rebinds` row joined to
`manager_rebind_prior_observations` for the exact Pod/incarnation/attempt. It
records supervisor PID/birth, boot identity, unit/cgroup and checkpoint digest.
The persisted Pod manifest retains the logical descriptor and unit name.
For the first **cross-boot** recovery slice, this activated rebind plus its
launch-binding foreign key and immutable manifest chain is the durable
pre-death identity source. Implementation must verify its store lineage, owner and
credential epochs, descriptor/checkpoint lineage, manifest inode/digest and
that no later conflicting binding exists. The ordinary activated rebind row
does not retain child PID/birth. Same-boot automatic retirement therefore
refuses without an independent exact child/cgroup proof. A verified changed-
boot branch can exclude every old local process birth using the stored old
boot identity, without inventing a child PID. If immutable manifest identity
or the cross-boot barrier cannot be established, this historical row remains
unverified. Future launches should commit a full launch-settlement receipt
before a separately designed same-boot recovery is considered.

## A. Inner V2 Pod: pending fence, OS proof, final disposition

Recovery is an explicit exact-key state machine under the manager's exclusive
state lock and trusted Owner policy. A transport refusal, timeout, missing
socket or generic `StaleGuard` is **never** death proof. The Linux inspection
port preserves bounded typed classes such as transport-unreachable,
manifest/policy/store changed, foreign unit and unknown. Death proof is a
separate exact-identity path; only an applicable class may request it.

1. **Prepare:** in one store transaction, compare store lineage, current Owner
   epoch/revision, scope, Pod incarnation, Run/attempt/resource binding,
   activated checkpoint/manifest identity and recovery request key. Commit
   `external_death_pending` and fence all new launch, rebind and dispatch
   claims for that incarnation. A previously claimed effect must first be
   reconciled by its original key; pending does not assume it had no effect.

   The schema-25 pending table is additive and has no trigger that fences old
   writers. Before production v25 activation, every launch, stop, native send,
   writer lease/use, rebind and effect-claim path must query pending/final for
   the exact lineage/scope/Pod/incarnation in its own transaction. A global
   authority-revision increment alone is insufficient: some rebind paths do
   not advance that revision, and a later caller can carry a fresh one. The
   first implementation may expose only a restricted disposable v25 prepare
   handle and exact-key readback; it must not claim the runtime is fenced until
   all actual paths and direct adapters have the guard.
2. **Exclude reanimation for this slice:** require the saved activated
   rebind's boot ID to differ from the trusted current machine boot. The old
   manager and Pod processes cannot survive this boot. The exact launch
   binding/effective contract and trusted launcher version must prove that
   this was a `StartTransientUnit` unit rather than a persistent service;
   retain the pinned launcher/policy identity in the proof. A collected unit
   cannot retrospectively supply its old `Restart` property, so that property
   is not an assumed legacy fact. Require no persistent service definition,
   queued systemd start job or same-name new unit. Reconcile every
   claimed launch/stop effect under its original key before proceeding. The
   manager state lock, recovered current Owner epoch and committed pending
   fence exclude another cooperating launcher from issuing a new old-
   incarnation effect. The old accepted launch command must have no pending
   dispatch. If any of these checks fails, pending stays blocking. This is
   the implementable cross-boot barrier; it is not a same-boot OS fence.
3. **Observe:** trusted Linux code checks the immutable manifest and saved
   process/boot/cgroup identities. With the changed boot proved, accept only
   the exact transient unit `LoadState=not-found` or inactive/MainPID0, no
   same-name active unit or queued start job, and the verified activated-
   rebind + launch-binding + manifest chain described above. No child PID is
   invented: the changed boot excludes every old local process birth. An
   active supervisor with dead child belongs to terminal-only orphan stop.
   Same-boot external death, foreign/mismatched unit, changed manifest,
   unknown job state or pending original launch effect refuses for this slice.
4. **Finalize:** recheck the pending fence and exact proof subject in a second
   store transaction. Append one `externally_dead` record with OS proof digest
   and `native_outcome=uncertain`; advance only that incarnation's candidate
   disposition. Do not insert a `pod.stop` row, reclassify any old input, or
   give another Run its identity. A crash before prepare changes nothing;
   after prepare it remains fenced/blocking; after finalize it is durable.

New insertion requires the current mutation epoch/revision. Exact-key readback
of a previously committed pending/final result compares immutable request and
proof digests and works across later Owner recovery epochs; a changed payload
or foreign actor refuses. Startup re-enumerates typed dispositions after each
successful recovery and never takes over the writer for an externally dead
Pod. Zap consumes the exact authenticated `externally_dead` result to retire
its old Coordinator as `retired_uncertain`, preserving chat/native history.
PodBay does not mutate Zap's Workspace database or authorise a new native turn.

## B. Outer Zap Service: stable generation ledger and readiness

A separate stable **owner-root ledger outside all generation directories** is
locked by the restart operation. Its idempotency identity is prior exact
terminal receipt digest + Owner restart request key. Before creating any
directory or launching anything, it records `Allocated` with the fresh
state directory; actor/scope/Pod/Run/attempt/resource/command identities;
pinned artifact/configuration digests; and requested database/profile identity.
Crash replay returns that same allocation, never mints another generation.
The low-level same-key `operator zap launch` remains an exact command and
continues to refuse a stopped binding.

The owner ledger advances through `LaunchAccepted` and then **Ready** only
after a bounded authenticated child protocol: a fresh nonce reply binds the
exact generation, actor/scope/Pod and child birth, artifact/config digests,
Workspace database identity, account/profile and protocol version. Verify
child birth again at readiness publication and persist the readiness receipt.
A child PID or PodBay HostAccepted alone is not readiness. Timeout, config
conflict or immediate child exit produces a typed non-ready outcome carrying
the original accepted command identity.

A failed generation with a surviving supervisor enters
`FailedTerminalStopRequired`. The terminal-only orphan-stop protocol of
P1-003 is a prerequisite: obtain/replay its one-use exact-unit stop and
terminal receipt before allocating a successor. No unchecked `systemctl stop`
or new generation while the old supervisor remains active. A competing legacy
Wayfinder that owns the same database is a typed conflict; service cutover
must select one authority and disable the former auto-start with a rollback
record. Unknown prior effects block automatic restart until reconciled.

## Focused acceptance before deployment

- Exact externally dead legacy/new Pod: distinct durable record, no fabricated
  stop, original native outcome uncertain, manager ready, old history readable.
- Claimed-uncertain stop, connection refusal alone, active supervisor/dead
  child, same-boot missing unit, foreign/mismatched unit, PID reuse, changed
  manifest/store, claimed launch and unaccounted descendant: no new death or
  ready claim. A changed-boot collected unit may finalize only with the
  verified activated-rebind identity and complete cross-boot barrier.
- Crash at prepare, OS barrier, observation, finalization, Owner epoch change,
  outer allocation, launch, readiness and orphan stop: exact-key replay and
  no duplicate native input or owner.
- Live high-event Pod still uses authenticated rebind and writer takeover.
  Outer exact terminal old generation obtains one authenticated Ready successor;
  repeated owner request returns that generation; child exit remains non-ready.

Implement this with versioned store/wire records and trusted-port OS evidence.
A caller JSON assertion or direct SQL edit cannot substitute for those proofs.
