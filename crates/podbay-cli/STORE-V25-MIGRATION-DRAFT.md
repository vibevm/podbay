# Store v24→v25 migration for external-death recovery

Status: candidate design, 2026-10-06. No live store has been migrated. The
old PodBay database remains schema 24 and is preserved. This is the migration
prerequisite for [cross-boot recovery](EXTERNAL-DEATH-RECOVERY-DESIGN.md),
not a release or an authorization to publish v25 on the host.

Implementation checkpoint `3d04cf0`: a separate lock-only preflight and
verified Linux atomic exchange pass disposable tests under the identical
manager lock. The exchange verifies exact v24/v25 inode orientation, private
files, schema/content/lineage, absent SQLite sidecars and the manager lock
namespace. A retry with the in-memory staging attestation does not exchange a
published pair back. Checkpoint `5cf8dd8` adds a versioned durable keyed intent
before the disposable exchange. A fresh process can recover and verify the
exact Unpublished or Published inode orientation without re-exchanging; same-key
retry repairs an interrupted pre-directory-fsync intent publication. These
paths remain test-scoped: their reader-exclusion token has no production
constructor. Checkpoint `b2398f4` adds a durable publication-only receipt that
binds exact intent bytes and a verified Published v25/v24 pair, with fresh-
process readback and interrupted-fsync repair. Its disposition is explicitly
`published_unactivated`; it does not settle old effects. Incomplete-staging
rebuild, rollback, production exclusion, ordinary v25 activation and live-store
cutover remain open. The old schema-24 store remains untouched.

## Decision and rejected alternative

Use a staged **copy, verify, atomic exchange** from v24 to v25. The v25
`external_death_pending` fence and final disposition must be in the same
SQLite store as launch, stop, rebind, dispatch and writer claims. An external
sidecar cannot establish their single-writer order, database foreign keys or
one authority revision without introducing a stronger shared lock and a
cross-database transaction protocol for every writer. No such protocol is in
current PodBay. Revisit only if a measured need justifies that larger design.

The existing `PodBayStore::open` and read-only open require exact schema 24;
they refuse another version before WAL/DDL write. A v25 binary therefore needs
a dedicated v24 migrator under the same manager lifetime lock **before**
ordinary store open or owner epoch replay. The old binary must continue
refusing v25. Do not make ordinary `open()` silently upgrade a database.

## Exact lock and publication boundary

`DurableAuthority::open_with_locked_preflight` obtains the lock on the
canonical database filename, runs a trusted local closure, then calls
`PodBayStore::open` and advances the Owner epoch. The migrator belongs in that
locked preflight or in a separately exposed entry that acquires the identical
lock. It must not use a second lock with a different key. Validate the
canonical regular 0600/single-link file, parent 0700 directory, uid and
no-follow paths again after lock acquisition. Shut down other connections;
recorded stale sockets are reconciled by their existing exact-inode path.

The manager lock does **not** fence pod-side `open_existing_read_only`.
This initial migration is admitted only at a proved changed-boot boundary
where every legacy source-bound Pod/witness process is dead, every old unit
is transient and non-restartable on the current boot, and no queued launch
effect can create another reader. Keep that exclusion true through exchange,
verification and first v25 activation. A momentary zero-connection count is
insufficient. If any reader can survive or reopen, refuse this cutover and
design dual-version reader compatibility first. Test a concurrent attempted
reader/relaunch against the maintained barrier.

A disposable user-systemd 259 probe on 2026-10-06 ruled out `mask --runtime`
as that maintained barrier. A previously accepted waiting job ran after the
mask; a loaded transient unit restarted under the mask; after stop/collection,
`systemd-run --unit=<same name>` created a fresh transient unit even while the
mask symlink remained. A follow-up held D-Bus `RefUnit` reference prevented
collection of a loaded transient object, but did not cancel its waiting job;
`systemctl start` still accepted a new job under the mask. A masked unit could
not be acquired with `RefUnit` in that probe. All disposable units and D-Bus
references were cleaned, and no product unit was touched. A production
admission capability therefore needs a separately
enforced launch/access gate, verified over the whole interval. The strict
same-UID raw-opener guarantee requires an OS access boundary; a narrower
cooperating-process contract must explicitly name and close every trusted
entry point. Neither contract is implemented by this draft or by `3d04cf0`.
One disposable privileged mount-namespace fixture preserved the original
database inode and owner UID while denying outside path, raw SQLite, symlink
and `/proc` opens. Its inherited-descriptor oracle failed before the full
descriptor/SCM/mmap boundary was established, so that probe is **not** a
production isolation receipt. Any future broker must prevent preexisting or
exported file descriptors as well as path opens, and prove its cleanup and
cold-boot admission separately.

The migration is bound to a stable Owner request key, old database lineage,
source file identity, schema 24 content digest and expected v25 schema digest.
A durable intent record in the same private directory names one staging file
and the original canonical filename; it is recovery metadata, not a second
authority ledger. A retry uses that exact staging path and key. Unknown or
foreign files fail closed.

1. With the lock held, inspect `PRAGMA user_version`, schema objects, source
   mode/uid/link/inode and existing WAL/SHM. If v24 WAL has committed pages,
   checkpoint it through SQLite under the lock before snapshotting; record
   logical and file identity afterward. A crash here leaves a valid v24 store.
2. Use SQLite's backup API to copy the committed v24 snapshot to a new private
   regular 0600 staging file **in the same directory**. Copying only the main
   file is invalid when WAL contains committed pages. Preserve exact lineage,
   row IDs, command/event/outbox sequences, blobs and `sqlite_sequence`
   high-water values. Do not initialize a fresh store, which mints a new
   lineage.
3. Close the backup source. Ensure staging is in a non-WAL journal mode; apply
   only the reviewed v25 DDL plus `user_version=25` in one target transaction.
   The new pending/final records are empty on migration. Pending references
   the exact launch binding, activated rebind/prior observation, lineage and
   recovery key. Final references one pending record and keeps
   `native_outcome=uncertain`. The schema and APIs separately validate that
   referenced phases/subject columns actually match; a scalar rowid FK alone
   cannot prove an activated rebind.
4. Verify exact expected v24→v25 schema objects, `integrity_check=ok`, empty
   `foreign_key_check`, exact preserved lineage/high-water values, row counts
   and content digests for unchanged tables, and semantic consistency of the
   specific current V2 recovery chain. Do not log sensitive row bodies.
   Close the staging connection, fsync the staged file and directory.
5. Confirm all connections are closed. Ensure the canonical filename has no
   applicable WAL/SHM pages; remove or archive only proven empty/stale
   sidecars under the lock. Exchange the canonical and staging directory
   entries with Linux `renameat2(RENAME_EXCHANGE)` through the installed
   safe `rustix::fs::renameat_with` API. If exchange is unsupported, stop
   before publication; do not use a two-rename fallback with an unbounded
   missing-canonical interval. Fsync the directory after exchange. The old
   v24 file now occupies the staging pathname and remains recoverable.
6. Verify canonical v25 through a dedicated **read-only, non-WAL** migration
   verifier while holding the lock and reader exclusion. Write a durable
   migration receipt with source/target digests and exact filenames. Only
   then allow ordinary v25 `PodBayStore::open` and the first Owner epoch
   transition. No automatic rollback is permitted after that ordinary open;
   it can enable WAL before any explicit Owner effect. A failure from there
   requires forward repair or a separately proved reverse migration.

Before ordinary v25 open, an exact rollback is a distinct keyed operation:
fsync a `rollback_requested` intent, close/quiesce both SQLite handles,
verify no v25 WAL/SHM or authority write, exchange back if the filenames are
in the forward orientation, fsync the directory, then persist a terminal
rollback receipt. Recovery respects that direction and never resumes the
forward migration after rollback was requested. If rollback orientation,
journal state or no-write proof is uncertain, fail closed.

Recovery is keyed by the durable intent and observed file orientation, not by
an optimistic last in-memory phase:

| Durable/observed state | Recovery action under the same lock |
| --- | --- |
| Intent only, absent/incomplete staging | Verify canonical v24 identity/digest and no publication, then rebuild the same keyed staging path; foreign files refuse. |
| Copied staged v24 | Reopen through SQLite, resolve or refuse any hot rollback journal, verify exact source snapshot, then run the reviewed v25 DDL transaction. |
| Converted staged v25, canonical v24 | Verify target schema/integrity/lineage, fsync file/directory, then exchange once. |
| Canonical v25, staged old v24, no terminal receipt | Verify both orientations and digests, repeat directory fsync if needed, finish read-only verification and receipt; do not exchange again. |
| `rollback_requested` before activation | Complete the separate quiesce/journal/orientation/dir-fsync/terminal-receipt protocol; never resume forward. |
| v25 activated by ordinary open/Owner replay | No blind exchange rollback; forward repair or separately proved reverse migration only. |

A crash during SQLite backup, DDL or a hot rollback journal does not count as
a valid staged v25. Mixed versions, wrong lineage, replacement inode,
applicable old WAL, foreign key/intent, or ambiguous exchange result refuse
until exact evidence resolves them. The manager publishes no `manager.sock`
in any ambiguous state.

## v25 runtime and schema obligations

The new store records `external_death_pending` and `externally_dead` as
separate append-only facts. Prepare compares the exact current V2 binding and
commits the pending fence in one SQLite transaction with an authority revision
advance. Every same-incarnation launch, stop, rebind, dispatch and writer
claim checks the pending/final disposition in its own transaction. The
external Linux proof happens outside the transaction under the manager
lifetime lock; finalize rechecks the pending subject, appends the exact
proof digest and advances revision. New insertion uses the current Owner
epoch; exact-key readback survives later Owner recoveries. No `pod.stop`
command or false native completion is manufactured.

The inventory cursor continues to bind lineage, Owner epoch and authority
revision. It exposes typed `ExternalDeathPending` and `ExternallyDead`
dispositions; the former blocks manager readiness, the latter excludes live
rebind/writer takeover while leaving the historical Pod inspectable. An
unresolved `claimed_uncertain` stop remains blocking. A v25 reader verifies
all v25 schema objects and performs full integrity/FK checks for migration
acceptance; merely matching `user_version` is insufficient.

## Disposable proof and release gates

- Snapshot representative v24 files, including activated rebind/prior OS
  observation and unresolved stops, via SQLite backup. Source logical content
  stays unchanged until publication. Verify exact lineage, IDs, high-water
  values, row counts/digests and old-binary refusal of v25.
- Inject crash before/after intent, WAL checkpoint, backup, DDL transaction,
  staging fsync, exchange, directory fsync, receipt and Owner replay. Retry
  the same key; never create a second staging identity or publish mixed data.
- Attempt a pod-side read-only opener and an old-unit relaunch throughout
  publication; the initial cross-boot migration must maintain exclusion or
  refuse before exchange. A surviving old v24 witness is a blocker, not a
  compatibility success.
- Refuse altered DDL, partial tables, FK/integrity failure, wrong source
  digest/lineage, symlink/hardlink/wrong mode, cross-filesystem staging,
  applicable WAL/SHM, foreign migration key and unknown exchange outcome.
- On v25 disposable stores, prove pending fences all affected claims,
  finalization is exact and idempotent, and startup handles active, pending,
  externally dead and uncertain-stop dispositions distinctly.
- Preserve the live v24 original and its read-only snapshot until product
  code, disposable tests, independent review and the specific cutover are
  approved. Passing model proofs or a green v25 fixture alone is not a live
  migration receipt.
