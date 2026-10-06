# Private CLOSED-origin acquisition prototype

The Linux/test-only [module](../../crates/podbay-host/src/access_barrier_gate/codec/closed_origin.rs)
exercises one private custodian channel and an opaque, non-admitting handle.
It binds a selected peer's credentials, PID/birth, nonce, sequence, complete
subject, manager lock, store pair, lineage, boot and artifact/policy hashes.
Loss, mismatch, replay, replacement and explicit late-engagement notification
permanently invalidate the handle. Existing complete or partial origin records
cannot be reopened into a handle. There is no production constructor,
admit/release operation, store-open grant or conversion API.

Parent tests ran as an ordinary UID with a new owner-0700 external fixture root:
**10 passed, 0 failed, 1 ignored child entry**. The child entry is invoked by
the exact-process tests. Ordinary non-test `podbay-host` check exited 0.
An independent bounded review found no P1/P2. The retained scratch patch,
source hashes, evidence and full report are at
`/fast/git/v/research/2026-10-06-podbay-closed-origin-prototype/`.

The test bootstrap selects the child and supplies its pins. Hashing source
and staging files begins before all identity fields are checked; acquisition
validates those fields before returning a handle. The prototype does not prove
that a production root/PID1 custodian ran before every issuer, that the whole
issuer set is known, or that FD, directory FD, mmap, queued SCM_RIGHTS,
`/proc`, namespaces and SQLite sidecars are excluded. Late engagement is
injected by the fixture, not autonomously detected. Custodian loss does not
install an OS-enforced CLOSED policy. The disposable v25 VM result remains a
separate persistence/refusal observation and does not close these gaps.
