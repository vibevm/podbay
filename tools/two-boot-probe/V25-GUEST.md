# Disposable v25 guest fixture

The [example](../../crates/podbay-store/examples/v25_two_boot_fixture.rs) calls
the real public v25 stage, intent, exchange, receipt, activation and recovery
APIs. It is a CLOSED/no-admission test workload, not a production constructor.
Boot A creates a fresh v24 store, activates v25, commits one FULL-synchronous
authority revision increment and persists an exact private manifest. Boot B
checks all saved bytes and identities, uses read-only recovery, and asserts
ordinary v25 open, frozen migration, foreign activation key and a separate
partial marker all refuse as specified.

The isolated source/build receipt is at
`/fast/git/v/research/2026-10-06-podbay-v25-guest-fixture/REPORT.md`.
Accepted example source SHA-256:
`98b767aba6f0713d98bda4584ae94a39ad5f9d5786f34d4536d20001ca9f9888`.
The static musl ELF SHA-256 is
`53ca9879fbb11e999c8f1a690c4c5096976f3e8e42e20a823f0260f639fd510c`
(3,680,464 bytes, ELF64 x86-64 ET_EXEC, no interpreter or dynamic section).
Ten separate host-process controls passed, including correct recovery and
refusal plus tampered database/manifest negatives. Their successful B phases
record `cold_boot_verified=false`; no guest execution has been inferred from
them. An independent source review found no P1/P2 within the disposable scope.

The next atom packages the exact ELF into a new initramfs and drives two fresh
QEMU boots against a new writable image. The host must compare Boot A's
`BOOT_A_DURABLE` manifest hash with both Boot B manifest hashes, and verify
nonce, executable hash, `domain=guest`, exact event order, sequence and distinct
boot IDs. The guest's own manifest check establishes internal consistency;
the host comparison anchors it across boots. Preserve the current marker and
partial-gate fixtures as independent controls.

Even a passing guest pair would not prove a production access barrier, Owner
authority, old-handle exclusion, signed terminal evidence, pending settlement,
restart readiness, arbitrary crash-window behavior or host power-loss durability.
