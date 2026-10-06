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

The exact ELF is now packaged into a new initramfs and driven through two fresh
QEMU boots against a new writable image. The host compares Boot A's
`BOOT_A_DURABLE` manifest hash with both Boot B manifest hashes, and verify
nonce, executable hash, `domain=guest`, exact event order, sequence and distinct
boot IDs. The guest's own manifest check establishes internal consistency;
the host comparison anchors it across boots. Preserve the current marker and
partial-gate fixtures as independent controls.

## Actual guest pair, 2026-10-06

The retained result is
`/home/olegchir/podbay-two-boot-persistence-build/persist-v25-parent/result.json`.
The runner exited 0 with
`DISPOSABLE_V25_TWO_BOOT_OBSERVED_NO_PRODUCTION_ADMISSION`.
Boot A emitted its four exact events, activated v25 and committed authority
revision 1. After the helper was reaped and the image cleanly unmounted, the
host validated A's complete oracle, sent SIGKILL to its exact QEMU pidfd and
reaped it (`exit_code=-9`). Boot B used a fresh kernel boot ID, emitted its
three exact events, recovered revision 1, and completed the ordinary-open,
frozen exchange, foreign key and partial activation refusal checks. It exited
0 and was reaped. Both QEMU PIDs were subsequently absent. The Boot A manifest
SHA-256 `30b9cd8c016fdb6422a7a31739efbf14396a3b78e6029cbead5e392cb7e25704`
matches both Boot B hashes. The retained image matches its result SHA-256.

Seven v25 oracle/packaging/failure tests and twelve marker/partial tests passed
after the source copy into this repository. The result uses the exact reviewed
ELF SHA-256 above; the existing CLOSED marker and partial-negative VM receipts
remain separate.

The copied repository runner was also executed directly as
`persist-v25-main` on a second fresh image. It exited 0 with the same bounded
status and event sequence; Boot A `-9`, Boot B `0`, both pidfd exits/reaps and
absent PIDs were verified. Both boots agreed on manifest SHA-256
`c7d492455720885b64fa89b326d1bb8c2877807a9a3bd887d06efc64482a7f95`
and revision 1. Its image hash matches the retained result at
`/home/olegchir/podbay-two-boot-persistence-build/persist-v25-main/result.json`.

This guest pair does not prove a production access barrier, Owner
authority, old-handle exclusion, signed terminal evidence, pending settlement,
restart readiness, arbitrary crash-window behavior or host power-loss durability.
Boot A's QEMU termination occurred after the helper and unmount completed.
