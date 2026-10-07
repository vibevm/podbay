# Disposable R1 producer refusal receipt (2026-10-07)

This receipt covers one ordinary-UID, TCG, read-only guest with actual systemd
PID 1 and the normal negative-only `podbay-r1-boot-producer` binary. It does
not establish production cold-boot provenance, a live keeper, source custody,
origin, admission, or readiness.

The offline plan SHA-256 was
`d3c9a5b42a161968f4212cc39683f15d585d6de04bbcaee9f6716196fb497cdc`;
the initramfs SHA-256 was
`3dbc2720cbdc7d69a03b45023cfd132aeed1b58d8b6ddf651722dc01b6a93aec`.
The normal producer binary SHA-256 was
`5f672ce6c43bab0361ada622af13655664d05a153bb3992f7ee5867f0ab047cf`.

The monitor installed source and lock inotify watches, exercised real
positive controls, drained them, and only then sent **monitor** readiness.
The sole 753-byte `ttyS1` event recorded this order (microseconds since
boot): armed `5259483`, producer start `5290271`, producer exit `5413589`,
window end `6248753`. Producer PID 84 exited 2 and never entered Ready;
issuer starts, watched source events, and watched lock events were all zero.
Four outside EACCES denials passed. The event retained
`production_origin=UNAVAILABLE` and `admission=UNAVAILABLE`.

QEMU PID 1673902 (birth tick 14156075) exited 0 with exact pidfd-verified
reap. Hypervisor stderr was empty; the diagnostic console ended with one
`reboot: Power down` and no EXEC failure. The 32 MiB read-only disk retained
SHA-256 `08beddae60a2738b4bd0af8b0f1f1f218a6f8c498563fd1467e2810dd66cd911`.
An independent read-only audit found no P1/P2 inconsistency in this bounded
evidence. Retained local result SHA-256:
`d9c2feff07fa1fe03298b4bc235cf031e8cd90a9d5d6a11668ac8047cbe2d40e`.
On this machine the raw evidence is under
`/home/olegchir/podbay-r1-producer-vm-build/producer-run-native-first/`.

The host-side watch mechanics test earlier returned ENOSPC and was explicitly
skipped; no global watch limit was changed. The fresh guest's positive
control is the actual watch evidence for this run. Inotify observes the
watched inodes during the measured window. It does not prove exclusion of
inherited FDs, mappings, queued rights, aliases, raw devices or every future
issuer. A separate trusted pre-issuer producer/keeper, two-boot custody and
durable release protocol remain required before production authority.
