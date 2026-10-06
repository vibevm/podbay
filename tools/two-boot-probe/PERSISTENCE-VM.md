# Disposable CLOSED marker persistence runner

This separate runner leaves `run_closed_vm.py`, its read-only CLOSED-stub image,
and all existing VM/service assets untouched. Default execution only assembles
new artifacts. It creates a NEW exclusive owner0600 32 MiB raw ext4 image below
`/home/olegchir/podbay-two-boot-persistence-build/<persist-name>/`. Every run name
must be new. Images and logs are retained on success and failure; there is no
cleanup CLI. Output identity/permissions use the existing retained-descriptor
assembler checks. Root and the invoking UID remain trusted.

```sh
python3 -B tools/two-boot-probe/run_persistence_vm_test.py
python3 -B tools/two-boot-probe/run_persistence_vm.py --name persist-review-dry
# After independent source/input/lifecycle review only:
python3 -B tools/two-boot-probe/run_persistence_vm.py --name persist-reviewed-pair \
  --run --qemu-sha256 <reviewed-installed-qemu-sha256>
```

Input is the existing pinned `final-a/vmlinuz`, matching kernel config and
modules.builtin. The runner does not rebuild/read the ISO or reuse the baseline
image writable. It compiles a static C PID1 with the installed GCC toolchain,
records source/tool/binary hashes, builds an initramfs containing only that PID1,
console, empty mount points and a fresh random nonce, then formats its new image
with pinned mke2fs. Compiler headers/archives, QEMU libraries/firmware, host root
and invoking UID are trusted local inputs; executable hashes are not portable
provenance or execution-inode attestation.

With `--run`, two separate ordinary-UID QEMU children use TCG, direct kernel,
no network/display/monitor/shared folders/guest agent/device passthrough and only
the exact new writable disk. The same host image inode/descriptor is retained
between boots. Each child must exit0, be reaped and have pidfd exit readiness
before the next boot. A signal latch spans both boots. Timeout/capture/parse or
teardown failure retains all artifacts and prevents boot B. SIGKILL of the host
runner and host crashes cannot be handled by this user process.

Guest A creates root0700 `/closed`, fsyncs its parent, writes one exact bounded
CLOSED/UNIMPLEMENTED marker through exclusive no-follow mode0600 `gate.writing`,
fsyncs it, publishes `gate.record` by no-replace rename and fsyncs the directory.
Guest B refuses any `gate.writing`, wrong mode/owner/link/type, unknown/partial/
foreign marker bytes or a reused boot ID. It validates exact nonce, stored boot-A
ID and fixed payload, and starts no issuer/Owner process. Both guests unmount
and request poweroff; PID1 never returns or launches a shell. Serial output binds
nonce, boot IDs, inode and exact marker bytes; host validation compares both
records and requires distinct boot IDs and identical marker inode/bytes.

Offline tests exercise the actual C decoder, malformed/truncated marker and
foreign/reused boot controls, fresh image/refusal behavior, fake child timeout
and exact reap flow, stopping after boot-A failure and same-image two-call
sequencing. These tests do NOT boot a guest. Real malformed `.writing`/image
controls and hypervisor power-loss recovery are separate unproved work.

A successful pair reports only `TWO_BOOT_CLOSED_MARKER_PERSISTED_NO_ADMISSION`.
There is **no actual v25 migration/admission**, root broker, process sealing,
Owner epoch constructor, read/launch barrier, rollback protocol, held-handle
negative control or production token. Orderly two-boot ext4 marker persistence
is infrastructure evidence, not production barrier acceptance.

## Actual two-boot receipt, 2026-10-06

The parent ran `persist-parent-20261006` with installed QEMU SHA-256
`0cd4112a8f0cb891eb7c10e8df38c9dfeec8c7389bb22db6aa425f0d6fe733dc`.
The retained result is
`/home/olegchir/podbay-two-boot-persistence-build/persist-parent-20261006/result.json`.
The runner exited 0 with `TWO_BOOT_CLOSED_MARKER_PERSISTED_NO_ADMISSION`.
Boot A and B each exited 0, had pidfd exit verified and exact child reaped;
both PIDs were subsequently absent. Boot IDs differed, while guest marker
inode 13 and exact marker bytes matched. The retained 32 MiB image SHA-256
`c905b6e4537d33a337259f1e27bece9f648689866c7f03820b3419d2b500da06`
matches the result receipt. Each serial log contains one accepted event.
The copied repository source files retain the scratch candidate's hashes:
PID1 `296a9f0a59d19fbb4a801c0a316adad36389198fb7dac9ee8dc7547baf458084`,
runner `33899e9a04fb4a700396c99cfed4694f12889fb36030709725b31e1862261fb9`.
The seven offline tests passed before this run and again after copying the
sources; the parent log is
`/fast/git/v/research/2026-10-06-podbay-two-boot-persistence/parent-offline-after-copy.log`.
This receipt does not include a malformed
guest disk or power-loss negative run.
