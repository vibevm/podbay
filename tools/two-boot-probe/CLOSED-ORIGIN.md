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

## Disposable guest PID1 and issued-capability controls

The separate `run_closed_origin_vm.py` runner builds `init.closed_origin.c` and
`closed_origin_probe.c` as static x86_64 executables. It generates a fresh
canonical schema24 specimen from `schema_v24.sql`, verifies its exact schema,
lineage, integrity and user_version through an immutable read-only connection,
and packages only these fixture bytes. No live database is read.

```sh
python3 -B tools/two-boot-probe/run_closed_origin_vm_test.py
python3 -B tools/two-boot-probe/run_closed_origin_vm.py --name origin-new-offline
# Only after independent source review and explicit disposable-VM authorization:
python3 -B tools/two-boot-probe/run_closed_origin_vm.py --name origin-new-reviewed \
  --run --qemu-sha256 <reviewed-installed-qemu-sha256>
```

Each new run has an exclusive retained directory and new writable 32 MiB ext4
image under `/home/olegchir/podbay-closed-origin-vm-build/`. Existing names refuse.
The runner uses TCG, no network, monitor, shared folders, guest agent, host mounts,
personal disk, snapshot or device passthrough. Default execution only compiles
and assembles. It never uses host root or sudo. It records raw serial/stderr,
strictly validated events, source/binary/image hashes and exact QEMU birth,
pidfd exit and reap state; failures retain the disk and do not trigger retries.

The real guest PID1 is the only launcher. It keeps each case's vault root0700,
preserves the source's owner1000/0600 identity under owner1000/0700 state, and
retains the exact manager flock. Initial acquisition requires source24 with
stage absent. A clean-exec diagnostic broker/probe receives a private mount
namespace and chroot containing only its executable and the exact state bind.
All unrelated descriptors, including a deliberate high data FD, are closed;
UID/GID/groups/capabilities are dropped; NNP/dumpable0 and the fixed x86_64
seccomp policy precede the first data open. Outside owner-UID probes exercise
path, `/proc` root/FD and namespace-handle denials. PID1 kills/reaps the exact
broker pidfd while its data FD is open, then repeats outside denials and proves
the manager flock remains held. Vault permissions are never relaxed.

Four independent dirty cases deliberately issue a data FD, directory FD,
shared mapping with its original FD closed, or queued SCM_RIGHTS before origin
acquisition. Each first proves real continued access despite new pathname
denial. Only then does PID1 record LateEngagement refusal, reap that exact
holder, and repeat the sticky refusal. These controls explicitly demonstrate
that pathname protection does not revoke preexisting capabilities. Production
release requires an independently established old-issuer exclusion boundary.

The parent-reviewed run `origin-guest-reviewed` on 2026-10-07 exited 0 with
`CLOSED_ORIGIN_GUEST_MECHANICS_OBSERVED_NO_PRODUCTION_ADMISSION`: 57 exact events,
guest boot `880e7cb8-8408-485e-b0df-04f6ba101b80`, QEMU PID 1348908/birth 8703655,
exit 0, verified pidfd exit and reap. The parent independently confirmed PID
absence and final image hash
`96d40bbd1b355a77fa7c0a2092dedcfbbeba4ab3a06f76306589a8007934236b`.
Full artifacts and the sealed report are retained at
`/home/olegchir/podbay-closed-origin-vm-build/origin-guest-reviewed/`.
Eight offline compiler/parser/fake-child tests passed. Offline fake receipts
carry `evidence_kind=OFFLINE_FAKE_CHILD_TEST`; they are not guest observations.

This is one boot of five disjoint fixed diagnostic cases. It proves the recorded
root-vault/clean-exec/late-refusal mechanics in that guest, not a production
constructor, complete owner-machine issuer census, migration, SQLite authority
mutation, Linux death proof or readiness. The data probes use raw exact-byte
read/write/fsync or mmap/msync; actual schema24 SQLite validation is offline.
Root/kernel/hypervisor, the invoking host UID and installed toolchain remain
trusted. User-namespace bind attacks, arbitrary hostile interleavings, custodian
warm recovery, persistent CLOSED recovery across boots, PID1 loss and power-loss
durability are not established by this run. No host reboot, deployment or live
cutover follows from the result.
