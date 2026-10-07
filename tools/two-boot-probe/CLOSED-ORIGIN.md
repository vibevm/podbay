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

## Separate two-boot diagnostic candidate

`run_r1_two_boot_origin.py`, `init.r1_two_boot.c`, `r1_two_boot_probe.c` and
`r1_two_boot_checkpoint.h` add a separate fixed crash/recovery fixture. The
default runner only builds a fresh canonical schema24 specimen, two static
executables, an initramfs and a retained 32 MiB ext4 image. It neither adopts an
existing image nor restores a handle from a checkpoint.

```sh
python3 -B tools/two-boot-probe/run_r1_two_boot_origin_test.py
python3 -B tools/two-boot-probe/run_r1_two_boot_origin.py --name r1-new-offline
# Only after independent source review and explicit disposable-VM authorization:
python3 -B tools/two-boot-probe/run_r1_two_boot_origin.py --name r1-new-reviewed \
  --run --qemu-sha256 <reviewed-installed-qemu-sha256>
```

Both boots begin with the fixed PID1 as the only launcher, no inherited data
descriptors and a root0700 unmounted `/fixture`. The CLOSED event precedes any
seed or source data read. After mounting the sole fixture device, PID1 keeps
the mount root and vault root0700 and the store owner1000/0600 under its
owner1000/0700 directory. The clean broker's private mount namespace, chroot,
descriptor closure, privilege drop and seccomp policy follow the one-boot
mechanism above. No other executable or owner process can run before CLOSED.

Boot A creates the source and exact manager lock, runs the clean broker with
an open source FD, and checks outside source/sidecar, proc and namespace denial.
It fsyncs the source, lock and directories, then writes a bounded canonical
checkpoint using file fsync, no-replace rename, directory fsync and exact
readback. The checkpoint binds the nonce, fixture declaration, Boot A, source,
parents, lock, executable/policy hashes and historical broker identity. After
a fresh held-FD response and pidfd liveness check, PID1 emits crash readiness
and waits indefinitely. The host validates that complete event prefix before
SIGKILL of the exact QEMU pidfd, verifies exit -9 and reaps it. It preserves raw
logs and the same image before starting Boot B in a new QEMU process.

Boot B reinstalls CLOSED before opening the checkpoint or source. It refuses
partial, noncanonical, foreign, same-boot or changed-identity records and
acquires the exact manager lock anew. The decoded record is historical data;
it creates no authority and supplies no inherited FD. Boot B validates the
unchanged source bytes, runs a fresh read-only broker, kills/reaps that exact
broker and repeats outside denial while PID1 retains the vault and lock. The
host requires a distinct guest boot ID and an unchanged source/checkpoint
tuple. Every accepted event says `admission=UNIMPLEMENTED` and
`origin_restored=false`.

On 2026-10-07, the static compiler and nine offline codec/parser/fake-child
tests passed. The first compiler failure and initial pinned candidate are
retained in the external report. After parent source review, the first VM
attempt `r1-guest-reviewed` failed in Boot A before seed/source reads: the phase
parser did not consume `/proc/cmdline`'s trailing newline. Its first failure
event also incorrectly labelled the gate CLOSED before establishment. Exact
QEMU PID 1433686/birth 9244865 was killed through its pidfd and reaped with exit
-9; Boot B was not launched. The raw first failure and image are retained.

The correction uses one tested whitespace-aware phase parser and an explicit
closure-established flag. A bootstrap failure now says `PRE_CLOSURE`; only the
validated `closed_before_source` transition sets CLOSED. New offline controls
exercise trailing-newline/malformed/duplicate phase tokens, the gate label and
strict parser refusal of a PRE_CLOSURE success stream. Both static builds and
all nine tests passed again. A second parent-authorized attempt,
`r1-guest-corrected`, passed phase parsing, CLOSED, vault creation and lock
acquisition, then failed because informational kernel TSC calibration output
interleaved inside the `seed_read_started` JSON record. The strict host parser
refused that malformed stream; exact QEMU PID 1436934/birth 9268971 was reaped
with -9 and verified pidfd exit. Boot B was not launched, and this second image
and raw failure are retained separately.

The current runner explicitly uses `loglevel=4` to suppress informational
kernel console chatter while retaining kernel error output. It still refuses
any corrupted/interleaved event rather than repairing the stream. PID1 formats
each complete JSON line into a fixed 2048-byte buffer and rejects truncation.
It issues one `write` request, retries only EINTR with no reported written
bytes, and refuses any short positive write. This is best-effort diagnostic
framing, not kernel/serial atomicity. An actual-pipe capture control verifies
malformed input cannot trigger the crash-ready signal. A separate ordinary-UID
C control calls the actual PID1 event function without bootstrap, checks the
pre/post-closure labels and validates exact complete JSON bytes/length below
the cap. All eleven offline tests and both static builds passed. The current
offline build is
`/home/olegchir/podbay-r1-two-boot-origin-build/r1-offline-single-write/`;
the source patch, pins, both raw failures and evidence are at
`/fast/git/v/research/2026-10-07-podbay-r1-two-boot-origin/`.
The third parent-reviewed attempt, `r1-guest-serial-corrected`, exited 0 with
`DISPOSABLE_TWO_BOOT_CLOSED_RECOVERY_NO_PRODUCTION_ADMISSION`. Boot A emitted
19 exact events and held its broker FD at the durable checkpoint. Exact QEMU
PID 1440085/birth 9312144 was killed through its pidfd, exited -9 and was reaped.
Boot B used a new kernel on the same retained image, emitted 39 exact events,
reacquired the lock without restoring authority and completed maintained
outside denial through fresh broker death. Its QEMU PID 1440098/birth 9312630
exited 0 with verified pidfd exit/reap. Both host PIDs are absent.

The distinct guest boot IDs were `f9d1b6d1-6c4d-4af9-8321-7213b67b4703` and
`f284b4d9-987d-491e-a093-12a045bb93c8`. Source device/inode/owner/size/hash and
checkpoint hash/inode/old-broker tuple matched across them. The parent
independently checked those tuples, event counts, process absence, result hash
and retained final image hash
`7993624565cdcc700b5fb23044761116670bc4535dbe1fc2aff016ce886413b7`.
Full raw logs, results and image are at
`/home/olegchir/podbay-r1-two-boot-origin-build/r1-guest-serial-corrected/`.
Both earlier failed images/logs remain separate. Synthetic offline test
receipts remain explicitly marked `OFFLINE_FAKE_CHILD_TEST`.

The successful run covers one selected crash after a durable checkpoint, followed
by a fresh kernel. The host fsyncs the retained image only after exact QEMU reap;
this does not model host power loss. Offline corruption tests exercise the
actual checkpoint decoder; they do not establish guest filesystem behavior at
every interrupted write/rename window. The guest uses raw exact-byte probes;
full canonical SQLite validation occurs offline before packaging, and whole
source hashing binds those bytes in the guest. The filesystem UUID is a
host-created declaration in the pinned config, not a guest superblock probe.
This fixture adds no migration, pending/final mutation, admission API, production
constructor, owner-machine deployment or warm recovery. Root/kernel/hypervisor,
the invoking host UID and toolchain remain trusted. Preexisting FD, directory
FD, mmap and queued SCM_RIGHTS still require an independently proved old-issuer
exclusion boundary before any production release.

## Production-compiled pre-source refusal seam

`crates/podbay-host/src/access_barrier_gate/bootstrap.rs` is a separate private
ordinary-build entry/lifetime boundary. Its borrowed request contains only an
unobserved intended boundary path and optional historical bytes. It requires
no source, stage, lock, lineage, PID/UID, boot, policy digest or artifact identity
to exist before exclusion. No request field can assert CLOSED or NeverStarted.
Constructing `PreSourceAttempt` creates inert bookkeeping only.

Acquisition returns `Result<Infallible, BootstrapRefusal>`: there is no safe Rust
success value or origin witness to return. On Linux, well-formed fresh requests
refuse with `LauncherEnforcementUnavailable`, malformed paths refuse with
`MalformedRequest`, and supplied historical bytes refuse with
`HistoricalInputCannotAcquire` without being decoded, hashed or copied. Other
targets refuse with `UnsupportedTarget`. The first refusal is sticky for that
attempt; creating another attempt still confers no authority. Drop has no
callback or release effect.

The entry uses only core operations. Its borrowed deferred-I/O observer is
never invoked: there is no filesystem, lock, socket, process or checkpoint
implementation. The observer is a testing boundary, not an enforcement oracle
or a source of evidence. There are no runtime callers, public exports, store
open grants, migration conversions, admit/release operations or Ready results.
The existing inert calculus remains unchanged, and `codec/closed_origin.rs`
remains restricted to Linux tests. A valid inert InitialClosed record passed
through the actual codec still cannot acquire a live origin through this seam.

Focused tests cover malformed and well-formed inputs, opaque historical bytes,
a real valid codec record, sticky refusal, new attempted lifetimes, drop, a
counting observer with a real disposable marker positive control, and unchanged
disposable source/checkpoint/lock specimens. The observer and snapshots prove
the stated tested boundary; they are not OS exclusion observations. An external
no-std compile control checks the ordinary module body, and the ordinary Host
check ensures the module is present outside cfg(test). The exact offline gates,
source pins and retained candidate report are at
`/fast/git/v/research/2026-10-07-podbay-r1-bootstrap-seam/`.

This seam establishes no production CLOSED boundary, old-issuer exclusion or
admission. The recorded disposable two-boot success does not supply a missing
production launcher. Actual enforcement still needs a separately reviewed
launcher and a custodian-loss experiment with the kernel and an open-FD broker
still alive; whole-guest termination does not establish that property. Live
schema24 stores, deployment, services, VM execution, migration/pending state and
CLI routing are unaffected by this preparatory atom.
