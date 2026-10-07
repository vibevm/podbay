# Separate producer Type=notify refusal fixture

This profile exercises the normal `podbay-r1-boot-producer` executable and its
v2 Type=notify template. The accepted third-run bootstrap/custodian fixture,
its source/oracle and receipts are unchanged. This builder has no VM switch;
the separate runner defaults to prepare-only. A native run requires independent
source review and a parent-authorized fresh-name go plus pinned QEMU hash.

```
python3 -B tools/two-boot-probe/build_r1_producer_vm.py \
  --name producer-new-a --producer /absolute/private-input/podbay-r1-boot-producer \
  --producer-sha256 EXACT_NORMAL_BUILD_HASH
python3 -B tools/two-boot-probe/run_r1_producer_vm.py \
  --name producer-run-new --input /home/olegchir/podbay-r1-producer-vm-build/producer-new-a \
  --input-plan-sha256 EXACT_PLAN_HASH
```

Use fresh private names. Builder uses the pinned existing kernel/runtime and
static PID1 setup, plus a fresh deterministic ext4 specimen disk. Producer bytes
are copied unchanged as root0755; no wrapper changes the producer MainPID or
NotifyAccess. Source/lock remain the existing disposable fixture layout, not a
production candidate layout. Imported artifact assembly and syscall lifecycle
helpers are pinned; old sources are not patched or monkeypatched.

## Exact graph and measurement

A new trusted monitor service is Type=notify. Producer has a fixture-only
Requires+After dependency on that monitor and stdout/stderr capture. Issuer has
the v2 Requires+After+BindsTo producer drop-in. Default target pulls all three.
The monitor's own READY is distinctly **monitor arming**, never producer READY
or origin. Producer ExecStart is the actual fixed normal binary, with no args.

Before enabling producer startup, monitor verifies PID1/artifact/source hashes,
source/lock metadata and zero prior producer/issuer start timestamp. It arms
inotify on the source and lock, then performs real positive controls: source
open+one-byte read must produce exactly OPEN|ACCESS; empty-lock open must produce
exactly OPEN. It drains those controls, records monotonic arming time and only
then sends its own readiness. Watch setup/overflow/error/unknown event fails
closed before the producer observation. Any watched event during the measurement
window fails. No host watch-limit changes are made.

Monitor requires producer Type=notify/NotifyAccess=main/Restart=no, failed
Result=exit-code, ExecMainCode1/Status2, exact refusal JSON and empty stderr,
ActiveEnterTimestampMonotonic0, NRestarts0 and a nonzero retained ExecMainPID.
Producer start must follow arming and exit precede the window end. It checks
issuer inactive/never-started/no marker, then drains watches again after the
failed/exited observation. Only after closing watches does it run its own source
hashing and four ordinary-UID EACCES probes. It writes one strict ttyS1 event
and requests systemd shutdown; console, exit/reap/pidfd and image-integrity gates
remain mandatory.

The event label is
`PRODUCER_REFUSED_BEFORE_READY_ISSUER_BLOCKED_NO_PRODUCTION_ORIGIN`.
`producer_ready=false` means no systemd ActiveEnter was observed and the exact
pinned producer reported refusal. It is not a syscall-level proof that no
notification send was attempted. Inotify counts cover the watched inode
open/access window only: **not universal FD/mmap/SCM_RIGHTS/raw-device exclusion**.
The trusted monitor deliberately reads source for hashing/positive controls
outside that window. No production origin/custody/admission or positive permit
is created.

## Offline verification

```
python3 -B tools/two-boot-probe/r1_producer_vm_test.py
python3 -B tools/two-boot-probe/r1_producer_runner_test.py
python3 -B tools/two-boot-probe/r1_producer_vm_test.py /absolute/build-a /absolute/build-b
```

Tests cover graph/arming/issuer gate mutations; all event-field mutations;
false READY/access/ordering/identity claims; channel/shutdown failure; decoder
queue overflow, unknown watch and malformed records; and synthetic host child
lifecycle failures. Synthetic receipts never count as native proof. Independent
readback checks exact archive membership/modes/hashes, ELF closure, production
binary, graph, source/lock/disk metadata and byte-identical fresh builds.

On this host, the ordinary-UID inotify watch probe returned ENOSPC. Decoder
controls passed, but the watch-mechanics test is explicitly skipped with its raw
failure retained. This is not a successful watch test. Fresh guest-kernel arming
and positive controls remain mandatory on the first future native run. If
systemd does not retain ExecMainPID or another expected field, the oracle fails
and preserves the first capture; no guess-driven relaxation or auto-retry.
