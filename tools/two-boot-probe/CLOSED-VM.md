# CLOSED-stub VM runner preparation

`run_closed_vm.py` defaults to a dry-run. It verifies fixed SHA-256 values for
`final-a/vmlinuz`, `final-a/initramfs.cpio.gz` and `final-a/fixture.raw` under
`/home/olegchir/podbay-two-boot-offline-build`, checks the unbooted CLOSED build
report, creates a new owner `0700` run directory and an exclusive mode `0600`
byte copy of the raw disk with a different inode. Existing paths and symlinks
are refused. Input/build ancestors and created paths use the assembler's retained
descriptor/identity checks. This trusts root and the invoking UID.

```sh
python3 -B tools/two-boot-probe/run_closed_vm.py --name vm-dry-review
python3 -B tools/two-boot-probe/run_closed_vm_test.py
```

These commands do not start any process other than Python. Dry-run artifacts are
retained for review, including `plan.json` and the fresh disk copy. Exit 0 means
preparation succeeded. No boot or two-boot result follows from that exit code.
All generated artifacts stay under the fixed external build root.

The prepared QEMU command uses fixed `/usr/bin/qemu-system-x86_64`, TCG, one CPU,
512 MiB, direct kernel/initramfs and only the fresh raw virtio disk in read-only
mode. `-no-user-config -nodefaults`, no network, no display, no monitor, no shared
folders, no guest agent, no host device passthrough, no snapshots/resume and no
arbitrary QEMU options. The serial backend writes stdout; stdin is `/dev/null`,
with no monitor mux or signal input. No KVM device is opened.

QEMU is installed and the owner authorized its local setup and virtualization
check. The actual CLOSED-stub run on 2026-10-06 used installed QEMU SHA-256
`0cd4112a8f0cb891eb7c10e8df38c9dfeec8c7389bb22db6aa425f0d6fe733dc`.
The accepted run retained its separate disk and receipt at
`/home/olegchir/podbay-two-boot-offline-build/vm-closed-20261006-accepted/`:
`CLOSED_STUB_OBSERVED_UNIMPLEMENTED`, QEMU exit 0, exact child reaped and pidfd
exit verified. Two earlier runs returned `VM_FAILED_OR_LIFECYCLE_UNVERIFIED`
because the serial parser rejected ordinary kernel clocksource/ACPI lines after
the exact stub event. Their disks and logs remain under sibling run directories.
The parser now permits only that bounded observed shutdown sequence, and its
14 fake-child/unit tests pass. Tool path trust is not execution-inode attestation; installed
firmware/shared-library dependencies remain within trusted host tool state.

The live branch passes only pinned kernel/initramfs/fresh-disk descriptors and
uses `/proc/self/fd` paths for QEMU inputs. It records exact child PID/process
birth, holds a pidfd, limits capture to 120 seconds, 2 MiB serial and 128 KiB
stderr, and kills/reaps the exact child on timeout/failure. SIGTERM, SIGHUP and
SIGINT handlers latch intent before launch and remain installed through teardown
and receipt/reporting. The capture loop checks the latch at most one second
apart. Handlers record intent during Popen rather than interrupting it before the
child handle is returned. Previous handlers are restored afterward. It never signals an
unrelated process group or recursively removes a directory. Logs are
`serial.raw`, `qemu.stderr`, validated `guest-events.jsonl` and `result.json`.
Both success and failure retain the image. The result receipt and raw logs are
fsynced, and the result parent directory is fsynced before reporting. Broken
stdout or receipt failure preserves the launched-child state and reports a
lifecycle/reporting failure instead of claiming nothing started. Unverified
teardown must be investigated before cleanup. Fake-child tests exercise this
control flow; actual QEMU/host process teardown remains unverified.

Only one exact `fixture_stub` CLOSED/unimplemented JSON event, normal QEMU exit
and verified pidfd exit/reap can produce `CLOSED_STUB_OBSERVED_UNIMPLEMENTED`.
Malformed, repeated, missing or failed events are failure. Invalid UTF-8, NUL,
JSON arrays and fatal kernel diagnostics fail closed. After the exact event, only
blank lines, a non-repeating optional subset of the observed clocksource/ACPI
shutdown messages, and at most one exact `reboot: Power down` line are allowed
in either observed order;
arbitrary trailing output is rejected. Kernel/BusyBox text
is retained in `serial.raw`; JSON records are separately validated. The launch/report transaction never automatically deletes the disk. A separate
internal cleanup helper refuses unless exact reap/pidfd exit and a durable
successful retained-image result receipt are supplied, then checks and removes
only the exact unchanged fresh disk inode and syncs its parent. There is no CLI
cleanup command in this preparation. The baseline image is never deleted or used
writable.

The guest event currently lacks runtime nonce, boot ID, sequence and artifact
attestation. Its exact message is only a stub oracle. The successful VM
run does not prove boot-A handle controls, fresh boot-B sealing, persistent
broker/rebind, late engagement refusal, recovery, production admission or the
campaign's full serial contract. Those remain separate implementation/test work.

The unit suite uses fake Popen children and mocked pidfd signaling; the separate
real run booted the exact CLOSED-stub and recorded QEMU exit, pidfd exit and
reap. The unit suite covers launch/capture signals, timeout,
capture overflow, immediate exit, pidfd-open/API failure, durable receipt failure,
broken stdout, safe cleanup prerequisites and retained images. Supported Python
`os.pidfd_open` and `signal.pidfd_send_signal` must be callable before launch; a
runtime pidfd-open failure triggers exact Popen-child kill/wait and retains the
image without claiming pidfd verification. SIGKILL of the supervisor and host
crash cannot be handled by this user process; no survival claim is made.
