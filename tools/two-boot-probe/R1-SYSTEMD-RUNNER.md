# Disposable systemd runner

`run_r1_systemd_vm.py` is separate from the offline builder. Its default creates
fresh private copies and durable plan/result receipts; it launches nothing.
A native invocation additionally requires `--run` and an explicitly reviewed
`--qemu-sha256`, after parent source review and a fresh-name disposable go.
There is no native result from implementing or testing this runner.

Prepare-only example for the corrected candidate:

```
python3 -B tools/two-boot-probe/run_r1_systemd_vm.py \
  --name systemd-run-review-new \
  --input /home/olegchir/podbay-r1-systemd-vm-build/systemd-umount-a \
  --input-plan-sha256 663536a6e677b8f39b55913d692f151e77c12374f0699703d8ab36b6cb71e287
```

Do not reuse a prepare-only directory for execution. Every invocation copies to
one new exclusive directory under the existing trusted private build root. A
failed or successful directory is retained; no automatic retry, replacement,
cleanup or deletion exists. Input reads and copies retain inode/owner/mode/FD
checks. Size bounds are applied before input hashing. The exact bounded plan-byte capture is hashed again immediately before parsing/copying; same-inode rewrites cannot borrow the earlier pin. Exact plan, artifact,
helper/parser source pins and explicit builder_sha256 are required; an earlier
unsafe /init or mismatched current parser generation refuses before copying.
Caller-provided argv from the input plan is never executed.

The native path constructs fixed TCG argv: no network, display, monitor, host
mounts/devices or KVM; readonly specimen disk. Kernel/archive/disk descriptors are explicitly retained/passed. A second fixed ISA serial port routes ttyS1 to a preopened pipe writer passed as /proc/self/fd/N; only that writer enters the child. The host selector drains its read end into guarded events.raw, independently of ttyS0 serial.raw and QEMU stderr. Events are capped at2048 bytes, with the bounded prefix retained and exact kill/reap on overflow. No guest controls a host filename. The exact Popen child gets pidfd and birth
identity; capture is bounded to 120 seconds, 2 MiB serial and 128 KiB stderr.
Timeout/error triggers exact owned-child teardown and bounded reap. Failure to
obtain pidfd falls back only to the still-owned unreaped Popen child, never
claiming pidfd verification. Unknown teardown preserves the image without
claiming a stable post-exit image hash. Interrupted, failed-parser, nonzero-exit,
stderr, changed-image or uncertain-reap runs cannot pass. The first failure is
retained even if teardown/reporting also fails.

Raw console/events/stderr and the image remain on every path. Result output is fsynced
with the output directory; a durable receipt/reporting failure exits nonzero
and carries known launch/reap state. Normal success additionally requires the
strict systemd-specific `native_receipt`, exact zero exit/reap/pidfd evidence,
empty stderr and unchanged kernel/archive/disk hashes. The observer channel must contain exactly one strict event with no ANSI. Console checks separately require final unique shutdown and normalize CR before destructive stripping, reject nested escape controls, and scan raw/CR-normalized text plus text after each CSI, OSC and DCS stage for fatal tokens; ANSI is never structural event data. Its only native pass
label is `BOOTSTRAP_REFUSED_ISSUERS_BLOCKED_NO_PRODUCTION_ADMISSION`.
No CLOSED authority, custody, broker sealing, release or readiness follows.

Offline tests:

```
python3 -B tools/two-boot-probe/r1_systemd_runner_test.py
python3 -B tools/two-boot-probe/r1_systemd_test.py
```

Runner tests substitute harmless Python children, never QEMU, and mark all
receipts `SYNTHETIC_TEST_ONLY`, `boot_executed=false`. Even synthetically valid
serial only yields `SYNTHETIC_LIFECYCLE_VERIFIED_NO_VM_PROOF`. Tests cover pinned
input/source mutation, fixed argv/FDs, timeout, pidfd/birth failure, invalid
parser data, nonzero exit, stderr, receipt failure and unknown reap, while
retaining first raw bytes and unchanged fixture files. Those tests do not prove
a native systemd boot. Invoking UID/root, kernel and installed QEMU/toolchain
remain trusted; no hostile same-UID or arbitrary-root containment is claimed.

A stopped machine-none local QEMU probe confirmed its file chardev can open the preopened pipe descriptor and quit with exact pidfd reap. No guest kernel/disk/CPU or ISA-UART write was exercised by that probe. Actual ttyS1 discovery/output remains a separately reviewed native gate.

Console `Failed at step EXEC` diagnostics are fatal even when the observer event and powerdown marker are present. The retained second native run is qualified negative-mechanism evidence, not a clean-shutdown pass.
