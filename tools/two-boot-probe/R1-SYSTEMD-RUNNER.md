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
  --input /home/olegchir/podbay-r1-systemd-vm-build/systemd-safe-a \
  --input-plan-sha256 18e57d75af50118c7d9a5304bf6461e0f9ee4e928ee23f02e51628d010a807a6
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
mounts/devices or KVM; readonly specimen disk. Kernel/archive/disk descriptors
are explicitly retained/passed. The exact Popen child gets pidfd and birth
identity; capture is bounded to 120 seconds, 2 MiB serial and 128 KiB stderr.
Timeout/error triggers exact owned-child teardown and bounded reap. Failure to
obtain pidfd falls back only to the still-owned unreaped Popen child, never
claiming pidfd verification. Unknown teardown preserves the image without
claiming a stable post-exit image hash. Interrupted, failed-parser, nonzero-exit,
stderr, changed-image or uncertain-reap runs cannot pass. The first failure is
retained even if teardown/reporting also fails.

Raw serial/stderr and the image remain on every path. Result output is fsynced
with the output directory; a durable receipt/reporting failure exits nonzero
and carries known launch/reap state. Normal success additionally requires the
strict systemd-specific `native_receipt`, exact zero exit/reap/pidfd evidence,
empty stderr and unchanged kernel/archive/disk hashes. Its only native pass
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
