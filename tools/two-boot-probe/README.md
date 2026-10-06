# Two-boot fixture preparation

This directory has a read-only inventory, an offline CLOSED-stub assembler and a
[QEMU runner](CLOSED-VM.md). The runner has passed dry-run, fake-child and one
real CLOSED-stub VM boot. There is **no two-boot barrier proof, production
admission or deployment capability**.

The separate [CLOSED marker persistence fixture](PERSISTENCE-VM.md) has now
completed two fresh QEMU boots against one new writable ext4 image. It verifies
the same closed marker/inode across distinct guest boot IDs with exact child
reap between boots. It does not execute v25 migration or release admission.
The [disposable v25 guest example](V25-GUEST.md) has now completed its own two
fresh guest boots with actual v25 activation/recovery and refusal checks. This
remains fixture evidence, not a production barrier.
`inventory.py` prints JSON and always exits 3 (`BLOCKED_NOT_BOOTED`). It opens
only the explicit ISO and device metadata, never the KVM device itself. It does
not execute discovered tools, extract files, download inputs or change services.

```sh
python3 tools/two-boot-probe/inventory.py \
  --iso /home/olegchir/Downloads/ubuntu-26.04.1-desktop-amd64.iso
```

Keep any redirected output and future build artifacts outside the repository.
The inventory validates bounded ISO9660 directory/extent records and the Linux
x86 boot header, then reports kernel/initrd byte ranges and SHA-256. Those hashes
pin observed bytes; they do not establish provenance, boot compatibility or policy
correctness. The ISO's desktop initrd must not become the fixture admission policy.

## Smallest proposed execution domain

A new external raw ext4 disk, extracted local ISO kernel and custom initramfs,
started by an ordinary-UID direct-kernel QEMU process. Use a fresh QEMU process
for each boot, no memory snapshot/resume, networking, shared folders, guest agent,
host mounts, device passthrough or existing personal VM disk. The raw disk is the
only state carried from boot A to boot B. A reviewed PID1 exclusively starts all
guest processes. Fix guest owner UID/GID to 1000. Root/kernel/hypervisor are trusted.

QEMU 10.2.1 is installed. A separate 512-byte guest boot sector executed under
KVM and emitted `KVM_GUEST_OK` (expected debug-exit status 33); the CLOSED-stub
runner itself uses TCG. Existing VMware tools and a personal VM are not a
qualified fallback. Do not start or inspect that personal VM. QEMU-img and
libvirt are unnecessary for a new raw image. Kernel config and matching
ext4/virtio module closure must be pinned;
the readable ISO alone does not establish that closure.

The current `../linux-broker-probe/broker.c` cannot be used unchanged: it creates
and deletes a random fresh store in one run, depends on SUDO_UID/GID, forks a
worker with inherited memory, and has no persistent gate or crash recovery. It
is mechanism evidence and reference code, not boot-B rebind implementation.

## Fixed guest state machine

| Boot/state | Required transition and evidence | Failure behavior |
| --- | --- | --- |
| A / CLOSED | PID1 mounts only fixture disk; creates root0700 vault, owner0700 inner directory, owner0600 tiny SQLite DB; pins inode/UID/digest. Writes root-owned policy generation, nonce and CLOSED gate; fsyncs file and parent. | Any mismatch halts closed. |
| A / NEGATIVE | Fixed diagnostic children obtain DB/directory FD, MAP_SHARED and queued SCM_RIGHTS before path protection. Verify denied new open but successful pread, same-byte pwrite/fsync, openat, mmap/msync, recvmsg then pread, all against exact inode. | Failed oracle invalidates case. Never describe existing handles as revoked. |
| A / STOPPED | Reap all exact children; remove sockets/mappings; flush DB and gate; record boot ID and byte/identity manifest; power off and wait for hypervisor exit. | Timeout preserves disk and reports exact holder; no boot B or deletion. |
| B / CLOSED | Fresh kernel and PID1; root validates fixture manifest and durable CLOSED gate. No owner process or descriptor issuer exists; PID1's closed program is the admission premise. Compare boot IDs, persistent inode and bytes. | Absent/malformed gate, foreign generation or unexpected holder halts closed. |
| B / SEALING | Clean exec reviewed worker in private namespace; sanitize FD/env/cwd/root, isolate store namespace, drop all credentials/caps, dumpable0/NNP1, audited seccomp. Root-only pipe handshake pins boot, process birth, inode, policy and artifact hashes. | No owner process starts before SealedReady. Worker/broker loss never opens vault. |
| B / SEALED | Worker first opens exact store only after sealing. Start fixed ordinary-UID probes from sanitized exec lineage. Run actual SQLite transaction/rollback and outside path/proc/import/export checks. | Any unintended authority is failure; no gate release. |
| B / RECOVERY | Fault cases kill worker or broker at each durable checkpoint. PID1 holds CLOSED independently; reaps holders; restart validates exact durable state and resumes only unambiguous direction. | Defaults closed; no reverse/second exchange, launch admission or permission restoration. |
| B / VERIFIED_STOP | Verify byte/inode preservation, exact children reaped, namespaces/aliases absent, no guest mount-holder or socket remains. Flush/power off; outside verifier waits hypervisor exit. | Preserve inaccessible disk on failure. |

Use pipe/pidfd phase handshakes with fixed deadlines, never timing sleeps as proof.
Missing evidence is failure. Serial JSONL events must include nonce, boot ID,
monotonic sequence, policy/artifact digest, process birth and syscall return/errno.
Root-only durable state is evidence, not an unprivileged caller-supplied manifest.
The host inventory's JSON is not this guest authority manifest.

## Separate control cases

The clean case must pass sealed admission and outside denials. Independent dirty
boot-B cases start an owner child before engagement, giving it respectively a
database/directory FD, queued rights or mapping. Each must prove the leak actually
works and **refuse admission before any migration operation**. An empty proc/FD
census does not establish absence of queued rights or mappings. LateEngagement
must refuse even if the deliberately leaked capability was subsequently closed.

Inject worker death and broker death before seal, after seal, after first open
and around each durable gate write. An independently surviving PID1 keeps the
launch domain held. Also kill the complete hypervisor, then restart the same disk
in closed mode; distinguish orderly poweroff from power-loss recovery. Missing or
partially written gate records must be refused. Killing PID1 destroys the guest;
it cannot be presented as surviving guest recovery.

Migration receipt, activation, pending and first Owner epoch are **not implemented
by the tiny SQLite fixture**. Model checkpoint names are insufficient evidence.
A later atom must include the actual protocol and independently review its
crash boundaries. Minimal PID1 establishes only its enumerated execution domain;
real systemd user manager/login/cron/container/privileged-issuer policy requires
a separate representative boot test. No production constructor is released here.

## Cleanup and next implementation atom

Pin all future external paths/inodes and created disk ownership before launch.
Guest cleanup removes only manifest-listed fixture entries after exact holder
teardown; it never exposes the vault or recursively deletes unknown entries.
Outside cleanup verifies the exact hypervisor process exited and all its handles
closed, then removes only its named image/initramfs/log artifacts. Never touch
host units, mounts, sudo/PAM/polkit policy or existing VM assets.

Next: implement reviewed fixture PID1 and persistent broker/rebind with a clean
exec worker, then build a writable raw disk/initramfs for separate boot A and
boot B processes. The existing CLOSED-stub boot is only an execution-domain
smoke test. Booting/rebooting the owner machine, production store cutover and
production policy installation remain outside this fixture.
