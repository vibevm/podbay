# Disposable appliance read custody, version 1

This separate fixture can establish an **owned, live, read-only custody resource
inside a closed disposable appliance**. It cannot construct `ColdOriginPermit`,
open a production Store, migrate, publish, activate, release an issuer, or enter
an Owner epoch. The normal bootstrap/custodian and negative producer remain
unchanged. No image flag, JSON value, caller UID or configured hash is a boot
witness. The closed-image assumption is discharged outside the keeper by the
reviewed host runner, pinned fresh kernel/archive/disk and native observation.

## Explicit trusted launch closure

The archive contains the pinned setup `/init`, actual systemd PID1, its executor,
shutdown helper, util-linux umount, fixed runtime loader/libraries, static
BusyBox, keeper, custodian and diagnostic monitor. There is no shell/getty,
network, user manager, package manager, generator or arbitrary startup unit.
The target requests monitor, keeper and one UID1000 sentinel issuer. The monitor
is Type=notify and arms before the keeper; its READY means only monitor arming.
The keeper is Type=notify, Restart=no, **never sends READY**, and has
KillMode=process so the observer's keeper kill does not substitute systemd's
child kill for the custodian's parent-loss response. The issuer Requires+After
and BindsTo keeper and remains unstarted. The monitor, PID1, kernel and host are
trusted diagnostic/launch components, not adversarial peers.

## Subject and attempt

`/fixture` and `/fixture/vault` are root0700 before source exposure, mounted
ext4 readonly,noload,nosuid,nodev,noexec. `/fixture/vault/state` is UID/GID1000
0700; `db.sqlite` and preexisting `db.sqlite.manager.lock` are UID/GID1000 0600,
regular and singly linked. Keeper retains the directory chain and repeatedly
compares current named parents/leaves, device/inode and policy. Every subject
component below fixture must be on fixture's held device. The keeper creates
`/run/r1-appliance/attempt` O_EXCL before lock/source/child; handle loss never
removes it. It opens the preexisting lock O_RDONLY and holds exclusive flock.
No root process reads source bytes. This is a descriptor-only UID bridge; no
SQL pathname access, ownership change or writable source admission occurs.

## Private handoff and seal

Raw fork setup duplicates only FD0 null-read, FD1 response-write, FD2 null-write,
FD3 source-read, FD4 command-read and FD5 keeper-pidfd, then closes FD6 upward and
executes the fixed custodian with a fixed environment. Mandatory controls create
an extra inheritable source FD257, actual queued SCM_RIGHTS FD258 and a source
mapping at a fixed address; clean exec must eliminate all three. These are
trusted setup controls, not claims that arbitrary old holders were revoked.

The custodian validates its actual parent/subject/FD shape, makes a private mount
namespace and empty chroot, drops groups/UID/GID to1000 and every capability,
sets nondumpability and no_new_privs, and installs an x86_64 seccomp allowlist.
Only source pread, command read, bounded response writes, parent polling and
needed memory/runtime operations remain. Source write, file-backed/shared mmap,
open, process creation/exec, descriptor duplication/import, socket/SCM transfer,
namespace changes and pidfd import/signalling are denied. Real syscall denial
controls must pass before the sealed response. The host has not exercised this
privileged branch offline; native failure is retained rather than bypassed.

The keeper sends one random nonce and image generation. The custodian hashes
actual FD3 bytes, verifies the source hash and returns the nonce, generation,
subject and SHA256(domain || nonce || actual_source_SHA256). Keeper verifies all
fields and recomputes that binding from the pinned source digest without reading
source bytes. Fixed-length records reject queued surplus/EOF before source read
or publication; later bytes terminate custody. The custodian retains FD3 and
polls keeper pidfd/command liveness without a second read grant.

On ordinary error, keeper explicitly kills/reaps the child while retaining its
lock. Unknown teardown retains the stack/lock indefinitely so the bounded host
supervisor rejects the run; it never claims clean release. SIGKILL of keeper
necessarily releases its kernel flock before child exit. Root-vault denial,
spent attempt and unreleased issuer gate remain throughout that interval.

## Native oracle and two boots

The monitor self-tests inotify on separate `/run` controls before watching the
source/lock. It performs no source-content read. It checks monitor-before-keeper,
actual read response, live pidfds, UID/caps/seccomp/FD0..5/chroot, absence of the
controlled source map, outside UID1000 denial and actual lock contention. It
kills the exact keeper, observes both pidfds exit and an empty/removed service
cgroup, checks no READY/restart/issuer start, runs the real spent-attempt refusal
with no new watched source/lock events, and checks lock release only after death.
A strict ttyS1 event is accepted only with clean ttyS0 shutdown and exact host
QEMU reap. Inotify proves only its watched inode window; it is not a universal
FD/mmap/raw-device exclusion detector. The clean-image launch closure is the
separate exclusion premise.

`run_r1_appliance_vm.py` defaults to prepare-only. An explicitly reviewed `--run`
performs BootA and, only if BootA fully succeeds, fresh BootB from separate private
copies with a new QEMU/kernel lifetime. Both execute the same custody/loss/spent
controls. Boot IDs and nonces must differ; specimen and generation must match.
No failed boot is retried. Images, first raw channels and durable receipts stay
retained. Even a successful pair reports production_origin and migration_admission
UNAVAILABLE. Synthetic tests never count as native evidence.
