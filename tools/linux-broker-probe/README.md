# Disposable Linux broker probe

This is a fixed Linux x86_64 experiment with one tiny SQLite database. It has no
production constructor, caller-selected store path, arbitrary worker command,
service integration, installation, or migration interface. **Do not use it as a
production access barrier.** Root/kernel and the reviewed bootstrap/worker code
are trusted. The outside probes run as the invoking ordinary UID.

## Build and run

Provide a local SQLite header directory and shared library explicitly. Nothing
is downloaded or installed. The external report records the exact local inputs,
compiler command, source hash, binary hash, and header/runtime versions.

```sh
make -C tools/linux-broker-probe \
  OUT=/fast/git/v/research/2026-10-06-podbay-linux-broker-build \
  SQLITE_INCLUDE=/absolute/local/sqlite/header/directory \
  SQLITE_LIBRARY=/absolute/local/libsqlite3.so
python3 tools/linux-broker-probe/test.py --run
```

The runner launches exactly `sudo -n <OUT>/broker --test-only`. The C bootstrap
requires a nonzero invoking `SUDO_UID`/`SUDO_GID`, refuses additional arguments,
and creates its own random 128-bit nonce under root-owned sticky `/var/tmp`.
No path is accepted from the caller. Build outputs and all run logs stay outside
the repository. The Makefile permits only the packet's external output directory.

## Sequence and observed checks

1. Pin `/`, `/var`, and root-owned sticky `/var/tmp` with no-follow directory
   opens. Create a root-owned `0700` nonce vault, an original owner-UID `0700`
   inner directory, and an original owner-UID `0600` SQLite file. Record database
   bytes, device, inode and owner. The only outside alias is a nonce symlink;
   an empty nonce directory is reserved for an outside user-namespace bind test.
2. Fork a fixed worker. It unshares its mount namespace, makes propagation
   recursively private, mounts a private tmpfs scaffold, binds the exact inner
   directory to `/probe/store`, and chroots into the scaffold. No host bind
   mount is installed. No `/proc`, socket, or device tree is mounted there.
3. Replace standard descriptors with control/status pipes. Inventory inherited
   descriptors, close the complete range starting at 3, then verify every
   inventoried descriptor and the deliberate inherited database/directory
   handles are `EBADF`, before the worker's first file access to the store.
4. Drop supplementary groups, real/effective/saved UID/GID, ambient/bounding/
   effective/permitted/inheritable capabilities, then set and check
   `no_new_privs=1` and `dumpable=0`. Install an x86_64 seccomp allowlist; wrong
   architecture/x32 calls are killed and unlisted native syscalls return
   `EPERM`. The worker cannot change dumpability, exec/fork, create sockets,
   send messages, join/create namespaces, ptrace, or import via `pidfd_getfd`.
   File, memory, signal, clock and SQLite calls are allowed inside the chroot.
5. Use explicit sealed/begin/open/stop/done pipe handshakes. Actually attempt
   the listed forbidden syscalls. Open the database, compare UID/device/inode/
   mode, execute a SQLite read/write transaction with update and rollback, then
   hold the inside handle while outside attempts execute.
6. An ordinary-UID process with sanitized descriptors attempts raw open,
   SQLite READWRITE open, symlink, `/proc/<worker>/root`, `/proc/<worker>/fd`,
   and worker namespace-handle access. It also actually calls mount-namespace
   `unshare`. If the host admits a new user+mount namespace, it maps its own
   UID/GID and attempts an actual bind of the protected source directory in
   that private namespace. The log distinguishes an unavailable user namespace
   from a tested user-namespace bind denial; no inaccessible handle is described
   as a completed `setns` call.
7. A separate **deliberately broken negative control** keeps only an inherited
   database FD and directory FD. New pathname access still fails, but actual
   `pread`, same-byte `pwrite`+`fsync`, and directory-relative `openat` work.
   The normal worker closed those descriptors before its ready handshake. The
   negative demonstrates that pathname denial cannot revoke an issued handle.
8. Stop and reap exact children using pidfds and bounded phase waits. Compare
   the original pathname and open handle's identity plus all database bytes.
   Remove only inode-checked nonce entries using pinned directory descriptors,
   close all handles, and compare the supervisor's namespace and complete mount
   table. No unit/job APIs or service configuration are used anywhere.

## Cleanup and scope limits

The supervisor funnels ordinary failures and interrupted protocol waits through
cleanup. It never opens the vault to the owner for cleanup. Unexpected inode,
ownership, contents, or child state is a failure; it does not trigger recursive
deletion or broad path cleanup. A retained failed vault stays root `0700` and
must be reported for exact operator cleanup. This disposable test does not
provide crash/SIGKILL recovery or a persistent recovery service.

After root exits, the runner starts a **separate ordinary-UID verifier**. It
checks all three exact nonce paths are absent, reaped PIDs have disappeared,
the fixture has no mount in the caller's namespace, and the supervisor reported
an unchanged host mount table. It also compares its own namespace/mount table.
Cleanup can be independently repeated without privilege:

```sh
python3 tools/linux-broker-probe/test.py --verify /absolute/external/probe.jsonl
```

This is evidence for this fixed fresh fixture and syscall trace, not proof of
all hostile interleavings or a production authority domain. The forked worker
is reviewed fixed code; its inherited bootstrap heap/library state is not an
attested clean address space. The allowlist is not a general untrusted-code
sandbox or SQLite compatibility promise. A privileged adversary can bypass it.
The worker deliberately has writable authority over the admitted fixture.

No cold-boot admission, absence of preexisting FD/SCM/mmap capabilities, two-boot
proof, source launch inhibition, production barrier, live cutover, or general
revocation is established. The negative control specifically falsifies late
FD revocation. Killed bootstrap cleanup, persistent recovery, clean launch
lineage, and production policy require separate atoms and authorization.

Evidence and exact repeat command:
`/fast/git/v/research/2026-10-06-podbay-linux-broker-report.md`.
