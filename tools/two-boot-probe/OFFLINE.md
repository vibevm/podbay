# Offline assembler and CLOSED PID1 stub

`offline.py` assembles local direct-kernel inputs. Its exit 0 means assembly
succeeded. **It does not mean a boot happened or a two-boot proof passed.** There
is a separate [CLOSED-stub QEMU runner preparation](CLOSED-VM.md), but its live
branch has not been executed. There is no persistent broker, sealed worker,
admission transition, recovery implementation or production interface.
`init.closed` is a reviewed source candidate with offline checks only; guest
execution is unverified.

Inputs are fixed: the explicit local ISO, its complete SHA-256 and kernel extent,
exact config and `modules.builtin` from its minimal squashfs, static x86_64
BusyBox, and installed `mke2fs`, `debugfs`, `unsquashfs` executable hashes. Config
and builtin records agree on ext4, virtio PCI/block and supporting features, so
this candidate needs no `.ko` files. Hashes pin local bytes without establishing
publisher provenance. Shared-library/runtime dependencies of the host assembly
tools are not a portable pinned toolchain; reproducibility is checked on this
machine with these inputs. Python's SQLite serializer must produce the exact
pinned 8192-byte specimen database or assembly refuses.

All output goes below this fixed external root, which the assembler creates if absent, or requires to be an
ordinary-user-owned directory with exact mode `0700`:

```sh
/home/olegchir/podbay-two-boot-offline-build/
```

Every ancestor must be a real directory owned by root or this user without
group/other write permission. The assembler retains descriptors for the ancestor
chain, build directory and every created file, and checks identity, type, owner
and modes before/after writes and tool calls. File creation is exclusive and
no-follow relative to the pinned build-directory descriptor. This trusts the
invoking user and root; it does not contain a hostile process of the same UID.
Installed tool paths and ancestors must be root-owned and not group/other
writable; executable hashes are checked, but execution-inode attestation is not
implemented. Historical artifacts in the old `/fast/git/v/research/` root remain
untouched and are not the revised assembler output.

The assembler accepts only a new simple build name and refuses an existing output
directory. It never replaces/deletes an image. Failed directories remain for
inspection. It reads the ISO through a pinned descriptor; unsquashfs reads only
the two named metadata files. It never mounts a host filesystem, uses sudo,
starts a VM, accesses personal VM files, downloads or installs anything.

```sh
python3 -B tools/two-boot-probe/offline.py --name final-a
python3 -B tools/two-boot-probe/offline.py --name final-b
python3 -B tools/two-boot-probe/offline_test.py
```

The last command expects those exact two build directories. Run from a clean
source checkout. `-B` avoids Python bytecode artifacts in the source repository.
Keep stdout/stderr logs outside the repository. `build-report.json` records tool
commands/exits, input/source hashes, output hashes and missing proof work. Tool
stdout/stderr is retained separately, including debugfs scripts. debugfs can
exit zero for failed individual commands, so the assembler rejects known error
output and the independent test reads back the resulting image and metadata.

## Artifact contract

* `vmlinuz`: exact Linux x86 kernel bytes from the pinned ISO extent.
* `initramfs.cpio.gz`: gzip mtime 0; sorted newc paths, fixed inode numbers,
  UID/GID 0, fixed timestamps, exact modes and `/dev/console` major/minor 5/1.
  Contains only directories, BusyBox, fixed `init`, and pinned fixture hashes.
* `fixture.raw`: fresh 32 MiB raw ext4 image, fixed UUID and directory hash seed,
  fixed times, no journal, explicit filesystem features and private mke2fs
  config. Host file mode `0600`; not an existing VM disk or a partitioned image.
* Disk `/`: root `0700`; `/vault`: root `0700`; `/vault/state`: 1000:1000 `0700`;
  database: 1000:1000 `0600`; gate and disk manifest: root `0600`.
* `/gate`: exact `CLOSED`, generation 1, policy `offline-closed-v1`, admission
  `UNIMPLEMENTED`. Its nonce is explicitly a deterministic offline placeholder,
  **not a root-generated runtime nonce or boot authority receipt**.
* `/disk-manifest.json`: exact DB path/inode, owner/mode, length/hash and gate
  digest. It describes assembled bytes; it cannot attest a guest boot.

The stub requires PID 1, mounts proc/sys/devtmpfs, mounts only guest `/dev/vda`
as ext4 `ro,noload,nosuid,nodev,noexec`, checks exact gate/database/manifest hashes,
gate state, modes/owners and DB inode. It starts no ordinary-UID process, broker
or login shell. A valid image still emits a blocked stub event and requests
poweroff. On failure it requests poweroff; if poweroff returns, PID1 stays in a
fixed sleep loop. That loop is containment intent, not timing-based evidence.
There is no writable disk transition or gate release in this program.

The independent tests decode newc without extraction, check every path/mode,
root identity and timestamps, static BusyBox/console metadata, read the raw
filesystem with debugfs, enumerate its exact tree, verify hashes and DB inode,
and compare all deployable artifacts from two builds. They also exercise wrong
input hash/path, unsafe build-name, exact base mode, writable ancestor, symlink,
preexisting output and tracked-image replacement refusals. Temporary negative
fixtures use a unique private directory under validated BASE, exclusive/no-follow
creation and cleanup restricted to inode/owner-checked entries they created. None of
these tests execute guest PID1 or establish that this kernel boots the archive.

## Missing proof work

A later reviewed atom must implement the persistent broker/rebind, clean exec
worker/sealing handshake and complete durable gate state machine. Then an
independently authorized disposable QEMU run must cover boot-A FD/directory FD,
shared mapping and queued SCM_RIGHTS negative controls; exact holder teardown;
fresh boot-B identity/byte preservation; actual SQLite sealed/outside checks;
dirty late-engagement refusal; worker/broker/hypervisor crash boundaries; and an
outside verifier for exact hypervisor exit and closed handles. These artifacts
cannot release any production constructor, migration receipt or Owner epoch.
