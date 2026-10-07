# Offline disposable systemd VM candidate

`build_r1_systemd_vm.py` builds a fresh deterministic archive/disk pair as an
ordinary UID. **It has no VM execution switch.** Exit 0 means offline assembly
and verification only. Parent source review and a separate disposable execution
atom are required before any boot. It never installs or changes host services,
uses root/sudo, downloads inputs, accesses a live store or mounts a host disk.

The guest is a root-in-archive minimal runtime: pinned Ubuntu systemd 259.5 is
actual PID1 after a reviewed static `/init` exec, with the retained ISO-derived
kernel. This is not a complete Ubuntu installation. `/init` mounts API filesystems,
closes inherited FDs and mounts only fresh `/dev/vda` as read-only ext4; both the
mountpoint and disk root are already root0700. It never opens source bytes. Invalid entry (non-PID1 or non-root) returns125 immediately, before any mount or reboot; guest failure shutdown is reachable only after this guard.
The fixture source is canonical generated schema24, `/fixture/vault/state/db.sqlite`.
Source sidecars/stage are absent; the separate lock is root0600. No admission,
production origin, broker acquisition or complete host issuer inventory exists.

The current normal-built enforcer refuses both fixed modes with exit 2 and
`COLD_BOOT_PROVENANCE_UNAVAILABLE` when run as guest root. The observer requires
that exact JSON, systemd's actual bootstrap result/exit status, unstarted gated
UID1000 fixture issuer and custodian, four actual EACCES source/sidecar checks,
unchanged source/artifact hashes, PID1 systemd identity and normal shutdown.
Its sole future native success label is
`BOOTSTRAP_REFUSED_ISSUERS_BLOCKED_NO_PRODUCTION_ADMISSION`.
The enforcer's gate remains `UNESTABLISHED`, admission `UNAVAILABLE`.

## Inputs and output

Supply the externally built **normal** enforcer and exact SHA256, external staged
manifest and exact SHA256, two staged units and their exact SHA256, and exact external `plan.json` SHA256 plus the exact
staged `r1-issuer.service.d/50-podbay-r1-closed.conf` SHA256. The stage follows
`rootfs/etc/podbay/r1-install-manifest.json` and
`rootfs/etc/systemd/system/`. The staged input binary must be non-writable by
group/other, regular/no-symlink and single-link (installer copy mode0600); its
unchanged bytes become root:root0755 only in the guest archive. No test feature
binary or fixture substitute is accepted as evidence of a normal build.

```
python3 -B tools/two-boot-probe/build_r1_systemd_vm.py \
  --name systemd-review-a \
  --enforcer /absolute/stage/rootfs/usr/local/libexec/podbay-r1-linux \
  --enforcer-sha256 EXACT_SHA256 \
  --stage /absolute/stage \
  --manifest-sha256 EXACT_SHA256 \
  --bootstrap-sha256 EXACT_SHA256 \
  --custodian-sha256 EXACT_SHA256 \
  --issuer-sha256 EXACT_SHA256 \
  --plan-sha256 EXACT_SHA256
```

Output is retained under `/home/olegchir/podbay-r1-systemd-vm-build/`, protected by
the existing descriptor/identity/mode guards. `/fast/git` has writable ancestry
and is refused for executable/image build outputs; research reports may point to
the retained private artifacts. Existing names fail; failed builds remain for
inspection; no automatic deletion/retry, disk replacement or cleanup occurs.

`r1_systemd_runtime.json` pins the local runtime including optional systemd
libraries and the normal enforcer's libgcc dependency. ELF parsing checks
interpreter and all DT_NEEDED names before packaging; dlopen features outside
this bounded closure remain an explicit first-native-boot gate. Hashes are local
byte pins, not independent publisher provenance. The compiler driver is pinned;
ordinary installed compiler/linker/static-library dependencies remain trusted.
Two builds verify reproducibility on this installed toolchain.

The exact staged bootstrap/custodian and issuer drop-in are retained in the
archive. A fixture-only output drop-in captures bootstrap stdout. Extra fixed
units provide the single issuer, root observer and shutdown graph. No vendor
login/getty/SSH/user-manager/network/generator/unit tree is imported. Strict
Requires+After and cycle checks plus pinned `systemd-analyze verify` run against
an extracted private root with generators/man checks disabled. Syntax success
does not establish native ordering, cgroup, mount or private-manager IPC behavior.

## Offline verification

```
python3 -B tools/two-boot-probe/r1_systemd_test.py
python3 -B tools/two-boot-probe/r1_systemd_test.py \
  /home/olegchir/podbay-r1-systemd-vm-build/systemd-review-a \
  /home/olegchir/podbay-r1-systemd-vm-build/systemd-review-b
```

The first command also compiles and invokes the static /init as an ordinary UID with a two-second timeout, requiring immediate exit125 and empty output. It never performs a host-root invocation. It tests runtime closure, missing/malformed dependencies,
archive formatting, graph failure gates, serial mutation/duplication/interleave
rejections and lifecycle evidence refusal. Harmless Python child processes test
bounded capture/timeout/overflow and pidfd exact exit/reap; they are explicitly
not VM evidence. The second independently decodes both archives, checks their
manifest/path/mode/pins, ELF closure, exact disk tree/metadata/source, and equality
of all deployable bytes. Every run remains unbooted.

`parse_events` is a new systemd-specific parser, not the warm fixture's 52-event
parser. `native_receipt` additionally requires zero exit, exact reap, pidfd exit
and empty QEMU stderr. It is a pure verifier and cannot launch a VM. Structured
serial records must be bounded single writes; corrupted/missing/extra events,
authority claims, fatal diagnostics and unknown output refuse. Future host
execution must also retain exact image/kernel/archive descriptors and use the
existing bounded TCG, no-network, no-monitor lifecycle harness. The read-only
disk means this first negative smoke cannot test a writable custodian or latch.
