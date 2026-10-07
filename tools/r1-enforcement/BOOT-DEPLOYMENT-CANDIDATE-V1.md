# R1 boot deployment candidate v1 — data only

Schema: `podbay.r1.boot-deployment-candidate/1`. The structural schema is
`boot_deployment_candidate_v1.schema.json`; the cross-field, capture and graph
checks in `validate_boot_candidate.py` are also mandatory. Schema matching
alone does not validate a candidate.

This is a separate ordinary-UID offline tool. It does not alter the installer
request/plan/runtime marker, normal `podbay-r1-linux` CLI, acquisition refusal
or uninhabited `ColdOriginPermit`. It opens no declared vault/source/lock, reads
no installed runtime manifest, acquires no lock, launches no child, writes no
output file, changes no permission and activates no service. The caller may
redirect its stdout to an external report file.

```
python3 -B tools/r1-enforcement/validate_boot_candidate.py \
  --candidate /absolute/private-bundle/candidate.json \
  --candidate-sha256 EXACT_SHA256 \
  --bundle /absolute/private-bundle
```

The bundle must be an ordinary-user-owned real directory with exact mode0700,
under nofollow/non-writable trusted ancestors outside repositories. The
candidate must be directly inside that explicit bundle. Candidate data cannot
select host paths: only closed-role flat artifact filenames are opened below
the bundle. Subject and install paths are inert declarations. Symlinks,
hardlinks, writable files, replacement or metadata drift refuse. Input uses the
existing `plan_install.captured_file`: it bounds the read, checks retained and
named identities, and hashes exactly the returned buffer. A retained directory
chain spans the complete operation; candidate and earlier captured artifact
identities/size/mtime/ctime are checked again after each later capture and at
completion. This detects tested concurrent changes but is not a live or atomic
filesystem snapshot and cannot prevent changes after return.

Success means `PREPARED_UNATTESTED`, `production_origin=UNAVAILABLE`,
`admission=UNAVAILABLE`, `deployment_blocked=true`. Only the supplied artifact
bytes/hashes and declaration consistency have been checked. Output explicitly
marks source metadata, provisioning, issuer completeness, runtime/ELF closure,
full image, actual ordering and live producer as unverified. No permit, boot
attestation or migration capability is returned.

## Exact declaration shape

All objects have closed keys; duplicate JSON keys, floats/nonfinite numbers,
unknown/missing fields, oversized/deep input and bool-as-integer values refuse.
Candidate JSON is at most262144 bytes. There are at most96 artifacts, each at
most64MiB and at most128MiB total. Unit text is at most32768 bytes.

Top-level keys are `schema`, `generation`, `domain`, `subject`, `artifacts`,
`producer`, `issuer_inventory`. Domain and inventory scope are exactly
`DECLARED_BOOT_IMAGE`. Current fixture/runtime marker/plan/native receipt formats
are not candidate formats.

Subject declares `vault_path`, device, equal nonroot owner UID/GID, vault/state
inode/owner/group/mode, source/lock metadata, exact absent companion list and
`aliases_absent_declared=true`. The vault is root0:0 mode0700; state is subject
owned0700. Leaf paths are fixed:

- `state/db.sqlite`: subject-owned0600, one link, nonempty bounded declared
  length, SHA256, schema SHA256 and32-lowercase-hex lineage.
- `state/db.sqlite.manager.lock`: same subject owner/group/device,0600, one
  link, distinct inode, declared length0..1MiB. Empty lock is not asserted by
  the existing metadata observer, so this format does not require it.

Vault/state/source/lock inode declarations must all differ on the declared
filesystem. Companions declared absent are exactly `state/stage.sqlite`,
`state/db.sqlite-wal`, `state/db.sqlite-shm`, `state/db.sqlite-journal`.
The diagnostic fixture's separate root-owned `vault/manager.lock` layout is
incompatible; the validator will not silently translate it.

Every artifact has exact keys `id`, `role`, `filename`, `sha256`, `bytes`,
`install_path`, `uid`, `gid`, `mode`, `generation`. Generation must match the
candidate; IDs, input names and destinations are unique. Intended UID/GID are0.
Required core IDs equal their roles:

| Role | Bundle filename | Declared installation path | Mode |
| --- | --- | --- | --- |
| kernel | kernel.bin | /boot/podbay/vmlinuz |0644 |
| setup | setup.bin | /usr/local/libexec/podbay-r1-setup |0755 |
| manager | manager.bin | /usr/lib/systemd/systemd |0755 |
| executor | executor.bin | /usr/lib/systemd/systemd-executor |0755 |
| shutdown | shutdown.bin | /usr/lib/systemd/systemd-shutdown |0755 |
| umount | umount.bin | /usr/bin/umount |0755 |
| enforcer | enforcer.bin | /usr/local/libexec/podbay-r1-linux |0755 |
| producer | producer.bin | /usr/local/libexec/podbay-r1-boot-producer |0755 |
| policy | policy.json | /etc/podbay/r1-boot-policy.json |0600 |

These are proposed installation declarations, never destinations written by
this tool. Executable identity/ELF validity, runtime closure and producer
implementation are not inferred from role labels or byte hashes. Tests use
explicitly inert artifact bytes to demonstrate this separation.

Additional roles are bounded: `unit-NNN.service` (id unit-NNN, role unit) at a
specific system service destination,0644; `lib-NNN.bin` at a permitted library
path,0755; `issuer-NNN.bin` at `/usr/local/libexec/podbay-r1/issuer-NNN`,0755.
IDs/filenames must match. Regular artifact destinations cannot be equal to or ancestors/descendants of one another or the declared vault, in either direction. Comparisons use component boundaries, so lexical-prefix siblings remain valid. No input filename is an absolute path or contains a slash.

Producer keys are `unit`, `artifact`, `live_evidence`, `attempt_policy`,
`late_entry`, `custody_loss`, `before_source_lock_child`,
`deferred_native_predicates`. They require the proposed fixed producer service,
producer artifact, unavailable live evidence, one-attempt-per-boot declaration,
late/loss refusal, before-effects obligation and all eight deferred predicates.
These policies are declarations only; no latch or live transfer is implemented.

Inventory declares exact `expected_units` (producer plus1..32 issuers), issuer
unit/artifact/numeric-UID records, `complete_declared=true`, `unresolved=[]`, and
one entry for every route named in `plan_install.ROUTES`. A route is either
`GATED_DECLARED` with named issuers or `ABSENT_DECLARED` with no units. Every
issuer must be covered. This is completeness of the supplied declaration, not
proof that the machine has no omitted route.

Captured unit bytes are parsed by the existing bounded unit parser. Every
issuer must explicitly Require and be After the fixed producer. Restart must
explicitly be no; conditions, hooks, environment files, arbitrary shell syntax,
unknown dependencies and cycles refuse. User/Group and executable path must
match captured artifact declarations. Producer is declared root0 oneshot,
DefaultDependencies=no, with its single fixed command. The limited graph
accounts for service basic/sysinit/shutdown defaults. It is not verification of
all systemd mount/device/drop-in/generator or production boot semantics.

## Tests and remaining obligations

```
python3 -B tools/r1-enforcement/validate_boot_candidate_test.py
```

Tests cover closed shapes, foreign fixture formats, source/lock mismatches,
artifact byte/hash/path/generation errors, issuer/route gaps, real unit
restart/skip/gate/cycle failures, same-inode rewrite, named-path replacement,
bundle replacement, rewriting/replacing earlier artifacts during later capture,
unsafe inputs/private bundle, no source/lock/child effects, root refusal and CLI.

The actual trusted pre-issuer producer, complete native issuer and alias
exclusion, protected provisioning, live capability transfer, one-attempt/loss
behavior, two-boot custody and production migration release remain deferred.
Normal CLI stays exactly as documented in `crates/podbay-r1-linux/CONTRACT.md`.
No validated candidate can satisfy that missing live provenance.
