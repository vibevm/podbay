# Offline R1 install-plan staging

`plan_install.py` writes a review package into one fresh external directory. It
has no install, enable, start, reload, reboot, mount, chown, service-query or
enforcer-execution operation. Every successful plan remains
`deployment_blocked=true`. This is a private, bounded **disposable systemd
image** planning profile; it cannot certify the owner machine's issuer list.

The fixed normal executable interface is:

```text
/usr/local/libexec/podbay-r1-linux bootstrap --manifest /etc/podbay/r1-install-manifest.json
/usr/local/libexec/podbay-r1-linux custodian --manifest /etc/podbay/r1-install-manifest.json
```

The current executable refuses both operations. It does not read its manifest
or establish a production CLOSED boundary. This package stages only this
explicit unavailable marker, with no invented future grant fields:

```json
{
  "schema": "podbay.r1.install-manifest/1",
  "deployment_blocked": true,
  "availability": "UNAVAILABLE",
  "reason": "COLD_BOOT_PROVENANCE_UNAVAILABLE"
}
```

The future full runtime manifest is not specified by this marker or by the
outer plan. Positive provenance, issuer coverage, native failure ordering and
the runtime policy contract need separate review.

## Invocation and filesystem boundary

From the repository root, using an ordinary Linux UID:

```sh
python3 -B tools/r1-enforcement/plan_install.py \
  --request /absolute/private-inputs/request.json \
  --request-sha256 <exact-64-lowercase-hex-digest> \
  --output /absolute/private-staging/new-plan
```

There is no default discovery or output directory. Root execution is refused
before input reads. Request, binary, issuer-unit and prior-backup paths are
explicit pinned inputs. The generator never derives an input open from the
subject's vault/source names and never opens a database to inspect it. Supplying
an input hash is a caller declaration; it does not establish review or origin.

All input and staging ancestors must be nonsymlink directories owned by root
or the invoking UID, without group/world write permission. Repository ancestry
is refused. `/tmp`, even with its sticky bit, is not a valid positive staging
ancestor. Existing outputs, symlinks, unsafe system output locations, path
traversal and collisions refuse. An owner-0700 dedicated directory under the
user's non-writable home ancestry is suitable for disposable tests. The
`/fast/git` ancestry observed during this task is group-writable and therefore
does not qualify as staging/input custody; the rule is not weakened for it.

Inputs are single-link regular files without group/world write or set-id bits,
opened nofollow/nonblocking. Their raw captured bytes must match the supplied
SHA-256. FD and named-file metadata are compared around bounded reads. The
request is at most 256 KiB, binary at most 64 MiB, units at most 32 KiB, and the
issuer inventory at most 32 services. JSON is fatal UTF-8, duplicate-aware and
closed by exact field sets; numbers, nesting, nodes and strings are bounded.
The ELF magic check is only a format filter, not proof of executable behavior.

The exact output directory is created exclusively with mode0700. All writes
use retained directory FDs, nofollow/exclusive file opens and component/identity
rechecks. Every staged file is mode0600, including binary bytes. Files and
directories are fsynced; `COMPLETE.json` is written last and lists exact payload
hashes. A failure retains partial output and never recursively rolls it back.
An existing partial directory cannot be reused. A consumer must validate all
completion hashes and the separately recorded successful generator outcome
before using a package. A late sync/identity failure can leave the completion
file present; its existence alone is not a successful-run receipt. No power-loss or hostile same-UID
filesystem guarantee follows; the invoking UID and reviewed tool code remain
trusted.

## Closed request shape

Top-level fields are exactly:

| Field | Required value or shape |
| --- | --- |
| `schema` | `podbay.r1.install-plan-request/1` |
| `generation` | bounded ASCII literal |
| `binary` | `{ "path": absolute_file, "sha256": exact_raw_hash }` |
| `subject` | `vault_path`, `source_relative_path`, `source_sha256`, `source_bytes`, `source_lineage`, `schema_sha256` |
| `issuer_inventory` | shape below |
| `prior_state` | exact destination-to-prior-state map for every emitted installed file |

The subject is a declaration only. Vault must be a literal absolute path safe
for an unquoted systemd path. The source relative path has 1–4 bounded literal
components without traversal. Source length is 1 through 256 MiB; source/schema
hashes have 64 lowercase hex digits. Lineage is a bounded literal. The output
marks these values `CALLER_DECLARED_NOT_OPENED` and the vault's root0700 as
**installation intent**, not observed ownership or provisioning.

`issuer_inventory` has exactly:

```text
scope: "DISPOSABLE_SYSTEMD_IMAGE_ONLY"
image_id: bounded literal
complete_declared: true
unresolved: []
expected_units: nonempty exact unique system-manager service names
excluded_routes: exactly the ten names below
issuers: [{ unit, uid, unit_file: { path, sha256 } }, ...]
```

The required declared exclusions are `user-manager`, `login`, `cron-at`, `ssh`,
`containers`, `initramfs-owner-code`, `root-helper-fd-pass`,
`manual-owner-code`, `alternate-source-aliases`, and
`inherited-fd-mmap-scm-rights`. Missing categories, unresolved entries,
duplicate/foreign issuers, missing expected units and root/bool UID values
refuse. These declarations do not prove those routes are absent; the output
preserves `independently_verified=false` and an explicit deployment blocker.

Each declared issuer must be a literal system-manager service running its
declared nonroot UID and matching numeric Group. Owner user-manager units
cannot depend on a system service across the manager boundary; this profile
does not pretend such a drop-in works. The observed Zap/Wayfinder user units
would need separately reviewed system-manager/login/other issuer gates and
the complete owner-machine inventory. They are not staged or modified here.

For the selected disposable VM, the issuer is `r1-issuer.service`,
`DefaultDependencies=no`, `Type=oneshot`, `User=1000`, `Group=1000`,
`Restart=no`, and `ExecStart=/bin/busybox touch /tmp/r1-issuer-ran`. That is the
only accepted BusyBox command shape; shell/env indirection is refused. The
issuer snapshot is retained in `graph-input/`, and the exact Requires+After
gate is generated separately.

The first profile permits only that exact diagnostic issuer command. Other
executable/interpreter commands, including renamed helpers, are unsupported;
a syntactically literal command is not a proof of its behavior. This bound
does not implement a general machine-service installer.

Prior state must cover exactly these destinations, including every issuer
drop-in:

- `/usr/local/libexec/podbay-r1-linux`
- `/etc/podbay/r1-install-manifest.json`
- `/etc/systemd/system/podbay-r1-closed-bootstrap.service`
- `/etc/systemd/system/podbay-r1-custodian.service`
- `/etc/systemd/system/<issuer>.d/50-podbay-r1-closed.conf`

Each value is either `{ "state": "absent" }` or
`{ "state": "file", "file": { "path": backup_input, "sha256": hash },
"uid": 0, "gid": 0, "mode": decimal_mode }`. Allowed prior modes are 0600,
0644, 0700 or 0755. Exact captured prior bytes are retained as `prior/NNN.bin`.
The generator never reads those live destination paths. Every prior state is
labelled `CALLER_DECLARED_UNVERIFIED`; unknown or incomplete declarations
refuse, and independent destination readback remains a deployment blocker.
Fixture `absent` declarations must never be reused as claims about the host.

## Outputs and graph checks

The `rootfs/` subtree mirrors only the listed destinations. `plan.json` binds
each output's SHA, length, intended root:root owner/mode, actual staging owner
and mode, and exact prior declaration/backup. Binary installation intent is
root:root0755; units are root:root0644 and unavailable marker root:root0600.
The generator does not perform chown or set execute permission on host binary
copies. A separately authorized disposable image builder can verify those
hashes and use the intended modes inside its private guest archive.

The bootstrap template has fixed argv, `DefaultDependencies=no`,
`RequiresMountsFor=<vault>`, After local-fs, Before sysinit/basic and all declared
issuers, Type=oneshot, RemainAfterExit=yes and Restart=no. Custodian uses the
fixed notify command and Requires+After bootstrap with Restart=no. Neither has
stop/failure/unseal hooks. Generated issuer drop-ins contain both `Requires`
and `After`; Wants/Condition-only gates are not substituted. Templates under
`systemd/` are exact review copies of fixed code strings, checked by tests;
the generator does not load caller-selected templates.

A strict unit subset rejects duplicate/reset directives, unsupported sections,
Conditions, environment/credential files, ExecCondition/Pre/Post/Stop, failure
actions, auto-restart, shell prefixes, continuations, interpolation and unsafe
commands. Declared startup dependencies must resolve inside the bounded graph.
The graph includes the staged units, issuer snapshots, local-fs→sysinit→basic→
multi-user anchors, default service basic ordering, explicit Before/After and
generated bootstrap gates. A cycle refuses before output creation.

This is a **declared staged startup graph**. Actual implicit mount units, the
complete image, installation pull-in links, boot cutoff/late invocation and
failure propagation still require independent systemd/native testing.
`systemd-analyze` is not invoked by the generator. A separate read-only staged
syntax check can help, but cannot prove issuer completeness or OS exclusion.
No enabling symlink is created.

`rollback-checklist.json` contains no executable actions. Its default remains
vault denied, source/checkpoints retained and relevant issuers blocked. Exact
controlled-holder teardown, separate authorization and verified prior bytes
are prerequisites to recovery. Removing a gate or restoring an old unit may
reopen issuers; there is no automatic unseal, deletion or legacy fallback.

## Offline gates and remaining boundary

```sh
python3 -B tools/r1-enforcement/plan_install_test.py -v
```

Tests use disposable ordinary-UID filesystem fixtures. They exercise exact
output hashes/modes, deterministic bytes, closed manifests, incomplete issuer
refusal, actual cycle/unknown-dependency refusal, unsafe directives/commands,
symlink/writable/hardlink/collision refusal, read replacement, output directory
and file replacement, retained partial writes, prior backups, no subject reads
or child execution, root invocation refusal and the CLI's lack of install
options. The declared source is not a live database. Tests do not start systemd
or an enforcer. Reports/pins for this candidate are outside the repository at
`/fast/git/v/research/2026-10-07-podbay-r1-install-plan/`.

A plan does not establish old-issuer exclusion, positive cold provenance,
source provisioning, custody, broker sealing, admission, migration or Ready.
The current boot, live schema24 stores and machine installation remain outside
this offline atom. The next owner decision must concern an exact independently
reviewed install/activation/provisioning/recovery plan; no such action is
provided or authorized here.
