# Operator FD3 observation data contracts

These internal wire types describe a future capability. They perform no file
inspection, profile registration, store admission, dispatch, FD transfer,
authentication or readiness transition. A successful decode proves structural
and canonical consistency only. Digests are not signatures or authority.

## Versions and framing

| Contract | Schema/domain |
| --- | --- |
| Policy | `podbay.operator-fd3-observe-policy/1` |
| Effective | `podbay.effective-launch/operator-fd3-observe/1` |
| Descriptor | `podbay.launch-descriptor/operator-fd3-observe/1` |

The profile is `podbay.operator.process.fd3-observe.v1`, the single Auxiliary
driver is `process.exec.fd3-observe.v1`, and the declared capability is
`operator_process_fd3_observe_v1`. None is advertised or enabled by these types.

Policy and descriptor use closed JSON envelopes with a schema and digest.
The descriptor also carries the existing wire protocol V1 tag. Their digest
is SHA256 of the schema/domain plus one NUL byte followed by the canonical
JSON body (`policy` or `descriptor`, respectively). Field order and spelling
come from the dedicated Rust structures. Decoders reencode and compare every
byte; alternative whitespace, key order, escape spellings and duplicate keys
are refused.

Effective bytes are the effective domain plus NUL, a four-byte big-endian
payload length, and the canonical closed JSON effective body. Its digest is
SHA256 of the entire frame. Trailing bytes and length overruns are refused.

Policy envelopes are bounded to 16,384 bytes. Complete effective frames and
descriptor envelopes are bounded to 65,536 bytes. These aggregate limits also
apply to constructors. Individual paths are at most 4,096 UTF-8 bytes; argv has
1..64 nonempty arguments of at most 1,024 bytes each, without control characters.

## Declared subject

Policy fixes `supervisorCreatedFd3`, descriptor 3, child protocol
`podbay.lens-readiness/1`, a 65,536-byte child frame limit and a 2,000 ms exchange
limit. These limits are declarations; this module runs no exchange or timer.

Expected pins cover the supervisor executable file, whole application artifact
tree, tagged absent/file configuration, public composition digest, registry
digest and logical workspace UUID/main path. Executable/config file hashes are
distinct from the typed artifact-tree hash (`podbay.operator-artifact-tree/1`).
Hashes are 64 lowercase hexadecimal characters. Paths are lexical absolute
Linux paths without empty, dot, parent or backslash components. Workspace IDs
are canonical lowercase UUIDv4 strings. These fields establish no physical
database identity, ownership, file existence or observed runtime composition.

The effective body fixes Linux, Coordinator/Service, no parent, read/write
workspace access, model/effort `none`, no fallback/tools/environment/credentials
and zero children. It carries an explicit finite lifetime of 30..3,600 seconds
or `UntilStopped`; no numerical sentinel or legacy Codex fallback is used.
Its cwd must equal the declared artifact root.

The descriptor embeds the complete effective body and its digest alongside the
planned first-root identity. Attempt ordinal/epoch, Pod incarnation and Resource
epoch are 1. There is exactly one Auxiliary resource with the reserved driver.
Descriptor construction and explicit binding validation require the exact
`PlannedRootBinding`; decoding alone is not a durable admission witness.
Counters use lossless canonical decimal strings; the bounded finite lifetime
seconds and fixed transport limits use JSON integers.

No future HostAccepted receipt, child PID/birth, secret key, nonce or allocated
restart generation is synthesized. Those require later reviewed associations
with a committed command/outbox and independently observed processes.

## Artifact measurement implementation and limits

The separate Linux launcher exposes `TrustedOperatorArtifact::inspect_tree`.
It measures the existing `podbay.operator-artifact-tree/1` stream; the wire
constructors above still only validate declared expectations. This helper adds
no FD3 Host admission, grant, dispatch or readiness capability.

The v1 hash input starts with `podbay.operator-artifact-tree/1` and one NUL.
At each directory, children are sorted by their raw Linux filename order and
visited depth first. Every entry starts with its root-relative raw pathname,
framed by an eight-byte big-endian length. `D` marks a directory; `F` is followed
by an eight-byte big-endian file size and the exact file bytes; `L` is followed
by the length-framed literal link target. Internal symlinks must resolve inside
the root; they are not traversed again through the alias. Empty directories are
included. The root itself, timestamps, inode numbers, modes and ownership are
not hash fields. Link targets are not normalized, so an absolute internal link
can make the digest sensitive to installation location.

The inspector limits discovery to 20,000 entries, regular-file content to
512 MiB, entry depth to 128, root/relative/target paths to 4,096 bytes each, and
cumulative relative-path plus target bytes to 16 MiB. Sibling entries consume
the shared budget while being discovered, before collection/sorting or descent.
Files are streamed only to their observed size plus one un-hashed growth probe.
Errors, overflow, growth, truncation and unsupported file types refuse; no
partial digest succeeds. Limits can refuse an installation previously accepted
by the less strictly bounded inspector. Unchanged supported trees retain their
exact v1 digests; a different framing or content algorithm needs a new domain.

The eight-second elapsed budget is polled during enumeration, around sorting,
and around each file read. It cannot interrupt a blocked filesystem syscall and
is not a hard wall-clock guarantee. No-follow/nonblocking regular-file opens and
before/after identity, size, mode, owner and change-time checks detect specified
changes; symlink identity/target and directory metadata are also rechecked.
Traversal remains cooperative pathname observation, not an atomic filesystem
snapshot, exclusive ownership, hostile-writer exclusion or a pin on later
execution. Dynamic dependencies, actual import closure and runtime composition
are outside this digest. Mutable runtime state belongs outside the installation.

`Configuration::Absent` carries no pathname and this measurement helper does
not establish configuration absence or disabled discovery. A later Host
admission must use a separately reviewed application configuration rule; neither
that rule nor a successful configuration/Ready observation is added here.

## Compatibility and tests

Legacy V1/V2 descriptor decoding explicitly rejects the reserved FD3 profile
or driver; legacy effective decoding rejects its profile. Old operator finite
and UntilStopped formats retain their serializers and digest domains. Frozen
legacy vectors and the existing wire suites test this boundary.

New tests cover both lifetimes, repeated construction as identical pure bytes,
policy/pin changes, stale hashes, complete effective/identity correspondence,
unknown and duplicate fields, noncanonical/truncated/trailing input, aggregate
bounds, lossless counters and cross-format/downgrade refusal. Repeated bytes are
not a claim of database command idempotency: store admission is outside this
slice, and `BoundLaunchFormat` has no FD3-observe variant yet.
