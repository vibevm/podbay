# Producer lifecycle v2 — negative-only scaffold

The separately normal-built `podbay-r1-boot-producer` accepts **zero arguments**.
It prints one fixed-schema refusal and exits2. Any argument produces
INVALID_ARGUMENTS/exit2; zero arguments produces
COLD_BOOT_PROVENANCE_UNAVAILABLE/exit2 for every UID. It does not need root to
refuse and no host-root test is required.

The executable does not read a candidate, manifest, stdin, environment variable,
inherited protocol FD, source, lock or notify endpoint. It does not allocate an
attempt, start a child, mount, change permissions or send readiness. Its sole
application output is a bounded stdout refusal; dynamic-loader/runtime I/O is
not represented as application source access. There is no positive switch or
variant. The existing bootstrap/custodian executable and its exact CLI remain
unchanged. `ColdOriginPermit` remains uninhabited and is not imported by this
scaffold.

This version does not revise the accepted
`podbay.r1.boot-deployment-candidate/1` format or its oneshot declaration. The
new notify unit template is an incompatible, explicitly unavailable lifecycle
profile. It is not installed, enabled or run by any supplied command. Its
Restart=no, Type=notify and fixed ExecStart cannot make this exit2 program
Ready. Proposed issuer Requires+After (plus BindsTo for loss) remains an
unverified native ordering/loss obligation, not a claim from unit text.

## Pure packet contract

The internal `producer_lifecycle` module accepts only caller-supplied bytes and
expected bindings. It has no I/O handle or effect callback. The normal CLI does
not feed this parser from any input. Its schema is
`podbay.r1.producer-lifecycle/2`, a canonical ASCII key=value packet, at most1024
bytes, exactly16 ordered lines and one final LF. CR, NUL, missing/duplicate/extra
keys, reordered keys, unknown enum values, noncanonical numbers and overflow
refuse. The exact order is:

```
schema=podbay.r1.producer-lifecycle/2
generation=<64 lowercase hex>
boot_id=<lowercase UUID 8-4-4-4-12>
nonce=<64 lowercase hex>
sequence=<canonical unsigned decimal, starts at1>
producer_pid=<2..4294967294>
producer_birth=<positive u64>
child_pid=<2..4294967294, distinct from producer>
child_birth=<positive u64>
attempt=<unclaimed|spent|partial>
channel=<live|lost>
migration=<absent|durable>
pending=<unresolved|resolved>
activation=<absent|durable>
owner_epoch=<canonical u64>
request=<validate|ready|restart>
```

Bindings are expected **data**, not proof these processes or channels exist.
Parsed private Packet values are never exported as authority. Every inspect
call returns a Refusal, including an internally consistent complete transcript.
The local NegativeLifecycle becomes spent on its first inspection, even when
that packet is malformed; subsequent calls refuse ATTEMPT_SPENT. This is pure
bookkeeping, not an OS-backed per-boot latch. Making a fresh local state can
only obtain another refusal.

Foreign generation/boot/nonce/process identities and noninitial sequence
refuse. Declared spent/partial attempt, lost channel and restart request
refuse. A ready request with absent migration/activation, unresolved pending or
zero Owner epoch refuses PREMATURE_READY_REFUSED. Claiming all predicates true
still refuses COLD_BOOT_PROVENANCE_UNAVAILABLE. No state says Ready, admitted,
CLOSED, or permits a positive constructor.

## Future positive contract remains deferred

An actual accepted producer must run before every source-capability issuer in
a reviewed immutable appliance image; create a real single-attempt boundary;
keep exact custody; seal and supervise its private child closure; and survive
release as the same notify keeper. It may send readiness only after durable
migration/publication, resolved pending/recovery, committed activation and first
Owner epoch inside that maintained closure. This scaffold implements none of
those privileged effects or successful transitions.

A future implementation requires separate source review and root disposable
native proof of producer ordering, full issuer/alias/FD/mmap/SCM_RIGHTS closure,
lock/child setup, loss/restart/attempt handling, durable release and a fresh
second boot. Root UID, caller fields, private FD numbers, candidate validation
and the accepted negative fixture cannot replace that evidence.

## Offline verification

Use a private target and TMPDIR:

```
cargo test --offline --locked -p podbay-r1-linux --bin podbay-r1-boot-producer
cargo build --offline --locked -p podbay-r1-linux --bin podbay-r1-boot-producer
python3 -B tools/r1-enforcement/producer_scaffold_test.py --binary /absolute/private-target/debug/podbay-r1-boot-producer
```

Pure tests cover closed packet syntax/bounds/bindings, terminal attempt/loss,
replay/restart and every premature-release predicate. Complete claimed release
still refuses. Ordinary-UID executable tests check fixed CLI/refusal, no notify
traffic to a private test socket, untouched sentinel inputs and unit-template
failure policy. Immediate exit2 is fail-closed behavior, **not proof of a
long-lived keeper or native issuer ordering**. Optional retained syscall traces
must distinguish dynamic-loader opens from application effects; they are not
production boot evidence.

For an available retained trace, pass `--trace /absolute/private-report/producer.strace` to the Python checks. On the measured normal run, loader opens were ld.so.cache/libgcc/libc and Rust runtime additionally opened /proc/self/maps for runtime setup; there were no application source/lock or socket/child syscalls. That trace is one ordinary invocation, not a production-boot proof.
