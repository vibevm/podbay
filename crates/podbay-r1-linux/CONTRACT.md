# Standalone R1 Linux source contract

This package currently has **no positive production acquisition**. It is a
production-built refusal executable plus private descriptor/seal machinery.
The reviewed early-boot producer, complete issuer gates and protected-source
provisioning contract are absent. Compiling or installing these bytes cannot
establish CLOSED, old-issuer exclusion, custody, admission or readiness.

## Fixed installer interface

Binary name: `podbay-r1-linux`.
Proposed installed executable: `/usr/local/libexec/podbay-r1-linux`.
Exactly two command shapes are recognized:

```text
podbay-r1-linux bootstrap --manifest /etc/podbay/r1-install-manifest.json
podbay-r1-linux custodian --manifest /etc/podbay/r1-install-manifest.json
```

The manifest schema identifier reserved for installer data is
`podbay.r1.install-manifest/1`. Its fixed path is a syntax contract, not a
trusted input loaded by this executable. The current executable never opens
the manifest, source, vault, lock, checkpoint or socket. It never allocates a
boot latch, starts a broker, changes permissions or invokes a service command.
No manifest body or purported historical grant can make it succeed.

Both modes exit 2. On Linux, ordinary UID returns `ROOT_REQUIRED`; root returns
`COLD_BOOT_PROVENANCE_UNAVAILABLE`. Unsupported targets return
`UNSUPPORTED_TARGET`; unexpected arguments return `INVALID_ARGUMENTS`.
Output is one bounded static JSON refusal, with gate `UNESTABLISHED` and
admission `UNAVAILABLE`. It contains no caller paths, config bytes or secrets.
There is no current-boot/force/cold override, environment discovery, alternate
manifest path, dynamic command, readiness notification or fallback manager.

The JSON manifest's future full content/attestation schema is deliberately
not frozen here. The installer may stage an explicitly unavailable manifest
under this schema ID; it must not describe it as a consumed origin grant.
The complete future image/unit graph, pre-issuer latch, persistent root vault
and installation/accepted-boot relationship require separate review. PID/UID,
uptime, caller flags, files, sealed memfds, or a PID1 socket/challenge alone
are insufficient. No mandatory nonexistent PID1 challenge API is imposed.

## Private machinery and tests

The private cold permit is uninhabited, including in tests. Descriptor-relative
checks reject symlinks, hardlinks, owner/mode/type/identity drift, replaced
parents and present source companions. They do not open SQLite, repair a vault
or infer that issuers never ran. Positive descriptor observations describe
metadata only and cannot produce the permit.

The narrow documented `sys.rs` contains Linux FFI. Other source forbids unsafe
operations through crate linting; other workspace crates are unchanged. A
fixed read-FD seccomp primitive can deny new opens, sockets/SCM, namespace,
ptrace/pidfd imports, clone/exec and writes to source. It alone is not a full
broker: trusted cold launch, namespace/chroot, capability/UID drop and exact
custodian/broker supervision still need the missing production boundary.

The optional `native-test-probe` feature builds a separate ordinary-UID-only
test executable. It is never an installed entrypoint and cannot acquire an
origin. Native controls run only in fresh task-owned fixtures and a bounded
child. They test the actual syscall filter and held-FD behavior, not a Rust
model of denial. Root/native boot, production broker, unit ordering and live
store gates are explicitly unrun.

Focused build and test commands, with CARGO_TARGET_DIR and TMPDIR pointing to
fresh private external directories:

```sh
cargo build --offline -p podbay-r1-linux --bin podbay-r1-linux
cargo test --offline -p podbay-r1-linux --features native-test-probe --all-targets -- --test-threads=1
```

Use separate targets for the normal artifact and the optional test feature.
The normal artifact is the only candidate for an install plan. Native tests
include a filter mutant allowing sendmsg: its invalid arguments then return
EBADF, and the exact EPERM oracle must fail. No syscall's generic `-1` result
counts as a filter denial. A test-only metadata anchor is ordinary-UID owned;
it tests descriptor mechanics and never claims to meet root-vault policy.
