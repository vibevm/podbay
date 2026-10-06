# Linux FD3 spawn boundary

This crate owns the small unsafe syscall boundary needed to exec one child with
a private socket at FD3. PodBay's Pod crate still forbids unsafe code and uses
this crate only as a Linux development dependency for disposable process tests.
No production launch profile, supervisor dispatch or readiness RPC enables it.

`reserve_fd3()` must run while FD3 is free. It atomically acquires a CLOEXEC
placeholder and refuses EBUSY if the slot is occupied, without changing existing
descriptors. The private reservation is borrowed until `spawn_fd3()` returns.
The API exposes neither its raw FD nor a reusable `Command` callback. The
parent's placeholder is unchanged by every child spawn.

Each consumed spawn spec names an absolute program and cwd, arguments and an
explicit environment. The environment is cleared first; stdin is null and
stdout/stderr are piped. A fresh CLOEXEC socketpair is created inside the
supervisor, with its owned endpoints moved above FD3 when necessary. The
post-fork callback maps only the child endpoint to FD3 and marks FD >=4 CLOEXEC.
It does not close Rust's exec-error pipe before exec. Unsupported or denied
`close_range(..., CLOSE_RANGE_CLOEXEC)` fails spawn; no fallback is available.
This requires the Linux flag introduced in 5.11.

The parent drops its copy of the child endpoint after spawn on both success and
failure. The returned parent channel remains CLOEXEC and starts with two-second
read/write timeouts. The caller owns the returned `Child`, must drain its output
pipes and must arrange exact child cleanup; dropping `Child` alone does not reap
or kill it. No fallible initialization occurs after successful spawn.

Tests use only disposable subprocesses of their own test executables. They
cover exact FD inventory, a deliberately inheritable high descriptor, nonce
echo retries, PID/birth/parent observations, successful exact reap and EOF,
occupied FD3, closed stdio, failed exec and private injected ENOSYS/EINVAL/EPERM
errors at the close-range step. Fault injection is compiled only in this
crate's unit tests; it is not a feature or environment-controlled production
switch. The injected errors test propagation, not a real older kernel.

With a private `CARGO_TARGET_DIR`, run offline:

```sh
cargo test --offline --locked -p podbay-fd3-sys -- --test-threads=1
cargo test --offline --locked -p podbay-pod --lib fd3_fixture_tests:: -- --test-threads=1
```

The two ignored functions per test suite are private subprocess endpoints,
invoked by the ordinary tests. The nonce echo is a transport check, not signed
readiness. These tests do not call `serve`, systemd, Lens, provider services or a
PodBay database. Existing standalone signature fixtures remain separate.

SO_PEERCRED on this inherited socketpair identifies its creator, not the exec
child. Production child identity needs the retained child handle plus independent
process observations and trusted launch binding. The child may pass its endpoint
on to descendants; this crate supplies no hostile-child or same-UID containment.
Production activation still requires a registered channel capability, refreshed
artifact pins, accepted-launch checks, fenced manager observation RPC, trusted
Lens state identity and production authentication/replay policy.
