# Private restart readiness fixture

This standalone test tool models a future authenticated child exchange. It is
outside the PodBay CLI crate and has no production hook. Its only authenticated
observation is `IdentityUnavailable`; `ForeignOwner` is a typed refusal. There
is no Ready wire tag, database identity, launch grant or restart allocation.

The actual child tests use a clean exec and inherited Unix socket FD3. A
fixture-only Ed25519 seed travels over that private FD; the parent supplies a
separate expected launch subject and verification key. Tests cover nonce,
generation, epochs, launch/policy/artifact/config/profile digests, IDs,
PID/birth, foreign Owner, immediate exit, EOF, timeout and replay. HTTP 200,
pairing tickets and a child PID alone cannot satisfy the verifier.

Run offline:

```sh
cargo test --offline --locked --manifest-path tools/restart-readiness-fixture/Cargo.toml
```

The extended offline fixture run passed **5 tests, 0 failed, 1 ignored**; the ignored
endpoint is invoked as a real subprocess by the child tests. The restricted `unsafe` blocks are limited to FD3 handoff/reconstruction and
a deliberately inheritable sentinel descriptor in this separate test tool.
`podbay-cli` retains its `#![forbid(unsafe_code)]` and was not changed for this
fixture. Positive Ready remains blocked on an independently trusted Lens
workspace database identity and reviewed supervisor FD forwarding. The
fixture's scripted `ForeignOwner` is not real Owner discovery.

Original scratch source and evidence are at
`/fast/git/v/research/2026-10-06-podbay-readiness-fixture/`.

## Supervisor-created FD custody control

The test supervisor creates a fresh CLOEXEC Unix socketpair immediately before
one clean child exec. An async-signal-safe `pre_exec` closure maps only the child
endpoint to FD3 and marks every FD >=4 CLOEXEC with Linux `close_range`. There is
no descriptor transfer through `systemd-run`. Unsupported kernels refuse spawn;
this fixture requires Linux `CLOSE_RANGE_CLOEXEC` support (Linux 5.11 or later).
The parent drops its child endpoint after spawn. A deliberately inheritable FD
>=64 remains open in the supervisor but must disappear from the child. The child
reports its complete FD inventory `[0,1,2,3]`; its temporary procfs enumeration
FD is closed before reporting. This is a fixture report, not platform attestation.

The supervisor independently checks actual PID/birth/parent PID before and after
challenge/retry. A fresh fixture nonce and Ed25519 seed come from `/dev/urandom`
and travel only over FD3. The existing signature verifier still permits only
`IdentityUnavailable`, against a separately held key and expected subject.
Exact retries retain the same child PID/birth. The test requests clean endpoint
exit, observes a two-second deadline, reaps that exact child and requires EOF on
the retained parent endpoint. Failure cleanup kills and reaps only its spawned
child; it never looks up a service or uses a process-name kill.

This does not supply a production-safe arbitrary-FD API for the
`#![forbid(unsafe_code)]` PodBay supervisor. A separately reviewed safe sys
boundary, trusted registered launch capability, fenced manager observation RPC,
accepted-launch revalidation and new artifact pins are still required. Scripted
subject/policy/artifact digests are fixture inputs, not measurements or a real
HostAccepted receipt. There is no operator wiring, systemd run, Ready grant,
physical DB identity, production key custody or hostile same-UID containment.
