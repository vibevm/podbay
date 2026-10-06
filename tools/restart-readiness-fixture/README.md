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

The accepted parent run passed **4 tests, 0 failed, 1 ignored**; the ignored
endpoint is invoked as a real subprocess by the child tests. The two `unsafe`
uses are limited to FD3 handoff/reconstruction in this separate test tool.
`podbay-cli` retains its `#![forbid(unsafe_code)]` and was not changed for this
fixture. Positive Ready remains blocked on an independently trusted Lens
workspace database identity and reviewed supervisor FD forwarding. The
fixture's scripted `ForeignOwner` is not real Owner discovery.

Original scratch source and evidence are at
`/fast/git/v/research/2026-10-06-podbay-readiness-fixture/`.
