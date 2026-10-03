# PodBay native wire v1 fixtures

These JSON files are golden compatibility vectors for the Rust `podbay-wire` codec and its generated thin TypeScript client. `contract.json`, every advertised command/read fixture, and the TypeScript binding are generated from Rust-owned definitions and checked in tests. The manifest is not a complete JSON Schema for the full P0 API.

The command digest is SHA-256 of UTF-8 canonical JSON containing `protocol`, `operation`, `target`, `guard`, `deadlineAt`, and `body`. Object keys sort lexically, arrays retain order, and insignificant whitespace is removed. JSON numbers must be integral and within JavaScript's safe integer range; large counters use canonical decimal strings. `requestId`, caller-scoped `key`, and `payloadDigest` are excluded from the digest. A changed target, guard, deadline or body therefore changes the digest for the same key.

Frames have a four-byte big-endian length prefix and at most 1 MiB of JSON payload. Each response has exactly one `ok` or `error` member alongside `protocol` and the matching transport `requestId`; the success body may contain a durable receipt or a read result. Cursors carry store lineage, exact query scope, and a decimal-string sequence. Receipts are durable stage facts; a persisted receipt does not assert provider consumption.

The current strict mutation and read schemas are exactly the operations listed in `contract.json`. Other operations refuse until their typed bodies are implemented and advertised. Future observational event schemas and fields remain opaque evidence under the compatible `podbay/1` outer protocol. The generated TypeScript binding executes these fixtures in `bindings/typescript/tests/`; remaining P0 methods, streaming transport and a full JSON Schema generator remain follow-up work.

This manifest advertises parser schemas, not runtime availability. A scoped capability snapshot decides whether a host can execute an operation. The wire catalog currently omits profile listing; run/session/resource listing; run, delivery and foreground waits; configuration, usage and artifact methods. The thin client does not implement a sustained event subscription or terminal byte stream. These omissions cannot be inferred as supported from a passing codec test.

Launch with `session.kind = new` opens a session; `session.close` closes one after the active run ends. Run report/finish record runtime declarations and lifecycle, never external domain acceptance. Question answer and permission decision are separate typed commands. Workspace paths are portable scope-relative identifiers translated by a host backend; public wire types carry no mandatory OS process, service or socket identity.

From the repository root, regenerate and check the artifacts with `cargo run -p podbay-wire --locked --offline --bin generate-ts` and `cargo run -p podbay-wire --locked --offline --bin generate-ts -- --check`.
