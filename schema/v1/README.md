# PodBay native wire v1 fixtures

These JSON files are golden compatibility vectors for the Rust `podbay-wire` codec and its generated thin TypeScript client. `contract.json`, the five command fixtures, and the TypeScript binding are generated from Rust-owned definitions and checked in tests. The manifest is not a complete JSON Schema for the full P0 API.

The command digest is SHA-256 of UTF-8 canonical JSON containing `protocol`, `operation`, `target`, `guard`, `deadlineAt`, and `body`. Object keys sort lexically, arrays retain order, and insignificant whitespace is removed. JSON numbers must be integral and within JavaScript's safe integer range; large counters use canonical decimal strings. `requestId`, caller-scoped `key`, and `payloadDigest` are excluded from the digest. A changed target, guard, deadline or body therefore changes the digest for the same key.

Frames have a four-byte big-endian length prefix and at most 1 MiB of JSON payload. Cursors carry store lineage, exact query scope, and a decimal-string sequence. Receipts are durable stage facts; a persisted receipt does not assert provider consumption.

The current strict mutation schemas cover the five operations listed in `contract.json`. Other mutations refuse until their typed bodies are implemented and advertised. Future observational event schemas and fields remain opaque evidence under the compatible `podbay/1` outer protocol. The generated TypeScript binding executes these fixtures in `bindings/typescript/tests/golden.test.ts`; the remaining P0 mutation catalog and a full JSON Schema generator remain follow-up work.

From the repository root, regenerate and check the artifacts with `cargo run -p podbay-wire --locked --offline --bin generate-ts` and `cargo run -p podbay-wire --locked --offline --bin generate-ts -- --check`.
