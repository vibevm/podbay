# PodBay TypeScript binding

This thin DTO/client is generated from the Rust podbay-wire crate. Edit the Rust codec or its template, then run from the repository root:

    RUSTC_WRAPPER= cargo run -p podbay-wire --locked --offline --bin generate-ts
    RUSTC_WRAPPER= cargo run -p podbay-wire --locked --offline --bin generate-ts -- --check
    node --test bindings/typescript/tests/golden.test.ts

The generated client covers the mutation and read schemas advertised in schema/v1/contract.json. It decodes receipt, event, snapshot, capability and error envelopes, keeps unknown observations opaque, and refuses unknown mutation operations and resource command kinds. Launch with a new session is the session-open path; session.close is explicit. Question answers and permission decisions have separate targets and bodies. The client does not implement streaming transport, the remaining P0 method catalog, or any provider process.

Catalog entries mean the request shape is recognized; they do not assert a runtime capability on a particular platform. Capability evidence may describe Linux, macOS or Windows support without placing OS process or supervisor IDs in required wire fields.
