# PodBay TypeScript binding

This thin DTO/client is generated from the Rust podbay-wire crate. Edit the Rust codec or its template, then run from the repository root:

    RUSTC_WRAPPER= cargo run -p podbay-wire --locked --offline --bin generate-ts
    RUSTC_WRAPPER= cargo run -p podbay-wire --locked --offline --bin generate-ts -- --check
    node --test bindings/typescript/tests/golden.test.ts

The generated client covers the five mutation schemas advertised in schema/v1/contract.json. It decodes receipt, event, snapshot, capability and error envelopes, keeps unknown observations opaque, and refuses unknown mutation operations and resource command kinds. It does not implement the remaining P0 mutation catalog or own any provider process.
