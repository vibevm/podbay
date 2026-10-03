# PodBay TypeScript binding

This thin DTO/client is generated from the Rust podbay-wire crate. Edit the Rust codec or its template, then run from the repository root:

    RUSTC_WRAPPER= cargo run -p podbay-wire --locked --offline --bin generate-ts
    RUSTC_WRAPPER= cargo run -p podbay-wire --locked --offline --bin generate-ts -- --check
    node --test bindings/typescript/tests/golden.test.ts

The generated client covers the mutation and read schemas advertised in schema/v1/contract.json. It decodes receipt, event, snapshot, capability and error envelopes, keeps unknown observations opaque, and refuses unknown mutation operations and resource command kinds. Launch with a new session is the session-open path; session.close is explicit. Question answers and permission decisions have separate targets and bodies. The client does not implement streaming transport, the remaining P0 method catalog, or any provider process.

Catalog entries mean the request shape is recognized; they do not assert a runtime capability on a particular platform. Capability evidence may describe Linux, macOS or Windows support without placing OS process or supervisor IDs in required wire fields.

## Node Unix-socket transport

`src/unix-socket.ts` implements one bounded framed request and response per
connection for a caller-selected absolute Unix-socket path. It uses finite
connect, write, and read deadlines and closes the connection after the reply or
failure. The caller supplies endpoint discovery and any required credentials;
this binding does not start a manager or add authentication.

The transport does not retry. `SocketTransportError.stage` is `before_write`
when no request bytes were handed to the socket, or `possible_effect` once a
write was attempted. For a lost reply or other `possible_effect` failure after
a mutation, retain the original command key and reconcile that command through
PodBay's read surface before deciding what to do next.

Run the local transport fixtures with Node.js 24:

    node --test bindings/typescript/tests/unix-socket.test.ts
