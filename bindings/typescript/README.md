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

## Authenticated Node Unix-socket transport

`src/authenticated-unix-socket.ts` implements the Linux `podbay.auth/1`
prelude on each new connection, then one PodBay/1 exchange. Construct
`AuthenticatedUnixSocketWireTransport` with an absolute, trusted `socketPath`,
an exact `expected` actor challenge (actor ID, store lineage, scope, credential
generation, UID/PID/start/cgroup process binding, and owner or pod origin), and
a `validateAndSign` callback. The transport strictly decodes the canonical TLV
challenge and compares every expected field before calling that callback.
Counters use `bigint` so u64 identities are never rounded.

The callback must validate the host endpoint through trusted information
outside the challenge and refuse any unwanted transcript before returning a
64-byte signature over `challenge.bytes`. A socket path or server-supplied
challenge is not by itself host authentication. Do not expose the callback as
an arbitrary-message signer. The transport does not discover an endpoint,
enroll an actor, store a private key, or retry a failed exchange.

The handshake has one absolute deadline from connection attempt through the
exact auth ACK. The following request/reply has a separate absolute deadline.
A successful exchange requires one bounded response frame followed by peer EOF;
extra bytes or a connection kept open past the deadline fail closed.
`AuthenticatedSocketTransportError.stage` is `before_request_write` until the
PodBay/1 request write is attempted and `possible_effect` afterward. On a
`possible_effect` failure, retain the original command key and reconcile it
through PodBay reads before deciding on a new operation.

Run its disposable local-socket fixtures with Node.js 24:

    node --test bindings/typescript/tests/authenticated-unix-socket.test.ts

## Initial Linux owner setup

`src/owner-setup.ts` enrolls the exact launcher-parent process over the
one-use `owner-setup.sock` before `manager.sock` opens. It generates an
Ed25519 KeyObject in memory, sends only its 32-byte public key, validates the
full domain-separated setup challenge against caller-supplied trusted actor,
scope, credential, store lineage, owner/revision, Linux process birth and
rights digest, and signs only that transcript. The returned
`authenticatedChannel()` retains the same private KeyObject in this process
and signs only an exact `podbay.auth/1` challenge. It never exports, logs or
persists the private key.

The launcher must independently pin the manager endpoint and supply
`validateHostEndpoint`; challenge fields and request JSON are not authority.
The client permits one same-key retry only when a signed attempt loses its
receipt or ACK. A remaining possible-enrollment error retains the KeyObject
in the client instance for read-only reconciliation; it must not trigger a
new key or owner enrollment automatically.

The mock socket tests use Node.js 24. A disposable Node-parent/Rust-manager
fixture runs when `PODBAY_TEST_MANAGER_BINARY` names the absolute current
`podbay` executable:

    PODBAY_TEST_MANAGER_BINARY=/absolute/path/to/podbay node --test bindings/typescript/tests/owner-setup.test.ts
