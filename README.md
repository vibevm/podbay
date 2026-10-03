# PodBay

PodBay is an independent Rust runtime for supervised agent processes. Zap consumes its public contract; PodBay does not depend on Zap. Coordinator, worker, and advisor are roles in one session/run/attempt/pod model.

The preproduction `0.1.0` branch currently has a versioned Rust wire contract and generated TypeScript binding, a durable command/event/outbox store, and a Linux user-systemd pod with a real PTY, scoped viewers, and fenced input. These are implementation slices, not a production-ready coordinator or provider adapter. Durable PTY spool, host authority, manager reattachment, Zap migration, and provider conformance are still in progress.

PodBay must support Linux, macOS, and Windows through one public API and separate OS backends. The current runtime tests are Linux-only. macOS and Windows do not yet have native acceptance receipts and must not be advertised as operational. See [platform backends](vibevm/vibespecs/PROP-008-platform-backends.xml) and the [native protocol](vibevm/vibespecs/PROP-002-protocol.xml).

`vibe install --offline --registry <local-registry>` materializes the pinned package closure. `vibe validate` and focused Cargo tests verify the current package and code slices. The optional outward ACP gateway has not been implemented or certified.
