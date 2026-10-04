# PodBay

PodBay is an independent Rust runtime for supervised agent processes. Zap consumes its public contract; PodBay does not depend on Zap. Coordinator, worker, and advisor are roles in one session/run/attempt/pod model.

The preproduction `0.1.0` branch has a versioned Rust wire contract, generated TypeScript binding and local Unix-socket transport, a durable command/event/outbox store, host authority, and Linux user-systemd pod slices. The current peer-bound launch path accepts only a bounded synthetic Worker/Task `process.exec` fixture. Earlier PTY, viewer, event-spool and input-fence slices exist, but terminal control and viewing are not yet connected to that peer-bound path. A new manager can inspect a surviving pod read-only; it cannot yet complete a mutating rebind. Codex has passed an isolated app-server handshake, not a pod-owned session or turn. These slices do not constitute a production-ready coordinator or provider adapter.

PodBay must support Linux, macOS, and Windows through one public API and separate OS backends. Current native runtime evidence is Linux-only. macOS and Windows do not yet have native acceptance receipts and must not be advertised as operational. Launching pods on another computer is not implemented: the tested Linux path uses local user-systemd and Unix sockets. `hostId` identifies a reviewed local target; it is not a remote transport. See [platform backends](vibevm/vibespecs/PROP-008-platform-backends.xml) and the [native protocol](vibevm/vibespecs/PROP-002-protocol.xml).

`vibe install --offline --registry <local-registry>` materializes the pinned package closure. `vibe validate` and focused Cargo tests verify the current package and code slices. The optional outward ACP gateway has not been implemented or certified.
