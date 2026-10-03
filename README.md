# PodBay

PodBay is an independent Rust runtime for supervised local agent processes. Zap is a consumer of PodBay; PodBay does not depend on Zap.

Coordinator and worker are roles of the same pod model. Each pod owns its process resources outside the client application's lifetime and exposes an exact, authenticated reattachment boundary. A future host adapter will provide PTY attachment, while an optional ACP gateway may expose compatible capabilities after conformance is proven.

This `0.1.0` line is a preproduction bootstrap. The crates establish dependency direction and build boundaries; they do not yet launch, control, or recover agents. See [PROP-001](vibevm/vibespecs/PROP-001-foundation.xml).
