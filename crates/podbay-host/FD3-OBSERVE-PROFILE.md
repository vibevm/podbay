# Trusted FD3-observe profile data resolution

This slice adds trusted profile construction and pure data resolution. It does
not add Store admission, a dispatch port, supervisor launch, manager RPC, CLI
selection, authentication-key custody or Ready.

Trusted Rust setup constructs a `RegisteredLaunchProfile` with
`from_trusted_operator_fd3_observe_policy(input, policy, lifetime)`. The complete
`OperatorFd3ObservePolicyV1` and explicit `LifetimeLimit` are private immutable
profile state. The normal trusted constructor refuses the reserved FD3 profile
or driver without that policy. Codex and ordinary operator opt-ins cannot be
combined with FD3-observe.

The constructor requires the exact FD3 profile and one Auxiliary driver,
LinuxCooperative execution, fixed argv, artifact root equal to workspace root,
workspace prefix `.`, read/write access, model/effort `none`, no extra arguments,
tools, environment or credentials, no fallback and zero children. Finite
lifetime must equal the registered wall selection; both are 30..3600 seconds.
UntilStopped is registered explicitly and is encoded as a tagged lifetime.

`resolve_operator_fd3_observe_data(host, planned, grant_id, selection)` checks
the exact profile generation, scope, workspace basis, fixed workspace `.`,
parentless Coordinator/Service root, one Auxiliary resource, grant association
and supported trusted host driver. Selection arguments/tools must be empty,
fallback disabled and children zero. The legacy `wall_seconds` selector must
equal the value in the registered input even for UntilStopped; it never changes
the typed registered lifetime. Model/effort can be omitted or explicitly `none`.
LaunchSelection contains no observation policy field and cannot replace pins.

The returned `ResolvedOperatorFd3ObserveData` exposes only `effective()` and
`descriptor()` references to immutable wire objects. Wire construction enforces
the aggregate frame bound and complete planned identity/policy correspondence.
No legacy EffectiveLaunchSpec bytes are produced. Generic V1/native/Codex
resolution and revalidation refuse FD3 policy state or reserved names, and the
legacy EffectiveLaunchSpec encoder separately refuses the reserved profile.

The existing authority registry delegates to one pure helper. Equal-generation
registration requires exact equality of the complete profile, policy and
lifetime; lower generations refuse; an explicitly higher generation may replace
the entry. Rejected updates leave the old entry intact. Stripped FD3 policy is
refused before insertion.

## Authority and observation limits

Resolution performs no filesystem reads. Executable, artifact, supervisor,
configuration and expected startup pins are copied from protected registration
as expectations. No file has thereby been measured, opened, locked or attested.
The supplied grant ID is checked for association with the selection; this
method does not authenticate an actor or establish a current grant.

Resolving a profile object does not prove that it is the registry's current
entry. A future admission path must fetch the current trusted registry entry,
authenticate/authorize the caller, verify owner/credential/authority guards and
measure required filesystem inputs. No existing admission or dispatch method
consumes `ResolvedOperatorFd3ObserveData` in this slice.

Ordinary operator V1, UntilStopped and Codex registration keep their existing
behavior. Tests use pure objects and the same registry helper invoked by the
authority method; they open no database and launch no process. Positive fixtures
are Linux-gated to match the compiled host backend. Cross-platform deployment,
current authority and production readiness remain unproved.
