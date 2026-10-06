# FD3-observe first-root admission

`admit_bound_operator_fd3_observe_root` commits reviewed declarations and a
Prepared `pod.offer` outbox. It never dispatches the effect. Both finite and
UntilStopped wire lifetimes use `BoundLaunchFormat::OperatorFd3ObserveV1`.

The request contains the principal, exact caller intent, key, scope and Pod.
A new request also supplies Session, queued Run, PlannedRootBinding, the typed
FD3 effective contract and descriptor, and expected owner/authority fences.
These are trusted-caller DTOs, not authentication or grant proofs. A future
authenticated host admission entry must fetch its current registered profile,
authorize its current actor/grant, resolve the exact typed pair and recheck its
fences. This Store API does not perform those host operations.

## Atomic commit and historical readback

The existing IMMEDIATE queued-root transaction inserts the command first. Its
transaction-scoped command witness admits the Run; Session/Run, Pod/resources,
target epochs, slot, immutable binding, event and Prepared outbox then commit
together with one authority revision increment. Failure rolls everything back.
No launch dispatch outcome or Codex V3 policy-fence row is created.

The existing schema24 tables already hold version strings and opaque bytes;
their DDL and user_version are unchanged. Readback accepts only the exact FD3
effective/descriptor version pair without a V3 policy row. It decodes both
canonical contracts, compares their complete policy/effective data, and checks
the existing Session/actor/Run/Attempt/Pod/resource/slot/command/event/outbox
associations. It never substitutes raw JSON fields for the typed decoder.

An exact duplicate can omit the proposal and returns the original immutable
receipt and bytes after reopen or mutable authority/lifecycle changes. Changed
caller intent, another format at the same key, or a competing initial target
refuses. Historical readback remains separate from dispatch eligibility.

## Dispatch remains closed

- The current-dispatch gate refuses FD3-observe.
- Generic `claim_effect` refuses it before fresh, ExistingUncertain and
  AlreadyObserved branches.
- `record_launch_port_result` and `observe_effect` refuse FD3 version markers
  before outcome replay or mutation. Other bound rows undergo strict immutable
  readback, so relabelling FD3 bytes cannot borrow an older outcome path.
  A missing binding is not classified as legacy by absence alone: the original
  generic command/event/outbox/slot graph and digests must verify, with no
  surviving launch.bound event or launch resource/policy rows.
  Complete legacy-unbound outcome and exact-retry behavior is preserved;
  missing or corrupt associations refuse without repair.
- The bootstrap HostAccepted predicate accepts only the existing Codex V2 wire
  version pair (also used by Codex V3). An FD3 row cannot satisfy it.
- Generic host resume/dispatch paths explicitly refuse the FD3 format. Existing
  legacy operator classification is not widened.

A normally admitted FD3 outbox therefore stays Prepared through these APIs.
Direct SQL mutants in tests do not establish that another state was reachable
through production APIs. No OS port, FD3 supervisor, HostAccepted, Ready,
signing-time admission or restart allocation is added.

## Bounded verification

Disposable tests cover both lifetimes, exact reopen/duplicate readback, schema
preservation, all-table mutation snapshots on refusal, stale fences, coherent
foreign actor/effective associations, mixed or relabelled wire versions, late
transaction failure, competing admission and impossible claimed/observed retry
rows. A private minimal-SQL predicate test distinguishes Codex HostAccepted
labels from FD3/mixed formats; it is not an authority or dispatch fixture.
Deleted-binding mutants retain their original admission event/outbox and cannot
downgrade into the legacy outcome path. A positive complete legacy graph still
supports outcome recording and exact retries; damaged legacy graphs refuse.
Generic event/effect payloads remain arbitrary opaque bytes within their original
1 MiB bound. Documentation mentioning a descriptor schema, or even canonical
FD3 descriptor JSON carried as generic data, does not classify an admission as
bound. If a hostile SQL writer removes or rewrites all bound metadata into a
coherent generic graph, this Store boundary cannot recover the lost provenance.

The fixtures use declared nonexistent artifact paths and synthetic principal,
grant and policy inputs. They launch no supervisor and touch no live store.
They establish database transaction and refusal behavior, not process crash,
power-loss, hostile writer exclusion or physical readiness. Older binaries keep
their existing unknown-version refusal for FD3 rows; no legacy fallback or
conversion of their bytes is provided.
