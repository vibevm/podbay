# PodBay post-MVP campaign — deferred work

**Read this entire document before planning or implementing the broader PodBay
prototype.** It is the durable project record for work deliberately excluded
from the local Linux MVP. The owner set this boundary on 2026-10-05. This is a
roadmap, not evidence that the listed capabilities exist or are authorized to
start now.

## The boundary and the next handoff

The active MVP is local to this Linux machine. It must run Zap itself as a
PodBay-owned service process, run Zap's coordinator through PodBay, preserve
both across the tested manager/CLI rebind, show native output, support truthful
chat readiness and later-turn settlement, promote only an explicitly proved
final answer into chat, stop the exact service, and allow a
trusted service to live without the former one-hour wall limit. It uses fresh
current PodBay stores. Old preproduction PodBay schemas have zero clients:
reject them; do not design migrations for hypothetical users.

Remote computers, macOS, Windows, delegated Worker/Task admission, generic
host questions and permissions, and the optional ACP gateway are **outside**
this MVP. Their design constraints still matter when choosing local interfaces,
but they do not block the MVP or the next authorized action.

**After the local MVP is proved, install/switch the selected Zap path to that
PodBay generation, then resume and finish the VibeVM campaign.** Do not wait
for the deferred work below before starting VibeVM. Implement a deferred
PodBay/Zap capability during VibeVM development only when an observed blocker
or unacceptable delay makes it necessary; keep that intervention narrow. The
owner prohibited a public VibeVM 1.1.0 release in the current campaign.

The implementation snapshot changes quickly. On resumption, verify Git,
installed generation, current specs, capabilities, live processes and exact
test receipts. Historical research is design input, never a passed gate.
Preserve accepted Zap/VibeVM domain history when changing their runtime. The
zero-client, no-migration decision applies to PodBay's preproduction store,
not to the 36 accepted VibeVM campaign tasks or other live product data.

## Source and architectural invariants

- PodBay is the independent Rust package org.vibevm.podbay/podbay. Zap is its
  client. The distributed supervisor belongs inside PodBay; do not create a
  second product above it that owns the processes.
- A local pod owns process/PTY handles and the event source. Managers, Zap,
  browsers, future remote controllers and terminal viewers are detachable
  clients. A lost connection does not imply a stopped process.
- Session, Run, Attempt, Pod, Resource, incarnation, CommandKey, CommandId,
  receipt stage and cursor remain explicit. Provider-native IDs and OS PIDs
  are scoped evidence, not replacements for PodBay identities.
- Record intent before a possible OS/provider/input effect. Duplicate key and
  digest return the original receipt; changed content conflicts. A lost reply
  after a possible effect is uncertain and must be reconciled by the original
  identity. Never blindly relaunch or resend.
- Process liveness, native idle, delivery, completed model work, final answer,
  Run report and domain acceptance are different facts. Unknown observations
  and gaps must not be rendered as completed/ready.
- Public contracts are platform-neutral. Systemd units, cgroups, launchd
  labels, Job handles, PTY implementations and native PIDs are backend
  evidence. A platform is unsupported until its native gate passes.
- ACP is only an optional outward gateway. No ACP DTO, JSON-RPC request ID or
  editor-client operation enters PodBay core or the native execution ledger.
- The final direct-only Zap cutover may remove old process-owning wrappers
  after a reference scan. Unsupported MVP actions must be unavailable, never
  silently routed through an old local process factory.

Canonical specifications are [the native protocol](vibevm/vibespecs/PROP-002-protocol.xml),
[resources and interaction drivers](vibevm/vibespecs/PROP-007-resources-and-interaction-drivers.xml),
and [platform backends](vibevm/vibespecs/PROP-008-platform-backends.xml).
The approved API study and earlier campaign inventory are in this machine's
research directory: /fast/git/v/research/2026-10-03-podbay-api-surface.md and
/fast/git/v/research/2026-10-03-podbay-development-plan.md. The phases below
restated their required work so those local files are not the only record.

## Deferred phase order

| Phase | Main dependency | Exit evidence |
| --- | --- | --- |
| PM-01 Core supervisor API and durable observations | Stable local MVP | RunHandle, command/event/stop ledger, snapshot plus replay and honest gaps |
| PM-02 Delegated Worker/Task pods and budgets | PM-01 authority and launch admission | Real parent-linked child, atomic budget, crash/rebind receipts |
| PM-03 PTY, TUI and browser resources | PM-01 resource ledger; PM-02 for delegated terminals | Multi-viewer screen, fenced input; separate browser gate |
| PM-04 Questions, permissions, broker and provider parity | PM-01; PM-02 where children participate | Typed requests, scoped answers/grants, supported adapter receipts |
| PM-05 Full Zap direct-runtime cutover | PM-01 through required PM-04 slices | No active old wrapper owner; product data and UX preserved |
| PM-06 macOS and Windows backends | Portable port seam and PM-01/03 semantics | Separate native receipt for each advertised platform |
| PM-07 Multi-host supervisor and operator tools | PM-01/02, host identity and routing | Two-host failure/recovery and exact command chain evidence |
| PM-08 Optional outward ACP gateway | PM-01/04, truthful foreground and transcript | Pinned v1 conformance matrix; v2 draft remains opt-in |

This is a dependency map, not a mandate to start PM-01 immediately when the
MVP ends. VibeVM is the next active product campaign. Each phase starts only
when the owner resumes broader PodBay work or a concrete VibeVM blocker
requires its relevant slice. Independent phases may run in parallel with
disjoint writers after their dependencies are proved.

### PM-01 — complete the native supervisor API

1. Turn the present local coordinator and operator-specific entry points into
   a small Rust RunHandle/client facade and typed podbay/1 service. Implement
   truthful capabilities and protected profile listing. Provide scoped
   Session/Run/Pod/Resource get and paginated list, wait and wait-many,
   current desired/execution/observation axes, and exact parentage. A wire
   enum entry does not count as a served operation.
2. Promote installed operator stop's private intent/terminal sidecar into the
   common durable command/outbox/event ledger when its general command
   semantics are designed. Keep the exact single-effect and uncertain-reply
   guarantees. Add Run pause/resume/interrupt/stop/finish/report and
   Session close only with actual effect and settlement receipts. Distinguish
   self/subtree stop scope and coverage; client handle close never stops a pod.
3. Serve a consistent current-scope snapshot and event watermark, then
   authenticated subscribe/history after that cursor. Keep EventId,
   provenance, source epoch/sequence, scope/lineage-bound cursor,
   retention gap and quarantine. Manager ingestion must advance incrementally
   from a pod snapshot; a new viewer must not replay the lifetime log to draw
   the current state. An event acknowledgement is not a model settlement.
4. Finish durable usage/budget reservations, protected artifact storage and
   exact configuration revisions for advertised profiles. Child quotas and
   service lifetime are different budgets. Storage corruption, disk full and
   crash before/after fsync have explicit unknown or repairable states.
5. Decide which local CLI operations use the common command ledger, then
   expose read-only process inspection before mutating conveniences. Preserve
   stable IDs and receipt lookup across manager death.
6. Separate provider protocol semantics from the reusable supervisor. The
   current MVP has Codex-specific later-turn control and journals inside
   `podbay-pod` and Codex-specific tables in `podbay-store`, as well as the
   dedicated `podbay-adapter-codex` crate. Keep their exact intent, receipt,
   idle-proof and single-input guarantees, but move provider-specific state
   and transitions behind a driver-owned interface. The generic PodBay API
   must be able to launch, inspect and stop an arbitrary process without a
   concept of an agent turn. A Codex driver may report a native `failed` turn;
   retry policy, including whether a model-capacity failure merits a new
   continuation, belongs to its client such as Zap. Prove both a plain
   process with no driver and a Codex process through the same Run/Pod API.

**Gate:** one local manager restart with a live process; same Pod/Resource
birth, same CommandId under lost reply, no second OS effect; snapshot and
subscribe from one watermark, bounded replay with a forced gap; stop/interrupt
uncertainty and durable readback; no private provider bytes in public logs.
The current operator stop sidecar is a scoped MVP bridge, not evidence that
PM-01's generic stop command is implemented.

### PM-02 — delegated Worker/Task admission

Use the approved [child-admission design](/fast/git/v/research/2026-10-04-podbay-delegated-worker-admission.md)
as the detailed implementation input.

1. A live coordinator pod actor, not an owner CLI or sibling pod, asks for a
   new Worker/Task Session and Run with non-null parentRunId. Its
   authorisation is bound to the exact parent Pod/incarnation, current actor
   credential generation, same scope, reviewed child profile and reduced
   grant. Parent role or a text parent ID grants nothing.
2. Reattest parent supervisor and provider-child birth immediately before
   admission. The SQLite transaction rechecks parent Session/Run/Attempt/Pod,
   authority revision, desired active state and policy. Recheck liveness
   before dispatch; parent death between checks leaves a visible blocked or
   uncertain child, not an unlinked replacement.
3. Persist maxChildren on the parent and make the first contract a monotonic
   lifetime admission budget. In one IMMEDIATE transaction: original-key
   duplicate check, atomic budget reservation, command row, private
   transaction-scoped Run admission witness, child Session/Run/Attempt/Pod/
   Resource association, parent link, descriptor, event, outbox and receipt.
   Roll back everything together on any failure.
4. After commit, recheck the exact parent/grant and dispatch only the
   committed child Pod. Register the child's own actor after birth; then
   delegate only reduced rights and depth. Child credential material is
   manager-owned protected input, never task JSON. Define parent-loss,
   orphan, join/cancel and retirement policies without adopting a provider's
   informal child thread as a PodBay Run.

**Gate:** two child keys race for the last slot and exactly one wins;
same-key replay consumes no second slot, changed text conflicts; stale
parent/sibling/zero budget refuse; injected transaction faults leave no
partial child; parent death after commit, manager restart, lost launch reply
and exact child rebind never duplicate launch.

### PM-03 — resource viewers, TUI and browser drivers

1. Finish pod-owned PTY lifecycle and durable output beyond the local
   process MVP. Every open PTY gets a consistent full-screen snapshot
   (primary/alternate buffers, cursor, attributes, modes, geometry and
   decoder checkpoint) plus a replay watermark. Retain bounded raw bytes;
   partial UTF-8, resize ordering, unknown control sequences, truncation and
   retention loss become Partial/Unknown fidelity and explicit gaps.
2. Support multiple independent read-only viewers. Detach and disconnect
   never stop the pod. Give a separate exclusive, expiring control lease for
   write, paste, key, resize and process control. Bind it to ResourceId,
   incarnation, actor and input epoch. Human takeover fences pending
   automation; an uncertain keystroke is never replayed blindly.
3. Add versioned TuiDriver profiles for applications such as Midnight
   Commander and Vim. Pin build/keymap/locale/TERM/encoding/geometry/parser
   and typed actions. Separate exact screen cells from recognized state and
   hypotheses. Each action checks a fresh screen revision and lease, performs
   one bounded step and verifies its postcondition. An unexpected modal,
   layout change or possible-input timeout stops the sequence.
4. Later, add a separate BrowserDriver/Playwright resource family for browser
   context/page/frame/navigation/DOM/locator/screenshot/download/network
   capabilities. It shares PodBay pod lifetime and authority, but has its own
   receipts and postconditions; a successful click is not proof of a business
   effect. Browser helpers are pod-owned resources, not new execution owners.

**Gate:** disposable MC/Vim navigation and edit, primary/alternate screen,
two viewers, snapshot-plus-replay, stale cursor gap, sole input/resize
controller, human takeover, unexpected dialog, possible-input timeout and
manager restart with the same PTY child. Browser work has a separate
isolated fixture and is not required for that TUI gate.

### PM-04 — human interactions, broker and provider parity

1. Implement durable question.ask/answer/cancel with typed fields, options,
   revision, recipient, deadline and delivery stage. Implement permission
   request/decide separately with exact proposed operation/target and
   reviewer grant. An answer to a question cannot mint a permission grant.
   Stale epoch, wrong recipient or unknown answer refuses before provider
   input. Preserve a pending request across manager and UI reconnect.
2. Add a scoped broker/mailbox for durable actor identities, addressed
   messages, acknowledgement and notices. Client transport request IDs are
   not durable message IDs. Delivery to a provider and its acceptance remain
   separate. Reconnect by exact actor and generation, with no cross-session
   leakage or duplicate acknowledgement.
3. Expand Codex only where the native app-server offers verifiable behavior:
   active steer, interrupt, host requests, native history, child observations,
   foreground interval, usage and final-item provenance. Advertise each
   capability only after a bounded real or controlled probe. A phase-null
   agent message remains output, not an invented final answer.
4. Add Claude/Qwen/OpenCode adapters independently with pinned profile,
   account, model, effort, approval and sandbox policy; no silent fallback to
   another provider or direct Zap-owned process. Record provider-specific
   continuation/readiness and uncertain input semantics. Unsupported features
   remain typed unsupported.

**Gate:** create→ask→answer→report/review under a live pod; denied and stale
permission never executes; recipient/scope separation, manager restart and
lost reply preserve one logical request; each advertised provider operation
has its own native receipt. Do not infer provider consumption from a PTY write
or HTTP success.

### PM-05 — full Zap runtime and UI cutover

The local MVP may support one pinned coordinator profile while old code still
exists outside that selected route. The broad cutover must eliminate active
Zap process ownership, not just add a PodBay dependency.

1. Inventory active Codex, managed-work and managed-terminal process
   factories, wrapper workers, broker stores and installer launchers. Compare
   their source paths with the current PodBay Run/Resource model. Freeze new
   old-wrapper effects at a precise barrier, audit the live roster and retain
   historical ghosts only as history. Never adopt an unverified old process.
2. Map the coordinator and every managed Worker/Task/PTY action to typed
   PodBay receipts, reads, event cursors and exact actor grants. Preserve
   accepted Zap/VibeVM plans, task/chat/review records and pause intent.
   Do not replay an old runtime queue into new pods. Unsupported actions are
   disabled, never silently routed to a legacy wrapper.
3. Bind Wayfinder routing/catalog/profile selection to effective PodBay
   policy. Pin provider binary/account/model/effort/cwd/tool bundle, and
   remove implicit native process fallback. Include the generated client and
   exact PodBay source generation in the installed Zap artifact.
4. Switch workspace event projection, chat, terminal viewers and managed
   control to source-bound PodBay snapshots and subscriptions. Preserve
   output/history with source EventIds and explicit gaps. Remove the old
   Codex stdio and managed-terminal wrapper implementation only after a
   reference scan proves no active consumer; do not delete unrelated dirty
   work merely because it resembles a wrapper.
5. Rehearse crash windows around the cutover barrier, manager restart, lost
   launch/send/stop reply, installer rollback and forward repair. Demonstrate
   exactly one dispatcher/spawn owner for every advertised path.

**Gate:** focused product and native fixtures preserve accepted records and
queued input, show no old process owner, no duplicate pod/provider input and
one installed generation. A source dependency or generated DTO alone is not
a direct-runtime cutover. The historical detailed mapping lives in
/fast/git/v/research/2026-10-04-zap-podbay-cutover-surface.md; verify it against
current Zap before acting because its 2026-10-04 status is now stale.

### PM-06 — macOS and Windows native backends

First finish or verify the portable SupervisorBackend, TerminalBackend,
LocalControlTransport and DurableFiles port boundaries. Core/wire compile
without Linux-only public fields. A cross-target compile is only a preliminary
check.

**macOS (PB26):** a distinct per-pod user launchd agent survives manager
restart within the login session; logout is an explicit stop/unknown boundary
until a separate daemon design is approved. Commit exact plist/manifest and
label before launch, reconcile a lost launchctl result by pod handshake,
and recheck PID plus process start/boot identity before adoption or signaling.
The pod owns POSIX PTY and process group. Verify whether PTY child setsid or
an escaping grandchild evades cleanup; do not claim owned-tree stop if so.
Authenticate Unix peers by UID plus PID/start and scoped capability, not UID
alone. Implement private append/sync and checkpoint replacement with
platform-proven durability; F_FULLFSYNC is a candidate, not assumed.
Native fixture: launch/restart/rebind, lost launch response, tree stop
including setsid escape, two viewers/lease/replay/gap, same-account sibling
refusal, sync crash windows, and logout boundary on a real macOS runner.

**Windows (PB27):** an independently living pod owns its child Job Object
handle, ConPTY and named-pipe server; the restartable manager must not hold
the sole kill-on-close handle. Create pod/child suspended, prove permitted
job breakaway/assignment before resuming user code, and refuse unsupported
parent-job hosts. Reattach using held PID plus creation time and manifest
digest; never PID alone. Secure named pipes with a narrow DACL, first-instance
and remote-client refusal, then attest both client and server process
birth/capability to separate same-account siblings. Implement Windows
FlushFileBuffers and immutable checkpoint-generation ledger; do not copy
POSIX rename/fsync assumptions. ConPTY output drain continues during close.
Native fixture on a Windows runner: job containment/descendant cleanup,
ambiguous launch, manager death/rebind, ConPTY view/input/resize, pipe scope
refusal and durable crash windows.

PB28 is an acceptance matrix. Advertise Linux, macOS and Windows separately
only when each requested capability passes its own native receipts. The
historical platform design notes are
/fast/git/v/research/2026-10-03-podbay-macos-backend.md and
/fast/git/v/research/2026-10-03-podbay-windows-backend.md.

### PM-07 — PodBay multi-host supervisor and operator tools

This is future architecture, explicitly **not** part of the local MVP or
current VibeVM-start gate.

1. Keep OS handles/process trees and input spool on the hosting computer.
   Introduce durable HostId, node incarnation, signed controller identity,
   placement policy, transport session and per-host capability discovery.
   The control plane routes; a central connection never becomes the owner of
   remote children.
2. Design authenticated host enrollment, key rotation/revocation, narrow
   grants, network transport, offline queue and reconnect. Bind a command to
   exact host/node incarnation, Pod/Resource epoch, caller key and deadline.
   Reconcile network loss before another dispatch; never assume a remote
   timeout means the process did not start.
3. Define split-brain/lease and clock rules. A partition cannot create two
   writers or two Pods for one logical attempt. Preserve source ordering,
   causal parentage, event watermarks, gaps and explicit stale observations
   across hosts without pretending wall-clock order is causality.
4. Provide hosts.list/route and bounded placement by capability, workspace,
   resource budget and trust domain. Separate local danger-full-access
   development from future stronger isolation/cloud sandboxes; a shared UID
   or copied token is not an adversarial security boundary.
5. Build PodBay-native operator utilities analogous to ps, exact launch on a
   selected computer, wait/watch, stop and tracing of parent/child invocation
   chains. They consume the same command/event ledger and return truthful
   stages; they do not invent a second dispatcher.

**Gate:** two real machines (not two paths on one host) with isolated state:
launch once, disconnect controller/host, manager restart on each side,
partition/rejoin, exact birth/Pod/CommandId recovery, no duplicate input,
scope refusal, bounded stop/descendant proof and ordered/gapped event replay.
The CLI tools must inspect the same identities seen by the API.

### PM-08 — optional outward ACP gateway

The detailed historical gateway design is
/fast/git/v/research/2026-10-03-podbay-acp-gateway-design.md.
Recheck the then-current official ACP v1 specification, v2 Draft revision,
SDK and TCK when this phase actually starts. This is a gateway, not a
statement that PodBay internally implements ACP.

1. Put translation in an optional removable crate/process. Negotiate a
   supported protocol major and expose only capabilities actually working
   for the selected provider/profile. ACP client metadata is not PodBay
   authentication; local stdio uses a protected scoped grant.
2. For v1, create a service session with no fabricated model input. A prompt
   is a durable PodBay message plus an exact foreground interval: keep the
   request pending until that interval settles, and stream source-bound
   updates. Cancellation requires observed abort/flush; a dead gateway
   connection is not a stopped pod. Map permission and elicitation only if
   their native typed routes and client capability are implemented. Do not
   confuse PodBay-owned terminals with ACP client terminal handles.
3. Provide correct retained session load/resume/list/close only when each is
   complete. Replay from stable source IDs, preserve chunks/upserts, and
   report gaps. ACP v1 lacks a universal cross-connection prompt idempotency
   key, so document lost-response limits rather than resending input.
4. Treat v2 Draft as a separate opt-in serializer/state adapter. Its prompt
   response acknowledges actual logical insertion, not provider completion;
   foreground running/requires_action/idle is a separate observed state.
   Implement required list/resume/close, replayFrom, upsert/chunk/null rules,
   display-only terminal updates and version-specific auth/capabilities
   before advertising v2. Preview subagent extensions do not become
   baseline v2 support.
5. Run pinned official TCK plus custom mandatory stdio-MCP, permission,
   cancel, lost-reply, gateway-restart, manager-restart, transcript replay and
   security fixtures. Record exact spec/TCK revisions; an experimental TCK
   pass is evidence for that revision, not general certification. Keep
   third-party Apache notices if using their SDK/material.

## Resumption checklist for the next agent

1. Read this full document, then the three canonical PodBay PROP files above
   and the relevant detailed research for the phase. Read the current PodBay
   and Zap code rather than trusting old path/line references.
2. Confirm the owner's current priority. The 2026-10-05 instruction is local
   MVP → PodBay-backed Zap → VibeVM to completion. Do not start PM-01 through
   PM-08 merely because this document exists.
3. Record an empirical baseline: Git refs and dirty worktrees, installed
   generation, current store schema, advertised versus served operations,
   live process ownership, exact passed/failed/skipped targeted tests.
4. Select one phase/atom with disjoint file ownership. Preserve the verified
   local MVP while implementing it. No old-schema migrations for nonexistent
   PodBay clients; protect existing Zap/VibeVM domain data.
5. For every newly advertised capability, obtain the stated native
   acceptance receipt on its target OS/host. A typecheck, DTO parser, mock
   restart or screenshot is insufficient. Leave unsupported capabilities
   explicitly unsupported until then.
6. Update this campaign record with accepted evidence, remaining blockers
   and changed dependencies when broader work is actually resumed.
