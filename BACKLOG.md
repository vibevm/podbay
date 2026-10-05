# PodBay backlog

Read [POST-MVP-CAMPAIGN.md](POST-MVP-CAMPAIGN.md) before expanding beyond the local MVP. These findings are not active work until prioritized.

## P2-001 — Native checkpoint write amplification

A real Codex turn produced 3,153 native events and a 1.1 MiB checkpoint. Each event reserves and commits by rewriting/fsyncing the bounded full index; the pod used roughly 74% CPU. [Evidence and benchmark design](NATIVE-CHECKPOINT-PERF.md) distinguish this writer cost from the now-fixed stale reader retry.

The 2026-10-05 live Zap PodBay store was under `/home` on ext4 although the
host's `/fast` NVMe mount is XFS. A disposable 1.4 MiB checkpoint-style
write+fsync+rename+directory-fsync probe measured median 19.12 ms on ext4
and 6.49 ms on XFS (20 timed iterations each). Zap 1.1.0 now supports an
owner-pinned XFS `podDirectory` for a **fresh** manager state. The current
running Pod cannot be repointed; use its signed stop and archive the complete
old manager state/map before starting a new Pod there. This placement change
reduces filesystem latency but does not remove the full-checkpoint rewrite.

**Owner decision after the disposable benchmark:** adopt a versioned append-only native commit record with periodic compact snapshots and crash-point proof, or keep the bounded v2 checkpoint for the local campaign? This is a format/recovery redesign; it does not block current VibeVM work while the 4,096-event window and prefix-verified reads hold.

## P1-002 — Claimed later turn loses port disposition

On 2026-10-05 the live VibeVM coordinator's later-turn command
`command.pb04.5f54c5f96d11f191ebe9c943b38cec80706e1c050850f0afcad7798f6a5379f5`
was durably admitted at owner epoch 4 and its outbox became
`claimed_uncertain`. More than the 75-second PodClient timeout later, the
manager had no Pod socket, while the live Pod/Codex remained healthy and the
Pod's fsynced `codex.turns.log` had no intent for that command. Both native
send paths write the intent before `turn/start`, so this observation rules out
a native input effect for this instance. The store retains neither the port's
`RefusedBeforeEffect` nor `UncertainAfterPossibleEffect` result; after a
restart the two cases are indistinguishable from `commands.get`, and a
same-key retry does not dispatch a claimed outbox again. Zap consequently
cannot repair this no-effect command through its ordinary API.

**Owner design decision for the broader supervisor:** persist a typed port
disposition and evidence reference after every claimed effect, expose it in
authenticated exact-command readback, and define a fenced repair action for
a proved pre-effect refusal. A transport timeout must remain uncertain until
the Pod journal and current process identity prove whether an intent was
fsynced; never blindly resend after a possible input effect. The local MVP
may retire this finite Coordinator through the signed exact stop path and
start a fresh unlimited Service, preserving Zap/VibeVM history separately.

## P1-003 — Outer Service cannot signed-stop after its child exits

The live Zap outer Service `v25` survived its child exiting during headless
config validation. `podbay operator zap stop` refused at rebind preparation
with `Host(StaleGuard)`, leaving the systemd supervisor active. The exact unit
was then stopped with `systemctl --user` after verifying the child had exited. The
[terminal-only stop design](crates/podbay-cli/ORPHAN-OUTER-STOP-DESIGN.md)
specifies the Pod attestation and one-use stop fence needed to make this a
normal signed operator operation. The current disposable known-gap fixture
compiles but was not run; the live failure is the operational evidence.

**Owner decision before broader deployment:** implement the terminal-only
stop path and its crash/foreign-unit proofs, or make the outer Pod supervisor
terminate itself with a durable terminal receipt when its child exits. Do not
weaken live-child rebind or issue an unchecked `systemctl stop` from PodBay.

## P1-004 — Local Run pause/resume capability and truthful observation

The VibeVM campaign reached a clean Coordinator checkpoint on 2026-10-05, but Zap's `project.pause.v1` had no PodBay pause operation to call. Zap then retained `pausing/unsupported`; the immediate stranded transition is a Zap defect tracked in its backlog. The broader PodBay supervisor plan already names generic Run pause/resume in [PM-01](POST-MVP-CAMPAIGN.md), but it has no local capability contract or implementation yet. Pausing a Pod process, holding new work at the manager boundary, interrupting a native turn, and stopping the Run are different effects and must not share one success label.

**Priority and design gate:** define the local Run pause/resume semantics before Zap advertises a native pause capability. Specify whether the scope is admission-only, cooperative process/agent quiescence, or OS suspension; expose unsupported capabilities truthfully. Require exact Run/Pod/Resource and owner-epoch fences, a durable requested-versus-observed receipt, behavior across manager restart and lease expiry, and explicit handling of an in-flight native turn and child processes. A plain `SIGSTOP` or lack of new messages is not proof of a durable PodBay pause. Implement the smallest local slice needed for Zap first; remote machines and the wider PM-01 campaign remain deferred.
