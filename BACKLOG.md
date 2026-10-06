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

## P1-005 — Manager handshake timeout blocks exact stop of a live Pod

On 2026-10-06, the local VibeVM Coordinator Pod was alive at exact Run
`run.64d8b3c06527bc287ad6ff68bf9dbffa`, Pod
`pod.debe7036ac13e486fd56af701b330b39`, epoch `1`. Zap's
`podbay.coordinator.stop.v1` failed twice **before effect** while reading the
current launch guard: `PodBay root stop guard read failed`. Its stderr had
repeated `AuthenticatedSocketTransportError: authenticated PodBay socket
exchange failed: handshake_timeout` for native readback and writer renewal.
Stopping/relaunching only the outer Zap/manager from `outer-v34` to
`outer-v35` kept the inner Pod alive but did not repair the guard read.
The PodBay event ledger contained no stop request or terminal stop receipt.
For the owner-requested computer reboot, the operator verified the exact
manifest Pod/Run, systemd unit, MainPID, no auto-restart and cgroup kill mode,
then stopped that one unit with `systemctl --user`; it became inactive/dead
and both Pod/Codex PIDs disappeared. This OS observation is **not** a signed
PodBay stop receipt. The Lens session remains historically uncertain pending
reconciliation after reboot.

After reboot, manager startup recovered owner epochs 10 and 12 but refused
readiness while preparing the same current V2 Pod for live rebind:
`pod I/O failed: Connection refused (os error 111)` became
`Host(StaleGuard)`. The exact unit was still inactive with `MainPID=0`.
`current_codex_v2_rebind_page` still lists the Pod because no `pod.stop`
outbox row exists. Repeating owner recovery changed epochs but did not settle
the Pod. A new manager generation cannot infer a signed stop from this state;
the old store must remain inspectable until an exact durable external-death
reconciliation is implemented.

**Priority investigation:** retain the underlying authenticated exchange
error and timing in the typed guard-read result; determine whether manager
load, socket backlog, peer authentication or the native checkpoint loop caused
the timeout. Add a bounded, exact-key stop/readback repair path that can
reconcile a proved inactive unit without forging a successful PodBay stop or
reissuing a possible native input. Test a live high-event Pod, manager restart,
timeout before effect and terminal-only external stop. Do not automate an
unchecked `systemctl stop` or weaken the current Pod/Run/epoch fence.

## P1-006 — Operator Zap boot has no terminal-to-fresh-generation path

The `operator zap restart` CLI now has a strict, typed closed front door. A
well-formed request returns `production_restart_closed` with exit 2 before
policy loading, directory creation or owner-state I/O; repeated requests have
the same refusal and no allocation. This is a preparatory contract only.
The passive evidence prototype can decode a strict signed envelope and read a
schema24 historical verifier snapshot in a disposable fixture. Production
origin acquisition returns `OriginUnavailable` before I/O; even a valid old
signature remains `SigningTimeUnavailable` without independent time evidence.
A separate Linux/test-only store fixture now shows that exact signed bytes can
be admitted under the current nonrevoked key in the same `BEGIN IMMEDIATE`
revision transaction used to serialize Owner rotation. Exact committed replay
survives rotation; an old key first presented after rotation refuses. Process
SIGKILL controls cover before/after commit, not power loss. This noncanonical
fixture does not sign or authorize the production terminal envelope.
P1-006 remains open until trusted signed-terminal acquisition, durable fresh
generation publication, and authenticated child readiness are implemented.

After the signed terminal stop of outer Service `outer-v35` on 2026-10-06,
`podbay operator zap launch --policy .../outer-v35/operator-zap-policy.json`
returned exit 2, `existing Zap Pod rebind preparation failed:
Host(StaleGuard)`. The stopped policy's original command key still resolves to
`HostAccepted`/`PortSettled`, so `launch` enters the live-Pod rebind branch;
that branch correctly refuses a stopped Pod. The operator had to copy the
policy into a fresh `outer-v36` directory and manually mint eight `v36`
identities. This is a boot orchestration gap, not evidence that the old Pod
should be rebound or its command replayed.

The fresh `outer-v36` launch then returned exit 0 and a `childPid`, although
the child exited immediately because another Wayfinder owned the same state
database. The PodBay supervisor remained active with a defunct child. Exit 0
here proves host acceptance, not Zap readiness. The exact failed supervisor
was stopped after identifying its unit and confirming the child had exited.

**Required boot path:** provide an idempotent owner-level restart operation
that reads the prior exact terminal receipt, allocates a fresh state directory
and disjoint actor/scope/Pod/Run/attempt/resource/command identities, retains
the same pinned artifact and verified configuration, then launches once. It
must wait for authenticated child readiness or return a typed child-exit /
configuration-conflict result with the exact accepted launch identity. On
unknown prior effect or live child, stop before allocating a new generation.
Test terminal restart, repeated request, crash between allocation and launch,
foreign live owner, immediate child exit and old-command replay. Do not make
the low-level same-key `launch` silently create a second Pod.
