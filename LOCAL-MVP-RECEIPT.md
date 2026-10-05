# Local Linux MVP evidence — 2026-10-05

This is a narrow operational receipt for the PodBay → Zap → VibeVM dogfood
path. It does not certify remote hosts, macOS/Windows, delegated Workers,
requests/permissions, ACP, or the broader supervisor API. Read
[POST-MVP-CAMPAIGN.md](POST-MVP-CAMPAIGN.md) before starting those phases.

## Observed live path

- Zap 1.1.0 runs as a PodBay-owned local `Coordinator/Service` outer Pod.
  Its signed exact-Pod operator stop was exercised during artifact switches;
  the final active outer systemd unit has `RuntimeMaxUSec=infinity`.
- Zap starts one Codex `Coordinator/Service` through a separate PodBay manager
  and store. The manager policy pins `gpt-6-sol`, `medium`, `approvalPolicy=never`,
  and `danger_full_access`. The active inner unit has
  `RuntimeMaxUSec=infinity` and `TimeoutStopUSec=5s`, with one Codex app-server
  child. A writer lease remains finite and renewable, independently of the
  Service lifetime.
- The finite predecessor was stopped through authenticated `run.stop` on the
  exact Run/Pod/epoch. PodBay recorded one `pod.stop` outbox effect as
  `observed/pod_stopped`; the Pod and Codex PIDs disappeared. Zap then used
  guarded `project.recover-coordinator.v1` to retire that incarnation without
  deleting Workspace chat or the VibeVM plan.
- The new Coordinator started in the same VibeVM context on a fresh PodBay
  store. Its first later turn reached `host_accepted` and `submitted`; native
  source events and Zap's acknowledged cursor advanced together without a
  quarantine. VibeVM development resumed from the clean `b0769c5ab` boundary.

The selected code was published on PodBay branch `codex/podbay-v2-pod` and Zap
branch `1.1.0`. Disposable focused tests cover UntilStopped systemd launch,
finite/unlimited exact stop, same-key lost-reply readback, A→B manager rebind,
multiple-rebind later sends, and Zap startup replay. No full gate panel or
mutation campaign was run for this operational cutover.

## Limits observed during dogfood

- [P1-002](BACKLOG.md#p1-002--claimed-later-turn-loses-port-disposition): a
  claimed later-turn effect can retain `claimed_uncertain` without the port's
  typed refusal/uncertainty reason. The finite predecessor had one such
  command; its intact Pod journal proved no native input, but ordinary API
  readback could not repair it. The historical Zap chat entry remains
  `uncertain` rather than falsely answered.
- [P1-003](BACKLOG.md#p1-003--outer-service-cannot-signed-stop-after-its-child-exits):
  an outer Pod whose child exits before rebind cannot yet use signed operator
  stop. A terminal-only fence or supervisor self-settlement is designed, not
  implemented. The live occurrence was cleaned up by stopping the exact
  orphaned systemd unit after confirming the child had exited.
- [P2-001](BACKLOG.md#p2-001--native-checkpoint-write-amplification): the
  bounded native checkpoint is rewritten for each event. This costs CPU but
  did not prevent native cursor catch-up in the current local campaign. A
  versioned format redesign is deferred by the owner until after the VibeVM
  campaign.

Before relying on this receipt later, recheck the current Git revisions,
manager policy, systemd units, Pod/Resource identity, Workspace execution,
native cursor, and exact test results. Process IDs and pairing URLs are
ephemeral and intentionally omitted.
