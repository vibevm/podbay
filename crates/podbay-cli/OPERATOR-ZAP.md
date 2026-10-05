# Installed headless Zap operator

`podbay operator zap hash --root ABSOLUTE_PRIVATE_ZAP_COPY` reports the installed
tree digest, entry count, bytes read, and hash time. Install the complete Zap
runtime, including `src`, package metadata, and `node_modules`, in a canonical
owner-owned directory without group/other write access. The verifier includes
file contents and symlink targets; symlinks must resolve within that tree. Each
scan is capped at 20,000 entries, 512 MiB, and eight seconds. Node runs with a
cleared environment, so imports must resolve from the installed copy.

`podbay operator zap launch --policy ABSOLUTE_PRIVATE_JSON` accepts one
owner-owned, singly linked 0600 `operator-zap-policy.json` in its canonical
0700 `stateDirectory`. The strict `podbay.operator-zap-policy/1` JSON pins:

- `stateDirectory`, `podExecutable`, `podExecutableSha256`,
  `nodeExecutable`, `nodeExecutableSha256`;
- `zapRoot`, `zapArtifactSha256`, `zapStateDirectory`;
- stable `actorId`, `scopeId`, `podId`, `sessionId`, `runId`, `attemptId`,
  `resourceId`, `workspaceBasisRef`, `hostId`, and `commandKey`;
- `lifetime` as exactly `{ "kind": "finite", "seconds": N }` with N from 30
  through 3600, or `{ "kind": "untilStopped" }` for this trusted local
  Auxiliary Coordinator/Service Pod;
- optionally, both `headlessConfig` and `headlessConfigSha256` for Zap's
  `--podbay-config` path. The config must be a private 0600 file directly in
  `zapStateDirectory`.

`podbay operator zap stop --policy ABSOLUTE_PRIVATE_JSON` uses that same exact
policy and signed owner key custody. It recovers the stable ActorId, checks the
original HostAccepted launch, proof-rebinds the live Pod, and checks the exact
StopPod(PodId) grant before a fenced Pod stop. The operator grant contains only
LaunchPod and StopPod for that one Pod; it has no provider input right.

The outer PodBay store and Pod directory are fixed at
`stateDirectory/podbay.sqlite` and `stateDirectory/pods`. They must be separate
from the installed Zap tree and Zap state. When `headlessConfig` is present,
Zap's inner manager uses `zapStateDirectory/podbay`, a different store and Pod
namespace. The launcher passes only the exact reviewed Node arguments:
`--experimental-strip-types src/zap-server.ts --state-dir ...` and, when pinned,
`--podbay-config ...`.

The first launch atomically publishes and fsyncs a private `owner-key.1.json`
before signing owner enrollment. Later CLI processes fsync the next generation key before signing
both sides of owner recovery. Key seeds remain in 0600 files under the outer
state directory; they are never policy fields, arguments, or output. Recovery
keeps one ActorId and command principal. An existing HostAccepted Pod is
proof-rebound before the original command receipt is returned. A Prepared
command may use its explicit reviewed resume path. Uncertain effects refuse a
second OS launch.

The policy digest is bound into key custody. A changed Zap tree, config, or
policy cannot recover the existing outer Pod. Retain the old private policy
and artifact until that Pod has been inspected and explicitly stopped. Before
the stop call, the CLI atomically publishes and fsyncs a private intent with the original launch
CommandId, policy digest, Pod, unit, manifest digest, socket inode, and
supervisor/child births. It invokes PodClient stop at most once for that intent.
A lost reply remains uncertain until exact unit and process observations prove
termination; a duplicate invocation reads the fsynced terminal receipt without another
Pod stop. These private stop files are an installed operator sidecar, not a
generic PodBay command/event ledger. A live Pod with an uncertain intent needs
explicit operator reconciliation; this CLI will not retry the stop blindly.
Install an updated artifact with a new outer state directory, store, IDs, and key
custody; this command provides no seamless upgrade or migration. The current
finite mode keeps its `RuntimeMaxSec` bound. `untilStopped` sets and verifies
an unlimited systemd `RuntimeMaxUSec` for the outer Zap Service while retaining
`KillMode=control-group`, `TasksMax=128`, and the signed exact-Pod stop path.
It does not restart a crashed process or persist a transient unit across a
machine reboot. Worker/Task Pods retain finite trusted budgets. The inner
Codex Coordinator/Service may opt into its own tagged `untilStopped` lifetime
through a private trusted manager policy and matching signed launch, while its
renewable writer lease remains bounded independently. Disposable fixtures prove outer A→B rebind, one nested
fake Codex coordinator with native output and cursor acknowledgement, and an
explicit terminal stop of the unlimited outer Service.

The inner manager accepts a signed `run.stop` only for its own current local
Codex V2 root Coordinator/Service with an `untilStopped` lifetime. The request
uses the exact Run target, `scope: "self_only"`, the exact `podId`, and current
manager, Pod, and Resource epoch guards. Manager owner and credential grants
must still match the committed launch. PodBay commits one stop intent and
claims its outbox effect before its one Pod stop call. A lost reply or manager
restart is reconciled from the original key and observed unit, process birth,
and socket identity; retries never send another stop. `commands.get` reports
`observedStage: "pod_stopped"` only after terminal proof. A claimed stop whose
unit remains live is uncertain and requires operator inspection; no automatic
second stop or relaunch is attempted.
