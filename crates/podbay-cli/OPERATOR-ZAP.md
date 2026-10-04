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
- `wallSeconds` from 30 through 3600;
- optionally, both `headlessConfig` and `headlessConfigSha256` for Zap's
  `--podbay-config` path. The config must be a private 0600 file directly in
  `zapStateDirectory`.

The outer PodBay store and Pod directory are fixed at
`stateDirectory/podbay.sqlite` and `stateDirectory/pods`. They must be separate
from the installed Zap tree and Zap state. When `headlessConfig` is present,
Zap's inner manager uses `zapStateDirectory/podbay`, a different store and Pod
namespace. The launcher passes only the exact reviewed Node arguments:
`--experimental-strip-types src/zap-server.ts --state-dir ...` and, when pinned,
`--podbay-config ...`.

The first launch fsyncs a private `owner-key.1.json` before signing owner
enrollment. Later CLI processes fsync the next generation key before signing
both sides of owner recovery. Key seeds remain in 0600 files under the outer
state directory; they are never policy fields, arguments, or output. Recovery
keeps one ActorId and command principal. An existing HostAccepted Pod is
proof-rebound before the original command receipt is returned. A Prepared
command may use its explicit reviewed resume path. Uncertain effects refuse a
second OS launch.

The policy digest is bound into key custody. A changed Zap tree, config, or
policy cannot recover the existing outer Pod. Retain the old private policy
and artifact until that Pod has been inspected and explicitly retired. Install
an updated artifact with a new outer state directory, store, IDs, and key
custody; this command provides no seamless upgrade or migration. The current
`RuntimeMaxSec` is at most 3600 seconds, so this is a bounded service launch,
not indefinite Zap hosting. The disposable fixture proves outer A→B rebind
and one authenticated HTTP session; nested coordinator startup is a separate
acceptance step.
