# Terminal stop of an outer Pod whose child has exited

## Observed gap

An `operator_process_v1` child can exit while its `untilStopped` supervisor and
systemd unit remain active. The next operator CLI process recovers its owner
key, but `operator zap stop` first calls
`prepare_current_operator_process_rebind`. The port's rebind inspection
requires the original child PID and birth to be live. It returns `StaleGuard`
before the CLI checks its exact StopPod grant or publishes a stop intent. The
disposable `exited_child_leaves_outer_unit_but_signed_stop_cannot_rebind`
fixture records that boundary. Child exit during Zap config validation has the
same supervisor state; SIGKILL in the fixture makes the transition deterministic.

## Required contract

Add a **terminal-only** Pod control operation for this case. It must never
produce `PodActive`, advance a resource input epoch, or claim that a live
child rebind succeeded. Keep the normal rebind path unchanged for a live child.

1. The CLI loads the exact private policy and owner key, recovers the current
   owner, looks up the original HostAccepted launch by key, and reviews the
   committed operator descriptor and immutable profile. Its exact StopPod
   grant and target guards must authorize the operation before a stop intent
   can be published.
2. The Pod side must attest a *settled* child from its retained PID, birth, and
   wait status while its supervisor is still running. A new terminal-stop
   inspection must bind the current owner/credential claim, original Pod fence
   identity and committed descriptor, manifest digest, socket inode, systemd
   unit, supervisor PID/birth, child PID/birth, and a fresh challenge. It must
   prove that the child birth is no longer live. A manager cannot infer this
   from a missing `/proc` entry or a unit name alone.
3. A distinct terminal-stop preparation must durably fence the Pod to the new
   manager for `StopPod` only. It must refuse if the child is live, if another
   manager or owner claim is current, or if any immutable identity changes.
   The Pod must reject all launch, provider input, and ordinary rebind attempts
   through that terminal fence. This is a state transition, not `PodActive`.
4. Publish a private, fsynced, one-use stop intent containing that terminal
   proof before one Pod stop call. A lost reply is handled by exact unit,
   process-birth, socket, and manifest observations. A still-live unit after
   one call remains uncertain; there is no automatic second stop. Preserve the
   existing terminal receipt and duplicate-read behavior.
5. Test live-child refusal of the terminal path, changed policy/manifest,
   replaced unit or supervisor, stale owner, lost reply, and duplicate stop.
   The exited-child fixture should then assert a successful signed terminal
   stop and removal of the exact unit without its disposal bypass.

The current `PodClient::attested_status` and `PodClient::stop` are guarded by
the old manager peer. Merely skipping rebind and calling them from a recovered
CLI fails that fence. Calling `systemctl --user stop` from the CLI after a
`StaleGuard` would bypass the Pod's signed owner and peer checks, and the
manifest has no durable original child or supervisor birth to exclude a
substituted live unit. That shortcut cannot be used as the operator recovery
contract.
