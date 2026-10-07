# Disposable systemd R1 refusal receipt (2026-10-07)

This receipt concerns the ordinary-UID, TCG, read-only fixture only. It does
not establish production cold-boot provenance, an admitted broker, custody,
origin, or readiness.

## Accepted negative observation

The third fresh run used the offline plan SHA-256
`663536a6e677b8f39b55913d692f151e77c12374f0699703d8ab36b6cb71e287`
and archive SHA-256
`1f733d32162168b9964610ce6e94624b68270e365c6fc331b87e51d5289edc7f`.
Its single `ttyS1` event reports actual systemd PID 1, bootstrap and custodian
exit code 2, zero issuer starts, and four outside EACCES denials. The event
keeps `enforcer_gate=UNESTABLISHED` and `admission=UNAVAILABLE`.

QEMU exited 0. The runner recorded exact child PID 1589279, birth tick
12648744, pidfd exit verification and reap. Its stderr was empty; the
diagnostic console had one final `reboot: Power down` and no missing-helper
EXEC warning. The 32 MiB read-only disk retained SHA-256
`08beddae60a2738b4bd0af8b0f1f1f218a6f8c498563fd1467e2810dd66cd911`.
The result receipt SHA-256 is
`72fef0c5f339caae905db5d8a41cd965dc570945af312f62a0f1061099505970`.
An independent read-only review found no P1/P2 inconsistency in this bounded
evidence. On this machine, the retained files are under
`/home/olegchir/podbay-r1-systemd-vm-build/systemd-run-native-third/`.

## Failed and qualified predecessors

- The first actual systemd run lacked mandatory `systemd-executor`; PID 1
  printed manager-allocation ENOENT and froze. The runner timed out, killed
  and reaped QEMU, and retained the unchanged disk.
- The second run observed the same refusal and blocked issuer, but systemd
  could not spawn `/usr/bin/umount` during shutdown. Its old runner result
  said success; the later audit reclassified it as negative mechanisms
  observed with clean shutdown failed. The original receipt remains intact.
- The third run packages the pinned util-linux `umount` and rejects the
  exact `Failed at step EXEC` diagnostic. BusyBox was not used because its
  applet did not advertise systemd's required `-c` option.

No fixture result is a production CLOSED-origin proof. The remaining R1
barrier requires a reviewed production constructor, maintained issuer and
reader exclusion through migration, and a separate controlled deployment
decision.
