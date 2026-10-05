# PodBay backlog

Read [POST-MVP-CAMPAIGN.md](POST-MVP-CAMPAIGN.md) before expanding beyond the local MVP. These findings are not active work until prioritized.

## P2-001 — Native checkpoint write amplification

A real Codex turn produced 3,153 native events and a 1.1 MiB checkpoint. Each event reserves and commits by rewriting/fsyncing the bounded full index; the pod used roughly 74% CPU. [Evidence and benchmark design](NATIVE-CHECKPOINT-PERF.md) distinguish this writer cost from the now-fixed stale reader retry.

**Owner decision after the disposable benchmark:** adopt a versioned append-only native commit record with periodic compact snapshots and crash-point proof, or keep the bounded v2 checkpoint for the local campaign? This is a format/recovery redesign; it does not block current VibeVM work while the 4,096-event window and prefix-verified reads hold.
