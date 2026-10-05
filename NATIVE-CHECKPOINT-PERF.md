# Native checkpoint write cost after the local MVP

## Observed bottleneck

A real Linux Codex turn reached about 3,153 native events and a roughly 1.1 MiB
checkpoint. The pod used about 74% CPU while reserving each take and committing
each append. Both operations serialize, write, and fsync the full bounded
checkpoint. The cost per event grows with the retained index, up to 4,096
events. The manager previously retried an authenticated page whenever the
checkpoint advanced between the pod reply and its private read. A bounded
prefix check now lets that page complete while its frames remain in the
verified retained index.

The prefix fix does not change the writer's durability cost. No live private
JSONL or prompt content is needed to measure it.

## Proposed next experiment

Use a disposable slot and generated non-sensitive frames. Record event rate,
checkpoint bytes written, checkpoint fsync count and latency, CPU, manager
cursor lag, and time to read a 64-event page at 128, 1,024, and 4,096 retained
events. Repeat with an active writer and with a forced crash at each write
boundary. Keep a no-gap reader and the exact crash/quarantine behavior as
acceptance conditions.

If the measurements confirm the write cost dominates, design a bounded
append-only commit record for the reservation and frame metadata, with
periodic compact snapshots. A record would need a checksummed generation,
source sequence, prior chain digest, redacted projection, and durable ordering
relative to the segment frame. Reopen must reject a torn or unindexed tail and
must never infer that a possibly consumed native notification was absent.
Rollover and pruning must retain their current chain and gap proofs. This is a
format and recovery change, not a local serialization tweak.

## Owner decision

After the disposable benchmark, should PodBay take on a versioned native
checkpoint/commit-log format with crash-point tests to remove the per-event
full-index fsync cost, or keep the bounded v2 format for the local campaign?
