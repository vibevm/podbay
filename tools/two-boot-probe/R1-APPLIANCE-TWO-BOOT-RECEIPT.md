# Disposable appliance read custody across two fresh boots

2026-10-07. **Qualified closed-appliance evidence only.** This receipt covers
the pinned, read-only QEMU fixture. It does not grant generic production
origin, migration admission, an Owner epoch, or systemd Ready.

The pair used offline plan SHA-256
`763e77301bf760d21dad8530794a82e57b9436065d5053a22f113ebcf332fcaf`
and artifact generation
`a55668c42f88295c7381d101a85be8ce05e68587dd67322d91be3805b862a7c2`.
Boot A and B were separate fresh kernels, not a memory snapshot. Their boot
IDs were `660ccef3-1444-45b7-8c58-378ea8f63597` and
`2593a2ef-3064-4cfc-bad8-0ccdba6115a7`; their nonces and bound read
digests differed. Both sealed UID1000 custodians read the same 397312-byte
source with SHA-256
`dff42af336ee86ff68236b579f210829a665c31e7df1c7ed1521b38def004ab6`.
The nonce-bound digest in each event matches the fixed domain-separated
calculation over its nonce and actual source hash.

The observed controlled sequence included an exclusive preexisting lock,
clean FD handoff and seal, a successful nonce-bound read, eight outside
denials, keeper SIGKILL, custodian/keeper pidfd exits, empty controlled
cgroup and same-boot spent-attempt refusal. Ordinary issuer starts were zero;
the producer never signaled Ready. Production origin and migration admission
remained `UNAVAILABLE`.

QEMU processes 1763027 and 1763069 both exited 0 with exact pidfd-verified
reap. Hypervisor stderr was empty and both consoles ended in power-down.
Both retained read-only 32 MiB disks hash to
`a3ef33f393d2bf2ed3f87dc278f466d187599874b21c9445b0d7c3a4048f22f0`.
An independent read-only audit found no P1/P2 inconsistency in this bounded
evidence. Exact receipt SHA-256 values:

- Pair: `5a071dcd4b35e6101ef60a2c58def5757a21ebf5d497ecccd5867359ddcdffdb`.
- Boot A: `5a37d2bf4285406e64432b01e00047aa71b156700517d11c332811ad54db5fb0`.
- Boot B: `c13e6ff4134fc4cb92d063f3f842e9fd6791f7880a6f05c3e2575b0e04e0b01a`.

Raw local evidence is under
`/home/olegchir/podbay-r1-positive-origin-build/appliance-run-native1{,-a,-b}/`.
The result depends on the reviewed immutable guest launch closure and trusted
kernel, PID1, guest root, observer, binaries, hypervisor and invoking host UID.
It does not exclude arbitrary hostile root, unreviewed aliases/devices or
future issuers on another installation. Writable migration, v25 Owner opening,
pending/final reconciliation and safe READY release remain separate work.
