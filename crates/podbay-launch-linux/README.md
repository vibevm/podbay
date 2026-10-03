# podbay-launch-linux

Linux HostDispatchPort adapter for the explicit synthetic Worker/Task,
single Auxiliary process.exec fixture. It accepts only host-created
ResolvedNativeLaunch capabilities; unbound launch and generic dispatch refuse.

Trusted configuration pins a canonical pod supervisor executable by SHA-256
and file identity, plus an owned private launch directory. The resolved cwd
must equal that directory. Preflight checks current manager identity and v10
credential, resource inputs, and the exact committed outbox payload and claim.
Bootstrap values come from the resolved capability, never the launch actor.

The supported fixture profile is podbay.fixture.process.exec, with no model,
effort, tools, environment or credential references; arguments are ["60"],
wall time is 60 seconds, and max_children is zero. It is not a Codex/provider
adapter. HostAccepted proves pod status attestation, not provider readiness.

Preflight failure refuses before the pod runner. After entering the pod runner,
all errors conservatively remain uncertain and are never retried. A stable
receipt identifies the committed descriptor digest. Duplicate host requests
return their original receipt without invoking this port again.

Pathname checks are cooperative local checks: they do not pin the loader or
libraries or prevent later same-UID replacement. No hostile same-UID isolation
is claimed.

Focused tests: cargo test -p podbay-launch-linux --lib
The ignored native_disposable_sleep_fixture test additionally requires a user
systemd session and PODBAY_TEST_POD_BINARY naming the built podbay-pod binary.
It runs a disposable sleep process and cleans up only its own transient unit.
