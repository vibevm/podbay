import assert from "node:assert/strict";
import { spawn, execFile, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { promisify } from "node:util";

import { AuthenticatedUnixSocketWireTransport } from "../src/authenticated-unix-socket.ts";
import { decimal, makeCommand, makeRead, PodBayWireClient, type NativeEventCursor } from "../src/generated.ts";
import { INITIAL_OWNER_RIGHTS_DIGEST, InitialOwnerSetupClient } from "../src/owner-setup.ts";

const exec = promisify(execFile);

test("Node owner launches one fake Codex pod, bootstraps once and reads its native journal", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "podbay-ts-fake-e2e-"));
  await chmod(root, 0o700);
  const state = join(root, "state");
  const pods = join(root, "pods");
  const workspace = join(root, "workspace");
  const credentials = join(root, "credentials");
  for (const path of [state, pods, workspace, credentials]) {
    await mkdir(path, { mode: 0o700 });
    await chmod(path, 0o700);
  }
  const podBinary = process.env["PODBAY_TEST_POD_BINARY"]!;
  const managerBinary = process.env["PODBAY_TEST_MANAGER_BINARY"]!;
  assert.equal((await stat(podBinary)).isFile(), true);
  assert.equal((await stat(managerBinary)).isFile(), true);
  const podDigest = createHash("sha256").update(await readFile(podBinary)).digest("hex");
  const authSource = join(credentials, "dummy-auth.json");
  await writeFile(authSource, "dummy fixture credential, no provider account\n", { mode: 0o600 });
  await chmod(authSource, 0o600);
  const fakeCodex = join(root, "fake-codex.sh");
  await writeFile(fakeCodex, fakeCodexScript(), { mode: 0o700 });
  await chmod(fakeCodex, 0o700);
  const codexDigest = createHash("sha256").update(await readFile(fakeCodex)).digest("hex");
  const policyPath = join(state, "trusted-policy.json");
  await writeFile(policyPath, JSON.stringify({
    schema: "podbay.trusted-manager-policy/1",
    actorId: "actor.zap.fake-e2e", scopeId: "scope.zap.fake-e2e",
    credentialRef: "vault.zap.fake-e2e", credentialSource: authSource,
    profileRef: "profile.codex.fake-e2e", profileGeneration: 1,
    executable: fakeCodex, executableSha256: codexDigest,
    workspaceRoot: workspace, workspaceBasisRef: "basis.fake-e2e",
    hostId: "host.fake-e2e", driverRef: "driver.codex.fake-e2e",
    protocolRef: "protocol.codex.fake-e2e", modelId: "gpt-6-sol",
    reasoningEffort: "medium", approvalPolicy: "never", sandbox: "danger_full_access",
    wallSeconds: 60, maxChildren: 2, resultContractRef: "result.none",
    launchDeadlineSeconds: 30, sendDeadlineSeconds: 30, writerLeaseSeconds: 120,
  }), { mode: 0o600 });
  await chmod(policyPath, 0o600);

  const database = join(state, "podbay.sqlite");
  const manager = spawn(managerBinary, [
    "manager", "serve", "--state-dir", state, "--database", database,
    "--pod-dir", pods, "--pod-binary", podBinary, "--pod-sha256", podDigest,
    "--trusted-policy", policyPath,
  ], { stdio: ["ignore", "ignore", "pipe"] });
  t.after(async () => {
    await stopPodUnits(pods);
    if (manager.exitCode === null && manager.signalCode === null) {
      manager.kill("SIGTERM");
      await waitExit(manager);
    }
    await rm(root, { recursive: true, force: true });
  });

  const setupSocket = join(state, "owner-setup.sock");
  const managerSocket = join(state, "manager.sock");
  await waitSocket(setupSocket, manager);
  const db = new DatabaseSync(database, { readOnly: true });
  const lineage = (db.prepare("SELECT lineage FROM store_identity WHERE singleton=1").get() as { lineage: string }).lineage;
  const ownerEpoch = BigInt((db.prepare("SELECT value FROM metadata WHERE key='owner_epoch'").get() as { value: number }).value);
  const authorityRevision = BigInt((db.prepare("SELECT value FROM metadata WHERE key='authority_revision'").get() as { value: number }).value);
  db.close();
  const ownerProcess = selfProcess();
  const custodyPath = join(state, "owner-key-custody.json");
  const owner = new InitialOwnerSetupClient({
    setupSocketPath: setupSocket, managerSocketPath: managerSocket,
    actorId: "actor.zap.fake-e2e", scopeId: "scope.zap.fake-e2e",
    credentialRef: "vault.zap.fake-e2e", storeLineage: lineage,
    ownerEpoch, authorityRevision, ...ownerProcess,
    ownerKeyCustodyPath: custodyPath,
    rightsDigest: INITIAL_OWNER_RIGHTS_DIGEST,
    validateHostEndpoint: async (phase) => {
      if (manager.exitCode !== null || manager.signalCode !== null) return false;
      const path = phase === "setup" ? setupSocket : managerSocket;
      const metadata = await stat(path).catch(() => undefined);
      return metadata?.isSocket() === true && metadata.uid === process.getuid?.() &&
        (metadata.mode & 0o777) === 0o600;
    },
  });
  const enrolled = await owner.enroll();
  assert.equal(enrolled.duplicate, false);
  assert.equal(enrolled.grantRef, "grant.1");
  await waitSocket(managerSocket, manager);
  const channel = owner.authenticatedChannel();
  const client = new PodBayWireClient(new AuthenticatedUnixSocketWireTransport({
    ...channel, exchangeTimeoutMs: 120_000,
  }));

  const launch = await makeCommand({
    operation: "launch", requestId: "request.fake-e2e.launch", key: "key.fake-e2e.launch",
    target: { kind: "scope", scopeId: "scope.zap.fake-e2e" },
    guard: { managerEpoch: decimal(ownerEpoch.toString()), podEpoch: decimal("1") },
    body: {
      session: { kind: "new" }, role: "coordinator",
      work: { kind: "service", resultContractRef: "result.none" },
      profileRef: "profile.codex.fake-e2e",
      selection: { modelId: "gpt-6-sol", reasoningEffort: "medium", fallback: "none" },
      workspace: { scopeId: "scope.zap.fake-e2e", relativeCwd: ".", basisRef: "basis.fake-e2e", access: "read_write" },
      toolBundleRefs: [], authority: { grantRef: enrolled.grantRef },
      limits: { wallSeconds: decimal("60"), maxChildren: decimal("2") },
    },
  });
  const launchReceipt = await client.command(launch);
  assert.equal(launchReceipt.state, "host_accepted");
  const launchValue = record(launchReceipt.value);
  assert.equal(launchValue["launchStage"], "host_accepted");
  assert.equal(launchValue["portCalled"], true);
  const bootstrap = record(launchValue["bootstrapGuard"]);
  assert.equal(bootstrap["available"], true);
  const guard = record(bootstrap["guard"]);
  assert.equal(bootstrap["scopeId"], "scope.zap.fake-e2e");
  assert.equal(bootstrap["sessionId"], launchValue["sessionId"]);
  assert.equal(bootstrap["runId"], launchValue["runId"]);
  assert.equal(bootstrap["attemptId"], launchValue["attemptId"]);
  assert.equal(bootstrap["podId"], launchValue["podId"]);
  const resources = launchValue["resources"];
  assert.ok(Array.isArray(resources) && resources.length === 1);
  assert.equal(bootstrap["resourceId"], record(resources[0])["resourceId"]);
  assert.equal(guard["resourceEpoch"], record(resources[0])["epoch"]);
  const readLaunch = (requestId: string) => client.read(makeRead({
    operation: "commands.get", requestId,
    target: { kind: "scope", scopeId: "scope.zap.fake-e2e" },
    body: { selector: { kind: "key", key: "key.fake-e2e.launch" } },
  }));
  const beforeSend = record(await readLaunch("request.fake-e2e.bootstrap.before-send"));
  assert.equal(record(beforeSend["currentLaterSendGuard"])["available"], true);
  assert.equal(record(beforeSend["currentBootstrapCompletion"])["available"], false,
    "a current writer lease is not bootstrap completion");

  const send = await makeCommand({
    operation: "session.send", requestId: "request.fake-e2e.send.one",
    key: "key.fake-e2e.send",
    target: { kind: "session", sessionId: string(bootstrap["sessionId"]) },
    guard: {
      managerEpoch: decimal(string(guard["managerEpoch"])),
      podEpoch: decimal(string(guard["podEpoch"])),
      resourceEpoch: decimal(string(guard["resourceEpoch"])),
      writerEpoch: decimal(string(guard["writerEpoch"])),
      targetRevision: decimal(string(guard["targetRevision"])),
    },
    body: { content: [{ kind: "text", text: "Fake bootstrap only; do not use a model." }], policy: { kind: "when_idle" } },
  });
  const sendReceipt = await client.command(send);
  assert.equal(sendReceipt.state, "uncertain");
  const sendValue = record(sendReceipt.value);
  assert.equal(sendValue["portCalled"], true);
  assert.equal(record(sendValue["portObservation"])["kind"], "pod_accepted");

  const readSend = (requestId: string) => client.read(makeRead({
    operation: "commands.get", requestId,
    target: { kind: "scope", scopeId: "scope.zap.fake-e2e" },
    body: { selector: { kind: "key", key: "key.fake-e2e.send" } },
  }));
  const firstRead = record(await readSend("request.fake-e2e.get.one"));
  assert.equal(record(firstRead["receipt"])["commandId"], sendReceipt.commandId);
  const firstNative = record(firstRead["nativeObservation"]);
  assert.equal(firstNative["source"], "pod_journal");
  assert.equal(firstNative["stage"], "submitted");
  assert.equal(firstNative["nativeTurnId"], "turn.fixture");
  const pending = record(await readLaunch("request.fake-e2e.bootstrap.submitted"));
  assert.equal(record(pending["currentLaterSendGuard"])["available"], true);
  assert.equal(record(pending["currentBootstrapCompletion"])["available"], false);

  const retry = await makeCommand({
    operation: "session.send", requestId: "request.fake-e2e.send.retry",
    key: send.key, target: send.target, guard: send.guard, body: send.body,
  });
  const duplicate = await client.command(retry);
  assert.equal(duplicate.commandId, sendReceipt.commandId);
  const duplicateValue = record(duplicate.value);
  assert.equal(duplicateValue["duplicate"], true);
  assert.equal(duplicateValue["portCalled"], false);
  const secondNative = record(record(await readSend("request.fake-e2e.get.two"))["nativeObservation"]);
  assert.equal(secondNative["nativeTurnId"], firstNative["nativeTurnId"]);
  assert.equal(secondNative["stage"], firstNative["stage"]);

  const nativeRead = (requestId: string, after?: NativeEventCursor) => client.read(makeRead({
    operation: "native.events.read", requestId,
    target: { kind: "scope", scopeId: "scope.zap.fake-e2e" },
    body: {
      sessionId: string(launchValue["sessionId"]),
      resourceId: string(record(resources[0])["resourceId"]),
      limit: decimal("2"),
      ...(after === undefined ? {} : { after }),
    },
  }));
  const nativeDeadline = performance.now() + 5_000;
  let nativePage: Record<string, unknown>;
  for (;;) {
    nativePage = record(await nativeRead("request.fake-e2e.native.initial"));
    const events = nativePage["events"];
    assert.ok(Array.isArray(events));
    if (events.length > 0) break;
    assert.ok(performance.now() < nativeDeadline, "fake native output did not reach manager read");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(nativePage["kind"], "native_events_page");
  const firstEvent = record((nativePage["events"] as unknown[])[0]);
  assert.equal(firstEvent["kind"], "output");
  assert.equal(firstEvent["sourceSequence"], "1");
  const rawJsonl = string(firstEvent["rawJsonl"]);
  assert.match(rawJsonl, /private owner-only output/u);
  assert.equal(createHash("sha256").update(Buffer.from(rawJsonl, "utf8")).digest("hex"),
    firstEvent["contentDigest"]);
  const cursor = record(nativePage["nextCursor"]);
  assert.equal(cursor["sourceSequence"], "1");
  const source = record(cursor["identity"]);
  assert.equal(source["storeLineage"], lineage);
  assert.equal(source["scopeId"], "scope.zap.fake-e2e");
  assert.equal(source["sessionId"], launchValue["sessionId"]);
  assert.equal(source["runId"], launchValue["runId"]);
  assert.equal(source["attemptId"], launchValue["attemptId"]);
  assert.equal(source["podId"], launchValue["podId"]);
  assert.equal(source["resourceId"], record(resources[0])["resourceId"]);
  assert.equal(source["resourceEpoch"], record(resources[0])["epoch"]);
  assert.equal(record(nativePage["snapshot"])["fidelity"], "exact");
  assert.equal(nativePage["gap"], null);
  const replay = record(await nativeRead("request.fake-e2e.native.replay"));
  assert.deepEqual(replay, nativePage, "same initial selector must replay durable exact output");
  const evidenceDb = new DatabaseSync(database, { readOnly: true });
  const evidenceCount = evidenceDb.prepare(
    "SELECT COUNT(*) AS count FROM codex_native_evidence WHERE resource_id=?",
  ).get(string(record(resources[0])["resourceId"])) as { count: number };
  evidenceDb.close();
  assert.equal(evidenceCount.count, 1, "replay must not insert a second native event");
  const advanced = record(await nativeRead("request.fake-e2e.native.after", cursor as unknown as NativeEventCursor));
  assert.deepEqual(advanced["events"], []);
  assert.equal(record(advanced["nextCursor"])["sourceSequence"], "1");

  // A separate same-UID process can read this fixture's private dummy key,
  // but its kernel PID/birth differ from the enrolled owner. The auth prelude
  // must refuse it before any native output can be returned.
  const siblingExpected = {
    actorId: "actor.zap.fake-e2e", storeLineage: lineage,
    scopeId: "scope.zap.fake-e2e", credentialGeneration: "1",
    osIdentity: ownerProcess.osIdentity, processIdentity: ownerProcess.processIdentity,
    startIdentity: ownerProcess.startIdentity.toString(),
    containmentIdentity: ownerProcess.containmentIdentity,
    origin: { kind: "owner-cli" },
  };
  const siblingScript = `
    import { readFileSync } from "node:fs";
    import { createPrivateKey, sign } from "node:crypto";
    const { AuthenticatedUnixSocketWireTransport } = await import(process.argv[1]);
    const { PodBayWireClient, makeRead } = await import(process.argv[2]);
    const custody = JSON.parse(readFileSync(process.argv[3], "utf8"));
    const key = createPrivateKey({key: Buffer.from(custody.privateKeyPkcs8,"base64"),format:"der",type:"pkcs8"});
    const expected = JSON.parse(process.argv[4]);
    expected.credentialGeneration = BigInt(expected.credentialGeneration);
    expected.startIdentity = BigInt(expected.startIdentity);
    const channel = new AuthenticatedUnixSocketWireTransport({
      socketPath: process.argv[5], expected,
      validateAndSign: (challenge) => new Uint8Array(sign(null, Buffer.from(challenge.bytes), key)),
      handshakeTimeoutMs: 3000, exchangeTimeoutMs: 3000,
    });
    const client = new PodBayWireClient(channel);
    const request = makeRead(JSON.parse(process.argv[6]));
    try {
      const page = await client.read(request);
      if (JSON.stringify(page).includes("private owner-only output")) process.exit(3);
      process.exit(2);
    } catch (error) { process.stdout.write("REFUSED:" + String(error?.code ?? error?.name) + "\\n"); }
  `;
  const siblingRequest = {
    operation: "native.events.read", requestId: "request.fake-e2e.native.sibling",
    target: { kind: "scope", scopeId: "scope.zap.fake-e2e" },
    body: { sessionId: string(launchValue["sessionId"]),
      resourceId: string(record(resources[0])["resourceId"]), limit: decimal("2") },
  };
  const sibling = await exec(process.execPath, ["--input-type=module", "-e", siblingScript,
    new URL("../src/authenticated-unix-socket.ts", import.meta.url).href,
    new URL("../src/generated.ts", import.meta.url).href,
    custodyPath, JSON.stringify(siblingExpected), managerSocket, JSON.stringify(siblingRequest)],
    { timeout: 5_000 });
  assert.equal(sibling.stdout, "REFUSED:auth_lost\n");
  assert.equal(manager.exitCode, null, "manager must remain live after sibling refusal");

  const manifests = (await readdir(pods)).filter((name) => /^[0-9a-f]{32}\.json$/u.test(name));
  assert.equal(manifests.length, 1, "exactly one disposable Pod manifest");
  const frames = await readFile(join(pods, `${manifests[0]!.slice(0, -5)}.private`,
    "home", "codex", "frames.log"), "utf8");
  const methods = frames.trimEnd().split("\n").map((line) => (JSON.parse(line) as { method: string }).method);
  assert.deepEqual(methods, ["initialize", "initialized", "thread/start", "thread/read", "turn/start"]);
  const codexHome = join(pods, `${manifests[0]!.slice(0, -5)}.private`, "home", "codex");
  await writeFile(join(codexHome, "finish-bootstrap"), "go\n");
  const idleRequestDeadline = performance.now() + 5_000;
  while (!(await stat(join(codexHome, "completion-read-seen")).then(() => true).catch(() => false))) {
    assert.ok(performance.now() < idleRequestDeadline, "fake completion read was not requested");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  const awaitingIdle = record(await readLaunch("request.fake-e2e.bootstrap.pending-idle"));
  assert.equal(record(awaitingIdle["currentLaterSendGuard"])["available"], true);
  assert.equal(record(awaitingIdle["currentBootstrapCompletion"])["available"], false,
    "turn/completed without a fresh idle reply is not completion");
  await writeFile(join(codexHome, "release-idle"), "go\n");
  const completedDeadline = performance.now() + 5_000;
  let completed: Record<string, unknown>;
  for (;;) {
    completed = record(await readLaunch("request.fake-e2e.bootstrap.completed"));
    if (record(completed["currentBootstrapCompletion"])["available"] === true) break;
    assert.ok(performance.now() < completedDeadline, "fsynced bootstrap completion was not projected");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  const proof = record(completed["currentBootstrapCompletion"]);
  assert.equal(proof["source"], "pod_journal");
  assert.equal(proof["bootstrapCommandId"], sendReceipt.commandId);
  assert.equal(proof["requestDigest"], record(firstRead["receipt"])["requestDigest"]);
  assert.equal(proof["scopeId"], "scope.zap.fake-e2e");
  assert.equal(proof["sessionId"], launchValue["sessionId"]);
  assert.equal(proof["runId"], launchValue["runId"]);
  assert.equal(proof["attemptId"], launchValue["attemptId"]);
  assert.equal(proof["podId"], launchValue["podId"]);
  assert.equal(proof["resourceId"], record(resources[0])["resourceId"]);
  assert.equal(proof["podEpoch"], guard["podEpoch"]);
  assert.equal(proof["resourceEpoch"], guard["resourceEpoch"]);
  assert.equal(proof["writerEpoch"], guard["writerEpoch"]);
  assert.equal(proof["nativeThreadId"], firstNative["nativeThreadId"]);
  assert.equal(proof["nativeSessionId"], firstNative["nativeSessionId"]);
  assert.equal(proof["nativeTurnId"], firstNative["nativeTurnId"]);
  const repeatedLaunch = record(await readLaunch("request.fake-e2e.bootstrap.replay"));
  assert.deepEqual(record(repeatedLaunch["currentBootstrapCompletion"]), proof,
    "read-only completion projection must be stable");
});

function fakeCodexScript(): string {
  return `#!/bin/sh
set -eu
[ "$1" = app-server ]
[ "$2" = --listen ]
[ "$3" = stdio:// ]
[ -r "$CODEX_HOME/auth.json" ]
read -r initialize
printf '%s\\n' "$initialize" > "$CODEX_HOME/frames.log"
printf '{"id":1,"result":{"codexHome":"%s","platformFamily":"unix","platformOs":"linux","userAgent":"fixture"}}\\n' "$CODEX_HOME"
read -r initialized
printf '%s\\n' "$initialized" >> "$CODEX_HOME/frames.log"
read -r start
printf '%s\\n' "$start" >> "$CODEX_HOME/frames.log"
printf '{"id":2,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]},"model":"gpt-6-sol","reasoningEffort":"medium","approvalPolicy":"never","sandbox":{"type":"dangerFullAccess"},"cwd":"%s"}}\\n' "$(pwd)" "$(pwd)"
read -r inspect
printf '%s\\n' "$inspect" >> "$CODEX_HOME/frames.log"
printf '{"id":3,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\\n' "$(pwd)"
read -r turn
printf '%s\\n' "$turn" >> "$CODEX_HOME/frames.log"
printf '{"id":4,"result":{"turn":{"id":"turn.fixture","status":"inProgress"}}}\\n'
printf '{"method":"item/agentMessage/delta","params":{"threadId":"thread.fixture","delta":"private owner-only output"}}\\n'
while [ ! -f "$CODEX_HOME/finish-bootstrap" ]; do sleep 0.05; done
printf '{"method":"turn/completed","params":{"threadId":"thread.fixture","turn":{"id":"turn.fixture","status":"completed","items":[]}}}\\n'
printf '{"method":"thread/status/changed","params":{"threadId":"thread.fixture","status":{"type":"idle"}}}\\n'
read -r completion_read
printf '%s\\n' "$completion_read" >> "$CODEX_HOME/frames.log"
: > "$CODEX_HOME/completion-read-seen"
while [ ! -f "$CODEX_HOME/release-idle" ]; do sleep 0.05; done
printf '{"id":5,"result":{"thread":{"id":"thread.fixture","sessionId":"native.session.fixture","cwd":"%s","status":{"type":"idle"},"turns":[]}}}\\n' "$(pwd)"
sleep 30
`;
}

function selfProcess() {
  const statLine = readFileSync("/proc/self/stat", "utf8");
  const fields = statLine.slice(statLine.lastIndexOf(")") + 2).trim().split(/\s+/u);
  const cgroup = readFileSync("/proc/self/cgroup", "utf8")
    .trimEnd().split("\n").find((line) => line.startsWith("0::"));
  assert.ok(cgroup);
  return {
    osIdentity: `linux.uid.${process.getuid!()}`,
    processIdentity: `linux.pid.${process.pid}`,
    startIdentity: BigInt(fields[19]!),
    containmentIdentity: cgroup.slice(3),
  };
}
function record(value: unknown): Record<string, unknown> {
  assert.equal(typeof value, "object");
  assert.ok(value !== null && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function string(value: unknown): string {
  assert.equal(typeof value, "string");
  return value as string;
}
async function waitSocket(path: string, child: ChildProcess): Promise<void> {
  const until = performance.now() + 10_000;
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null)
      throw new Error("PodBay manager exited before socket readiness");
    const ready = await stat(path).then((item) => item.isSocket()).catch(() => false);
    if (ready) return;
    if (performance.now() >= until) throw new Error("PodBay socket did not appear");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
async function waitExit(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => child.once("exit", () => resolve()));
}
async function stopPodUnits(pods: string): Promise<void> {
  const entries = await readdir(pods).catch(() => []);
  for (const name of entries) {
    if (!/^[0-9a-f]{32}\.json$/u.test(name)) continue;
    const unit = `podbay-pod-${basename(name, ".json")}.service`;
    await exec("systemctl", ["--user", "stop", unit], { timeout: 10_000 }).catch(() => undefined);
    const until = performance.now() + 5_000;
    for (;;) {
      const result = await exec("systemctl", ["--user", "show", "--property=LoadState", "--value", unit],
        { timeout: 5_000 }).catch(() => ({ stdout: "not-found" }));
      if (result.stdout.trim() === "not-found") break;
      if (performance.now() >= until) throw new Error("disposable PodBay unit remained loaded");
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
}
