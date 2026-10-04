/** Two separate Node launcher births around one surviving systemd V2 pod. */
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { AuthenticatedUnixSocketWireTransport } from "../src/authenticated-unix-socket.ts";
import { decimal, makeCommand, makeRead, PodBayWireClient } from "../src/generated.ts";
import { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } from "../src/owner-setup.ts";
import { recoverInstalledOwner } from "../src/owner-recovery.ts";

const [mode, root, managerBinary, podBinary] = process.argv.slice(2);
if (!mode || !root || !managerBinary || !podBinary || !["A", "B"].includes(mode)) throw new Error();
const state = join(root, "state"), database = join(state, "podbay.sqlite"), pods = join(root, "pods");
const podDigest = createHash("sha256").update(readFileSync(podBinary)).digest("hex");
const manager = spawn(managerBinary, [
  "manager", "serve", "--state-dir", state, "--database", database,
  "--pod-dir", pods, "--pod-binary", podBinary, "--pod-sha256", podDigest,
  "--trusted-policy", join(state, "trusted-policy.json"),
], { stdio: ["ignore", "ignore", "pipe"] });
writeFileSync(join(root, `manager-${mode}.pid`), String(manager.pid), { mode: 0o600, flag: "wx" });
const diagnostics: Buffer[] = [];
manager.stderr.on("data", (chunk: Buffer) => diagnostics.push(chunk));

try {
  const managerSocket = join(state, "manager.sock");
  if (mode === "A") {
    await waitSocket(join(state, "owner-setup.sock"));
    const db = new DatabaseSync(database, { readOnly: true });
    const lineage = (db.prepare("SELECT lineage FROM store_identity WHERE singleton=1").get() as { lineage: string }).lineage;
    const ownerEpoch = BigInt((db.prepare("SELECT value FROM metadata WHERE key='owner_epoch'").get() as { value: number }).value);
    const revision = BigInt((db.prepare("SELECT value FROM metadata WHERE key='authority_revision'").get() as { value: number }).value);
    db.close();
    const owner = new InitialOwnerSetupClient({
      setupSocketPath: join(state, "owner-setup.sock"), managerSocketPath: managerSocket,
      ownerKeyCustodyPath: join(state, "owner-key-custody.json"),
      actorId: "actor.zap.auto-rebind", scopeId: "scope.zap.auto-rebind",
      credentialRef: "vault.zap.auto-rebind", storeLineage: lineage,
      ownerEpoch, authorityRevision: revision, ...selfProcess(),
      rightsDigest: INITIAL_OWNER_RIGHTS_DIGEST,
      validateHostEndpoint: (phase) => liveSocket(join(state, phase === "setup" ? "owner-setup.sock" : "manager.sock")),
    });
    const enrolled = await owner.enroll();
    await waitSocket(managerSocket);
    const client = new PodBayWireClient(new AuthenticatedUnixSocketWireTransport({
      ...owner.authenticatedChannel(), exchangeTimeoutMs: 120_000,
    }));
    const launch = await makeCommand({
      operation: "launch", requestId: "request.auto-rebind.launch", key: "key.auto-rebind.launch",
      target: { kind: "scope", scopeId: "scope.zap.auto-rebind" },
      guard: { managerEpoch: decimal(ownerEpoch.toString()), podEpoch: decimal("1") },
      body: {
        session: { kind: "new" }, role: "coordinator",
        work: { kind: "service", resultContractRef: "result.none" },
        profileRef: "profile.codex.auto-rebind",
        selection: { modelId: "gpt-6-sol", reasoningEffort: "medium", fallback: "none" },
        workspace: { scopeId: "scope.zap.auto-rebind", relativeCwd: ".", basisRef: "basis.auto-rebind", access: "read_write" },
        toolBundleRefs: [], authority: { grantRef: enrolled.grantRef },
        limits: { wallSeconds: decimal("60"), maxChildren: decimal("2") },
      },
    });
    const launchReceipt = await client.command(launch);
    assert.equal(launchReceipt.state, "host_accepted");
    const launchValue = record(launchReceipt.value);
    assert.equal(launchValue["launchStage"], "host_accepted");
    const proof = await waitPodProof(pods);
    await waitNativeBootstrap(proof.codexHome);
    writeFileSync(join(root, "receipt-A.json"), JSON.stringify({
      podId: launchValue["podId"], sessionId: launchValue["sessionId"], ...proof,
    }), { mode: 0o600, flag: "wx" });
  } else {
    await waitSocket(join(state, "owner-recovery.sock"));
    const recovered = await recoverInstalledOwner({
      stateDirectory: state, actorId: "actor.zap.auto-rebind", scopeId: "scope.zap.auto-rebind",
      credentialRef: "vault.zap.auto-rebind",
      validateHostEndpoint: (phase) => liveSocket(join(state, phase === "recovery" ? "owner-recovery.sock" : "manager.sock")),
    });
    await waitSocket(managerSocket);
    const prior = JSON.parse(readFileSync(join(root, "receipt-A.json"), "utf8")) as Record<string, unknown>;
    const proof = await waitPodProof(pods);
    assert.equal(proof.supervisorPid, prior["supervisorPid"]);
    assert.equal(proof.supervisorBirth, prior["supervisorBirth"]);
    assert.equal(proof.childPid, prior["childPid"]);
    assert.equal(proof.childBirth, prior["childBirth"]);
    const client = new PodBayWireClient(new AuthenticatedUnixSocketWireTransport({
      ...recovered.channel, exchangeTimeoutMs: 120_000,
    }));
    const launch = record(await client.read(makeRead({
      operation: "commands.get", requestId: "request.auto-rebind.launch.get",
      target: { kind: "scope", scopeId: "scope.zap.auto-rebind" },
      body: { selector: { kind: "key", key: "key.auto-rebind.launch" } },
    })));
    const bootstrap = record(launch["bootstrapGuard"]);
    assert.equal(bootstrap["available"], true);
    assert.equal(bootstrap["sessionId"], prior["sessionId"]);
    const guard = record(bootstrap["guard"]);
    assert.equal(guard["managerEpoch"], "2");
    assert.equal(guard["writerEpoch"], "2");
    const send = await makeCommand({
      operation: "session.send", requestId: "request.auto-rebind.send.one", key: "key.auto-rebind.send",
      target: { kind: "session", sessionId: string(bootstrap["sessionId"]) },
      guard: {
        managerEpoch: decimal(string(guard["managerEpoch"])),
        podEpoch: decimal(string(guard["podEpoch"])),
        resourceEpoch: decimal(string(guard["resourceEpoch"])),
        writerEpoch: decimal(string(guard["writerEpoch"])),
        targetRevision: decimal(string(guard["targetRevision"])),
      },
      body: { content: [{ kind: "text", text: "One turn after manager rebind." }], policy: { kind: "when_idle" } },
    });
    const submitted = await client.command(send);
    assert.equal(submitted.state, "uncertain");
    assert.equal(record(record(submitted.value)["portObservation"])["kind"], "pod_accepted");
    const readSend = (requestId: string) => client.read(makeRead({
      operation: "commands.get", requestId,
      target: { kind: "scope", scopeId: "scope.zap.auto-rebind" },
      body: { selector: { kind: "key", key: "key.auto-rebind.send" } },
    }));
    const native = record(record(await readSend("request.auto-rebind.send.get"))["nativeObservation"]);
    const duplicate = await client.command(await makeCommand({
      operation: "session.send", requestId: "request.auto-rebind.send.retry", key: send.key,
      target: send.target, guard: send.guard, body: send.body,
    }));
    assert.equal(duplicate.commandId, submitted.commandId);
    assert.equal(record(duplicate.value)["duplicate"], true);
    assert.equal(record(duplicate.value)["portCalled"], false);
    writeFileSync(join(root, "receipt-B.json"), JSON.stringify({
      ...proof, nativeTurnId: native["nativeTurnId"], duplicate: true,
    }), { mode: 0o600, flag: "wx" });
  }
} catch (error) {
  writeFileSync(join(root, `failure-${mode}.txt`), `${String(error)}\n${Buffer.concat(diagnostics).toString("utf8")}`, { mode: 0o600 });
  throw error;
} finally {
  if (manager.exitCode === null && manager.signalCode === null)
    manager.kill(mode === "A" ? "SIGKILL" : "SIGTERM");
  await waitExit();
}

function selfProcess() {
  const stat = readFileSync("/proc/self/stat", "utf8");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
  const cgroup = readFileSync("/proc/self/cgroup", "utf8").trimEnd()
    .split("\n").find((line) => line.startsWith("0::"));
  if (!cgroup || !/^[1-9][0-9]*$/u.test(fields[19] ?? "")) throw new Error();
  return { osIdentity: `linux.uid.${String(process.getuid?.())}`,
    processIdentity: `linux.pid.${String(process.pid)}`,
    startIdentity: BigInt(fields[19]!), containmentIdentity: cgroup.slice(3) };
}
function liveSocket(path: string): boolean {
  return manager.exitCode === null && manager.signalCode === null &&
    (() => { try { const item = lstatSync(path); return item.isSocket() && (item.mode & 0o7777) === 0o600; }
      catch { return false; } })();
}
async function waitSocket(path: string): Promise<void> {
  const until = performance.now() + 10_000;
  while (!liveSocket(path)) {
    if (manager.exitCode !== null || manager.signalCode !== null)
      throw new Error(`manager exited before socket: ${Buffer.concat(diagnostics).toString("utf8")}`);
    if (performance.now() >= until) throw new Error(`manager socket timeout: ${path}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
async function waitExit(): Promise<void> {
  if (manager.exitCode !== null || manager.signalCode !== null) return;
  const until = performance.now() + 5_000;
  while (manager.exitCode === null && manager.signalCode === null) {
    if (performance.now() >= until) { manager.kill("SIGKILL"); break; }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
async function waitPodProof(pods: string): Promise<{
  supervisorPid: number; supervisorBirth: string; childPid: number; childBirth: string; codexHome: string;
}> {
  const until = performance.now() + 10_000;
  for (;;) {
    const manifest = readdirSync(pods).find((name) => /^[0-9a-f]{32}\.json$/u.test(name));
    if (manifest) {
      const unit = `podbay-pod-${basename(manifest, ".json")}.service`;
      const raw = execFileSync("systemctl", ["--user", "show", "--property=MainPID", "--value", unit],
        { encoding: "utf8", timeout: 5_000 }).trim();
      const supervisorPid = Number(raw);
      if (Number.isSafeInteger(supervisorPid) && supervisorPid > 0) {
        const children = readFileSync(`/proc/${supervisorPid}/task/${supervisorPid}/children`, "utf8")
          .trim().split(/\s+/u).filter(Boolean).map(Number);
        if (children.length === 1 && children[0]! > 0) {
          const childPid = children[0]!;
          const value = readFileSync(`/proc/${childPid}/environ`, "utf8").split("\0")
            .find((entry) => entry.startsWith("CODEX_HOME="));
          if (!value) throw new Error("Codex child lacks private home");
          return { supervisorPid, supervisorBirth: birth(supervisorPid), childPid,
            childBirth: birth(childPid), codexHome: value.slice("CODEX_HOME=".length) };
        }
      }
    }
    if (performance.now() >= until) throw new Error("pod process proof timeout");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
async function waitNativeBootstrap(codexHome: string): Promise<void> {
  const until = performance.now() + 10_000;
  for (;;) {
    try {
      const methods = readFileSync(join(codexHome, "frames.log"), "utf8").trimEnd()
        .split("\n").map((line) => (JSON.parse(line) as { method: string }).method);
      if (methods.length >= 2 && methods.slice(0, 2).join(",") ===
        "initialize,initialized") return;
    } catch { /* native startup has not written all frames yet */ }
    if (performance.now() >= until) throw new Error("native child did not initialize");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
function birth(pid: number): string {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const value = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u)[19];
  if (!value || !/^[1-9][0-9]*$/u.test(value)) throw new Error("pod process birth unavailable");
  return value;
}
function record(value: unknown): Record<string, unknown> {
  assert.equal(typeof value, "object"); assert.ok(value !== null && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function string(value: unknown): string { assert.equal(typeof value, "string"); return value as string; }
