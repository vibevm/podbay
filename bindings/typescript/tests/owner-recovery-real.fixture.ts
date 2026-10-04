/** Spawned only by owner-recovery-real.test.ts; this process is the manager's launcher parent. */
import { createHash, generateKeyPairSync } from "node:crypto";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, lstatSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createConnection, Socket } from "node:net";

import { AuthenticatedUnixSocketWireTransport } from "../src/authenticated-unix-socket.ts";
import { PodBayWireClient, makeRead } from "../src/generated.ts";
import { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } from "../src/owner-setup.ts";
import { recoverInstalledOwner } from "../src/owner-recovery.ts";
import { stageNextOwnerKeyCustody } from "../src/owner-key-custody.ts";

const [mode, root, managerBinary, podBinary] = process.argv.slice(2);
if (!mode || !root || !managerBinary || !podBinary || !["A", "A_KILL", "B", "B_FAIL", "B_NO_PUBLIC", "B_LOST_ACK", "C"].includes(mode)) throw new Error();
const state = join(root, "state");
const database = join(state, "podbay.sqlite");
const podDigest = createHash("sha256").update(readFileSync(podBinary)).digest("hex");
const manager = spawn(managerBinary, [
  "manager", "serve", "--state-dir", state, "--database", database,
  "--pod-dir", join(root, "pods"), "--pod-binary", podBinary,
  "--pod-sha256", podDigest, "--trusted-policy", join(state, "trusted-policy.json"),
], { stdio: ["ignore", "ignore", "pipe"] });
writeFileSync(join(root, `manager-${mode}.pid`), String(manager.pid), { mode: 0o600, flag: "wx" });
const diagnostics: Buffer[] = [];
manager.stderr.on("data", (chunk: Buffer) => diagnostics.push(chunk));

try {
  const socketName = mode === "A" || mode === "A_KILL" ? "owner-setup.sock" : "owner-recovery.sock";
  await waitSocket(join(state, socketName));
  if (mode === "A" || mode === "A_KILL") {
    const db = new DatabaseSync(database, { readOnly: true });
    const ownerEpoch = BigInt((db.prepare("SELECT value FROM metadata WHERE key='owner_epoch'").get() as { value: number }).value);
    const authorityRevision = BigInt((db.prepare("SELECT value FROM metadata WHERE key='authority_revision'").get() as { value: number }).value);
    const storeLineage = (db.prepare("SELECT lineage FROM store_identity WHERE singleton=1").get() as { lineage: string }).lineage;
    db.close();
    const receipt = await new InitialOwnerSetupClient({
      setupSocketPath: join(state, "owner-setup.sock"),
      managerSocketPath: join(state, "manager.sock"),
      ownerKeyCustodyPath: join(state, "owner-key-custody.json"),
      actorId: "actor.zap.recovery", scopeId: "scope.zap.recovery",
      credentialRef: "vault.zap.recovery", storeLineage,
      ownerEpoch, authorityRevision, ...selfProcess(),
      rightsDigest: INITIAL_OWNER_RIGHTS_DIGEST,
      validateHostEndpoint: (phase) => liveSocket(join(state, phase === "setup" ? "owner-setup.sock" : "manager.sock")),
    }).enroll();
    await waitSocket(join(state, "manager.sock"));
    writeFileSync(join(root, "receipt-A.json"), JSON.stringify({
      actorId: receipt.actorId, grantRef: receipt.grantRef, ownerEpoch: receipt.ownerEpoch.toString(),
    }), { mode: 0o600, flag: "wx" });
  } else if (mode === "B_FAIL" || mode === "B_NO_PUBLIC") {
    const db = new DatabaseSync(database, { readOnly: true });
    const ownerEpoch = BigInt((db.prepare("SELECT value FROM metadata WHERE key='owner_epoch'").get() as { value: number }).value);
    const authorityRevision = BigInt((db.prepare("SELECT value FROM metadata WHERE key='authority_revision'").get() as { value: number }).value);
    const storeLineage = (db.prepare("SELECT lineage FROM store_identity WHERE singleton=1").get() as { lineage: string }).lineage;
    db.close();
    const key = generateKeyPairSync("ed25519");
    const staged = stageNextOwnerKeyCustody(state, 2n, {
      actorId: "actor.zap.recovery", scopeId: "scope.zap.recovery",
      credentialRef: "vault.zap.recovery", storeLineage,
      ownerEpoch, authorityRevision, ...selfProcess(),
    }, key.privateKey);
    if (mode === "B_NO_PUBLIC")
      rmSync(join(dirname(staged.path), "owner-next-public.json"));
    let offeredOld = Buffer.alloc(32, 1);
    if (mode === "B_NO_PUBLIC") {
      const publicDb = new DatabaseSync(database, { readOnly: true });
      try {
        offeredOld = Buffer.from((publicDb
          .prepare("SELECT public_key FROM actor_verifiers WHERE actor_id='actor.zap.recovery'")
          .get() as { public_key: Uint8Array }).public_key);
      } finally { publicDb.close(); }
    }
    await new Promise<void>((resolve, reject) => {
      const socket = createConnection({ path: join(state, "owner-recovery.sock") });
      socket.once("error", reject);
      socket.once("connect", () => {
        const value = Buffer.concat([offeredOld, Buffer.from(staged.publicKey)]);
        const prefix = Buffer.alloc(4); prefix.writeUInt32BE(value.length, 0);
        socket.end(Buffer.concat([prefix, value]), resolve);
      });
    });
    await waitExit();
    if (manager.exitCode !== 2) throw new Error("failed recovery did not refuse proof");
    writeFileSync(join(root, `receipt-${mode}.json`), JSON.stringify({
      ownerEpoch: ownerEpoch.toString(), stagedPublic: Buffer.from(staged.publicKey).toString("hex"),
    }), { mode: 0o600, flag: "wx" });
  } else {
    let droppedAck = false;
    if (mode === "B_LOST_ACK") {
      const original = Socket.prototype.write;
      Object.defineProperty(Socket.prototype, "write", {
        configurable: true, writable: true,
        value: function (this: Socket, ...args: unknown[]) {
          const chunk = args[0];
          const bytes = typeof chunk === "string" ? Buffer.from(chunk) :
            chunk instanceof Uint8Array ? Buffer.from(chunk) : null;
          if (!droppedAck && bytes?.equals(Buffer.from([0, 0, 0, 3, 97, 99, 107]))) {
            droppedAck = true;
            this.destroy();
            const callback = args.find((arg) => typeof arg === "function");
            if (typeof callback === "function")
              queueMicrotask(() => (callback as (error: Error) => void)(new Error("synthetic lost ACK")));
            return true;
          }
          return Reflect.apply(original, this, args);
        },
      });
    }
    const recovered = await recoverInstalledOwner({
      stateDirectory: state, actorId: "actor.zap.recovery", scopeId: "scope.zap.recovery",
      credentialRef: "vault.zap.recovery",
      validateHostEndpoint: (phase) => liveSocket(join(state, phase === "recovery" ? "owner-recovery.sock" : "manager.sock")),
    });
    if (mode === "B_LOST_ACK" && (!droppedAck || !recovered.duplicate))
      throw new Error("lost ACK readback did not return the original receipt");
    await waitSocket(join(state, "manager.sock"));
    const client = new PodBayWireClient(new AuthenticatedUnixSocketWireTransport(recovered.channel));
    let forbidden = false;
    try {
      await client.read(makeRead({
        operation: "commands.get", requestId: "request.recovery.read",
        target: { kind: "scope", scopeId: "scope.zap.recovery" },
        body: { selector: { kind: "key", key: "key.absent.recovery" } },
      }));
    } catch (error) {
      forbidden = (error as { envelope?: { error?: { code?: string } } }).envelope?.error?.code === "forbidden";
    }
    if (!forbidden) throw new Error("authenticated missing-key read did not reach PodBay");
    writeFileSync(join(root, `receipt-${mode}.json`), JSON.stringify({
      grantRef: recovered.grantRef, ownerEpoch: recovered.ownerEpoch.toString(),
      generation: recovered.credentialGeneration.toString(), forbidden,
      duplicate: recovered.duplicate,
    }), { mode: 0o600, flag: "wx" });
  }
} catch (error) {
  writeFileSync(join(root, `failure-${mode}.txt`), `${String(error)}\n${Buffer.concat(diagnostics).toString("utf8")}`, { mode: 0o600 });
  throw error;
} finally {
  if (manager.exitCode === null && manager.signalCode === null)
    manager.kill(mode === "A_KILL" ? "SIGKILL" : "SIGTERM");
  await waitExit();
}

function liveSocket(path: string): boolean {
  return manager.exitCode === null && manager.signalCode === null &&
    (() => { try { return lstatSync(path).isSocket(); } catch { return false; } })();
}
async function waitSocket(path: string): Promise<void> {
  const until = performance.now() + 10_000;
  while (!liveSocket(path)) {
    if (manager.exitCode !== null || manager.signalCode !== null)
      throw new Error(`manager exited before socket: ${Buffer.concat(diagnostics).toString("utf8")}`);
    if (performance.now() >= until) throw new Error("manager socket timeout");
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
function selfProcess() {
  const stat = readFileSync("/proc/self/stat", "utf8");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
  const cgroup = readFileSync("/proc/self/cgroup", "utf8").trimEnd()
    .split("\n").find((line) => line.startsWith("0::"));
  if (!cgroup || !/^[1-9][0-9]*$/u.test(fields[19] ?? "")) throw new Error();
  return {
    osIdentity: `linux.uid.${String(process.getuid?.())}`,
    processIdentity: `linux.pid.${String(process.pid)}`,
    startIdentity: BigInt(fields[19]!), containmentIdentity: cgroup.slice(3),
  };
}
