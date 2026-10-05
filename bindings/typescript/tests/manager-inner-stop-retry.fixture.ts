/** A fresh owner process resumes one already claimed/settled Pod stop. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { AuthenticatedUnixSocketWireTransport } from "../src/authenticated-unix-socket.ts";
import { makeCommand, PodBayWireClient } from "../src/generated.ts";
import { recoverInstalledOwner } from "../src/owner-recovery.ts";

const [root, managerBinary, podBinary] = process.argv.slice(2);
if (!root || !managerBinary || !podBinary) throw new Error("fixture arguments missing");
const state = join(root, "state");
const socket = join(state, "manager.sock");
const podDigest = createHash("sha256").update(readFileSync(podBinary)).digest("hex");
const manager = spawn(managerBinary, [
  "manager", "serve", "--state-dir", state, "--database", join(state, "podbay.sqlite"),
  "--pod-dir", join(root, "pods"), "--pod-binary", podBinary, "--pod-sha256", podDigest,
  "--trusted-policy", join(state, "trusted-policy.json"),
], { stdio: ["ignore", "ignore", "pipe"] });
const diagnostics: Buffer[] = [];
manager.stderr.on("data", (chunk: Buffer) => diagnostics.push(chunk));

function liveSocket(path: string): boolean {
  try {
    const metadata = lstatSync(path);
    return metadata.isSocket() && metadata.uid === process.getuid?.() && (metadata.mode & 0o777) === 0o600;
  } catch { return false; }
}

async function waitSocket(path: string): Promise<void> {
  const deadline = performance.now() + 5_000;
  while (!liveSocket(path)) {
    if (manager.exitCode !== null || manager.signalCode !== null) throw new Error("manager exited before socket");
    if (performance.now() >= deadline) throw new Error("manager socket deadline elapsed");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

try {
  await waitSocket(join(state, "owner-recovery.sock"));
  const recovered = await recoverInstalledOwner({
    stateDirectory: state, actorId: "actor.zap.fake-e2e", scopeId: "scope.zap.fake-e2e",
    credentialRef: "vault.zap.fake-e2e",
    validateHostEndpoint: (phase) => liveSocket(phase === "recovery" ? join(state, "owner-recovery.sock") : socket),
  });
  await waitSocket(socket);
  const client = new PodBayWireClient(new AuthenticatedUnixSocketWireTransport({
    ...recovered.channel, exchangeTimeoutMs: 120_000,
  }));
  const saved = JSON.parse(readFileSync(join(root, "stop-retry.json"), "utf8")) as Record<string, unknown>;
  const request = await makeCommand({ operation: "run.stop",
    requestId: "request.fake-e2e.stop.after-restart", key: saved["key"] as string,
    target: saved["target"] as never, guard: saved["guard"] as never,
    body: saved["body"] as never });
  const result = await client.command(request);
  if (result.commandId !== saved["commandId"] || result.state !== "settled")
    throw new Error("resumed stop receipt differs");
  process.stdout.write(JSON.stringify(result));
} catch (cause) {
  process.stderr.write(`${String(cause)}\n${Buffer.concat(diagnostics).toString("utf8")}`);
  process.exitCode = 1;
} finally {
  if (manager.exitCode === null && manager.signalCode === null) {
    manager.kill("SIGTERM");
    await new Promise((resolve) => manager.once("exit", resolve));
  }
}
