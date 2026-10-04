import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("two Node launcher births recover one real Rust manager owner without pod or native input", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario(["A", "B"]);
});

test("SIGKILL leaves a manager socket and the next Node process recovers without repair", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario(["A_KILL", "B"]);
});

test("a failed B proof advances the manager epoch, then C recovers from the fresh store", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario(["A", "B_FAIL", "C"]);
});

test("lost recovery ACK reads the exact receipt without a second rotation", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario(["A", "B_LOST_ACK"]);
});

test("missing staged public receipt refuses proof and a later process recovers", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario(["A", "B_NO_PUBLIC", "C"]);
});

async function runScenario(modes: readonly string[]): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "podbay-owner-recovery-real-"));
  await chmod(root, 0o700);
  const managerBinary = process.env["PODBAY_TEST_MANAGER_BINARY"]!;
  const podBinary = process.env["PODBAY_TEST_POD_BINARY"]!;
  try {
    for (const name of ["state", "pods", "workspace", "credentials"])
      await mkdir(join(root, name), { mode: 0o700 });
    const auth = join(root, "credentials", "dummy-auth.json");
    await writeFile(auth, "dummy fixture credential, no provider account\n", { mode: 0o600 });
    const fakeCodex = join(root, "fake-codex.sh");
    await writeFile(fakeCodex, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await chmod(fakeCodex, 0o700);
    const codexDigest = createHash("sha256").update(await readFile(fakeCodex)).digest("hex");
    await writeFile(join(root, "state", "trusted-policy.json"), JSON.stringify({
      schema: "podbay.trusted-manager-policy/1",
      actorId: "actor.zap.recovery", scopeId: "scope.zap.recovery",
      credentialRef: "vault.zap.recovery", credentialSource: auth,
      profileRef: "profile.codex.recovery", profileGeneration: 1,
      executable: fakeCodex, executableSha256: codexDigest,
      workspaceRoot: join(root, "workspace"), workspaceBasisRef: "basis.recovery",
      hostId: "host.recovery", driverRef: "driver.codex.recovery",
      protocolRef: "protocol.codex.recovery", modelId: "gpt-6-sol",
      reasoningEffort: "medium", approvalPolicy: "never", sandbox: "danger_full_access",
      wallSeconds: 60, maxChildren: 2, resultContractRef: "result.none",
      launchDeadlineSeconds: 30, sendDeadlineSeconds: 30, writerLeaseSeconds: 120,
    }), { mode: 0o600 });
    for (const mode of modes) {
      const output = await runFixture(mode, root, managerBinary, podBinary);
      assert.equal(output.code, 0, output.stderr);
      assert.equal(output.stdout, "");
      if (mode === "B_FAIL" || mode === "B_NO_PUBLIC") {
        const paused = new DatabaseSync(join(root, "state", "podbay.sqlite"), { readOnly: true });
        try {
          const epoch = paused.prepare("SELECT value FROM metadata WHERE key='owner_epoch'").get() as { value: number };
          const actor = paused.prepare("SELECT credential_generation FROM authority_actors WHERE actor_id='actor.zap.recovery'").get() as { credential_generation: number };
          const grant = paused.prepare("SELECT credential_generation FROM authority_grants WHERE actor_id='actor.zap.recovery'").get() as { credential_generation: number };
          assert.equal(epoch.value, 2);
          assert.equal(actor.credential_generation, 1);
          assert.equal(grant.credential_generation, 1);
        } finally { paused.close(); }
      }
    }
    const a = JSON.parse(await readFile(join(root, "receipt-A.json"), "utf8")) as Record<string, unknown>;
    const finalMode = modes.at(-1)!;
    const b = JSON.parse(await readFile(join(root, `receipt-${finalMode}.json`), "utf8")) as Record<string, unknown>;
    assert.equal(b["grantRef"], a["grantRef"]);
    assert.equal(b["generation"], "2");
    assert.equal(b["forbidden"], true);
    assert.equal(b["duplicate"], finalMode === "B_LOST_ACK");
    const failed = modes.includes("B_FAIL") || modes.includes("B_NO_PUBLIC");
    assert.equal(b["ownerEpoch"], failed ? "3" : "2");
    const db = new DatabaseSync(join(root, "state", "podbay.sqlite"), { readOnly: true });
    try {
      const actor = db.prepare("SELECT credential_generation FROM authority_actors WHERE actor_id='actor.zap.recovery'").get() as { credential_generation: number };
      const grant = db.prepare("SELECT credential_generation FROM authority_grants WHERE actor_id='actor.zap.recovery'").get() as { credential_generation: number };
      assert.equal(actor.credential_generation, 2);
      assert.equal(grant.credential_generation, 2);
      assert.equal((db.prepare("SELECT COUNT(*) AS value FROM launch_bindings").get() as { value: number }).value, 0);
      if (failed) {
        const failedMode = modes.includes("B_FAIL") ? "B_FAIL" : "B_NO_PUBLIC";
        const failedReceipt = JSON.parse(await readFile(join(root, `receipt-${failedMode}.json`), "utf8")) as Record<string, unknown>;
        const current = db.prepare("SELECT public_key FROM actor_verifiers WHERE actor_id='actor.zap.recovery'").get() as { public_key: Uint8Array };
        assert.notEqual(failedReceipt["stagedPublic"], Buffer.from(current.public_key).toString("hex"));
      }
    } finally { db.close(); }
  } finally {
    for (const mode of modes) {
      const path = join(root, `manager-${mode}.pid`);
      try { process.kill(Number(await readFile(path, "utf8")), "SIGTERM"); } catch { /* already exited */ }
    }
    await rm(root, { recursive: true, force: true });
  }
}

async function runFixture(mode: string, root: string, manager: string, pod: string): Promise<{
  code: number | null; stdout: string; stderr: string;
}> {
  const script = fileURLToPath(new URL("./owner-recovery-real.fixture.ts", import.meta.url));
  const child = spawn(process.execPath, ["--experimental-strip-types", script, mode, root, manager, pod],
    { stdio: ["ignore", "pipe", "pipe"] });
  const stdout: Buffer[] = [], stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject); child.once("exit", resolve);
  });
  return { code, stdout: Buffer.concat(stdout).toString("utf8"),
    stderr: Buffer.concat(stderr).toString("utf8") };
}
