import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { promisify } from "node:util";

const exec = promisify(execFile);

test("SIGKILL manager owner auto-rebinds one exact V2 pod before serving the next native turn", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario("normal");
});

test("changed V2 policy refuses automatic rebind before Pod effect and manager readiness", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario("stale_policy");
});

test("missing V2 Pod refuses manager readiness without a rebind or native send", {
  skip: process.platform !== "linux" || !process.env["PODBAY_TEST_MANAGER_BINARY"] ||
    !process.env["PODBAY_TEST_POD_BINARY"],
}, async () => {
  await runScenario("missing_pod");
});

async function runScenario(kind: "normal" | "stale_policy" | "missing_pod"): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "podbay-auto-rebind-real-"));
  await chmod(root, 0o700);
  try {
    for (const name of ["state", "pods", "workspace", "credentials"])
      await mkdir(join(root, name), { mode: 0o700 });
    const auth = join(root, "credentials", "dummy-auth.json");
    await writeFile(auth, "dummy fixture credential, no provider account\n", { mode: 0o600 });
    const codex = join(root, "fake-codex.sh");
    await writeFile(codex, fakeCodexScript(), { mode: 0o700 });
    await chmod(codex, 0o700);
    const digest = createHash("sha256").update(await readFile(codex)).digest("hex");
    const policyPath = join(root, "state", "trusted-policy.json");
    const policy = {
      schema: "podbay.trusted-manager-policy/1",
      actorId: "actor.zap.auto-rebind", scopeId: "scope.zap.auto-rebind",
      credentialRef: "vault.zap.auto-rebind", credentialSource: auth,
      profileRef: "profile.codex.auto-rebind", profileGeneration: 1,
      executable: codex, executableSha256: digest,
      workspaceRoot: join(root, "workspace"), workspaceBasisRef: "basis.auto-rebind",
      hostId: "host.auto-rebind", driverRef: "driver.codex.auto-rebind",
      protocolRef: "protocol.codex.auto-rebind", modelId: "gpt-6-sol",
      reasoningEffort: "medium", approvalPolicy: "never", sandbox: "danger_full_access",
      wallSeconds: 60, maxChildren: 2, resultContractRef: "result.none",
      launchDeadlineSeconds: 30, sendDeadlineSeconds: 30, writerLeaseSeconds: 120,
    };
    await writeFile(policyPath, JSON.stringify(policy), { mode: 0o600 });
    const first = await runFixture("A", root);
    assert.equal(first.code, 0, first.stderr);
    assert.equal(first.stdout, "");
    if (kind === "stale_policy") {
      await writeFile(policyPath, JSON.stringify({ ...policy, workspaceBasisRef: "basis.auto-rebind.changed" }), { mode: 0o600 });
    }
    if (kind === "missing_pod") await stopPodUnits(join(root, "pods"));
    const second = await runFixture("B", root);
    assert.equal(second.stdout, "");
    const a = JSON.parse(await readFile(join(root, "receipt-A.json"), "utf8")) as Record<string, unknown>;
    if (kind !== "normal") {
      assert.notEqual(second.code, 0);
      assert.match(second.stderr, /manager exited before socket|owner recovery response ended/u);
      assert.match(second.stderr, /current V2 Pod .* is unverified after [0-9]+ settled Pods on page [0-9]+; manager not ready/u);
      const db = new DatabaseSync(join(root, "state", "podbay.sqlite"), { readOnly: true });
      try {
        const count = db.prepare("SELECT COUNT(*) AS count FROM manager_rebinds").get() as { count: number };
        assert.equal(count.count, 0);
        const sends = db.prepare("SELECT COUNT(*) AS count FROM codex_bootstrap_sends").get() as { count: number };
        assert.equal(sends.count, 0);
        const actor = db.prepare("SELECT credential_generation FROM authority_actors WHERE actor_id='actor.zap.auto-rebind'")
          .get() as { credential_generation: number };
        assert.equal(actor.credential_generation, 2, second.stderr);
      } finally { db.close(); }
      if (kind === "stale_policy") {
        const frames = await readFile(join(a["codexHome"] as string, "frames.log"), "utf8");
        const methods = frames.trimEnd().split("\n").map((line) => (JSON.parse(line) as { method: string }).method);
        assert.deepEqual(methods, ["initialize", "initialized"]);
      }
      return;
    }
    assert.equal(second.code, 0, second.stderr);
    const b = JSON.parse(await readFile(join(root, "receipt-B.json"), "utf8")) as Record<string, unknown>;
    assert.equal(b["supervisorPid"], a["supervisorPid"]);
    assert.equal(b["supervisorBirth"], a["supervisorBirth"]);
    assert.equal(b["childPid"], a["childPid"]);
    assert.equal(b["childBirth"], a["childBirth"]);
    assert.equal(b["codexHome"], a["codexHome"]);
    assert.equal(b["nativeTurnId"], "turn.fixture");
    assert.equal(b["duplicate"], true);
    const db = new DatabaseSync(join(root, "state", "podbay.sqlite"), { readOnly: true });
    try {
      const rebinds = db.prepare("SELECT phase,next_owner_epoch,command_key FROM manager_rebinds").all() as
        Array<{ phase: string; next_owner_epoch: number; command_key: string }>;
      assert.equal(rebinds.length, 1);
      assert.equal(rebinds[0]?.phase, "activated");
      assert.equal(rebinds[0]?.next_owner_epoch, 2);
      assert.match(rebinds[0]?.command_key ?? "", /^rebind\.owner\.2\.[a-f0-9]{64}$/u);
      const launches = db.prepare("SELECT COUNT(*) AS count FROM launch_bindings").get() as { count: number };
      assert.equal(launches.count, 1);
      const writer = db.prepare("SELECT writer_epoch,owner_epoch,holder_credential_generation FROM native_writer_leases")
        .get() as { writer_epoch: number; owner_epoch: number; holder_credential_generation: number };
      assert.equal(writer.writer_epoch, 2);
      assert.equal(writer.owner_epoch, 2);
      assert.equal(writer.holder_credential_generation, 2);
    } finally { db.close(); }
    assert.equal(typeof b["codexHome"], "string");
    const frames = await readFile(join(b["codexHome"] as string, "frames.log"), "utf8");
    const methods = frames.trimEnd().split("\n").map((line) => (JSON.parse(line) as { method: string }).method);
    assert.deepEqual(methods, ["initialize", "initialized", "thread/start", "thread/read", "turn/start"]);
  } finally {
    for (const mode of ["A", "B"]) {
      const pid = await readFile(join(root, `manager-${mode}.pid`), "utf8").catch(() => null);
      if (pid !== null) { try { process.kill(Number(pid), "SIGTERM"); } catch { /* exited */ } }
    }
    await stopPodUnits(join(root, "pods"));
    await rm(root, { recursive: true, force: true });
  }
}

async function runFixture(mode: string, root: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const script = fileURLToPath(new URL("./manager-auto-rebind-real.fixture.ts", import.meta.url));
  const child = spawn(process.execPath, ["--experimental-strip-types", script, mode, root,
    process.env["PODBAY_TEST_MANAGER_BINARY"]!, process.env["PODBAY_TEST_POD_BINARY"]!],
  { stdio: ["ignore", "pipe", "pipe"] });
  const stdout: Buffer[] = [], stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject); child.once("exit", resolve);
  });
  return { code, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") };
}

async function stopPodUnits(pods: string): Promise<void> {
  for (const name of await readdir(pods).catch(() => [])) {
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
sleep 30
`;
}
