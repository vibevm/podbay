import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import test, { type TestContext } from "node:test";

import { AuthenticatedUnixSocketWireTransport } from "../src/authenticated-unix-socket.ts";
import { PodBayWireClient, makeRead } from "../src/generated.ts";
import {
  INITIAL_OWNER_RIGHTS_DIGEST,
  InitialOwnerSetupClient,
  OwnerSetupError,
  type TrustedOwnerSetupExpectations,
} from "../src/owner-setup.ts";

const domain = Buffer.from("podbay.owner-initial-enrollment/1\0", "ascii");
const rights = "launch_pod.scope+use_credential.exact+send_session.scope";

test("setup signs only the exact trusted challenge and returns a process-owned auth channel", async (t) => {
  let key: Buffer = Buffer.alloc(0);
  let signatures = 0;
  const socketPath = await fakeSetupServer(t, async (socket) => {
    const frames = new Frames(socket);
    key = await frames.next();
    assert.equal(key.length, 32);
    const challenge = challengeBytes(key, expectations(socketPath));
    const framed = frame(challenge);
    socket.write(framed.subarray(0, 2));
    socket.write(framed.subarray(2));
    const signature = await frames.next();
    assert.equal(signature.length, 64);
    assert.equal(verify(null, challenge, publicKey(key), signature), true);
    signatures += 1;
    socket.write(frame(receiptBytes(expectations(socketPath), false)));
    assert.equal((await frames.next()).toString("ascii"), "ack");
    socket.end();
  });
  const client = new InitialOwnerSetupClient(expectations(socketPath));
  const receipt = await client.enroll();
  assert.equal(receipt.actorId, "actor.owner.fixture");
  assert.equal(receipt.grantRef, "grant.1");
  assert.equal(receipt.duplicate, false);
  assert.equal(signatures, 1);
  assert.deepEqual(await client.enroll(), receipt);
  const channel = client.authenticatedChannel();
  assert.equal(channel.socketPath, join(socketPath.slice(0, -"owner-setup.sock".length), "manager.sock"));
  assert.equal(channel.expected.credentialGeneration, 1n);
  const auth = actorChallengeBytes(channel.expected);
  const authSignature = await channel.validateAndSign({
    ...channel.expected,
    bytes: new Uint8Array(auth),
    nonce: new Uint8Array(32).fill(7),
  });
  assert.equal(verify(null, auth, publicKey(key), Buffer.from(authSignature)), true);
  await assert.rejects(
    () => Promise.resolve(channel.validateAndSign({
      ...channel.expected,
      bytes: new Uint8Array(Buffer.from("arbitrary message")),
      nonce: new Uint8Array(32).fill(7),
    })),
    /challenge or endpoint differs/u,
  );
});

test("every setup authority field is checked before signing or retry", async (t) => {
  for (const field of [
    "lineage", "owner", "revision", "actor", "scope", "generation",
    "uid", "pid", "birth", "cgroup", "key", "credential", "rights",
  ] as const) {
    let connections = 0;
    let framesSeen = 0;
    const socketPath = await fakeSetupServer(t, async (socket) => {
      connections += 1;
      const frames = new Frames(socket);
      const key = await frames.next();
      framesSeen = frames.receivedCount;
      const altered = {
        lineage: field === "lineage" ? "lineage.wrong" : undefined,
        owner: field === "owner" ? 2n : undefined,
        revision: field === "revision" ? 2n : undefined,
        actor: field === "actor" ? "actor.other" : undefined,
        scope: field === "scope" ? "scope.other" : undefined,
        generation: field === "generation" ? "owner_cli.worker.generation1" : undefined,
        uid: field === "uid" ? "linux.uid.999" : undefined,
        pid: field === "pid" ? "linux.pid.999" : undefined,
        rights: field === "rights" ? "launch_pod.scope" : undefined,
        birth: field === "birth" ? 99n : undefined,
        cgroup: field === "cgroup" ? "/foreign.slice" : undefined,
        key: field === "key" ? Buffer.alloc(32, 9) : undefined,
        credential: field === "credential" ? "vault.other" : undefined,
      };
      socket.write(frame(challengeBytes(key, expectations(socketPath), altered)));
    });
    const client = new InitialOwnerSetupClient(expectations(socketPath));
    await assert.rejects(() => client.enroll(), failure("invalid_challenge", "before_signature"));
    assert.equal(connections, 1);
    assert.equal(framesSeen, 1);
  }
});

test("lost receipt reconciles once with the same public key and a fresh challenge", async (t) => {
  let firstKey: Buffer | undefined;
  let connections = 0;
  const socketPath = await fakeSetupServer(t, async (socket) => {
    connections += 1;
    const frames = new Frames(socket);
    const key = await frames.next();
    if (firstKey === undefined) firstKey = Buffer.from(key);
    else assert.deepEqual(key, firstKey);
    const challenge = challengeBytes(key, expectations(socketPath), { nonce: connections });
    socket.write(frame(challenge));
    assert.equal(verify(null, challenge, publicKey(key), await frames.next()), true);
    if (connections === 1) socket.destroy();
    else {
      socket.write(frame(receiptBytes(expectations(socketPath), true)));
      assert.equal((await frames.next()).toString("ascii"), "ack");
      socket.end();
    }
  });
  const client = new InitialOwnerSetupClient(expectations(socketPath));
  const receipt = await client.enroll();
  assert.equal(receipt.duplicate, true);
  assert.equal(connections, 2);
});

test("reconciliation refuses a replayed nonce without signing again", async (t) => {
  let connections = 0;
  let signatures = 0;
  const socketPath = await fakeSetupServer(t, async (socket) => {
    connections += 1;
    const frames = new Frames(socket);
    const key = await frames.next();
    const challenge = challengeBytes(key, expectations(socketPath), { nonce: 7 });
    socket.write(frame(challenge));
    if (connections === 2) return;
    assert.equal(verify(null, challenge, publicKey(key), await frames.next()), true);
    signatures += 1;
    socket.destroy();
  });
  await assert.rejects(
    () => new InitialOwnerSetupClient(expectations(socketPath)).enroll(),
    failure("reconciliation_failed", "possible_enrollment"),
  );
  assert.equal(connections, 2);
  assert.equal(signatures, 1);
});

test("malformed receipt and endpoint refusal do not authorize a retry", async (t) => {
  let connections = 0;
  const socketPath = await fakeSetupServer(t, async (socket) => {
    connections += 1;
    const frames = new Frames(socket);
    const key = await frames.next();
    socket.write(frame(challengeBytes(key, expectations(socketPath))));
    await frames.next();
    socket.end(frame(Buffer.from('{"protocol":"podbay.owner-initial-enrollment/1"}', "ascii")));
  });
  await assert.rejects(
    () => new InitialOwnerSetupClient(expectations(socketPath)).enroll(),
    failure("invalid_receipt", "possible_enrollment"),
  );
  assert.equal(connections, 1);

  const refusedPath = await fakeSetupServer(t, async (socket) => {
    const frames = new Frames(socket);
    const key = await frames.next();
    socket.write(frame(challengeBytes(key, expectations(refusedPath))));
  });
  const refused = expectations(refusedPath);
  await assert.rejects(
    () => new InitialOwnerSetupClient({ ...refused, validateHostEndpoint: () => false }).enroll(),
    failure("endpoint_refused", "before_signature"),
  );
});

test("oversized or partial setup challenge fails within a finite deadline", async (t) => {
  for (const partial of [false, true]) {
    let connections = 0;
    const socketPath = await fakeSetupServer(t, async (socket) => {
      connections += 1;
      await new Frames(socket).next();
      if (partial) socket.write(Buffer.from([0, 0]));
      else {
        const prefix = Buffer.alloc(4);
        prefix.writeUInt32BE(8_193);
        socket.write(prefix);
      }
    });
    await assert.rejects(
      () => new InitialOwnerSetupClient({ ...expectations(socketPath), totalTimeoutMs: 40 }).enroll(),
      failure(partial ? "timeout" : "invalid_challenge", "before_signature"),
    );
    assert.equal(connections, 1);
  }
});

test("Node launcher parent enrolls through real Rust owner-setup socket and authenticates", {
  skip: !process.env["PODBAY_TEST_MANAGER_BINARY"] || process.platform !== "linux",
}, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "podbay-ts-owner-real-"));
  const state = join(directory, "state");
  const pods = join(directory, "pods");
  await mkdirPrivate(state);
  await mkdirPrivate(pods);
  const binary = join(directory, "fake-pod");
  const contents = Buffer.from("#!/bin/sh\nexit 0\n", "ascii");
  await writeFile(binary, contents, { mode: 0o700 });
  await chmod(binary, 0o700);
  const digest = createHash("sha256").update(contents).digest("hex");
  const database = join(state, "podbay.sqlite");
  const executable = process.env["PODBAY_TEST_MANAGER_BINARY"]!;
  const manager = spawn(executable, [
    "manager", "serve", "--state-dir", state, "--database", database,
    "--pod-dir", pods, "--pod-binary", binary, "--pod-sha256", digest,
    "--initial-owner-actor", "actor.owner.fixture", "--initial-owner-scope", "scope.owner.fixture",
    "--initial-owner-credential", "vault.owner.fixture",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  t.after(async () => {
    if (manager.exitCode === null && manager.signalCode === null) {
      manager.kill("SIGTERM");
      await new Promise<void>((resolve) => manager.once("exit", () => resolve()));
    }
    await rm(directory, { recursive: true, force: true });
  });
  const socketPath = join(state, "owner-setup.sock");
  await waitForFile(socketPath, manager);
  const db = new DatabaseSync(database, { readOnly: true });
  const lineage = (db.prepare("SELECT lineage FROM store_identity WHERE singleton=1").get() as { lineage: string }).lineage;
  const owner = BigInt((db.prepare("SELECT value FROM metadata WHERE key='owner_epoch'").get() as { value: number }).value);
  const revision = BigInt((db.prepare("SELECT value FROM metadata WHERE key='authority_revision'").get() as { value: number }).value);
  db.close();
  const client = new InitialOwnerSetupClient({
    ...expectations(socketPath),
    storeLineage: lineage,
    ownerEpoch: owner,
    authorityRevision: revision,
    validateHostEndpoint: () => manager.exitCode === null,
  });
  const receipt = await client.enroll();
  assert.equal(receipt.duplicate, false);
  assert.equal(receipt.authorityRevision, revision + 1n);
  await waitForFile(join(state, "manager.sock"), manager);
  const wire = new PodBayWireClient(new AuthenticatedUnixSocketWireTransport(client.authenticatedChannel()));
  const request = makeRead({
    operation: "commands.get", requestId: "request.owner.setup.read",
    target: { kind: "scope", scopeId: "scope.owner.fixture" },
    body: { selector: { kind: "key", key: "key.missing" } },
  });
  await assert.rejects(() => wire.read(request), (error: unknown) => {
    assert.equal((error as { envelope?: { error?: { code?: string } } }).envelope?.error?.code, "forbidden");
    return true;
  });
});

function expectations(socketPath: string): TrustedOwnerSetupExpectations {
  const self = selfProcess();
  return {
    setupSocketPath: socketPath,
    managerSocketPath: join(socketPath.slice(0, -"owner-setup.sock".length), "manager.sock"),
    actorId: "actor.owner.fixture", scopeId: "scope.owner.fixture",
    credentialRef: "vault.owner.fixture", storeLineage: "lineage.owner.fixture",
    ownerEpoch: 1n, authorityRevision: 1n,
    ...self, rightsDigest: INITIAL_OWNER_RIGHTS_DIGEST,
    validateHostEndpoint: () => true,
  };
}

function selfProcess() {
  const statLine = requireRead("/proc/self/stat");
  const fields = statLine.slice(statLine.lastIndexOf(")") + 2).trim().split(/\s+/u);
  const cgroup = requireRead("/proc/self/cgroup").trimEnd().split("\n").find((line) => line.startsWith("0::"));
  assert.ok(cgroup);
  return {
    osIdentity: `linux.uid.${process.getuid!()}`,
    processIdentity: `linux.pid.${process.pid}`,
    startIdentity: BigInt(fields[19]!),
    containmentIdentity: cgroup.slice(3),
  };
}

function requireRead(path: string): string {
  return readFileSync(path, "utf8");
}

function field(tag: number, value: Buffer | string): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "ascii") : value;
  const result = Buffer.alloc(3 + bytes.length);
  result[0] = tag;
  result.writeUInt16BE(bytes.length, 1);
  result.set(bytes, 3);
  return result;
}
function counter(value: bigint): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(value);
  return bytes;
}
function challengeBytes(
  key: Buffer,
  expected: TrustedOwnerSetupExpectations,
  changed: {
    lineage?: string; owner?: bigint; revision?: bigint; actor?: string; scope?: string;
    generation?: string; uid?: string; pid?: string; birth?: bigint; cgroup?: string;
    key?: Buffer; credential?: string; rights?: string; nonce?: number;
  } = {},
): Buffer {
  return Buffer.concat([
    domain,
    field(1, Buffer.alloc(32, changed.nonce ?? 7)),
    field(2, changed.lineage ?? expected.storeLineage),
    field(3, counter(changed.owner ?? expected.ownerEpoch)),
    field(4, counter(changed.revision ?? expected.authorityRevision)),
    field(5, changed.actor ?? expected.actorId),
    field(6, changed.scope ?? expected.scopeId),
    field(7, changed.generation ?? "owner_cli.coordinator.generation1"),
    field(8, changed.uid ?? expected.osIdentity),
    field(9, changed.pid ?? expected.processIdentity),
    field(10, counter(changed.birth ?? expected.startIdentity)),
    field(11, changed.cgroup ?? expected.containmentIdentity),
    field(12, changed.key ?? key),
    field(13, changed.credential ?? expected.credentialRef),
    field(14, changed.rights ?? rights),
  ]);
}
function actorChallengeBytes(expected: ReturnType<InitialOwnerSetupClient["authenticatedChannel"]>["expected"]): Buffer {
  const parts = [
    Buffer.from("podbay.actor-credential.challenge\0", "ascii"), Buffer.from([1]),
    field(1, Buffer.alloc(32, 7)), field(2, expected.storeLineage),
    field(3, expected.actorId), field(4, expected.scopeId),
    field(5, counter(expected.credentialGeneration)), field(6, Buffer.from([1])),
    field(7, expected.osIdentity), field(8, expected.processIdentity),
    field(9, counter(expected.startIdentity)), field(10, expected.containmentIdentity),
    field(11, Buffer.from([1])),
  ];
  return Buffer.concat(parts);
}
function receiptBytes(expected: TrustedOwnerSetupExpectations, duplicate: boolean): Buffer {
  return Buffer.from(JSON.stringify({
    actorId: expected.actorId, authorityRevision: (expected.authorityRevision + 1n).toString(),
    duplicate, grantRef: "grant.1", ownerEpoch: expected.ownerEpoch.toString(),
    protocol: "podbay.owner-initial-enrollment/1", scopeId: expected.scopeId,
  }), "utf8");
}
function publicKey(raw: Buffer) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
    format: "der", type: "spki",
  });
}
function frame(payload: Buffer): Buffer {
  const bytes = Buffer.alloc(4 + payload.length);
  bytes.writeUInt32BE(payload.length, 0);
  bytes.set(payload, 4);
  return bytes;
}
function failure(code: OwnerSetupError["code"], stage: OwnerSetupError["stage"]) {
  return (error: unknown) => {
    assert.equal(error instanceof OwnerSetupError, true);
    if (!(error instanceof OwnerSetupError)) return false;
    assert.equal(error.code, code);
    assert.equal(error.stage, stage);
    return true;
  };
}

class Frames {
  receivedCount = 0;
  readonly #queue: Buffer[] = [];
  readonly #waiting: Array<(value: Buffer) => void> = [];
  #pending = Buffer.alloc(0);
  constructor(socket: Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.#pending = Buffer.concat([this.#pending, chunk]);
      while (this.#pending.length >= 4) {
        const size = this.#pending.readUInt32BE(0);
        if (this.#pending.length < size + 4) break;
        const value = Buffer.from(this.#pending.subarray(4, size + 4));
        this.#pending = this.#pending.subarray(size + 4);
        this.receivedCount += 1;
        const waiting = this.#waiting.shift();
        if (waiting) waiting(value); else this.#queue.push(value);
      }
    });
  }
  next(): Promise<Buffer> {
    const ready = this.#queue.shift();
    return ready ? Promise.resolve(ready) : new Promise((resolve) => this.#waiting.push(resolve));
  }
}

async function fakeSetupServer(t: TestContext, handle: (socket: Socket) => Promise<void>): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "podbay-owner-socket-"));
  const socketPath = join(directory, "owner-setup.sock");
  const sockets = new Set<Socket>();
  const errors: unknown[] = [];
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    void handle(socket).catch((error) => { errors.push(error); socket.destroy(); });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => { server.off("error", reject); resolve(); });
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
    assert.deepEqual(errors, []);
  });
  return socketPath;
}

async function mkdirPrivate(path: string): Promise<void> {
  await mkdir(path, { mode: 0o700 });
  await chmod(path, 0o700);
}
async function waitForFile(path: string, child: ChildProcess): Promise<void> {
  const until = performance.now() + 5_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error("Rust manager exited before setup was ready");
    try { await stat(path); return; } catch { /* not ready */ }
    if (performance.now() >= until) throw new Error("Rust manager socket did not appear");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
