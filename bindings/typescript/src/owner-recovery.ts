/** Trusted Linux owner recovery client; no pod launch or input lives here. */
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { createConnection, type Socket } from "node:net";
import { isAbsolute, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import {
  loadOwnerKeyForRecovery,
  stageNextOwnerKeyCustody,
  type OwnerKeyCustodyBinding,
} from "./owner-key-custody.ts";
import {
  matchesCanonicalActorChallenge,
  parseCanonicalActorChallenge,
  type AuthenticatedUnixSocketOptions,
} from "./authenticated-unix-socket.ts";

const DOMAIN = Buffer.from("podbay.owner-recovery/1\0", "ascii");
const MAX_FRAME = 8_192;
const IO_TIMEOUT_MS = 5_000;
const RECEIPT_KEYS = [
  "actorId", "authorityRevision", "credentialGeneration", "duplicate", "grantRef",
  "ownerEpoch", "protocol", "rotationKey", "scopeId",
].sort().join("\0");

export interface TrustedOwnerRecoveryConfig {
  readonly stateDirectory: string;
  readonly actorId: string;
  readonly scopeId: string;
  readonly credentialRef: string;
  /** Independently pin the manager process and exact socket before signing. */
  readonly validateHostEndpoint: (phase: "recovery" | "auth") => boolean | Promise<boolean>;
}

export interface OwnerRecoveryResult {
  readonly grantRef: string;
  readonly ownerEpoch: bigint;
  readonly authorityRevision: bigint;
  readonly credentialGeneration: bigint;
  readonly duplicate: boolean;
  readonly channel: AuthenticatedUnixSocketOptions;
}

type Snapshot = {
  lineage: string; ownerEpoch: bigint; revision: bigint; managerCredentialEpoch: bigint;
  generation: bigint; publicKey: Buffer; osIdentity: string; processIdentity: string;
  startIdentity: bigint; containmentIdentity: string;
};

/** The existing store verifier chooses the old key; the new key is fsynced before either signature. */
export async function recoverInstalledOwner(config: TrustedOwnerRecoveryConfig): Promise<OwnerRecoveryResult> {
  validateConfig(config);
  const current = currentProcess();
  const prior = readCurrentOwner(config);
  if (prior.osIdentity !== current.osIdentity ||
      (prior.processIdentity === current.processIdentity && prior.startIdentity === current.startIdentity))
    throw new TypeError("recovery owner process birth is not new");
  const oldPath = prior.generation === 1n
    ? join(config.stateDirectory, "owner-key-custody.json")
    : join(config.stateDirectory, `owner-generation-${prior.generation.toString()}`,
      `key-${prior.publicKey.toString("hex")}`, "owner-key-custody.json");
  const old = loadOwnerKeyForRecovery(oldPath, {
    actorId: config.actorId, scopeId: config.scopeId, storeLineage: prior.lineage,
  }, prior.publicKey);
  const generated = generateKeyPairSync("ed25519");
  const nextBinding: OwnerKeyCustodyBinding = {
    actorId: config.actorId, scopeId: config.scopeId, storeLineage: prior.lineage,
    credentialRef: config.credentialRef, ownerEpoch: prior.ownerEpoch,
    authorityRevision: prior.revision, ...current,
  };
  const staged = stageNextOwnerKeyCustody(
    config.stateDirectory, prior.generation + 1n, nextBinding, generated.privateKey,
  );
  const keys = Buffer.concat([prior.publicKey, Buffer.from(staged.publicKey)]);
  const expected = {
    actorId: config.actorId, storeLineage: prior.lineage, scopeId: config.scopeId,
    credentialGeneration: prior.generation + 1n,
    ...current, origin: { kind: "owner-cli" as const },
  };
  const channel: AuthenticatedUnixSocketOptions = {
    socketPath: join(config.stateDirectory, "manager.sock"), expected,
    validateAndSign: async (challenge) => {
      if (!matchesCanonicalActorChallenge(challenge, expected) ||
          await config.validateHostEndpoint("auth") !== true ||
          !sameCurrentProcess(current))
        throw new TypeError("recovered owner auth challenge differs");
      return new Uint8Array(sign(null, Buffer.from(challenge.bytes), staged.privateKey));
    },
  };
  let signed = false;
  let rotationKey: string | null = null;
  try {
    const socket = await FrameSocket.connect(join(config.stateDirectory, "owner-recovery.sock"));
    try {
      await socket.write(keys);
      const challenge = await socket.read();
      rotationKey = verifyRecoveryChallenge(challenge, config, prior, current, staged.publicKey);
      if (await config.validateHostEndpoint("recovery") !== true || !sameCurrentProcess(current))
        throw new TypeError("owner recovery endpoint or process changed");
      const signatures = Buffer.concat([
        Buffer.from(old.signVerifiedTranscript(challenge)),
        sign(null, challenge, staged.privateKey),
      ]);
      signed = true;
      await socket.write(signatures);
      const receipt = parseReceipt(await socket.read(), config, prior, rotationKey);
      await socket.write(Buffer.from("ack", "ascii"));
      await socket.waitEnd();
      return { ...receipt, channel };
    } finally { socket.close(); }
  } catch (error) {
    if (!signed) throw error;
    // Possible durable rotation: one read-only same-key receipt path, never another rotation.
    const socket = await FrameSocket.connect(join(config.stateDirectory, "owner-recovery.sock"));
    try {
      await socket.write(keys);
      const challenge = await socket.read();
      // The manager's second challenge is normal auth/1 for the newly recorded owner.
      // The authenticated transport parser is the canonical verifier for it.
      const parsed = parseCanonicalActorChallenge(challenge);
      if (parsed === null || !matchesCanonicalActorChallenge(parsed, expected) ||
        await config.validateHostEndpoint("recovery") !== true || !sameCurrentProcess(current))
        throw new TypeError("owner recovery readback challenge differs");
      await socket.write(sign(null, challenge, staged.privateKey));
      if (rotationKey === null) throw new TypeError("original recovery key is unavailable");
      const receipt = parseReceipt(await socket.read(), config, prior, rotationKey);
      if (!receipt.duplicate) throw new TypeError("owner recovery readback is not duplicate");
      await socket.write(Buffer.from("ack", "ascii"));
      await socket.waitEnd();
      return { ...receipt, channel };
    } finally { socket.close(); }
  }
}

function verifyRecoveryChallenge(
  bytes: Buffer, config: TrustedOwnerRecoveryConfig, prior: Snapshot,
  current: ReturnType<typeof currentProcess>, nextKey: Uint8Array,
): string {
  if (!bytes.subarray(0, DOMAIN.length).equals(DOMAIN)) throw new TypeError("recovery domain differs");
  let at = DOMAIN.length;
  const field = (tag: number): Buffer => {
    if (at + 3 > bytes.length || bytes[at] !== tag) throw new TypeError("recovery field differs");
    const size = bytes.readUInt16BE(at + 1);
    if (size === 0 || at + 3 + size > bytes.length) throw new TypeError("recovery field bound");
    const value = bytes.subarray(at + 3, at + 3 + size);
    at += 3 + size;
    return value;
  };
  const number = (tag: number) => {
    const value = field(tag);
    if (value.length !== 8) throw new TypeError("recovery counter differs");
    return value.readBigUInt64BE(0);
  };
  const nonce = field(1);
  if (nonce.length !== 32 || nonce.every((byte) => byte === 0)) throw new TypeError("recovery nonce differs");
  const lineage = field(2).toString("ascii");
  const ownerEpoch = number(3), managerCredential = number(4), revision = number(5);
  const rotationKey = field(6).toString("ascii");
  const actor = field(7).toString("ascii"), scope = field(8).toString("ascii");
  const generation = number(9);
  const oldOs = field(10).toString("ascii"), oldProcess = field(11).toString("ascii");
  const oldStart = number(12), oldContainment = field(13).toString("ascii");
  const newOs = field(14).toString("ascii"), newProcess = field(15).toString("ascii");
  const newStart = number(16), newContainment = field(17).toString("ascii");
  const oldKey = field(18), offeredNext = field(19);
  const digest = createHash("sha256").update(Buffer.from("podbay.owner-recovery.key/1\0", "ascii"))
    .update(nonce).update(lineage).update(actor).update(counter(ownerEpoch)).digest("hex");
  if (at !== bytes.length || lineage !== prior.lineage || ownerEpoch !== prior.ownerEpoch ||
      managerCredential !== prior.managerCredentialEpoch || revision !== prior.revision ||
      rotationKey !== `rotation.owner.${digest}` || actor !== config.actorId ||
      scope !== config.scopeId || generation !== prior.generation ||
      oldOs !== prior.osIdentity || oldProcess !== prior.processIdentity ||
      oldStart !== prior.startIdentity || oldContainment !== prior.containmentIdentity ||
      newOs !== current.osIdentity || newProcess !== current.processIdentity ||
      newStart !== current.startIdentity || newContainment !== current.containmentIdentity ||
      !oldKey.equals(prior.publicKey) || !offeredNext.equals(Buffer.from(nextKey)))
    throw new TypeError("owner recovery challenge differs from current store and process");
  return rotationKey;
}

function parseReceipt(bytes: Buffer, config: TrustedOwnerRecoveryConfig, prior: Snapshot, rotationKey: string) {
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const value: unknown = JSON.parse(raw);
  if (!isRecord(value) || JSON.stringify(value) !== raw ||
      Object.keys(value).sort().join("\0") !== RECEIPT_KEYS ||
      value["protocol"] !== "podbay.owner-recovery/1" ||
      value["actorId"] !== config.actorId || value["scopeId"] !== config.scopeId ||
      value["ownerEpoch"] !== prior.ownerEpoch.toString() ||
      value["authorityRevision"] !== (prior.revision + 1n).toString() ||
      value["credentialGeneration"] !== (prior.generation + 1n).toString() ||
      typeof value["grantRef"] !== "string" || !/^grant\.[1-9][0-9]*$/u.test(value["grantRef"]) ||
      typeof value["rotationKey"] !== "string" || !/^rotation\.owner\.[a-f0-9]{64}$/u.test(value["rotationKey"]) ||
      value["rotationKey"] !== rotationKey ||
      typeof value["duplicate"] !== "boolean")
    throw new TypeError("owner recovery receipt differs");
  return {
    grantRef: value["grantRef"], ownerEpoch: prior.ownerEpoch,
    authorityRevision: prior.revision + 1n,
    credentialGeneration: prior.generation + 1n,
    duplicate: value["duplicate"],
  };
}

function readCurrentOwner(config: TrustedOwnerRecoveryConfig): Snapshot {
  const path = join(config.stateDirectory, "podbay.sqlite");
  const file = lstatSync(path);
  if (!file.isFile() || file.uid !== process.getuid?.() ||
      (file.mode & 0o7777) !== 0o600 || file.nlink !== 1 || realpathSync(path) !== path)
    throw new TypeError("recovery store is not private and canonical");
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const value = (key: string) => {
      const row = db.prepare("SELECT value FROM metadata WHERE key=?").get(key) as { value: number } | undefined;
      if (!row || !Number.isSafeInteger(row.value) || row.value < 1) throw new TypeError("owner recovery counter unavailable");
      return BigInt(row.value);
    };
    const lineage = (db.prepare("SELECT lineage FROM store_identity WHERE singleton=1").get() as { lineage: string }).lineage;
    const actor = db.prepare("SELECT scope_id,origin,role,credential_generation,os_identity,process_identity,start_identity,containment_identity FROM authority_actors WHERE actor_id=?")
      .get(config.actorId) as Record<string, unknown> | undefined;
    const verifier = db.prepare("SELECT public_key,credential_generation,revoked FROM actor_verifiers WHERE actor_id=?")
      .get(config.actorId) as Record<string, unknown> | undefined;
    const manager = db.prepare("SELECT owner_epoch,credential_epoch FROM manager_credential_claims WHERE singleton=1")
      .get() as Record<string, unknown> | undefined;
    if (!actor || !verifier || !manager || actor["scope_id"] !== config.scopeId ||
        actor["origin"] !== "owner_cli" || actor["role"] !== "coordinator" ||
        verifier["revoked"] !== 0 || !(verifier["public_key"] instanceof Uint8Array) ||
        verifier["public_key"].length !== 32 ||
        typeof actor["credential_generation"] !== "number" ||
        actor["credential_generation"] !== verifier["credential_generation"] ||
        typeof actor["os_identity"] !== "string" || typeof actor["process_identity"] !== "string" ||
        typeof actor["start_identity"] !== "number" ||
        typeof actor["containment_identity"] !== "string")
      throw new TypeError("current owner verifier is unavailable");
    const ownerEpoch = value("owner_epoch");
    if (manager["owner_epoch"] !== Number(ownerEpoch) ||
        typeof manager["credential_epoch"] !== "number" || manager["credential_epoch"] < 1)
      throw new TypeError("manager credential claim differs");
    return {
      lineage, ownerEpoch, revision: value("authority_revision"),
      managerCredentialEpoch: BigInt(manager["credential_epoch"]),
      generation: BigInt(actor["credential_generation"]),
      publicKey: Buffer.from(verifier["public_key"]),
      osIdentity: actor["os_identity"], processIdentity: actor["process_identity"],
      startIdentity: BigInt(actor["start_identity"]), containmentIdentity: actor["containment_identity"],
    };
  } finally { db.close(); }
}

function currentProcess() {
  const stat = readFileSync("/proc/self/stat", "utf8");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
  const cgroup = readFileSync("/proc/self/cgroup", "utf8").trimEnd()
    .split("\n").find((line) => line.startsWith("0::"));
  if (!cgroup || !/^[1-9][0-9]*$/u.test(fields[19] ?? "") || typeof process.getuid !== "function")
    throw new TypeError("current owner process birth unavailable");
  return {
    osIdentity: `linux.uid.${String(process.getuid())}`,
    processIdentity: `linux.pid.${String(process.pid)}`,
    startIdentity: BigInt(fields[19]!), containmentIdentity: cgroup.slice(3),
  };
}
function sameCurrentProcess(expected: ReturnType<typeof currentProcess>): boolean {
  const current = currentProcess();
  return current.osIdentity === expected.osIdentity && current.processIdentity === expected.processIdentity &&
    current.startIdentity === expected.startIdentity && current.containmentIdentity === expected.containmentIdentity;
}
function validateConfig(config: TrustedOwnerRecoveryConfig): void {
  if (process.platform !== "linux" || typeof process.getuid !== "function" ||
      !isAbsolute(config.stateDirectory) || config.stateDirectory.includes("\0") ||
      typeof config.validateHostEndpoint !== "function" ||
      !/^[A-Za-z][A-Za-z0-9._:-]{2,159}$/u.test(config.actorId) ||
      !/^[A-Za-z][A-Za-z0-9._:-]{2,159}$/u.test(config.scopeId) ||
      !/^[A-Za-z0-9._:-]{3,160}$/u.test(config.credentialRef))
    throw new TypeError("trusted owner recovery config is invalid");
  const dir = lstatSync(config.stateDirectory);
  if (!dir.isDirectory() || dir.uid !== process.getuid() ||
      (dir.mode & 0o7777) !== 0o700 || realpathSync(config.stateDirectory) !== config.stateDirectory)
    throw new TypeError("owner recovery state directory is not private");
}
function counter(value: bigint): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(value);
  return bytes;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

class FrameSocket {
  readonly #socket: Socket;
  #pending = Buffer.alloc(0);
  readonly #frames: Buffer[] = [];
  readonly #readers: Array<{ resolve: (value: Buffer) => void; reject: (error: Error) => void }> = [];
  #ended = false;
  private constructor(socket: Socket) {
    this.#socket = socket;
    socket.on("data", (chunk: Buffer) => {
      this.#pending = Buffer.concat([this.#pending, chunk]);
      while (this.#pending.length >= 4) {
        const size = this.#pending.readUInt32BE(0);
        if (size < 1 || size > MAX_FRAME) { this.#socket.destroy(); return; }
        if (this.#pending.length < size + 4) break;
        const frame = Buffer.from(this.#pending.subarray(4, size + 4));
        this.#pending = this.#pending.subarray(size + 4);
        const reader = this.#readers.shift();
        if (reader) reader.resolve(frame); else this.#frames.push(frame);
      }
    });
    socket.on("end", () => { this.#ended = true; this.#failReaders(); });
    socket.on("error", () => { this.#ended = true; this.#failReaders(); });
    socket.on("close", () => { this.#ended = true; this.#failReaders(); });
  }
  static async connect(path: string): Promise<FrameSocket> {
    const socket = createConnection({ path });
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { socket.destroy(); reject(new Error("recovery connection timeout")); }, IO_TIMEOUT_MS);
      socket.once("connect", () => { clearTimeout(timer); socket.off("error", reject); resolve(); });
      socket.once("error", (error) => { clearTimeout(timer); reject(error); });
    });
    return new FrameSocket(socket);
  }
  async read(): Promise<Buffer> {
    const ready = this.#frames.shift();
    if (ready) return ready;
    if (this.#ended) throw new Error("recovery response ended");
    return new Promise<Buffer>((resolve, reject) => {
      const reader = { resolve, reject };
      this.#readers.push(reader);
      const timer = setTimeout(() => { this.#readers.splice(this.#readers.indexOf(reader), 1); reject(new Error("recovery read timeout")); }, IO_TIMEOUT_MS);
      reader.resolve = (value) => { clearTimeout(timer); resolve(value); };
      reader.reject = (error) => { clearTimeout(timer); reject(error); };
    });
  }
  write(value: Buffer): Promise<void> {
    if (value.length < 1 || value.length > MAX_FRAME) return Promise.reject(new TypeError("recovery frame bound"));
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(value.length, 0);
    return new Promise((resolve, reject) => this.#socket.write(Buffer.concat([prefix, value]), (error) => error ? reject(error) : resolve()));
  }
  async waitEnd(): Promise<void> {
    if (this.#ended) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("recovery EOF timeout")), IO_TIMEOUT_MS);
      this.#socket.once("end", () => { clearTimeout(timer); resolve(); });
    });
  }
  close(): void { this.#socket.destroy(); }
  #failReaders(): void {
    for (const reader of this.#readers.splice(0)) reader.reject(new Error("recovery response ended"));
  }
}
