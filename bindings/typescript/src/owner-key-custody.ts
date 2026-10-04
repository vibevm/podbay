/** Owner-only key custody for a future proof-bearing owner rotation. */
import { createPrivateKey, createPublicKey, randomBytes, sign, type KeyObject } from "node:crypto";
import { constants as fsConstants, closeSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";

const SCHEMA = "podbay.owner-key-custody/1";
const FILE_NAME = "owner-key-custody.json";
const PROOF_DOMAIN = Buffer.from("podbay.owner-key-custody.continuity/1\0", "ascii");
const MAX_FILE_BYTES = 8_192;
const MAX_U64 = (1n << 64n) - 1n;
const RECORD_KEYS = [
  "actorId", "authorityRevision", "containmentIdentity", "credentialRef",
  "osIdentity", "ownerEpoch", "privateKeyPkcs8", "processIdentity",
  "publicKey", "schema", "scopeId", "startIdentity", "storeLineage",
] as const;

export interface OwnerKeyCustodyBinding {
  readonly actorId: string;
  readonly scopeId: string;
  readonly storeLineage: string;
  readonly credentialRef: string;
  readonly ownerEpoch: bigint;
  readonly authorityRevision: bigint;
  readonly osIdentity: string;
  /** Historical key origin. After cross-process enrollment, consult the store for current actor birth. */
  readonly processIdentity: string;
  readonly startIdentity: bigint;
  readonly containmentIdentity: string;
}

export interface LoadedOwnerKeyCustody {
  readonly binding: OwnerKeyCustodyBinding;
  readonly publicKey: Uint8Array;
  /** Test-only continuity proof. It is not a manager auth or rotation signature. */
  proveContinuity(nonce: Uint8Array): Uint8Array;
}

/** Private temporary write, no-clobber publication, and directory fsync precede any signature. */
export function persistOwnerKeyCustody(
  path: string,
  binding: OwnerKeyCustodyBinding,
  privateKey: KeyObject,
): void {
  validateBinding(binding);
  assertCurrentLinuxBirth(binding);
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519")
    throw new TypeError("owner custody requires one Ed25519 private key");
  const directory = pinnedPrivateDirectory(path);
  try {
    reconcileOrphanTemps(path, directory);
    const publicKey = rawPublicKey(privateKey);
    const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
    if (!Buffer.isBuffer(pkcs8) || pkcs8.length < 32 || pkcs8.length > 256)
      throw new TypeError("owner private key encoding is invalid");
    const record = {
      schema: SCHEMA,
      actorId: binding.actorId,
      scopeId: binding.scopeId,
      storeLineage: binding.storeLineage,
      credentialRef: binding.credentialRef,
      ownerEpoch: binding.ownerEpoch.toString(),
      authorityRevision: binding.authorityRevision.toString(),
      osIdentity: binding.osIdentity,
      processIdentity: binding.processIdentity,
      startIdentity: binding.startIdentity.toString(),
      containmentIdentity: binding.containmentIdentity,
      publicKey: publicKey.toString("base64url"),
      privateKeyPkcs8: pkcs8.toString("base64"),
    };
    const bytes = Buffer.from(JSON.stringify(record), "utf8");
    if (bytes.length > MAX_FILE_BYTES) throw new TypeError("owner custody record exceeds bound");
    if (entryExists(path)) throw new TypeError("owner custody final key already exists");
    const temporary = `${path}.tmp.${String(process.pid)}.${binding.startIdentity.toString()}.${randomBytes(16).toString("hex")}`;
    const file = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    let identity: { dev: number; ino: number };
    try {
      const metadata = fstatSync(file);
      if (!metadata.isFile() || metadata.uid !== process.getuid?.() ||
          (metadata.mode & 0o7777) !== 0o600 || metadata.nlink !== 1)
        throw new TypeError("owner custody temporary file identity differs");
      identity = { dev: metadata.dev, ino: metadata.ino };
      writeFileSync(file, bytes);
      fsyncSync(file);
    } finally { closeSync(file); }
    try {
      linkSync(temporary, path);
    } finally {
      const current = lstatSync(temporary);
      if (!current.isFile() || current.dev !== identity.dev || current.ino !== identity.ino ||
          current.uid !== process.getuid?.() || (current.mode & 0o7777) !== 0o600 ||
          current.nlink < 1 || current.nlink > 2)
        throw new TypeError("owner custody temporary file changed before unlink");
      unlinkSync(temporary);
    }
    fsyncSync(directory);
    const loaded = loadOwnerKeyMaterial(path, binding);
    if (!Buffer.from(loaded.publicKey).equals(publicKey))
      throw new TypeError("owner custody published key differs");
  } finally { closeSync(directory); }
}

/** Fail closed on path, owner, binding, encoding, or key mismatch. */
function loadOwnerKeyMaterial(
  path: string,
  expected: Pick<OwnerKeyCustodyBinding, "actorId" | "scopeId" | "storeLineage">,
): LoadedOwnerKeyCustody & { readonly privateKey: KeyObject } {
  const directory = pinnedPrivateDirectory(path);
  try {
    const file = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    let bytes: Buffer;
    try {
      const before = fstatSync(file);
      if (!before.isFile() || before.uid !== process.getuid?.() ||
          (before.mode & 0o7777) !== 0o600 || before.nlink !== 1 ||
          before.size < 1 || before.size > MAX_FILE_BYTES || realpathSync(path) !== path)
        throw new TypeError("owner custody file is not private and canonical");
      bytes = readFileSync(file);
      const after = fstatSync(file);
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
          before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs ||
          bytes.length !== before.size)
        throw new TypeError("owner custody file changed during read");
    } finally { closeSync(file); }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value: unknown = JSON.parse(text);
    if (!isRecord(value) || JSON.stringify(value) !== text ||
        Object.keys(value).sort().join("\0") !== [...RECORD_KEYS].sort().join("\0") ||
        value["schema"] !== SCHEMA ||
        value["actorId"] !== expected.actorId || value["scopeId"] !== expected.scopeId ||
        value["storeLineage"] !== expected.storeLineage ||
        !isGraphic(value["credentialRef"], 256) || !isGraphic(value["osIdentity"], 256) ||
        !isGraphic(value["processIdentity"], 256) ||
        !isGraphic(value["containmentIdentity"], 4096) ||
        !isCounter(value["ownerEpoch"]) || !isCounter(value["authorityRevision"]) ||
        !isCounter(value["startIdentity"]) ||
        typeof value["publicKey"] !== "string" || typeof value["privateKeyPkcs8"] !== "string")
      throw new TypeError("owner custody binding is invalid");
    const encoded = value["privateKeyPkcs8"];
    if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded) || Buffer.from(encoded, "base64").toString("base64") !== encoded)
      throw new TypeError("owner custody private key encoding is invalid");
    const privateKey = createPrivateKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "pkcs8" });
    if (privateKey.asymmetricKeyType !== "ed25519")
      throw new TypeError("owner custody key algorithm differs");
    const publicKey = rawPublicKey(privateKey);
    if (publicKey.toString("base64url") !== value["publicKey"])
      throw new TypeError("owner custody public verifier differs");
    const binding: OwnerKeyCustodyBinding = {
      actorId: expected.actorId, scopeId: expected.scopeId, storeLineage: expected.storeLineage,
      credentialRef: value["credentialRef"], ownerEpoch: BigInt(value["ownerEpoch"]),
      authorityRevision: BigInt(value["authorityRevision"]), osIdentity: value["osIdentity"],
      processIdentity: value["processIdentity"], startIdentity: BigInt(value["startIdentity"]),
      containmentIdentity: value["containmentIdentity"],
    };
    return {
      binding,
      publicKey: new Uint8Array(publicKey),
      privateKey,
      proveContinuity(nonce) {
        if (!(nonce instanceof Uint8Array) || nonce.length !== 32 || nonce.every((byte) => byte === 0))
          throw new TypeError("owner custody continuity nonce is invalid");
        return new Uint8Array(sign(null, Buffer.concat([PROOF_DOMAIN, nonce]), privateKey));
      },
    };
  } finally { closeSync(directory); }
}

export function loadOwnerKeyCustody(
  path: string,
  expected: Pick<OwnerKeyCustodyBinding, "actorId" | "scopeId" | "storeLineage">,
): LoadedOwnerKeyCustody {
  const material = loadOwnerKeyMaterial(path, expected);
  return {
    binding: material.binding,
    publicKey: material.publicKey,
    proveContinuity: (nonce) => material.proveContinuity(nonce),
  };
}

/** Trusted local recovery code must validate the full host transcript before calling this signer. */
export function loadOwnerKeyForRecovery(
  path: string,
  expected: Pick<OwnerKeyCustodyBinding, "actorId" | "scopeId" | "storeLineage">,
  expectedPublicKey: Uint8Array,
): { readonly publicKey: Uint8Array; signVerifiedTranscript(bytes: Uint8Array): Uint8Array } {
  const material = loadOwnerKeyMaterial(path, expected);
  if (!(expectedPublicKey instanceof Uint8Array) || expectedPublicKey.length !== 32 ||
      !Buffer.from(material.publicKey).equals(Buffer.from(expectedPublicKey)))
    throw new TypeError("owner recovery verifier differs from custody");
  return {
    publicKey: material.publicKey,
    signVerifiedTranscript(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.length < 32 || bytes.length > 8_192 ||
          !Buffer.from(bytes).subarray(0, "podbay.owner-recovery/1\0".length)
            .equals(Buffer.from("podbay.owner-recovery/1\0", "ascii")))
        throw new TypeError("owner recovery transcript domain is invalid");
      return new Uint8Array(sign(null, Buffer.from(bytes), material.privateKey));
    },
  };
}

/**
 * Reuse the exact pre-enrollment key after a cut before first setup proof.
 * A different process is admitted only after the prior PID and birth are gone.
 * This does not authorize rotation of an already enrolled owner actor.
 * Later rotation must verify the current actor binding from the durable store;
 * the saved process birth is only the origin of these key bytes.
 */
export function recoverOwnerKeyForInitialEnrollment(
  path: string,
  expected: OwnerKeyCustodyBinding,
  generatedPublicKey: Uint8Array,
): { readonly privateKey: KeyObject; readonly publicKey: Uint8Array } {
  validateBinding(expected);
  assertCurrentLinuxBirth(expected);
  const cleanupDirectory = pinnedPrivateDirectory(path);
  try { reconcileOrphanTemps(path, cleanupDirectory); }
  finally { closeSync(cleanupDirectory); }
  const material = loadOwnerKeyMaterial(path, expected);
  const prior = material.binding;
  if (prior.credentialRef !== expected.credentialRef ||
      prior.ownerEpoch !== expected.ownerEpoch ||
      prior.authorityRevision !== expected.authorityRevision ||
      prior.osIdentity !== expected.osIdentity)
    throw new TypeError("owner custody enrollment expectation differs");
  const sameBirth = prior.processIdentity === expected.processIdentity &&
    prior.startIdentity === expected.startIdentity &&
    prior.containmentIdentity === expected.containmentIdentity;
  if (sameBirth) {
    if (!Buffer.from(material.publicKey).equals(Buffer.from(generatedPublicKey)))
      throw new TypeError("another live owner client generated a different key");
  } else if (priorProcessStillLive(prior)) {
    throw new TypeError("prior owner process is still live");
  }
  const directory = pinnedPrivateDirectory(path);
  try {
    const file = openSync(path, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
    try {
      const metadata = fstatSync(file);
      if (!metadata.isFile() || metadata.uid !== process.getuid?.() ||
          (metadata.mode & 0o7777) !== 0o600 || metadata.nlink !== 1)
        throw new TypeError("owner custody file changed before sync");
      fsyncSync(file);
    } finally { closeSync(file); }
    fsyncSync(directory);
  } finally { closeSync(directory); }
  const verified = loadOwnerKeyMaterial(path, expected);
  if (!Buffer.from(verified.publicKey).equals(Buffer.from(material.publicKey)) ||
      verified.binding.processIdentity !== prior.processIdentity ||
      verified.binding.startIdentity !== prior.startIdentity)
    throw new TypeError("owner custody changed during recovery");
  return { privateKey: verified.privateKey, publicKey: verified.publicKey };
}

/**
 * Stages the next owner key under an exact generation directory without
 * replacing any prior-generation key. The store's current actor generation
 * and verifier, not a local pointer, decide which generation is authoritative.
 */
export function stageNextOwnerKeyCustody(
  stateDirectory: string,
  nextGeneration: bigint,
  binding: OwnerKeyCustodyBinding,
  generatedKey: KeyObject,
): { readonly path: string; readonly privateKey: KeyObject; readonly publicKey: Uint8Array } {
  if (nextGeneration < 2n || nextGeneration > MAX_U64 ||
      !isAbsolute(stateDirectory) || stateDirectory.includes("\0"))
    throw new TypeError("next owner custody generation or state directory is invalid");
  const state = lstatSync(stateDirectory);
  if (!state.isDirectory() || state.uid !== process.getuid?.() ||
      (state.mode & 0o7777) !== 0o700 || realpathSync(stateDirectory) !== stateDirectory)
    throw new TypeError("next owner custody state directory is not canonical and private");
  const parent = openSync(stateDirectory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try {
    const pinned = fstatSync(parent);
    if (pinned.dev !== state.dev || pinned.ino !== state.ino)
      throw new TypeError("next owner custody state directory changed");
    const directory = join(stateDirectory, `owner-generation-${nextGeneration.toString()}`);
    try { mkdirSync(directory, { mode: 0o700 }); }
    catch (error) {
      if (!isRecord(error) || error["code"] !== "EEXIST") throw error;
    }
    const child = lstatSync(directory);
    if (!child.isDirectory() || child.uid !== state.uid ||
        (child.mode & 0o7777) !== 0o700 || realpathSync(directory) !== directory)
      throw new TypeError("next owner custody generation directory differs");
    fsyncSync(parent);
    const publicKey = rawPublicKey(generatedKey);
    const keyDirectory = join(directory, `key-${publicKey.toString("hex")}`);
    try { mkdirSync(keyDirectory, { mode: 0o700 }); }
    catch (error) {
      if (!isRecord(error) || error["code"] !== "EEXIST") throw error;
    }
    const keyDir = lstatSync(keyDirectory);
    if (!keyDir.isDirectory() || keyDir.uid !== state.uid ||
        (keyDir.mode & 0o7777) !== 0o700 || realpathSync(keyDirectory) !== keyDirectory)
      throw new TypeError("next owner key directory differs");
    const generationFd = openSync(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
    try { fsyncSync(generationFd); } finally { closeSync(generationFd); }
    const path = join(keyDirectory, FILE_NAME);
    let selected: { readonly privateKey: KeyObject; readonly publicKey: Uint8Array };
    try {
      persistOwnerKeyCustody(path, binding, generatedKey);
      selected = { privateKey: generatedKey, publicKey: new Uint8Array(publicKey) };
    } catch {
      selected = recoverOwnerKeyForInitialEnrollment(path, binding, publicKey);
    }
    publishNextPublicReceipt(keyDirectory, nextGeneration, binding, selected.publicKey);
    return { path, ...selected };
  } finally { closeSync(parent); }
}

function publishNextPublicReceipt(
  directory: string, generation: bigint, binding: OwnerKeyCustodyBinding, publicKey: Uint8Array,
): void {
  const record = {
    schema: "podbay.owner-next-public/1", actorId: binding.actorId,
    scopeId: binding.scopeId, storeLineage: binding.storeLineage,
    credentialGeneration: generation.toString(),
    ownerEpoch: binding.ownerEpoch.toString(),
    authorityRevision: binding.authorityRevision.toString(),
    osIdentity: binding.osIdentity, processIdentity: binding.processIdentity,
    startIdentity: binding.startIdentity.toString(),
    containmentIdentity: binding.containmentIdentity,
    publicKey: Buffer.from(publicKey).toString("base64url"),
  };
  const bytes = Buffer.from(JSON.stringify(record), "utf8");
  const path = join(directory, "owner-next-public.json");
  const parent = openSync(directory, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  try {
    for (const name of readdirSync(directory)) {
      const match = /^owner-next-public\.json\.tmp\.([1-9][0-9]*)\.([1-9][0-9]*)\.([a-f0-9]{32})$/u.exec(name);
      if (!match) continue;
      const live = processBirthStillLive(match[1]!, BigInt(match[2]!));
      if (live && match[1] !== String(process.pid)) continue;
      const temporary = join(directory, name);
      const orphan = lstatSync(temporary);
      if (!orphan.isFile() || orphan.uid !== process.getuid?.() ||
          (orphan.mode & 0o7777) !== 0o600 || orphan.nlink < 1 || orphan.nlink > 2)
        throw new TypeError("next owner public receipt temporary differs");
      if (live && orphan.nlink === 1) continue;
      if (orphan.nlink === 2) {
        const final = lstatSync(path);
        if (!final.isFile() || final.dev !== orphan.dev || final.ino !== orphan.ino ||
            final.nlink !== 2 || final.uid !== orphan.uid || (final.mode & 0o7777) !== 0o600)
          throw new TypeError("next owner public receipt link differs");
      }
      unlinkSync(temporary);
      fsyncSync(parent);
    }
    if (!entryExists(path)) {
      const temporary = `${path}.tmp.${String(process.pid)}.${binding.startIdentity.toString()}.${randomBytes(16).toString("hex")}`;
      const file = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
      try { writeFileSync(file, bytes); fsyncSync(file); }
      finally { closeSync(file); }
      try { linkSync(temporary, path); }
      finally { unlinkSync(temporary); }
      fsyncSync(parent);
    }
    const file = openSync(path, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
    try {
      const metadata = fstatSync(file);
      if (!metadata.isFile() || metadata.uid !== process.getuid?.() ||
          (metadata.mode & 0o7777) !== 0o600 || metadata.nlink !== 1 ||
          metadata.size !== bytes.length || realpathSync(path) !== path ||
          !readFileSync(file).equals(bytes))
        throw new TypeError("next owner public receipt differs");
      fsyncSync(file);
    } finally { closeSync(file); }
    fsyncSync(parent);
  } finally { closeSync(parent); }
}

export function ownerKeyContinuityChallenge(nonce: Uint8Array): Uint8Array {
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32 || nonce.every((byte) => byte === 0))
    throw new TypeError("owner custody continuity nonce is invalid");
  return new Uint8Array(Buffer.concat([PROOF_DOMAIN, nonce]));
}

function pinnedPrivateDirectory(path: string): number {
  if (process.platform !== "linux" || typeof process.getuid !== "function" ||
      !isAbsolute(path) || basename(path) !== FILE_NAME || path.includes("\0"))
    throw new TypeError("owner custody path is invalid");
  const parent = dirname(path);
  const before = lstatSync(parent);
  if (!before.isDirectory() || before.uid !== process.getuid() ||
      (before.mode & 0o7777) !== 0o700 || realpathSync(parent) !== parent)
    throw new TypeError("owner custody parent is not canonical and private");
  const descriptor = openSync(parent, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW);
  const pinned = fstatSync(descriptor);
  if (pinned.dev !== before.dev || pinned.ino !== before.ino) {
    closeSync(descriptor);
    throw new TypeError("owner custody parent changed");
  }
  return descriptor;
}

function reconcileOrphanTemps(path: string, directory: number): void {
  const parent = dirname(path);
  let changed = false;
  for (const name of readdirSync(parent)) {
    const match = /^owner-key-custody\.json\.tmp\.([1-9][0-9]*)\.([1-9][0-9]*)\.([a-f0-9]{32})$/u.exec(name);
    if (!match) continue;
    const live = processBirthStillLive(match[1]!, BigInt(match[2]!));
    const temporary = join(parent, name);
    const metadata = lstatSync(temporary);
    if (!metadata.isFile() || metadata.uid !== process.getuid?.() ||
        (metadata.mode & 0o7777) !== 0o600 ||
        metadata.nlink < 1 || metadata.nlink > 2 || realpathSync(temporary) !== temporary)
      throw new TypeError("owner custody orphan temporary file is not private and canonical");
    if (live && (match[1] !== String(process.pid) || metadata.nlink === 1)) continue;
    if (metadata.nlink === 2) {
      const final = lstatSync(path);
      if (!final.isFile() || final.dev !== metadata.dev || final.ino !== metadata.ino ||
          final.uid !== metadata.uid || (final.mode & 0o7777) !== 0o600 || final.nlink !== 2)
        throw new TypeError("owner custody published hard link differs from orphan");
    }
    unlinkSync(temporary);
    changed = true;
  }
  if (changed) fsyncSync(directory);
}

function entryExists(path: string): boolean {
  try { lstatSync(path); return true; }
  catch (error) {
    if (isRecord(error) && error["code"] === "ENOENT") return false;
    throw error;
  }
}

function priorProcessStillLive(binding: OwnerKeyCustodyBinding): boolean {
  const match = /^linux\.pid\.([1-9][0-9]*)$/u.exec(binding.processIdentity);
  if (!match) return true;
  return processBirthStillLive(match[1]!, binding.startIdentity);
}

function processBirthStillLive(pid: string, expectedStart: bigint): boolean {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const end = stat.lastIndexOf(")");
    if (end < 0) return true;
    const start = stat.slice(end + 2).trim().split(/\s+/u)[19];
    return start === undefined || !/^[1-9][0-9]*$/u.test(start) ||
      BigInt(start) === expectedStart;
  } catch (error) {
    return !isRecord(error) || error["code"] !== "ENOENT";
  }
}

function assertCurrentLinuxBirth(binding: OwnerKeyCustodyBinding): void {
  if (typeof process.getuid !== "function")
    throw new TypeError("owner custody requires Linux process identity");
  const stat = readFileSync("/proc/self/stat", "utf8");
  const end = stat.lastIndexOf(")");
  const start = end < 0 ? undefined : stat.slice(end + 2).trim().split(/\s+/u)[19];
  const cgroups = readFileSync("/proc/self/cgroup", "utf8").trimEnd()
    .split("\n").filter((line) => line.startsWith("0::"));
  if (start === undefined || !/^[1-9][0-9]*$/u.test(start) || cgroups.length !== 1 ||
      binding.osIdentity !== `linux.uid.${String(process.getuid())}` ||
      binding.processIdentity !== `linux.pid.${String(process.pid)}` ||
      binding.startIdentity !== BigInt(start) ||
      binding.containmentIdentity !== cgroups[0]!.slice(3))
    throw new TypeError("owner custody process birth differs from current Linux process");
}

function rawPublicKey(privateKey: KeyObject): Buffer {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string")
    throw new TypeError("owner custody verifier is invalid");
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32 || raw.every((byte) => byte === 0))
    throw new TypeError("owner custody verifier is invalid");
  return raw;
}

function validateBinding(binding: OwnerKeyCustodyBinding): void {
  if (![binding.actorId, binding.scopeId, binding.storeLineage, binding.credentialRef,
        binding.osIdentity, binding.processIdentity].every((value) => isGraphic(value, 256)) ||
      !isGraphic(binding.containmentIdentity, 4096) ||
      ![binding.ownerEpoch, binding.authorityRevision, binding.startIdentity].every((value) =>
        typeof value === "bigint" && value > 0n && value <= MAX_U64))
    throw new TypeError("owner custody binding is invalid");
}

function isGraphic(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum &&
    [...value].every((char) => char.charCodeAt(0) >= 0x21 && char.charCodeAt(0) <= 0x7e);
}
function isCounter(value: unknown): value is string {
  return typeof value === "string" && /^[1-9][0-9]*$/u.test(value) &&
    BigInt(value) <= MAX_U64;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
