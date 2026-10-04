/** One process-owned Linux owner enrollment before the manager socket opens. */
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { createConnection, type Socket } from "node:net";
import { basename, dirname, isAbsolute } from "node:path";

import {
  matchesCanonicalActorChallenge,
  type AuthenticatedUnixSocketOptions,
} from "./authenticated-unix-socket.ts";

const DOMAIN = Buffer.from("podbay.owner-initial-enrollment/1\0", "ascii");
const PROTOCOL = "podbay.owner-initial-enrollment/1";
const RIGHTS = Buffer.from(
  "launch_pod.scope+use_credential.exact+send_session.scope",
  "ascii",
);
const GENERATION = "owner_cli.coordinator.generation1";
const MAX_U64 = (1n << 64n) - 1n;
const MAX_CHALLENGE = 8_192;
const MAX_RECEIPT = 2_048;
const IO_LIMIT_MS = 5_000;
const TOTAL_LIMIT_MS = 20_000;
const RECEIPT_KEYS = [
  "actorId", "authorityRevision", "duplicate", "grantRef", "ownerEpoch", "protocol", "scopeId",
] as const;

export const INITIAL_OWNER_RIGHTS_DIGEST = createHash("sha256").update(RIGHTS).digest("hex");

export interface TrustedOwnerSetupExpectations {
  readonly setupSocketPath: string;
  readonly managerSocketPath: string;
  readonly actorId: string;
  readonly scopeId: string;
  readonly credentialRef: string;
  readonly storeLineage: string;
  readonly ownerEpoch: bigint;
  readonly authorityRevision: bigint;
  readonly osIdentity: string;
  readonly processIdentity: string;
  readonly startIdentity: bigint;
  readonly containmentIdentity: string;
  readonly rightsDigest: string;
  /** Independently verify the pinned manager endpoint before each signature. */
  readonly validateHostEndpoint: (phase: "setup" | "auth") => boolean | Promise<boolean>;
  readonly totalTimeoutMs?: number;
  /** Opt-in owner-only key custody, written before any setup signature. */
  readonly ownerKeyCustodyPath?: string;
}

export interface InitialOwnerSetupReceipt {
  readonly protocol: typeof PROTOCOL;
  readonly actorId: string;
  readonly scopeId: string;
  readonly grantRef: string;
  readonly ownerEpoch: bigint;
  readonly authorityRevision: bigint;
  readonly duplicate: boolean;
}

export type OwnerSetupFailureStage = "before_signature" | "possible_enrollment";
export type OwnerSetupFailureCode =
  | "connect_failed" | "timeout" | "invalid_challenge" | "endpoint_refused"
  | "lost_receipt" | "invalid_receipt" | "lost_ack" | "trailing_frame"
  | "reconciliation_failed";

export class OwnerSetupError extends Error {
  readonly code: OwnerSetupFailureCode;
  readonly stage: OwnerSetupFailureStage;
  constructor(code: OwnerSetupFailureCode, stage: OwnerSetupFailureStage) {
    super(`PodBay initial owner setup failed: ${code}`);
    this.name = "OwnerSetupError";
    this.code = code;
    this.stage = stage;
  }
}

type Expected = Omit<TrustedOwnerSetupExpectations, "totalTimeoutMs"> & {
  readonly totalTimeoutMs: number;
};

/** Private KeyObject remains in this process and is never exported. */
export class InitialOwnerSetupClient {
  readonly #expected: Expected;
  readonly #privateKey: KeyObject;
  readonly #publicKey: Buffer;
  #started = false;
  #receipt: InitialOwnerSetupReceipt | undefined;
  #observedReceipt: InitialOwnerSetupReceipt | undefined;
  #seenNonce: Buffer | undefined;
  #custodyPrepared = false;

  constructor(input: TrustedOwnerSetupExpectations) {
    this.#expected = validateExpected(input);
    const pair = generateKeyPairSync("ed25519");
    this.#privateKey = pair.privateKey;
    const jwk = pair.publicKey.export({ format: "jwk" });
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string")
      throw new TypeError("Node did not produce an Ed25519 public key");
    this.#publicKey = Buffer.from(jwk.x, "base64url");
    if (this.#publicKey.length !== 32)
      throw new TypeError("Node Ed25519 public key has the wrong length");
  }

  /** Durably pins the generated key before any setup signature is possible. */
  async prepareOwnerKeyCustody(): Promise<void> {
    if (this.#custodyPrepared || this.#expected.ownerKeyCustodyPath === undefined) return;
    const { persistOwnerKeyCustody } = await import("./owner-key-custody.ts");
    persistOwnerKeyCustody(this.#expected.ownerKeyCustodyPath, this.#expected, this.#privateKey);
    this.#custodyPrepared = true;
  }

  /** One setup, with one same-key retry only after a lost receipt or ACK. */
  async enroll(): Promise<InitialOwnerSetupReceipt> {
    if (this.#receipt) return this.#receipt;
    if (this.#started) throw new OwnerSetupError("reconciliation_failed", "possible_enrollment");
    this.#started = true;
    await this.prepareOwnerKeyCustody();
    const deadline = performance.now() + this.#expected.totalTimeoutMs;
    try {
      this.#receipt = await this.#attempt(deadline, false);
    } catch (error) {
      if (!(error instanceof OwnerSetupError) ||
          (error.code !== "lost_receipt" && error.code !== "lost_ack")) throw error;
      try {
        this.#receipt = await this.#attempt(deadline, true);
      } catch {
        throw new OwnerSetupError("reconciliation_failed", "possible_enrollment");
      }
    }
    return this.#receipt;
  }

  /**
   * Retains this process's key after an uncertain setup so a trusted caller
   * can reconcile against the normal manager endpoint. This callback signs
   * only a freshly parsed, exact auth/1 challenge for this same process.
   */
  authenticatedChannel(): AuthenticatedUnixSocketOptions {
    const expected = this.#expected;
    const actor = {
      actorId: expected.actorId,
      storeLineage: expected.storeLineage,
      scopeId: expected.scopeId,
      credentialGeneration: 1n,
      osIdentity: expected.osIdentity,
      processIdentity: expected.processIdentity,
      startIdentity: expected.startIdentity,
      containmentIdentity: expected.containmentIdentity,
      origin: { kind: "owner-cli" as const },
    };
    return {
      socketPath: expected.managerSocketPath,
      expected: actor,
      validateAndSign: async (challenge) => {
        assertCurrentProcess(expected);
        if (!matchesCanonicalActorChallenge(challenge, actor) ||
            await expected.validateHostEndpoint("auth") !== true)
          throw new TypeError("manager auth challenge or endpoint differs");
        return new Uint8Array(sign(null, Buffer.from(challenge.bytes), this.#privateKey));
      },
    };
  }

  #attempt(deadline: number, reconciliation: boolean): Promise<InitialOwnerSetupReceipt> {
    const expected = this.#expected;
    const publicKey = this.#publicKey;
    return new Promise((resolve, reject) => {
      let socket: Socket | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let phase: "connecting" | "challenge" | "signing" | "receipt" | "ack_wait" = "connecting";
      let pending = Buffer.alloc(0);
      let frameLength: number | undefined;
      let settled = false;
      let signatureAttempted = false;
      let ackWriteCompleted = false;
      let peerEnded = false;
      let receipt: InitialOwnerSetupReceipt | undefined;

      const finish = (value: InitialOwnerSetupReceipt | OwnerSetupError) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        socket?.destroy();
        if (value instanceof OwnerSetupError) reject(value);
        else resolve(value);
      };
      const fail = (code: OwnerSetupFailureCode) =>
        finish(new OwnerSetupError(code, signatureAttempted ? "possible_enrollment" : "before_signature"));
      const arm = () => {
        if (timer !== undefined) clearTimeout(timer);
        const remaining = Math.min(IO_LIMIT_MS, deadline - performance.now());
        if (remaining <= 0) {
          fail(signatureAttempted ? phase === "ack_wait" ? "lost_ack" : "lost_receipt" : "timeout");
          return;
        }
        timer = setTimeout(
          () => fail(signatureAttempted ? phase === "ack_wait" ? "lost_ack" : "lost_receipt" : "timeout"),
          remaining,
        );
      };
      const write = (bytes: Buffer, code: OwnerSetupFailureCode) => {
        try {
          socket!.write(bytes, (error?: Error | null) => { if (error && !settled) fail(code); });
        } catch {
          fail(code);
        }
      };
      const nextFrame = () => {
        pending = Buffer.alloc(0);
        frameLength = undefined;
        arm();
      };
      const acceptChallenge = (bytes: Buffer) => {
        const nonce = setupChallengeNonce(bytes, expected, publicKey);
        if (!nonce || this.#seenNonce?.equals(nonce)) {
          fail("invalid_challenge");
          return;
        }
        this.#seenNonce = Buffer.from(nonce);
        phase = "signing";
        nextFrame();
        Promise.resolve()
          .then(() => expected.validateHostEndpoint("setup"))
          .then((trusted) => {
            if (settled) return;
            if (trusted !== true) { fail("endpoint_refused"); return; }
            assertCurrentProcess(expected);
            const signature = sign(null, bytes, this.#privateKey);
            if (signature.length !== 64) { fail("invalid_challenge"); return; }
            signatureAttempted = true;
            phase = "receipt";
            nextFrame();
            write(frame(signature), "lost_receipt");
          })
          .catch(() => fail("endpoint_refused"));
      };
      const onFrame = (bytes: Buffer) => {
        if (phase === "challenge") acceptChallenge(bytes);
        else if (phase === "receipt") {
          try {
            receipt = parseReceipt(bytes, expected, reconciliation);
            if (this.#observedReceipt &&
                (this.#observedReceipt.actorId !== receipt.actorId ||
                 this.#observedReceipt.scopeId !== receipt.scopeId ||
                 this.#observedReceipt.grantRef !== receipt.grantRef ||
                 this.#observedReceipt.ownerEpoch !== receipt.ownerEpoch ||
                 this.#observedReceipt.authorityRevision !== receipt.authorityRevision))
              throw new TypeError("reconciled owner receipt differs");
            this.#observedReceipt = receipt;
          } catch {
            fail("invalid_receipt");
            return;
          }
          phase = "ack_wait";
          nextFrame();
          try {
            socket!.write(frame(Buffer.from("ack", "ascii")), (error?: Error | null) => {
              if (error && !settled) fail("lost_ack");
              else {
                ackWriteCompleted = true;
                if (peerEnded && receipt) finish(receipt);
              }
            });
          } catch {
            fail("lost_ack");
          }
        }
      };
      const onData = (chunk: Buffer) => {
        if (settled) return;
        if (phase !== "challenge" && phase !== "receipt") {
          fail("trailing_frame");
          return;
        }
        const maximum = phase === "challenge" ? MAX_CHALLENGE : MAX_RECEIPT;
        if (pending.length + chunk.length > maximum + 4) { fail("trailing_frame"); return; }
        pending = Buffer.concat([pending, chunk]);
        if (frameLength === undefined && pending.length >= 4) {
          const size = pending.readUInt32BE(0);
          if (size === 0 || size > maximum) {
            fail(phase === "challenge" ? "invalid_challenge" : "invalid_receipt");
            return;
          }
          frameLength = size + 4;
        }
        if (frameLength === undefined) return;
        if (pending.length > frameLength) { fail("trailing_frame"); return; }
        if (pending.length === frameLength) onFrame(pending.subarray(4));
      };
      arm();
      try {
        socket = createConnection({ path: expected.setupSocketPath });
      } catch {
        fail("connect_failed");
        return;
      }
      socket.once("connect", () => {
        if (settled) return;
        phase = "challenge";
        nextFrame();
        write(frame(publicKey), "connect_failed");
      });
      socket.on("data", onData);
      socket.once("error", () => {
        fail(signatureAttempted ? phase === "ack_wait" ? "lost_ack" : "lost_receipt" : "connect_failed");
      });
      socket.once("end", () => {
        peerEnded = true;
        if (phase === "ack_wait" && receipt) {
          if (ackWriteCompleted) finish(receipt);
        } else fail(signatureAttempted ? "lost_receipt" : "invalid_challenge");
      });
      socket.once("close", () => {
        if (!settled) {
          if (phase === "ack_wait" && receipt && ackWriteCompleted && peerEnded) finish(receipt);
          else fail(signatureAttempted ? phase === "ack_wait" ? "lost_ack" : "lost_receipt" : "connect_failed");
        }
      });
    });
  }
}

function validateExpected(input: TrustedOwnerSetupExpectations): Expected {
  if (process.platform !== "linux" || typeof process.getuid !== "function")
    throw new TypeError("initial owner setup requires Linux");
  if (!isAbsolute(input.setupSocketPath) || basename(input.setupSocketPath) !== "owner-setup.sock" ||
      !isAbsolute(input.managerSocketPath) || basename(input.managerSocketPath) !== "manager.sock" ||
      dirname(input.setupSocketPath) !== dirname(input.managerSocketPath) ||
      input.setupSocketPath.includes("\0") || input.managerSocketPath.includes("\0") ||
      (input.ownerKeyCustodyPath !== undefined &&
       (!isAbsolute(input.ownerKeyCustodyPath) ||
        basename(input.ownerKeyCustodyPath) !== "owner-key-custody.json" ||
        dirname(input.ownerKeyCustodyPath) !== dirname(input.setupSocketPath))) ||
      !graphic(input.actorId, 256) || !graphic(input.scopeId, 256) ||
      !graphic(input.credentialRef, 256) || !graphic(input.storeLineage, 256) ||
      !counter(input.ownerEpoch) || !counter(input.authorityRevision) ||
      input.authorityRevision === MAX_U64 ||
      !graphic(input.osIdentity, 256) || !graphic(input.processIdentity, 256) ||
      !counter(input.startIdentity) || !graphic(input.containmentIdentity, 4096) ||
      !/^[0-9a-f]{64}$/u.test(input.rightsDigest) ||
      input.rightsDigest !== INITIAL_OWNER_RIGHTS_DIGEST ||
      typeof input.validateHostEndpoint !== "function")
    throw new TypeError("trusted initial owner expectations are incomplete or invalid");
  const selected = input.totalTimeoutMs ?? TOTAL_LIMIT_MS;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > TOTAL_LIMIT_MS)
    throw new RangeError("owner setup timeout exceeds protocol bound");
  const expected = { ...input, totalTimeoutMs: selected };
  assertCurrentProcess(expected);
  return expected;
}

function assertCurrentProcess(expected: Pick<Expected,
  "osIdentity" | "processIdentity" | "startIdentity" | "containmentIdentity">): void {
  const uid = process.getuid?.();
  const pid = process.pid;
  const stat = readFileSync("/proc/self/stat", "utf8");
  const end = stat.lastIndexOf(")");
  const fields = end < 0 ? [] : stat.slice(end + 2).trim().split(/\s+/u);
  const start = fields[19];
  const cgroups = readFileSync("/proc/self/cgroup", "utf8")
    .trimEnd().split("\n").filter((line) => line.startsWith("0::"));
  if (uid === undefined || start === undefined || !/^[1-9][0-9]*$/u.test(start) ||
      cgroups.length !== 1 ||
      expected.osIdentity !== `linux.uid.${uid}` ||
      expected.processIdentity !== `linux.pid.${pid}` ||
      expected.startIdentity !== BigInt(start) ||
      expected.containmentIdentity !== cgroups[0]!.slice(3))
    throw new TypeError("trusted owner process birth differs from current Linux process");
}

function graphic(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum &&
    [...value].every((char) => char.charCodeAt(0) >= 0x21 && char.charCodeAt(0) <= 0x7e);
}
function counter(value: unknown): value is bigint {
  return typeof value === "bigint" && value > 0n && value <= MAX_U64;
}
function frame(payload: Buffer): Buffer {
  const bytes = Buffer.allocUnsafe(payload.length + 4);
  bytes.writeUInt32BE(payload.length, 0);
  bytes.set(payload, 4);
  return bytes;
}

function setupChallengeNonce(bytes: Buffer, expected: Expected, publicKey: Buffer): Buffer | undefined {
  if (bytes.length > MAX_CHALLENGE ||
      !bytes.subarray(0, DOMAIN.length).equals(DOMAIN)) return undefined;
  let at = DOMAIN.length;
  const field = (tag: number, maximum: number): Buffer | undefined => {
    if (at + 3 > bytes.length || bytes[at] !== tag) return undefined;
    const size = bytes.readUInt16BE(at + 1);
    if (size === 0 || size > maximum || at + 3 + size > bytes.length) return undefined;
    const value = bytes.subarray(at + 3, at + 3 + size);
    at += size + 3;
    return value;
  };
  const text = (tag: number, maximum: number): string | undefined => {
    const value = field(tag, maximum);
    return value && value.every((byte) => byte >= 0x21 && byte <= 0x7e)
      ? value.toString("ascii") : undefined;
  };
  const number = (tag: number): bigint | undefined => {
    const value = field(tag, 8);
    return value?.length === 8 && value.readBigUInt64BE(0) > 0n
      ? value.readBigUInt64BE(0) : undefined;
  };
  const nonce = field(1, 32);
  const lineage = text(2, 256);
  const owner = number(3);
  const revision = number(4);
  const actor = text(5, 256);
  const scope = text(6, 256);
  const generation = text(7, 64);
  const os = text(8, 256);
  const pid = text(9, 256);
  const start = number(10);
  const containment = text(11, 4096);
  const key = field(12, 32);
  const credential = text(13, 256);
  const rights = field(14, 256);
  const matches = at === bytes.length && nonce?.length === 32 && !nonce.every((byte) => byte === 0) &&
    lineage === expected.storeLineage && owner === expected.ownerEpoch &&
    revision === expected.authorityRevision && actor === expected.actorId &&
    scope === expected.scopeId && generation === GENERATION &&
    os === expected.osIdentity && pid === expected.processIdentity &&
    start === expected.startIdentity && containment === expected.containmentIdentity &&
    key?.length === 32 && key.equals(publicKey) && credential === expected.credentialRef &&
    rights !== undefined && createHash("sha256").update(rights).digest("hex") === expected.rightsDigest;
  return matches ? nonce : undefined;
}

function parseReceipt(bytes: Buffer, expected: Expected, reconciliation: boolean): InitialOwnerSetupReceipt {
  if (bytes.length === 0 || bytes.length > MAX_RECEIPT) throw new TypeError("receipt bound");
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const value: unknown = JSON.parse(raw);
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("receipt object");
  const item = value as Record<string, unknown>;
  if (JSON.stringify(item) !== raw ||
      Object.keys(item).sort().join("\0") !== [...RECEIPT_KEYS].sort().join("\0") ||
      item.protocol !== PROTOCOL || item.actorId !== expected.actorId ||
      item.scopeId !== expected.scopeId || item.duplicate !== reconciliation ||
      typeof item.grantRef !== "string" || !/^grant\.[1-9][0-9]*$/u.test(item.grantRef) ||
      typeof item.ownerEpoch !== "string" || !/^[1-9][0-9]*$/u.test(item.ownerEpoch) ||
      typeof item.authorityRevision !== "string" || !/^[1-9][0-9]*$/u.test(item.authorityRevision) ||
      BigInt(item.ownerEpoch) !== expected.ownerEpoch ||
      BigInt(item.authorityRevision) !== expected.authorityRevision + 1n)
    throw new TypeError("receipt differs from trusted setup");
  return {
    protocol: PROTOCOL,
    actorId: expected.actorId,
    scopeId: expected.scopeId,
    grantRef: item.grantRef,
    ownerEpoch: expected.ownerEpoch,
    authorityRevision: expected.authorityRevision + 1n,
    duplicate: reconciliation,
  };
}
