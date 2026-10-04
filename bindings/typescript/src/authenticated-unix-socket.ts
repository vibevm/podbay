/** One authenticated PodBay/1 exchange over a caller-pinned local Unix socket. */
import { createConnection, type Socket } from "node:net";
import { isAbsolute } from "node:path";

import { MAX_FRAME_BYTES, decodeFrame, type WireTransport } from "./generated.ts";

const AUTH_PROTOCOL = "podbay.auth/1";
const CHALLENGE_DOMAIN = Buffer.from("podbay.actor-credential.challenge\0", "ascii");
const CHALLENGE_VERSION = 1;
const MAX_SELECTOR_BYTES = 512;
const MAX_CHALLENGE_BYTES = 8_192;
const SIGNATURE_BYTES = 64;
const ACK_BYTES = Buffer.from('{"protocol":"podbay.auth/1","ok":true}', "ascii");
const MAX_U64 = (1n << 64n) - 1n;

export type AuthenticatedSocketFailureStage = "before_request_write" | "possible_effect";
export type AuthenticatedSocketFailureCode =
  | "invalid_request_frame"
  | "connect_failed"
  | "handshake_timeout"
  | "exchange_timeout"
  | "invalid_challenge"
  | "challenge_mismatch"
  | "signer_rejected"
  | "invalid_signature"
  | "invalid_ack"
  | "auth_lost"
  | "request_write_failed"
  | "lost_reply"
  | "invalid_response_frame"
  | "trailing_frame";

/** Auth failures happen before request input; all request writes are uncertain. */
export class AuthenticatedSocketTransportError extends Error {
  readonly code: AuthenticatedSocketFailureCode;
  readonly stage: AuthenticatedSocketFailureStage;

  constructor(
    code: AuthenticatedSocketFailureCode,
    stage: AuthenticatedSocketFailureStage,
  ) {
    super(`authenticated PodBay socket exchange failed: ${code}`);
    this.name = "AuthenticatedSocketTransportError";
    this.code = code;
    this.stage = stage;
  }
}

export type ActorChallengeOrigin =
  | { readonly kind: "owner-cli" }
  | { readonly kind: "pod"; readonly podId: string; readonly incarnation: bigint };

/** Exact trusted expectations; counters are bigint to preserve all u64 values. */
export interface ExpectedActorChallenge {
  readonly actorId: string;
  readonly storeLineage: string;
  readonly scopeId: string;
  readonly credentialGeneration: bigint;
  readonly osIdentity: string;
  readonly processIdentity: string;
  readonly startIdentity: bigint;
  readonly containmentIdentity: string;
  readonly origin: ActorChallengeOrigin;
}

/** Canonical transcript bytes and strictly decoded fields presented to the signer. */
export interface CanonicalActorChallenge extends ExpectedActorChallenge {
  readonly bytes: Uint8Array;
  readonly nonce: Uint8Array;
}

export interface AuthenticatedUnixSocketOptions {
  readonly socketPath: string;
  readonly expected: ExpectedActorChallenge;
  /**
   * Validate the expected host endpoint out of band and refuse any unwanted
   * transcript before signing. This must not be a generic signing oracle.
   */
  readonly validateAndSign: (
    challenge: CanonicalActorChallenge,
  ) => Uint8Array | Promise<Uint8Array>;
  /** Absolute limit from connection attempt through the exact auth ACK. */
  readonly handshakeTimeoutMs?: number;
  /** Absolute limit from auth ACK through one complete reply and peer EOF. */
  readonly exchangeTimeoutMs?: number;
}

type Phase = "connecting" | "challenge" | "signing" | "ack" | "response" | "reply_complete";

/** Authenticates before writing one request; never retries uncertain input. */
export class AuthenticatedUnixSocketWireTransport implements WireTransport {
  readonly #socketPath: string;
  readonly #expected: ExpectedActorChallenge;
  readonly #validateAndSign: AuthenticatedUnixSocketOptions["validateAndSign"];
  readonly #handshakeTimeoutMs: number;
  readonly #exchangeTimeoutMs: number;
  readonly #selector: Buffer;

  constructor(options: AuthenticatedUnixSocketOptions) {
    if (!isAbsolute(options.socketPath) || options.socketPath.includes("\0"))
      throw new TypeError("socketPath must be an absolute Unix socket path");
    if (typeof options.validateAndSign !== "function")
      throw new TypeError("validateAndSign must be a callback");
    this.#socketPath = options.socketPath;
    this.#expected = copyAndValidateExpected(options.expected);
    this.#validateAndSign = options.validateAndSign;
    this.#handshakeTimeoutMs = deadline(options.handshakeTimeoutMs, 5_000, 60_000);
    this.#exchangeTimeoutMs = deadline(options.exchangeTimeoutMs, 30_000, 300_000);
    this.#selector = frameRaw(
      Buffer.from(JSON.stringify({ protocol: AUTH_PROTOCOL, actorId: this.#expected.actorId }), "ascii"),
    );
    if (this.#selector.length - 4 > MAX_SELECTOR_BYTES)
      throw new RangeError("auth selector exceeds bound");
  }

  exchange(frame: Uint8Array): Promise<Uint8Array> {
    let request: Buffer;
    try {
      decodeFrame(frame);
      request = Buffer.from(frame);
    } catch {
      return Promise.reject(
        new AuthenticatedSocketTransportError("invalid_request_frame", "before_request_write"),
      );
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      let socket: Socket | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let phase: Phase = "connecting";
      let deadlineAt = performance.now() + this.#handshakeTimeoutMs;
      let settled = false;
      let requestWriteAttempted = false;
      let pending = Buffer.alloc(0);
      let frameBytes: number | undefined;
      let reply: Buffer | undefined;

      const finish = (result: Uint8Array | AuthenticatedSocketTransportError) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        socket?.destroy();
        if (result instanceof AuthenticatedSocketTransportError) reject(result);
        else resolve(result);
      };
      const fail = (code: AuthenticatedSocketFailureCode) =>
        finish(new AuthenticatedSocketTransportError(
          code,
          requestWriteAttempted ? "possible_effect" : "before_request_write",
        ));
      const arm = (milliseconds: number, code: AuthenticatedSocketFailureCode) => {
        if (timer !== undefined) clearTimeout(timer);
        deadlineAt = performance.now() + milliseconds;
        timer = setTimeout(() => fail(code), milliseconds);
      };
      const expired = () => performance.now() >= deadlineAt;
      const write = (bytes: Uint8Array, code: AuthenticatedSocketFailureCode) => {
        try {
          socket!.write(bytes, (error?: Error | null) => {
            if (error && !settled) fail(code);
          });
        } catch {
          fail(code);
        }
      };
      const sendRequest = () => {
        if (expired()) {
          fail("handshake_timeout");
          return;
        }
        pending = Buffer.alloc(0);
        frameBytes = undefined;
        phase = "response";
        arm(this.#exchangeTimeoutMs, "exchange_timeout");
        requestWriteAttempted = true;
        write(request, "request_write_failed");
      };
      const acceptChallenge = (bytes: Buffer) => {
        const challenge = parseChallenge(bytes);
        if (!challenge) {
          fail("invalid_challenge");
          return;
        }
        if (!matchesExpected(challenge, this.#expected)) {
          fail("challenge_mismatch");
          return;
        }
        phase = "signing";
        const signerBytes = Uint8Array.from(bytes);
        const presented: CanonicalActorChallenge = {
          ...challenge,
          bytes: signerBytes,
          nonce: Uint8Array.from(challenge.nonce),
        };
        Promise.resolve()
          .then(() => this.#validateAndSign(presented))
          .then((signature) => {
            if (settled) return;
            if (expired()) {
              fail("handshake_timeout");
              return;
            }
            if (!Buffer.from(signerBytes).equals(bytes) ||
                !(signature instanceof Uint8Array) || signature.length !== SIGNATURE_BYTES) {
              fail("invalid_signature");
              return;
            }
            pending = Buffer.alloc(0);
            frameBytes = undefined;
            phase = "ack";
            write(frameRaw(Buffer.from(signature)), "auth_lost");
          })
          .catch(() => fail("signer_rejected"));
      };
      const onFrame = (bytes: Buffer) => {
        if (phase === "challenge") {
          acceptChallenge(bytes);
        } else if (phase === "ack") {
          if (!bytes.equals(ACK_BYTES)) {
            fail("invalid_ack");
            return;
          }
          sendRequest();
        } else if (phase === "response") {
          reply = Buffer.from(pending);
          phase = "reply_complete";
          // Wait for EOF so a later extra frame cannot be mistaken for success.
        }
      };
      const onData = (chunk: Buffer) => {
        if (settled) return;
        if (expired()) {
          fail(requestWriteAttempted ? "exchange_timeout" : "handshake_timeout");
          return;
        }
        if (phase === "reply_complete") {
          fail("trailing_frame");
          return;
        }
        if (phase !== "challenge" && phase !== "ack" && phase !== "response") {
          fail("trailing_frame");
          return;
        }
        const maximum = phase === "challenge" ? MAX_CHALLENGE_BYTES :
          phase === "ack" ? ACK_BYTES.length : MAX_FRAME_BYTES;
        const malformed = phase === "challenge" ? "invalid_challenge" :
          phase === "ack" ? "invalid_ack" : "invalid_response_frame";
        if (pending.length + chunk.length > maximum + 4) {
          fail("trailing_frame");
          return;
        }
        pending = Buffer.concat([pending, chunk]);
        if (frameBytes === undefined && pending.length >= 4) {
          const length = pending.readUInt32BE(0);
          if (length === 0 || length > maximum) {
            fail(malformed);
            return;
          }
          frameBytes = length + 4;
        }
        if (frameBytes === undefined) return;
        if (pending.length > frameBytes) {
          fail("trailing_frame");
          return;
        }
        if (pending.length === frameBytes) onFrame(pending.subarray(4));
      };

      arm(this.#handshakeTimeoutMs, "handshake_timeout");
      try {
        socket = createConnection({ path: this.#socketPath });
      } catch {
        fail("connect_failed");
        return;
      }
      socket.once("connect", () => {
        if (settled) return;
        if (expired()) {
          fail("handshake_timeout");
          return;
        }
        phase = "challenge";
        write(this.#selector, "auth_lost");
      });
      socket.on("data", onData);
      socket.once("error", () => fail(phase === "connecting" ? "connect_failed" :
        requestWriteAttempted ? "lost_reply" : "auth_lost"));
      socket.once("end", () => {
        if (phase === "reply_complete" && reply !== undefined) {
          if (expired()) {
            fail("exchange_timeout");
            return;
          }
          try {
            decodeFrame(reply);
            finish(new Uint8Array(reply));
          } catch {
            fail("invalid_response_frame");
          }
        } else {
          fail(requestWriteAttempted ? "lost_reply" : "auth_lost");
        }
      });
      socket.once("close", () => {
        if (!settled) fail(requestWriteAttempted ? "lost_reply" : "auth_lost");
      });
    });
  }
}

function deadline(value: number | undefined, fallback: number, maximum: number): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum)
    throw new RangeError("deadline must be a finite positive millisecond count");
  return selected;
}

function frameRaw(payload: Uint8Array): Buffer {
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32BE(payload.length, 0);
  frame.set(payload, 4);
  return frame;
}

function graphic(value: string, maximum: number): boolean {
  return value.length > 0 && value.length <= maximum &&
    [...value].every((char) => char.charCodeAt(0) >= 0x21 && char.charCodeAt(0) <= 0x7e);
}

function counter(value: bigint): boolean {
  return typeof value === "bigint" && value > 0n && value <= MAX_U64;
}

function copyAndValidateExpected(input: ExpectedActorChallenge): ExpectedActorChallenge {
  if (!input || typeof input !== "object" ||
      typeof input.actorId !== "string" || !/^[A-Za-z0-9._:-]{3,256}$/.test(input.actorId) ||
      typeof input.storeLineage !== "string" || !graphic(input.storeLineage, 256) ||
      typeof input.scopeId !== "string" || !graphic(input.scopeId, 256) ||
      !counter(input.credentialGeneration) ||
      typeof input.osIdentity !== "string" || !graphic(input.osIdentity, 256) ||
      typeof input.processIdentity !== "string" || !graphic(input.processIdentity, 256) ||
      !counter(input.startIdentity) ||
      typeof input.containmentIdentity !== "string" || !graphic(input.containmentIdentity, 4096))
    throw new TypeError("expected actor challenge is incomplete or invalid");
  const origin = input.origin;
  if (!origin || typeof origin !== "object")
    throw new TypeError("expected actor origin is invalid");
  if (origin.kind === "owner-cli") return { ...input, origin: { kind: "owner-cli" } };
  if (origin.kind === "pod" && typeof origin.podId === "string" &&
      graphic(origin.podId, 256) && counter(origin.incarnation))
    return { ...input, origin: { kind: "pod", podId: origin.podId, incarnation: origin.incarnation } };
  throw new TypeError("expected actor origin is invalid");
}

function parseChallenge(bytes: Buffer): CanonicalActorChallenge | undefined {
  if (bytes.length > MAX_CHALLENGE_BYTES ||
      !bytes.subarray(0, CHALLENGE_DOMAIN.length).equals(CHALLENGE_DOMAIN) ||
      bytes[CHALLENGE_DOMAIN.length] !== CHALLENGE_VERSION) return undefined;
  let at = CHALLENGE_DOMAIN.length + 1;
  const field = (tag: number, maximum: number): Buffer | undefined => {
    if (at + 3 > bytes.length || bytes[at] !== tag) return undefined;
    const length = bytes.readUInt16BE(at + 1);
    if (length === 0 || length > maximum || at + 3 + length > bytes.length) return undefined;
    const value = bytes.subarray(at + 3, at + 3 + length);
    at += 3 + length;
    return value;
  };
  const text = (tag: number, maximum: number): string | undefined => {
    const value = field(tag, maximum);
    if (!value || !value.every((byte) => byte >= 0x21 && byte <= 0x7e)) return undefined;
    return value.toString("ascii");
  };
  const number = (tag: number): bigint | undefined => {
    const value = field(tag, 8);
    if (!value || value.length !== 8) return undefined;
    const parsed = value.readBigUInt64BE(0);
    return parsed > 0n ? parsed : undefined;
  };
  const nonce = field(1, 32);
  if (!nonce || nonce.length !== 32 || nonce.every((byte) => byte === 0)) return undefined;
  const storeLineage = text(2, 256);
  const actorId = text(3, 256);
  const scopeId = text(4, 256);
  const credentialGeneration = number(5);
  const platform = field(6, 1);
  const osIdentity = text(7, 256);
  const processIdentity = text(8, 256);
  const startIdentity = number(9);
  const containmentIdentity = text(10, 4096);
  const originKind = field(11, 1);
  if (!storeLineage || !actorId || !scopeId || credentialGeneration === undefined ||
      !platform || platform.length !== 1 || platform[0] !== 1 || !osIdentity ||
      !processIdentity || startIdentity === undefined || !containmentIdentity ||
      !originKind || originKind.length !== 1) return undefined;
  let origin: ActorChallengeOrigin;
  if (originKind[0] === 1) origin = { kind: "owner-cli" };
  else if (originKind[0] === 2) {
    const podId = text(12, 256);
    const incarnation = number(13);
    if (!podId || incarnation === undefined) return undefined;
    origin = { kind: "pod", podId, incarnation };
  } else return undefined;
  if (at !== bytes.length) return undefined;
  return {
    bytes: Uint8Array.from(bytes), nonce: Uint8Array.from(nonce),
    storeLineage, actorId, scopeId, credentialGeneration, osIdentity,
    processIdentity, startIdentity, containmentIdentity, origin,
  };
}

function matchesExpected(actual: CanonicalActorChallenge, expected: ExpectedActorChallenge): boolean {
  return actual.actorId === expected.actorId &&
    actual.storeLineage === expected.storeLineage && actual.scopeId === expected.scopeId &&
    actual.credentialGeneration === expected.credentialGeneration &&
    actual.osIdentity === expected.osIdentity && actual.processIdentity === expected.processIdentity &&
    actual.startIdentity === expected.startIdentity &&
    actual.containmentIdentity === expected.containmentIdentity &&
    actual.origin.kind === expected.origin.kind &&
    (actual.origin.kind === "owner-cli" ||
      (expected.origin.kind === "pod" && actual.origin.podId === expected.origin.podId &&
       actual.origin.incarnation === expected.origin.incarnation));
}
