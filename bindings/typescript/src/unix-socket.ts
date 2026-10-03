/** One PodBay/1 framed exchange over a caller-selected local Unix socket. */
import { createConnection, type Socket } from "node:net";
import { isAbsolute } from "node:path";

import { MAX_FRAME_BYTES, decodeFrame, type WireTransport } from "./generated.ts";

export type SocketTransportFailureStage = "before_write" | "possible_effect";
export type SocketTransportFailureCode =
  | "invalid_request_frame"
  | "connect_failed"
  | "connect_timeout"
  | "write_failed"
  | "write_timeout"
  | "read_timeout"
  | "lost_reply"
  | "invalid_response_frame";

/** Once write begins, a transport failure cannot establish whether PodBay acted. */
export class SocketTransportError extends Error {
  readonly code: SocketTransportFailureCode;
  readonly stage: SocketTransportFailureStage;

  constructor(
    code: SocketTransportFailureCode,
    stage: SocketTransportFailureStage,
    message: string,
  ) {
    super(message);
    this.name = "SocketTransportError";
    this.code = code;
    this.stage = stage;
  }
}

export interface UnixSocketTransportOptions {
  readonly socketPath: string;
  readonly connectTimeoutMs?: number;
  readonly writeTimeoutMs?: number;
  readonly readTimeoutMs?: number;
}

/** The caller owns endpoint discovery, authentication, and command-key recovery. */
export class UnixSocketWireTransport implements WireTransport {
  readonly #socketPath: string;
  readonly #connectTimeoutMs: number;
  readonly #writeTimeoutMs: number;
  readonly #readTimeoutMs: number;

  constructor(options: UnixSocketTransportOptions) {
    if (!isAbsolute(options.socketPath) || options.socketPath.includes("\0"))
      throw new TypeError("socketPath must be an absolute Unix socket path");
    this.#socketPath = options.socketPath;
    this.#connectTimeoutMs = deadline(options.connectTimeoutMs, 3_000, "connectTimeoutMs");
    this.#writeTimeoutMs = deadline(options.writeTimeoutMs, 5_000, "writeTimeoutMs");
    this.#readTimeoutMs = deadline(options.readTimeoutMs, 30_000, "readTimeoutMs");
  }

  exchange(frame: Uint8Array): Promise<Uint8Array> {
    try {
      decodeFrame(frame);
    } catch {
      return Promise.reject(
        new SocketTransportError(
          "invalid_request_frame",
          "before_write",
          "request is not one bounded frame",
        ),
      );
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      let socket: Socket | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let settled = false;
      let writeAttempted = false;
      let response = Buffer.alloc(0);
      let expectedBytes: number | undefined;

      const finish = (result: Uint8Array | SocketTransportError) => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        socket?.destroy();
        if (result instanceof SocketTransportError) reject(result);
        else resolve(result);
      };
      const fail = (code: SocketTransportFailureCode, message: string) =>
        finish(
          new SocketTransportError(
            code,
            writeAttempted ? "possible_effect" : "before_write",
            message,
          ),
        );
      const arm = (milliseconds: number, code: SocketTransportFailureCode, message: string) => {
        if (timer !== undefined) clearTimeout(timer);
        timer = setTimeout(() => fail(code, message), milliseconds);
      };

      try {
        socket = createConnection({ path: this.#socketPath });
      } catch {
        fail("connect_failed", "local socket connection failed");
        return;
      }
      arm(this.#connectTimeoutMs, "connect_timeout", "local socket connection timed out");
      socket.once("connect", () => {
        if (settled) return;
        writeAttempted = true;
        arm(this.#writeTimeoutMs, "write_timeout", "request frame write timed out");
        try {
          socket!.write(frame, (error?: Error | null) => {
            if (settled) return;
            if (error !== undefined && error !== null) {
              fail("write_failed", "request frame write failed");
              return;
            }
            arm(this.#readTimeoutMs, "read_timeout", "response frame read timed out");
          });
        } catch {
          fail("write_failed", "request frame write failed");
        }
      });
      socket.on("data", (chunk: Buffer) => {
        if (settled) return;
        if (!writeAttempted) {
          fail("invalid_response_frame", "response arrived before request write");
          return;
        }
        if (response.length + chunk.length > MAX_FRAME_BYTES + 4) {
          fail("invalid_response_frame", "response frame exceeds bound");
          return;
        }
        response = Buffer.concat([response, chunk]);
        if (expectedBytes === undefined && response.length >= 4) {
          const declared = response.readUInt32BE(0);
          if (declared === 0 || declared > MAX_FRAME_BYTES) {
            fail("invalid_response_frame", "response frame exceeds bound");
            return;
          }
          expectedBytes = declared + 4;
        }
        if (expectedBytes === undefined) return;
        if (response.length > expectedBytes) {
          fail("invalid_response_frame", "response contains trailing bytes");
          return;
        }
        if (response.length === expectedBytes) finish(new Uint8Array(response));
      });
      socket.once("error", () => {
        fail(
          writeAttempted ? "lost_reply" : "connect_failed",
          writeAttempted ? "socket failed before a complete reply" : "local socket connection failed",
        );
      });
      socket.once("end", () => fail("lost_reply", "socket closed before a complete reply"));
      socket.once("close", () => fail("lost_reply", "socket closed before a complete reply"));
    });
  }
}

function deadline(value: number | undefined, fallback: number, name: string): number {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > 300_000)
    throw new RangeError(`${name} must be a finite millisecond deadline`);
  return selected;
}
