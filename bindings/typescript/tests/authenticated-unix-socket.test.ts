import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { decodeFrame, encodeFrame } from "../src/generated.ts";
import {
  AuthenticatedSocketTransportError,
  AuthenticatedUnixSocketWireTransport,
  type AuthenticatedUnixSocketOptions,
  type ExpectedActorChallenge,
} from "../src/authenticated-unix-socket.ts";

const expected: ExpectedActorChallenge = {
  actorId: "actor.owner",
  storeLineage: "lineage.one",
  scopeId: "scope.one",
  credentialGeneration: 3n,
  osIdentity: "1000",
  processIdentity: "4321",
  startIdentity: 987654321n,
  containmentIdentity: "0::/podbay/fixture",
  origin: { kind: "owner-cli" },
};
const signature = Uint8Array.from({ length: 64 }, (_, index) => index + 1);
const ack = Buffer.from('{"protocol":"podbay.auth/1","ok":true}', "ascii");
const request = encodeFrame({ protocol: "podbay/1", operation: "fixture.read" });
const reply = Buffer.from(encodeFrame({ protocol: "podbay/1", requestId: "request.1", ok: {} }));

test("authenticates before one PodBay request and accepts fragmented challenge, ACK and reply", async (t) => {
  let selectorSeen = false;
  let signatureSeen = false;
  let requests = 0;
  const done = deferred();
  const socketPath = await fakeServer(t, async (socket) => {
    const frames = new Frames(socket);
    const selector = await frames.next();
    assert.equal(selector.toString("ascii"), '{"protocol":"podbay.auth/1","actorId":"actor.owner"}');
    selectorSeen = true;
    const challenge = frame(challengeBytes());
    socket.write(challenge.subarray(0, 2));
    socket.write(challenge.subarray(2, 17));
    socket.write(challenge.subarray(17));
    assert.deepEqual(await frames.next(), Buffer.from(signature));
    signatureSeen = true;
    const framedAck = frame(ack);
    socket.write(framedAck.subarray(0, 4));
    socket.write(framedAck.subarray(4));
    const wireRequest = await frames.next();
    requests += 1;
    assert.deepEqual(wireRequest, Buffer.from(decodeFrame(request)));
    socket.write(reply.subarray(0, 3));
    socket.end(reply.subarray(3));
    done.resolve();
  });
  let signerCalls = 0;
  const transport = client(socketPath, (challenge) => {
    signerCalls += 1;
    assert.deepEqual(challenge.bytes, new Uint8Array(challengeBytes()));
    assert.equal(challenge.actorId, expected.actorId);
    assert.equal(challenge.startIdentity, expected.startIdentity);
    return signature;
  });
  assert.deepEqual(await transport.exchange(request), new Uint8Array(reply));
  await done.promise;
  assert.equal(selectorSeen, true);
  assert.equal(signatureSeen, true);
  assert.equal(requests, 1);
  assert.equal(signerCalls, 1);
});

test("wrong or malformed canonical challenge refuses before signer or PodBay request", async (t) => {
  for (const [bad, code] of [
    [challengeBytes({ storeLineage: "foreign.lineage" }), "challenge_mismatch"],
    [Buffer.concat([challengeBytes(), Buffer.from([99, 0, 1, 1])]), "invalid_challenge"],
  ] as const) {
    const closed = deferred();
    let serverFrames: Frames | undefined;
    const socketPath = await fakeServer(t, async (socket) => {
      const frames = new Frames(socket);
      serverFrames = frames;
      await frames.next();
      socket.once("close", closed.resolve);
      socket.write(frame(bad));
    });
    let signerCalls = 0;
    const transport = client(socketPath, () => {
      signerCalls += 1;
      return signature;
    });
    await assert.rejects(
      () => transport.exchange(request),
      failure(code, "before_request_write"),
    );
    await closed.promise;
    assert.equal(signerCalls, 0);
    assert.equal(serverFrames?.receivedCount, 1);
  }
});

test("pod origin and incarnation are exact before signing", async (t) => {
  const podExpected: ExpectedActorChallenge = {
    ...expected,
    actorId: "actor.pod",
    origin: { kind: "pod", podId: "pod.one", incarnation: 7n },
  };
  const socketPath = await fakeServer(t, async (socket) => {
    const frames = new Frames(socket);
    await frames.next();
    socket.write(frame(challengeBytes(podExpected)));
    assert.deepEqual(await frames.next(), Buffer.from(signature));
    socket.write(frame(ack));
    await frames.next();
    socket.end(reply);
  });
  const transport = new AuthenticatedUnixSocketWireTransport({
    socketPath,
    expected: podExpected,
    validateAndSign: (challenge) => {
      assert.deepEqual(challenge.origin, podExpected.origin);
      return signature;
    },
  });
  assert.deepEqual(await transport.exchange(request), new Uint8Array(reply));
});

test("callback refusal and lost ACK never write PodBay request", async (t) => {
  const refusedClose = deferred();
  const refusedPath = await fakeServer(t, async (socket) => {
    const frames = new Frames(socket);
    await frames.next();
    socket.once("close", refusedClose.resolve);
    socket.write(frame(challengeBytes()));
  });
  await assert.rejects(
    () => client(refusedPath, () => { throw new Error("host endpoint not trusted"); }).exchange(request),
    failure("signer_rejected", "before_request_write"),
  );
  await refusedClose.promise;

  const lostAckClose = deferred();
  let signatureSeen = false;
  const lostAckPath = await fakeServer(t, async (socket) => {
    const frames = new Frames(socket);
    await frames.next();
    socket.once("close", lostAckClose.resolve);
    socket.write(frame(challengeBytes()));
    assert.deepEqual(await frames.next(), Buffer.from(signature));
    signatureSeen = true;
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(frames.receivedCount, 2, "request was not written before ACK");
    socket.destroy();
  });
  await assert.rejects(
    () => client(lostAckPath, () => signature).exchange(request),
    failure("auth_lost", "before_request_write"),
  );
  await lostAckClose.promise;
  assert.equal(signatureSeen, true);
});

test("malformed ACK and trailing auth bytes fail before PodBay request", async (t) => {
  for (const payload of [
    frame(Buffer.from('{"ok":true,"protocol":"podbay.auth/1"}', "ascii")),
    Buffer.concat([frame(ack), Buffer.from([0, 0, 0, 1, 88])]),
  ]) {
    const closed = deferred();
    const socketPath = await fakeServer(t, async (socket) => {
      const frames = new Frames(socket);
      await frames.next();
      socket.write(frame(challengeBytes()));
      await frames.next();
      socket.once("close", closed.resolve);
      socket.write(payload);
    });
    await assert.rejects(
      () => client(socketPath, () => signature).exchange(request),
      failure(payload.length > frame(ack).length ? "trailing_frame" : "invalid_ack", "before_request_write"),
    );
    await closed.promise;
  }
});

test("lost reply and trailing reply are possible-effect with no automatic retry", async (t) => {
  for (const tail of [undefined, Buffer.from([0, 0, 0, 1, 88])]) {
    let connections = 0;
    let requests = 0;
    const closed = deferred();
    const socketPath = await fakeServer(t, async (socket) => {
      connections += 1;
      const frames = new Frames(socket);
      await frames.next();
      socket.write(frame(challengeBytes()));
      await frames.next();
      socket.write(frame(ack));
      assert.deepEqual(await frames.next(), Buffer.from(decodeFrame(request)));
      requests += 1;
      socket.once("close", closed.resolve);
      if (tail) socket.end(Buffer.concat([reply, tail]));
      else socket.destroy();
    });
    await assert.rejects(
      () => client(socketPath, () => signature).exchange(request),
      failure(tail ? "trailing_frame" : "lost_reply", "possible_effect"),
    );
    await closed.promise;
    assert.equal(connections, 1);
    assert.equal(requests, 1);
  }
});

test("handshake and exchange deadlines are absolute, and invalid request fails before connection", async (t) => {
  let connections = 0;
  const socketPath = await fakeServer(t, async (socket) => {
    connections += 1;
    const frames = new Frames(socket);
    await frames.next();
    // No challenge: the handshake timer must close this connection.
  });
  const transport = client(socketPath, () => signature, { handshakeTimeoutMs: 40 });
  await assert.rejects(
    () => transport.exchange(new Uint8Array([0, 0, 0, 1])),
    failure("invalid_request_frame", "before_request_write"),
  );
  assert.equal(connections, 0);
  await assert.rejects(() => transport.exchange(request), failure("handshake_timeout", "before_request_write"));
  assert.equal(connections, 1);

  const exchangePath = await fakeServer(t, async (socket) => {
    const frames = new Frames(socket);
    await frames.next();
    socket.write(frame(challengeBytes()));
    await frames.next();
    socket.write(frame(ack));
    await frames.next();
    socket.write(reply.subarray(0, 2));
    // Partial reply cannot extend the absolute exchange deadline.
  });
  await assert.rejects(
    () => client(exchangePath, () => signature, { exchangeTimeoutMs: 40 }).exchange(request),
    failure("exchange_timeout", "possible_effect"),
  );
});

test("oversized challenge and stalled validation fail before request input", async (t) => {
  const oversizedPath = await fakeServer(t, async (socket) => {
    const frames = new Frames(socket);
    await frames.next();
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(8_193);
    socket.write(prefix);
  });
  await assert.rejects(
    () => client(oversizedPath, () => signature).exchange(request),
    failure("invalid_challenge", "before_request_write"),
  );

  let serverFrames: Frames | undefined;
  const stalledPath = await fakeServer(t, async (socket) => {
    serverFrames = new Frames(socket);
    await serverFrames.next();
    socket.write(frame(challengeBytes()));
  });
  await assert.rejects(
    () => client(stalledPath, () => new Promise<Uint8Array>(() => undefined),
      { handshakeTimeoutMs: 40 }).exchange(request),
    failure("handshake_timeout", "before_request_write"),
  );
  assert.equal(serverFrames?.receivedCount, 1);
});

function client(
  socketPath: string,
  validateAndSign: AuthenticatedUnixSocketOptions["validateAndSign"],
  limits: Partial<Pick<AuthenticatedUnixSocketOptions, "handshakeTimeoutMs" | "exchangeTimeoutMs">> = {},
): AuthenticatedUnixSocketWireTransport {
  return new AuthenticatedUnixSocketWireTransport({ socketPath, expected, validateAndSign, ...limits });
}

function failure(
  code: AuthenticatedSocketTransportError["code"],
  stage: AuthenticatedSocketTransportError["stage"],
) {
  return (error: unknown): boolean => {
    assert.equal(error instanceof AuthenticatedSocketTransportError, true);
    if (!(error instanceof AuthenticatedSocketTransportError)) return false;
    assert.equal(error.code, code);
    assert.equal(error.stage, stage);
    return true;
  };
}

function challengeBytes(changes: Partial<ExpectedActorChallenge> = {}): Buffer {
  const value = { ...expected, ...changes };
  const number = (counter: bigint) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(counter);
    return bytes;
  };
  const field = (tag: number, body: Buffer | string) => {
    const bytes = typeof body === "string" ? Buffer.from(body, "ascii") : body;
    const header = Buffer.alloc(3);
    header[0] = tag;
    header.writeUInt16BE(bytes.length, 1);
    return Buffer.concat([header, bytes]);
  };
  const parts = [
    Buffer.from("podbay.actor-credential.challenge\0", "ascii"),
    Buffer.from([1]),
    field(1, Buffer.alloc(32, 7)),
    field(2, value.storeLineage),
    field(3, value.actorId),
    field(4, value.scopeId),
    field(5, number(value.credentialGeneration)),
    field(6, Buffer.from([1])),
    field(7, value.osIdentity),
    field(8, value.processIdentity),
    field(9, number(value.startIdentity)),
    field(10, value.containmentIdentity),
    field(11, Buffer.from([value.origin.kind === "owner-cli" ? 1 : 2])),
  ];
  if (value.origin.kind === "pod") {
    parts.push(field(12, value.origin.podId), field(13, number(value.origin.incarnation)));
  }
  return Buffer.concat(parts);
}

function frame(payload: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(payload.length);
  return Buffer.concat([prefix, payload]);
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve = () => undefined;
  const promise = new Promise<void>((settle) => { resolve = settle; });
  return { promise, resolve };
}

class Frames {
  receivedCount = 0;
  readonly #queue: Buffer[] = [];
  readonly #waiting: Array<(value: Buffer) => void> = [];
  #buffer = Buffer.alloc(0);

  constructor(socket: Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      while (this.#buffer.length >= 4) {
        const size = this.#buffer.readUInt32BE(0);
        if (this.#buffer.length < size + 4) break;
        const payload = Buffer.from(this.#buffer.subarray(4, size + 4));
        this.#buffer = this.#buffer.subarray(size + 4);
        this.receivedCount += 1;
        const waiting = this.#waiting.shift();
        if (waiting) waiting(payload);
        else this.#queue.push(payload);
      }
    });
  }

  next(): Promise<Buffer> {
    const ready = this.#queue.shift();
    if (ready) return Promise.resolve(ready);
    return new Promise((resolve) => this.#waiting.push(resolve));
  }
}

async function fakeServer(t: TestContext, onConnection: (socket: Socket) => Promise<void>): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "podbay-auth-socket-"));
  const socketPath = join(directory, "wire.sock");
  const sockets = new Set<Socket>();
  const errors: unknown[] = [];
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    void onConnection(socket).catch((error) => {
      errors.push(error);
      socket.destroy();
    });
  });
  await listen(server, socketPath);
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
    assert.deepEqual(errors, []);
  });
  return socketPath;
}

function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
}
