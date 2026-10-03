import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { MAX_FRAME_BYTES, decodeFrame, encodeFrame } from "../src/generated.ts";
import {
  SocketTransportError,
  UnixSocketWireTransport,
} from "../src/unix-socket.ts";

const request = encodeFrame({ protocol: "podbay/1", operation: "fixture.read" });

test("one connection reads a fragmented response and closes after one frame", async (t) => {
  const closed = deferred();
  let connections = 0;
  const reply = Buffer.from(encodeFrame({ protocol: "podbay/1", requestId: "request.1", ok: {} }));
  const socketPath = await fakeServer(t, (socket) => {
    connections += 1;
    socket.once("close", closed.resolve);
    socket.once("data", () => {
      socket.write(reply.subarray(0, 2));
      setTimeout(() => socket.write(reply.subarray(2, 5)), 2);
      setTimeout(() => socket.write(reply.subarray(5)), 4);
    });
  });
  const transport = new UnixSocketWireTransport({ socketPath });
  const response = await transport.exchange(request);
  assert.deepEqual(response, new Uint8Array(reply));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(decodeFrame(response))), {
    protocol: "podbay/1",
    requestId: "request.1",
    ok: {},
  });
  await closed.promise;
  assert.equal(connections, 1);
});

test("rejects oversized response length after write and invalid outbound frame before write", async (t) => {
  let connections = 0;
  const socketPath = await fakeServer(t, (socket) => {
    connections += 1;
    socket.once("data", () => {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
      socket.write(header);
    });
  });
  const transport = new UnixSocketWireTransport({ socketPath });
  await assert.rejects(
    () => transport.exchange(new Uint8Array([0, 0, 0, 1])),
    failure("invalid_request_frame", "before_write"),
  );
  const tooLarge = Buffer.alloc(MAX_FRAME_BYTES + 5);
  tooLarge.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
  await assert.rejects(
    () => transport.exchange(tooLarge),
    failure("invalid_request_frame", "before_write"),
  );
  assert.equal(connections, 0);
  await assert.rejects(
    () => transport.exchange(request),
    failure("invalid_response_frame", "possible_effect"),
  );
  assert.equal(connections, 1);
});

test("read timeout is uncertain and destroys the accepted connection", async (t) => {
  const closed = deferred();
  const socketPath = await fakeServer(t, (socket) => {
    socket.once("close", closed.resolve);
    socket.on("data", () => undefined);
  });
  const transport = new UnixSocketWireTransport({ socketPath, readTimeoutMs: 25 });
  await assert.rejects(() => transport.exchange(request), failure("read_timeout", "possible_effect"));
  await closed.promise;
});

test("lost reply remains possible-effect and never opens a retry connection", async (t) => {
  const closed = deferred();
  let connections = 0;
  const socketPath = await fakeServer(t, (socket) => {
    connections += 1;
    socket.once("close", closed.resolve);
    socket.once("data", () => socket.destroy());
  });
  const transport = new UnixSocketWireTransport({ socketPath });
  await assert.rejects(() => transport.exchange(request), failure("lost_reply", "possible_effect"));
  await closed.promise;
  assert.equal(connections, 1);
});

test("connect failure is before-write and every deadline must be finite", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "podbay-unbound-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const socketPath = join(directory, "absent.sock");
  const transport = new UnixSocketWireTransport({ socketPath });
  await assert.rejects(() => transport.exchange(request), failure("connect_failed", "before_write"));
  assert.throws(() => new UnixSocketWireTransport({ socketPath, writeTimeoutMs: Infinity }));
  assert.throws(() => new UnixSocketWireTransport({ socketPath, connectTimeoutMs: 0 }));
});

function failure(code: SocketTransportError["code"], stage: SocketTransportError["stage"]) {
  return (error: unknown): boolean => {
    assert.equal(error instanceof SocketTransportError, true);
    if (!(error instanceof SocketTransportError)) return false;
    assert.equal(error.code, code);
    assert.equal(error.stage, stage);
    return true;
  };
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve = () => undefined;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

async function fakeServer(t: TestContext, onConnection: (socket: Socket) => void): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "podbay-socket-"));
  const socketPath = join(directory, "wire.sock");
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    onConnection(socket);
  });
  try {
    await listen(server, socketPath);
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
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
