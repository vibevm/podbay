import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  CONTRACT,
  PodBayWireClient,
  PodBayWireError,
  commandDigest,
  decodeCapabilities,
  decodeCommand,
  decodeCursor,
  decodeError,
  decodeEvent,
  decodeFrame,
  decodeReceipt,
  decodeSnapshot,
  decodeSuccess,
  decimal,
  effectiveSupport,
  encodeFrame,
  eventKind,
  makeCommand,
  validateCursorFor,
  type ReadEnvelope,
} from "../src/generated.ts";

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(new URL("../../../schema/v1/" + name, import.meta.url), "utf8"),
  ) as unknown;
}

test("Rust contract manifest and generated TypeScript vocabulary match", () => {
  assert.deepEqual(CONTRACT, fixture("contract.json"));
  assert.equal(CONTRACT.supportedMutationSchemas.length, 20);
  assert.equal(CONTRACT.supportedReadSchemas.length, 11);
});

test("golden resource command digest and strict mutation decoding", async () => {
  const raw = fixture("command-resource-write.json") as Record<string, unknown>;
  const command = await decodeCommand(raw);
  assert.equal(command.operation, "resource.command");
  assert.equal(command.payloadDigest, "df8abdefd49491a11b6312b252922528ed9d558093770df2ee86f07750113b11");
  assert.equal(await commandDigest(command), command.payloadDigest);
  const generated = await makeCommand({
    requestId: command.requestId,
    key: command.key,
    target: command.target,
    guard: command.guard,
    deadlineAt: command.deadlineAt,
    operation: command.operation,
    body: command.body,
  });
  assert.deepEqual(generated, command);
  await assert.rejects(() => decodeCommand({ ...raw, operation: "grant.issue" }));
  await assert.rejects(() => decodeCommand({ ...raw, action: "stop" }));
  await assert.rejects(() => decodeCommand({
    ...raw,
    body: { command: { kind: "grant_permission" } },
  }));
  await assert.rejects(() => decodeCommand({
    ...raw,
    body: { command: { kind: "write", contentRef: "artifact.input.1", operation: "stop" } },
  }));
  await assert.rejects(() => decodeCommand({
    ...raw,
    target: { kind: "resource", podId: "pod.other", resourceId: "resource.pty" },
  }));
});

test("all five Rust-generated mutation fixtures execute in the TypeScript codec", async () => {
  for (const [name, operation] of [
    ["command-session-send.json", "session.send"],
    ["command-run-pause.json", "run.pause"],
    ["command-run-resume.json", "run.resume"],
    ["command-run-stop.json", "run.stop"],
    ["command-resource-write.json", "resource.command"],
  ]) {
    const command = await decodeCommand(fixture(name));
    assert.equal(command.operation, operation);
    assert.equal(await commandDigest(command), command.payloadDigest);
    const roundtrip = await makeCommand({
      requestId: command.requestId,
      key: command.key,
      target: command.target,
      guard: command.guard,
      deadlineAt: command.deadlineAt,
      operation: command.operation,
      body: command.body,
    });
    assert.deepEqual(roundtrip, command);
  }
});

test("decimal strings preserve values above 2^53 and reject numeric JSON", () => {
  const receipt = decodeReceipt(fixture("receipt-persisted.json"));
  assert.equal(receipt.cursor.sequence, "9007199254740993");
  assert.equal(BigInt(receipt.cursor.sequence), 9007199254740993n);
  assert.equal(decimal("18446744073709551615"), "18446744073709551615");
  for (const invalid of [9007199254740993, "01", "-1", "18446744073709551616"]) {
    assert.throws(() => decimal(invalid));
  }
  const numeric = structuredClone(fixture("receipt-persisted.json")) as Record<string, unknown>;
  (numeric.cursor as Record<string, unknown>).sequence = 9007199254740993;
  assert.throws(() => decodeReceipt(numeric));
});

test("cursor binds lineage and exact scope and rejects future or pruned position", () => {
  const cursor = decodeCursor((fixture("snapshot-current.json") as Record<string, unknown>).cursor);
  validateCursorFor(cursor, "store.fixture", "project.fixture", decimal("1"), decimal("9007199254741000"));
  assert.throws(() => validateCursorFor(cursor, "store.other", "project.fixture", decimal("1"), decimal("9007199254741000")));
  assert.throws(() => validateCursorFor(cursor, "store.fixture", "project.other", decimal("1"), decimal("9007199254741000")));
  assert.throws(() => validateCursorFor(cursor, "store.fixture", "project.fixture", decimal("1"), decimal("5")));
  assert.throws(() => validateCursorFor(cursor, "store.fixture", "project.fixture", decimal("9007199254741000"), decimal("9007199254741000")));
});

test("future observations and additive fields remain opaque while capabilities fail closed", () => {
  const unknown = decodeEvent(fixture("event-unknown-observation.json"));
  assert.deepEqual(eventKind(unknown), { known: false, kind: "future_observation" });
  assert.deepEqual(unknown, fixture("event-unknown-observation.json"));
  assert.deepEqual(unknown.sourceOrder, { state: "gap", expectedNext: "7" });
  const futureSchema = decodeEvent(fixture("event-future-schema.json"));
  assert.deepEqual(eventKind(futureSchema), { known: false, kind: "run_admitted" });
  assert.deepEqual(futureSchema, fixture("event-future-schema.json"));
  const capabilities = decodeCapabilities(fixture("capabilities.json"));
  assert.equal(effectiveSupport(capabilities.capabilities[0]!), "conditional");
  assert.equal(effectiveSupport(capabilities.capabilities[1]!), "unverified");
  assert.equal(capabilities.capabilities[1]!.futureField, true);
  assert.throws(() => decodeEvent({ ...futureSchema, protocol: "podbay/2" }));
});

test("receipt, snapshot, error, frame and thin command client use golden fixtures", async () => {
  const receipt = decodeReceipt(fixture("receipt-persisted.json"));
  const success = decodeSuccess(fixture("success-receipt.json"));
  assert.equal(success.requestId, "request.pb03.1");
  assert.deepEqual(decodeReceipt(success.ok), receipt);
  const readSuccess = decodeSuccess(fixture("success-snapshot.json"));
  assert.deepEqual(decodeSnapshot(readSuccess.ok), decodeSnapshot(fixture("snapshot-current.json")));
  const snapshot = decodeSnapshot(fixture("snapshot-current.json"));
  const error = decodeError(fixture("error-stale-guard.json"));
  assert.equal(receipt.state, "persisted");
  assert.equal(snapshot.cursor.scopeId, snapshot.scopeId);
  assert.equal(error.error.code, "stale_guard");
  const frame = encodeFrame(fixture("receipt-persisted.json"));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(decodeFrame(frame))), fixture("receipt-persisted.json"));
  assert.throws(() => decodeFrame(new Uint8Array([...frame, 0])));
  const command = await decodeCommand(fixture("command-resource-write.json"));
  let exchanges = 0;
  const client = new PodBayWireClient({
    async exchange(request) {
      exchanges++;
      assert.deepEqual(await decodeCommand(decodeFrame(request)), command);
      return encodeFrame(fixture("success-receipt.json"));
    },
  });
  assert.equal((await client.command(command)).state, "persisted");
  assert.equal(exchanges, 1);
  const refusing = new PodBayWireClient({
    async exchange() {
      return encodeFrame(fixture("error-stale-guard.json"));
    },
  });
  await assert.rejects(() => refusing.command(command), PodBayWireError);
  const reading = new PodBayWireClient({ async exchange() { return encodeFrame(fixture("success-snapshot.json")); } });
  const readRequest = fixture("read-snapshot-get.json") as ReadEnvelope;
  assert.equal(decodeSnapshot<{ foreground: string }>(await reading.read(readRequest)).state.foreground, "unknown");
  const uncorrelated = new PodBayWireClient({ async exchange() { return encodeFrame(fixture("success-receipt.json")); } });
  await assert.rejects(() => uncorrelated.read(readRequest), /requestId mismatch/u);
});
