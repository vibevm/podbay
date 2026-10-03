import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  CONTRACT, PodBayWireClient, commandDigest, decodeCommand, decodeFrame,
  decodeRead, encodeFrame, makeCommand, makeRead,
} from "../src/generated.ts";

function fixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL("../../../schema/v1/" + name, import.meta.url), "utf8")) as unknown;
}

test("every advertised mutation and read fixture executes in the generated codec", async () => {
  for (const operation of CONTRACT.supportedMutationSchemas) {
    const name = operation === "resource.command" ? "command-resource-write.json"
      : "command-" + operation.replaceAll(".", "-") + ".json";
    const command = await decodeCommand(fixture(name));
    assert.equal(command.operation, operation, name);
    assert.equal(await commandDigest(command), command.payloadDigest, name);
    const rebuilt = await makeCommand({
      requestId: command.requestId, key: command.key, target: command.target,
      guard: command.guard, deadlineAt: command.deadlineAt,
      operation: command.operation, body: command.body,
    });
    assert.deepEqual(rebuilt, command, name);
  }
  for (const operation of CONTRACT.supportedReadSchemas) {
    const name = "read-" + operation.replaceAll(".", "-") + ".json";
    const request = decodeRead(fixture(name));
    assert.equal(request.operation, operation, name);
    assert.deepEqual(makeRead({
      operation: request.operation, requestId: request.requestId,
      target: request.target, body: request.body,
    }), request, name);
    assert.equal(Object.hasOwn(request, "key"), false, "read requests carry no mutation key");
  }
});

test("launch session choice changes digest under the same key", async () => {
  const fresh = await decodeCommand(fixture("command-launch.json"));
  const existing = await decodeCommand(fixture("command-launch-existing.json"));
  assert.equal(fresh.key, existing.key);
  assert.notEqual(fresh.payloadDigest, existing.payloadDigest);
  assert.equal(fresh.operation, "launch");
  assert.equal(existing.operation, "launch");
});

test("question answers cannot become permission decisions or domain acceptance", async () => {
  const answer = fixture("command-question-answer.json") as Record<string, unknown>;
  await assert.rejects(() => decodeCommand({ ...answer, body: { ...(answer.body as object), decision: { kind: "allow_once" } } }));
  const permission = fixture("command-permission-decide.json") as Record<string, unknown>;
  await assert.rejects(() => decodeCommand({ ...permission, target: { kind: "question", questionId: "question.fixture" } }));
  const report = fixture("command-run-report.json") as Record<string, unknown>;
  await assert.rejects(() => decodeCommand({ ...report, body: { ...(report.body as object), accepted: true } }));
  const read = fixture("read-commands-get.json") as Record<string, unknown>;
  assert.throws(() => decodeRead({ ...read, key: "mutation-key" }));
});

test("thin client sends scoped read without a mutation key", async () => {
  const request = decodeRead(fixture("read-snapshot-get.json"));
  const response = fixture("snapshot-current.json");
  const client = new PodBayWireClient({
    async exchange(frame) {
      assert.deepEqual(decodeRead(decodeFrame(frame)), request);
      return encodeFrame(response);
    },
  });
  assert.deepEqual(await client.read(request), response);
});
