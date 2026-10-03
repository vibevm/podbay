import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { decodeCommand } from "../src/generated.ts";

test("launch workspace path remains portable and scope relative", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../schema/v1/command-launch.json", import.meta.url), "utf8")) as Record<string, unknown>;
  const body = fixture.body as Record<string, unknown>;
  for (const path of ["C:", "/tmp/work", "../other", "sub\\tree", "sub//tree", "bad\u0000path"]) {
    await assert.rejects(() => decodeCommand({
      ...fixture,
      body: { ...body, workspace: { ...(body.workspace as object), relativeCwd: path } },
    }), path);
  }
});
