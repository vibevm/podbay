import { createPrivateKey, sign } from "node:crypto";
import { createConnection } from "node:net";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [socketPath, bindingRoot] = process.argv.slice(2);
const probe = createConnection(socketPath);
await once(probe, "connect");
process.stdout.write("ready\n");

const lines = createInterface({ input: process.stdin });
let setup;
for await (const line of lines) {
  setup = JSON.parse(line);
  break;
}
if (!setup) throw new Error("Rust fixture did not provide actor expectations");
probe.destroy();

const { makeRead, PodBayWireClient } = await import(
  pathToFileURL(join(bindingRoot, "generated.ts")).href
);
const { AuthenticatedUnixSocketWireTransport } = await import(
  pathToFileURL(join(bindingRoot, "authenticated-unix-socket.ts")).href
);
const seed = Buffer.alloc(32, 7);
const pkcs8 = Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"),
  seed,
]);
const signer = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
const transport = new AuthenticatedUnixSocketWireTransport({
  socketPath,
  expected: {
    actorId: setup.actorId,
    storeLineage: setup.storeLineage,
    scopeId: setup.scopeId,
    credentialGeneration: BigInt(setup.credentialGeneration),
    osIdentity: setup.osIdentity,
    processIdentity: setup.processIdentity,
    startIdentity: BigInt(setup.startIdentity),
    containmentIdentity: setup.containmentIdentity,
    origin: { kind: "owner-cli" },
  },
  validateAndSign: (challenge) =>
    new Uint8Array(sign(null, Buffer.from(challenge.bytes), signer)),
});
const request = makeRead({
  operation: "commands.get",
  requestId: "request.node.real",
  target: { kind: "scope", scopeId: setup.scopeId },
  body: { selector: { kind: "key", key: "key.own" } },
});
const response = await new PodBayWireClient(transport).read(request);
process.stdout.write(`${JSON.stringify(response)}\n`);
