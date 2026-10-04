import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, chown, link, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { loadOwnerKeyCustody, ownerKeyContinuityChallenge, persistOwnerKeyCustody } from "../src/owner-key-custody.ts";

const ownerSetupUrl = pathToFileURL(new URL("../src/owner-setup.ts", import.meta.url).pathname).href;
const custodyUrl = pathToFileURL(new URL("../src/owner-key-custody.ts", import.meta.url).pathname).href;

test("an owner-only setup key survives its Node process and proves same-key continuity", {
  skip: process.platform !== "linux",
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "podbay-owner-custody-"));
  await chmod(root, 0o700);
  const custody = join(root, "owner-key-custody.json");
  const proof = join(root, "continuity-proof.bin");
  const nonce = randomBytes(32);
  try {
    const create = `
      import { readFileSync } from 'node:fs';
      import { join } from 'node:path';
      import { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } from ${JSON.stringify(ownerSetupUrl)};
      const stat = readFileSync('/proc/self/stat','utf8');
      const fields = stat.slice(stat.lastIndexOf(')')+2).trim().split(/\\s+/u);
      const cgroup = readFileSync('/proc/self/cgroup','utf8').trimEnd().split('\\n').find(x=>x.startsWith('0::'));
      if (!cgroup) throw new Error();
      await new InitialOwnerSetupClient({
        setupSocketPath: join(${JSON.stringify(root)}, 'owner-setup.sock'),
        managerSocketPath: join(${JSON.stringify(root)}, 'manager.sock'),
        ownerKeyCustodyPath: ${JSON.stringify(custody)},
        actorId:'actor.owner.fixture', scopeId:'scope.owner.fixture',
        credentialRef:'credential.owner.fixture', storeLineage:'lineage.owner.fixture',
        ownerEpoch:1n, authorityRevision:1n,
        osIdentity:'linux.uid.'+String(process.getuid()),
        processIdentity:'linux.pid.'+String(process.pid),
        startIdentity:BigInt(fields[19]), containmentIdentity:cgroup.slice(3),
        rightsDigest:INITIAL_OWNER_RIGHTS_DIGEST, validateHostEndpoint:()=>true,
      }).prepareOwnerKeyCustody();
    `;
    assert.equal(execFileSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "--eval", create]).length, 0);
    const metadata = await lstat(custody);
    assert.equal(metadata.isFile(), true);
    assert.equal(metadata.mode & 0o7777, 0o600);
    assert.equal(metadata.nlink, 1);
    const loaded = loadOwnerKeyCustody(custody, {
      actorId: "actor.owner.fixture", scopeId: "scope.owner.fixture",
      storeLineage: "lineage.owner.fixture",
    });
    assert.notEqual(loaded.binding.processIdentity, `linux.pid.${String(process.pid)}`);
    const prove = `
      import { writeFileSync } from 'node:fs';
      import { loadOwnerKeyCustody } from ${JSON.stringify(custodyUrl)};
      const loaded = loadOwnerKeyCustody(${JSON.stringify(custody)}, {
        actorId:'actor.owner.fixture', scopeId:'scope.owner.fixture',
        storeLineage:'lineage.owner.fixture',
      });
      writeFileSync(${JSON.stringify(proof)}, loaded.proveContinuity(Buffer.from(${JSON.stringify(nonce.toString("base64"))},'base64')), {mode:0o600,flag:'wx'});
    `;
    assert.equal(execFileSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "--eval", prove]).length, 0);
    const publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(loaded.publicKey).toString("base64url") },
      format: "jwk",
    });
    assert.equal(verify(null, ownerKeyContinuityChallenge(nonce), publicKey, await readFile(proof)), true);
    assert.throws(() => loadOwnerKeyCustody(custody, {
      actorId: "actor.other", scopeId: "scope.owner.fixture", storeLineage: "lineage.owner.fixture",
    }));
    const link = join(root, "owner-key-link.json");
    await symlink(custody, link);
    assert.throws(() => loadOwnerKeyCustody(link, {
      actorId: "actor.owner.fixture", scopeId: "scope.owner.fixture",
      storeLineage: "lineage.owner.fixture",
    }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("owner key custody refuses changed binding, path, privacy, duplicate and torn state", {
  skip: process.platform !== "linux",
}, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "podbay-owner-custody-faults-"));
  await chmod(root, 0o700);
  const path = join(root, "owner-key-custody.json");
  const binding = {
    actorId: "actor.owner.fixture", scopeId: "scope.owner.fixture",
    storeLineage: "lineage.owner.fixture", credentialRef: "credential.owner.fixture",
    ownerEpoch: 1n, authorityRevision: 1n, osIdentity: `linux.uid.${String(process.getuid?.())}`,
    processIdentity: `linux.pid.${String(process.pid)}`, startIdentity: 1n,
    containmentIdentity: "/fixture",
  };
  const expected = { actorId: binding.actorId, scopeId: binding.scopeId, storeLineage: binding.storeLineage };
  try {
    const privateKey = generateKeyPairSync("ed25519").privateKey;
    assert.throws(() => loadOwnerKeyCustody(path, expected));
    persistOwnerKeyCustody(path, binding, privateKey);
    assert.throws(() => persistOwnerKeyCustody(path, binding, generateKeyPairSync("ed25519").privateKey));
    for (const changed of [
      { ...expected, actorId: "actor.other" },
      { ...expected, scopeId: "scope.other" },
      { ...expected, storeLineage: "lineage.other" },
    ]) assert.throws(() => loadOwnerKeyCustody(path, changed));
    const linkedDirectory = join(root, "linked");
    await mkdir(linkedDirectory, { mode: 0o700 });
    await symlink(path, join(linkedDirectory, "owner-key-custody.json"));
    assert.throws(() => loadOwnerKeyCustody(join(linkedDirectory, "owner-key-custody.json"), expected));
    const hardlink = join(root, "owner-key-hardlink.json");
    await link(path, hardlink);
    assert.throws(() => loadOwnerKeyCustody(path, expected));
    await rm(hardlink);
    await chmod(path, 0o644);
    assert.throws(() => loadOwnerKeyCustody(path, expected));
    await chmod(path, 0o600);
    await chmod(root, 0o755);
    assert.throws(() => loadOwnerKeyCustody(path, expected));
    await chmod(root, 0o700);
    if (process.getuid?.() === 0) {
      await chown(path, 1, 1);
      assert.throws(() => loadOwnerKeyCustody(path, expected));
      await chown(path, 0, 0);
    } else t.diagnostic("wrong-owner file mutation requires root; owner UID guard remains checked in code");
    await writeFile(path, '{"schema":', { mode: 0o600 });
    assert.throws(() => loadOwnerKeyCustody(path, expected));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
