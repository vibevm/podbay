import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { chmod, chown, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createServer, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { loadOwnerKeyCustody, ownerKeyContinuityChallenge, persistOwnerKeyCustody, recoverOwnerKeyForInitialEnrollment, stageNextOwnerKeyCustody } from "../src/owner-key-custody.ts";
import { INITIAL_OWNER_RIGHTS_DIGEST, InitialOwnerSetupClient, OwnerSetupError } from "../src/owner-setup.ts";

const setupDomain = Buffer.from("podbay.owner-initial-enrollment/1\0", "ascii");
const setupRights = "launch_pod.scope+use_credential.exact+send_session.scope";

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
    const identityPath = join(root, "second-process-identity.json");
    const receiptPath = join(root, "second-process-receipt.json");
    const setupPath = join(root, "owner-setup.sock");
    const publicKey = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(loaded.publicKey).toString("base64url") },
      format: "jwk",
    });
    let setupFailure: unknown;
    const server = createServer((socket) => {
      void (async () => {
        const frames = new Frames(socket);
        const offeredKey = await frames.next();
        assert.deepEqual(offeredKey, Buffer.from(loaded.publicKey));
        const identity = JSON.parse(await readFile(identityPath, "utf8")) as {
          osIdentity: string; processIdentity: string; startIdentity: string; containmentIdentity: string;
        };
        const challenge = Buffer.concat([
          setupDomain,
          field(1, randomBytes(32)), field(2, "lineage.owner.fixture"),
          field(3, counter(1n)), field(4, counter(1n)),
          field(5, "actor.owner.fixture"), field(6, "scope.owner.fixture"),
          field(7, "owner_cli.coordinator.generation1"),
          field(8, identity.osIdentity), field(9, identity.processIdentity),
          field(10, counter(BigInt(identity.startIdentity))),
          field(11, identity.containmentIdentity), field(12, offeredKey),
          field(13, "credential.owner.fixture"), field(14, setupRights),
        ]);
        socket.write(frame(challenge));
        assert.equal(verify(null, challenge, publicKey, await frames.next()), true);
        socket.write(frame(Buffer.from(JSON.stringify({
          actorId: "actor.owner.fixture", authorityRevision: "2", duplicate: false,
          grantRef: "grant.1", ownerEpoch: "1",
          protocol: "podbay.owner-initial-enrollment/1", scopeId: "scope.owner.fixture",
        }), "utf8")));
        assert.equal((await frames.next()).toString("ascii"), "ack");
        socket.end();
      })().catch((error: unknown) => { setupFailure = error; socket.destroy(); });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(setupPath, () => { server.off("error", reject); resolve(); });
    });
    try {
      const resume = `
        import { readFileSync, writeFileSync } from 'node:fs';
        import { join } from 'node:path';
        import { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } from ${JSON.stringify(ownerSetupUrl)};
        const stat = readFileSync('/proc/self/stat','utf8');
        const fields = stat.slice(stat.lastIndexOf(')')+2).trim().split(/\\s+/u);
        const cgroup = readFileSync('/proc/self/cgroup','utf8').trimEnd().split('\\n').find(x=>x.startsWith('0::'));
        if (!cgroup) throw new Error();
        const identity = {
          osIdentity:'linux.uid.'+String(process.getuid()),
          processIdentity:'linux.pid.'+String(process.pid),
          startIdentity:fields[19], containmentIdentity:cgroup.slice(3),
        };
        writeFileSync(${JSON.stringify(identityPath)}, JSON.stringify(identity), {mode:0o600,flag:'wx'});
        const client = new InitialOwnerSetupClient({
          setupSocketPath: join(${JSON.stringify(root)}, 'owner-setup.sock'),
          managerSocketPath: join(${JSON.stringify(root)}, 'manager.sock'),
          ownerKeyCustodyPath: ${JSON.stringify(custody)},
          actorId:'actor.owner.fixture', scopeId:'scope.owner.fixture',
          credentialRef:'credential.owner.fixture', storeLineage:'lineage.owner.fixture',
          ownerEpoch:1n, authorityRevision:1n,
          ...identity, startIdentity:BigInt(identity.startIdentity),
          rightsDigest:INITIAL_OWNER_RIGHTS_DIGEST, validateHostEndpoint:()=>true,
        });
        const receipt = await client.enroll();
        writeFileSync(${JSON.stringify(receiptPath)}, JSON.stringify({
          actorId:receipt.actorId, grantRef:receipt.grantRef, duplicate:receipt.duplicate,
        }), {mode:0o600,flag:'wx'});
      `;
      const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "--eval", resume],
        { stdio: ["ignore", "pipe", "pipe"] });
      const stdout: Buffer[] = [], stderr: Buffer[] = [];
      child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      const status = await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code) => resolve(code));
      });
      assert.equal(status, 0, Buffer.concat(stderr).toString("utf8"));
      assert.equal(Buffer.concat(stdout).length, 0);
      assert.equal(setupFailure, undefined);
      assert.deepEqual(JSON.parse(await readFile(receiptPath, "utf8")), {
        actorId: "actor.owner.fixture", grantRef: "grant.1", duplicate: false,
      });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
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

test("partial temporary write cut leaves no final key and the next process enrolls afresh", {
  skip: process.platform !== "linux",
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "podbay-owner-custody-cut-"));
  await chmod(root, 0o700);
  const custody = join(root, "owner-key-custody.json");
  const identityPath = join(root, "restarted-identity.json");
  const receiptPath = join(root, "restarted-receipt.json");
  try {
    const cut = `
      import fs from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      const original=fs.writeFileSync;
      fs.writeFileSync=(target,bytes,options)=>{
        if(typeof target==='number' && Buffer.isBuffer(bytes)) {
          original(target,bytes.subarray(0,11),options);
          process.exit(71);
        }
        return original(target,bytes,options);
      };
      syncBuiltinESMExports();
      const { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } = await import(${JSON.stringify(ownerSetupUrl)});
      const stat=fs.readFileSync('/proc/self/stat','utf8');
      const fields=stat.slice(stat.lastIndexOf(')')+2).trim().split(/\\s+/u);
      const cgroup=fs.readFileSync('/proc/self/cgroup','utf8').trimEnd().split('\\n').find(x=>x.startsWith('0::'));
      if(!cgroup) throw new Error();
      await new InitialOwnerSetupClient({
        setupSocketPath:${JSON.stringify(join(root, "owner-setup.sock"))},
        managerSocketPath:${JSON.stringify(join(root, "manager.sock"))},
        ownerKeyCustodyPath:${JSON.stringify(custody)},
        actorId:'actor.owner.partial',scopeId:'scope.owner.partial',
        credentialRef:'credential.owner.partial',storeLineage:'lineage.owner.partial',
        ownerEpoch:1n,authorityRevision:1n,
        osIdentity:'linux.uid.'+String(process.getuid()),
        processIdentity:'linux.pid.'+String(process.pid),
        startIdentity:BigInt(fields[19]),containmentIdentity:cgroup.slice(3),
        rightsDigest:INITIAL_OWNER_RIGHTS_DIGEST,validateHostEndpoint:()=>true,
      }).prepareOwnerKeyCustody();
    `;
    let cutError: unknown;
    try { execFileSync(process.execPath, ["--experimental-strip-types", "--input-type=module", "--eval", cut]); }
    catch (error) { cutError = error; }
    assert.equal((cutError as { status?: number } | undefined)?.status, 71);
    await assert.rejects(() => lstat(custody));
    const orphanNames = (await readdir(root)).filter((name) => name.startsWith("owner-key-custody.json.tmp."));
    assert.equal(orphanNames.length, 1);
    assert.equal((await lstat(join(root, orphanNames[0]!))).size, 11);

    let observedKey: Buffer | undefined;
    let setupFailure: unknown;
    const server = createServer((socket) => {
      void (async () => {
        const frames = new Frames(socket);
        const key = await frames.next();
        observedKey = key;
        assert.equal(key.length, 32);
        const identity = JSON.parse(await readFile(identityPath, "utf8")) as {
          osIdentity: string; processIdentity: string; startIdentity: string; containmentIdentity: string;
        };
        const challenge = Buffer.concat([
          setupDomain,
          field(1, randomBytes(32)), field(2, "lineage.owner.partial"),
          field(3, counter(1n)), field(4, counter(1n)),
          field(5, "actor.owner.partial"), field(6, "scope.owner.partial"),
          field(7, "owner_cli.coordinator.generation1"),
          field(8, identity.osIdentity), field(9, identity.processIdentity),
          field(10, counter(BigInt(identity.startIdentity))),
          field(11, identity.containmentIdentity), field(12, key),
          field(13, "credential.owner.partial"), field(14, setupRights),
        ]);
        socket.write(frame(challenge));
        const publicKey = createPublicKey({
          key: { kty: "OKP", crv: "Ed25519", x: key.toString("base64url") }, format: "jwk",
        });
        assert.equal(verify(null, challenge, publicKey, await frames.next()), true);
        socket.write(frame(Buffer.from(JSON.stringify({
          actorId: "actor.owner.partial", authorityRevision: "2", duplicate: false,
          grantRef: "grant.1", ownerEpoch: "1",
          protocol: "podbay.owner-initial-enrollment/1", scopeId: "scope.owner.partial",
        }), "utf8")));
        assert.equal((await frames.next()).toString("ascii"), "ack");
        socket.end();
      })().catch((error: unknown) => { setupFailure = error; socket.destroy(); });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(join(root, "owner-setup.sock"), () => { server.off("error", reject); resolve(); });
    });
    try {
      const restart = `
        import { readFileSync, writeFileSync } from 'node:fs';
        const { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } = await import(${JSON.stringify(ownerSetupUrl)});
        const stat=readFileSync('/proc/self/stat','utf8');
        const fields=stat.slice(stat.lastIndexOf(')')+2).trim().split(/\\s+/u);
        const cgroup=readFileSync('/proc/self/cgroup','utf8').trimEnd().split('\\n').find(x=>x.startsWith('0::'));
        if(!cgroup) throw new Error();
        const identity={osIdentity:'linux.uid.'+String(process.getuid()),
          processIdentity:'linux.pid.'+String(process.pid),
          startIdentity:fields[19],containmentIdentity:cgroup.slice(3)};
        writeFileSync(${JSON.stringify(identityPath)},JSON.stringify(identity),{mode:0o600,flag:'wx'});
        const receipt=await new InitialOwnerSetupClient({
          setupSocketPath:${JSON.stringify(join(root, "owner-setup.sock"))},
          managerSocketPath:${JSON.stringify(join(root, "manager.sock"))},
          ownerKeyCustodyPath:${JSON.stringify(custody)},
          actorId:'actor.owner.partial',scopeId:'scope.owner.partial',
          credentialRef:'credential.owner.partial',storeLineage:'lineage.owner.partial',
          ownerEpoch:1n,authorityRevision:1n,
          ...identity,startIdentity:BigInt(identity.startIdentity),
          rightsDigest:INITIAL_OWNER_RIGHTS_DIGEST,validateHostEndpoint:()=>true,
        }).enroll();
        writeFileSync(${JSON.stringify(receiptPath)},JSON.stringify({
          actorId:receipt.actorId,grantRef:receipt.grantRef,
        }),{mode:0o600,flag:'wx'});
      `;
      const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "--eval", restart],
        { stdio: ["ignore", "pipe", "pipe"] });
      const stderr: Buffer[] = [];
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      const status = await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject); child.once("exit", (code) => resolve(code));
      });
      assert.equal(status, 0, Buffer.concat(stderr).toString("utf8"));
      assert.equal(setupFailure, undefined);
      assert.deepEqual(JSON.parse(await readFile(receiptPath, "utf8")), {
        actorId: "actor.owner.partial", grantRef: "grant.1",
      });
      assert.ok(observedKey);
      assert.deepEqual(loadOwnerKeyCustody(custody, {
        actorId: "actor.owner.partial", scopeId: "scope.owner.partial",
        storeLineage: "lineage.owner.partial",
      }).publicKey, new Uint8Array(observedKey));
      assert.equal((await readdir(root)).some((name) => name.startsWith("owner-key-custody.json.tmp.")), false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
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
  const selfStat = await readFile("/proc/self/stat", "utf8");
  const selfFields = selfStat.slice(selfStat.lastIndexOf(")") + 2).trim().split(/\s+/u);
  const selfCgroup = (await readFile("/proc/self/cgroup", "utf8")).trimEnd()
    .split("\n").find((line) => line.startsWith("0::"));
  assert.ok(selfCgroup);
  const binding = {
    actorId: "actor.owner.fixture", scopeId: "scope.owner.fixture",
    storeLineage: "lineage.owner.fixture", credentialRef: "credential.owner.fixture",
    ownerEpoch: 1n, authorityRevision: 1n, osIdentity: `linux.uid.${String(process.getuid?.())}`,
    processIdentity: `linux.pid.${String(process.pid)}`,
    startIdentity: BigInt(selfFields[19]!), containmentIdentity: selfCgroup.slice(3),
  };
  const expected = { actorId: binding.actorId, scopeId: binding.scopeId, storeLineage: binding.storeLineage };
  try {
    const privateKey = generateKeyPairSync("ed25519").privateKey;
    assert.throws(() => loadOwnerKeyCustody(path, expected));
    persistOwnerKeyCustody(path, binding, privateKey);
    const completeBytes = await readFile(path);
    assert.throws(() => persistOwnerKeyCustody(path, binding, generateKeyPairSync("ed25519").privateKey));
    assert.deepEqual(await readFile(path), completeBytes);
    const original = createPublicKey(privateKey).export({ format: "jwk" });
    assert.equal(typeof original.x, "string");
    const linkedTemporary = join(root, `owner-key-custody.json.tmp.99999999.1.${"a".repeat(32)}`);
    await link(path, linkedTemporary);
    assert.equal((await lstat(path)).nlink, 2);
    assert.deepEqual(recoverOwnerKeyForInitialEnrollment(path, binding,
      Buffer.from(original.x!, "base64url")).publicKey,
      new Uint8Array(Buffer.from(original.x!, "base64url")));
    assert.equal((await lstat(path)).nlink, 1);
    await assert.rejects(() => lstat(linkedTemporary));
    const unrelated = createPublicKey(generateKeyPairSync("ed25519").privateKey)
      .export({ format: "jwk" });
    assert.equal(typeof unrelated.x, "string");
    assert.throws(() => recoverOwnerKeyForInitialEnrollment(
      path, binding, Buffer.from(unrelated.x!, "base64url"),
    ));
    assert.throws(() => recoverOwnerKeyForInitialEnrollment(
      path, { ...binding, ownerEpoch: 2n }, Buffer.from(unrelated.x!, "base64url"),
    ));
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

test("setup can retry the same generated key after a pre-signature custody failure", {
  skip: process.platform !== "linux",
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "podbay-owner-custody-retry-"));
  const custody = join(root, "owner-key-custody.json");
  try {
    const stat = await readFile("/proc/self/stat", "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
    const cgroup = (await readFile("/proc/self/cgroup", "utf8")).trimEnd()
      .split("\n").find((line) => line.startsWith("0::"));
    assert.ok(cgroup);
    const client = new InitialOwnerSetupClient({
      setupSocketPath: join(root, "owner-setup.sock"),
      managerSocketPath: join(root, "manager.sock"),
      ownerKeyCustodyPath: custody,
      actorId: "actor.owner.retry", scopeId: "scope.owner.retry",
      storeLineage: "lineage.owner.retry", credentialRef: "credential.owner.retry",
      ownerEpoch: 1n, authorityRevision: 1n,
      osIdentity: `linux.uid.${String(process.getuid?.())}`,
      processIdentity: `linux.pid.${String(process.pid)}`,
      startIdentity: BigInt(fields[19]!), containmentIdentity: cgroup.slice(3),
      rightsDigest: INITIAL_OWNER_RIGHTS_DIGEST, validateHostEndpoint: () => true,
    });
    await chmod(root, 0o755);
    await assert.rejects(() => client.enroll(), /owner custody parent/u);
    await chmod(root, 0o700);
    await assert.rejects(() => client.enroll(), (error: unknown) => {
      assert.equal(error instanceof OwnerSetupError, true);
      return error instanceof OwnerSetupError && error.code === "connect_failed";
    });
    assert.equal((await lstat(custody)).mode & 0o7777, 0o600);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a second process cannot reuse custody while the first owner birth is live", {
  skip: process.platform !== "linux",
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "podbay-owner-custody-live-"));
  await chmod(root, 0o700);
  const path = join(root, "owner-key-custody.json");
  const create = `
    import { existsSync, readFileSync } from 'node:fs';
    import { join } from 'node:path';
    import { InitialOwnerSetupClient, INITIAL_OWNER_RIGHTS_DIGEST } from ${JSON.stringify(ownerSetupUrl)};
    const stat=readFileSync('/proc/self/stat','utf8');
    const fields=stat.slice(stat.lastIndexOf(')')+2).trim().split(/\\s+/u);
    const cgroup=readFileSync('/proc/self/cgroup','utf8').trimEnd().split('\\n').find(x=>x.startsWith('0::'));
    if(!cgroup) throw new Error();
    await new InitialOwnerSetupClient({
      setupSocketPath:join(${JSON.stringify(root)},'owner-setup.sock'),
      managerSocketPath:join(${JSON.stringify(root)},'manager.sock'),
      ownerKeyCustodyPath:${JSON.stringify(path)},
      actorId:'actor.owner.live',scopeId:'scope.owner.live',
      credentialRef:'credential.owner.live',storeLineage:'lineage.owner.live',
      ownerEpoch:1n,authorityRevision:1n,
      osIdentity:'linux.uid.'+String(process.getuid()),
      processIdentity:'linux.pid.'+String(process.pid),
      startIdentity:BigInt(fields[19]),containmentIdentity:cgroup.slice(3),
      rightsDigest:INITIAL_OWNER_RIGHTS_DIGEST,validateHostEndpoint:()=>true,
    }).prepareOwnerKeyCustody();
    while(!existsSync(${JSON.stringify(join(root, "release"))}))
      await new Promise(resolve=>setTimeout(resolve,20));
  `;
  const child = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "--eval", create],
    { stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  try {
    const until = performance.now() + 2_000;
    while (true) {
      try { await lstat(path); break; } catch { /* wait for fsynced file */ }
      if (performance.now() >= until) throw new Error();
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const stat = await readFile("/proc/self/stat", "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
    const cgroup = (await readFile("/proc/self/cgroup", "utf8")).trimEnd()
      .split("\n").find((line) => line.startsWith("0::"));
    assert.ok(cgroup);
    const expected = {
      actorId: "actor.owner.live", scopeId: "scope.owner.live",
      credentialRef: "credential.owner.live", storeLineage: "lineage.owner.live",
      ownerEpoch: 1n, authorityRevision: 1n,
      osIdentity: `linux.uid.${String(process.getuid?.())}`,
      processIdentity: `linux.pid.${String(process.pid)}`,
      startIdentity: BigInt(fields[19]!), containmentIdentity: cgroup.slice(3),
    };
    assert.throws(() => recoverOwnerKeyForInitialEnrollment(path, expected, randomBytes(32)),
      /prior owner process is still live/u);
    await writeFile(join(root, "release"), "go\n", { mode: 0o600 });
    const status = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject); child.once("exit", (code) => resolve(code));
    });
    assert.equal(status, 0, Buffer.concat(stderr).toString("utf8"));
    const recovered = recoverOwnerKeyForInitialEnrollment(path, expected, randomBytes(32));
    assert.deepEqual(recovered.publicKey, loadOwnerKeyCustody(path, expected).publicKey);
    const advanced = recoverOwnerKeyForInitialEnrollment(path, {
      ...expected, ownerEpoch: 3n, authorityRevision: 3n,
    }, randomBytes(32));
    assert.deepEqual(advanced.publicKey, recovered.publicKey);
    assert.throws(() => recoverOwnerKeyForInitialEnrollment(path, {
      ...expected, ownerEpoch: 3n, authorityRevision: 4n,
    }, randomBytes(32)), /expectation differs/u);
  } finally {
    if (child.exitCode === null) child.kill("SIGTERM");
    await rm(root, { recursive: true, force: true });
  }
});

test("next owner keys are private, generation-scoped and never replace earlier keys", {
  skip: process.platform !== "linux",
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "podbay-next-owner-custody-"));
  await chmod(root, 0o700);
  try {
    const stat = await readFile("/proc/self/stat", "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/u);
    const cgroup = (await readFile("/proc/self/cgroup", "utf8")).trimEnd()
      .split("\n").find((line) => line.startsWith("0::"));
    assert.ok(cgroup);
    const binding = {
      actorId: "actor.owner.next", scopeId: "scope.owner.next",
      storeLineage: "lineage.owner.next", credentialRef: "credential.owner.next",
      ownerEpoch: 2n, authorityRevision: 7n,
      osIdentity: `linux.uid.${String(process.getuid?.())}`,
      processIdentity: `linux.pid.${String(process.pid)}`,
      startIdentity: BigInt(fields[19]!), containmentIdentity: cgroup.slice(3),
    };
    const secondKey = generateKeyPairSync("ed25519").privateKey;
    const second = stageNextOwnerKeyCustody(root, 2n, binding, secondKey);
    assert.equal(second.path, join(root, "owner-generation-2",
      `key-${Buffer.from(second.publicKey).toString("hex")}`, "owner-key-custody.json"));
    assert.equal((await lstat(join(root, "owner-generation-2"))).mode & 0o7777, 0o700);
    assert.equal((await lstat(second.path)).mode & 0o7777, 0o600);
    const publicReceipt = join(dirname(second.path), "owner-next-public.json");
    assert.equal((await lstat(publicReceipt)).mode & 0o7777, 0o600);
    const publicText = await readFile(publicReceipt, "utf8");
    assert.equal(publicText.includes("privateKeyPkcs8"), false);
    assert.equal((JSON.parse(publicText) as { credentialGeneration: string }).credentialGeneration, "2");
    const secondBytes = await readFile(second.path);
    const linkedReceiptTemp = join(dirname(second.path), `owner-next-public.json.tmp.99999999.1.${"b".repeat(32)}`);
    await link(publicReceipt, linkedReceiptTemp);
    assert.equal((await lstat(publicReceipt)).nlink, 2);
    assert.deepEqual(stageNextOwnerKeyCustody(root, 2n, binding, secondKey).publicKey, second.publicKey);
    assert.equal((await lstat(publicReceipt)).nlink, 1);
    await assert.rejects(() => lstat(linkedReceiptTemp));
    await rm(publicReceipt);
    const partialReceiptTemp = join(dirname(second.path), `owner-next-public.json.tmp.99999999.1.${"c".repeat(32)}`);
    await writeFile(partialReceiptTemp, "partial", { mode: 0o600 });
    assert.deepEqual(stageNextOwnerKeyCustody(root, 2n, binding, secondKey).publicKey, second.publicKey);
    assert.equal((await lstat(publicReceipt)).mode & 0o7777, 0o600);
    await assert.rejects(() => lstat(partialReceiptTemp));
    assert.deepEqual(await readFile(second.path), secondBytes);
    assert.deepEqual(stageNextOwnerKeyCustody(root, 2n, binding, secondKey).publicKey, second.publicKey);
    assert.deepEqual(await readFile(second.path), secondBytes);
    const alternate = stageNextOwnerKeyCustody(root, 2n, binding,
      generateKeyPairSync("ed25519").privateKey);
    assert.notEqual(alternate.path, second.path);
    assert.notDeepEqual(alternate.publicKey, second.publicKey);
    assert.deepEqual(await readFile(second.path), secondBytes);
    const third = stageNextOwnerKeyCustody(root, 3n, binding,
      generateKeyPairSync("ed25519").privateKey);
    assert.equal(third.path, join(root, "owner-generation-3",
      `key-${Buffer.from(third.publicKey).toString("hex")}`, "owner-key-custody.json"));
    assert.deepEqual(await readFile(second.path), secondBytes);
    assert.notDeepEqual(third.publicKey, second.publicKey);
    assert.deepEqual(loadOwnerKeyCustody(third.path, binding).publicKey, third.publicKey);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

class Frames {
  readonly #queue: Buffer[] = [];
  readonly #waiting: Array<(value: Buffer) => void> = [];
  #pending = Buffer.alloc(0);
  constructor(socket: Socket) {
    socket.on("data", (chunk: Buffer) => {
      this.#pending = Buffer.concat([this.#pending, chunk]);
      while (this.#pending.length >= 4) {
        const size = this.#pending.readUInt32BE(0);
        if (this.#pending.length < size + 4) break;
        const value = Buffer.from(this.#pending.subarray(4, size + 4));
        this.#pending = this.#pending.subarray(size + 4);
        const waiting = this.#waiting.shift();
        if (waiting) waiting(value);
        else this.#queue.push(value);
      }
    });
  }
  next(): Promise<Buffer> {
    const ready = this.#queue.shift();
    return ready === undefined ? new Promise((resolve) => this.#waiting.push(resolve)) : Promise.resolve(ready);
  }
}

function frame(value: Buffer): Buffer {
  const bytes = Buffer.alloc(4 + value.length);
  bytes.writeUInt32BE(value.length, 0);
  bytes.set(value, 4);
  return bytes;
}
function field(tag: number, value: Buffer | string): Buffer {
  const input = typeof value === "string" ? Buffer.from(value, "ascii") : value;
  const bytes = Buffer.alloc(3 + input.length);
  bytes[0] = tag;
  bytes.writeUInt16BE(input.length, 1);
  bytes.set(input, 3);
  return bytes;
}
function counter(value: bigint): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(value);
  return bytes;
}
