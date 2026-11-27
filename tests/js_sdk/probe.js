// Runs the JavaScript Azure Storage SDKs against Azuifer. Start the server with
// --services blob,queue,table,file,dfs --hns-accounts devstoreaccount1 --dfs-port 20003.
// The Data Lake SDK needs a host-style URL (map devstoreaccount1.dfs.localhost and
// devstoreaccount1.blob.localhost to 127.0.0.1) on a port outside the SDK's list of
// emulator ports, which it addresses path-style and then builds wrong rename URLs for.
const { BlobServiceClient, StorageSharedKeyCredential, generateBlobSASQueryParameters, BlobSASPermissions } = require("@azure/storage-blob");
const { QueueServiceClient, StorageSharedKeyCredential: QKey } = require("@azure/storage-queue");
const { TableServiceClient, TableClient, AzureNamedKeyCredential, odata } = require("@azure/data-tables");
const { FileSASPermissions, ShareServiceClient, StorageSharedKeyCredential: FKey } = require("@azure/storage-file-share");
const { DataLakeServiceClient, StorageSharedKeyCredential: DKey } = require("@azure/storage-file-datalake");
const crypto = require("crypto");
const assert = require("node:assert/strict");

const account = "devstoreaccount1";
const key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const sfx = crypto.randomBytes(4).toString("hex");
let failures = 0;
const only = process.argv[2] || "";
async function step(name, fn) {
  if (only && !name.startsWith(only)) return;
  try { await fn(); console.log("PASS " + name); }
  catch (e) { failures++; console.log("FAIL " + name + ": " + String(e && e.message || e).replace(/\s+/g, " ").slice(0, 400)); }
}
const check = (ok, what) => { if (!ok) throw new Error("check failed: " + what); };
const rnd = (n) => crypto.randomBytes(n);
async function toBuf(stream) { const c = []; for await (const x of stream) c.push(Buffer.from(x)); return Buffer.concat(c); }

(async () => {
  const cred = new StorageSharedKeyCredential(account, key);
  const blobSvc = new BlobServiceClient(`http://127.0.0.1:10000/${account}`, cred);
  const cont = blobSvc.getContainerClient("js" + sfx);
  await step("blob: create container with metadata", async () => { await cont.create({ metadata: { k: "v" } }); const p = await cont.getProperties(); check(p.metadata.k === "v", "meta"); });
  await step("blob: upload, download, ranged download", async () => {
    const data = rnd(5000); const b = cont.getBlockBlobClient("small.bin");
    await b.uploadData(data);
    check((await b.downloadToBuffer()).equals(data), "bytes");
    check((await b.downloadToBuffer(100, 200)).equals(data.subarray(100, 300)), "range");
  });
  await step("blob: parallel chunked upload 20 MiB", async () => {
    const data = rnd(20 * 1024 * 1024); const b = cont.getBlockBlobClient("big.bin");
    await b.uploadData(data, { blockSize: 4 * 1024 * 1024, concurrency: 4 });
    check((await b.downloadToBuffer()).equals(data), "bytes");
  });
  await step("blob: list flat, hierarchical, with metadata", async () => {
    await cont.getBlockBlobClient("dir/a.txt").upload("a", 1, { metadata: { m: "1" } });
    const flat = []; for await (const i of cont.listBlobsFlat({ includeMetadata: true })) flat.push(i.name);
    check(flat.includes("dir/a.txt"), flat.join());
    const hier = []; for await (const i of cont.listBlobsByHierarchy("/")) hier.push(i.name);
    check(hier.includes("dir/"), hier.join());
  });
  await step("blob: properties, headers, snapshot", async () => {
    const b = cont.getBlockBlobClient("small.bin");
    await b.setHTTPHeaders({ blobContentType: "text/x-test" }); await b.setMetadata({ x: "1" });
    const p = await b.getProperties(); check(p.contentType === "text/x-test" && p.metadata.x === "1", "props");
    const snap = await b.createSnapshot();
    const names = []; for await (const i of cont.listBlobsFlat({ includeSnapshots: true })) if (i.snapshot) names.push(i.snapshot);
    check(names.includes(snap.snapshot), "snapshot listed");
    await b.withSnapshot(snap.snapshot).delete();
  });
  await step("blob: lease", async () => {
    const l = cont.getBlobLeaseClient(); const b = cont.getBlobClient("small.bin");
    const lease = b.getBlobLeaseClient(); await lease.acquireLease(30); await lease.renewLease(); await lease.releaseLease();
  });
  await step("blob: tags and find by tags", async () => {
    const b = cont.getBlockBlobClient("small.bin"); await b.setTags({ color: "blue" });
    check((await b.getTags()).tags.color === "blue", "tags");
    let n = 0; for await (const x of blobSvc.findBlobsByTags("\"color\"='blue'")) n++;
    check(n >= 1, "find");
  });
  await step("blob: page blob and append blob", async () => {
    const p = cont.getPageBlobClient("p.vhd"); await p.create(4096); await p.uploadPages(rnd(1024), 512, 1024);
    const r = await p.getPageRanges(); check(r.pageRange.length === 1 && r.pageRange[0].offset === 512, "ranges");
    const a = cont.getAppendBlobClient("log.txt"); await a.create(); await a.appendBlock("hello ", 6); await a.appendBlock("world", 5);
    check((await a.downloadToBuffer()).toString() === "hello world", "append");
  });
  await step("blob: SAS", async () => {
    const sas = generateBlobSASQueryParameters({ containerName: cont.containerName, blobName: "small.bin", permissions: BlobSASPermissions.parse("r"), expiresOn: new Date(Date.now() + 3600e3) }, cred).toString();
    const { BlobClient } = require("@azure/storage-blob");
    const c = new BlobClient(`http://127.0.0.1:10000/${account}/${cont.containerName}/small.bin?${sas}`);
    check((await c.getProperties()).contentLength === 5000, "sas");
  });
  await step("blob: copy and batch delete", async () => {
    const src = cont.getBlobClient("small.bin"); const dst = cont.getBlobClient("copy.bin");
    const sasUrl = await src.generateSasUrl({ permissions: BlobSASPermissions.parse("r"), expiresOn: new Date(Date.now() + 3600e3) });
    const poller = await dst.beginCopyFromURL(sasUrl); await poller.pollUntilDone();
    check((await dst.getProperties()).contentLength === 5000, "copy");
    const bb = blobSvc.getBlobBatchClient();
    await bb.deleteBlobs([dst.url, cont.getBlobClient("log.txt").url], cred);
  });
  await step("blob: conditional create 409", async () => {
    try { await cont.getBlockBlobClient("small.bin").upload("x", 1, { conditions: { ifNoneMatch: "*" } }); throw new Error("expected failure"); }
    catch (e) { check(e.statusCode === 409 && e.code === "BlobAlreadyExists", String(e.code)); }
  });
  await step("blob: delete container", async () => { await cont.delete(); });

  const qs = new QueueServiceClient(`http://127.0.0.1:10001/${account}`, new QKey(account, key));
  await step("queue: lifecycle", async () => {
    const q = qs.getQueueClient("jsq" + sfx); await q.create();
    await q.sendMessage("one"); await q.sendMessage("two");
    check((await q.peekMessages({ numberOfMessages: 2 })).peekedMessageItems.length === 2, "peek");
    const r = await q.receiveMessages({ visibilityTimeout: 30 });
    check(r.receivedMessageItems[0].messageText === "one", "recv");
    await q.updateMessage(r.receivedMessageItems[0].messageId, r.receivedMessageItems[0].popReceipt, "uno", 1);
    await new Promise((s) => setTimeout(s, 1500));
    const again = await q.receiveMessages();
    await q.deleteMessage(again.receivedMessageItems[0].messageId, again.receivedMessageItems[0].popReceipt);
    await q.delete();
  });

  const tcred = new AzureNamedKeyCredential(account, key);
  const tname = "jst" + sfx;
  const tsvc = new TableServiceClient(`http://127.0.0.1:10002/${account}`, tcred, { allowInsecureConnection: true });
  const tc = new TableClient(`http://127.0.0.1:10002/${account}`, tname, tcred, { allowInsecureConnection: true });
  await step("table: crud and query", async () => {
    await tsvc.createTable(tname);
    await tc.createEntity({ partitionKey: "p", rowKey: "r1", n: 1, s: "alpha", d: 2.5, b: true });
    await tc.createEntity({ partitionKey: "p", rowKey: "r2", n: 2, s: "beta" });
    const e = await tc.getEntity("p", "r1"); check(e.s === "alpha", "get");
    const out = []; for await (const x of tc.listEntities({ queryOptions: { filter: odata`PartitionKey eq 'p' and n gt 1` } })) out.push(x.rowKey);
    check(out.length === 1 && out[0] === "r2", out.join());
    await tc.updateEntity({ partitionKey: "p", rowKey: "r1", s: "gamma" }, "Replace");
    await tc.upsertEntity({ partitionKey: "p", rowKey: "r3", n: 3 }, "Merge");
    await tc.deleteEntity("p", "r2");
  });
  await step("table: transaction", async () => {
    const r = await tc.submitTransaction([["create", { partitionKey: "b", rowKey: "1", v: 1 }], ["create", { partitionKey: "b", rowKey: "2", v: 2 }], ["upsert", { partitionKey: "b", rowKey: "3", v: 3 }]]);
    check(r.status === 202, "tx " + r.status);
    await tsvc.deleteTable(tname);
  });

  const fsvc = new ShareServiceClient(`http://127.0.0.1:10004/${account}`, new FKey(account, key));
  await step("files: share, dir, file, range", async () => {
    const sh = fsvc.getShareClient("jss" + sfx); await sh.create();
    const dir = sh.getDirectoryClient("d1"); await dir.create();
    const f = dir.getFileClient("f.bin"); const data = rnd(300000);
    await f.create(data.length); await f.uploadRange(data, 0, data.length);
    check((await f.downloadToBuffer()).equals(data), "bytes");
    const names = []; for await (const i of dir.listFilesAndDirectories()) names.push(i.name);
    check(names.includes("f.bin"), "list");
    await f.setMetadata({ a: "b" }); check((await f.getProperties()).metadata.a === "b", "meta");
    await sh.delete();
  });

  await step("files: copy with source SAS and a share-scoped permission", async () => {
    const sourceShare = fsvc.getShareClient("jssrc" + sfx);
    const targetShare = fsvc.getShareClient("jsdst" + sfx);
    await sourceShare.create();
    await targetShare.create();
    try {
      const source = sourceShare.rootDirectoryClient.getFileClient("source.txt");
      const target = targetShare.rootDirectoryClient.getFileClient("copy.txt");
      const sddl = "O:SYG:SYD:(A;;FR;;;SY)";
      const permission = await sourceShare.createPermission(sddl);
      const bytes = Buffer.from("source bytes");
      await source.create(bytes.length, { filePermissionKey: permission.filePermissionKey });
      await source.uploadRange(bytes, 0, bytes.length);
      const sasUrl = (access) => source.generateSasUrl({
        permissions: FileSASPermissions.parse(access), expiresOn: new Date(Date.now() + 300e3)
      });
      await assert.rejects(
        () => target.startCopyFromURL(sasUrl("w")),
        (e) => e.statusCode === 403 && (e.details?.errorCode || e.code) === "CannotVerifyCopySource"
      );
      check(!(await target.exists()), "a refused copy did not publish a file");
      check((await target.startCopyFromURL(sasUrl("r"))).copyStatus === "success", "accepted copy");
      check((await target.downloadToBuffer()).equals(bytes), "copied bytes");
      const props = await target.getProperties();
      check((await targetShare.getPermission(props.filePermissionKey)).permission === sddl, "copied permission resolves in the target share");
    } finally {
      await targetShare.delete();
      await sourceShare.delete();
    }
  });

  await step("files nfs: share, posix properties, hard and symbolic links", async () => {
    const sh = fsvc.getShareClient("jsn" + sfx);
    await sh.create({ protocols: { nfsEnabled: true }, rootSquash: "RootSquash" });
    const share = await sh.getProperties();
    check(share.protocols && share.protocols.nfsEnabled && !share.protocols.smbEnabled, "nfs protocol");
    check(share.rootSquash === "RootSquash", "root squash");
    const rw = (read, write) => ({ read, write, execute: false });
    const mode = { owner: rw(true, true), group: rw(true, false), other: rw(true, false), effectiveUserIdentity: false, effectiveGroupIdentity: false, stickyBit: false };
    const dir = sh.getDirectoryClient("d"); await dir.create({ posixProperties: { owner: "3", group: "4" } });
    const dprops = (await dir.getProperties()).posixProperties;
    check(dprops.owner === "3" && dprops.group === "4" && dprops.fileType === "Directory", "directory posix");
    const f = dir.getFileClient("f.txt");
    await f.create(5, { posixProperties: { owner: "7", group: "8", fileMode: mode } });
    await f.uploadRange(Buffer.from("hello"), 0, 5);
    const posix = (await f.getProperties()).posixProperties;
    check(posix.owner === "7" && posix.group === "8" && posix.linkCount === 1 && posix.fileType === "Regular", "file posix");
    check(posix.fileMode.owner.write && posix.fileMode.group.read && !posix.fileMode.group.write, "file mode");
    const l = dir.getFileClient("l.txt"); await l.createHardLink("d/f.txt");
    check((await l.getProperties()).posixProperties.linkCount === 2, "link count 2");
    check((await l.downloadToBuffer()).toString() === "hello", "link bytes");
    const s = sh.rootDirectoryClient.getFileClient("sym"); await s.createSymbolicLink("d/f.txt", { owner: "9" });
    check((await s.getSymbolicLink()).linkText === "d/f.txt", "symlink text");
    const sp = (await s.getProperties()).posixProperties;
    check(sp.fileType === "SymLink" && sp.owner === "9", "symlink posix");
    let refused = ""; try { await s.downloadToBuffer(); } catch (e) { refused = e.details && e.details.errorCode || e.code || String(e.message); }
    check(String(refused).includes("XNfs4FileTypeUnsupportedException"), "symlink bytes refused: " + refused);
    await f.delete();
    check((await l.getProperties()).posixProperties.linkCount === 1, "count after delete");
    check((await l.downloadToBuffer()).toString() === "hello", "bytes after first name deleted");
    await sh.delete();
  });

  await step("files: service properties round trip", async () => {
    const props = await fsvc.getProperties();
    check(props.hourMetrics && props.hourMetrics.enabled, "default hour metrics");
    await fsvc.setProperties({ ...props, cors: [{ allowedOrigins: "http://app.example", allowedMethods: "GET,PUT", allowedHeaders: "*", exposedHeaders: "x-ms-*", maxAgeInSeconds: 60 }] });
    const again = await fsvc.getProperties();
    check(again.cors.length === 1 && again.cors[0].allowedOrigins === "http://app.example", "cors kept");
  });
  const dsvc = new DataLakeServiceClient(`http://${account}.dfs.localhost:20003`, new DKey(account, key));
  const fs = dsvc.getFileSystemClient("jsf" + sfx);
  await step("dfs: filesystem, directory, file", async () => {
    await fs.create(); const dir = fs.getDirectoryClient("dir1"); await dir.create();
    const f = dir.getFileClient("hello.txt"); await f.create();
    await f.append("hello dfs", 0, 9); await f.flush(9);
    check((await toBuf((await f.read()).readableStreamBody)).toString() === "hello dfs", "read");
  });
  await step("dfs: upload 8 MiB chunked", async () => {
    const data = rnd(8 * 1024 * 1024); const f = fs.getFileClient("dir1/big.bin");
    await f.upload(data);
    check((await toBuf((await f.read()).readableStreamBody)).equals(data), "bytes");
  });
  await step("dfs: properties, list, ACL, rename", async () => {
    check((await fs.getFileClient("dir1/hello.txt").getProperties()).contentLength === 9, "len");
    const names = []; for await (const p of fs.listPaths({ recursive: true })) names.push(p.name);
    check(names.includes("dir1/hello.txt") && names.includes("dir1"), names.join());
    const dir = fs.getDirectoryClient("dir1");
    await dir.setPermissions({ owner: { read: true, write: true, execute: true }, group: { read: true, write: false, execute: true }, other: { read: false, write: false, execute: false }, stickyBit: false, extendedAcls: false });
    const acl = await dir.getAccessControl(); check(acl.permissions.group.read && !acl.permissions.group.write, "perm");
    await fs.getFileClient("dir1/hello.txt").move("dir1/renamed.txt");
    await dir.move("dir2");
    const after = []; for await (const p of fs.listPaths({ recursive: true })) after.push(p.name);
    check(after.includes("dir2/renamed.txt"), after.join());
  });
  await step("dfs: delete recursive and filesystem", async () => { await fs.getDirectoryClient("dir2").delete(true); await fs.delete(); });

  console.log(failures === 0 ? "ALL PASSED" : failures + " FAILED");
  process.exit(failures === 0 ? 0 : 1);
})();
