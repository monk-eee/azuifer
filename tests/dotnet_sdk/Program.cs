using System.Text;
using Azure;
using Azure.Data.Tables;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Azure.Storage.Blobs.Batch;
using Azure.Storage.Files.DataLake;
using Azure.Storage.Files.DataLake.Models;
using Azure.Storage.Files.Shares;
using Azure.Storage.Files.Shares.Models;
using Azure.Storage.Queues;
using Azure.Storage.Sas;

const string account = "devstoreaccount1";
const string key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
var cred = new StorageSharedKeyCredential(account, key);
var failures = 0;
var only = args.Length > 0 ? args[0] : "";

async Task Step(string name, Func<Task> body)
{
    if (only != "" && !name.StartsWith(only)) return;
    try { await body(); Console.WriteLine($"PASS {name}"); }
    catch (Exception e)
    {
        failures++;
        var msg = e.Message.Replace("\n", " ").Replace("\r", "");
        Console.WriteLine($"FAIL {name}: {e.GetType().Name}: {msg[..Math.Min(400, msg.Length)]}");
    }
}
void Check(bool ok, string what) { if (!ok) throw new Exception("check failed: " + what); }

var rnd = new Random(5);
byte[] Bytes(int n) { var b = new byte[n]; rnd.NextBytes(b); return b; }
var suffix = Guid.NewGuid().ToString("N")[..8];

// ---------------- Blob
var blobSvc = new BlobServiceClient(new Uri("http://127.0.0.1:10000" + $"/{account}"), cred);
var container = blobSvc.GetBlobContainerClient("dn" + suffix);
await Step("blob: create container", async () => await container.CreateAsync(metadata: new Dictionary<string, string> { ["k"] = "v" }));
await Step("blob: container properties and metadata", async () =>
{
    var p = (await container.GetPropertiesAsync()).Value;
    Check(p.Metadata["k"] == "v", "metadata");
});
await Step("blob: upload and download small block blob", async () =>
{
    var data = Bytes(5000);
    var b = container.GetBlobClient("small.bin");
    await b.UploadAsync(new BinaryData(data), overwrite: true);
    var dl = (await b.DownloadContentAsync()).Value.Content.ToArray();
    Check(dl.SequenceEqual(data), "bytes");
});
await Step("blob: parallel chunked upload 20 MiB and ranged download", async () =>
{
    var data = Bytes(20 * 1024 * 1024);
    var b = container.GetBlobClient("big.bin");
    await b.UploadAsync(new MemoryStream(data), new BlobUploadOptions { TransferOptions = new StorageTransferOptions { MaximumTransferSize = 4 * 1024 * 1024, InitialTransferSize = 4 * 1024 * 1024, MaximumConcurrency = 4 } });
    var r = (await b.DownloadAsync(new HttpRange(1000, 5000))).Value;
    var ms = new MemoryStream(); await r.Content.CopyToAsync(ms);
    Check(ms.ToArray().SequenceEqual(data.Skip(1000).Take(5000)), "range");
    var full = new MemoryStream(); await b.DownloadToAsync(full);
    Check(full.ToArray().SequenceEqual(data), "full");
});
await Step("blob: list flat and hierarchical", async () =>
{
    await container.GetBlobClient("dir/a.txt").UploadAsync(new BinaryData("a"), overwrite: true);
    var names = new List<string>();
    await foreach (var i in container.GetBlobsAsync()) names.Add(i.Name);
    Check(names.Contains("dir/a.txt") && names.Count >= 3, "flat " + string.Join(",", names));
    var hier = new List<string>();
    await foreach (var i in container.GetBlobsByHierarchyAsync(BlobTraits.None, BlobStates.None, "/", null, default)) hier.Add(i.IsPrefix ? i.Prefix : i.Blob.Name);
    Check(hier.Contains("dir/"), "hier " + string.Join(",", hier));
});
await Step("blob: metadata, properties, headers", async () =>
{
    var b = container.GetBlobClient("small.bin");
    await b.SetMetadataAsync(new Dictionary<string, string> { ["x"] = "1" });
    await b.SetHttpHeadersAsync(new BlobHttpHeaders { ContentType = "text/x-test", CacheControl = "no-cache" });
    var p = (await b.GetPropertiesAsync()).Value;
    Check(p.Metadata["x"] == "1" && p.ContentType == "text/x-test", "props");
});
await Step("blob: snapshot listing", async () =>
{
    var b = container.GetBlobClient("small.bin");
    var snap = (await b.CreateSnapshotAsync()).Value;
    var found = false;
    await foreach (var i in container.GetBlobsAsync(new GetBlobsOptions { States = BlobStates.Snapshots })) if (i.Snapshot == snap.Snapshot) found = true;
    Check(found, "snapshot listed");
    await b.WithSnapshot(snap.Snapshot).DeleteAsync();
});
await Step("blob: lease acquire, renew, release", async () =>
{
    var b = container.GetBlobClient("small.bin");
    var lease = b.GetBlobLeaseClient();
    await lease.AcquireAsync(TimeSpan.FromSeconds(30));
    await lease.RenewAsync();
    await lease.ReleaseAsync();
});
await Step("blob: tags and find by tags", async () =>
{
    var b = container.GetBlobClient("small.bin");
    await b.SetTagsAsync(new Dictionary<string, string> { ["color"] = "blue" });
    var t = (await b.GetTagsAsync()).Value.Tags;
    Check(t["color"] == "blue", "tags");
    var n = 0;
    await foreach (var x in blobSvc.FindBlobsByTagsAsync("\"color\"='blue'")) n++;
    Check(n >= 1, "find");
});
await Step("blob: page blob write/read ranges", async () =>
{
    var p = container.GetPageBlobClient("page.vhd");
    await p.CreateAsync(4096);
    await p.UploadPagesAsync(new MemoryStream(Bytes(1024)), 512);
    var ranges = (await p.GetPageRangesAsync()).Value.PageRanges.ToList();
    Check(ranges.Count == 1 && ranges[0].Offset == 512, "ranges");
});
await Step("blob: append blob", async () =>
{
    var a = container.GetAppendBlobClient("log.txt");
    await a.CreateAsync();
    await a.AppendBlockAsync(new MemoryStream(Encoding.UTF8.GetBytes("hello ")));
    await a.AppendBlockAsync(new MemoryStream(Encoding.UTF8.GetBytes("world")));
    var s = (await a.DownloadContentAsync()).Value.Content.ToString();
    Check(s == "hello world", s);
});
await Step("blob: service SAS and account SAS", async () =>
{
    var b = container.GetBlobClient("small.bin");
    var uri = b.GenerateSasUri(BlobSasPermissions.Read, DateTimeOffset.UtcNow.AddHours(1));
    var viaSas = new BlobClient(uri);
    Check((await viaSas.GetPropertiesAsync()).Value.ContentLength == 5000, "sas read");
    var acct = blobSvc.GenerateAccountSasUri(AccountSasPermissions.All, DateTimeOffset.UtcNow.AddHours(1), AccountSasResourceTypes.All);
    var svc2 = new BlobServiceClient(acct);
    await foreach (var c in svc2.GetBlobContainersAsync()) { break; }
});
await Step("blob: server-side copy", async () =>
{
    var dst = container.GetBlobClient("copy.bin");
    var src = container.GetBlobClient("small.bin").GenerateSasUri(BlobSasPermissions.Read, DateTimeOffset.UtcNow.AddHours(1));
    var op = await dst.StartCopyFromUriAsync(src);
    await op.WaitForCompletionAsync();
    Check((await dst.GetPropertiesAsync()).Value.ContentLength == 5000, "copy len");
});
await Step("blob: batch delete", async () =>
{
    var batch = blobSvc.GetBlobBatchClient();
    var uris = new[] { container.GetBlobClient("copy.bin").Uri, container.GetBlobClient("log.txt").Uri };
    await batch.DeleteBlobsAsync(uris);
});
await Step("blob: conditional request fails with 409", async () =>
{
    var b = container.GetBlobClient("small.bin");
    try { await b.UploadAsync(new BinaryData("x"), new BlobUploadOptions { Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All } }); throw new Exception("expected failure"); }
    catch (RequestFailedException e) { Check(e.Status == 409 && e.ErrorCode == "BlobAlreadyExists", e.ErrorCode ?? "?"); }
});
await Step("blob: delete container", async () => await container.DeleteAsync());

// ---------------- Queue
var qsvc = new QueueServiceClient(new Uri($"http://127.0.0.1:10001/{account}"), cred);
var queue = qsvc.GetQueueClient("dnq" + suffix);
await Step("queue: create, send, peek, receive, update, delete", async () =>
{
    await queue.CreateAsync();
    await queue.SendMessageAsync("one");
    await queue.SendMessageAsync("two");
    var peek = (await queue.PeekMessagesAsync(2)).Value;
    Check(peek.Length == 2, "peek");
    var got = (await queue.ReceiveMessagesAsync(1, TimeSpan.FromSeconds(30))).Value;
    Check(got.Length == 1 && got[0].MessageText == "one", "receive");
    await queue.UpdateMessageAsync(got[0].MessageId, got[0].PopReceipt, "uno", TimeSpan.FromSeconds(1));
    await Task.Delay(1500);
    var again = (await queue.ReceiveMessagesAsync(1)).Value;
    Check(again[0].MessageText == "uno" || again[0].MessageText == "two", "after update");
    await queue.DeleteMessageAsync(again[0].MessageId, again[0].PopReceipt);
    var props = (await queue.GetPropertiesAsync()).Value;
    Check(props.ApproximateMessagesCount >= 1, "count");
    await queue.DeleteAsync();
});

// ---------------- Table
var tsvc = new TableServiceClient(new Uri($"http://127.0.0.1:10002/{account}"), new TableSharedKeyCredential(account, key));
var table = tsvc.GetTableClient("dnt" + suffix);
await Step("table: create, insert, get, query, update, delete", async () =>
{
    await table.CreateAsync();
    await table.AddEntityAsync(new TableEntity("p", "r1") { ["n"] = 1, ["s"] = "alpha", ["d"] = 2.5, ["b"] = true, ["dt"] = DateTimeOffset.UtcNow, ["g"] = Guid.NewGuid(), ["bin"] = new byte[] { 1, 2, 3 }, ["l"] = 1L << 40 });
    await table.AddEntityAsync(new TableEntity("p", "r2") { ["n"] = 2, ["s"] = "beta" });
    var e = (await table.GetEntityAsync<TableEntity>("p", "r1")).Value;
    Check(e.GetInt32("n") == 1 && e.GetInt64("l") == 1L << 40 && e.GetBinary("bin").Length == 3, "get");
    var q = table.Query<TableEntity>(x => x.PartitionKey == "p" && x.GetInt32("n") > 1).ToList();
    Check(q.Count == 1 && q[0].RowKey == "r2", "query");
    e["s"] = "gamma";
    await table.UpdateEntityAsync(e, e.ETag, TableUpdateMode.Replace);
    await table.UpsertEntityAsync(new TableEntity("p", "r3") { ["n"] = 3 });
    await table.DeleteEntityAsync("p", "r2");
});
await Step("table: transaction batch", async () =>
{
    var actions = new List<TableTransactionAction>
    {
        new(TableTransactionActionType.Add, new TableEntity("b", "1") { ["v"] = 1 }),
        new(TableTransactionActionType.Add, new TableEntity("b", "2") { ["v"] = 2 }),
        new(TableTransactionActionType.UpsertReplace, new TableEntity("b", "3") { ["v"] = 3 }),
    };
    var r = await table.SubmitTransactionAsync(actions);
    Check(r.Value.Count == 3, "batch result");
});
await Step("table: list tables and delete", async () =>
{
    var found = false;
    await foreach (var t in tsvc.QueryAsync()) if (t.Name == table.Name) found = true;
    Check(found, "listed");
    await table.DeleteAsync();
});

// ---------------- Files
var fsvc = new ShareServiceClient(new Uri($"http://127.0.0.1:10004/{account}"), cred);
var share = fsvc.GetShareClient("dns" + suffix);
await Step("files: share, directory, file upload and download", async () =>
{
    await share.CreateAsync();
    var dir = share.GetDirectoryClient("d1");
    await dir.CreateAsync();
    var f = dir.GetFileClient("f.bin");
    var data = Bytes(300000);
    await f.CreateAsync(data.Length);
    await f.UploadRangeAsync(new HttpRange(0, data.Length), new MemoryStream(data));
    var dl = (await f.DownloadAsync()).Value.Content;
    var ms = new MemoryStream(); await dl.CopyToAsync(ms);
    Check(ms.ToArray().SequenceEqual(data), "bytes");
    var names = new List<string>();
    await foreach (var i in dir.GetFilesAndDirectoriesAsync()) names.Add(i.Name);
    Check(names.Contains("f.bin"), "list");
});
await Step("files: metadata, ranges, delete share", async () =>
{
    var f = share.GetDirectoryClient("d1").GetFileClient("f.bin");
    await f.SetMetadataAsync(new Dictionary<string, string> { ["a"] = "b" });
    var props = (await f.GetPropertiesAsync()).Value;
    Check(props.Metadata["a"] == "b", "meta");
    var ranges = (await f.GetRangeListAsync(new HttpRange())).Value.Ranges.ToList();
    Check(ranges.Count >= 1, "ranges");
    await share.DeleteAsync();
});

await Step("files: service properties round trip", async () =>
{
    var props = (await fsvc.GetPropertiesAsync()).Value;
    Check(props.HourMetrics.Enabled, "default hour metrics");
    props.Cors = new List<ShareCorsRule> { new ShareCorsRule { AllowedOrigins = "http://app.example", AllowedMethods = "GET,PUT", AllowedHeaders = "*", ExposedHeaders = "x-ms-*", MaxAgeInSeconds = 60 } };
    await fsvc.SetPropertiesAsync(props);
    var again = (await fsvc.GetPropertiesAsync()).Value;
    Check(again.Cors.Count == 1 && again.Cors[0].AllowedOrigins == "http://app.example", "cors kept");
});
// ---------------- DFS
var dsvc = new DataLakeServiceClient(new Uri($"http://127.0.0.1:10003/{account}"), cred);
var fs = dsvc.GetFileSystemClient("dnf" + suffix);
await Step("dfs: create filesystem, directory, file", async () =>
{
    await fs.CreateAsync();
    var dir = fs.GetDirectoryClient("dir1");
    await dir.CreateAsync();
    var file = dir.GetFileClient("hello.txt");
    await file.CreateAsync();
    await file.AppendAsync(new MemoryStream(Encoding.UTF8.GetBytes("hello dfs")), 0);
    await file.FlushAsync(9);
    var content = (await file.ReadContentAsync()).Value.Content.ToString();
    Check(content == "hello dfs", content);
});
await Step("dfs: upload 8 MiB with chunking and read back", async () =>
{
    var data = Bytes(8 * 1024 * 1024);
    var file = fs.GetFileClient("dir1/big.bin");
    await file.UploadAsync(new MemoryStream(data), new DataLakeFileUploadOptions { TransferOptions = new StorageTransferOptions { MaximumTransferSize = 2 * 1024 * 1024, InitialTransferSize = 2 * 1024 * 1024, MaximumConcurrency = 4 } });
    var ms = new MemoryStream(); await file.ReadToAsync(ms);
    Check(ms.ToArray().SequenceEqual(data), "bytes");
});
await Step("dfs: get properties, list paths recursive", async () =>
{
    var p = (await fs.GetFileClient("dir1/hello.txt").GetPropertiesAsync()).Value;
    Check(p.ContentLength == 9, "len");
    var names = new List<string>();
    await foreach (var i in fs.GetPathsAsync(null, true, false, default)) names.Add(i.Name);
    Check(names.Contains("dir1/hello.txt") && names.Contains("dir1"), string.Join(",", names));
});
await Step("dfs: access control get/set", async () =>
{
    var dir = fs.GetDirectoryClient("dir1");
    await dir.GetAccessControlAsync();
    await dir.SetPermissionsAsync(PathPermissions.ParseSymbolicPermissions("rwxr-x---"));
    var again = (await dir.GetAccessControlAsync()).Value;
    Check(again.Permissions.Owner == (RolePermissions.Read | RolePermissions.Write | RolePermissions.Execute) && again.Permissions.Group == (RolePermissions.Read | RolePermissions.Execute) && again.Permissions.Other == RolePermissions.None, again.Permissions.ToString());
    await dir.SetAccessControlListAsync(PathAccessControlExtensions.ParseAccessControlList("user::rwx,group::r-x,other::---,user:11111111-1111-1111-1111-111111111111:r-x,mask::r-x"));
});
await Step("dfs: rename file and directory", async () =>
{
    await fs.GetFileClient("dir1/hello.txt").RenameAsync("dir1/renamed.txt");
    await fs.GetDirectoryClient("dir1").RenameAsync("dir2");
    var names = new List<string>();
    await foreach (var i in fs.GetPathsAsync(null, true, false, default)) names.Add(i.Name);
    Check(names.Contains("dir2/renamed.txt") && !names.Contains("dir1"), string.Join(",", names));
});
await Step("dfs: blob API sees the same bytes", async () =>
{
    var bc = new BlobServiceClient(new Uri($"http://127.0.0.1:10000/{account}"), cred).GetBlobContainerClient(fs.Name).GetBlobClient("dir2/renamed.txt");
    var s = (await bc.DownloadContentAsync()).Value.Content.ToString();
    Check(s == "hello dfs", s);
});
await Step("dfs: lease, delete directory recursive, delete filesystem", async () =>
{
    var lease = fs.GetFileClient("dir2/renamed.txt").GetDataLakeLeaseClient();
    await lease.AcquireAsync(TimeSpan.FromSeconds(20));
    await lease.ReleaseAsync();
    await fs.GetDirectoryClient("dir2").DeleteAsync(recursive: true);
    await fs.DeleteAsync();
});

Console.WriteLine(failures == 0 ? "ALL PASSED" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
