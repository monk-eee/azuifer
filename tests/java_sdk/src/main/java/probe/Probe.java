// Runs the Java Azure Storage SDKs against Azuifer. Start the server with
// --services blob,queue,table,file,dfs --hns-accounts devstoreaccount1 --file-port 80.
// The Java Share client drops the port and the account path from its endpoint, so Files
// needs a host-style URL on port 80 (map devstoreaccount1.file.localhost to the server).
package probe;

import com.azure.core.util.BinaryData;
import com.azure.data.tables.TableClient;
import com.azure.data.tables.TableServiceClient;
import com.azure.data.tables.TableServiceClientBuilder;
import com.azure.data.tables.models.TableEntity;
import com.azure.data.tables.models.TableTransactionAction;
import com.azure.data.tables.models.TableTransactionActionType;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobItem;
import com.azure.storage.blob.models.BlobHttpHeaders;
import com.azure.storage.blob.models.BlobRange;
import com.azure.storage.blob.models.ListBlobsOptions;
import com.azure.storage.blob.models.ParallelTransferOptions;
import com.azure.storage.blob.options.BlobParallelUploadOptions;
import com.azure.storage.blob.sas.BlobSasPermission;
import com.azure.storage.blob.sas.BlobServiceSasSignatureValues;
import com.azure.storage.blob.specialized.AppendBlobClient;
import com.azure.storage.blob.specialized.BlobLeaseClient;
import com.azure.storage.blob.specialized.BlobLeaseClientBuilder;
import com.azure.storage.blob.specialized.PageBlobClient;
import com.azure.storage.common.StorageSharedKeyCredential;
import com.azure.storage.file.datalake.DataLakeDirectoryClient;
import com.azure.storage.file.datalake.DataLakeFileClient;
import com.azure.storage.file.datalake.DataLakeFileSystemClient;
import com.azure.storage.file.datalake.DataLakeServiceClient;
import com.azure.storage.file.datalake.DataLakeServiceClientBuilder;
import com.azure.storage.file.datalake.models.ListPathsOptions;
import com.azure.storage.file.datalake.models.PathItem;
import com.azure.storage.file.share.ShareClient;
import com.azure.storage.file.share.ShareDirectoryClient;
import com.azure.storage.file.share.ShareFileClient;
import com.azure.storage.file.share.ShareServiceClient;
import com.azure.storage.file.share.ShareServiceClientBuilder;
import com.azure.storage.queue.QueueClient;
import com.azure.storage.queue.QueueServiceClient;
import com.azure.storage.queue.QueueServiceClientBuilder;
import com.azure.storage.queue.models.QueueMessageItem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

public class Probe {
    static int failures = 0;
    static String only = "";

    interface Body { void run() throws Exception; }

    static void step(String name, Body body) {
        if (!only.isEmpty() && !name.startsWith(only)) return;
        try { body.run(); System.out.println("PASS " + name); }
        catch (Throwable e) {
            failures++;
            String msg = String.valueOf(e.getMessage()).replaceAll("\\s+", " ");
            System.out.println("FAIL " + name + ": " + e.getClass().getSimpleName() + ": " + msg.substring(0, Math.min(400, msg.length())));
        }
    }

    static void check(boolean ok, String what) { if (!ok) throw new IllegalStateException("check failed: " + what); }

    static final Random RND = new Random(5);
    static byte[] bytes(int n) { byte[] b = new byte[n]; RND.nextBytes(b); return b; }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) only = args[0];
        String host = System.getenv().getOrDefault("AZUIFER_HOST", "127.0.0.1");
        String account = "devstoreaccount1";
        String key = System.getenv().getOrDefault("AZUIFER_ACCOUNT_KEY", "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==");
        StorageSharedKeyCredential cred = new StorageSharedKeyCredential(account, key);
        String sfx = UUID.randomUUID().toString().replace("-", "").substring(0, 8);

        // ---- Blob
        BlobServiceClient blobSvc = new BlobServiceClientBuilder().endpoint(System.getenv().getOrDefault("AZUIFER_BLOB", "http://" + host + ":10000/" + account)).credential(cred).buildClient();
        BlobContainerClient cont = blobSvc.getBlobContainerClient("jv" + sfx);
        step("blob: create container with metadata", () -> {
            cont.createWithResponse(Map.of("k", "v"), null, null, null);
            check("v".equals(cont.getProperties().getMetadata().get("k")), "metadata");
        });
        step("blob: upload, download, ranged download", () -> {
            byte[] data = bytes(5000);
            BlobClient b = cont.getBlobClient("small.bin");
            b.upload(BinaryData.fromBytes(data), true);
            check(Arrays.equals(b.downloadContent().toBytes(), data), "bytes");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            b.downloadStreamWithResponse(out, new BlobRange(100, 200L), null, null, false, null, null);
            check(Arrays.equals(out.toByteArray(), Arrays.copyOfRange(data, 100, 300)), "range");
        });
        step("blob: parallel chunked upload 20 MiB", () -> {
            byte[] data = bytes(20 * 1024 * 1024);
            BlobClient b = cont.getBlobClient("big.bin");
            ParallelTransferOptions pto = new ParallelTransferOptions().setBlockSizeLong(4L * 1024 * 1024).setMaxConcurrency(4);
            b.uploadWithResponse(new BlobParallelUploadOptions(new ByteArrayInputStream(data)).setParallelTransferOptions(pto), null, null);
            check(Arrays.equals(b.downloadContent().toBytes(), data), "bytes");
        });
        step("blob: list flat and hierarchical", () -> {
            cont.getBlobClient("dir/a.txt").upload(BinaryData.fromString("a"), true);
            List<String> flat = new ArrayList<>();
            for (BlobItem i : cont.listBlobs()) flat.add(i.getName());
            check(flat.contains("dir/a.txt"), String.join(",", flat));
            List<String> hier = new ArrayList<>();
            for (BlobItem i : cont.listBlobsByHierarchy("/", new ListBlobsOptions(), null)) hier.add(i.getName());
            check(hier.contains("dir/"), String.join(",", hier));
        });
        step("blob: properties, headers, metadata, snapshot", () -> {
            BlobClient b = cont.getBlobClient("small.bin");
            b.setHttpHeaders(new BlobHttpHeaders().setContentType("text/x-test"));
            b.setMetadata(Map.of("x", "1"));
            check("text/x-test".equals(b.getProperties().getContentType()) && "1".equals(b.getProperties().getMetadata().get("x")), "props");
            var snap = b.createSnapshot();
            List<String> snaps = new ArrayList<>();
            ListBlobsOptions opts = new ListBlobsOptions().setDetails(new com.azure.storage.blob.models.BlobListDetails().setRetrieveSnapshots(true));
            for (BlobItem i : cont.listBlobs(opts, null)) if (i.getSnapshot() != null) snaps.add(i.getSnapshot());
            check(snaps.contains(snap.getSnapshotId()), "snapshot listed");
            snap.delete();
        });
        step("blob: lease", () -> {
            BlobLeaseClient lease = new BlobLeaseClientBuilder().blobClient(cont.getBlobClient("small.bin")).buildClient();
            lease.acquireLease(30);
            lease.renewLease();
            lease.releaseLease();
        });
        step("blob: tags and find by tags", () -> {
            BlobClient b = cont.getBlobClient("small.bin");
            b.setTags(Map.of("color", "blue"));
            check("blue".equals(b.getTags().get("color")), "tags");
            int n = 0;
            for (var x : blobSvc.findBlobsByTags("\"color\"='blue'")) n++;
            check(n >= 1, "find");
        });
        step("blob: page blob and append blob", () -> {
            PageBlobClient p = cont.getBlobClient("p.vhd").getPageBlobClient();
            p.create(4096);
            p.uploadPages(new com.azure.storage.blob.models.PageRange().setStart(512).setEnd(1535), new ByteArrayInputStream(bytes(1024)));
            var ranges = p.getPageRanges(new BlobRange(0)).getPageRange();
            check(ranges.size() == 1 && ranges.get(0).getStart() == 512, "ranges");
            AppendBlobClient a = cont.getBlobClient("log.txt").getAppendBlobClient();
            a.create();
            a.appendBlock(new ByteArrayInputStream("hello ".getBytes(StandardCharsets.UTF_8)), 6);
            a.appendBlock(new ByteArrayInputStream("world".getBytes(StandardCharsets.UTF_8)), 5);
            check("hello world".equals(a.downloadContent().toString()), "append");
        });
        step("blob: SAS and server-side copy", () -> {
            BlobClient src = cont.getBlobClient("small.bin");
            String sas = src.generateSas(new BlobServiceSasSignatureValues(OffsetDateTime.now().plusHours(1), BlobSasPermission.parse("r")));
            BlobClient viaSas = new com.azure.storage.blob.BlobClientBuilder().endpoint(src.getBlobUrl() + "?" + sas).buildClient();
            check(viaSas.getProperties().getBlobSize() == 5000, "sas");
            BlobClient dst = cont.getBlobClient("copy.bin");
            dst.beginCopy(src.getBlobUrl() + "?" + sas, Duration.ofMillis(100)).waitForCompletion();
            check(dst.getProperties().getBlobSize() == 5000, "copy");
        });
        step("blob: batch delete", () -> {
            var batch = new com.azure.storage.blob.batch.BlobBatchClientBuilder(blobSvc).buildClient();
            try { batch.deleteBlobs(List.of(cont.getBlobClient("copy.bin").getBlobUrl(), cont.getBlobClient("log.txt").getBlobUrl()), com.azure.storage.blob.models.DeleteSnapshotsOptionType.INCLUDE).forEach(r -> { }); } catch (com.azure.storage.blob.batch.BlobBatchStorageException e) { StringBuilder sb = new StringBuilder(); e.getBatchExceptions().forEach(x -> sb.append(x.getStatusCode()).append(" ").append(x.getErrorCode()).append(" ").append(x.getMessage()).append(" | ")); throw new IllegalStateException(sb.toString()); }
        });
        step("blob: conditional create is 409", () -> {
            try {
                cont.getBlobClient("small.bin").uploadWithResponse(new BlobParallelUploadOptions(BinaryData.fromString("x")).setRequestConditions(new com.azure.storage.blob.models.BlobRequestConditions().setIfNoneMatch("*")), null, null);
                throw new IllegalStateException("expected failure");
            } catch (com.azure.storage.blob.models.BlobStorageException e) {
                check(e.getStatusCode() == 409 && "BlobAlreadyExists".equals(e.getErrorCode().toString()), String.valueOf(e.getErrorCode()));
            }
        });
        step("blob: delete container", () -> cont.delete());

        // ---- Queue
        QueueServiceClient qsvc = new QueueServiceClientBuilder().endpoint("http://" + host + ":10001/" + account).credential(cred).buildClient();
        step("queue: lifecycle", () -> {
            QueueClient q = qsvc.getQueueClient("jvq" + sfx);
            q.create();
            q.sendMessage("one");
            q.sendMessage("two");
            check(q.peekMessages(2, null, null).stream().count() == 2, "peek");
            QueueMessageItem m = q.receiveMessages(1, Duration.ofSeconds(30), null, null).iterator().next();
            check("one".equals(m.getBody().toString()), "recv");
            q.updateMessage(m.getMessageId(), m.getPopReceipt(), "uno", Duration.ofSeconds(1));
            Thread.sleep(1500);
            QueueMessageItem again = q.receiveMessage();
            q.deleteMessage(again.getMessageId(), again.getPopReceipt());
            q.delete();
        });

        // ---- Table
        TableServiceClient tsvc = new TableServiceClientBuilder().endpoint("http://" + host + ":10002/" + account)
            .credential(new com.azure.core.credential.AzureNamedKeyCredential(account, key)).buildClient();
        step("table: crud, query and transaction", () -> {
            String name = "jvt" + sfx;
            tsvc.createTable(name);
            TableClient tc = tsvc.getTableClient(name);
            tc.createEntity(new TableEntity("p", "r1").addProperty("n", 1).addProperty("s", "alpha").addProperty("d", 2.5).addProperty("b", true));
            tc.createEntity(new TableEntity("p", "r2").addProperty("n", 2));
            check("alpha".equals(tc.getEntity("p", "r1").getProperty("s")), "get");
            int n = 0;
            for (var e : tc.listEntities(new com.azure.data.tables.models.ListEntitiesOptions().setFilter("PartitionKey eq 'p' and n gt 1"), null, null)) n++;
            check(n == 1, "query " + n);
            tc.upsertEntity(new TableEntity("p", "r3").addProperty("n", 3));
            tc.deleteEntity("p", "r2");
            var result = tc.submitTransaction(List.of(
                new TableTransactionAction(TableTransactionActionType.CREATE, new TableEntity("b", "1").addProperty("v", 1)),
                new TableTransactionAction(TableTransactionActionType.CREATE, new TableEntity("b", "2").addProperty("v", 2))));
            check(result.getTransactionActionResponses().size() == 2, "tx");
            tsvc.deleteTable(name);
        });

        // ---- Files
        ShareServiceClient fsvc = new ShareServiceClientBuilder().endpoint(System.getenv().getOrDefault("AZUIFER_FILE_ENDPOINT", "http://" + account + ".file.localhost")).credential(cred).buildClient();
        step("files: share, directory, file, range", () -> {
            ShareClient share = fsvc.getShareClient("jvs" + sfx); 
            share.create();
            ShareDirectoryClient dir = share.getDirectoryClient("d1");
            dir.create();
            ShareFileClient f = dir.getFileClient("f.bin");
            byte[] data = bytes(300000);
            f.create(data.length);
            f.upload(new ByteArrayInputStream(data), data.length);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            f.download(out);
            check(Arrays.equals(out.toByteArray(), data), "bytes");
            boolean found = false;
            for (var i : dir.listFilesAndDirectories()) if (i.getName().equals("f.bin")) found = true;
            check(found, "list");
            f.setMetadata(Map.of("a", "b"));
            check("b".equals(f.getProperties().getMetadata().get("a")), "meta");
            share.delete();
        });
        step("files: NFS share, hard link, symbolic link", () -> {
            ShareClient nfs = fsvc.getShareClient("jvn" + sfx);
            nfs.createWithResponse(new com.azure.storage.file.share.options.ShareCreateOptions()
                .setProtocols(new com.azure.storage.file.share.models.ShareProtocols().setNfsEnabled(true)), null, null);
            byte[] data = bytes(5000);
            ShareFileClient target = nfs.getFileClient("target.bin");
            target.create(data.length);
            target.upload(new ByteArrayInputStream(data), data.length);
            ShareFileClient hard = nfs.getFileClient("hard.bin");
            hard.createHardLink("target.bin");
            ByteArrayOutputStream viaHard = new ByteArrayOutputStream();
            hard.download(viaHard);
            check(Arrays.equals(viaHard.toByteArray(), data), "hard link shares the bytes");
            ShareFileClient sym = nfs.getFileClient("sym.bin");
            sym.createSymbolicLink("target.bin");
            check("target.bin".equals(sym.getSymbolicLink().getLinkText()), "link text");
            nfs.delete();
        });

        // ---- DFS
        DataLakeServiceClient dsvc = new DataLakeServiceClientBuilder().endpoint("http://" + host + ":10003/" + account).credential(cred).buildClient();
        DataLakeFileSystemClient fs = dsvc.getFileSystemClient("jvf" + sfx);
        step("dfs: filesystem, directory, file", () -> {
            fs.create();
            DataLakeDirectoryClient dir = fs.createDirectory("dir1");
            DataLakeFileClient f = dir.createFile("hello.txt");
            byte[] data = "hello dfs".getBytes(StandardCharsets.UTF_8);
            f.append(new ByteArrayInputStream(data), 0, data.length);
            f.flush(data.length, true);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            f.read(out);
            check("hello dfs".equals(out.toString(StandardCharsets.UTF_8)), "read");
        });
        step("dfs: upload 8 MiB chunked", () -> {
            byte[] data = bytes(8 * 1024 * 1024);
            DataLakeFileClient f = fs.getFileClient("dir1/big.bin");
            f.upload(new ByteArrayInputStream(data), data.length, true);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            f.read(out);
            check(Arrays.equals(out.toByteArray(), data), "bytes");
        });
        step("dfs: properties, list, ACL, rename", () -> {
            check(fs.getFileClient("dir1/hello.txt").getProperties().getFileSize() == 9, "len");
            List<String> names = new ArrayList<>();
            for (PathItem p : fs.listPaths(new ListPathsOptions().setRecursive(true), null)) names.add(p.getName());
            check(names.contains("dir1/hello.txt") && names.contains("dir1"), String.join(",", names));
            DataLakeDirectoryClient dir = fs.getDirectoryClient("dir1");
            dir.setPermissions(com.azure.storage.file.datalake.models.PathPermissions.parseSymbolic("rwxr-x---"), null, null);
            String perm = dir.getAccessControl().getPermissions().toString(); check("0750".equals(perm), "perm " + perm);
            fs.getFileClient("dir1/hello.txt").rename(null, "dir1/renamed.txt");
            fs.getDirectoryClient("dir1").rename(null, "dir2");
            List<String> after = new ArrayList<>();
            for (PathItem p : fs.listPaths(new ListPathsOptions().setRecursive(true), null)) after.add(p.getName());
            check(after.contains("dir2/renamed.txt"), String.join(",", after));
        });
        step("dfs: create with a scheduled deletion", () -> {
            DataLakeFileClient f = fs.getFileClient("ttl.txt");
            f.createWithResponse(new com.azure.storage.file.datalake.options.DataLakePathCreateOptions()
                .setScheduleDeletionOptions(new com.azure.storage.file.datalake.options.DataLakePathScheduleDeletionOptions(Duration.ofSeconds(4))), null, null);
            byte[] data = "short lived".getBytes(StandardCharsets.UTF_8);
            f.append(new ByteArrayInputStream(data), 0, data.length);
            f.flush(data.length, true);
            var viaBlob = blobSvc.getBlobContainerClient(fs.getFileSystemName()).getBlobClient("ttl.txt");
            check(viaBlob.getProperties().getExpiresOn() != null, "blob shows the deadline");
            check(f.exists(), "present before the deadline");
            Thread.sleep(5000);
            check(!f.exists(), "gone after the deadline");
            check(!viaBlob.exists(), "gone for blob too");
        });
        step("dfs: delete recursive and filesystem", () -> {
            fs.getDirectoryClient("dir2").deleteWithResponse(true, null, null, null);
            fs.delete();
        });

        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
