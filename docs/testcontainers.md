# Use Azuifer with Testcontainers

Run Azuifer as a throwaway container in integration tests. Each example starts the image with in-memory storage, waits for the readiness endpoint, and uploads a blob through the official Azure SDK.

Build the image once from the repository root, or use the tag from your own registry:

```sh
docker build -t azuifer:latest .
```

## Container contract

| Item | Value |
| --- | --- |
| Ports | Blob `10000`, Queue `10001`, Table `10002`, Data Lake (DFS) `10003`, Files `10004`, admin `10005` |
| Command | `serve --bind 0.0.0.0 --in-memory --skip-api-version-check` (the image entrypoint is `/azuifer`) |
| Account key | `AZUIFER_ACCOUNT_KEY`: a Base64 key that decodes to 32 through 64 bytes. Generate a fresh one per run. |
| Account name | `devstoreaccount1` unless you set `AZUIFER_ACCOUNT_NAME` |
| Readiness | `GET /readyz` on port `10005` returns `200` with `ready` |
| Endpoints | Path style: `http://<host>:<mapped port>/<account>` |

The container binds `0.0.0.0` so that the host can reach the mapped ports. Azuifer refuses the public development key on a non-loopback bind, so the container fails to start without `AZUIFER_ACCOUNT_KEY`. `--skip-api-version-check` lets SDKs that send a newer `x-ms-version` than the Blob baseline (`2023-11-03`) work. Omit it to test a client pinned to the baseline.

Map every port with a random host port and read the mapped port from the container. Do not hard-code `10000`, so parallel tests do not collide.

For state that survives a restart, drop `--in-memory` and mount a volume at `/data` with `--location /data`.

## Java

Uses `org.testcontainers:testcontainers` and `com.azure:azure-storage-blob`.

```java
import com.azure.core.util.BinaryData;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.common.StorageSharedKeyCredential;
import java.security.SecureRandom;
import java.util.Base64;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

byte[] bytes = new byte[32];
new SecureRandom().nextBytes(bytes);
String key = Base64.getEncoder().encodeToString(bytes);

try (GenericContainer<?> azuifer = new GenericContainer<>(DockerImageName.parse("azuifer:latest"))
        .withEnv("AZUIFER_ACCOUNT_KEY", key)
        .withCommand("serve", "--bind", "0.0.0.0", "--in-memory", "--skip-api-version-check")
        .withExposedPorts(10000, 10001, 10002, 10003, 10004, 10005)
        .waitingFor(Wait.forHttp("/readyz").forPort(10005).forStatusCode(200))) {
    azuifer.start();

    String blobEndpoint = "http://" + azuifer.getHost() + ":" + azuifer.getMappedPort(10000)
            + "/devstoreaccount1";
    BlobServiceClient service = new BlobServiceClientBuilder()
            .endpoint(blobEndpoint)
            .credential(new StorageSharedKeyCredential("devstoreaccount1", key))
            .buildClient();
    service.createBlobContainer("example").getBlobClient("hello.txt").upload(
            BinaryData.fromString("hello"));
}
```

## .NET

Uses `Testcontainers` and `Azure.Storage.Blobs`.

```csharp
using System.Security.Cryptography;
using Azure.Storage;
using Azure.Storage.Blobs;
using DotNet.Testcontainers.Builders;

var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

await using var azuifer = new ContainerBuilder()
    .WithImage("azuifer:latest")
    .WithEnvironment("AZUIFER_ACCOUNT_KEY", key)
    .WithCommand("serve", "--bind", "0.0.0.0", "--in-memory", "--skip-api-version-check")
    .WithPortBinding(10000, true)
    .WithPortBinding(10001, true)
    .WithPortBinding(10002, true)
    .WithPortBinding(10003, true)
    .WithPortBinding(10004, true)
    .WithPortBinding(10005, true)
    .WithWaitStrategy(Wait.ForUnixContainer()
        .UntilHttpRequestIsSucceeded(request => request.ForPath("/readyz").ForPort(10005)))
    .Build();
await azuifer.StartAsync();

var blobEndpoint = new Uri($"http://{azuifer.Hostname}:{azuifer.GetMappedPublicPort(10000)}/devstoreaccount1");
var service = new BlobServiceClient(blobEndpoint, new StorageSharedKeyCredential("devstoreaccount1", key));
var container = (await service.CreateBlobContainerAsync("example")).Value;
await container.GetBlobClient("hello.txt").UploadAsync(BinaryData.FromString("hello"));
```

## Node.js

Uses `testcontainers` and `@azure/storage-blob`.

```ts
import { randomBytes } from "node:crypto";
import { GenericContainer, Wait } from "testcontainers";
import { BlobServiceClient, StorageSharedKeyCredential } from "@azure/storage-blob";

const key = randomBytes(32).toString("base64");

const azuifer = await new GenericContainer("azuifer:latest")
  .withEnvironment({ AZUIFER_ACCOUNT_KEY: key })
  .withCommand(["serve", "--bind", "0.0.0.0", "--in-memory", "--skip-api-version-check"])
  .withExposedPorts(10000, 10001, 10002, 10003, 10004, 10005)
  .withWaitStrategy(Wait.forHttp("/readyz", 10005).forStatusCode(200))
  .start();

try {
  const endpoint = `http://${azuifer.getHost()}:${azuifer.getMappedPort(10000)}/devstoreaccount1`;
  const service = new BlobServiceClient(
    endpoint,
    new StorageSharedKeyCredential("devstoreaccount1", key),
  );
  const container = service.getContainerClient("example");
  await container.create();
  await container.getBlockBlobClient("hello.txt").upload("hello", 5);
} finally {
  await azuifer.stop();
}
```

## Python

Uses `testcontainers` and `azure-storage-blob`.

```python
import base64
import os
import time
import urllib.request

from azure.storage.blob import BlobServiceClient
from testcontainers.core.container import DockerContainer

key = base64.b64encode(os.urandom(32)).decode()

azuifer = (
    DockerContainer("azuifer:latest")
    .with_env("AZUIFER_ACCOUNT_KEY", key)
    .with_command("serve --bind 0.0.0.0 --in-memory --skip-api-version-check")
    .with_exposed_ports(10000, 10001, 10002, 10003, 10004, 10005)
)

with azuifer:
    host = azuifer.get_container_host_ip()
    admin = f"http://{host}:{azuifer.get_exposed_port(10005)}"
    for _ in range(100):
        try:
            if urllib.request.urlopen(f"{admin}/readyz", timeout=2).status == 200:
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Azuifer did not become ready")

    endpoint = f"http://{host}:{azuifer.get_exposed_port(10000)}/devstoreaccount1"
    service = BlobServiceClient(endpoint, credential={"account_name": "devstoreaccount1", "account_key": key})
    service.create_container("example").upload_blob("hello.txt", b"hello")
```

## Other services

Use the same container and map the other ports. Each service has its own listener, so give each client its own endpoint:

| Service | Container port | Endpoint |
| --- | --- | --- |
| Queue | `10001` | `http://<host>:<port>/devstoreaccount1` |
| Table | `10002` | `http://<host>:<port>/devstoreaccount1` |
| Data Lake (DFS) | `10003` | `http://<host>:<port>/devstoreaccount1` (HNS accounts only; start with `--hns-accounts devstoreaccount1`) |
| Files | `10004` | `http://<host>:<port>/devstoreaccount1` |

Inspect a running test container with `azuifer status` and `azuifer doctor`. The image has no shell, so call the binary directly and pass the same flags the container was started with:

```sh
docker exec <container> /azuifer status
docker exec <container> /azuifer doctor --bind 0.0.0.0 --in-memory
```

`doctor` uses `/status` to check which listeners and storage locks belong to the running instance. An occupied port or lock is not considered healthy just because an admin listener responds. The status reports a persistent data directory as an absolute path.

Add `--prometheus` to the command to serve metrics at `http://<host>:<admin port>/metrics`. Set `--otlp-endpoint http://<collector>:4317` to send traces and metrics to a collector on the container network.
