# ADR-0023: Serve Blob calls addressed to the `blob` host on the DFS listener

- **Status:** Proposed

## Context

The Data Lake SDKs and the Azure CLI derive a Blob endpoint from the DFS endpoint by replacing `dfs` with `blob` in the host name and keeping the port. They use it for path properties, existence checks, metadata, HTTP headers, and downloads (`DataLakeFileClient.download_file`, `get_file_properties`, `az storage fs file download`). On Azure that host is a different service endpoint. Against Azuifer, where every service has its own port ([ADR-0009](0009-serve-each-service-on-its-own-listener.md)), the derived URL names the DFS port, so those calls would reach the DFS handler with a Blob request.

## Decision and scope

The DFS listener hands any request whose `Host` is `{account}.blob.{domain}` to the Blob handler, before it takes a DFS request slot, and answers every other request as DFS. The Blob handler runs against the same store, clock, configuration and request slots as the Blob listener, so the two ports show one namespace ([ADR-0003](0003-share-the-blob-and-dfs-namespace.md)). Path-style requests and `{account}.dfs.{domain}` hosts are always DFS. This is a routing rule on the listener, not a second implementation: the Blob parser, authentication and responses are the ones the Blob listener uses, and the DFS handler never calls Blob handlers. A user must still publish the DFS port to use it; a client that can address the Blob port directly is unaffected.

## Alternatives and consequences

Requiring users to configure separate Blob and DFS endpoints works for AzCopy and the .NET and Java SDKs but not for the Python Data Lake SDK, which exposes no override for the derived Blob URL. Sniffing request shape (`restype`, `comp`) instead of the host cannot separate a Blob Get Properties from a DFS Get Path Properties, which are the same `HEAD`. Host routing costs one host comparison per DFS request and a Blob state object built for the DFS listener.

## Verification criteria

- The Python Data Lake SDK, given only `http://{account}.dfs.localhost:{port}`, creates filesystems, files and directories, reads properties and downloads through the derived Blob host, and sees the same ETag and bytes the DFS listener reports.
- `az storage fs` with a connection string whose Blob endpoint uses the `blob` host on the DFS port completes its file and directory commands.
- A request to the DFS port with a path-style or `dfs` host is never answered by the Blob handler, and a `blob` host request does not consume two request slots.
