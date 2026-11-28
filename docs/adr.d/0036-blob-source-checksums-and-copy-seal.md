# ADR-0036: Verify From-URL source checksums and seal on Copy Blob

- **Status:** Proposed

## Context

The Blob manifest recorded `x-ms-source-content-md5`, `x-ms-source-content-crc64`, and `x-ms-seal-blob` as unimplemented. A request carrying one was refused with 501 `NotImplemented`, so an SDK or tool that sent a source hash could not write at all. The work began from a broader description, so this record first fixes what the Azure documentation actually defines. Sources: the Microsoft Learn REST pages for [Put Blob From URL](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob-from-url), [Put Block From URL](https://learn.microsoft.com/en-us/rest/api/storageservices/put-block-from-url), [Put Page From URL](https://learn.microsoft.com/en-us/rest/api/storageservices/put-page-from-url), [Append Block From URL](https://learn.microsoft.com/en-us/rest/api/storageservices/append-block-from-url), [Append Block](https://learn.microsoft.com/en-us/rest/api/storageservices/append-block), and [Copy Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/copy-blob), read on the date this record was drafted.

| Operation | `x-ms-source-content-md5` | `x-ms-source-content-crc64` | `x-ms-seal-blob` |
| --- | --- | --- | --- |
| Put Blob From URL | documented | not documented as a source header | no |
| Put Block From URL | documented | documented | no |
| Put Page From URL | documented | documented | no |
| Append Block From URL | documented | documented | no |
| Append Block | no | no | **no** |
| Copy Blob | no | no | documented, append blobs only |

For the three operations that take both hashes, a request that carries both fails with 400. A mismatch between the declared hash and the bytes that arrived from the source fails with 400, and the hash is not stored with the blob. `x-ms-seal-blob` on Copy Blob seals the destination after the copy and is valid for append blobs only. Append Block, including its From-URL form, has no seal header; sealing an append blob is the separate `comp=seal` operation, which already exists.

## Decision and scope

- **Source checksums.** The four From-URL operations accept the headers marked above. The hash is compared with the bytes actually read from the source window, before anything is written, by the same `Checksums::verify` that checks a request-body hash, so one comparison serves both kinds. A mismatch changes no state: no pages, no appended block, no staged block, no blob.
- **Errors.** A mismatch answers 400 `Md5Mismatch` or `Crc64Mismatch`; both headers, a value that is not base64, or a value of the wrong length answers 400 `InvalidHeaderValue`. Put Blob From URL keeps refusing `x-ms-source-content-crc64` with `NotImplemented`, because the documentation lists no such source header for it.
- **Seal.** Copy Blob accepts `x-ms-seal-blob`. `true` seals an append destination; `false` or absence leaves it unsealed, as before. `true` on a page or block blob source answers 400 `InvalidHeaderValue` and copies nothing. Any other value is 400 `InvalidHeaderValue`. The response gains no header.
- **Not added.** Append Block and Append Block From URL do not accept `x-ms-seal-blob`; adding it would implement a header Azure does not define. They keep answering 501 for it.

## Unverified until live Azure recording

The Learn pages state the 400 status but not the error code of a source-hash mismatch, so `Md5Mismatch` and `Crc64Mismatch` follow the codes Azure uses for a request-body hash and are not confirmed. The same applies to the code for both hash headers present, to the code and status for sealing a non-append copy, and to whether a copy from a sealed append source is unsealed when `x-ms-seal-blob` is absent (Azuifer leaves it unsealed, which `x-ms-seal-blob: false` also asks for explicitly). The documentation of the success response headers is inconsistent about when `Content-MD5` and `x-ms-content-crc64` are returned; Azuifer still returns `Content-MD5` for these operations. The planned rows B-47 and B-48 in the [recording plan](../compatibility/azure-recording-plan.md) exist to settle these points. Until then every affected operation stays `known-difference`.

## Alternatives and consequences

Ignoring the headers, as an emulator may be tempted to do, would let a corrupted transfer succeed and hide the failure a real service reports. Hashing in the store would reach the check later and leave a staged file to clean up; checking in the executor, after the source is read and before any write, keeps the failure free of side effects. Putting `x-ms-seal-blob` on Append Block, as first proposed, was rejected because the Azure documentation defines no such header.

## Verification criteria

- For each of Put Blob From URL, Put Block From URL, Put Page From URL, and Append Block From URL, a matching hash succeeds, a mismatch answers 400 and leaves the destination as it was, and (where both are documented) both headers together are refused.
- A source window smaller than the blob is hashed over the window, not the whole blob.
- Copy Blob with `x-ms-seal-blob: true` of an append blob yields a sealed destination that answers `BlobIsSealed` to an append, and leaves the source open; the same header on a page or block blob source is refused and creates nothing.
- The official Python SDK's `source_content_md5` and `seal_destination_blob` options work against Azuifer.
