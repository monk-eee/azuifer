# ADR-0037: Check Put Range From URL source checksums and read other accounts' files with their SAS

- **Status:** Proposed

## Context

Put Range From URL ignored `x-ms-source-content-crc64`, so a range corrupted on its way from the source was written without complaint. Copy File and Put Range From URL answered 404 `CannotVerifyCopySource` for any source in another account, even one configured on the same instance and offered with a valid SAS. Both gaps were listed in the manifest, and [ADR-0032](0032-check-copy-source-sas-and-convert-binary-security-descriptors.md) had left other accounts refused. This record fixes what Microsoft Learn defines for them before any code, because the work began from a broader description. Sources: the Learn pages for [Put Range From URL](https://learn.microsoft.com/en-us/rest/api/storageservices/put-range-from-url), [Copy File](https://learn.microsoft.com/en-us/rest/api/storageservices/copy-file), and [Azure Files error codes](https://learn.microsoft.com/en-us/rest/api/storageservices/file-service-error-codes), read on the date this record was drafted.

**Put Range From URL.**

| Header | Documented |
| --- | --- |
| `x-ms-source-content-crc64` | yes: a mismatch with the bytes that arrived from the source is 400; the hash is not stored |
| `x-ms-source-if-match-crc64`, `x-ms-source-if-none-match-crc64` | yes: the operation proceeds only if the CRC64 of the source range equals, or differs from, the value; otherwise 412 |
| `x-ms-source-content-md5` | **no**. Files documents no source MD5 |
| `x-ms-source-if-match`, `-if-none-match`, `-if-modified-since`, `-if-unmodified-since` | **no**, for Put Range From URL and for Copy File |

The response carries `x-ms-content-crc64`. The source "must either be public or be authorized via a shared access signature", and the example copies from a second account with a SAS.

**Copy File sources.** Learn's table: a source file in the same account may be authorized with Shared Key or a SAS; a source file in another account only with a SAS ("Shared Key: No"); a source blob in the same or another account only with a SAS, or when public. Access to the source is authorized separately from the destination. Learn also lists `SnapshotAcrossSharesNotSupported` (400, "the file snapshot source account and share must be the same as that of the destination") and `FileSnapshotSourceSignedAccessNotSupported`.

## Decision and scope

- **Source checksum.** Put Range From URL accepts `x-ms-source-content-crc64`, compared with the bytes read from the source range by the existing `Checksums::verify` before the range is published. A mismatch is 400 `Crc64Mismatch` and writes nothing; a value that is not 8 base64 bytes is 400 `InvalidHeaderValue`. The success response now carries `x-ms-content-crc64`.
- **Source conditions.** `x-ms-source-if-match-crc64` and `x-ms-source-if-none-match-crc64` are evaluated against the same digest, also before publishing; an unmet one is 412 `ConditionNotMet` and writes nothing. No MD5 or `x-ms-source-if-*` header is added, since Learn documents none. A request that sends `x-ms-source-content-md5` has it ignored, as any undocumented header is.
- **Cross-account sources.** The source account may be any account configured on this instance. Copy File and Put Range From URL share one function, `authorized_source`, that resolves the source. A source in the destination's account is unchanged: a SAS on its URL must allow reading, and without one the request's own credentials are used. A source in another account must carry a SAS, verified against **that account's** keys, signature, expiry, resource, stored policy, and read permission. A request that carries only the destination account's Shared Key, a SAS signed with the wrong key, a SAS naming another account, or an account that is not configured is 403 `CannotVerifyCopySource`, the same answer for each so that account names are not probed. A `sharesnapshot` source in another account is 400 `SnapshotAcrossSharesNotSupported`.
- **Dependency direction.** FileREST keeps reading only through its own store. A same-instance copy between accounts shares extents exactly as a copy between two shares does; no Blob code is involved.
- **Blob sources: not added.** Learn allows Copy File to take a blob source with a SAS. Serving it would make FileREST read the Blob store, which `--services file` may not even start, and ADR-0010 keeps the services' state separate. A Blob source stays `NotImplemented`. A narrow seam (a read interface the Blob service implements) could be proposed on its own.

## Unverified until live Azure recording

Learn gives no code for an unmet `x-ms-source-if-*-crc64` (only 412), so `ConditionNotMet` is by analogy with other conditions. The same holds for the code and status Azure returns for a cross-account source with no SAS or with a bad one (403 `CannotVerifyCopySource` follows Azuifer's same-account behavior, itself unverified, ADR-0032). It is not known whether Azure refuses a snapshot source in another account for Put Range From URL as well as Copy File, or whether the documented `SnapshotAcrossSharesNotSupported` also applies to a different share of the same account, which Azuifer still allows. `FileSnapshotSourceSignedAccessNotSupported` is not implemented. Whether the response also carries `Content-MD5` is undocumented; Azuifer still sends it. The checksum algorithm is the one Azuifer uses for every CRC64 (CRC-64/NVME). Rows F-28 and F-29 in the [recording plan](../compatibility/azure-recording-plan.md) are meant to settle these. Until then both operations stay `known-difference`.

## Alternatives and consequences

Treating a cross-account source like a same-account one (read with the request's own credentials) would let a client holding one account's key read another account's files with no SAS, which Learn's table says does not work. Reading the other account's keys to authorize a destination-account request would also be wrong: the SAS is the source account's grant. Putting the checks inside the store would couple them to HTTP-level headers and credentials.

A deployment that relied on the earlier refusal now copies across accounts when it supplies a valid SAS; nothing else changes.

## Verification criteria

- A matching `x-ms-source-content-crc64` writes the range and is echoed in `x-ms-content-crc64`; a wrong one is 400 `Crc64Mismatch` and leaves the destination bytes unchanged; a malformed one is 400 `InvalidHeaderValue`.
- Each source-CRC64 condition that is not met is 412 and writes nothing; each that is met writes.
- Copy File and Put Range From URL read a file of another configured account with a valid read SAS of that account, in memory and on disk, and by its host-style name; the copy keeps its bytes after the source file and share are deleted.
- Each of no SAS, a write-only SAS, an expired SAS, a SAS signed with the destination key, a SAS naming the destination account, and an unconfigured account is 403 `CannotVerifyCopySource` and creates nothing.
- A snapshot source in another account is 400 `SnapshotAcrossSharesNotSupported`.
- The official Python SDK's `start_copy_from_url` and `upload_range_from_url` (with `source_content_crc64`) work against Azuifer across two accounts.
