# ADR-0030: Read Path range checksums and Create Path expiry on the shared object identity

- **Status:** Proposed

## Context

Two DFS gaps were listed as unsupported: Read Path ignored `x-ms-range-get-content-md5` and date conditions were recorded as missing, and Create Path refused `x-ms-expiry-option` and `x-ms-expiry-time` with 501. A DFS file is a Blob block blob row ([ADR-0003](0003-share-the-blob-and-dfs-namespace.md)), and Blob already has the primitives: `Guard` for conditions, `read_row` for range checksums, and the lifecycle table with a lazy sweep for expiry ([ADR-0022](0022-keep-blob-lifecycle-state-and-sweep-lazily.md)). The Learn pages for [Read](https://learn.microsoft.com/rest/api/storageservices/datalakestoragegen2/path/read) and [Create](https://learn.microsoft.com/rest/api/storageservices/datalakestoragegen2/path/create) are the only source; nothing here is recorded from Azure.

## Decision and scope

**Read Path.** `x-ms-range-get-content-md5: true` with a `Range` or `x-ms-range` returns `Content-MD5` of the returned range, computed by the Blob read path. `x-ms-range` wins over `Range`. Without a range it is `400 InvalidHeaderValue`, as Learn says; so is a range over 4 MiB. The checksum header is attached in the DFS response because the shared Blob response builder drops it. The date conditions needed no change: `Guard::parse` already read `If-Modified-Since` and `If-Unmodified-Since`, so the old manifest note was stale, and tests now pin them to Blob's answers (304, 412 `ConditionNotMet`). `x-ms-range-get-content-crc64` is **not** accepted: Learn documents no such header for Read Path (only a structured-body header), so it stays an unsupported `x-ms-*` header (501). Blob's Get Blob does accept it; adding it to DFS is a one-line change once a recording shows Azure does too.

**Create Path expiry.** `ExpiryOption::parse` reads the headers. Learn documents RelativeToNow (milliseconds), Absolute (RFC 1123) and NeverExpire, for files only. A file gets a row in `blob_lifecycle` in the creating transaction, so Blob `HEAD` shows `x-ms-expiry-time`, and the next metadata action after the deadline removes the file for Blob and DFS alike on the shared clock. Three behaviors the store already had and tests now pin: Create Path over an existing file replaces it and its deadline; a rename keeps the row (the foreign key cascades the name); and Flush Data, which rewrites the row to publish content, now keeps the deadline set at creation. Without that last change a file created with an expiry and then flushed, which is what every SDK upload does, lost its expiry. Append Data that creates a file implicitly sets none.

**Refused, and not verified.** Learn does not list RelativeToCreation for Create Path, so it is refused. Expiry on a directory is refused. A past Absolute time, a non-numeric relative time, NeverExpire with a time, an unknown option, and a time without an option are refused. All of these answer `400 InvalidHeaderValue` (`400 MissingRequiredHeader` when one of the two headers is absent). Learn names no error for any of them; the status and code are Azuifer's choice.

**Structure.** `src/dfs/request.rs` had passed the 800-line threshold. The pure header parsers (`properties`, content, POSIX, ACL, lease) moved unchanged to `src/dfs/headers.rs`, which also holds the two new parsers.

## Alternatives and consequences

Accepting CRC64 on Read would follow Blob but would claim a header Azure does not document. Accepting RelativeToCreation would be harmless for a new file (creation is now) but is also undocumented. Storing expiry in the file row instead of the lifecycle table would split Blob's Set Blob Expiry from DFS's. The cost is the unverified error shapes above; they are `known-difference` in the manifest.

## Verification criteria

- Blob write, then DFS ranged read with MD5: the MD5 equals Blob's for the same range; date conditions answer alike on both protocols.
- DFS create with each documented option: Blob `HEAD` shows the deadline, both protocols see the file until it passes and neither after.
- The Python Data Lake SDK's `create_file(expires_on=...)` for an int and a datetime, then append, flush and rename, sees the deadline and loses the file on the shared test clock.
- A differential recording against real Azure DFS is still needed before any of this is `exact`: the rejected combinations, `RelativeToCreation`, CRC64 on Read, and whether Azure keeps the deadline across a rename.
