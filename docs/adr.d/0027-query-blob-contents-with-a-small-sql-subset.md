# ADR-0027: Query Blob Contents with a small SQL subset and an Avro response

- **Status:** Proposed

## Context

Query Blob Contents (`POST {blob}?comp=query`) runs a SQL expression over a delimited or JSON blob and returns the result as an Avro object container holding `resultData`, `progress`, `end`, and `error` records. SDKs (Python `query_blob` and the .NET, Java, and JavaScript equivalents) decode that stream. The operation answered `501`, so any application that filters blobs this way failed against Azuifer.

## Decision and scope

Add the operation behind `Operation::QueryBlob`, authorized like Get Blob, with snapshot and `versionid` selectors, conditions, and a lease. The request body is parsed with the shared XML tree. Input and output can each be delimited text (column separator, field quote, escape character, record separator, headers) or JSON lines; Arrow and Parquet answer `NotImplemented`. The blob is read whole, bounded by `--max-blob-bytes`, and decoded as UTF-8.

The SQL subset is `SELECT * | expression [AS alias], … FROM BlobStorage [alias] [WHERE …] [LIMIT n]`. Columns are `_N` positions, header names (case-insensitive fallback), or JSON paths such as `s.a.b[0]`. Operators: comparisons, `AND`, `OR`, `NOT`, `LIKE`, `IS [NOT] NULL`, `BETWEEN`, `IN`, `+ - * / %`, and `||`, with three-valued logic. Functions: `CAST` to INT, FLOAT, BOOL, or STRING, `LOWER`, `UPPER`, `TRIM`, `CHAR_LENGTH`, `SUBSTRING`, `COALESCE`, `NULLIF`. Aggregates `COUNT`, `SUM`, `AVG`, `MIN`, `MAX` work without `GROUP BY` and cannot mix with other select items. A text value compared with a number is compared as a number when it parses as one; two texts compare as text.

At `2023-11-03` the recorded response is `200 avro/binary` without `Content-Length`. The Avro union in namespace `com.microsoft.azure.storage.queryBlobContents` orders its branches `resultData`, `error`, `progress`, `end`. Each record occupies its own block, using the default null codec. A `resultData` record comes first even if empty; the Python SDK decodes it before installing its error handler. Data chunks are about 1 MiB at record boundaries. For the recorded inputs, a final `progress` and `end` carry the scanned byte count and source size. Invalid SQL returns `400 ErrorProcessingQueryExpression` with request correlation. Bad row conversions in the recorded projection emit nonfatal `InvalidTypeConversion` records with source byte offsets. Other runtime errors can still be fatal.

The code lives in `src/blob_query/`: `avro.rs` (writer), `sql.rs` (parser and evaluator), `format.rs` (serializations), and `mod.rs` (request and response).

## Alternatives and consequences

A streaming reader would bound memory by row, but the store reads whole blobs for most operations and the blob size is already capped. Buffered Avro output is capped at the larger of that limit and 1 MiB to allow for framing; oversized results return `413`. A SQL parser crate would add a dependency for a dialect that is much smaller than the grammar Azure documents. `GROUP BY`, `JOIN`, subqueries, window functions, date functions, Arrow, and Parquet are out of scope and answer a parse error or `NotImplemented`. The [live cassette](../../tests/contracts/cassettes/blob-query-avro.json) covers small CSV and JSON inputs. The manifest still marks the operation `known-difference`: the SQL dialect, scan limits, streaming at large input sizes and other errors are not established by that recording.

## Verification criteria

- The Python SDK reads filtered, projected, aggregated, and JSON results, receives row conversion errors through `on_error`, and surfaces `ErrorProcessingQueryExpression` for invalid SQL.
- HTTP tests decode the Avro stream and check sync markers, a leading data record, the `end` total, snapshots, a `501` for Parquet, and a `404` for a missing blob.
- Unit tests cover the parser, three-valued logic, CSV quoting and separators, and Avro framing.
- The recorded CSV, JSON, empty, conversion-error and invalid-SQL exchanges replay offline and have independent Azure drift checks.
