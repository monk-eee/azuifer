# ADR-0027: Query Blob Contents with a small SQL subset and an Avro response

- **Status:** Proposed

## Context

Query Blob Contents (`POST {blob}?comp=query`) runs a SQL expression over a delimited or JSON blob and returns the result as an Avro object container holding `resultData`, `progress`, `end`, and `error` records. SDKs (Python `query_blob` and the .NET, Java, and JavaScript equivalents) decode that stream. The operation answered `501`, so any application that filters blobs this way failed against Azuifer.

## Decision and scope

Add the operation behind `Operation::QueryBlob`, authorized like Get Blob, with snapshot and `versionid` selectors, conditions, and a lease. The request body is parsed with the shared XML tree. Input and output can each be delimited text (column separator, field quote, escape character, record separator, headers) or JSON lines; Arrow and Parquet answer `NotImplemented`. The blob is read whole, bounded by `--max-blob-bytes`, and decoded as UTF-8.

The SQL subset is `SELECT * | expression [AS alias], … FROM BlobStorage [alias] [WHERE …] [LIMIT n]`. Columns are `_N` positions, header names (case-insensitive fallback), or JSON paths such as `s.a.b[0]`. Operators: comparisons, `AND`, `OR`, `NOT`, `LIKE`, `IS [NOT] NULL`, `BETWEEN`, `IN`, `+ - * / %`, and `||`, with three-valued logic. Functions: `CAST` to INT, FLOAT, BOOL, or STRING, `LOWER`, `UPPER`, `TRIM`, `CHAR_LENGTH`, `SUBSTRING`, `COALESCE`, `NULLIF`. Aggregates `COUNT`, `SUM`, `AVG`, `MIN`, `MAX` work without `GROUP BY` and cannot mix with other select items. A text value compared with a number is compared as a number when it parses as one; two texts compare as text.

The response is one Avro block whose schema is a union of the four records in namespace `com.microsoft.azure.storage.queryBlobContents`. The first record is always a `progress` record, because the Python SDK decodes it before it installs its error handler. Result data follows in chunks of about 1 MiB at record boundaries, then a final `progress` and an `end` record. A syntax error answers `400 ParseError`. A failure while scanning is a fatal `error` record with the row index as its position, after any data already produced.

The code lives in `src/blob_query/`: `avro.rs` (writer), `sql.rs` (parser and evaluator), `format.rs` (serializations), and `mod.rs` (request and response).

## Alternatives and consequences

A streaming reader would bound memory by row, but the store reads whole blobs for most operations and the blob size is already capped. A SQL parser crate would add a dependency for a dialect that is much smaller than the grammar Azure documents. `GROUP BY`, `JOIN`, subqueries, window functions, date functions, Arrow, and Parquet are out of scope and answer a parse error or `NotImplemented`. The wire details are inferred from the SDK decoders, not recorded from Azure, so the manifest marks the operation `known-difference`.

## Verification criteria

- The Python SDK reads filtered, projected, aggregated, and JSON results, receives a fatal error through `on_error`, and surfaces a `ParseError`.
- HTTP tests decode the Avro stream and check sync markers, the leading `progress` record, the `end` total, snapshots, a `501` for Parquet, and a `404` for a missing blob.
- Unit tests cover the parser, three-valued logic, CSV quoting and separators, and Avro framing.
- A differential recording against real Azure is needed before this is called compatible.
