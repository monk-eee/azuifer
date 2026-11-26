# ADR-0014: Evaluate Table queries in Rust over typed entities

- **Status:** Proposed

## Context

Table entities carry typed properties (`Edm.String`, `Int32`, `Int64`, `Double`, `Boolean`, `DateTime`, `Guid`, `Binary`) and system properties `PartitionKey`, `RowKey`, and `Timestamp`. OData `$filter` comparisons follow Azure's type rules, which SQLite's loose typing does not reproduce. Clients also send batches that must succeed or fail as a unit, and they negotiate JSON metadata levels.

## Decision and scope

Persist entities in the Table store ([ADR-0010](0010-isolate-service-state.md)) keyed by `(table, PartitionKey, RowKey)`. Store the properties as typed values so each `Edm` type round-trips, and derive the ETag from the modification timestamp (`W/"datetime'…'"`). Parse `$filter` into an AST and evaluate it in Rust against typed values. SQL narrows candidates only by partition and row-key ranges. Support the comparison and logical operators and the types above; reject unsupported functions or malformed expressions with the Azure error code instead of ignoring them. Support `$select`, `$top`, and continuation through `NextPartitionKey` and `NextRowKey`, and return results ordered by partition then row key.

Implement insert, get, update (replace), merge, delete, insert-or-replace, and insert-or-merge with `If-Match` semantics. Run an entity-group `$batch` (multipart `changeset`) in one SQLite transaction for one partition, up to 100 operations, with no partial writes on failure. Support Shared Key, Shared Key Lite, and SAS through [ADR-0011](0011-compose-authentication-from-shared-primitives.md), and serve the `nometadata`, `minimalmetadata`, and `fullmetadata` JSON formats.

## Alternatives and consequences

Translating OData to SQL is fast but changes comparison semantics for 64-bit integers, dates, GUIDs, and binary. A key-value store without a query layer cannot answer filters. Evaluating in Rust makes type behavior testable and keeps unsupported cases explicit; unindexed filters scan the narrowed range, which is acceptable at local scale.

## Verification criteria

- Round-trip tests cover every `Edm` type, including values at integer and date boundaries.
- Filter tests cover each supported operator and type, and each unsupported expression returns the Azure error.
- A batch with one failing operation changes no entity; ETag mismatches return the Azure precondition error.
- Official Table SDK and `az storage entity` workflows pass, including paged queries across partitions.
