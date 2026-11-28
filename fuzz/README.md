# Parser contract corpus

`corpus/` contains fixed synthetic protocol cases. Stable Rust tests replay them directly through the parsers in the emulator. No server, credentials, Azure connection, nightly compiler, or external runner is needed.

```sh
cargo test --locked --workspace --all-features corpus
```

The normal workspace test suite also runs the corpus on Linux, macOS, and Windows CI. Each listed directory is replayed in file-name order on a 1 MiB test thread stack. A `.ok` fixture must be accepted and an `.err` one rejected. Keep cases small, self-contained, and free of keys, signatures, or captured traffic.

| Directory | Contract exercised |
| --- | --- |
| `uri_and_address` | Blob host/path style, IPv6 authority, query, range, and conditions |
| `xml_bodies` | Blob block lists, CORS and service properties, Blob Batch envelopes, Queue message text, and FileREST ACL syntax |
| `odata_query` | Table filter and projection, and typed entity values |
| `sas_token` | Timestamp syntax and validity-window boundaries, not credentials |
| `shared_key` | Shared canonicalization of paths, headers, and query parameters, without signing |
| `blob_query_sql` | SQL parsing, filtering, and projection over a fixed CSV row |

This is fixed-case replay, not coverage-guided fuzzing. There is no standalone fuzz workspace or nightly fuzz job here.
