# ADR-0038: Name a compatibility mode that ignores only listed unknown request names

- **Status:** Proposed

## Context

[Specification section 10](../specs/azuifer.md) says strict protocol behavior is the default and that "a named compatibility mode may allow selected unknown parameters or headers; each relaxation must be observable in logs and conformance results." Nothing implemented it. Surveying what "unknown" means today found:

- **Only Blob and DFS reject unknown names.** Their parsers share one function, `protocol::check`, which answers 501 `NotImplemented` for a query parameter an operation does not list, for an `x-ms-*` header it does not list, and for a conditional, range, checksum, or content header it does not list. Queue, Table, and Files have no such check. A request with an unknown query parameter and an unknown `x-ms-*` header succeeds on all three, in every configuration; `tests/ops_http/compat.rs` pins this for each of them. So "strict" is already two behaviors. This record does not change that: making them reject would alter today's behavior, and `strict` must stay exactly today's behavior.
- **A real client trips the rejection.** The browser and React Native builds of `@azure/core-rest-pipeline` (1.25.1, `getHeaderName()` in `userAgentPlatform-browser`) send their user-agent string in `x-ms-useragent`, because a browser may not set `User-Agent`. Blob answers it with 501. No other non-operation name from the SDKs in this repository qualified; the Python, Java, Go, .NET and Node builds send only `x-ms-client-request-id`, which is already accepted.
- **There is no evidence-backed query parameter.** The search found no real client sending an unknown query parameter.

## Decision and scope

**Two modes.** `--compatibility-mode strict|lenient` (`AZUIFER_COMPATIBILITY_MODE`, TOML `compatibility_mode`), with the usual precedence: command line, environment, file, default. `strict` is the default and is today's behavior. The name `lenient` says what it does, tolerate more, where `compat` would suggest the whole product's goal. An unknown value is refused at startup by `config validate`, `serve`, and every other command that reads configuration.

**What `lenient` may ignore.** Only names on an explicit list, and only for Blob and DFS requests:

- a short built-in list, today only the header `x-ms-useragent`, each entry with evidence like the above;
- names the operator adds with `--compatibility-allow` (`AZUIFER_COMPATIBILITY_ALLOW`, TOML `compatibility_allow`), a comma-separated list in which an `x-ms-*` name is a header and any other name is a query parameter. The operator list needs `lenient`; with `strict` it is an error, so a setting cannot silently do nothing.

A name that is not on the list is rejected exactly as in `strict`, whatever it looks like.

**What it never relaxes.** An operator may not list a name that carries protocol meaning, and startup fails with the name and the reason. The check is in one place, `src/compat.rs`:

- headers that start with a family Azure gives meaning to (encryption and encryption scopes, conditionals, copy sources, leases, immutability and legal hold, tags, metadata, blob and content properties, ranges, tiers, sealing, expiry, page blob state, the API version and date, request correlation, Azure Files and Data Lake headers), and any header whose name contains a credential or checksum word (`auth`, `sas`, `sig`, `token`, `key`, `secret`, `password`, `credential`, `md5`, `crc`, `checksum`, `hash`);
- every query parameter the Blob and DFS parsers know, the SAS parameters, and any name containing the same credential or checksum words;
- headers that are not `x-ms-*`: `If-*`, `Range`, `Content-MD5` and the content headers stay rejected, because `lenient` only ever consults the list for names `strict` would reject, and the list can hold only `x-ms-*` headers and query parameters.

Authentication, SAS, and Shared Key verification run before this check and are not touched. A recognized unsupported operation (`comp=rename`, and the rest) is a different refusal and is unchanged. Tests send each protected class in both modes and require the same answer.

**Observability.** Each name ignored writes one `WARN` record with `service`, `request_id`, `kind` (`header` or `query`), `name`, and `compatibility_mode`, and never a value. Only a name on the list can be logged, so a client cannot choose what appears. The request span also records `url.query` for every request; the redactor now masks the value of each listed query parameter as it does `sig`, so the value does not reach the log or an exporter through the span either. This was a defect found while testing: the first version of the log test failed because the span carried the raw value.

`GET /status` gains a `compatibility` object (`mode`, `ignored_headers`, `ignored_query_parameters`); `azuifer status` prints it as `Compat:`. An instance from before this record omits it, and `azuifer status` copes. `azuifer conformance export` gains a `compatibility` object in JSON and a "Compatibility mode" section in Markdown with the active mode, the names ignored, and the areas never relaxed. The mode changes no operation's state in the manifests.

**Orthogonal to the API version.** `--skip-api-version-check` is unchanged and independent.

## Not decided here

Whether Queue, Table, and Files should reject unknown names in `strict`. That would be a behavior change with its own verification and its own record.

## Unverified until live Azure recording

Whether Azure itself ignores `x-ms-useragent` and unknown query parameters is not recorded; the modes exist so a deployment can choose, not because Azure's behavior is known. No recording-plan row is added, because the mode's subject is a local policy rather than an Azure operation.

## Alternatives and consequences

A built-in list only, with no operator list, would have been one header and no query parameter. A deny-list instead of a list of permitted names would have let any new Azure header slip through unnoticed; the list fails closed. Logging the value would help debugging and leak anything a client puts in it. Relaxing by service rather than by name would make one flag cover unrelated behaviors, which is what this record avoids.

A deployment that changes nothing sees nothing change. A deployment that sets `lenient` accepts that a request may carry a header Azuifer then ignores, and sees it in the log.

## Verification criteria

- With no setting, Blob and DFS answer 501 to `x-ms-useragent` and to an unknown query parameter, `/status` reports `strict`, and Queue, Table, and Files accept unknown names.
- With `lenient`, `x-ms-useragent` and the operator's names succeed on Blob and DFS, each is logged once with its service and the response's request ID, and no value appears anywhere in the log.
- With `lenient`, every probe of an encryption scope, a customer key, tags, a checksum, a CRC64, a conditional header, a lease, immutability, a copy source, a protocol query parameter, an unlisted name, and `comp=rename` returns the status `strict` returns, and an invalid SAS or wrong Shared Key is still 403.
- `config validate` refuses an unknown mode, an operator list without `lenient`, and each protected name, and says why.
- Precedence is command line over environment over file over default, and `status` and `conformance export` report the result.
