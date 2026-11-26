# ADR-0025: Serve the static website from the `{account}.web.{domain}` host of the Blob listener

- **Status:** Proposed

## Context

Azure serves a static website from a separate `web` endpoint (`{account}.z13.web.core.windows.net`) that reads the `$web` container anonymously, using the index document and 404 document of the account's static website setting. Developers use the setting from `az storage blob service-properties update --static-website` and upload their site with `az storage blob upload-batch -d '$web'`. Azuifer stored the setting but refused the `$web` container and had no web endpoint, so the workflow stopped at the first step ([ADR-0019](0019-store-account-level-blob-features-separately.md), [ADR-0009](0009-serve-each-service-on-its-own-listener.md)).

## Decision and scope

Accept `$web` as a container name (not `$root` or `$logs`) and decode the container segment of a path, since SDKs send `%24web`. Serve the website on the Blob listener for any request whose host is `{account}.web.{domain}`, the way host-style addressing already names the account; a sixth listener and port would change `--services`, the admin status, Compose, and every client's configuration for a read-only view of data Blob already holds. The handler runs before Blob authentication, accepts only `GET` and `HEAD` (405 otherwise), and reads through the same `read_path` that Blob uses, so conditions, ranges, content types and HNS behavior are the store's. An empty path or a path ending in `/` reads that directory's index document; a path that names a directory with an index answers 302 to the slash form; a missing blob answers 404 with the configured 404 document when it exists, and otherwise an HTML 404 with `x-ms-error-code: WebContentNotFound`. A disabled website, an unknown account and a missing index document answer the same 404. Path-style requests to `$web` stay ordinary Blob requests with ordinary authorization.

## Alternatives and consequences

A separate `web` listener matches Azure's separation but multiplies configuration for one anonymous read path. Making `$web` public at the Blob endpoint would change authorization for every client. The cost is that the website host needs `*.web.localhost` to resolve (the same requirement as host-style Blob), the HTML bodies are approximations of Azure's, and `defaultIndexDocumentPath`, custom domains and the `z13` host form are not served.

## Verification criteria

- With the website enabled, `/`, `/dir/` and a file path return the index, the directory index and the file with its stored content type; `/dir` redirects to `/dir/`.
- A missing path returns the 404 document with status 404, and the same request with the website disabled returns `WebContentNotFound`.
- `$web` can be created and read through the Blob endpoint with a percent-encoded or literal `$`.
