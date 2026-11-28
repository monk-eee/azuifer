# Architecture decision records

The [product specification](../specs/azuifer.md) describes the target. An ADR records why a bounded choice was proposed, what alternatives it rules out, and what would prove the implementation follows it.

| Record | Status |
| --- | --- |
| [ADR-0001: Record architecture decisions with verification criteria](0001-record-architecture-decisions.md) | Proposed |
| [ADR-0002: Build an independent Rust binary](0002-build-an-independent-rust-binary.md) | Proposed |
| [ADR-0003: Share the Blob and DFS namespace](0003-share-the-blob-and-dfs-namespace.md) | Proposed |
| [ADR-0004: Commit only durable content references](0004-commit-durable-content-references.md) | Proposed |
| [ADR-0005: Publish operation-level conformance](0005-publish-operation-level-conformance.md) | Proposed |
| [ADR-0006: Keep the emulator local by default](0006-default-to-local-only.md) | Proposed |
| [ADR-0007: Make OpenTelemetry export opt-in](0007-opt-in-opentelemetry.md) | Proposed |
| [ADR-0008: Package native and Azure Linux releases](0008-package-native-and-azure-linux-releases.md) | Proposed |
| [ADR-0009: Serve each service on its own listener](0009-serve-each-service-on-its-own-listener.md) | Proposed |
| [ADR-0010: Isolate service state and share only Blob with DFS](0010-isolate-service-state.md) | Proposed |
| [ADR-0011: Compose authentication from shared primitives](0011-compose-authentication-from-shared-primitives.md) | Proposed |
| [ADR-0012: Inject time through one clock](0012-inject-time-through-one-clock.md) | Proposed |
| [ADR-0013: Model queue messages as transactional SQLite state](0013-model-queue-messages-in-sqlite.md) | Proposed |
| [ADR-0014: Evaluate Table queries in Rust over typed entities](0014-evaluate-table-queries-in-rust-over-typed-entities.md) | Proposed |
| [ADR-0015: Map mutable ranges over immutable extents](0015-map-mutable-ranges-over-immutable-extents.md) | Proposed |
| [ADR-0016: Give FileREST its own namespace, leases, and handles](0016-give-filerest-its-own-namespace.md) | Proposed |
| [ADR-0017: Model leases as a clocked state machine](0017-model-leases-as-a-clocked-state-machine.md) | Proposed |
| [ADR-0018: Model snapshots, versions, and copy as immutable references](0018-model-snapshots-versions-and-copy-as-immutable-references.md) | Proposed |
| [ADR-0019: Store account-level Blob features separately from blob content](0019-store-account-level-blob-features-separately.md) | Proposed |
| [ADR-0020: Represent HNS directories and POSIX ACLs on the shared namespace](0020-represent-hns-directories-and-posix-acls.md) | Proposed |
| [ADR-0021: Publish one conformance manifest per service](0021-publish-one-conformance-manifest-per-service.md) | Proposed |
| [ADR-0022: Keep blob lifecycle state beside the content and sweep it lazily on the clock](0022-keep-blob-lifecycle-state-and-sweep-lazily.md) | Proposed |
| [ADR-0023: Serve Blob calls addressed to the `blob` host on the DFS listener](0023-serve-blob-calls-addressed-to-the-blob-host-on-the-dfs-listener.md) | Proposed |
| [ADR-0024: Fetch external copy sources only from allowlisted hosts](0024-fetch-external-copy-sources-only-from-allowlisted-hosts.md) | Proposed |
| [ADR-0025: Serve the static website from the `{account}.web.{domain}` host of the Blob listener](0025-serve-the-static-website-from-the-web-host.md) | Proposed |
| [ADR-0026: Keep deleted shares under a hidden name and restore them by renaming](0026-keep-deleted-shares-under-a-hidden-name.md) | Proposed |
| [ADR-0027: Query Blob Contents with a small SQL subset and an Avro response](0027-query-blob-contents-with-a-small-sql-subset.md) | Proposed |
| [ADR-0028: Address the root container by a single path segment](0028-address-the-root-container-by-a-single-path-segment.md) | Proposed |
| [ADR-0029: Serve NFS file shares: POSIX properties, hard links, and symbolic links](0029-serve-nfs-file-shares-with-posix-properties-and-links.md) | Proposed |
| [ADR-0030: Read Path range checksums and Create Path expiry on the shared object identity](0030-read-path-range-checksums-and-create-path-expiry.md) | Proposed |
| [ADR-0031: Check search rights on the directories of a recursive ACL change](0031-check-search-rights-in-recursive-acl-changes.md) | Proposed |
| [ADR-0032: Check a copy source's SAS and convert binary security descriptors](0032-check-copy-source-sas-and-convert-binary-security-descriptors.md) | Proposed |
| [ADR-0033: Report store state as runtime metrics](0033-report-store-state-as-runtime-metrics.md) | Proposed |
| [ADR-0034: Refuse newer schemas and linked storage in every persistent store](0034-refuse-newer-schemas-and-linked-storage.md) | Proposed |
| [ADR-0035: ADLS Gen2 Set Path Expiry over `PUT ?comp=expiry` and DFS expiry visibility](0035-dfs-set-path-expiry.md) | Proposed |
| [ADR-0036: Verify From-URL source checksums and seal on Copy Blob](0036-blob-source-checksums-and-copy-seal.md) | Proposed |
| [ADR-0037: Check Put Range From URL source checksums and read other accounts' files with their SAS](0037-files-copy-checksums-and-cross-account-sources.md) | Proposed |

Search the index before drafting a record. If a change needs a new decision, use the [template](template.md), pick the next four-digit number, and add the proposed record to the index. Keep separate decisions in separate records.

Maintainers record acceptance after review; publishing a proposal does not accept it. Acceptance records intent, not proof: link actual tests, fixtures, or results from the implementing change. Keep an accepted rationale in history and link a superseding ADR if the decision changes. This collection does not install a blocking check.
