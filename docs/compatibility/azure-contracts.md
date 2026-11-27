# Azure contract cassettes

The [Rust harness](../../tests/contracts/mod.rs) runs the same requests against Azure and the built Azuifer binary over HTTPS. Each case pins API version `2023-11-03`. The reviewed Azure cassette is the baseline. A live check compares each service with it independently: Azure drift, Azuifer drift, or both can fail the check. Matching each other is not enough.

The [recording plan](azure-recording-plan.md) counts the exchange target, lists concrete pathways across all five services, and tracks which target or permissions each still needs.

| Case | What it compares |
| --- | --- |
| [Get User Delegation Key](../../tests/contracts/cassettes/blob-get-user-delegation-key.json) | HTTP status, selected headers, the XML fields, the requested validity window, and the decoded key length. The cassette omits the key and identifiers. |
| [Invalid delegation key windows](../../tests/contracts/cassettes/blob-delegation-key-invalid-windows.json) | Missing expiry, a future expiry before the requested start, and a malformed start. Checks the Azure error code, the rejected node, the value's relation to the input, and error-message correlation. |
| [Read-only Blob user-delegation SAS](../../tests/contracts/cassettes/blob-user-delegation-sas-read-only.json) | HEAD, byte-range GET, a denied DELETE, and a final GET that must return the original bytes and ETag. The XML denial includes a timestamp and the request ID from the response header. |
| [List Blobs with a container user-delegation SAS](../../tests/contracts/cassettes/blob-user-delegation-sas-list.json) | Prefix and delimiter listing with a one-entry page limit. Resumes using the returned marker, checks the marker echo, and follows a `BlobPrefix` to a nested blob. Verifies listing metadata and unquoted XML ETags; list-only SAS cannot read and read-only SAS cannot list. |
| [User-delegation SAS response overrides](../../tests/contracts/cassettes/blob-user-delegation-sas-overrides.json) | Checks all five signed content header overrides on HEAD and byte-range GET. The payload, ETag and metadata match the seed, and a read without overrides returns the stored headers. |
| [Conditional Blob overwrite](../../tests/contracts/cassettes/blob-conditional-overwrite.json) | Rejects a create on an existing blob and a stale ETag. A write with the current ETag publishes new bytes, metadata, and ETag. Rejected writes leave the visible state unchanged. |
| [Staged block commit](../../tests/contracts/cassettes/blob-staged-block-commit.json) | Stages two blocks, observes the uncommitted blob is not readable, and commits them in reverse staging order. A block list naming a missing block is rejected without changing the committed bytes, metadata, or ETag. |
| [Blob lease guard](../../tests/contracts/cassettes/blob-lease-guard.json) | Acquires an infinite lease, rejects writes with absent and wrong IDs, and accepts a write with the correct ID. Verifies bytes, metadata, ETag and lease state before and after release. |
| [Snapshot recovery](../../tests/contracts/cassettes/blob-snapshot-recovery.json) | A base blob with a snapshot rejects DELETE without a snapshots option. An overwrite leaves the snapshot's bytes, metadata and ETag intact. A conditional PUT restores the snapshot bytes and metadata to the base blob; this tests client-driven recovery, not Copy Blob. |
| [Append position](../../tests/contracts/cassettes/blob-append-position.json) | The stale-position append is rejected without changing bytes or ETag. Valid appends report their offsets and committed block counts and preserve byte order. |
| [Sparse page writes](../../tests/contracts/cassettes/blob-sparse-page-writes.json) | A write to the second 512-byte page leaves zeroes in the first. A failed sequence guard preserves the bytes and ETag. Clearing the written page returns it to zeroes without changing the blob length or sequence number. |
| [Blob range checksums](../../tests/contracts/cassettes/blob-range-checksums.json) | Validates MD5, CRC64, `x-ms-range` precedence, open-ended reads, the conflicting-checksums error and the out-of-range response. A final full read checks the original bytes, MD5, metadata and ETag. |
| [Blob metadata and properties](../../tests/contracts/cassettes/blob-metadata-properties.json) | Conditional metadata replacement removes omitted entries and rejects stale updates. A properties update clears omitted headers while preserving content and the newly set metadata. |
| [Conditional Blob reads](../../tests/contracts/cassettes/blob-conditional-reads.json) | Distinguishes empty 304 `ConditionNotMet` responses from 412 XML errors for ETag and date conditions, including mixed preconditions. A valid ETag-conditioned range read returns 206. |
| [Conditional Blob deletion](../../tests/contracts/cassettes/blob-conditional-delete.json) | Deletion with the current ETag is permanent on the flat profile. A read and repeat delete return 404. After recreation, the old ETag cannot delete the replacement. |
| [Blob container lifecycle](../../tests/contracts/cassettes/blob-container-lifecycle.json) | Create and reject a duplicate; replace metadata; distinguish metadata reads from properties; follow and verify a filtered continuation; delete and confirm the container is gone. |
| [Blob container leases](../../tests/contracts/cassettes/blob-container-lease.json) | Acquire, verify locked properties and the same ETag, reject deletion without the lease ID and renewal with the wrong ID, then renew, release and delete. |
| [Block-list selectors](../../tests/contracts/cassettes/blob-block-list-selectors.json) | List committed and uncommitted blocks independently. Commit a staged block and a committed block in that order, even when the committed ID also has a staged replacement. A mismatched block ID width is rejected without changing the committed bytes. |
| [Page ranges, resize and sequence](../../tests/contracts/cassettes/blob-page-resize-sequence.json) | Verify allocated ranges and an intersecting window, reject an unaligned write, shrink and grow with zero-fill, and observe max, update and increment sequence actions. |
| [Append sealing](../../tests/contracts/cassettes/blob-append-sealing.json) | Append exactly at the size limit, reject growth beyond it, seal the blob, reject a later append, and read back the unchanged bytes and one committed block. |
| [Blob account and service reads](../../tests/contracts/cassettes/blob-account-read-only.json) | Checks an empty account-info response with SKU, account kind and HNS headers, then selected Blob service properties for a flat StorageV2 Standard_LRS account with empty CORS and disabled Blob soft delete and static website. No settings are changed. |
| [Empty container-scoped Batch envelope](../../tests/contracts/cassettes/blob-batch-empty-envelope.json) | The outer response is 202 with one multipart 400 `InvalidInput` rejection. It has no subrequest Content-ID and its XML correlates with the embedded request ID. No Blob is seeded or deleted. |
| [Truncated container-scoped Batch part](../../tests/contracts/cassettes/blob-batch-truncated-part.json) | A multipart part ending in its header also returns 202 with a single embedded 400 `InvalidInput` and no Content-ID. No subrequest is executed. |
| [Malformed Query Blob Contents XML](../../tests/contracts/cassettes/blob-query-malformed-xml.json) | An unclosed query XML document returns 400 `InvalidXmlDocument` before reading Blob data, with Azure's message and request correlation. This does not cover successful query results or Avro framing. |

The mutation cases use Entra bearer authentication. Their cassettes record the request method, operation, payload length and selected guards alongside the observed response. ETags, lease IDs, continuation markers and conditional dates are represented by their relationship to the scenario, never by their value.

## Replay without Azure

```sh
cargo test --locked --test tls_auth_http replay_
```

The regular Rust CI suite replays the reviewed recordings against Azuifer, without Azure credentials. To replay a saved read-only SAS candidate instead, set `AZUIFER_CONTRACT_REPLAY_FILE` and explicitly run `cargo test --locked --test tls_auth_http replay_saved_blob_sas_contract -- --ignored`. This does not change the CI baseline.

## Check for drift against real Azure

Sign in to Azure CLI locally. Use a disposable public-cloud storage account tagged `azuifer-contract-tests=true` with management-plane read access. Get User Delegation Key needs the delegation-key action at account scope or above. The SAS and mutation cases also need **Storage Blob Data Contributor** at the account scope or equivalent permissions to create, read, and delete their test containers and upload blobs. Do not use a production or customer-data account.

Set these variables in the local environment, not in the repository:

| Variable | Value |
| --- | --- |
| `AZUIFER_LIVE_STORAGE_SUBSCRIPTION` | UUID of the selected dev subscription |
| `AZUIFER_LIVE_STORAGE_RESOURCE_GROUP` | Resource group of the tagged account |
| `AZUIFER_LIVE_STORAGE_ACCOUNT` | Storage account name, not a URL |

```sh
cargo test --locked --test tls_auth_http \
  contracts::live::check_live_ -- --ignored --nocapture --test-threads=1
```

All live tests check the account and tag before requesting a Storage access token. The delegation cases use short validity windows; neither they nor the account and service reads create containers or blobs. The SAS and mutation cases each create randomly named containers for synthetic data and delete them afterward. The tests do not list account keys, change account settings, or access existing containers. The recorder reports cleanup failures; an interrupted run may leave an `azuifer-contract-` container.

## Capture and review a new baseline

1. Define a synthetic scenario with a pinned API version, auth mode, and any required account features. Follow the [mutation probes](../../tests/contracts/mutations.rs) for setup, request construction, typed projection, and cleanup. Check a read after each important mutation or rejection so success cannot hide the wrong state.
2. Set `AZUIFER_CONTRACT_CAPTURE=1` and run the live command (or filter to the new case). Capture mode only observes Azure and writes a uniquely named candidate under `dist/azure-contracts/` (ignored by Git). It does not check Azuifer or update the baseline. Unset the variable to resume live comparisons.
3. Review the candidate before copying it into [the cassette directory](../../tests/contracts/cassettes/). If the baseline changes, review the Git diff and explain why. Commit only the typed projection: no URLs, resource identifiers, credentials, SAS parameters, delegation keys, raw headers, or arbitrary bodies. A failed setup cannot produce a record for that workflow.
4. Run offline replay against the reviewed record, then rerun the live check. A regression should fail against the reviewed record before fixing Azuifer; never change the record just to make the emulator pass.

A passing cassette proves only the exchanges, API version, auth mode, account features, and fields that the case checked. It does not certify other operations, Blob versioning or soft delete, or parity across services.
