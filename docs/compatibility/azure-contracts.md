# Azure contract cassettes

The [Rust harness](../../tests/contracts/mod.rs) runs the same requests against Azure and the built Azuifer binary over HTTPS. Each case pins API version `2023-11-03`.

| Case | What it compares |
| --- | --- |
| Get User Delegation Key | HTTP status, selected headers, the XML fields, the requested validity window, and the decoded key length. The cassette omits the key and identifiers. |
| Invalid delegation key windows | Missing expiry, a future expiry before the requested start, and a malformed start. Checks the Azure error code, the rejected node, the value's relation to the input, and error-message correlation. |
| Read-only Blob user-delegation SAS | HEAD, byte-range GET, a denied DELETE, and a final GET that must return the original bytes and ETag. The XML denial includes a timestamp and the request ID from the response header. |
| Conditional Blob overwrite (Entra bearer) | Rejects a create on an existing blob and a write using a stale ETag. A write with the current ETag publishes new bytes, metadata, and ETag. The rejected writes leave the visible state unchanged. |
| Staged block commit (Entra bearer) | Stages two blocks, observes the uncommitted blob is not readable, and commits them in reverse staging order. A block list naming a missing block is rejected without changing the committed bytes, metadata, or ETag. |

## Replay without Azure

```sh
cargo test --locked --test tls_auth_http replay_
```

The regular Rust CI suite replays the sanitized Azure recordings: [key issuance](../../tests/contracts/cassettes/blob-get-user-delegation-key.json), [invalid delegation key windows](../../tests/contracts/cassettes/blob-delegation-key-invalid-windows.json), [read-only SAS](../../tests/contracts/cassettes/blob-user-delegation-sas-read-only.json), [conditional overwrite](../../tests/contracts/cassettes/blob-conditional-overwrite.json), and [staged block commit](../../tests/contracts/cassettes/blob-staged-block-commit.json). Set `AZUIFER_CONTRACT_REPLAY_FILE` to replay a different saved read-only SAS cassette without running any Azure commands.

## Record from a dedicated Azure test account

Sign in to Azure CLI locally. Use a disposable public-cloud storage account tagged `azuifer-contract-tests=true` with management-plane read access. Get User Delegation Key needs the delegation-key action at account scope or above. The SAS and mutation cases also need **Storage Blob Data Contributor** at the account scope or equivalent permissions to create, read, and delete their test containers and upload blobs. Do not use a production or customer-data account.

Set these variables in the local environment, not in the repository:

| Variable | Value |
| --- | --- |
| `AZUIFER_LIVE_STORAGE_SUBSCRIPTION` | UUID of the selected dev subscription |
| `AZUIFER_LIVE_STORAGE_RESOURCE_GROUP` | Resource group of the tagged account |
| `AZUIFER_LIVE_STORAGE_ACCOUNT` | Storage account name, not a URL |

```sh
cargo test --locked --test tls_auth_http \
  contracts::live::record_live_delegation_key_contract -- --ignored --exact --nocapture

cargo test --locked --test tls_auth_http \
  contracts::live::record_live_delegation_window_contract -- --ignored --exact --nocapture

cargo test --locked --test tls_auth_http \
  contracts::live::record_live_blob_sas_contract -- --ignored --exact --nocapture

cargo test --locked --test tls_auth_http \
  contracts::live::record_live_blob_mutation -- --ignored --nocapture --test-threads=1
```

All live tests check the account and tag before requesting a Storage access token. The delegation cases use short validity windows and do not create containers or blobs. The SAS and mutation cases each create a randomly named container for synthetic data and delete it afterward. The tests do not list account keys, change account settings, or access existing containers. The recorder reports cleanup failures; an interrupted run may leave an `azuifer-contract-` container.

The recorder writes only the allowlisted contract model to `dist/azure-contracts/` (ignored by Git). It never writes request URLs, Azure resource identifiers, access tokens, SAS parameters, delegation keys, raw headers, or arbitrary bodies. For example, an ETag is recorded as matching the seeded object's ETag, not as the original value. The Azure result is saved before comparison so a mismatch can be inspected and replayed. A failed setup or an Azure response that cannot be tied to the seeded blob does not produce a cassette.

Review the normalized fields and provenance before adding an Azure fixture to source control. A passing cassette is evidence only for those operations, that API version and auth mode, and the fields checked by the scenario. It does not change an operation's conformance rating or replace live reruns as Azure evolves.
