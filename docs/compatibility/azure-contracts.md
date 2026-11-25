# Azure contract cassettes

The [Rust harness](../../tests/contracts/mod.rs) runs the same requests against Azure and the built Azuifer binary over HTTPS. Both cases pin API version `2023-11-03`.

| Case | What it compares |
| --- | --- |
| Get User Delegation Key | HTTP status, selected headers, the XML fields, the requested validity window, and the decoded key length. The cassette omits the key and identifiers. |
| Read-only Blob user-delegation SAS | HEAD, byte-range GET, a denied DELETE, and a final GET that must return the original bytes and ETag. It checks the XML error shape and correlation fields rather than treating missing fields as equivalent. |

## Replay without Azure

```sh
cargo test --locked --test tls_auth_http replay_
```

The regular Rust CI suite runs both tests. The [Get User Delegation Key cassette](../../tests/contracts/cassettes/blob-get-user-delegation-key.json) was recorded against Azure and matched Azuifer on the selected fields. The [read-only SAS cassette](../../tests/contracts/cassettes/blob-user-delegation-sas-read-only.json) remains synthetic. Set `AZUIFER_CONTRACT_REPLAY_FILE` to a saved read-only SAS cassette to replay that case without running any Azure commands.

## Record from a dedicated Azure test account

Sign in to Azure CLI locally. Use a disposable public-cloud storage account tagged `azuifer-contract-tests=true` with management-plane read access. Get User Delegation Key needs the delegation-key action at account scope or above. The full SAS case also needs **Storage Blob Data Contributor** at the account scope or equivalent permissions to create, seed, and delete its own container. Do not use a production or customer-data account.

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
  contracts::live::record_live_blob_sas_contract -- --ignored --exact --nocapture
```

Both live tests check the account and tag before requesting a Storage access token. The key case uses a short validity window and does not create containers or blobs. The SAS case creates a new randomly named container and one synthetic blob, uses a short-lived SAS for the probes, then deletes the test container. Neither test lists account keys, changes account settings, or accesses existing containers. The SAS test reports cleanup failures; an interrupted run may leave an `azuifer-contract-` container.

The recorder writes only the allowlisted contract model to `dist/azure-contracts/` (ignored by Git). It never writes request URLs, Azure resource identifiers, access tokens, SAS parameters, delegation keys, raw headers, or arbitrary bodies. For example, an ETag is recorded as matching the seeded object's ETag, not as the original value. The Azure result is saved before comparison so a mismatch can be inspected and replayed. A failed setup or an Azure response that cannot be tied to the seeded blob does not produce a cassette.

Review the normalized fields and provenance before adding an Azure fixture to source control. A passing cassette is evidence only for those operations, that API version and auth mode, and the fields checked by the scenario. It does not change an operation's conformance rating or replace live reruns as Azure evolves.
