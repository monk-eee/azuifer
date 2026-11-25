# Azure contract cassettes

The [Rust harness](../../tests/contracts/mod.rs) runs the same Blob user-delegation SAS scenario against Azure and the built Azuifer binary over HTTPS. On API version `2023-11-03`, it checks a HEAD response, a byte-range GET, a DELETE denied to a read-only SAS, and a final GET that must return the original bytes and ETag. It compares the status, selected headers, the expected synthetic bytes, and the XML error shape. It checks correlation fields when present rather than treating missing fields as equivalent.

## Replay without Azure

```sh
cargo test --locked --test tls_auth_http contracts::replay_blob_sas_contract -- --exact
```

The regular Rust CI suite runs this test. The [checked-in starting cassette](../../tests/contracts/cassettes/blob-user-delegation-sas-read-only.json) is a synthetic expectation, not an Azure recording. Set `AZUIFER_CONTRACT_REPLAY_FILE` to a saved cassette to compare Azuifer to that capture without running any Azure commands.

## Record from a dedicated Azure test account

Sign in to Azure CLI locally. Use a disposable public-cloud storage account tagged `azuifer-contract-tests=true`, with management-plane read access and **Storage Blob Data Contributor** at the storage account scope (or equivalent permissions to create, seed, and delete a container and get a user delegation key). Do not use a production or customer-data account.

Set these variables in the local environment, not in the repository:

| Variable | Value |
| --- | --- |
| `AZUIFER_LIVE_STORAGE_SUBSCRIPTION` | UUID of the selected dev subscription |
| `AZUIFER_LIVE_STORAGE_RESOURCE_GROUP` | Resource group of the tagged account |
| `AZUIFER_LIVE_STORAGE_ACCOUNT` | Storage account name, not a URL |

```sh
cargo test --locked --test tls_auth_http \
  contracts::live::record_live_blob_sas_contract -- --ignored --exact --nocapture
```

The live test checks the account and tag before requesting a Storage access token. It creates a new randomly named container and one synthetic blob, uses a short-lived user-delegation SAS for the probes, then deletes the test container. It does not list account keys, change account settings, or access existing containers. The test reports cleanup failures; an interrupted run may leave an `azuifer-contract-` container.

The recorder writes only the allowlisted contract model to `dist/azure-contracts/` (ignored by Git). It never writes request URLs, Azure resource identifiers, access tokens, SAS parameters, delegation keys, raw headers, or arbitrary bodies. For example, an ETag is recorded as matching the seeded object's ETag, not as the original value. The Azure result is saved before comparison so a mismatch can be inspected and replayed. A failed setup or an Azure response that cannot be tied to the seeded blob does not produce a cassette.

Review the normalized fields and provenance before adding an Azure fixture to source control. A passing cassette is evidence only for those operations, that API version and auth mode, and the fields checked by the scenario. It does not change an operation's conformance rating or replace live reruns as Azure evolves.
