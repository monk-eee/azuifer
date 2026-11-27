use super::{
    Cassette, Source, delegation, mutations, observe_blob, observe_local, reviewed_sas, with_local,
};
use anyhow::{Context as _, Result, anyhow, ensure};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

const SUBSCRIPTION: &str = "AZUIFER_LIVE_STORAGE_SUBSCRIPTION";
const RESOURCE_GROUP: &str = "AZUIFER_LIVE_STORAGE_RESOURCE_GROUP";
const ACCOUNT: &str = "AZUIFER_LIVE_STORAGE_ACCOUNT";
const OPT_IN_TAG: &str = "azuifer-contract-tests";
const CAPTURE: &str = "AZUIFER_CONTRACT_CAPTURE";

struct LiveTarget {
    subscription: String,
    resource_group: String,
    account: String,
}

impl LiveTarget {
    fn configured() -> Result<Self> {
        let required = |name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.is_empty())
                .with_context(|| format!("{name} must select a dedicated Azure test target"))
        };
        let subscription = Uuid::parse_str(&required(SUBSCRIPTION)?)
            .map_err(|_| anyhow!("{SUBSCRIPTION} must be a subscription UUID"))?
            .hyphenated()
            .to_string();
        let resource_group = required(RESOURCE_GROUP)?;
        let account = required(ACCOUNT)?;
        ensure!(
            valid_resource_group(&resource_group),
            "{RESOURCE_GROUP} is not a supported resource group name"
        );
        ensure!(
            valid_account(&account),
            "{ACCOUNT} must be a public Azure Storage account name"
        );
        Ok(Self {
            subscription,
            resource_group,
            account,
        })
    }

    fn verified_endpoint(&self) -> Result<Url> {
        let raw = az(
            &[
                "storage",
                "account",
                "show",
                "--subscription",
                &self.subscription,
                "--resource-group",
                &self.resource_group,
                "--name",
                &self.account,
            ],
            "verify dedicated storage account",
        )?;
        let info: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|_| anyhow!("Azure CLI returned invalid storage account metadata"))?;
        let endpoint = format!("https://{}.blob.core.windows.net/", self.account);
        ensure!(
            info["tags"][OPT_IN_TAG].as_str() == Some("true"),
            "the selected account is not tagged {OPT_IN_TAG}=true"
        );
        ensure!(
            info["primaryEndpoints"]["blob"].as_str() == Some(endpoint.as_str()),
            "the selected account does not use a public Azure Blob HTTPS endpoint"
        );
        Ok(Url::parse(&endpoint)?)
    }

    fn bearer(&self) -> Result<String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Token {
            access_token: String,
        }
        let raw = az(
            &[
                "account",
                "get-access-token",
                "--subscription",
                &self.subscription,
                "--resource",
                "https://storage.azure.com/",
            ],
            "acquire Azure Storage data-plane credential",
        )?;
        let token: Token = serde_json::from_slice(&raw)
            .map_err(|_| anyhow!("Azure CLI did not return a usable Storage credential"))?;
        ensure!(
            !token.access_token.is_empty(),
            "Azure CLI returned an empty Storage credential"
        );
        Ok(token.access_token)
    }
}

fn valid_account(name: &str) -> bool {
    (3..=24).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn valid_resource_group(name: &str) -> bool {
    (1..=90).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn az(arguments: &[&str], phase: &'static str) -> Result<Vec<u8>> {
    let invoke = |executable| {
        Command::new(executable)
            .args(arguments)
            .args(["--only-show-errors", "--output", "json"])
            .env("AZURE_CORE_COLLECT_TELEMETRY", "no")
            .stdin(Stdio::null())
            .output()
    };
    let output = match invoke("az") {
        Err(error) if cfg!(windows) && error.kind() == ErrorKind::NotFound => invoke("az.cmd"),
        result => result,
    }
    .map_err(|error| anyhow!("{phase}: Azure CLI could not start ({:?})", error.kind()))?;
    // Azure CLI diagnostics may contain account names or URLs.
    ensure!(
        output.status.success(),
        "{phase}: Azure CLI failed ({:?}); check the selected subscription, login and RBAC",
        output.status.code()
    );
    Ok(output.stdout)
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum Record<'a> {
    Sas(&'a Cassette),
    Delegation(&'a delegation::KeyCassette),
    InvalidWindows(&'a delegation::WindowCassette),
    BlobMutation(&'a mutations::MutationCassette),
}

pub(super) fn save(cassette: Record<'_>, directory: &Path) -> Result<PathBuf> {
    fs::create_dir_all(directory)
        .context("could not create the ignored cassette output directory")?;
    let scenario = match cassette {
        Record::Sas(_) => "blob-user-delegation-sas-read-only",
        Record::Delegation(_) => "blob-get-user-delegation-key",
        Record::InvalidWindows(_) => "blob-delegation-key-invalid-windows",
        Record::BlobMutation(cassette) => cassette.case.file_stem(),
    };
    let name = format!("{scenario}-{}.json", Uuid::new_v4().simple());
    let target = directory.join(name);
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer_pretty(file.as_file_mut(), &cassette)?;
    writeln!(file)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&target)
        .context("could not save the normalized Azure cassette")?;
    Ok(target)
}

fn with_azure<T>(observe: impl FnOnce(&Client, &str, &Url, &str) -> Result<T>) -> Result<T> {
    let target = LiveTarget::configured()?;
    let endpoint = target.verified_endpoint()?;
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| anyhow!("could not initialize the Azure HTTPS client"))?;
    let bearer = target.bearer()?;
    observe(&client, &target.account, &endpoint, &bearer)
}

fn save_azure(cassette: Record<'_>) -> Result<()> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("dist")
        .join("azure-contracts");
    let path = save(cassette, &directory)?;
    println!(
        "Saved Azure candidate (not an approved baseline) to {}",
        path.display()
    );
    Ok(())
}

fn check_drift<T>(
    baseline: &T,
    azure: Result<T>,
    local: Result<T>,
    compare: fn(&T, &T) -> Result<()>,
) -> Result<()> {
    let check = |side, result: Result<T>| {
        let actual = result.with_context(|| format!("{side} observation failed"))?;
        compare(baseline, &actual)
            .with_context(|| format!("{side} drift against the reviewed cassette"))
    };
    match (check("Azure", azure), check("Azuifer", local)) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(azure), Err(local)) => Err(anyhow!("{azure:#}\n{local:#}")),
    }
}

fn run_live<T>(
    reviewed: impl FnOnce() -> Result<T>,
    azure: impl FnOnce(&Client, &str, &Url, &str) -> Result<T>,
    local: impl FnOnce() -> Result<T>,
    compare: fn(&T, &T) -> Result<()>,
    capture: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    match std::env::var_os(CAPTURE) {
        Some(flag) if flag == "1" => return capture(&with_azure(azure)?),
        Some(_) => {
            return Err(anyhow!(
                "unset {CAPTURE} for checks or set it to 1 to capture"
            ));
        }
        None => (),
    }
    let baseline = reviewed()?;
    check_drift(&baseline, with_azure(azure), local(), compare)?;
    println!("Azure and Azuifer each matched the reviewed cassette");
    Ok(())
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_sas_contract() -> Result<()> {
    run_live(
        reviewed_sas,
        |client, account, endpoint, bearer| {
            observe_blob(client, account, endpoint, bearer, Source::Azure)
        },
        observe_local,
        Cassette::compare,
        |azure| {
            ensure!(
                azure.seeded_blob_was_read(),
                "Azure did not return the seeded blob via the read-only SAS; no cassette written"
            );
            save_azure(Record::Sas(azure))
        },
    )
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_delegation_key_contract() -> Result<()> {
    run_live(
        delegation::reviewed_key,
        |client, _, endpoint, bearer| delegation::observe(client, endpoint, bearer, Source::Azure),
        || {
            with_local(|client, endpoint, bearer| {
                delegation::observe(client, endpoint, bearer, Source::Synthetic)
            })
        },
        delegation::KeyCassette::compare,
        |azure| save_azure(Record::Delegation(azure)),
    )
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_delegation_window_contract() -> Result<()> {
    run_live(
        delegation::reviewed_windows,
        |client, _, endpoint, bearer| {
            delegation::observe_invalid_windows(client, endpoint, bearer, Source::Azure)
        },
        || {
            with_local(|client, endpoint, bearer| {
                delegation::observe_invalid_windows(client, endpoint, bearer, Source::Synthetic)
            })
        },
        delegation::WindowCassette::compare,
        |azure| save_azure(Record::InvalidWindows(azure)),
    )
}

fn live_mutation(case: mutations::Case) -> Result<()> {
    run_live(
        || mutations::reviewed(case),
        |client, _, endpoint, bearer| {
            mutations::observe(client, endpoint, bearer, Source::Azure, case)
        },
        || mutations::observe_local(case),
        mutations::MutationCassette::compare,
        |azure| {
            azure.validate()?;
            save_azure(Record::BlobMutation(azure))
        },
    )
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_mutation_conditional_overwrite() -> Result<()> {
    live_mutation(mutations::Case::ConditionalOverwrite)
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_mutation_staged_block_commit() -> Result<()> {
    live_mutation(mutations::Case::StagedBlockCommit)
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_mutation_lease_guard() -> Result<()> {
    live_mutation(mutations::Case::LeaseGuard)
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_mutation_snapshot_recovery() -> Result<()> {
    live_mutation(mutations::Case::SnapshotRecovery)
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_mutation_append_position() -> Result<()> {
    live_mutation(mutations::Case::AppendPosition)
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn check_live_blob_mutation_sparse_page_writes() -> Result<()> {
    live_mutation(mutations::Case::SparsePageWrites)
}

#[test]
fn live_drift_is_reported_even_when_both_services_change_together() -> Result<()> {
    let baseline = reviewed_sas()?;
    let actual = |drift| {
        let mut observed = serde_json::to_value(&baseline)?;
        if drift {
            observed["exchanges"][1]["content_length"] = serde_json::json!(99);
        }
        Cassette::load(&serde_json::to_vec(&observed)?)
    };
    for (azure, local) in [(true, false), (false, true), (true, true)] {
        let error = check_drift(&baseline, actual(azure), actual(local), Cassette::compare)
            .expect_err("a mismatch on either side must fail");
        let message = format!("{error:#}");
        assert_eq!(
            message.contains("Azure drift against the reviewed cassette"),
            azure
        );
        assert_eq!(
            message.contains("Azuifer drift against the reviewed cassette"),
            local
        );
        assert!(message.contains("Range:"));
    }
    Ok(())
}

#[test]
fn live_target_inputs_do_not_allow_urls_or_command_arguments() {
    assert!(valid_account("account123"));
    assert!(!valid_account("example.com"));
    assert!(!valid_account("--debug"));
    assert!(!valid_account("account?sig=secret"));
    assert!(valid_resource_group("dev-test_01"));
    assert!(!valid_resource_group("--help"));
    assert!(!valid_resource_group("dev&echo"));
}
