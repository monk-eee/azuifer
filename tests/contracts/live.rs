use super::{Cassette, Source, delegation, observe_blob, observe_local, with_local};
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
}

pub(super) fn save(cassette: Record<'_>, directory: &Path) -> Result<PathBuf> {
    fs::create_dir_all(directory)
        .context("could not create the ignored cassette output directory")?;
    let scenario = match cassette {
        Record::Sas(_) => "blob-user-delegation-sas-read-only",
        Record::Delegation(_) => "blob-get-user-delegation-key",
        Record::InvalidWindows(_) => "blob-delegation-key-invalid-windows",
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
        "Saved normalized Azure response cassette to {}",
        path.display()
    );
    Ok(())
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn record_live_blob_sas_contract() -> Result<()> {
    let local = observe_local()?;
    ensure!(
        local.seeded_blob_was_read(),
        "Azuifer did not serve the synthetic setup blob"
    );
    let azure = with_azure(|client, account, endpoint, bearer| {
        observe_blob(client, account, endpoint, bearer, Source::Azure)
    })?;
    ensure!(
        azure.seeded_blob_was_read(),
        "Azure did not return the seeded blob via the read-only SAS; no cassette written"
    );
    save_azure(Record::Sas(&azure))?;
    azure.compare(&local)?;
    println!("Live Azure and Azuifer matched on all selected fields");
    Ok(())
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn record_live_delegation_key_contract() -> Result<()> {
    let local = with_local(|client, endpoint, bearer| {
        delegation::observe(client, endpoint, bearer, Source::Synthetic)
    })?;
    let azure = with_azure(|client, _, endpoint, bearer| {
        delegation::observe(client, endpoint, bearer, Source::Azure)
    })?;
    save_azure(Record::Delegation(&azure))?;
    azure.compare(&local)?;
    println!("Live Azure and Azuifer matched on the selected delegation key fields");
    Ok(())
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn record_live_delegation_window_contract() -> Result<()> {
    let local = with_local(|client, endpoint, bearer| {
        delegation::observe_invalid_windows(client, endpoint, bearer, Source::Synthetic)
    })?;
    let azure = with_azure(|client, _, endpoint, bearer| {
        delegation::observe_invalid_windows(client, endpoint, bearer, Source::Azure)
    })?;
    save_azure(Record::InvalidWindows(&azure))?;
    azure.compare(&local)?;
    println!("Live Azure and Azuifer matched on all selected invalid delegation window responses");
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
