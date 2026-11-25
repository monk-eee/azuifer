use super::{Cassette, Source, observe_blob, observe_local};
use anyhow::{Context as _, Result, anyhow, ensure};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
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

pub(super) fn save(cassette: &Cassette, directory: &Path) -> Result<PathBuf> {
    fs::create_dir_all(directory)
        .context("could not create the ignored cassette output directory")?;
    let name = format!(
        "blob-user-delegation-sas-read-only-{}.json",
        Uuid::new_v4().simple()
    );
    let target = directory.join(name);
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer_pretty(file.as_file_mut(), cassette)?;
    writeln!(file)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&target)
        .context("could not save the normalized Azure cassette")?;
    Ok(target)
}

#[test]
#[ignore = "live Azure access: requires a signed-in Azure CLI and an explicitly tagged test account"]
fn record_live_blob_sas_contract() -> Result<()> {
    let target = LiveTarget::configured()?;
    let endpoint = target.verified_endpoint()?;
    let local = observe_local()?;
    ensure!(
        local.seeded_blob_was_read(),
        "Azuifer did not serve the synthetic setup blob"
    );
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| anyhow!("could not initialize the Azure HTTPS client"))?;
    let bearer = target.bearer()?;
    let azure = observe_blob(&client, &target.account, &endpoint, &bearer, Source::Azure)?;
    ensure!(
        azure.seeded_blob_was_read(),
        "Azure did not return the seeded blob via the read-only SAS; no cassette written"
    );
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("dist")
        .join("azure-contracts");
    let path = save(&azure, &directory)?;
    println!(
        "Saved normalized Azure response cassette to {}",
        path.display()
    );
    azure.compare(&local)?;
    println!("Live Azure and Azuifer matched on all selected fields");
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
