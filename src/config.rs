use crate::domain::{AccountName, ApiVersion};
use anyhow::{Context as _, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Args;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

const DEV_ACCOUNT: &str = "devstoreaccount1";
// Public emulator interoperability fixture, never permitted on a non-loopback bind.
const PUBLIC_DEV_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const MIB: u64 = 1024 * 1024;
pub(crate) const CONFORMANCE: &str = include_str!("../specs/conformance/blob.json");

#[derive(Args, Default)]
pub(crate) struct Options {
    #[arg(long, env = "AZUIFER_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[arg(long, env = "AZUIFER_BIND", global = true)]
    bind: Option<IpAddr>,
    #[arg(long, env = "AZUIFER_PORT", global = true)]
    port: Option<u16>,
    #[arg(long, env = "AZUIFER_ADMIN_PORT", global = true)]
    admin_port: Option<u16>,
    #[arg(long, env = "AZUIFER_LOCATION", global = true)]
    location: Option<PathBuf>,
    #[arg(long, env = "AZUIFER_IN_MEMORY", global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    in_memory: Option<bool>,
    #[arg(long, env = "AZUIFER_MEMORY_LIMIT", global = true)]
    memory_limit: Option<u64>,
    #[arg(long, env = "AZUIFER_MAX_BLOB_BYTES", global = true)]
    max_blob_bytes: Option<u64>,
    #[arg(long, env = "AZUIFER_UPLOAD_TIMEOUT_SECONDS", global = true)]
    upload_timeout_seconds: Option<u64>,
    #[arg(long, env = "AZUIFER_SKIP_API_VERSION_CHECK", global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    skip_api_version_check: Option<bool>,
    #[arg(long, env = "AZUIFER_SERVICES", global = true)]
    services: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    bind: Option<IpAddr>,
    port: Option<u16>,
    admin_port: Option<u16>,
    location: Option<PathBuf>,
    in_memory: Option<bool>,
    memory_limit: Option<u64>,
    max_blob_bytes: Option<u64>,
    upload_timeout_seconds: Option<u64>,
    skip_api_version_check: Option<bool>,
    services: Option<String>,
    accounts: Vec<AccountConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountConfig {
    name: String,
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct Manifest {
    api_version: String,
}

pub(crate) struct Config {
    pub(crate) blob: SocketAddr,
    pub(crate) admin: SocketAddr,
    pub(crate) location: Option<PathBuf>,
    pub(crate) memory_limit: u64,
    pub(crate) max_blob_bytes: u64,
    pub(crate) upload_timeout: Duration,
    pub(crate) skip_api_version_check: bool,
    pub(crate) accounts: HashMap<AccountName, Vec<Vec<u8>>>,
    pub(crate) api_version: ApiVersion,
}

impl Config {
    pub(crate) fn load(options: Options) -> Result<Self> {
        let file = if let Some(path) = options.config {
            let text = std::fs::read_to_string(path).context("could not read configuration")?;
            toml::from_str::<FileConfig>(&text).map_err(|error| {
                anyhow::anyhow!(
                    "invalid configuration TOML at byte {}",
                    error.span().map_or(0, |span| span.start)
                )
            })?
        } else {
            FileConfig::default()
        };
        let binding = options
            .bind
            .or(file.bind)
            .unwrap_or(Ipv4Addr::LOCALHOST.into());
        let port = options.port.or(file.port).unwrap_or(10000);
        let admin_port = options.admin_port.or(file.admin_port).unwrap_or(10005);
        ensure!(
            port == 0 || port != admin_port,
            "Blob and admin ports must differ"
        );
        let services = options
            .services
            .or(file.services)
            .unwrap_or_else(|| "blob".into());
        ensure!(
            services == "blob",
            "only the Blob service is implemented in this build"
        );
        let in_memory = options.in_memory.or(file.in_memory).unwrap_or(false);
        let location = if in_memory {
            None
        } else {
            Some(
                options
                    .location
                    .or(file.location)
                    .unwrap_or_else(|| "data".into()),
            )
        };
        let memory_limit = options
            .memory_limit
            .or(file.memory_limit)
            .unwrap_or(64 * MIB);
        let max_blob_bytes = options
            .max_blob_bytes
            .or(file.max_blob_bytes)
            .unwrap_or(16 * MIB);
        ensure!(
            (1..=1024 * MIB).contains(&max_blob_bytes),
            "max-blob-bytes must be between 1 and 1073741824"
        );
        ensure!(
            memory_limit > 0 && memory_limit <= 16 * 1024 * MIB,
            "memory-limit must be between 1 and 17179869184"
        );
        let upload_timeout = options
            .upload_timeout_seconds
            .or(file.upload_timeout_seconds)
            .unwrap_or(60);
        ensure!(
            (1..=600).contains(&upload_timeout),
            "upload-timeout-seconds must be between 1 and 600"
        );

        let accounts = load_accounts(file.accounts, binding.is_loopback())?;
        let manifest: Manifest =
            serde_json::from_str(CONFORMANCE).context("invalid embedded protocol manifest")?;
        let api_version = ApiVersion::parse(&manifest.api_version)
            .map_err(|_| anyhow::anyhow!("invalid Blob API version in the protocol manifest"))?;
        Ok(Self {
            blob: SocketAddr::new(binding, port),
            admin: SocketAddr::new(binding, admin_port),
            location,
            memory_limit,
            max_blob_bytes,
            upload_timeout: Duration::from_secs(upload_timeout),
            skip_api_version_check: options
                .skip_api_version_check
                .or(file.skip_api_version_check)
                .unwrap_or(false),
            accounts,
            api_version,
        })
    }
}

fn load_accounts(
    mut entries: Vec<AccountConfig>,
    loopback: bool,
) -> Result<HashMap<AccountName, Vec<Vec<u8>>>> {
    let env_name = env_value("AZUIFER_ACCOUNT_NAME")?;
    if let Some(key) = env_value("AZUIFER_ACCOUNT_KEY")? {
        let name = env_name.unwrap_or_else(|| DEV_ACCOUNT.into());
        entries.retain(|entry| entry.name != name);
        entries.push(AccountConfig {
            name,
            keys: vec![key],
        });
    } else {
        ensure!(
            env_name.is_none(),
            "AZUIFER_ACCOUNT_NAME requires AZUIFER_ACCOUNT_KEY"
        );
    }
    if entries.is_empty() {
        entries.push(AccountConfig {
            name: DEV_ACCOUNT.into(),
            keys: vec![PUBLIC_DEV_KEY.into()],
        });
    }
    let mut result = HashMap::new();
    for entry in entries {
        let name =
            AccountName::parse(&entry.name).map_err(|_| anyhow::anyhow!("invalid account name"))?;
        ensure!(
            (1..=2).contains(&entry.keys.len()),
            "an account must have one or two Shared Keys"
        );
        let keys = entry
            .keys
            .into_iter()
            .map(|key| {
                ensure!(
                    loopback || key != PUBLIC_DEV_KEY,
                    "the public development Shared Key requires loopback"
                );
                let key = STANDARD
                    .decode(key)
                    .map_err(|_| anyhow::anyhow!("Shared Key must be valid Base64"))?;
                ensure!(
                    (32..=64).contains(&key.len()),
                    "Shared Key must decode to 32 through 64 bytes"
                );
                Ok(key)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            result.insert(name, keys).is_none(),
            "duplicate account in configuration"
        );
    }
    Ok(result)
}

fn env_value(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be UTF-8"),
    }
}
