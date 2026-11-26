use crate::domain::{AccountName, ApiVersion};
use crate::telemetry;
use anyhow::{Context as _, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::Args;
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

const DEV_ACCOUNT: &str = "devstoreaccount1";
// Public emulator interoperability fixture, never permitted on a non-loopback bind.
const PUBLIC_DEV_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const MIB: u64 = 1024 * 1024;
/// How long a request queues for one of the 16 active-request permits before the
/// listener answers `503 ServerBusy`; AzCopy opens hundreds of connections at once.
pub(crate) const PERMIT_WAIT: Duration = Duration::from_secs(5);
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
    #[arg(long, env = "AZUIFER_MAX_BLOCK_BYTES", global = true)]
    max_block_bytes: Option<u64>,
    #[arg(long, env = "AZUIFER_MAX_ASSEMBLED_BLOB_BYTES", global = true)]
    max_assembled_blob_bytes: Option<u64>,
    #[arg(long, env = "AZUIFER_TEST_CLOCK", global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    test_clock: Option<bool>,
    #[arg(long, env = "AZUIFER_UPLOAD_TIMEOUT_SECONDS", global = true)]
    upload_timeout_seconds: Option<u64>,
    #[arg(long, env = "AZUIFER_SKIP_API_VERSION_CHECK", global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    skip_api_version_check: Option<bool>,
    #[arg(long, env = "AZUIFER_SERVICES", global = true)]
    services: Option<String>,
    #[arg(long, env = "AZUIFER_QUEUE_PORT", global = true)]
    queue_port: Option<u16>,
    #[arg(long, env = "AZUIFER_TABLE_PORT", global = true)]
    table_port: Option<u16>,
    #[arg(long, env = "AZUIFER_DFS_PORT", global = true)]
    dfs_port: Option<u16>,
    /// Comma-separated configured accounts with the DFS namespace enabled.
    #[arg(long, env = "AZUIFER_HNS_ACCOUNTS", global = true)]
    hns_accounts: Option<String>,
    /// Comma-separated configured accounts with Blob versioning enabled.
    #[arg(long, env = "AZUIFER_VERSIONING_ACCOUNTS", global = true)]
    versioning_accounts: Option<String>,
    #[arg(long, env = "AZUIFER_FILE_PORT", global = true)]
    file_port: Option<u16>,
    /// Comma-separated hosts (`host`, `host:port`, `*.domain`) that Copy Blob and the
    /// `...From URL` operations may read from other servers. Off by default.
    #[arg(long, env = "AZUIFER_ALLOW_EXTERNAL_COPY_SOURCES", global = true)]
    allow_external_copy_sources: Option<String>,
    #[command(flatten)]
    telemetry: telemetry::TelemetryOptions,
    #[command(flatten)]
    tls: crate::tls::TlsOptions,
    #[command(flatten)]
    oauth: crate::oauth::OAuthOptions,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Service {
    Blob,
    Queue,
    Table,
    Dfs,
    File,
}

impl Service {
    pub(crate) const ALL: [Self; 5] = [Self::Blob, Self::Queue, Self::Table, Self::Dfs, Self::File];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Queue => "queue",
            Self::Table => "table",
            Self::Dfs => "dfs",
            Self::File => "file",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Blob => 10000,
            Self::Queue => 10001,
            Self::Table => 10002,
            Self::Dfs => 10003,
            Self::File => 10004,
        }
    }

    fn parse_list(value: &str) -> Result<BTreeSet<Self>> {
        let mut services = BTreeSet::new();
        for name in value.split(',').map(str::trim) {
            let service = Self::ALL
                .into_iter()
                .find(|service| service.name() == name)
                .with_context(|| format!("unknown service `{name}`"))?;
            ensure!(services.insert(service), "duplicate service `{name}`");
        }
        Ok(services)
    }
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
    max_block_bytes: Option<u64>,
    max_assembled_blob_bytes: Option<u64>,
    test_clock: Option<bool>,
    upload_timeout_seconds: Option<u64>,
    skip_api_version_check: Option<bool>,
    services: Option<String>,
    queue_port: Option<u16>,
    table_port: Option<u16>,
    dfs_port: Option<u16>,
    hns_accounts: Option<String>,
    versioning_accounts: Option<String>,
    file_port: Option<u16>,
    allow_external_copy_sources: Option<String>,
    otlp_endpoint: Option<String>,
    otlp_protocol: Option<telemetry::OtlpProtocol>,
    prometheus: Option<bool>,
    log_format: Option<telemetry::LogFormat>,
    log_file: Option<PathBuf>,
    tls: crate::tls::FileSettings,
    oauth: crate::oauth::FileSettings,
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
    pub(crate) services: BTreeSet<Service>,
    pub(crate) blob: SocketAddr,
    pub(crate) queue: SocketAddr,
    pub(crate) table: SocketAddr,
    pub(crate) dfs: SocketAddr,
    pub(crate) file: SocketAddr,
    pub(crate) admin: SocketAddr,
    pub(crate) location: Option<PathBuf>,
    pub(crate) memory_limit: u64,
    pub(crate) max_blob_bytes: u64,
    pub(crate) max_block_bytes: u64,
    pub(crate) max_assembled_blob_bytes: u64,
    pub(crate) test_clock: bool,
    pub(crate) upload_timeout: Duration,
    pub(crate) skip_api_version_check: bool,
    pub(crate) accounts: HashMap<AccountName, Vec<Vec<u8>>>,
    pub(crate) hns_accounts: HashSet<AccountName>,
    pub(crate) versioning_accounts: HashSet<AccountName>,
    pub(crate) external_copy_sources: crate::blob_external::Allowlist,
    pub(crate) tls: Option<crate::tls::Settings>,
    pub(crate) oauth: crate::oauth::OAuth,
    pub(crate) delegation: crate::delegation::Keys,
    pub(crate) api_version: ApiVersion,
    pub(crate) telemetry: telemetry::Settings,
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
        let services = Service::parse_list(
            &options
                .services
                .or(file.services)
                .unwrap_or_else(|| "blob,queue,table,dfs,file".into()),
        )?;
        // An ephemeral Blob port makes unspecified service ports ephemeral too,
        // so parallel test runs never collide on the fixed defaults.
        let service_port = |service: Service, explicit: Option<u16>| {
            explicit.unwrap_or(if port == 0 { 0 } else { service.default_port() })
        };
        let ports = [
            (Service::Blob, port),
            (
                Service::Queue,
                service_port(Service::Queue, options.queue_port.or(file.queue_port)),
            ),
            (
                Service::Table,
                service_port(Service::Table, options.table_port.or(file.table_port)),
            ),
            (
                Service::Dfs,
                service_port(Service::Dfs, options.dfs_port.or(file.dfs_port)),
            ),
            (
                Service::File,
                service_port(Service::File, options.file_port.or(file.file_port)),
            ),
        ];
        let mut used = BTreeSet::new();
        for (service, port) in ports
            .iter()
            .filter(|(service, _)| services.contains(service))
            .chain([&(Service::Blob, admin_port)])
        {
            ensure!(
                *port == 0 || used.insert(*port),
                "service ports must differ ({} conflicts)",
                service.name()
            );
        }
        let address = |service: Service| {
            let port = ports
                .iter()
                .find_map(|(candidate, port)| (*candidate == service).then_some(*port))
                .unwrap_or(0);
            SocketAddr::new(binding, port)
        };
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
            .unwrap_or(256 * MIB);
        let max_block_bytes = options
            .max_block_bytes
            .or(file.max_block_bytes)
            .unwrap_or(5000 * MIB);
        let max_assembled_blob_bytes = options
            .max_assembled_blob_bytes
            .or(file.max_assembled_blob_bytes)
            .unwrap_or(512 * MIB);
        ensure!(
            (1..=5000 * MIB).contains(&max_blob_bytes),
            "max-blob-bytes must be between 1 and 5242880000"
        );
        ensure!(
            (1..=5000 * MIB).contains(&max_block_bytes),
            "max-block-bytes must be between 1 and 5242880000"
        );
        ensure!(
            memory_limit > 0 && memory_limit <= 16 * 1024 * MIB,
            "memory-limit must be between 1 and 17179869184"
        );
        ensure!(
            (1..=16 * 1024 * MIB).contains(&max_assembled_blob_bytes),
            "max-assembled-blob-bytes must be between 1 and 17179869184"
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
        let mut hns_accounts = HashSet::new();
        if let Some(value) = options.hns_accounts.or(file.hns_accounts)
            && !value.is_empty()
        {
            for name in value.split(',').map(str::trim) {
                let account = AccountName::parse(name)
                    .map_err(|_| anyhow::anyhow!("invalid name in hns-accounts"))?;
                ensure!(
                    accounts.contains_key(&account),
                    "HNS account `{name}` is not configured"
                );
                ensure!(
                    hns_accounts.insert(account),
                    "duplicate HNS account `{name}`"
                );
            }
        }
        let versioning_accounts = account_list(
            options.versioning_accounts.or(file.versioning_accounts),
            &accounts,
            "versioning-accounts",
        )?;
        let external_copy_sources = crate::blob_external::Allowlist::parse(
            &options
                .allow_external_copy_sources
                .or(file.allow_external_copy_sources)
                .unwrap_or_default(),
        )
        .context("invalid allow-external-copy-sources")?;
        let test_clock = options.test_clock.or(file.test_clock).unwrap_or(false);
        ensure!(
            !test_clock || binding.is_loopback(),
            "--test-clock requires loopback binding"
        );
        let manifest: Manifest =
            serde_json::from_str(CONFORMANCE).context("invalid embedded protocol manifest")?;
        let api_version = ApiVersion::parse(&manifest.api_version)
            .map_err(|_| anyhow::anyhow!("invalid Blob API version in the protocol manifest"))?;
        Ok(Self {
            blob: address(Service::Blob),
            queue: address(Service::Queue),
            table: address(Service::Table),
            dfs: address(Service::Dfs),
            file: address(Service::File),
            services,
            admin: SocketAddr::new(binding, admin_port),
            location,
            memory_limit,
            max_blob_bytes,
            max_block_bytes,
            max_assembled_blob_bytes,
            test_clock,
            upload_timeout: Duration::from_secs(upload_timeout),
            skip_api_version_check: options
                .skip_api_version_check
                .or(file.skip_api_version_check)
                .unwrap_or(false),
            accounts,
            hns_accounts,
            versioning_accounts,
            external_copy_sources,
            tls: crate::tls::Settings::resolve(options.tls, file.tls)?,
            oauth: crate::oauth::OAuth::resolve(options.oauth, file.oauth, binding.is_loopback())?,
            delegation: crate::delegation::Keys::default(),
            api_version,
            telemetry: telemetry::Settings::resolve(
                options.telemetry,
                telemetry::FileSettings {
                    otlp_endpoint: file.otlp_endpoint,
                    otlp_protocol: file.otlp_protocol,
                    prometheus: file.prometheus,
                    log_format: file.log_format,
                    log_file: file.log_file,
                },
            )?,
        })
    }
}

fn account_list(
    value: Option<String>,
    accounts: &HashMap<AccountName, Vec<Vec<u8>>>,
    option: &str,
) -> Result<HashSet<AccountName>> {
    let mut selected = HashSet::new();
    for name in value
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
    {
        if name.is_empty() {
            continue;
        }
        let account =
            AccountName::parse(name).map_err(|_| anyhow::anyhow!("invalid name in {option}"))?;
        ensure!(
            accounts.contains_key(&account),
            "account `{name}` in {option} is not configured"
        );
        ensure!(
            selected.insert(account),
            "duplicate account `{name}` in {option}"
        );
    }
    Ok(selected)
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
