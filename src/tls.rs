//! TLS for every service listener (ADR-0006, ADR-0009).
//!
//! One certificate serves all services. It comes from a PEM certificate chain and
//! key, from a PKCS#12 (PFX) file, or, for development, from `--tls-generate`: a
//! self-signed ECDSA certificate for `localhost`, `127.0.0.1`, `::1`, and the
//! `*.{blob,queue,table,dfs,file}.localhost` host-style names. The stack is
//! rustls with the `ring` provider, so it builds without system OpenSSL.

use crate::config::Config;
use anyhow::{Context as _, Result, bail, ensure};
use clap::Args;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use serde::Deserialize;
use std::{
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const DEV_CERT: &str = "azuifer-dev.crt";
const DEV_KEY: &str = "azuifer-dev.key";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKES: usize = 128;
const DEV_NAMES: [&str; 8] = [
    "localhost",
    "127.0.0.1",
    "::1",
    "*.blob.localhost",
    "*.queue.localhost",
    "*.table.localhost",
    "*.dfs.localhost",
    "*.file.localhost",
];

#[derive(Args, Default)]
pub(crate) struct TlsOptions {
    /// PEM certificate chain served by every service (with `--tls-key`).
    #[arg(long = "tls-cert", env = "AZUIFER_TLS_CERT", global = true)]
    cert: Option<PathBuf>,
    /// PEM private key for `--tls-cert`.
    #[arg(long = "tls-key", env = "AZUIFER_TLS_KEY", global = true)]
    key: Option<PathBuf>,
    /// PKCS#12 (PFX) file holding the certificate chain and key.
    #[arg(long = "tls-pfx", env = "AZUIFER_TLS_PFX", global = true)]
    pfx: Option<PathBuf>,
    /// Password of the `--tls-pfx` file; empty when omitted.
    #[arg(
        long = "tls-pfx-password",
        env = "AZUIFER_TLS_PFX_PASSWORD",
        global = true
    )]
    pfx_password: Option<String>,
    /// Create (or reuse) a self-signed development certificate under the data directory.
    #[arg(long = "tls-generate", env = "AZUIFER_TLS_GENERATE", global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    generate: Option<bool>,
}

/// The `[tls]` table of the TOML configuration.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FileSettings {
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    pfx: Option<PathBuf>,
    pfx_password: Option<String>,
    generate: Option<bool>,
}

/// Where the certificate comes from. Absent from the configuration means plain HTTP.
#[derive(Clone)]
pub(crate) enum Settings {
    Pem { cert: PathBuf, key: PathBuf },
    Pfx { path: PathBuf, password: String },
    Generate,
}

impl Settings {
    pub(crate) fn resolve(options: TlsOptions, file: FileSettings) -> Result<Option<Self>> {
        let cert = options.cert.or(file.cert);
        let key = options.key.or(file.key);
        let pfx = options.pfx.or(file.pfx);
        let password = options.pfx_password.or(file.pfx_password);
        let generate = options.generate.or(file.generate).unwrap_or(false);
        ensure!(
            password.is_none() || pfx.is_some(),
            "--tls-pfx-password requires --tls-pfx"
        );
        let sources = usize::from(cert.is_some() || key.is_some())
            + usize::from(pfx.is_some())
            + usize::from(generate);
        ensure!(
            sources <= 1,
            "choose one of --tls-cert with --tls-key, --tls-pfx, or --tls-generate"
        );
        if generate {
            return Ok(Some(Self::Generate));
        }
        if let Some(path) = pfx {
            ensure!(path.is_file(), "the --tls-pfx file does not exist");
            return Ok(Some(Self::Pfx {
                path,
                password: password.unwrap_or_default(),
            }));
        }
        match (cert, key) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => {
                ensure!(cert.is_file(), "the --tls-cert file does not exist");
                ensure!(key.is_file(), "the --tls-key file does not exist");
                Ok(Some(Self::Pem { cert, key }))
            }
            _ => bail!("--tls-cert and --tls-key must be given together"),
        }
    }
}

impl Config {
    /// `https` when the listeners terminate TLS, otherwise `http`.
    pub(crate) fn scheme(&self) -> &'static str {
        if self.tls.is_some() { "https" } else { "http" }
    }
}

/// A ready TLS acceptor, plus the certificate file clients should trust when it
/// was generated.
pub(crate) struct Tls {
    pub(crate) acceptor: TlsAcceptor,
    pub(crate) generated: Option<PathBuf>,
    // Keeps an in-memory run's generated files alive until the server stops.
    _scratch: Option<tempfile::TempDir>,
}

/// Loads (or generates) the certificate. `location` is the data directory, or
/// `None` for an in-memory run, which generates into a temporary directory.
pub(crate) async fn prepare(settings: &Settings, location: Option<&Path>) -> Result<Tls> {
    let (settings, location) = (settings.clone(), location.map(Path::to_owned));
    tokio::task::spawn_blocking(move || build(&settings, location.as_deref()))
        .await
        .context("TLS initialization did not complete")?
}

fn build(settings: &Settings, location: Option<&Path>) -> Result<Tls> {
    let mut scratch = None;
    let mut generated = None;
    let (chain, key) = match settings {
        Settings::Pem { cert, key } => load_pem(cert, key)?,
        Settings::Pfx { path, password } => load_pfx(path, password)?,
        Settings::Generate => {
            let directory = match location {
                Some(location) => location.join("tls"),
                None => {
                    let temporary = tempfile::Builder::new()
                        .prefix("azuifer-tls-")
                        .tempdir()
                        .context("could not create a temporary directory for the certificate")?;
                    let path = temporary.path().to_owned();
                    scratch = Some(temporary);
                    path
                }
            };
            let (cert, key) = (directory.join(DEV_CERT), directory.join(DEV_KEY));
            if !(cert.is_file() && key.is_file()) {
                std::fs::create_dir_all(&directory)
                    .context("could not create the TLS directory")?;
                write_development_certificate(&cert, &key)?;
            }
            generated = Some(cert.clone());
            load_pem(&cert, &key)?
        }
    };
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("could not select TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("the certificate and private key do not match or are not usable")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Tls {
        acceptor: TlsAcceptor::from(Arc::new(config)),
        generated,
        _scratch: scratch,
    })
}

type Identity = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

fn load_pem(cert: &Path, key: &Path) -> Result<Identity> {
    let chain = CertificateDer::pem_file_iter(cert)
        .context("could not read the certificate file")?
        .collect::<Result<Vec<_>, _>>()
        .context("the certificate file is not valid PEM")?;
    ensure!(
        !chain.is_empty(),
        "the certificate file holds no certificate"
    );
    let key = PrivateKeyDer::from_pem_file(key)
        .context("the private key file is missing or holds no PEM private key")?;
    Ok((chain, key))
}

fn load_pfx(path: &Path, password: &str) -> Result<Identity> {
    let data = std::fs::read(path).context("could not read the PFX file")?;
    let store = p12_keystore::KeyStore::from_pkcs12(
        &data,
        password,
        p12_keystore::Pkcs12ImportPolicy::Strict,
    )
    .map_err(|_| {
        anyhow::anyhow!("the PFX file is not a valid PKCS#12 store or the password is wrong")
    })?;
    let (_, chain) = store
        .private_key_chain()
        .context("the PFX file holds no private key with a certificate")?;
    let certificates = chain
        .certs()
        .iter()
        .map(|certificate| CertificateDer::from(certificate.as_der().to_vec()))
        .collect::<Vec<_>>();
    ensure!(
        !certificates.is_empty(),
        "the PFX file holds no certificate"
    );
    let key = PrivateKeyDer::try_from(chain.key().as_der().to_vec())
        .map_err(|_| anyhow::anyhow!("the PFX private key is not PKCS#8"))?;
    Ok((certificates, key))
}

fn write_development_certificate(cert: &Path, key: &Path) -> Result<()> {
    let (certificate, private_key) = generate()?;
    std::fs::write(cert, certificate).context("could not write the certificate")?;
    write_private(key, &private_key)
}

/// A self-signed ECDSA P-256 certificate and its PKCS#8 key, both PEM.
pub(crate) fn generate() -> Result<(String, String)> {
    use rcgen::{DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
    let mut params = rcgen::CertificateParams::new(DEV_NAMES.map(str::to_owned).to_vec())
        .context("could not describe the development certificate")?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Azuifer development certificate");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let year = 1970
        + i32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
                / 31_556_952,
        )
        .unwrap_or(0);
    params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + 10, 12, 31);
    let key = KeyPair::generate().context("could not generate a TLS key")?;
    let certificate = params
        .self_signed(&key)
        .context("could not sign the development certificate")?;
    Ok((certificate.pem(), key.serialize_pem()))
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .context("could not write the private key")
}

/// Terminates TLS for one service. Handshakes run on their own tasks, so a slow
/// or stalled client never delays other connections.
pub(crate) struct TlsListener {
    address: SocketAddr,
    accepted: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

impl TlsListener {
    pub(crate) fn new(listener: TcpListener, acceptor: TlsAcceptor) -> std::io::Result<Self> {
        let address = listener.local_addr()?;
        let (sender, accepted) = mpsc::channel(64);
        tokio::spawn(accept_loop(listener, acceptor, sender));
        Ok(Self { address, accepted })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.address)
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    sender: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    loop {
        let permit = tokio::select! {
            () = sender.closed() => return,
            permit = handshakes.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return,
            },
        };
        let (stream, peer) = tokio::select! {
            () = sender.closed() => return,
            accepted = listener.accept() => match accepted {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "could not accept a connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let (acceptor, sender) = (acceptor.clone(), sender.clone());
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let _ = sender.send((stream, peer)).await;
                }
                Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn options() -> TlsOptions {
        TlsOptions::default()
    }

    #[test]
    fn exactly_one_certificate_source_is_allowed() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("x");
        std::fs::write(&file, "x").unwrap();
        let resolve = |build: &dyn Fn(&mut TlsOptions)| {
            let mut options = options();
            build(&mut options);
            Settings::resolve(options, FileSettings::default())
        };
        assert!(resolve(&|_| ()).unwrap().is_none());
        assert!(matches!(
            resolve(&|o| o.generate = Some(true)).unwrap(),
            Some(Settings::Generate)
        ));
        assert!(resolve(&|o| o.generate = Some(false)).unwrap().is_none());
        assert!(resolve(&|o| o.cert = Some(file.clone())).is_err());
        assert!(resolve(&|o| o.key = Some(file.clone())).is_err());
        assert!(
            resolve(&|o| {
                o.cert = Some(file.clone());
                o.key = Some(file.clone());
            })
            .unwrap()
            .is_some()
        );
        assert!(
            resolve(&|o| {
                o.cert = Some(file.clone());
                o.key = Some(file.clone());
                o.generate = Some(true);
            })
            .is_err()
        );
        assert!(resolve(&|o| o.pfx_password = Some("p".into())).is_err());
        assert!(resolve(&|o| o.pfx = Some(directory.path().join("missing"))).is_err());
        assert!(
            resolve(&|o| {
                o.pfx = Some(file.clone());
                o.generate = Some(true);
            })
            .is_err()
        );
    }

    fn client_config(trusted: &Path) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(trusted).unwrap() {
            roots.add(certificate.unwrap()).unwrap();
        }
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    async fn handshake(listener_tls: &Tls, trusted: &Path, name: &'static str) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut accepting = TlsListener::new(listener, listener_tls.acceptor.clone()).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = axum::serve::Listener::accept(&mut accepting).await;
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            stream.write_all(&byte).await.unwrap();
            stream.flush().await.unwrap();
        });
        let connector = tokio_rustls::TlsConnector::from(client_config(trusted));
        let tcp = TcpStream::connect(address).await.unwrap();
        let outcome = match connector
            .connect(ServerName::try_from(name).unwrap(), tcp)
            .await
        {
            Ok(mut stream) => {
                stream.write_all(b"x").await.unwrap();
                let mut echo = [0u8; 1];
                stream.read_exact(&mut echo).await.unwrap();
                echo == *b"x"
            }
            Err(_) => false,
        };
        server.abort();
        outcome
    }

    #[tokio::test]
    async fn the_generated_certificate_covers_every_development_name() {
        let location = tempfile::tempdir().unwrap();
        let tls = prepare(&Settings::Generate, Some(location.path()))
            .await
            .unwrap();
        let certificate = tls.generated.clone().unwrap();
        assert_eq!(certificate, location.path().join("tls").join(DEV_CERT));
        for name in [
            "localhost",
            "127.0.0.1",
            "::1",
            "devstoreaccount1.blob.localhost",
            "acct.queue.localhost",
            "acct.table.localhost",
            "acct.dfs.localhost",
            "acct.file.localhost",
        ] {
            assert!(handshake(&tls, &certificate, name).await, "{name}");
        }
        assert!(!handshake(&tls, &certificate, "example.com").await);
    }

    #[tokio::test]
    async fn a_generated_certificate_is_reused_and_in_memory_runs_use_a_temporary_directory() {
        let location = tempfile::tempdir().unwrap();
        let first = prepare(&Settings::Generate, Some(location.path()))
            .await
            .unwrap();
        let path = first.generated.clone().unwrap();
        let before = std::fs::read(&path).unwrap();
        prepare(&Settings::Generate, Some(location.path()))
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let memory = prepare(&Settings::Generate, None).await.unwrap();
        let temporary = memory.generated.clone().unwrap();
        assert!(temporary.is_file());
        drop(memory);
        assert!(!temporary.exists(), "the scratch directory is removed");
    }

    #[tokio::test]
    async fn pem_and_pfx_sources_load_the_same_identity() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = generate().unwrap();
        let (cert, key) = (
            directory.path().join("c.pem"),
            directory.path().join("k.pem"),
        );
        std::fs::write(&cert, &cert_pem).unwrap();
        std::fs::write(&key, &key_pem).unwrap();
        let pem = prepare(
            &Settings::Pem {
                cert: cert.clone(),
                key: key.clone(),
            },
            None,
        )
        .await
        .unwrap();
        assert!(handshake(&pem, &cert, "localhost").await);

        let (chain, private_key) = load_pem(&cert, &key).unwrap();
        let mut store = p12_keystore::KeyStore::new();
        store.add_entry(
            "azuifer",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(p12_keystore::PrivateKeyChain::new(
                b"1".to_vec(),
                p12_keystore::PrivateKey::from_der(private_key.secret_der()).unwrap(),
                [p12_keystore::Certificate::from_der(chain[0].as_ref()).unwrap()],
            )),
        );
        let pfx = directory.path().join("id.pfx");
        std::fs::write(&pfx, store.writer("pw").write().unwrap()).unwrap();
        let from_pfx = prepare(
            &Settings::Pfx {
                path: pfx.clone(),
                password: "pw".into(),
            },
            None,
        )
        .await
        .unwrap();
        assert!(handshake(&from_pfx, &cert, "127.0.0.1").await);
        let wrong = prepare(
            &Settings::Pfx {
                path: pfx,
                password: "nope".into(),
            },
            None,
        )
        .await;
        assert!(wrong.is_err());
    }
}
