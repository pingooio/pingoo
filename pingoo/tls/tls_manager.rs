use std::{path::PathBuf, sync::Arc};

use dashmap::DashMap;
use instant_acme::KeyAuthorization;
use rustls::{ServerConfig, crypto::CryptoProvider, server::ClientHello};
use tokio::fs;
use tracing::warn;

use crate::{
    Error,
    config::{DEFAULT_TLS_FOLDER, TlsConfig},
    tls::{
        acme::load_or_create_acme_account,
        certificate::{Certificate, generate_self_signed_certificates, parse_certificate_and_private_key},
    },
};

pub struct TlsManager {
    pub default_certificate: Certificate,
    /// certificates indexed by their Subject Alternative Names that don't contain a wildcard
    pub certificates: DashMap<String, Arc<Certificate>>,
    /// certificates that have at least 1 Subject Alternative Name containing a wildcard
    wildcard_certificates: Vec<Arc<Certificate>>,

    pub acme_account: instant_acme::Account,
    pub acme_directory_url: String,
    pub acme_domains: Vec<String>,
    pub acme_authorizations: DashMap<String, KeyAuthorization>,
}

impl TlsManager {
    pub async fn new(tls_config: &TlsConfig) -> Result<Self, Error> {
        fs::create_dir_all(DEFAULT_TLS_FOLDER)
            .await
            .map_err(|err| Error::Config(format!("error creating TLS folder ({DEFAULT_TLS_FOLDER}): {err}")))?;

        let (certificates, wildcard_certificates) = load_certificates(DEFAULT_TLS_FOLDER).await?;

        let default_certificate = load_or_create_default_certificate(DEFAULT_TLS_FOLDER.into()).await?;

        let acme_config = tls_config.acme.clone().unwrap_or_default();

        let acme_account = load_or_create_acme_account(DEFAULT_TLS_FOLDER, acme_config.directory_url.clone()).await?;

        Ok(TlsManager {
            default_certificate,
            certificates,
            wildcard_certificates,

            acme_account,
            acme_directory_url: acme_config.directory_url,
            acme_domains: acme_config.domains,
            acme_authorizations: DashMap::new(),
        })
    }

    pub async fn get_server_config(&self, client_hello: &ClientHello<'_>) -> Arc<ServerConfig> {
        // Server Name Indicator, SNI
        let sni = client_hello.server_name().unwrap_or_default();

        let mut tls_config = {
            // first, we try an exact match of the SNI against the certificates Subject Alternative Names
            let key = match self.certificates.get(sni) {
                Some(cert) => cert.key.clone(),
                None => {
                    // if not found, we try with certificates that contain wildcard Subject Alternative Names
                    self.wildcard_certificates
                        .iter()
                        .find(|cert| {
                            cert.metadata
                                .wildcard_matchers
                                .iter()
                                .any(|matcher| matcher.is_match(sni.as_bytes()))
                        })
                        .map(|cert| cert.key.clone())
                        // Finally, if still not found, we serve the default certificate
                        .unwrap_or(self.default_certificate.key.clone())
                }
            };

            // we only support TLS 1.3
            // TLS 1.3 was introduced in 2018 and is supported by virtually all browsers
            // and client libraries: https://caniuse.com/tls1-3
            // Only unmaintained bots don't support TLS 1.3
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(key)
        };

        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        // tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        return Arc::new(tls_config);
    }
}

async fn load_certificates(
    directory_path: &str,
) -> Result<(DashMap<String, Arc<Certificate>>, Vec<Arc<Certificate>>), Error> {
    let mut directory = fs::read_dir(directory_path)
        .await
        .map_err(|err| Error::Config(format!("error reading certificates folder ({directory_path}): {err}")))?;

    // list certs
    let mut certificate_paths = Vec::new();
    while let Ok(Some(entry)) = directory.next_entry().await {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .await
            .map_err(|err| Error::Config(format!("error getting file type for {path:?}: {err}")))?;
        if !file_type.is_file() {
            continue;
        }

        let file_extension = path.extension().unwrap_or_default().to_str().unwrap_or_default();
        // we expect that all .pem files are certificates
        if file_extension == "pem" && path.file_name().unwrap_or_default().to_str().unwrap_or_default() != "default" {
            certificate_paths.push(path);
        }
    }

    let certificates = DashMap::with_capacity(certificate_paths.len());
    let mut wildcard_certificates = Vec::new();
    for cert_file_path in certificate_paths {
        let certificate = Arc::new(load_certificate(&cert_file_path).await?);

        for hostname in &certificate.metadata.hostnames {
            if certificates.contains_key(hostname) {
                warn!("duplicate TLS certificate found for {hostname}");
            }
            certificates.insert(hostname.clone(), certificate.clone());
        }
        if certificate.metadata.wildcard_matchers.len() != 0 {
            wildcard_certificates.push(certificate.clone());
        }
    }

    return Ok((certificates, wildcard_certificates));
}

async fn load_certificate(cert_file_path: &PathBuf) -> Result<Certificate, Error> {
    let cert_file_content = fs::read(cert_file_path)
        .await
        .map_err(|err| Error::Config(format!("error reading certificate {cert_file_path:?}: {err}")))?;

    let mut private_key_path = cert_file_path.clone();
    private_key_path.set_extension("key");
    let private_key_file_content = fs::read(&private_key_path)
        .await
        .map_err(|err| Error::Config(format!("error reading private key {private_key_path:?}: {err}")))?;

    return parse_certificate_and_private_key(
        &cert_file_content,
        &private_key_file_content,
        CryptoProvider::get_default().unwrap(),
    );
}

async fn load_or_create_default_certificate(mut certs_dir: PathBuf) -> Result<Certificate, Error> {
    certs_dir.push("default.pem");
    let mut default_cert_path = certs_dir;

    let default_cert = match fs::metadata(&default_cert_path).await {
        Ok(_) => load_certificate(&default_cert_path).await,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let (default_certificate, pem) = generate_self_signed_certificates(&["*"])?;

            // save certificate and private key
            fs::write(&default_cert_path, pem.cert.as_bytes())
                .await
                .map_err(|err| {
                    Error::Tls(format!("error writing default TLS certificate to {default_cert_path:?}: {err}"))
                })?;

            default_cert_path.set_extension("key");
            fs::write(&default_cert_path, pem.key.as_bytes()).await.map_err(|err| {
                Error::Tls(format!(
                    "error writing private key for default TLS certificate to {default_cert_path:?}: {err}"
                ))
            })?;

            Ok(default_certificate)
        }
        Err(err) => Err(Error::Tls(format!(
            "error loading default certificate {default_cert_path:?}: {err}"
        ))),
    }?;

    if default_cert.metadata.hostnames.len() != 0
        || default_cert.metadata.wildcard_matchers.len() != 1
        || default_cert.metadata.wildcard_matchers[0].pattern() != b"*"
    {
        return Err(Error::Tls("default TLS certificate is not valid".to_string()));
    }

    return Ok(default_cert);
}
