use std::{path::PathBuf, sync::Arc, time::Duration};

use chrono::Utc;
use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy};
use rcgen::{CustomExtension, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    server::ClientHello,
    sign::{CertifiedKey, SingleCertAndKey},
};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{debug, error, info};

use crate::{
    Error,
    config::DEFAULT_TLS_FOLDER,
    tls::{TlsManager, certificate::parse_certificate_and_private_key},
};

pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";
pub const LETSENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
// const LETSENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Serialize, Deserialize)]
pub struct AcmeConfig {
    pub account: instant_acme::AccountCredentials,
}

impl TlsManager {
    pub fn start_acme_in_background(self: Arc<Self>) {
        if self.acme_domains.is_empty() {
            return;
        }

        tokio::spawn(async move {
            loop {
                let in_30_days = Utc::now() + Duration::from_secs(30 * 24 * 3600);
                let domains_to_order: Vec<String> = self
                    .acme_domains
                    .iter()
                    .filter(|&domain| match self.certificates.get(domain) {
                        Some(cert) if cert.metadata.not_after < in_30_days => true,
                        None => true,
                        _ => false,
                    })
                    .map(Clone::clone)
                    .collect();

                for domain in domains_to_order {
                    tokio::spawn({
                        let tls_manager = self.clone();
                        async move {
                            // time for listeners to start
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            let tls_dir: PathBuf = DEFAULT_TLS_FOLDER.into();

                            debug!(domain, "acme: ordering certificate");

                            let (private_key_pem, cert_chain_pem) = match tls_manager.order_certificate(&domain).await {
                                Ok(cert) => cert,
                                Err(err) => {
                                    error!(domain, "TLS: error ordering TLS certificate: {err}");
                                    return;
                                }
                            };

                            debug!(domain, "acme: order successfully completed");

                            // parse certificate and add to cert store
                            let certificate = match parse_certificate_and_private_key(
                                cert_chain_pem.as_bytes(),
                                private_key_pem.as_bytes(),
                                CryptoProvider::get_default().unwrap(),
                            ) {
                                Ok(cert) => cert,
                                Err(err) => {
                                    error!(domain, "error parsing ACME certificate: {err}");
                                    return;
                                }
                            };
                            tls_manager.certificates.insert(domain.clone(), Arc::new(certificate));

                            // save private key and certificate chain
                            let mut private_key_path = tls_dir.clone();
                            private_key_path.push(format!("{domain}.key"));
                            if let Err(err) = fs::write(private_key_path, private_key_pem.as_bytes()).await {
                                error!(domain, "TLS: error saving ACME TLS private key: {err}");
                                return;
                            };

                            let mut cert_chain_path = tls_dir;
                            cert_chain_path.push(format!("{domain}.pem"));
                            if let Err(err) = fs::write(cert_chain_path, cert_chain_pem.as_bytes()).await {
                                error!(domain, "TLS: error saving ACME TLS certificate chain: {err}");
                                return;
                            };

                            info!(domain, "acme: TLS certificate successfully saved");
                        }
                    });
                }

                // sleep for 12 hours
                tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
            }
        });
    }

    pub async fn order_certificate(&self, domain: &str) -> Result<(String, String), Error> {
        let mut order = self
            .acme_account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
            .await
            .map_err(|err| Error::Unspecified(format!("error placing ACME order for {domain}: {err}")))?;

        let mut authorizations = order.authorizations();

        let mut authorization = authorizations
            .next()
            .await
            .ok_or(Error::Unspecified(format!("ACME authorizations is empty for {domain}")))?
            .map_err(|err| Error::Unspecified(format!("error getting ACME authorization for {domain}: {err}")))?;
        if !matches!(authorization.status, AuthorizationStatus::Pending | AuthorizationStatus::Valid) {
            return Err(Error::Unspecified(format!(
                "unexpected ACME order status for {domain} (status: {:?})",
                authorization.status
            )));
        }

        let mut challenge = authorization
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or(Error::Unspecified("tls-alpn-01 challenge not found".to_string()))?;

        self.acme_authorizations
            .insert(domain.to_string(), challenge.key_authorization());

        challenge
            .set_ready()
            .await
            .map_err(|err| Error::Unspecified(format!("error setting ACME challenge as ready for {domain}: {err}")))?;

        debug!(domain, "acme: challenge ready. waiting for server verification");

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|err| Error::Unspecified(format!("error polling ACME challenge for {domain}: {err}")))?;
        if status != OrderStatus::Ready {
            return Err(Error::Unspecified(format!(
                "unexpected ACME order status for {domain} (status: {status:?})"
            )));
        }

        let private_key_pem = order.finalize().await.map_err(|err| {
            Error::Unspecified(format!("error getting private key for ACME order for {domain}: {err}"))
        })?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await.map_err(|err| {
            Error::Unspecified(format!("error getting certificate chain for ACME order for {domain}: {err}"))
        })?;

        self.acme_authorizations.remove(domain);

        return Ok((private_key_pem, cert_chain_pem));
    }

    pub async fn get_tls_alpn_01_server_config(&self, client_hello: &ClientHello<'_>) -> Arc<ServerConfig> {
        match self.get_tls_alpn_01_cert(&client_hello).await {
            Ok(certified_key) => {
                let mut tls_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::new(certified_key))));
                tls_config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
                Arc::new(tls_config)
            }
            Err(err) => {
                error!("acme: error getting tls-alpn-01 certificate: {err}");
                self.get_server_config(client_hello).await
            }
        }
    }

    async fn get_tls_alpn_01_cert(&self, client_hello: &ClientHello<'_>) -> Result<CertifiedKey, Error> {
        let domain = client_hello.server_name().unwrap_or_default();
        debug!(domain = domain, "acme: got tls-alpn-01 request");

        let key_auth = self
            .acme_authorizations
            .get(domain)
            .ok_or(Error::Unspecified(format!("key authorization not found for {domain}")))?;
        debug!(domain = domain, "acme: key authorization found");

        let mut cert_params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|err| Error::Unspecified(format!("error creating certificate for {domain}: {err}")))?;

        cert_params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.digest().as_ref())];

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|err| Error::Unspecified(format!("error generating keypair for {domain}: {err}")))?;
        let cert = cert_params.self_signed(&key_pair).map_err(|err| {
            Error::Unspecified(format!("error generating self-signed certificate for {domain}: {err}"))
        })?;

        let signing_key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        ))
        .map_err(|err| Error::Unspecified(format!("error creating SigningKey for {domain}: {err}")))?;
        let certified_key = CertifiedKey::new(vec![cert.der().clone()], signing_key);

        return Ok(certified_key);
    }
}

pub(super) async fn load_or_create_acme_account(
    tls_folder_path: &str,
    acme_directory_url: String,
) -> Result<instant_acme::Account, Error> {
    let mut acme_config_path: PathBuf = tls_folder_path.into();
    acme_config_path.push("acme.json");

    match fs::read(&acme_config_path).await {
        Ok(acme_config_file_content) => {
            let acme_config: AcmeConfig = serde_json::from_slice(&acme_config_file_content)
                .map_err(|err| Error::Unspecified(format!("error reading acme.json file: {err}")))?;
            let acme_account = instant_acme::Account::builder()
                .map_err(|err| Error::Unspecified(format!("error creating ACME account builder: {err}")))?
                .from_credentials(acme_config.account)
                .await
                .map_err(|err| Error::Unspecified(format!("error loading ACME account: {err}")))?;
            return Ok(acme_account);
        }
        Err(_) => {
            let (acme_account, acme_credentials) = instant_acme::Account::builder()
                .map_err(|err| Error::Config(format!("error building ACME client: {err}")))?
                .create(
                    &instant_acme::NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    acme_directory_url.clone(),
                    None,
                )
                .await
                .map_err(|err| Error::Config(format!("error creating ACME account: {err}")))?;
            let acme_config = AcmeConfig {
                account: acme_credentials,
            };
            let acme_config_file_content = serde_json::to_vec_pretty(&acme_config)
                .map_err(|err| Error::Config(format!("error serializing ACME account: {err}")))?;
            fs::write(&acme_config_path, &acme_config_file_content)
                .await
                .map_err(|err| {
                    Error::Config(format!("error saving ACME account credentials to {acme_config_path:?}: {err}"))
                })?;

            return Ok(acme_account);
        }
    };
}

/// Returns `true` if the client_hello indicates a TLS-ALPN-01 challenge connection.
pub fn is_tls_alpn_challenge(client_hello: &ClientHello) -> bool {
    client_hello.alpn().into_iter().flatten().eq([ACME_TLS_ALPN_NAME])
}
