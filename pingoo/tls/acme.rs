use std::{fmt::Debug, path::PathBuf, sync::Arc, time::Duration};

use chrono::Utc;
use dashmap::DashMap;
use indexmap::IndexMap;
use instant_acme::{
    AuthorizationStatus, ChallengeType, Identifier, KeyAuthorization, NewOrder, OrderStatus, RetryPolicy,
};
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
    serde_utils, 
    services::tcp_proxy_service::retry,
    tls::{TLS_ALPN_ACME, TlsManager, certificate::parse_certificate_and_private_key},
};

pub const LETSENCRYPT_PRODUCTION_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
// const LETSENCRYPT_STAGING_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "version", content = "data")]
pub enum AcmeConfig {
    #[serde(rename = "1")]
    V1(AcmeConfigV1),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeConfigV1 {
    pub accounts: IndexMap<String, AcmeAccount>,
}

#[derive(Serialize, Deserialize)]
pub struct AcmeAccount {
    pub id: String,
    #[serde(with = "serde_utils::rustls_private_pkcs_key_der")]
    pub key: PrivatePkcs8KeyDer<'static>,
}

impl Debug for AcmeAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeAccount")
            .field("id", &self.id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

pub(super) struct AcmeChallenge {
    // identifier: String,
    // token: String,
    key_authorization: KeyAuthorization,
}

impl TlsManager {
    pub fn start_acme_in_background(self: &Arc<Self>) {
        let acme_config = match &self.acme {
            Some(acme) => acme.clone(),
            None => return,
        };

        if acme_config.domains.is_empty() {
            debug!("tls: ACME domains are empty. Exiting ACME manager.");
            return;
        }

        debug!("tls: starting ACME manager in background");

        let tls_manager = self.clone();
        tokio::spawn(async move {
            loop {
                let in_30_days = Utc::now() + Duration::from_secs(30 * 24 * 3600);
                let domains_to_order: Vec<String> = acme_config
                    .domains
                    .iter()
                    .filter(|&domain| {
                        // keep domains that are not yet in the store, or that expire in less than 30 days
                        match tls_manager.certificates.get(domain) {
                            Some(cert) if cert.metadata.not_after < in_30_days => true,
                            None => true,
                            _ => false,
                        }
                    })
                    .map(Clone::clone)
                    .collect();

                for domain in domains_to_order {
                    tokio::spawn({
                        let tls_manager = tls_manager.clone();
                        let acme_config = acme_config.clone();
                        async move {
                            // time for listeners to start
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            let tls_dir: PathBuf = DEFAULT_TLS_FOLDER.into();
                            let domain = &domain;

                            debug!(domain, "tls: ordering ACME certificate");

                            let (private_key_pem, cert_chain_pem) =
                                match order_certificate(&acme_config.account, &acme_config.challenges, &domain).await {
                                    Ok(cert) => cert,
                                    Err(err) => {
                                        error!(domain, "TLS: error ordering TLS certificate: {err}");
                                        return;
                                    }
                                };
                            let private_key_pem = private_key_pem.as_bytes();
                            let cert_chain_pem = cert_chain_pem.as_bytes();

                            debug!(domain, "tls: ACME order successfully completed");

                            // parse certificate and add to cert store
                            let certificate = match parse_certificate_and_private_key(
                                cert_chain_pem,
                                private_key_pem,
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
                            if let Err(err) = retry(
                                || {
                                    let tls_dir = tls_dir.clone();
                                    async move {
                                        let mut private_key_path = tls_dir.clone();
                                        private_key_path.push(format!("{domain}.key"));
                                        fs::write(&private_key_path, private_key_pem).await.map_err(|err| {
                                            Error::Unspecified(format!(
                                                "error writing private key to {private_key_path:?}: {err}"
                                            ))
                                        })?;

                                        let mut cert_chain_path = tls_dir;
                                        cert_chain_path.push(format!("{domain}.pem"));
                                        fs::write(&cert_chain_path, cert_chain_pem).await.map_err(|err| {
                                            Error::Unspecified(format!(
                                                "tls: error writing ACME certificate to {cert_chain_path:?}: {err}"
                                            ))
                                        })?;

                                        Ok(())
                                    }
                                },
                                5,
                                Duration::from_secs(5),
                            )
                            .await
                            {
                                error!(domain, "tls: error saving ACME TLS certificate: {err}");
                                return;
                            }
                            info!(domain, "tls: ACME TLS certificate successfully saved");
                        }
                    });
                }

                // sleep for 6 hours
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
            }
        });
    }

    pub async fn get_tls_alpn_01_server_config(self: &Arc<Self>, client_hello: &ClientHello<'_>) -> Arc<ServerConfig> {
        let acme = match &self.acme {
            Some(acme) => acme.clone(),
            None => {
                debug!("tls: got tls-alpn-01 request but ACME config is empty");
                return self.get_tls_server_config([]);
            }
        };

        match get_tls_alpn_01_cert(&acme.challenges, &client_hello).await {
            Ok(certified_key) => {
                let mut tls_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::new(certified_key))));
                // make sure to specify the ACME tls-alpn-01 ALPN protocol
                tls_config.alpn_protocols.push(TLS_ALPN_ACME.to_vec());
                Arc::new(tls_config)
            }
            Err(err) => {
                error!("tls: error getting tls-alpn-01 certificate: {err}");
                self.get_tls_server_config([])
            }
        }
    }
}

/// Generates a self-signed certificate to answer the tls-alpn-01 challenge as specified in
/// [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737).
async fn get_tls_alpn_01_cert(
    challenges_store: &DashMap<String, AcmeChallenge>,
    client_hello: &ClientHello<'_>,
) -> Result<CertifiedKey, Error> {
    let domain = client_hello.server_name().unwrap_or_default();
    debug!(domain, "tls: got tls-alpn-01 request");

    let challenge = challenges_store
        .get(domain)
        .ok_or(Error::Unspecified(format!("ACME challenge not found for {domain}")))?;
    debug!(domain, "tls: ACME challenge found for tls-alpn-01 request");

    // create the self-signed certificate with the ACME TLS-ALPN-01 extension
    let mut cert_params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|err| Error::Unspecified(format!("error creating certificate for {domain}: {err}")))?;
    cert_params.custom_extensions = vec![CustomExtension::new_acme_identifier(
        challenge.key_authorization.digest().as_ref(),
    )];

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|err| Error::Unspecified(format!("error generating keypair for {domain}: {err}")))?;

    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|err| Error::Unspecified(format!("error generating self-signed certificate for {domain}: {err}")))?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        key_pair.serialize_der(),
    )))
    .map_err(|err| Error::Unspecified(format!("error creating SigningKey for {domain}: {err}")))?;

    let certified_key = CertifiedKey::new(vec![cert.der().clone()], signing_key);

    return Ok(certified_key);
}

/// Place an order for a TLS certificate to the given ACME directory.
async fn order_certificate(
    acme_account: &instant_acme::Account,
    challenges_store: &DashMap<String, AcmeChallenge>,
    domain: &str,
) -> Result<(String, String), Error> {
    let mut order = acme_account
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

    let acme_challenge = AcmeChallenge {
        key_authorization: challenge.key_authorization(),
    };
    challenges_store.insert(domain.to_string(), acme_challenge);

    challenge
        .set_ready()
        .await
        .map_err(|err| Error::Unspecified(format!("error setting ACME challenge as ready for {domain}: {err}")))?;

    debug!(domain, "tls: ACME challenge ready. Waiting for server verification");

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|err| Error::Unspecified(format!("error polling ACME challenge for {domain}: {err}")))?;
    if status != OrderStatus::Ready {
        return Err(Error::Unspecified(format!(
            "unexpected ACME order status for {domain} (status: {status:?})"
        )));
    }

    let private_key_pem = order
        .finalize()
        .await
        .map_err(|err| Error::Unspecified(format!("error getting private key for ACME order for {domain}: {err}")))?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await.map_err(|err| {
        Error::Unspecified(format!("error getting certificate chain for ACME order for {domain}: {err}"))
    })?;

    challenges_store.remove(domain);

    return Ok((private_key_pem, cert_chain_pem));
}

pub(super) async fn load_or_create_acme_account(
    tls_folder_path: &str,
    acme_directory_url: String,
) -> Result<instant_acme::Account, Error> {
    let mut acme_config_path: PathBuf = tls_folder_path.into();
    acme_config_path.push("acme.json");

    let acme_config: AcmeConfig = match fs::read(&acme_config_path).await {
        Ok(acme_config_file_content) => serde_json::from_slice(&acme_config_file_content)
            .map_err(|err| Error::Unspecified(format!("error reading {acme_config_path:?}: {err}")))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => AcmeConfig::V1(AcmeConfigV1 {
            accounts: IndexMap::new(),
        }),
        Err(err) => {
            return Err(Error::Unspecified(format!(
                "error reading ACME configuration file ({acme_config_path:?}): {err}"
            )));
        }
    };

    match acme_config {
        AcmeConfig::V1(mut acme_config_v1) => {
            // if there is an account for this directory_url, return it.
            if let Some(account) = acme_config_v1.accounts.get(&acme_directory_url) {
                let acme_account = instant_acme::Account::builder()
                    .map_err(|err| Error::Unspecified(format!("error creating ACME account builder: {err}")))?
                    .from_parts(account.id.clone(), account.key.clone_key(), acme_directory_url)
                    .await
                    .map_err(|err| Error::Unspecified(format!("error loading ACME account: {err}")))?;
                return Ok(acme_account);
            } else {
                // otherwise, create a new account and save it
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
                let account = AcmeAccount {
                    id: acme_account.id().to_string(),
                    key: acme_credentials.private_key().clone_key(),
                };
                acme_config_v1.accounts.insert(acme_directory_url, account);

                let acme_config_file_content = serde_json::to_vec_pretty(&AcmeConfig::V1(acme_config_v1))
                    .map_err(|err| Error::Config(format!("error serializing ACME configuration: {err}")))?;
                fs::write(&acme_config_path, &acme_config_file_content)
                    .await
                    .map_err(|err| {
                        Error::Config(format!("error saving ACME configuration file to {acme_config_path:?}: {err}"))
                    })?;

                return Ok(acme_account);
            }
        }
    }
}

/// Returns `true` if the client_hello indicates a TLS-ALPN-01 challenge connection, false otherwise.
pub fn is_tls_alpn_challenge(client_hello: &ClientHello) -> bool {
    client_hello.alpn().into_iter().flatten().eq([TLS_ALPN_ACME])
}
