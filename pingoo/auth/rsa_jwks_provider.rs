use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use aws_lc_rs::signature;
use base64::Engine;
use dashmap::DashMap;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
// Note: The jwt crate provides better JWK types (Jwk, JwkCrypto, Jwks) for general use,
// but this module uses a simplified RSA-only structure for fetching public keys from
// external JWKS endpoints which typically only expose RSA public key parameters (n, e)
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwksError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("JWKS fetch failed: {0}")]
    FetchFailed(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Unsupported key type for RSA validation: {0}")]
    UnsupportedKeyType(String),
}

/// RSA-specific JWK representation for external JWKS endpoints
/// These endpoints typically only expose public keys (n, e)
#[derive(Debug, Clone, Deserialize, Serialize)]
struct RsaJwk {
    kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<RsaJwk>,
}

pub struct CachedKey {
    pub key: signature::RsaPublicKeyComponents<Vec<u8>>,
    pub cached_at: Instant,
}

#[derive(Clone)]
pub struct ProviderConfig {
    pub name: String,
    pub jwks_url: String,
    pub issuer: String,
    pub cache_ttl: Duration,
}

pub struct RsaJwksProvider {
    configs: Vec<ProviderConfig>,
    cache: Arc<DashMap<String, CachedKey>>,
    http_client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Empty<bytes::Bytes>,
    >,
}

impl RsaJwksProvider {
    pub fn new(configs: Vec<ProviderConfig>) -> Self {
        let tls_config =
            rustls::ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
                .with_safe_default_protocol_versions()
                .expect("error setting up TLS versions")
                .with_native_roots()
                .expect("error loading native root certs")
                .with_no_client_auth();

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(hyper_util::client::legacy::connect::HttpConnector::new());

        let http_client = Client::builder(TokioExecutor::new()).build(https_connector);

        Self {
            configs,
            cache: Arc::new(DashMap::new()),
            http_client,
        }
    }

    pub async fn get_key(&self, kid: &str) -> Result<signature::RsaPublicKeyComponents<Vec<u8>>, JwksError> {
        if let Some(cached) = self.cache.get(kid) {
            let config = self.configs.iter().find(|c| cached.cached_at.elapsed() < c.cache_ttl);

            if config.is_some() {
                return Ok(cached.key.clone());
            }
        }

        for config in &self.configs {
            match self.refresh_keys(config).await {
                Ok(_) => {
                    if let Some(cached) = self.cache.get(kid) {
                        return Ok(cached.key.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to refresh keys from {}: {}", config.name, e);
                    continue;
                }
            }
        }

        Err(JwksError::KeyNotFound(kid.to_string()))
    }

    async fn refresh_keys(&self, config: &ProviderConfig) -> Result<(), JwksError> {
        let uri: hyper::Uri = config
            .jwks_url
            .parse()
            .map_err(|e: hyper::http::uri::InvalidUri| JwksError::FetchFailed(format!("Invalid URL: {}", e)))?;

        let req = Request::builder()
            .uri(uri)
            .header("Accept", "application/json")
            .body(Empty::<bytes::Bytes>::new())
            .map_err(|e| JwksError::Http(e.to_string()))?;

        let resp = self
            .http_client
            .request(req)
            .await
            .map_err(|e| JwksError::FetchFailed(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(JwksError::FetchFailed(format!("HTTP {}", status)));
        }

        let body_bytes = resp
            .collect()
            .await
            .map_err(|e| JwksError::FetchFailed(e.to_string()))?
            .to_bytes();

        let jwks: JwksResponse =
            serde_json::from_slice(&body_bytes).map_err(|e| JwksError::FetchFailed(e.to_string()))?;

        let now = Instant::now();

        for jwk in jwks.keys {
            if jwk.kty != "RSA" {
                tracing::debug!("Skipping non-RSA key type: {}", jwk.kty);
                continue;
            }

            // Validate use parameter if present
            if let Some(ref use_val) = jwk.r#use {
                if use_val != "sig" {
                    tracing::debug!("Skipping key {} with use: {}", jwk.kid, use_val);
                    continue;
                }
            }

            // Validate algorithm if present - only support RS256 for now
            if let Some(ref alg) = jwk.alg {
                if alg != "RS256" {
                    tracing::warn!(
                        "Skipping key {} with unsupported algorithm: {} (only RS256 supported)",
                        jwk.kid,
                        alg
                    );
                    continue;
                }
            }

            match self.rsa_jwk_to_key(&jwk) {
                Ok(key) => {
                    self.cache.insert(jwk.kid.clone(), CachedKey { key, cached_at: now });
                }
                Err(e) => {
                    tracing::warn!("Invalid JWK {}: {}", jwk.kid, e);
                }
            }
        }

        Ok(())
    }

    fn rsa_jwk_to_key(&self, jwk: &RsaJwk) -> Result<signature::RsaPublicKeyComponents<Vec<u8>>, JwksError> {
        let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&jwk.n)
            .map_err(|e| JwksError::InvalidKey(format!("Invalid n parameter: {}", e)))?;

        let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&jwk.e)
            .map_err(|e| JwksError::InvalidKey(format!("Invalid e parameter: {}", e)))?;

        // Validate RSA key size (minimum 2048 bits)
        let key_bits = n_bytes.len() * 8;
        if key_bits < 2048 {
            return Err(JwksError::InvalidKey(format!(
                "RSA key too small: {} bits (minimum 2048 required)",
                key_bits
            )));
        }

        Ok(signature::RsaPublicKeyComponents { n: n_bytes, e: e_bytes })
    }

    pub fn invalidate_cache(&self) {
        self.cache.clear();
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl ProviderConfig {
    pub fn google() -> Self {
        Self {
            name: "Google".to_string(),
            jwks_url: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
            issuer: "https://accounts.google.com".to_string(),
            cache_ttl: Duration::from_secs(3600),
        }
    }

    pub fn github() -> Self {
        Self {
            name: "GitHub".to_string(),
            jwks_url: "https://github.com/login/oauth/.well-known/jwks".to_string(),
            issuer: "https://github.com".to_string(),
            cache_ttl: Duration::from_secs(3600),
        }
    }
}
