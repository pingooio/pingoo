use std::{sync::Arc, time::Duration};

use aws_lc_rs::signature;
use base64::Engine;
use chrono::Utc;
use thiserror::Error;

use super::rsa_jwks_provider::RsaJwksProvider;

// Re-export types from jwt crate to avoid duplication
pub use jwt::{Header as JwtHeader, RegisteredClaims};

// Extended claims for OAuth/OIDC that include user profile information
// These extend the standard RegisteredClaims from RFC 7519
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtClaims {
    // Standard registered claims (flatten to include all fields at root level)
    #[serde(flatten)]
    pub registered: RegisteredClaims,

    // OpenID Connect standard claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Token expired")]
    Expired,
    #[error("Token not yet valid (nbf)")]
    NotYetValid,
    #[error("Invalid issuer: expected one of {expected:?}, got {actual}")]
    InvalidIssuer { expected: Vec<String>, actual: String },
    #[error("Invalid audience: expected one of {expected:?}, got {actual}")]
    InvalidAudience { expected: Vec<String>, actual: String },
    #[error("Missing required claim: {0}")]
    MissingClaim(String),
    #[error("JWKS error: {0}")]
    Jwks(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

pub struct ValidationConfig {
    pub allowed_issuers: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub clock_skew: Duration,
    pub require_exp: bool,
    pub require_nbf: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            allowed_issuers: Vec::new(),
            allowed_audiences: Vec::new(),
            clock_skew: Duration::from_secs(300),
            require_exp: true,
            require_nbf: false,
        }
    }
}

pub struct JwtValidator {
    jwks_provider: Arc<RsaJwksProvider>,
    config: ValidationConfig,
}

impl JwtValidator {
    pub fn new(jwks_provider: Arc<RsaJwksProvider>, config: ValidationConfig) -> Self {
        Self {
            jwks_provider,
            config,
        }
    }

    pub async fn validate(&self, token: &str) -> Result<JwtClaims, ValidationError> {
        let mut parts = token.split('.');

        let header_b64 = parts.next().ok_or(ValidationError::InvalidFormat)?;
        let claims_b64 = parts.next().ok_or(ValidationError::InvalidFormat)?;
        let signature_b64 = parts.next().ok_or(ValidationError::InvalidFormat)?;

        if parts.next().is_some() {
            return Err(ValidationError::InvalidFormat);
        }

        let header = self.parse_header(header_b64)?;
        let claims = self.parse_claims(claims_b64)?;

        self.verify_signature(&header, header_b64, claims_b64, signature_b64)
            .await?;

        self.validate_claims(&claims)?;

        Ok(claims)
    }

    fn parse_header(&self, header_b64: &str) -> Result<JwtHeader, ValidationError> {
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| ValidationError::InvalidFormat)?;

        serde_json::from_slice(&header_bytes).map_err(|_| ValidationError::InvalidFormat)
    }

    fn parse_claims(&self, claims_b64: &str) -> Result<JwtClaims, ValidationError> {
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|_| ValidationError::InvalidFormat)?;

        serde_json::from_slice(&claims_bytes).map_err(|_| ValidationError::InvalidFormat)
    }

    async fn verify_signature(
        &self,
        header: &JwtHeader,
        header_b64: &str,
        claims_b64: &str,
        signature_b64: &str,
    ) -> Result<(), ValidationError> {
        // Only RS256 is supported for JWKS-based validation
        if header.alg != jwt::Algorithm::RS256 {
            return Err(ValidationError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
        }

        println!("{:?}", claims_b64);

        let kid = header
            .kid
            .as_ref()
            .ok_or_else(|| ValidationError::MissingClaim("kid".to_string()))?;

        let public_key = self
            .jwks_provider
            .get_key(kid)
            .await
            .map_err(|e| ValidationError::Jwks(e.to_string()))?;

        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| ValidationError::InvalidSignature)?;

        let signed_data = format!("{}.{}", header_b64, claims_b64);

        let public_key_components = signature::RsaPublicKeyComponents {
            n: &public_key.n,
            e: &public_key.e,
        };

        public_key_components
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, signed_data.as_bytes(), &signature_bytes)
            .map_err(|_| ValidationError::InvalidSignature)?;

        Ok(())
    }

    fn validate_claims(&self, claims: &JwtClaims) -> Result<(), ValidationError> {
        let now = Utc::now().timestamp();

        // Validate expiration
        if self.config.require_exp {
            let exp = claims.registered.exp.ok_or_else(|| ValidationError::MissingClaim("exp".to_string()))?;

            if now > exp + self.config.clock_skew.as_secs() as i64 {
                return Err(ValidationError::Expired);
            }
        }

        // Validate not-before
        if self.config.require_nbf {
            let nbf = claims.registered.nbf.ok_or_else(|| ValidationError::MissingClaim("nbf".to_string()))?;

            if now < nbf - self.config.clock_skew.as_secs() as i64 {
                return Err(ValidationError::NotYetValid);
            }
        }

        // Validate issuer
        if !self.config.allowed_issuers.is_empty() {
            let issuer = claims
                .registered
                .iss
                .as_ref()
                .ok_or_else(|| ValidationError::MissingClaim("iss".to_string()))?;

            if !self.config.allowed_issuers.contains(issuer) {
                return Err(ValidationError::InvalidIssuer {
                    expected: self.config.allowed_issuers.clone(),
                    actual: issuer.clone(),
                });
            }
        }

        // Validate audience
        if !self.config.allowed_audiences.is_empty() {
            let audience = claims
                .registered
                .aud
                .as_ref()
                .ok_or_else(|| ValidationError::MissingClaim("aud".to_string()))?;

            if !self.config.allowed_audiences.contains(audience) {
                return Err(ValidationError::InvalidAudience {
                    expected: self.config.allowed_audiences.clone(),
                    actual: audience.clone(),
                });
            }
        }

        Ok(())
    }
}
