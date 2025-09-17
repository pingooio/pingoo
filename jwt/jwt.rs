use core::fmt;
use std::{str::FromStr, time::Duration};

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

mod base64_utils;
mod jwk;

pub use jwk::*;

pub const ED25519_SIGNATURE_SIZE: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("jwt: invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("jwt: invalid token type: {0}")]
    InvalidTokenType(String),
    #[error("error encoding JWT to JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWT is not valid")]
    InvalidToken,
    #[error("{0} is not a valid elliptic curve")]
    InvalidEllipticCurve(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The only valid value is "JWT"
    /// https://tools.ietf.org/html/rfc7519#section-5.1
    pub typ: TokenType,

    /// ttps://tools.ietf.org/html/rfc7515#section-4.1.1
    pub alg: Algorithm,

    /// Content type
    /// https://tools.ietf.org/html/rfc7519#section-5.2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    /// JSON Key URL
    /// https://tools.ietf.org/html/rfc7515#section-4.1.2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// JSON Web Key
    /// https://tools.ietf.org/html/rfc7515#section-4.1.3
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub jwk: Option<Jwk>,

    /// Key ID
    /// https://tools.ietf.org/html/rfc7515#section-4.1.4
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL
    /// https://tools.ietf.org/html/rfc7515#section-4.1.5
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 certificate chain.
    /// https://tools.ietf.org/html/rfc7515#section-4.1.6
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 SHA1 certificate Thumbprint
    /// https://tools.ietf.org/html/rfc7515#section-4.1.7
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 SHA256 certificate Thumbprint
    /// https://tools.ietf.org/html/rfc7515#section-4.1.8
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
}

/// Registered claim names from https://www.rfc-editor.org/rfc/rfc7519#section-4.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct RegisteredClaims {
    /// Issuer
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration Time
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Not Before
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Issued At
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// JWT ID
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

pub struct ValidateOptions<'a> {
    pub allowed_time_drift: Duration,
    pub nbf: bool,
    pub exp: bool,
    pub aud: &'a [&'a str],
    pub iss: &'a [&'a str],
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum TokenType {
    #[default]
    Jwt,
}

/// The algorithms supported for signing / verifying JWTs
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-512
    // #[default]
    // HS512,

    /// ECDSA using SHA-256
    // ES256,

    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    #[default]
    EdDSA,
}

#[derive(Debug, Clone)]
pub struct ParsedJwt<C: DeserializeOwned> {
    pub header: Header,
    pub claims: C,
    pub signature: [u8; ED25519_SIGNATURE_SIZE],
}

pub fn sign<C: Serialize>(key: &Ed25519KeyPair, header: &Header, claims: &C) -> Result<String, Error> {
    let mut jwt = String::with_capacity(100);

    jwt.push_str(&base64::encode_with_alphabet(
        serde_json::to_string(header)?.as_bytes(),
        base64::Alphabet::UrlNoPadding,
    ));
    jwt.push('.');
    jwt.push_str(&base64::encode_with_alphabet(
        serde_json::to_string(claims)?.as_bytes(),
        base64::Alphabet::UrlNoPadding,
    ));

    let signature = key.sign(jwt.as_bytes());
    let signature_base64 = base64::encode_with_alphabet(signature.as_ref(), base64::Alphabet::UrlNoPadding);

    jwt.push('.');
    jwt.push_str(&signature_base64);

    return Ok(jwt);
}

pub fn parse_header(token: &str) -> Result<Header, Error> {
    let mut parts = token.split('.');
    let header_base64 = parts.next().ok_or(Error::InvalidToken)?;
    if parts.count() != 2 {
        return Err(Error::InvalidToken);
    }

    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_base64.as_bytes())
        .map_err(|_| Error::InvalidToken)?;
    let header: Header = serde_json::from_slice(&header_json).map_err(|_| Error::InvalidToken)?;

    return Ok(header);
}

pub fn parse_and_verify<C: DeserializeOwned>(
    key: &Ed25519KeyPair,
    token: &str,
    valdiate_options: &ValidateOptions,
) -> Result<ParsedJwt<C>, Error> {
    let mut parts = token.split('.');

    let header_base64 = parts.next().ok_or(Error::InvalidToken)?;
    let claims_base64 = parts.next().ok_or(Error::InvalidToken)?;
    let signature_base64 = parts.next().ok_or(Error::InvalidToken)?;
    if parts.next().is_some() {
        return Err(Error::InvalidToken);
    }

    let mut raw_signature = [0u8; ED25519_SIGNATURE_SIZE];

    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(signature_base64.as_bytes(), &mut raw_signature)
        .map_err(|_| Error::InvalidToken)?;

    let signed_message = &token[..header_base64.len() + 1 + claims_base64.len()];
    let public_key = aws_lc_rs::signature::ParsedPublicKey::new(&ED25519, key.public_key().as_ref())
        .expect("error getting public key");
    public_key
        .verify_sig(signed_message.as_bytes(), &raw_signature)
        .map_err(|_| Error::InvalidToken)?;

    // TODO: validate header.
    // as of now, it's already validate by parsing, but if we start to accept more signing algorithms
    // we will need to defend against algorithm confusion attacks
    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_base64.as_bytes())
        .map_err(|_| Error::InvalidToken)?;
    let header: Header = serde_json::from_slice(&header_json).map_err(|_| Error::InvalidToken)?;

    let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_base64.as_bytes())
        .map_err(|_| Error::InvalidToken)?;

    let claims = if valdiate_options.exp
        || valdiate_options.nbf
        || valdiate_options.aud.len() != 0
        || valdiate_options.iss.len() != 0
    {
        let claims_json_value: serde_json::Value =
            serde_json::from_slice(&claims_json).map_err(|_| Error::InvalidToken)?;

        match &claims_json_value {
            serde_json::Value::Object(claims_object) => {
                if valdiate_options.exp {
                    match claims_object.get("exp") {
                        None => return Err(Error::InvalidToken),
                        Some(exp_value) => {
                            if let Some(exp) = exp_value.as_i64() {
                                if exp < (Utc::now() - valdiate_options.allowed_time_drift).timestamp() {
                                    return Err(Error::InvalidToken);
                                }
                            } else {
                                return Err(Error::InvalidToken);
                            }
                        }
                    }
                }

                if valdiate_options.nbf {
                    match claims_object.get("nbf") {
                        None => return Err(Error::InvalidToken),
                        Some(nbf_value) => {
                            if let Some(nbf) = nbf_value.as_i64() {
                                if nbf > (Utc::now() + valdiate_options.allowed_time_drift).timestamp() {
                                    return Err(Error::InvalidToken);
                                }
                            } else {
                                return Err(Error::InvalidToken);
                            }
                        }
                    }
                }

                if !valdiate_options.aud.is_empty() {
                    match claims_object.get("aud") {
                        None => return Err(Error::InvalidToken),
                        Some(aud_value) => {
                            if let Some(aud) = aud_value.as_str() {
                                if !valdiate_options.aud.contains(&aud) {
                                    return Err(Error::InvalidToken);
                                }
                            } else {
                                return Err(Error::InvalidToken);
                            }
                        }
                    }
                }

                if !valdiate_options.iss.is_empty() {
                    match claims_object.get("iss") {
                        None => return Err(Error::InvalidToken),
                        Some(iss_value) => {
                            if let Some(iss) = iss_value.as_str() {
                                if !valdiate_options.iss.contains(&iss) {
                                    return Err(Error::InvalidToken);
                                }
                            } else {
                                return Err(Error::InvalidToken);
                            }
                        }
                    }
                }
            }
            _ => return Err(Error::InvalidToken),
        };

        serde_json::from_value(claims_json_value).map_err(|_| Error::InvalidToken)?
    } else {
        serde_json::from_slice(&claims_json).map_err(|_| Error::InvalidToken)?
    };

    return Ok(ParsedJwt {
        header,
        claims,
        signature: raw_signature,
    });
}

impl FromStr for TokenType {
    type Err = Error;

    fn from_str(algo: &str) -> Result<Self, Self::Err> {
        match algo {
            "JWT" => Ok(TokenType::Jwt),
            _ => Err(Error::InvalidTokenType(algo.to_string())),
        }
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(algo: &str) -> Result<Self, Self::Err> {
        match algo {
            // "HS512" => Ok(Algorithm::HS512),
            // "PS256" => Ok(Algorithm::PS256),
            "EdDSA" => Ok(Algorithm::EdDSA),
            _ => Err(Error::InvalidAlgorithm(algo.to_string())),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Algorithm::EdDSA => "EdDSA",
        };
        write!(f, "{value}")
    }
}
