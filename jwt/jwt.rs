use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

mod base64_utils;
mod jwk;
mod key;

pub use jwk::*;
pub use key::*;

const SIGNATURE_MAX_SIZE: usize = 132;

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
    #[error("JWSignatureT is not valid")]
    InvalidSignature,
    #[error("{0} is not a valid elliptic curve")]
    InvalidEllipticCurve(String),
    #[error("{kid} is not a valid JWK: {err}")]
    InvalidJwk { kid: String, err: String },
    #[error("{0}")]
    Unspecified(String),
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

#[derive(Debug, Default, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum TokenType {
    #[default]
    JWT,
}

/// The algorithms supported for signing / verifying JWTs
#[derive(Copy, Debug, Default, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-512
    HS512,

    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    #[default]
    EdDSA,

    /// ECDSA using P-256 and SHA-256
    ES256,

    /// ECDSA using P-521 and SHA-512
    ES512,
}

#[derive(Debug, Clone)]
pub struct ParsedJwt<C: DeserializeOwned> {
    pub header: Header,
    pub claims: C,
}

impl Algorithm {
    pub fn signature_size(&self) -> usize {
        match self {
            Algorithm::HS512 | Algorithm::EdDSA | Algorithm::ES256 => 64,
            Algorithm::ES512 => 132,
        }
    }
}

pub fn sign<C: Serialize>(key: &Key, header: &Header, claims: &C) -> Result<String, Error> {
    let header_base64 =
        base64::encode_with_alphabet(serde_json::to_string(header)?.as_bytes(), base64::Alphabet::UrlNoPadding);
    let claims_base64 =
        base64::encode_with_alphabet(serde_json::to_string(claims)?.as_bytes(), base64::Alphabet::UrlNoPadding);

    let mut jwt = String::with_capacity(
        header_base64.len()
            + claims_base64.len()
            + base64::encoded_len(key.algorithm.signature_size(), false).expect("error getting base64 encoding length")
            + 2,
    );
    jwt.push_str(&header_base64);
    jwt.push('.');
    jwt.push_str(&claims_base64);

    let signature = key.sign(jwt.as_bytes())?;
    jwt.push('.');
    jwt.push_str(&base64::encode_with_alphabet(
        signature.as_ref(),
        base64::Alphabet::UrlNoPadding,
    ));

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
    key: &Key,
    token: &str,
    valdiate_options: &ValidateOptions,
) -> Result<ParsedJwt<C>, Error> {
    let mut signature_buffer = [0u8; SIGNATURE_MAX_SIZE];
    let mut parts = token.split('.');

    let header_base64 = parts.next().ok_or(Error::InvalidToken)?;
    let claims_base64 = parts.next().ok_or(Error::InvalidToken)?;
    let signature_base64 = parts.next().ok_or(Error::InvalidToken)?;
    if parts.next().is_some() {
        return Err(Error::InvalidToken);
    }

    let signature_size = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(signature_base64.as_bytes(), &mut signature_buffer)
        .map_err(|_| Error::InvalidSignature)?;
    let raw_signature = &signature_buffer[..signature_size];

    let signed_message = &token[..header_base64.len() + 1 + claims_base64.len()].as_bytes();
    key.verify(signed_message, &raw_signature)?;

    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_base64.as_bytes())
        .map_err(|_| Error::InvalidToken)?;
    let header: Header = serde_json::from_slice(&header_json).map_err(|_| Error::InvalidToken)?;
    if header.alg != key.algorithm {
        return Err(Error::InvalidToken);
    }

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

    return Ok(ParsedJwt { header, claims });
}
