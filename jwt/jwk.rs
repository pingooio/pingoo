use aws_lc_rs::{encoding::AsBigEndian, signature::KeyPair};
use serde::{Deserialize, Serialize};

use crate::{Algorithm, Key, base64_utils::Base64UrlNoPaddingBytes};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// a JSON Web Key
/// https://www.rfc-editor.org/rfc/rfc7517
/// https://www.rfc-editor.org/rfc/rfc8037
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub r#use: KeyUse,
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    #[serde(flatten)]
    pub crypto: JwkCrypto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE", tag = "kty")]
pub enum JwkCrypto {
    Okp {
        #[serde(rename = "crv")]
        curve: OkpCurve,
        /// base64UrlNoPadding encoded public key
        // #[serde(with = "base64_url_no_padding")]
        x: Base64UrlNoPaddingBytes,
        d: Option<Base64UrlNoPaddingBytes>,
    },
    Ec {
        #[serde(rename = "crv")]
        curve: EcCurve,
        x: Base64UrlNoPaddingBytes,
        y: Base64UrlNoPaddingBytes,
        d: Option<Base64UrlNoPaddingBytes>,
    },
}

#[derive(Copy, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Sign,
    #[serde(rename = "enc")]
    Encrypt,
}

// https://csrc.nist.gov/pubs/fips/186-5/final
// https://csrc.nist.gov/pubs/sp/800/186/final
// https://www.rfc-editor.org/rfc/rfc8032
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum OkpCurve {
    Ed25519,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum EcCurve {
    /// P-256 and SHA-256
    #[serde(rename = "P-256")]
    P256,

    /// P-521 and SHA-512
    #[serde(rename = "P-521")]
    P521,
}

impl From<&Key> for Jwk {
    fn from(key: &Key) -> Self {
        match &key.crypto {
            crate::KeyCrypto::Eddsa { curve, keypair } => {
                let public_key = keypair.public_key().as_ref().to_vec();
                let private_key = keypair
                    .seed()
                    .expect("error getting seed")
                    .as_be_bytes()
                    .expect("error converting Ed25519 seed to bytes")
                    .as_ref()
                    .to_vec();
                Jwk {
                    kid: key.id.clone(),
                    r#use: KeyUse::Sign,
                    algorithm: Algorithm::EdDSA,
                    crypto: JwkCrypto::Okp {
                        curve: *curve,
                        x: Base64UrlNoPaddingBytes(public_key),
                        d: Some(Base64UrlNoPaddingBytes(private_key)),
                    },
                }
            }
            crate::KeyCrypto::Ecdsa { curve, keypair } => {
                let public_key = keypair.public_key().as_ref();
                let private_key = keypair
                    .private_key()
                    .as_be_bytes()
                    .expect("error converting EcDsa seed to bytes")
                    .as_ref()
                    .to_vec();
                let algorithm = match curve {
                    EcCurve::P256 => Algorithm::ES256,
                    EcCurve::P521 => Algorithm::ES512,
                };
                let (x, y) = match curve {
                    EcCurve::P256 => (public_key[..32].to_vec(), public_key[32..].to_vec()),
                    EcCurve::P521 => (public_key[..66].to_vec(), public_key[66..].to_vec()),
                };
                Jwk {
                    kid: key.id.clone(),
                    r#use: KeyUse::Sign,
                    algorithm,
                    crypto: JwkCrypto::Ec {
                        curve: *curve,
                        x: Base64UrlNoPaddingBytes(x),
                        y: Base64UrlNoPaddingBytes(y),
                        d: Some(Base64UrlNoPaddingBytes(private_key)),
                    },
                }
            }
        }
    }
}
