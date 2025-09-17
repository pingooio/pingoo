use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Algorithm, Error, base64_utils::Base64UrlNoPaddingBytes};

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
    pub kty: KeyType,
    pub r#use: KeyUse,
    pub alg: Algorithm,
    // #[serde(flatten)]
    // pub crypto: KeyCrypto,
    // #[serde(flatten)]
    pub crv: EllipticCurve,
    // /// base64UrlNoPadding encoded public key
    // #[serde(with = "serde_bytes")]
    pub x: Base64UrlNoPaddingBytes,
    /// base64UrlNoPadding encoded private key
    pub d: Option<Base64UrlNoPaddingBytes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyCrypto {
    Ed25519 {
        crv: EllipticCurve,
        /// base64UrlNoPadding encoded public key
        // #[serde(with = "base64_url_no_padding")]
        x: Base64UrlNoPaddingBytes,
        d: Option<Base64UrlNoPaddingBytes>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    OKP,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Sign,
    #[serde(rename = "enc")]
    Encrypt,
}

// https://csrc.nist.gov/pubs/fips/186-5/final
// https://csrc.nist.gov/pubs/sp/800/186/final
// https://www.rfc-editor.org/rfc/rfc8032
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum EllipticCurve {
    Ed25519,
    // P256
}

impl FromStr for EllipticCurve {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "Ed25519" => Ok(EllipticCurve::Ed25519),
            _ => Err(Error::InvalidEllipticCurve(input.to_string())),
        }
    }
}

impl fmt::Display for EllipticCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            EllipticCurve::Ed25519 => "Ed25519",
        };
        write!(f, "{value}")
    }
}

// mod base64_url_no_padding {
//         use serde::{Deserialize, Deserializer, Serializer};

//         pub fn serialize<S>(data: &[u8], s: S) -> Result<S::Ok, S::Error>
//         where
//             S: Serializer,
//         {
//             let str_value = base64::encode_with_alphabet(data, base64::Alphabet::UrlNoPadding);
//             s.serialize_str(&str_value)
//         }

//         pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
//             let value_str = String::deserialize(deserializer)?;
//             let ret = base64::decode_with_alphabet(value_str.as_bytes(), base64::Alphabet::UrlNoPadding)
//                 .map_err(|err| serde::de::Error::custom(err.to_string()))?;
//             return Ok(ret);
//         }
//     }
