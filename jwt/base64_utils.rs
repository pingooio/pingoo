#[derive(Debug, Clone, PartialEq)]
pub struct Base64UrlNoPaddingBytes(pub Vec<u8>);

use base64::{Engine as _, engine::general_purpose};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

impl Serialize for Base64UrlNoPaddingBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::URL_SAFE_NO_PAD.encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for Base64UrlNoPaddingBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value_str = String::deserialize(deserializer)?;
        let v = general_purpose::URL_SAFE_NO_PAD
            .decode(&value_str)
            .map_err(|e| DeError::custom(format!("base64 decode error: {}", e)))?;
        Ok(Base64UrlNoPaddingBytes(v))
    }
}

impl From<Vec<u8>> for Base64UrlNoPaddingBytes {
    fn from(value: Vec<u8>) -> Self {
        Base64UrlNoPaddingBytes(value)
    }
}
