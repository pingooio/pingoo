pub mod base64_url_no_padding {
    use base64::{Engine, engine::general_purpose};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref());
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S, T>(opt: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: AsRef<[u8]>,
        {
            match opt {
                Some(arr) => super::serialize(arr.as_ref(), serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt: Option<String> = Option::deserialize(deserializer)?;
            match opt {
                None => Ok(None),
                Some(s) => super::deserialize(serde::de::value::StringDeserializer::new(s)).map(Some),
            }
        }
    }
}
