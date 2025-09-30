pub mod asn {
    use serde::{Deserialize, Deserializer};

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let asn_str = String::deserialize(deserializer)?;
        return Ok(asn_str.trim_start_matches("AS").parse::<u32>().unwrap_or(0));
    }
}

pub mod uri {
    use http::Uri;
    use serde::Serializer;

    #[inline]
    pub fn serialize<S: Serializer>(uri: &Uri, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&uri)
    }
}

pub mod method {
    use http::Method;
    use serde::Serializer;

    #[inline]
    pub fn serialize<S: Serializer>(method: &Method, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(method.as_str())
    }
}
