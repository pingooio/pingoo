pub mod asn {
    use serde::{Deserialize, Deserializer};

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let asn_str = String::deserialize(deserializer)?;
        return Ok(asn_str.trim_start_matches("AS").parse::<u32>().unwrap_or(0));
    }
}

pub mod http_uri {
    use http::Uri;
    use serde::Serializer;

    #[inline]
    pub fn serialize<S: Serializer>(uri: &Uri, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&uri)
    }
}

pub mod http_method {
    use http::Method;
    use serde::Serializer;

    #[inline]
    pub fn serialize<S: Serializer>(method: &Method, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(method.as_str())
    }
}

pub mod rustls_private_pkcs_key_der {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use serde::{Deserializer, Serializer, de};
    use std::fmt;

    pub fn serialize<S: Serializer>(pruvate_key: &PrivatePkcs8KeyDer<'_>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::encode(pruvate_key.secret_pkcs8_der()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PrivatePkcs8KeyDer<'static>, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = PrivatePkcs8KeyDer<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64-encoded PKCS#8 private key")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let bytes = base64::decode(v.as_bytes()).map_err(de::Error::custom)?;
                PrivatePkcs8KeyDer::try_from(bytes).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}
