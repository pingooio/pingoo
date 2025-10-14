use core::fmt;
use std::{net::IpAddr, str::FromStr, time::Duration};

use maxminddb::MaxMindDBError;
use moka::future::Cache;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::fs;
use tracing::debug;

use crate::{config, serde_utils};

pub struct GeoipDB {
    mmdb: maxminddb::Reader<Vec<u8>>,
    cache: Cache<IpAddr, GeoipRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Copy)]
pub struct GeoipRecord {
    #[serde(deserialize_with = "serde_utils::asn::deserialize")]
    pub asn: u32,
    /// 2-letters country code
    pub country: CountryCode,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("address not found: {0}")]
    AddressNotFound(IpAddr),
    #[error("{0}")]
    Unspecified(String),
    #[error("mmdb file is not valid: {0}")]
    InvalidMmdbFile(#[from] MaxMindDBError),
    #[error("{0} is not a valid country code")]
    InvalidCountryCode(String),
}

/// 2-letters country code.
/// We use a custome type to reduce the memory footprint and avoid allocations.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode([u8; 2]);

impl GeoipDB {
    /// try to load the geoip database from the default paths.
    pub async fn load() -> Result<Option<Self>, Error> {
        let (geoip_db_path, mut mmdb_content) = match read_geoip_db().await? {
            Some(path_and_content) => path_and_content,
            None => return Ok(None),
        };

        // if the geoip database has the .zst extension, then we consider it to be ZSTD-compressed
        if geoip_db_path.ends_with(".zst") {
            mmdb_content = zstd::decode_all(mmdb_content.as_slice()).map_err(|err| {
                Error::Unspecified(format!("error decompressing geoip database ({geoip_db_path}): {err}"))
            })?;
        }

        let mmdb_reader = maxminddb::Reader::from_source(mmdb_content)?;

        let cache = Cache::builder()
            .max_capacity(50_000)
            // Time to live (TTL): 1 hour
            .time_to_live(Duration::from_secs(3600))
            .build();

        debug!("geoip database successfully loaded from {geoip_db_path}");

        return Ok(Some(GeoipDB {
            mmdb: mmdb_reader,
            cache,
        }));
    }

    pub async fn lookup(&self, ip: IpAddr) -> Result<GeoipRecord, Error> {
        if ip.is_loopback() || ip.is_multicast() {
            return Err(Error::AddressNotFound(ip));
        }

        if let Some(record) = self.cache.get(&ip).await {
            return Ok(record);
        }

        return match self.mmdb.lookup::<GeoipRecord>(ip) {
            Ok(record) => {
                // if geoip data is found, cache it for this IP
                self.cache.insert(ip, record).await;
                Ok(record)
            }
            Err(MaxMindDBError::AddressNotFoundError(_)) => Err(Error::AddressNotFound(ip)),
            Err(err) => Err(Error::Unspecified(format!("geoip: error looking up GEOI for {ip}: {err}"))),
        };
    }
}

async fn read_geoip_db() -> Result<Option<(String, Vec<u8>)>, Error> {
    for geoip_db_path in config::GEOIP_DATABASE_PATHS {
        if fs::try_exists(geoip_db_path)
            .await
            .map_err(|err| Error::Unspecified(format!("error reading geoip database ({geoip_db_path}): {err}")))?
        {
            return Ok(Some((
                geoip_db_path.to_string(),
                fs::read(geoip_db_path).await.map_err(|err| {
                    Error::Unspecified(format!("error reading geoip database ({geoip_db_path}): {err}"))
                })?,
            )));
        }
    }
    return Ok(None);
}

impl Default for GeoipRecord {
    fn default() -> Self {
        GeoipRecord {
            asn: 0,
            country: CountryCode::from_str("XX").unwrap(),
        }
    }
}

impl CountryCode {
    pub fn as_str(&self) -> &str {
        // safe because we only allow ASCII uppercase letters
        // which are valid UTF-8 single-byte characters
        unsafe { str::from_utf8_unchecked(&self.0) }
    }
}

impl FromStr for CountryCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();

        if bytes.len() != 2 || !bytes.iter().all(|byte| (b'A'..=b'Z').contains(byte)) {
            return Err(Error::InvalidCountryCode(s.to_string()));
        }

        let mut arr = [0u8; 2];
        arr.copy_from_slice(bytes);
        Ok(CountryCode(arr))
    }
}

impl fmt::Debug for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CountryCode").field(&self.as_str()).finish()
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for CountryCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CountryCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        let s = String::deserialize(deserializer)?;
        CountryCode::from_str(&s).map_err(|e| D::Error::custom(e.to_string()))
    }
}
