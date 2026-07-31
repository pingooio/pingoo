use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::Uri;
use serde::Serialize;
use tracing::warn;

use crate::{geoip::CountryCode, serde_utils};

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub expression: Option<rules::CompiledExpression>,
    pub actions: Vec<rules::Action>,
    pub cidr_v4: Option<CidrV4>,
    pub cidr_v6: Option<CidrV6>,
}

#[derive(Debug, Serialize)]
pub struct RequestData<'a> {
    pub host: &'a str,
    #[serde(serialize_with = "serde_utils::http_uri::serialize")]
    pub url: &'a Uri,
    pub path: &'a str,
    #[serde(serialize_with = "serde_utils::http_method::serialize")]
    pub method: &'a http::Method,
    pub user_agent: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientData {
    pub ip: IpAddr,
    // only signed integers are supported so we can't use an u16
    pub remote_port: i32,
    pub asn: i64,
    pub country: CountryCode,
}

impl Rule {
    pub fn match_request(&self, request_ctx: &rules::Context) -> bool {
        if let Some(expression) = &self.expression {
            let return_value = match expression.execute(request_ctx) {
                Ok(value) => value,
                Err(err) => {
                    warn!("error executing rule {}: {err}", self.name);
                    return false;
                }
            };

            return return_value == true.into();
        } else {
            return true;
        }
    }
}

// fn serialize_arc_string<S>(value: &Arc<String>, serializer: S) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     serializer.serialize_str(value)
// }

#[derive(Debug, Clone)]
pub struct CidrV4 {
    pub network: Ipv4Addr,
    pub prefix: u32,
    mask: u32,
}

#[derive(Debug, Clone)]
pub struct CidrV6 {
    pub network: Ipv6Addr,
    pub prefix: u128,
    mask: u128,
}

impl CidrV4 {
    pub fn new(network: Ipv4Addr, prefix: u32) -> Self {
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        Self { network, prefix, mask }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (ip.to_bits() & self.mask) == (self.network.to_bits() & self.mask)
    }
}

impl CidrV6 {
    pub fn new(network: Ipv6Addr, prefix: u128) -> Self {
        let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
        Self { network, prefix, mask }
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        (ip.to_bits() & self.mask) == (self.network.to_bits() & self.mask)
    }
}
