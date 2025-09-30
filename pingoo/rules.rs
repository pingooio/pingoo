use std::net::IpAddr;

use http::Uri;
use serde::Serialize;
use tracing::warn;

use crate::{geoip::CountryCode, serde_utils};

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub expression: Option<rules::CompiledExpression>,
    pub actions: Vec<rules::Action>,
}

#[derive(Debug, Serialize)]
pub struct RequestData<'a> {
    pub host: &'a str,
    #[serde(serialize_with = "serde_utils::uri::serialize")]
    pub url: &'a Uri,
    pub path: &'a str,
    #[serde(serialize_with = "serde_utils::method::serialize")]
    pub method: &'a http::Method,
    pub user_agent: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientData {
    pub ip: IpAddr,
    pub remote_port: u16,
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
