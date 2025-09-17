use std::net::SocketAddr;

use crate::geoip::CountryCode;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_address: SocketAddr,
    pub server_address: SocketAddr,
    pub asn: u32,
    pub country: CountryCode,
    pub geoip_enabled: bool,
    pub tls: bool,
}
