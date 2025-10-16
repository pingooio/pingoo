use core::fmt;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use http::{StatusCode, Uri};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, de::Visitor};
use url::Url;

use crate::{
    Error,
    config::{
        ChildProcess, ListConfig, ListenerProtocol, ServiceConfig, ServiceDiscoveryConfig, StaticSiteServiceConfig,
        StaticSiteServiceNotFound, TlsConfig, UpstreamConfig,
    },
    service_discovery::service_registry::Upstream,
};

// TODO: error on map duplicate key
// https://docs.rs/serde_with/latest/serde_with/rust/maps_duplicate_key_is_error/index.html
#[derive(Clone, Debug, Deserialize)]
pub struct ConfigFile {
    pub listeners: IndexMap<String, ListenerConfigFile>,
    pub services: IndexMap<String, ServiceConfigFile>,
    #[serde(default)]
    pub rules: IndexMap<String, RuleConfigFile>,
    pub tls: Option<TlsConfig>,
    pub service_discovery: Option<ServiceDiscoveryConfig>,
    pub lists: Option<IndexMap<String, ListConfig>>,
    pub child_process: Option<ChildProcess>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListenerConfigFile {
    pub address: ListenerAddressConfigFile,
    pub services: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub struct ListenerAddressConfigFile {
    pub socket_address: SocketAddr,
    pub protocol: ListenerProtocol,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfigFile {
    // #[serde(default)]
    // pub provider: Provider,
    // pub servers: Vec<String>,
    // #[serde(default)]
    // pub listeners: Vec<String>,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub http_proxy: Option<Vec<String>>,
    #[serde(default)]
    pub r#static: Option<ServiceConfigFileStatic>,
    #[serde(default)]
    pub tcp_proxy: Option<Vec<String>>,
    #[serde(default)]
    pub auth: Option<AuthConfigFile>,
    // #[serde(default)]
    // pub rules: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfigFile {
    pub provider: crate::config::AuthProvider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfigFileStatic {
    #[serde(default)]
    pub root: String,

    #[serde(default)]
    pub not_found: ServiceConfigFileStaticNotFound,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfigFileStaticNotFound {
    #[serde(default)]
    pub file: Option<String>,

    #[serde(default = "default_service_static_not_found_status")]
    pub status: u16,
}

// #[derive(Clone, Debug, Deserialize)]
// pub struct TcpProxyConfigFile {
//     #[serde(default)]
//     pub upstreams: Vec<String>,
// }

// #[derive(Clone, Debug, Deserialize)]
// pub struct HttpProxyConfigFile {
//     #[serde(default)]
//     pub upstreams: Vec<String>,
// }

#[derive(Clone, Debug, Deserialize)]
pub struct RuleConfigFile {
    pub expression: Option<String>,
    pub actions: Vec<rules::Action>,
}

impl Default for ServiceConfigFileStaticNotFound {
    fn default() -> Self {
        Self {
            file: None,
            status: default_service_static_not_found_status(),
        }
    }
}

impl<'de> Deserialize<'de> for ListenerAddressConfigFile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SVisitor;

        impl<'de> Visitor<'de> for SVisitor {
            type Value = ListenerAddressConfigFile;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Listener")
            }

            fn visit_str<E>(self, value: &str) -> Result<ListenerAddressConfigFile, E>
            where
                E: serde::de::Error,
            {
                parse_listener_address(value).map_err(|err| serde::de::Error::custom(err.to_string()))
            }

            fn visit_string<E>(self, value: String) -> Result<ListenerAddressConfigFile, E>
            where
                E: serde::de::Error,
            {
                parse_listener_address(&value).map_err(|err| serde::de::Error::custom(err.to_string()))
            }
        }

        deserializer.deserialize_string(SVisitor)
    }
}

fn parse_listener_address(listener_address: &str) -> Result<ListenerAddressConfigFile, Error> {
    let listener_uri = Uri::from_str(listener_address)
        .map_err(|err| Error::Config(format!("config: error parsing listener [{listener_address}]: {err}")))?;

    let protocol = listener_uri
        .scheme_str()
        .map(|scheme| scheme.to_string())
        .unwrap_or(ListenerProtocol::Http.to_string())
        .parse::<ListenerProtocol>()
        .map_err(|err| {
            Error::Config(format!("config: listeners.[{listener_address}]: protocol is not valid: {err}"))
        })?;

    if !listener_uri.path().is_empty() {
        Error::Config(format!("config: listeners.[{listener_address}]: path must be empty"));
    }

    let authority = listener_uri.authority().ok_or(Error::Config(format!(
        "listener address {} is not valid: authority is missing",
        &listener_address
    )))?;

    let port = match (authority.port_u16(), protocol) {
        (Some(port), _) => port,
        (None, ListenerProtocol::Http) => 80,
        (None, ListenerProtocol::Https) => 443,
        _ => {
            return Err(Error::Config(format!(
                "listener address {} is not valid: port is missing",
                &listener_address
            )));
        }
    };

    let ip_address: IpAddr = authority
        .host()
        .parse()
        .map_err(|err| Error::Config(format!("listener address {} is not valid: {err}", &listener_address)))?;

    return Ok(ListenerAddressConfigFile {
        socket_address: SocketAddr::new(ip_address, port),
        protocol,
    });
}

pub fn parse_service(service_name: String, service: ServiceConfigFile) -> Result<ServiceConfig, Error> {
    if [
        service.http_proxy.is_some(),
        service.tcp_proxy.is_some(),
        service.r#static.is_some(),
    ]
    .iter()
    .filter(|&&is_some| is_some)
    .count()
        != 1
    {
        return Err(Error::Config(format!(
            "invalid service definition for {service_name}: services must have exactly 1 http_proxy, tcp_proxy or static field"
        )));
    }

    let r#static = match &service.r#static {
        Some(s) => {
            let root = PathBuf::from(&s.root);
            let not_found_file = s.not_found.file.clone().map(|file| {
                let mut not_found_path = root.clone();
                not_found_path.push(file);
                not_found_path
            });

            let status = StatusCode::from_u16(s.not_found.status).map_err(|_| {
                Error::Config(format!(
                    "services.[{service_name}].static.not_found.status: Not a valid HTTP status code"
                ))
            })?;
            Some(StaticSiteServiceConfig {
                root: root,
                not_found: StaticSiteServiceNotFound {
                    status_code: status,
                    file: not_found_file,
                },
            })
        }
        None => None,
    };

    let http_proxy = service
        .http_proxy
        .map(|upstreams| {
            upstreams
                .iter()
                .map(|upstream| parse_upstream(&upstream))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_or(Ok(None), |r| r.map(Some))?;

    // TCP proxy
    if service.tcp_proxy.is_some() && service.route.is_some() {
        return Err(Error::Config(format!(
            "Invalid service definition for {service_name}: TCP proxy can't have a route"
        )));
    }
    let tcp_proxy = service
        .tcp_proxy
        .map(|upstreams| {
            upstreams
                .iter()
                .map(|upstream| parse_upstream(&upstream))
                .collect::<Result<Vec<_>, _>>()
        })
        .map_or(Ok(None), |r| r.map(Some))?;

    let route = service
        .route
        .map(|route| {
            let compiled_route = rules::compile_expression(&route)?;
            Ok(compiled_route)
        })
        .map(|r| r.map(Some))
        .unwrap_or(Ok(None))
        .map_err(|err: rules::Error| Error::Config(format!("error parsing route for service {service_name}: {err}")))?;

    let auth = service.auth.map(|auth_config| crate::config::AuthConfig {
        provider: auth_config.provider,
        client_id: auth_config.client_id,
        client_secret: auth_config.client_secret,
        redirect_url: auth_config.redirect_url,
    });

    return Ok(ServiceConfig {
        name: service_name,
        route,
        http_proxy,
        r#static: r#static,
        tcp_proxy,
        auth,
    });
}

const fn default_service_static_not_found_status() -> u16 {
    return 404;
}

fn parse_upstream(upstream_str: &str) -> Result<UpstreamConfig, Error> {
    let url =
        Url::parse(upstream_str).map_err(|err| Error::Config(format!("{upstream_str} is not a valid URL: {err}")))?;
    let hostname = url.host_str().unwrap_or_default();
    if hostname.is_empty() {
        return Err(Error::Config(format!("{upstream_str} is not a valid URL: host is missing")));
    }
    if !hostname.is_ascii() {
        return Err(Error::Config(format!(
            "{upstream_str} is not a valid URL: only ascii hostnames are currently supported"
        )));
    }

    let protocol = match url.scheme() {
        protocol @ ("tcp" | "http" | "https") => protocol,
        _ => {
            return Err(Error::Config(format!(
                "{upstream_str} is not a valid URL: {} is not a valid protocol",
                url.scheme()
            )));
        }
    };

    let port = url
        .port()
        .or_else(|| match protocol {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        })
        .ok_or(Error::Config(format!("{upstream_str} is not a valid URL: port is missing")))?;

    let tls = protocol == "https";

    if hostname == "localhost" {
        return Ok(UpstreamConfig::IPAddress(Upstream {
            socket_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
            hostname: hostname.to_string(),
            tls,
        }));
    } else if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(UpstreamConfig::IPAddress(Upstream {
            socket_address: SocketAddr::new(ip, port),
            hostname: hostname.to_string(),
            tls,
        }));
    } else {
        return Ok(UpstreamConfig::Domain {
            hostname: hostname.to_string(),
            tls,
            port,
        });
    }
}
