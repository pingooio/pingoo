use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

use http::StatusCode;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    Error,
    config::config_file::{ConfigFile, parse_service},
    lists::ListType,
    rules::Rule,
    service_discovery::service_registry::Upstream,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_CONFIG_PATH: &str = "/etc/pingoo/pingoo.yml";
pub const DEFAULT_TLS_FOLDER: &str = "/etc/pingoo/certificates";
pub const GEOIP_DATABASE_PATHS: &[&str] = &[
    "/etc/pingoo/geoip.mmdb",
    "/etc/pingoo/geoip.mmdb.zst",
    "/etc/pingoo_data/geoip.mmdb.zst",
    "/etc/pingoo_data/geoip.mmdb.zst",
];
pub const CAPTCHA_JWKS_PATH: &str = "/etc/pingoo/captcha_jwks.json";
pub const USER_AGENT: &str = concat!("pingoo/", env!("CARGO_PKG_VERSION"), " (https://pingoo.io)");

#[derive(Debug)]
pub struct Config {
    pub listeners: Vec<ListenerConfig>,
    pub services: Vec<ServiceConfig>,
    pub rules: Vec<Rule>,
    pub tls: TlsConfig,
    pub service_discovery: ServiceDiscoveryConfig,
    pub lists: HashMap<String, ListConfig>,
    pub child_process: Option<ChildProcess>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum ListenerProtocol {
    Tcp,
    TcpAndTls,
    Http,
    Https,
}

#[derive(Clone, Debug)]
pub struct ListenerConfig {
    pub name: String,
    pub address: SocketAddr,
    pub protocol: ListenerProtocol,
    pub services: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub name: String,
    // pub provider: Provider,
    // pub servers: Vec<SocketAddr>,
    pub route: Option<rules::CompiledExpression>,
    pub http_proxy: Option<Vec<UpstreamConfig>>,
    pub r#static: Option<StaticSiteServiceConfig>,
    pub tcp_proxy: Option<Vec<UpstreamConfig>>,
}

// #[derive(Clone, Debug)]
// pub struct TcpProxyConfig {
//     pub upstreams: Vec<UpstreamConfig>,
// }

// #[derive(Clone, Debug)]
// pub struct HttpProxyConfig {
//     pub upstreams: Vec<UpstreamConfig>,
// }

#[derive(Clone, Debug)]
pub enum UpstreamConfig {
    IPAddress(Upstream),
    Domain { hostname: String, tls: bool, port: u16 },
}

#[derive(Clone, Debug)]
pub struct StaticSiteServiceConfig {
    pub root: PathBuf,
    pub not_found: StaticSiteServiceNotFound,
}

#[derive(Clone, Debug)]
pub struct StaticSiteServiceNotFound {
    pub file: Option<PathBuf>,
    pub status_code: StatusCode,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_folder")]
    pub folder: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct ServiceDiscoveryConfig {
    pub docker: ServiceDiscoveryDockerConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceDiscoveryDockerConfig {
    #[serde(default = "default_docker_socket")]
    pub socket: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GeoipConfig {
    pub database: String,
}

impl Default for ServiceDiscoveryDockerConfig {
    fn default() -> Self {
        ServiceDiscoveryDockerConfig {
            socket: default_docker_socket(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListConfig {
    pub r#type: ListType,
    pub file: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChildProcess {
    pub command: Vec<String>,
}

impl FromStr for ListenerProtocol {
    type Err = Error;

    fn from_str(protocol_str: &str) -> Result<Self, Self::Err> {
        match protocol_str {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "tcp" => Ok(Self::Tcp),
            "tcp+tls" => Ok(Self::TcpAndTls),
            _ => Err(Error::Config(format!("{protocol_str} is not a valid protocol"))),
        }
    }
}

impl fmt::Display for ListenerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str_value = match self {
            ListenerProtocol::Http => "http",
            ListenerProtocol::Https => "https",
            ListenerProtocol::Tcp => "tcp",
            ListenerProtocol::TcpAndTls => "tcp+tls",
        };
        return write!(f, "{str_value}");
    }
}

pub fn load_and_validate(config_file_path: Option<String>) -> Result<Config, Error> {
    // first read and deserialize the configuration file into a `ConfigFile` struct
    // then convert it into a `Config` struct
    // finally, validate the configuration

    let (config_file_path, raw_config) = read_config_file(config_file_path)?;

    info!("configuration successfully loaded from {config_file_path}");

    let config_file: ConfigFile = serde_yaml::from_slice(&raw_config)
        .map_err(|err| Error::Config(format!("error parsing config file ({config_file_path}): {err}")))?;

    let services: IndexMap<String, ServiceConfig> = config_file
        .services
        .into_iter()
        .map(|(name, service)| Ok((name.clone(), parse_service(name, service)?)))
        .collect::<Result<_, Error>>()?;
    // validate_services(&services).await?;

    let all_http_services: Vec<String> = services
        .iter()
        .filter(|(_, service_config)| service_config.http_proxy.is_some() || service_config.r#static.is_some())
        .map(|(name, _)| name.clone())
        .collect();

    let all_tcp_services: Vec<String> = services
        .iter()
        .filter(|(_, service_config)| service_config.tcp_proxy.is_some())
        .map(|(name, _)| name.clone())
        .collect();

    let default_services_for_listener = |protocol: ListenerProtocol| -> Vec<String> {
        match protocol {
            ListenerProtocol::Tcp | ListenerProtocol::TcpAndTls => all_tcp_services.clone(),
            ListenerProtocol::Http | ListenerProtocol::Https => all_http_services.clone(),
        }
    };

    let listeners: Vec<ListenerConfig> = config_file
        .listeners
        .into_iter()
        .map(|(name, listener_config)| ListenerConfig {
            name: name,
            address: listener_config.address.socket_address,
            protocol: listener_config.address.protocol,
            services: listener_config
                .services
                .unwrap_or(default_services_for_listener(listener_config.address.protocol)),
        })
        .collect();
    validate_listeners_config(&listeners, &services)?;

    let rules: Vec<Rule> = config_file
        .rules
        .unwrap_or_default()
        .into_iter()
        .map(|(rule_name, rule_config)| {
            Ok(Rule {
                name: rule_name,
                expression: rule_config
                    .expression
                    .map(|expression| rules::compile_expression(&expression))
                    .map_or(Ok(None), |r| r.map(Some))?,
                actions: rule_config.actions,
            })
        })
        .collect::<Result<_, rules::Error>>()
        .map_err(|err| Error::Config(format!("error parsing rules: {err}")))?;

    let tls_config = config_file.tls.unwrap_or(TlsConfig {
        folder: default_tls_folder(),
    });

    let lists = config_file
        .lists
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key, value))
        .collect();

    let config = Config {
        listeners,
        services: services.into_iter().map(|(_, config)| config).collect(),
        rules,
        tls: tls_config,
        service_discovery: config_file.service_discovery.unwrap_or_default(),
        lists,
        child_process: config_file.child_process,
    };

    return Ok(config);
}

fn read_config_file(path: Option<String>) -> Result<(String, Vec<u8>), Error> {
    match path {
        Some(config_file_path) => Ok((
            config_file_path.clone(),
            fs::read(&config_file_path)
                .map_err(|err| Error::Config(format!("error reading config file ({config_file_path}): {err}")))?,
        )),
        None => {
            for config_file_path in ["pingoo.yml", "/etc/pingoo/pingoo.yml"] {
                if fs::exists(config_file_path)
                    .map_err(|err| Error::Config(format!("error reading config file ({config_file_path}): {err}")))?
                {
                    return Ok((
                        config_file_path.to_string(),
                        fs::read(config_file_path).map_err(|err| {
                            Error::Config(format!("error reading config file ({config_file_path}): {err}"))
                        })?,
                    ));
                }
            }
            return Err(Error::Config("config file not found".to_string()));
        }
    }
}

fn validate_listeners_config(
    listeners: &[ListenerConfig],
    all_services: &IndexMap<String, ServiceConfig>,
) -> Result<(), Error> {
    for (i, listener) in listeners.iter().enumerate() {
        for (j, other_listener) in listeners.iter().enumerate() {
            if i == j {
                continue;
            }
            if listener.address.port() == other_listener.address.port() {
                return Err(Error::Config(format!(
                    "config: listeners: {} and {} can't listen on the same port",
                    listener.name, other_listener.name
                )));
            }
        }

        if listener.services.len() == 0 {
            return Err(Error::Config(format!(
                "config: listeners: {}: no service found for this listener",
                listener.name
            )));
        }

        if (listener.protocol == ListenerProtocol::Tcp || listener.protocol == ListenerProtocol::TcpAndTls)
            && listener.services.len() > 1
        {
            return Err(Error::Config(format!(
                "config: listeners: {}: TCP listeners can only have 1 associated service",
                listener.name
            )));
        }

        for service_name in &listener.services {
            if !all_services.contains_key(service_name) {
                return Err(Error::Config(format!(
                    "config: listeners: {}: service {service_name} doesn't exist",
                    listener.name,
                )));
            }
        }

        if let Some(duplicate) = find_duplicate(&listener.services) {
            return Err(Error::Config(format!(
                "config: listeners: {}: duplicate services are not allowed ({duplicate})",
                listener.name,
            )));
        }
    }

    return Ok(());
}

fn find_duplicate<'a, T: Eq + std::hash::Hash>(v: &'a [T]) -> Option<&'a T> {
    let mut seen: HashSet<&T> = HashSet::new();
    for item in v {
        if !seen.insert(item) {
            return Some(item);
        }
    }
    None
}

fn default_tls_folder() -> PathBuf {
    return DEFAULT_TLS_FOLDER.into();
}

fn default_docker_socket() -> String {
    return ::docker::DEFAULT_DOCKER_SOCKET.to_string();
}
