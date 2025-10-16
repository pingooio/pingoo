use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

use http::StatusCode;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{debug, info, warn};

use crate::{
    Error,
    config::config_file::{ConfigFile, RuleConfigFile, parse_service},
    lists::ListType,
    rules::Rule,
    service_discovery::service_registry::Upstream,
    tls::acme::LETSENCRYPT_PRODUCTION_URL,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_CONFIG_FILE: &str = "/etc/pingoo/pingoo.yml";
pub const DEFAULT_CONFIG_FOLDER: &str = "/etc/pingoo";
pub const DEFAULT_TLS_FOLDER: &str = "/etc/pingoo/tls";
/// Locations where geoip database are looked for.
/// We use the /usr/share/pingoo folder so people using docker can bind the /etc/pingoo folder
/// and still use the provided Geoip database.
pub const GEOIP_DATABASE_PATHS: &[&str] = &[
    "/etc/pingoo/geoip.mmdb",
    "/etc/pingoo/geoip.mmdb.zst",
    "/usr/share/pingoo/geoip.mmdb",
    "/usr/share/pingoo/geoip.mmdb.zst",
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
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub provider: AuthProvider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    Google,
    #[serde(rename = "github")]
    GitHub,
    #[serde(rename = "custom")]
    Custom,
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
    pub acme: Option<TlsAcmeConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig { acme: None }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TlsAcmeConfig {
    #[serde(default = "default_tls_acme_directory_url")]
    pub directory_url: String,
    pub domains: Vec<String>,
}

impl Default for TlsAcmeConfig {
    fn default() -> Self {
        TlsAcmeConfig {
            domains: Vec::new(),
            directory_url: default_tls_acme_directory_url(),
        }
    }
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

pub async fn load_and_validate() -> Result<Config, Error> {
    // first read and deserialize the configuration file into a `ConfigFile` struct
    // then convert it into a `Config` struct
    // finally, validate the configuration

    let raw_config = fs::read(DEFAULT_CONFIG_FILE)
        .await
        .map_err(|err| Error::Config(format!("error reading config file ({DEFAULT_CONFIG_FILE}): {err}")))?;

    info!("configuration successfully loaded from {DEFAULT_CONFIG_FILE}");

    let mut config_file: ConfigFile = serde_yaml::from_slice(&raw_config)
        .map_err(|err| Error::Config(format!("error parsing config file ({DEFAULT_CONFIG_FILE}): {err}")))?;

    let rules_from_folder = load_rules().await?;
    if let Some(duplicate_rule_name) = find_duplicate2(
        rules_from_folder.iter().map(|(rule_name, _)| rule_name),
        config_file.rules.iter().map(|(rule_name, _)| rule_name),
    ) {
        return Err(Error::Config(format!("duplicate rule name: {duplicate_rule_name}")));
    }
    config_file.rules.extend(rules_from_folder);

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

    let mut tls_config = config_file.tls.unwrap_or_default();
    if let Some(acme_config) = tls_config.acme.as_mut() {
        acme_config.directory_url = acme_config.directory_url.trim().trim_end_matches('/').to_string();

        debug!(directory_url = acme_config.directory_url, domains = ?acme_config.domains, "config: ACME");

        if let Some(domain) = find_duplicate(&acme_config.domains) {
            return Err(Error::Config(format!("acme: duplicate domain: {domain}")));
        }

        for domain in &acme_config.domains {
            if domain.contains('*') {
                return Err(Error::Config(format!(
                    "acme: Pingoo currently doesn't support wildcard domains for automatic TLS ({domain})"
                )));
            }

            if !domain.is_ascii() || domain.to_ascii_lowercase().as_str() != domain {
                return Err(Error::Config(format!("acme: invalid domain: {domain}")));
            }
        }

        // warn user if none of their TLS listeners listen on port 443.
        // It's not a hard error as port can be re-mapped e.g. docker run -p 443:8443 [...]
        if !listeners.iter().any(|listener| {
            matches!(listener.protocol, ListenerProtocol::Https | ListenerProtocol::TcpAndTls)
                && listener.address.port() == 443
        }) {
            warn!(
                "config: at least one of your TLS listeners must listen on the port 443 for ACME certificates verification. Visit https://pingoo.io/docs/tls for more information."
            );
        }
    }

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

async fn load_rules() -> Result<IndexMap<String, RuleConfigFile>, Error> {
    let mut ret = IndexMap::new();

    let rules_folder_path = PathBuf::from(DEFAULT_CONFIG_FOLDER).join("rules");

    let mut rule_dir = match fs::read_dir(&rules_folder_path).await {
        Ok(rule_dir) => rule_dir,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(ret),
        Err(err) => {
            return Err(Error::Config(format!(
                "error reading rules folder {rules_folder_path:?}: {err}"
            )));
        }
    };

    while let Ok(Some(file)) = rule_dir.next_entry().await {
        if file
            .path()
            .extension()
            .map(|ext| ext.to_str().unwrap_or_default())
            .unwrap_or_default()
            != "yml"
        {
            continue;
        }

        let rule_file_content = fs::read(file.path())
            .await
            .map_err(|err| Error::Config(format!("error reading rules file {:?}: {err}", file.path())))?;

        let rules: IndexMap<String, RuleConfigFile> = serde_yaml::from_slice(&rule_file_content)
            .map_err(|err| Error::Config(format!("error parsing rules file {:?}: {err}", file.path())))?;

        if let Some(duplicate_rule_name) = find_duplicate2(
            rules.iter().map(|(rule_name, _)| rule_name),
            ret.iter().map(|(rule_name, _)| rule_name),
        ) {
            return Err(Error::Config(format!("duplicate rule name: {duplicate_rule_name}")));
        }

        ret.extend(rules);
    }

    return Ok(ret);
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

fn find_duplicate2<I, J, T>(a: I, b: J) -> Option<T>
where
    I: IntoIterator<Item = T>,
    J: IntoIterator<Item = T>,
    T: Eq + std::hash::Hash + Clone,
{
    let set_a: HashSet<T> = a.into_iter().collect();
    b.into_iter().find(|item| set_a.contains(item))
}

fn default_docker_socket() -> String {
    return ::docker::DEFAULT_DOCKER_SOCKET.to_string();
}

fn default_tls_acme_directory_url() -> String {
    return LETSENCRYPT_PRODUCTION_URL.to_string();
}
