use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use hickory_resolver::{Resolver, config::ResolverOpts, name_server::TokioConnectionProvider};

use crate::{
    Error,
    config::{ServiceConfig, UpstreamConfig},
    service_discovery::service_registry::{ServiceDiscoverer, Upstream},
};

type DnsResolver = Resolver<TokioConnectionProvider>;

pub struct DnsServiceDiscoverer {
    dns_resolver: DnsResolver,
    hosts: HashMap<String, Vec<UpstreamHost>>,
}

struct UpstreamHost {
    hostname: String,
    tls: bool,
    port: u16,
}

impl DnsServiceDiscoverer {
    pub fn new(services_config: &[ServiceConfig]) -> Self {
        let hosts = get_upstream_hosts(services_config);

        let dns_resolver = Resolver::builder_tokio()
            .expect("error building DNS resolver")
            .with_options(default_resolver_opts())
            .build();

        // AsyncResolver::tokio(
        //     // ResolverConfig::from_parts(None, vec![], nameserver_config_group),
        //     ResolverConfig::cloudflare_https(),
        //     default_resolver_opts(),
        // );

        return DnsServiceDiscoverer { dns_resolver, hosts };
    }
}

#[async_trait::async_trait]
impl ServiceDiscoverer for DnsServiceDiscoverer {
    async fn discover(&self) -> Result<HashMap<String, Vec<Upstream>>, Error> {
        let mut ret = HashMap::with_capacity(self.hosts.len());
        for (service, upstream_hosts) in &self.hosts {
            let mut upstreams = Vec::with_capacity(upstream_hosts.len());
            for upstream_host in upstream_hosts {
                let ips: Vec<IpAddr> = match self.dns_resolver.lookup_ip(&upstream_host.hostname).await {
                    Ok(records) => records.iter().collect(),
                    Err(_) => Vec::new(), // TODO: log error?
                };
                let host_upstreams: Vec<Upstream> = ips
                    .iter()
                    .map(|ip| {
                        // if self.ipv4_only {
                        //     if socket_address.is_ipv4() {
                        //         return Some(socket_address);
                        //     } else {
                        //         return None;
                        //     }
                        // }

                        // the loopback IPv6 address can cause problems: let's say that upstream is
                        // "localhost" which resolves to 127.0.01 and [::1]
                        // if the server listens on 0.0.0.0, any request to [::1] won't be able to
                        // connect to the upstream
                        if ip.is_ipv6() && ip.is_loopback() {
                            return SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), upstream_host.port);
                        }
                        return SocketAddr::new(*ip, upstream_host.port);
                    })
                    // dedup ips
                    .collect::<HashSet<SocketAddr>>()
                    .into_iter()
                    .map(|socket_address| Upstream {
                        socket_address,
                        tls: upstream_host.tls,
                        hostname: upstream_host.hostname.clone(),
                    })
                    .collect();

                upstreams.extend(host_upstreams);
            }
            ret.insert(service.clone(), upstreams);
        }

        return Ok(ret);
    }
}

pub fn default_resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(8);
    // opts.shuffle_dns_servers = true;
    opts.positive_min_ttl = Some(Duration::from_secs(60));
    opts.positive_max_ttl = Some(Duration::from_secs(7200));
    opts.negative_max_ttl = Some(Duration::from_secs(1800));
    return opts;
}

fn get_upstream_hosts(services_config: &[ServiceConfig]) -> HashMap<String, Vec<UpstreamHost>> {
    services_config
        .iter()
        .map(|service_config| {
            let name = service_config.name.clone();

            if let Some(upstreams) = &service_config.http_proxy {
                return (
                    name,
                    upstreams
                        .iter()
                        .filter_map(|upstream| match upstream {
                            UpstreamConfig::IPAddress(_) => None,
                            UpstreamConfig::Domain { hostname, tls, port } => Some(UpstreamHost {
                                hostname: hostname.clone(),
                                tls: *tls,
                                port: *port,
                            }),
                        })
                        .collect(),
                );
            }
            if let Some(upstreams) = &service_config.tcp_proxy {
                return (
                    name,
                    upstreams
                        .iter()
                        .filter_map(|upstream| match upstream {
                            UpstreamConfig::IPAddress(_) => None,
                            UpstreamConfig::Domain { hostname, tls, port } => Some(UpstreamHost {
                                hostname: hostname.clone(),
                                tls: *tls,
                                port: *port,
                            }),
                        })
                        .collect(),
                );
            } else {
                return (name, Vec::new());
            }
        })
        .collect()
}
