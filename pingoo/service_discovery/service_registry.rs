use std::{
    cmp::max,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use futures::future::join_all;
use tokio::time;
use tracing::{debug, error};

use crate::{
    Error,
    config::{ServiceConfig, ServiceDiscoveryConfig, UpstreamConfig},
    service_discovery::{dns::DnsServiceDiscoverer, docker::DockerServiceDiscoverer},
};

/// The ServiceRegistry, unique per pingoo instance, keeps track of service upstreams.
/// It can be queried to get the list of healthy upstreams for a given service.
pub struct ServiceRegistry {
    // upstreams: DashMap<String, Arc<Vec<Upstream>>>,
    upstreams: DashMap<String, Arc<Vec<Upstream>>>,

    // TODO: should we Arc the Vec?
    // problem: getting a mut Arc (e.g to extend it with new upstream) is hard as it requires only 1 copy.
    /// static_upstreams are the upstreams that were provided direactly as IP addresses in the config
    static_upstreams: HashMap<String, Vec<Upstream>>,

    dns: DnsServiceDiscoverer,
    docker: DockerServiceDiscoverer,
}

#[async_trait::async_trait]
pub trait ServiceDiscoverer: Send + Sync {
    async fn discover(&self) -> Result<HashMap<String, Vec<Upstream>>, Error>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Upstream {
    pub socket_address: SocketAddr,
    pub hostname: String,
    pub tls: bool,
}

struct UpstreamDiff {
    /// services that have upstreams that have been added or updated
    updated: HashSet<String>,
    /// services that no longer have upstreams
    deleted: HashSet<String>,
}

impl ServiceRegistry {
    pub async fn new(
        service_discovery_config: &ServiceDiscoveryConfig,
        services_config: &[ServiceConfig],
    ) -> Result<Self, Error> {
        let static_upstreams = get_static_upstreams(services_config);
        let dns = DnsServiceDiscoverer::new(services_config);
        let docker = DockerServiceDiscoverer::new(service_discovery_config).await?;

        let upstreams = static_upstreams
            .iter()
            .map(|(service_name, upstreams)| (service_name.clone(), Arc::new(upstreams.clone())));

        return Ok(ServiceRegistry {
            upstreams: DashMap::from_iter(upstreams),
            static_upstreams,
            dns,
            docker,
        });
    }

    pub async fn get_upstreams(&self, service: &str) -> Arc<Vec<Upstream>> {
        return self
            .upstreams
            .get(service)
            .map(|upstreams| upstreams.clone())
            .unwrap_or(Arc::new(Vec::new()));
    }

    pub fn start_in_background(self: Arc<Self>) {
        tokio::spawn(async move {
            debug!("Starting ServiceRegistry background service");
            let mut ticker = time::interval(Duration::from_secs(2)); // every 2 seconds
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(err) = self.discover().await {
                            error!("{err}");
                        }
                    },
                    // Ok(_) = shutdown.changed() => {
                    //     info!("Shutting down ServiceDiscovery background service");
                    //     return;
                    // }
                };
            }
        });
    }

    pub async fn discover(&self) -> Result<(), Error> {
        // TODO: what if a discoverer fail?
        let mut new_upstreams = self.static_upstreams.clone();

        let service_discoverers = vec![self.dns.discover(), self.docker.discover()];

        let res = join_all(service_discoverers).await;
        for upstreams_res in res {
            let upstreams = match upstreams_res {
                Ok(upstreams) => upstreams,
                Err(err) => {
                    debug!("service_registry: {err}");
                    continue;
                }
            };

            // merge discovered upstreams with static upstreams
            for (service_name, upstreams) in upstreams {
                new_upstreams
                    .entry(service_name)
                    .or_insert(Vec::new())
                    .extend(upstreams);
            }
        }

        let upstreams_diff = diff_upstreams(&self.upstreams, &new_upstreams);
        for service_name in upstreams_diff.updated.into_iter() {
            if let Some(new_upstreams_for_service) = new_upstreams.remove(&service_name) {
                debug!("upstreams updated for service {service_name}");
                self.upstreams.insert(service_name, Arc::new(new_upstreams_for_service));
            }
        }

        for service_name in upstreams_diff.deleted.into_iter() {
            debug!("upstreams deleted for service {service_name}");
            self.upstreams.remove(&service_name);
        }

        return Ok(());
    }
}

/// diff_upstreams returns the list of services that have upstreams that have been updated or removed
fn diff_upstreams(
    old_upstreams: &DashMap<String, Arc<Vec<Upstream>>>,
    new_upstreams: &HashMap<String, Vec<Upstream>>,
) -> UpstreamDiff {
    // it's better to allocate a little bit too much than to allocate too many times
    let ret_capacity = max(old_upstreams.len(), new_upstreams.len());
    let mut ret = UpstreamDiff {
        updated: HashSet::with_capacity(ret_capacity),
        deleted: HashSet::with_capacity(ret_capacity),
    };

    for (service_name, new_upstreams_for_service) in new_upstreams.iter() {
        if let Some(old_upstreams_for_service) = old_upstreams.get(service_name) {
            // if the upstreams are not in new upstreams (upstreams deleted)
            for old_upstream in old_upstreams_for_service.iter() {
                if !new_upstreams_for_service.contains(old_upstream) {
                    ret.deleted.insert(service_name.clone());
                }
            }

            // if the upstreams are not in old upstreams (upstreams added)
            for new_upstream in new_upstreams_for_service.iter() {
                if !old_upstreams_for_service.contains(new_upstream) {
                    ret.updated.insert(service_name.clone());
                }
            }
        } else {
            // if the service is not in the old upstreams (service added)
            ret.updated.insert(service_name.clone());
        }
    }

    // if the service is in old upstreams but not in new upstreams (service deleted)
    for entry in old_upstreams.iter() {
        let service_name = entry.key();
        if !new_upstreams.contains_key(service_name) {
            ret.deleted.insert(service_name.clone());
        }
    }

    return ret;
}

fn get_static_upstreams(services_config: &[ServiceConfig]) -> HashMap<String, Vec<Upstream>> {
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
                            UpstreamConfig::IPAddress(upstream) => Some(upstream.clone()),
                            UpstreamConfig::Domain { .. } => None,
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
                            UpstreamConfig::IPAddress(upstream) => Some(upstream.clone()),
                            UpstreamConfig::Domain { .. } => None,
                        })
                        .collect(),
                );
            } else {
                return (name, Vec::new());
            }
        })
        .collect()
}
