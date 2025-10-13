use docker::model::ListContainersOptions;
use moka::future::Cache;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{fs, sync::Mutex};
use tracing::{info, warn};

use crate::{
    Error,
    config::ServiceDiscoveryConfig,
    service_discovery::service_registry::{ServiceDiscoverer, Upstream},
};

pub struct DockerServiceDiscoverer {
    docker_client: Option<Arc<Mutex<::docker::Client>>>,
    /// containers that have a problem and we have already issued a warning, to avoid flooding the logs
    /// we use a cache to avoid memory leaks where containers would add up and never be freed.
    warned_containers: Cache<String, ()>,
}

impl DockerServiceDiscoverer {
    pub async fn new(config: &ServiceDiscoveryConfig) -> Result<Self, Error> {
        let docker_client = match fs::metadata(&config.docker.socket).await {
            Ok(_) => Ok(Some(Arc::new(Mutex::new(::docker::Client::new(Some(&config.docker.socket)))))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    "docker socket ({}) not found. Docker service discovery disabled.",
                    config.docker.socket
                );
                Ok(None)
            }
            Err(err) => Err(Error::Config(format!("error reading docker socket: {err}"))),
        }?;

        let warned_containers = Cache::builder().time_to_idle(Duration::from_secs(600)).build();

        return Ok(DockerServiceDiscoverer {
            docker_client,
            warned_containers,
        });
    }
}

#[async_trait::async_trait]
impl ServiceDiscoverer for DockerServiceDiscoverer {
    async fn discover(&self) -> Result<HashMap<String, Vec<Upstream>>, Error> {
        let mut new_upstreams = HashMap::new();
        if self.docker_client.is_none() {
            return Ok(new_upstreams);
        }

        let mut docker_filters = HashMap::new();
        docker_filters.insert("label".to_string(), vec!["pingoo.service".to_string()]);
        let containers = self
            .docker_client
            .as_ref()
            .unwrap()
            .lock()
            .await
            .list_containers(Some(ListContainersOptions {
                filters: docker_filters,
                ..Default::default()
            }))
            .await
            .map_err(|err| Error::Unspecified(format!("discovering Docker services: {err}")))?;

        for container in containers {
            // container.
            let container_id = container.id.unwrap_or_default();
            let labels = container.labels.unwrap_or_default();
            if labels.get("pingoo.service").is_none() {
                continue;
            }
            let pingoo_service_name = labels.get("pingoo.service").unwrap();

            // if the label pingoo.port is present, use it
            let port = match labels.get("pingoo.port") {
                Some(port_str) => match port_str.parse::<u16>() {
                    Ok(port) => port,
                    Err(err) => {
                        if !self.warned_containers.contains_key(&container_id) {
                            warn!(
                                "pingoo.port={port_str} is not valid for service {pingoo_service_name} (container: {container_id}): {err}"
                            );
                            self.warned_containers.insert(container_id, ()).await;
                        }
                        continue;
                    }
                },
                None => {
                    // otherwise, use the exposed ports
                    match container.ports {
                        Some(ports) if ports.len() > 0 => {
                            // we currently use the first exposed port
                            ports[0].private_port
                        }
                        _ => {
                            if !self.warned_containers.contains_key(&container_id) {
                                warn!("no port found for service {pingoo_service_name} (container: {container_id})");
                                self.warned_containers.insert(container_id, ()).await;
                            }
                            continue;
                        }
                    }
                }
            };

            let container_ip = container
                .network_settings
                .map(|network_settings| network_settings.networks.unwrap_or_default())
                .unwrap_or_default()
                .get("bridge")
                .map(|endpoint_settings| endpoint_settings.ip_address.clone().unwrap_or_default());
            if container_ip.is_none() {
                if !self.warned_containers.contains_key(&container_id) {
                    warn!(
                        "container {} (service: {pingoo_service_name}) has no ip address for the bridge network",
                        &container_id
                    );
                    self.warned_containers.insert(container_id, ()).await;
                }
                continue;
            }

            let container_ip_str = container_ip.unwrap();
            let container_ip: IpAddr = match container_ip_str.parse() {
                Ok(ip) => ip,
                Err(err) => {
                    if !self.warned_containers.contains_key(&container_id) {
                        warn!(
                            "container {container_id} (service: {pingoo_service_name}) has not a valid IP address ({container_ip_str}): {err}",
                        );
                        self.warned_containers.insert(container_id, ()).await;
                    }
                    continue;
                }
            };

            // this container is valid, we can remove it from the warned containers
            if self.warned_containers.contains_key(&container_id) {
                self.warned_containers.remove(&container_id).await;
            }

            new_upstreams
                .entry(pingoo_service_name.clone())
                .or_insert(Vec::new())
                .push(Upstream {
                    socket_address: SocketAddr::new(container_ip, port),
                    tls: false,
                    hostname: container_id,
                });
        }

        return Ok(new_upstreams);
    }
}
