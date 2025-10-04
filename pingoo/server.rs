use std::{collections::HashMap, sync::Arc};

use tokio::{sync::watch, task::JoinSet};

use crate::{
    captcha::CaptchaManager,
    geoip::GeoipDB,
    listeners::Listener,
    lists::load_lists,
    service_discovery::service_registry::ServiceRegistry,
    services::{HttpService, TcpService, http_utils::new_http_service, tcp_proxy_service::TcpProxyService},
};
use tracing::info;

use crate::{
    config::{Config, ListenerProtocol},
    error::Error,
    listeners::{self},
    tls::TlsManager,
};

/// The Server binds the listeners.
#[derive(Debug)]
pub struct Server {
    config: Config,
}

impl Server {
    pub fn new(config: Config) -> Server {
        return Server { config: config };
    }

    pub async fn run(self, shutdown_signal: watch::Receiver<()>) -> Result<(), Error> {
        let mut listeners_handles = JoinSet::new();

        let service_registry =
            Arc::new(ServiceRegistry::new(&self.config.service_discovery, &self.config.services).await?);
        service_registry.clone().start_in_background();

        let geoip_db = Some(Arc::new(GeoipDB::new().await?));

        let captcha_manager = Arc::new(CaptchaManager::new().await?);

        let lists = load_lists(&self.config.lists).await?;

        let tcp_services: HashMap<String, Arc<dyn TcpService>> = self
            .config
            .services
            .iter()
            .filter(|service_config| service_config.tcp_proxy.is_some())
            .map(|service_config| {
                (
                    service_config.name.clone(),
                    Arc::new(TcpProxyService::new(service_config.name.clone(), service_registry.clone()))
                        as Arc<dyn TcpService>,
                )
            })
            .collect();

        let http_services: HashMap<String, Arc<dyn HttpService>> = self
            .config
            .services
            .into_iter()
            .filter(|service_config| service_config.http_proxy.is_some() || service_config.r#static.is_some())
            .map(|service_config| {
                (
                    service_config.name.clone(),
                    new_http_service(service_config, service_registry.clone()),
                )
            })
            .collect();

        let rules = Arc::new(self.config.rules);

        let tls_manager = Arc::new(TlsManager::new(&self.config.tls).await?);
        tls_manager.start_acme_in_background();

        for listener_config in self.config.listeners {
            let listener_address = listener_config.address;
            let listener_name = listener_config.name.clone();
            let listener_protocol = listener_config.protocol;

            let mut listener: Box<dyn Listener> = match listener_protocol {
                ListenerProtocol::Tcp => {
                    let tcp_service_for_listener = tcp_services
                        .get(&listener_config.services[0])
                        .expect("TCP service not found for tcp listener")
                        .clone();
                    Box::new(listeners::TcpListener::new(listener_config, tcp_service_for_listener))
                }
                ListenerProtocol::TcpAndTls => {
                    let tcp_service_for_listener = tcp_services
                        .get(&listener_config.services[0])
                        .expect("TCP service not found for tcp+tls listener")
                        .clone();
                    Box::new(listeners::TcpAndTlsListener::new(
                        listener_config,
                        tls_manager.clone(),
                        tcp_service_for_listener,
                    ))
                }
                ListenerProtocol::Http => {
                    let http_services_for_listener = listener_config
                        .services
                        .iter()
                        .map(|service| http_services.get(service).unwrap().clone())
                        .collect();
                    Box::new(listeners::HttpListener::new(
                        listener_config,
                        http_services_for_listener,
                        rules.clone(),
                        lists.clone(),
                        geoip_db.clone(),
                        captcha_manager.clone(),
                    ))
                }
                ListenerProtocol::Https => {
                    let http_services_for_listener = listener_config
                        .services
                        .iter()
                        .map(|service| http_services.get(service).unwrap().clone())
                        .collect();
                    Box::new(listeners::HttpsListener::new(
                        listener_config,
                        tls_manager.clone(),
                        http_services_for_listener,
                        rules.clone(),
                        lists.clone(),
                        geoip_db.clone(),
                        captcha_manager.clone(),
                    ))
                }
            };

            info!("Starting listener {listener_name} on {listener_protocol}://{listener_address}");

            listener.bind()?;
            listeners_handles.spawn(listener.listen(shutdown_signal.clone()));
        }

        listeners_handles.join_all().await;

        return Ok(());
    }
}
