use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use hyper_util::{rt::TokioIo, server::graceful};
use tokio::sync::watch;
use tracing::debug;

use crate::{
    Error,
    auth::OAuthManager,
    captcha::CaptchaManager,
    config::ListenerConfig,
    geoip::GeoipDB,
    listeners::{
        GRACEFUL_SHUTDOWN_TIMEOUT, Listener, accept_tcp_connection, accept_tls_connection, bind_tcp_socket,
        http_listener::serve_http_requests,
    },
    rules::Rule,
    services::HttpService,
    tls::{TLS_ALPN_HTTP2, TLS_ALPN_HTTP11, TlsManager},
};

pub struct HttpsListener {
    name: Arc<String>,
    address: SocketAddr,
    socket: Option<tokio::net::TcpListener>,
    services: Arc<Vec<Arc<dyn HttpService>>>,
    tls_manager: Arc<TlsManager>,
    rules: Arc<Vec<Rule>>,
    lists: Arc<bel::Value>,
    geoip: Option<Arc<GeoipDB>>,
    captcha_manager: Arc<CaptchaManager>,
    auth_managers: Arc<HashMap<String, Arc<OAuthManager>>>,
}

impl HttpsListener {
    pub fn new(
        config: ListenerConfig,
        tls_manager: Arc<TlsManager>,
        services: Vec<Arc<dyn HttpService>>,
        rules: Arc<Vec<Rule>>,
        lists: Arc<bel::Value>,
        geoip: Option<Arc<GeoipDB>>,
        captcha_manager: Arc<CaptchaManager>,
        auth_managers: Arc<HashMap<String, Arc<OAuthManager>>>,
    ) -> Self {
        return HttpsListener {
            name: Arc::new(config.name),
            address: config.address,
            socket: None,
            services: Arc::new(services),
            tls_manager,
            rules,
            lists,
            geoip,
            captcha_manager,
            auth_managers,
        };
    }
}

#[async_trait::async_trait]
impl Listener for HttpsListener {
    fn bind(&mut self) -> Result<(), Error> {
        let socket = bind_tcp_socket(self.address, &self.name)?;
        self.socket = Some(socket);
        return Ok(());
    }

    async fn listen(self: Box<Self>, mut shutdown_signal: watch::Receiver<()>) {
        let tcp_socket = self
            .socket
            .expect("You need to bind the listener before calling listen()");

        // see HTTP listener to learn how graceful shutdown works for HTTP requests
        let graceful_shutdown = graceful::GracefulShutdown::new();

        let tls_server_config = self
            .tls_manager
            .get_tls_server_config([TLS_ALPN_HTTP2.to_vec(), TLS_ALPN_HTTP11.to_vec()]);

        loop {
            tokio::select! {
                accept_tcp_res = accept_tcp_connection(&tcp_socket, &self.name) => {
                    let (tcp_stream, client_socket_addr) = match accept_tcp_res {
                        Ok(connection) => connection,
                        Err(_) => continue,
                    };

                    let tls_stream = match accept_tls_connection(
                        tcp_stream,
                        self.tls_manager.clone(),
                        client_socket_addr,
                        &self.name,
                        tls_server_config.clone(),
                    )
                    .await
                    {
                        Ok(Some(tls_stream)) => tls_stream,
                        _ => continue,
                    };

                    tokio::spawn(serve_http_requests(
                        TokioIo::new(tls_stream),
                        self.services.clone(),
                        client_socket_addr,
                        self.address,
                        self.name.clone(),
                        self.rules.clone(),
                        self.lists.clone(),
                        self.geoip.clone(),
                        self.captcha_manager.clone(),
                        self.auth_managers.clone(),
                        true,
                        graceful_shutdown.watcher(),
                    ));
                },
                _ = shutdown_signal.changed() => {
                    break;
                }
            }
        }

        tokio::select! {
            _ = graceful_shutdown.shutdown() => {
                debug!("listener {} has gracefully shut down", self.name);
            },
            _ = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {}
        }
    }
}
