use std::{net::SocketAddr, sync::Arc};

use tokio::{sync::watch, task::JoinSet};
use tracing::debug;

use crate::{
    Error,
    config::ListenerConfig,
    listeners::{GRACEFUL_SHUTDOWN_TIMEOUT, Listener, accept_tcp_connection, accept_tls_connection, bind_tcp_socket},
    services::TcpService,
    tls::TlsManager,
};

pub struct TcpAndTlsListener {
    name: String,
    address: SocketAddr,
    socket: Option<tokio::net::TcpListener>,
    cert_manager: Arc<TlsManager>,
    service: Arc<dyn TcpService>,
}

impl TcpAndTlsListener {
    pub fn new(config: ListenerConfig, cert_manager: Arc<TlsManager>, service: Arc<dyn TcpService>) -> Self {
        return TcpAndTlsListener {
            name: config.name,
            address: config.address,
            socket: None,
            cert_manager,
            service,
        };
    }
}

#[async_trait::async_trait]
impl Listener for TcpAndTlsListener {
    fn bind(&mut self) -> Result<(), Error> {
        let socket = bind_tcp_socket(self.address, &self.name)?;
        self.socket = Some(socket);
        return Ok(());
    }

    async fn listen(self: Box<Self>, mut shutdown_signal: watch::Receiver<()>) {
        let tcp_socket = self
            .socket
            .expect("You need to bind the listener before calling listen()");

        let mut connections: JoinSet<_> = JoinSet::new();

        let tls_server_config = self.cert_manager.get_tls_server_config([]);

        loop {
            tokio::select! {
                accept_tcp_res = accept_tcp_connection(&tcp_socket, &self.name) => {
                    let (tcp_stream, client_socket_addr) = match accept_tcp_res {
                        Ok(connection) => connection,
                        Err(_) => continue,
                    };

                    if let Ok(Some(tls_stream)) =
                        accept_tls_connection(tcp_stream, self.cert_manager.clone(), client_socket_addr, &self.name, tls_server_config.clone()).await
                    {
                        let service = self.service.clone();
                        connections.spawn(service.serve_connection(Box::new(tls_stream), client_socket_addr));
                    };
                },
                 _ = shutdown_signal.changed() => {
                    break;
                }
            }
        }

        // TODO: should we use connections.shutdown()?
        tokio::select! {
            _ = connections.join_all() => {
                debug!("listener {} has gracefully shut down", self.name);
            },
            _ = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {}
        }
    }
}
