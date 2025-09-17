use std::{net::SocketAddr, sync::Arc};

use crate::{
    Error,
    config::ListenerConfig,
    listeners::{Listener, accept_tcp_connection, accept_tls_connection, bind_tcp_socket},
    services::TcpService,
    tls::CertManager,
};

pub struct TcpAndTlsListener {
    name: String,
    address: SocketAddr,
    socket: Option<tokio::net::TcpListener>,
    cert_manager: Arc<CertManager>,
    service: Arc<dyn TcpService>,
}

impl TcpAndTlsListener {
    pub fn new(config: ListenerConfig, cert_manager: Arc<CertManager>, service: Arc<dyn TcpService>) -> Self {
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

    async fn listen(self: Box<Self>) {
        let tcp_socket = self
            .socket
            .expect("You need to bind the listener before calling listen()");

        loop {
            let (tcp_stream, client_socket_addr) = match accept_tcp_connection(&tcp_socket, &self.name).await {
                Ok(connection) => connection,
                Err(_) => continue,
            };

            if let Ok(tls_stream) =
                accept_tls_connection(tcp_stream, self.cert_manager.clone(), client_socket_addr, &self.name).await
            {
                let service = self.service.clone();
                tokio::task::spawn(service.serve_connection(Box::new(tls_stream), client_socket_addr));
            };
        }
    }
}
