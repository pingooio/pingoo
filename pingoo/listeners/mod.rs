use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rustls::{ServerConfig, server::Acceptor};
use socket2::{Domain, Socket, Type};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::watch};
use tokio_rustls::{LazyConfigAcceptor, server::TlsStream};
use tracing::debug;

use crate::{
    Error,
    tls::{TlsManager, acme::is_tls_alpn_challenge},
};

mod http_listener;
mod https_listener;
mod tcp_listener;
mod tcp_tls_listener;

pub use http_listener::HttpListener;
pub use https_listener::HttpsListener;
pub use tcp_listener::TcpListener;
pub use tcp_tls_listener::TcpAndTlsListener;

pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Listeners handle connections and dispatch HTTP requests to services
#[async_trait::async_trait]
pub trait Listener: Send + Sync {
    fn bind(&mut self) -> Result<(), Error>;
    async fn listen(self: Box<Self>, shutdown_signal: watch::Receiver<()>);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// utils
////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn bind_tcp_socket(address: SocketAddr, listener_name: &str) -> Result<tokio::net::TcpListener, Error> {
    // configure the socket to use the SO_REUSEADDR and SO_REUSEPORT options
    let socket_domain = match &address.ip() {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket2_socket = Socket::new(socket_domain, Type::STREAM, None).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;
    socket2_socket.set_nonblocking(true).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;
    socket2_socket.set_reuse_port(true).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;
    socket2_socket.set_reuse_address(true).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;

    socket2_socket.bind(&address.into()).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;
    // tokio's TcpListener::bind use a value of 1024
    socket2_socket.listen(2048).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;

    // convert the socket2 Socket into tokio TcpListener
    let std_listener: std::net::TcpListener = socket2_socket.into();
    std_listener.set_nonblocking(true).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;
    let listener = tokio::net::TcpListener::from_std(std_listener).map_err(|err| Error::Listening {
        listener: listener_name.to_string(),
        address: address,
        err: err,
    })?;
    return Ok(listener);
}

async fn accept_tcp_connection(
    listener: &tokio::net::TcpListener,
    listener_name: &str,
) -> Result<(TcpStream, SocketAddr), ()> {
    let connection = match listener.accept().await {
        Ok(connection) => connection,
        Err(err) => {
            debug!(listener = listener_name, "error accepting TCP connection: {err}",);
            return Err(());
        }
    };

    debug!(listener = listener_name, client = ?connection.1,"TCP connection accepted");
    return Ok(connection);
}

// returns Ok(None) if it's an ACME tls-alpn-01 connection
async fn accept_tls_connection<IO: Unpin + tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static>(
    tcp_stream: IO,
    tls_manager: Arc<TlsManager>,
    client_socket_addr: SocketAddr,
    listener_name: &str,
    tls_server_config: Arc<ServerConfig>,
) -> Result<Option<TlsStream<IO>>, ()> {
    let tls_start_handshake = match LazyConfigAcceptor::new(Acceptor::default(), tcp_stream).await {
        Ok(tls_start_handshake) => tls_start_handshake,
        Err(err) => {
            debug!(listener = listener_name, client = ?client_socket_addr, "error accepting TLS connection: {err:?}");
            return Err(());
        }
    };

    let client_hello = tls_start_handshake.client_hello();

    // handle ACME tls-alpn-01 challenges
    if is_tls_alpn_challenge(&client_hello) {
        let tls_config_acme = tls_manager.get_tls_alpn_01_server_config(&client_hello).await;
        let mut stream = match tls_start_handshake.into_stream(tls_config_acme).await {
            Ok(stream) => stream,
            Err(err) => {
                debug!(listener = listener_name, client = ?client_socket_addr, "error converting TLS stream to TCP stream for ACME: {err:?}");
                return Err(());
            }
        };
        let _ = stream.shutdown().await;
        return Ok(None);
    }

    let tcp_stream = match tls_start_handshake.into_stream(tls_server_config).await {
        Ok(tcp_stream) => tcp_stream,
        Err(err) => {
            debug!(listener = listener_name, client = ?client_socket_addr, "error converting TLS stream to TCP stream: {err:?}");
            return Err(());
        }
    };

    debug!(listener = listener_name, client = ?client_socket_addr, "TLS connection accepted");

    return Ok(Some(tcp_stream));
}
