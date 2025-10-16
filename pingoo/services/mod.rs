use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

pub mod http_proxy_service;
pub mod http_static_site_service;
pub mod http_utils;
pub mod tcp_proxy_service;

/// DynIo is a trait used to serve connections for both TCP and TCP+TLS streams
pub trait DynIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl DynIo for TcpStream {}
impl DynIo for TlsStream<TcpStream> {}

#[async_trait::async_trait]
pub trait TcpService: Send + Sync {
    // TODO: can we do without the Box?
    async fn serve_connection(
        self: Arc<Self>,
        mut inbound_tcp_connection: Box<dyn DynIo>,
        client_socket_address: SocketAddr,
    );
}

#[async_trait::async_trait]
pub trait HttpService: Send + Sync {
    fn name(&self) -> String;
    fn match_request(&self, ctx: &rules::Context) -> bool;
    async fn handle_http_request(&self, req: Request<hyper::body::Incoming>) -> Response<BoxBody<Bytes, hyper::Error>>;
}
