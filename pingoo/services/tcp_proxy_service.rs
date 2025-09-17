use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::FutureExt;
use rand::{rng, seq::IndexedRandom};
use tokio::{
    net::TcpStream,
    time::{self, timeout},
};
use tracing::{debug, error};

use crate::{
    Error,
    service_discovery::service_registry::ServiceRegistry,
    services::{DynIo, TcpService},
};

pub struct TcpProxyService {
    name: String,
    service_registry: Arc<ServiceRegistry>,
}

impl TcpProxyService {
    pub fn new(name: String, service_registry: Arc<ServiceRegistry>) -> Self {
        return TcpProxyService { name, service_registry };
    }
}

#[async_trait::async_trait]
impl TcpService for TcpProxyService {
    async fn serve_connection(
        self: Arc<Self>,
        mut inbound_tcp_connection: Box<dyn DynIo>,
        _client_socket_address: SocketAddr,
    ) {
        let mut outbound_stream = match retry(
            || {
                let self = self.clone();
                async move {
                    let upstreams = self.service_registry.get_upstreams(&self.name).await;
                    if upstreams.is_empty() {
                        return Err(Error::Unspecified("no upstream available".to_string()));
                    }

                    let upstream = upstreams.choose(&mut rng()).unwrap();

                    let tcp_stream =
                        match timeout(Duration::from_secs(3), TcpStream::connect(upstream.socket_address)).await {
                            Ok(Ok(stream)) => Ok(stream),
                            Ok(Err(err)) => Err(Error::Unspecified(format!(
                                "error connecting to upstream {}: {err}",
                                upstream.socket_address
                            ))),
                            Err(_) => Err(Error::Unspecified(format!(
                                "error connecting to upstream {}: timeout",
                                upstream.socket_address
                            ))),
                        }?;

                    Ok(tcp_stream)
                }
            },
            3,
            Duration::from_millis(5),
        )
        .await
        {
            Ok(stream) => stream,
            Err(err) => {
                debug!("[{}]: {err}", self.name,);
                return;
            }
        };

        tokio::spawn(async move {
            tokio::io::copy_bidirectional(&mut inbound_tcp_connection, &mut outbound_stream)
                .map(|r| {
                    if let Err(e) = r {
                        error!("Failed to transfer; error={e}");
                    }
                })
                .await
        });
    }
}

pub async fn retry<F, Fut, T>(mut operation: F, retries: usize, delay: Duration) -> Result<T, Error>
where
    // `F` is a mutable callable that produces a future each time it’s invoked.
    F: FnMut() -> Fut,
    // The future must be `Send` because we’ll await it inside an async context.
    Fut: Future<Output = Result<T, Error>> + Send,
{
    let mut attempt = 0;

    loop {
        attempt += 1;
        match operation().await {
            Ok(val) => return Ok(val),
            Err(_) if attempt < retries => {
                // If we still have attempts left, wait then try again.
                if !delay.is_zero() {
                    time::sleep(delay).await;
                }
                // Continue looping for the next attempt.
            }
            Err(err) => {
                // No more retries left – return the last error.
                return Err(err);
            }
        }
    }
}
