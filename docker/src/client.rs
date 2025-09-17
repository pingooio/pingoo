use std::path::PathBuf;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, StatusCode, Uri,
    client::conn::http1::SendRequest,
    header::{CONTENT_TYPE, HOST},
};
use hyper_util::rt::TokioIo;
use serde::{Serialize, de::DeserializeOwned};
use tokio::{net::UnixStream, sync::Mutex};
use tracing::{debug, error};

use crate::{DEFAULT_DOCKER_SOCKET, error::Error};

pub struct Client {
    socket_path: PathBuf,
    // we use the interior mutability pattern to avoid users needing to make the client mut
    // each time they want to send a request.
    // See here to learn more about the Interior Mutability Pattern
    // https://doc.rust-lang.org/book/ch15-05-interior-mutability.html
    // socket: Arc<Mutex<RefCell<Option<SendRequest<Full<Bytes>>>>>>,
    socket: Mutex<Option<SendRequest<Full<Bytes>>>>,
}

impl Client {
    pub fn new(socket_path: Option<&str>) -> Client {
        let socket_path = socket_path.unwrap_or(DEFAULT_DOCKER_SOCKET);
        let socket_path = PathBuf::from(socket_path);

        return Client {
            socket_path: socket_path,
            socket: Mutex::new(None),
        };
    }

    /// connect to the docker host.
    /// Note that you don't necessarily need to call `connect`. The client automatically connects
    /// to the Docker host on the first request if `connect` is not called before.
    pub async fn connect(&self) -> Result<(), Error> {
        if self.socket.lock().await.is_some() {
            return Ok(());
        }

        let unix_stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|err| Error::Connecting(err.into()))?;
        let stream = TokioIo::new(unix_stream);

        let (sender, conn) = hyper::client::conn::http1::handshake(stream)
            .await
            .map_err(|err| Error::Connecting(err.into()))?;
        debug!("connection established");

        // spawn a task to poll the connection and drive the HTTP state
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                error!("connection error: {:?}", err);
            }
        });

        self.socket.lock().await.replace(sender);

        return Ok(());
    }

    pub(crate) async fn send_request<R: DeserializeOwned, S: Serialize>(
        &self,
        path: &str,
        query: Option<S>,
        body: Option<S>,
    ) -> Result<R, Error> {
        if self.socket.lock().await.is_none() {
            self.connect().await?;
        }

        // first we need to prepare the request for hyper
        let path_and_query = match query {
            Some(query_params) => {
                let query_string = serde_urlencoded::to_string(query_params)
                    .map_err(|err| Error::Unspecified(format!("encoding request's query parameters: {err}")))?;
                format!("{path}?{query_string}")
            }
            None => path.to_string(),
        };

        let hyper_uri = Uri::builder()
            .scheme("unix")
            .authority("docker")
            .path_and_query(path_and_query)
            .build()
            .map_err(|err| Error::Unspecified(format!("building request's URL: {err}")))?;

        let body = body
            .map(|body_data| serde_json::to_vec(&body_data))
            .unwrap_or(Ok(Vec::new()))
            .map_err(|err| Error::Unspecified(format!("encoding body to JSON: {err}")))?;
        let body_bytes = Bytes::from(body);

        let hyper_request = hyper::Request::builder()
            .method(Method::GET)
            .uri(hyper_uri)
            .header(HOST, "docker")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(body_bytes))
            .map_err(|err| Error::Unspecified(format!("building request: {err}")))?;

        let response = {
            let mut socket = self.socket.lock().await;
            // we can safely unwrap here as `connect` would have returned an error earlier if the connection
            // failed
            socket
                .as_mut()
                .unwrap()
                .send_request(hyper_request)
                .await
                .map_err(|err| Error::Unspecified(format!("sending request: {err}")))?
        };

        if response.status() != StatusCode::OK {
            return Err(Error::Unspecified(format!(
                "received not OK status code: {}",
                response.status()
            )));
        }

        // let mut response_body = BytesMut::with_capacity(response.size_hint().upper().unwrap_or(500) as usize);
        // while let Some(next) = response.frame().await {
        //     let frame = next.map_err(|err| Error::Unspecified(format!("reading response: {err}")))?;
        //     if let Some(chunk) = frame.data_ref() {
        //         response_body.put(chunk.as_ref());
        //     }
        // }

        let response_body = response
            .collect()
            .await
            .map_err(|err| Error::Unspecified(format!("reading response: {err}")))?
            .to_bytes();
        let res = serde_json::from_slice(&response_body)
            .map_err(|err| Error::Unspecified(format!("parsing response: {err}")))?;

        return Ok(res);
    }
}
