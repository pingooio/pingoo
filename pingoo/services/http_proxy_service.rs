use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, combinators::BoxBody};
use http_body_util::Empty;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use rand::{rng, seq::IndexedRandom};
use tracing::{debug, error, warn};

use crate::{
    config::ServiceConfig,
    service_discovery::service_registry::ServiceRegistry,
    services::{
        HttpService,
        http_utils::{RequestExtensionContext, new_bad_gateway_error},
    },
};

/// Check if the request is a WebSocket upgrade.
fn is_websocket_upgrade(req: &Request<hyper::body::Incoming>) -> bool {
    req.headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

// headers that need to be removed from the client request
// https://github.com/golang/go/blob/c39abe065886f62791f41240eef6ca03d452a17b/src/net/http/httputil/reverseproxy.go#L302
const HOP_HEADERS: &[&str] = &[
    "Connection",
    "Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Te",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

const REPONSE_HEADERS_TO_REEMOVE: &[&str] = &[
    "X-Accel-Buffering",
    "X-Accel-Charset",
    "X-Accel-Limit-Rate",
    "X-Accel-Redirect",
    "Alt-Svc",
];

pub struct HttpProxyService {
    name: Arc<String>,
    http_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, hyper::body::Incoming>,
    service_registry: Arc<ServiceRegistry>,
    route: Option<rules::CompiledExpression>,
}

impl HttpProxyService {
    pub fn new(config: ServiceConfig, service_registry: Arc<ServiceRegistry>) -> Self {
        let tls_config = rustls::ClientConfig::builder()
            .with_native_roots()
            .expect("error building TLS config")
            .with_no_client_auth();

        let mut http_connector = HttpConnector::new();
        http_connector.set_connect_timeout(Some(Duration::from_secs(4)));
        http_connector.enforce_http(false);

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector);

        let http_client: Client<_, hyper::body::Incoming> =
            Client::builder(TokioExecutor::new()).build(https_connector);

        return HttpProxyService {
            name: Arc::new(config.name),
            http_client,
            service_registry,
            route: config.route,
        };
    }
}

#[async_trait::async_trait]
impl HttpService for HttpProxyService {
    fn match_request(&self, ctx: &rules::Context) -> bool {
        match &self.route {
            None => true,
            Some(route) => match route.execute(&ctx) {
                Ok(value) => value == true.into(),
                Err(err) => {
                    warn!("error executing route for service {}: {err}", self.name);
                    false
                }
            },
        }
    }

    async fn handle_http_request(
        &self,
        mut req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let is_ws = is_websocket_upgrade(&req);

        let upstreams = self.service_registry.get_upstreams(&self.name).await;
        if upstreams.is_empty() {
            debug!("[{}]: no upstream available", self.name);
            return new_bad_gateway_error();
        }

        let request_context = req
            .extensions()
            .get::<RequestExtensionContext>()
            .expect("error getting RequestContext extension")
            .0
            .clone();

        // For WebSocket requests, preserve Connection and Upgrade headers.
        // These are hop-by-hop headers per RFC 7230, but the WebSocket protocol
        // (RFC 6455 Section 4.1) requires them to be forwarded for the upgrade handshake.
        for header in HOP_HEADERS {
            if is_ws && (*header == "Connection" || *header == "Upgrade") {
                continue;
            }
            req.headers_mut().remove(*header);
        }

        let upstream = upstreams.choose(&mut rng()).unwrap();
        let path_and_query = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
        // WebSocket upgrade must use HTTP/1.1 — HTTP/2 does not support the Upgrade mechanism.
        let upstream_tls_version = if is_ws {
            http::Version::HTTP_11
        } else if upstream.tls {
            http::Version::HTTP_2
        } else {
            http::Version::HTTP_11
        };

        let uri_str = if upstream.tls {
            // TODO: use upstream socketAddress and correct SNI
            format!("https://{}{path_and_query}", &upstream.hostname)
        } else {
            format!("http://{}{path_and_query}", &upstream.socket_address)
        };
        let uri = uri_str.parse().unwrap();

        *req.uri_mut() = uri;
        *req.version_mut() = upstream_tls_version;

        // here we forward the host from the client's request.
        // TODO: allow to configure if we forward the Host header or not (and thus use the host from the upstream).
        if let Ok(host_header) = HeaderValue::from_str(&request_context.host) {
            req.headers_mut().insert(header::HOST, host_header.clone()); // TODO: try to avoid clone
            req.headers_mut()
                .insert(HeaderName::from_static("x-forwarded-host"), host_header);
        }

        let client_ip = request_context.client_address.ip();
        let client_ip_str = Arc::new(client_ip.to_string());

        // TODO: allow users to configure if they trust the x-forwarded-for header or no
        let forwarded_for_from_client = req
            .headers()
            .get_all("x-forwarded-for")
            .iter()
            .map(|header_value| header_value.to_str().unwrap_or_default())
            .collect::<Vec<_>>();
        let forwarded_for_to_upstream = if forwarded_for_from_client.is_empty() {
            client_ip_str.clone()
        } else {
            Arc::new(forwarded_for_from_client.join(", ") + format!(", {client_ip}").as_str())
        };
        if let Ok(forwarded_for) = HeaderValue::from_str(&forwarded_for_to_upstream) {
            req.headers_mut().insert("x-forwarded-for", forwarded_for);
        }

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-Proto
        if request_context.tls {
            req.headers_mut()
                .insert("x-forwarded-proto", HeaderValue::from_static("https"));
        } else {
            req.headers_mut()
                .insert("x-forwarded-proto", HeaderValue::from_static("http"));
        }

        if let Ok(client_ip_header) = HeaderValue::from_str(&client_ip_str) {
            req.headers_mut().insert("pingoo-client-ip", client_ip_header);
        }

        if request_context.geoip_enabled {
            let request_headers = req.headers_mut();
            let country_code = &request_context.country.as_str();
            match HeaderValue::from_str(country_code) {
                Ok(country_header_value) => {
                    request_headers.insert(HeaderName::from_static("pingoo-client-country"), country_header_value);
                }
                Err(err) => error!("error converting country code ({country_code}) to HTTP header: {err}"),
            };

            match HeaderValue::from_str(request_context.asn.to_string().as_str()) {
                Ok(country_header_value) => {
                    request_headers.insert(HeaderName::from_static("pingoo-client-asn"), country_header_value);
                }
                Err(err) => error!("error converting ASN ({}) to HTTP header: {err}", request_context.asn),
            };
        }

        // ── WebSocket upgrade path ──────────────────────────────────────────
        // For WebSocket requests, we set up the client-side upgrade future before
        // forwarding, then relay bytes bidirectionally after both sides complete
        // the 101 Switching Protocols handshake.
        if is_ws {
            // Prepare the client-side upgrade future. This must be done before the
            // request is consumed by the HTTP client.
            let client_upgrade = hyper::upgrade::on(&mut req);

            let mut res = match self.http_client.request(req).await {
                Ok(res) => res,
                Err(err) => {
                    error!("WebSocket upstream request failed: {err}");
                    return new_bad_gateway_error();
                }
            };

            if res.status() != StatusCode::SWITCHING_PROTOCOLS {
                debug!("WebSocket upstream did not return 101, got {}", res.status());
                // Fall through to return whatever the upstream sent (e.g. 400, 404)
                for header in REPONSE_HEADERS_TO_REEMOVE {
                    res.headers_mut().remove(*header);
                }
                res.headers_mut().insert("server", HeaderValue::from_static("pingoo"));
                let (parts, body) = res.into_parts();
                return Response::from_parts(parts, BoxBody::new(body));
            }

            // Upstream returned 101 — set up the bidirectional relay.
            let upstream_upgrade = hyper::upgrade::on(&mut res);

            // Build the 101 response to send back to the client, preserving
            // the Sec-WebSocket-Accept and other upgrade headers from upstream.
            let mut client_response = Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS);

            // Copy relevant headers from upstream 101 response
            for (name, value) in res.headers() {
                // Forward all headers except the ones we manage
                if name != "server" {
                    client_response = client_response.header(name.clone(), value.clone());
                }
            }
            client_response = client_response.header("server", "pingoo");

            let service_name = self.name.clone();

            // Spawn a background task to relay bytes between client and upstream
            // once both sides have completed the protocol upgrade.
            tokio::spawn(async move {
                let (client_io, upstream_io) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok(io) => io,
                    Err(err) => {
                        error!("[{}]: WebSocket upgrade handshake failed: {err}", service_name);
                        return;
                    }
                };

                let mut client_io = TokioIo::new(client_io);
                let mut upstream_io = TokioIo::new(upstream_io);

                match tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
                    Ok((client_to_upstream, upstream_to_client)) => {
                        debug!(
                            "[{}]: WebSocket closed (client→upstream: {} bytes, upstream→client: {} bytes)",
                            service_name, client_to_upstream, upstream_to_client
                        );
                    }
                    Err(err) => {
                        debug!("[{}]: WebSocket relay ended: {err}", service_name);
                    }
                }
            });

            let body: BoxBody<Bytes, hyper::Error> = BoxBody::new(Empty::new().map_err(|never| match never {}));
            return client_response.body(body).unwrap();
        }

        // ── Normal HTTP proxy path ──────────────────────────────────────────
        let mut res = match self.http_client.request(req).await {
            Ok(res) => res,
            Err(_) => return new_bad_gateway_error(),
        };

        for header in REPONSE_HEADERS_TO_REEMOVE {
            res.headers_mut().remove(*header);
        }

        res.headers_mut().insert("server", HeaderValue::from_static("pingoo"));

        let (parts, body) = res.into_parts();
        let boxed_body: BoxBody<Bytes, hyper::Error> = BoxBody::new(body);
        // Ok(Response::from_parts(parts, boxed_body))
        return Response::from_parts(parts, boxed_body);
    }
}
