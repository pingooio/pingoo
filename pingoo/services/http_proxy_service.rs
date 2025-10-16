use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, header};
use http_body_util::combinators::BoxBody;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
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
    fn name(&self) -> String {
        self.name.to_string()
    }

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

        for header in HOP_HEADERS {
            req.headers_mut().remove(*header);
        }

        let upstream = upstreams.choose(&mut rng()).unwrap();
        let path_and_query = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("/");
        let mut upstream_tls_version = http::Version::HTTP_11;

        let uri_str = if upstream.tls {
            // TODO: use upstream socketAddress and correct SNI
            upstream_tls_version = http::Version::HTTP_2;
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
