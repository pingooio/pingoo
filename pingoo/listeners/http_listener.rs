use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc};

use ::rules::Action;
use cookie::Cookie;
use http::Request;
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::{conn::auto, graceful},
};
use tokio::sync::watch;
use tracing::{debug, error};

use crate::{
    Error,
    auth::OAuthManager,
    captcha::{CAPTCHA_VERIFIED_COOKIE, CaptchaManager, generate_captcha_client_id},
    config::ListenerConfig,
    geoip::{self, GeoipDB, GeoipRecord},
    listeners::{GRACEFUL_SHUTDOWN_TIMEOUT, Listener, accept_tcp_connection, bind_tcp_socket},
    rules,
    services::{
        HttpService,
        http_utils::{
            HOSTNAME_MAX_LENGTH, RequestContext, RequestExtensionContext, USER_AGENT_MAX_LENGTH, get_path,
            new_blocked_response, new_not_found_error,
        },
    },
};

pub struct HttpListener {
    name: Arc<String>,
    address: SocketAddr,
    socket: Option<tokio::net::TcpListener>,
    services: Arc<Vec<Arc<dyn HttpService>>>,
    rules: Arc<Vec<rules::Rule>>,
    lists: Arc<bel::Value>,
    geoip: Option<Arc<GeoipDB>>,
    captcha_manager: Arc<CaptchaManager>,
    auth_managers: Arc<HashMap<String, Arc<OAuthManager>>>,
}

impl HttpListener {
    pub fn new(
        config: ListenerConfig,
        services: Vec<Arc<dyn HttpService>>,
        rules: Arc<Vec<rules::Rule>>,
        lists: Arc<bel::Value>,
        geoip: Option<Arc<GeoipDB>>,
        captcha_manager: Arc<CaptchaManager>,
        auth_managers: Arc<HashMap<String, Arc<OAuthManager>>>,
    ) -> Self {
        return HttpListener {
            name: Arc::new(config.name),
            address: config.address,
            socket: None,
            services: Arc::new(services),
            rules,
            lists,
            geoip,
            captcha_manager,
            auth_managers,
        };
    }
}

#[async_trait::async_trait]
impl Listener for HttpListener {
    fn bind(&mut self) -> Result<(), Error> {
        let socket = bind_tcp_socket(self.address, &self.name)?;
        self.socket = Some(socket);
        return Ok(());
    }

    async fn listen(self: Box<Self>, mut shutdown_signal: watch::Receiver<()>) {
        let tcp_socket = self
            .socket
            .expect("You need to bind the listener before calling listen()");

        // GracefulShutdown watches individual connections. It can be awaited by calling `.shutdown()`
        // which resolves once all in-flight connections have completed.
        // references:
        // - https://docs.rs/hyper-util/latest/hyper_util/server/graceful/struct.GracefulShutdown.html
        // - https://github.com/hyperium/hyper-util/blob/master/examples/server_graceful.rs
        let graceful_shutdown = graceful::GracefulShutdown::new();

        loop {
            tokio::select! {
                accept_tcp_res = accept_tcp_connection(&tcp_socket, &self.name) => {
                    let (tcp_stream, client_socket_addr) = match accept_tcp_res {
                        Ok(connection) => connection,
                        Err(_) => continue,
                    };

                    tokio::task::spawn(serve_http_requests(
                        TokioIo::new(tcp_stream),
                        self.services.clone(),
                        client_socket_addr,
                        self.address,
                        self.name.clone(),
                        self.rules.clone(),
                        self.lists.clone(),
                        self.geoip.clone(),
                        self.captcha_manager.clone(),
                        self.auth_managers.clone(),
                        false,
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

pub(super) async fn serve_http_requests<IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static>(
    tcp_stream: IO,
    services: Arc<Vec<Arc<dyn HttpService>>>,
    client_socket_addr: SocketAddr,
    listener_address: SocketAddr,
    listener_name: Arc<String>,
    rules: Arc<Vec<rules::Rule>>,
    lists: Arc<bel::Value>,
    geoip: Option<Arc<GeoipDB>>,
    captcha_manager: Arc<CaptchaManager>,
    auth_managers: Arc<HashMap<String, Arc<OAuthManager>>>,
    use_tls: bool,
    graceful_shutdown_watcher: graceful::Watcher,
) {
    let hyper_handler = service_fn(move |mut req| {
        let services = services.clone();
        let rules = rules.clone();
        let lists = lists.clone();
        let geoip = geoip.clone();
        let captcha_manager = captcha_manager.clone();
        let auth_managers = auth_managers.clone();
        async move {
            let host = get_host(&req);
            let path = get_path(&req).to_string();

            let geoip_record = match geoip.as_ref() {
                Some(geoip_db) => {
                    let client_ip = client_socket_addr.ip();
                    geoip_db.lookup(client_ip).await.unwrap_or_else(|err| {
                        if !matches!(err, geoip::Error::AddressNotFound(_)) {
                            error!("geoip: error looking up ip {client_ip}: {err}")
                        }
                        GeoipRecord::default()
                    })
                }
                None => GeoipRecord::default(),
            };

            let user_agent = heapless::String::<USER_AGENT_MAX_LENGTH>::from_str(
                req.headers()
                    .get("user-agent")
                    .map(|header| header.to_str().unwrap_or_default().trim())
                    .unwrap_or_default(),
            )
            .unwrap_or_default();

            let client_id = generate_captcha_client_id(client_socket_addr.ip(), &user_agent, &host);

            let parsed_cookies = if let Some((_, cookies_header)) = req
                .headers()
                .iter()
                .find(|(header_name, _)| header_name.as_str() == "cookie")
                && let Ok(cookie_header_str) = cookies_header.to_str()
            {
                // TODO: try to avoid allocation
                Cookie::split_parse(cookie_header_str)
                    .flat_map(|cookie| cookie.ok().map(|cookie| cookie.into_owned()))
                    .collect()
            } else {
                Vec::new()
            };

            let request_context = Arc::new(RequestContext {
                client_address: client_socket_addr,
                server_address: listener_address,
                asn: geoip_record.asn,
                country: geoip_record.country,
                geoip_enabled: geoip.is_some(),
                tls: use_tls,
                host: host,
            });

            req.extensions_mut()
                .insert(RequestExtensionContext(request_context.clone()));

            if user_agent.is_empty() || user_agent.len() >= USER_AGENT_MAX_LENGTH {
                return Ok(new_blocked_response());
            }

            if path.starts_with("/__pingoo/captcha") {
                return Ok(captcha_manager
                    .serve_captcha_request(req, parsed_cookies, &client_id)
                    .await);
            }

            // apply rules
            let request_data = rules::RequestData {
                host: &request_context.host,
                path: &path,
                url: req.uri(),
                method: req.method(),
                user_agent: &user_agent,
            };
            let client_data = rules::ClientData {
                ip: request_context.client_address.ip(),
                remote_port: request_context.client_address.port(),
                asn: request_context.asn as i64,
                country: request_context.country,
            };

            // true if the captcha verified cookie is present and valid
            let mut captcha_verified = false;

            if let Some(challenge_verified_cookie) = parsed_cookies
                .iter()
                .find(|cookie| cookie.name() == CAPTCHA_VERIFIED_COOKIE)
            {
                if captcha_manager
                    .validate_captcha_verified_cookie(challenge_verified_cookie.value(), &client_id)
                    .is_ok()
                {
                    captcha_verified = true;
                } else {
                    return Ok(captcha_manager.serve_captcha());
                }
            }

            // rules_ctx is ued for both rules matching and HTTP requests routing
            let mut rules_ctx = ::rules::Context::default();
            // ctx.add_function("", value);
            // TODO: log error?
            if let Err(err) = rules_ctx.add_variable("http_request", request_data) {
                debug!("rules: error adding http_request variable: {err}")
            }
            if let Err(err) = rules_ctx.add_variable("client", &client_data) {
                debug!("rules: error adding client variable: {err}")
            }
            // TODO: is it really fast? Make sure than no extra clone for the list happen. Only Arc clones
            rules_ctx.add_variable_from_value("lists", &*lists);

            for rule in rules.as_ref() {
                if rule.match_request(&rules_ctx) {
                    for action in &rule.actions {
                        match action {
                            Action::Block {} => return Ok(new_blocked_response()),
                            Action::Captcha {} => {
                                if !captcha_verified {
                                    return Ok(captcha_manager.serve_captcha());
                                }
                            }
                        }
                    }
                }
            }

            for service in services.as_ref() {
                if service.match_request(&rules_ctx) {
                    let service_name = service.name();

                    if let Some(oauth_manager) = auth_managers.get(&service_name) {
                        if path == "/auth/callback" {
                            let callback_result =
                                crate::auth::AuthMiddleware::handle_oauth_callback(service_name, oauth_manager, &req)
                                    .await;
                            if let Some(res) = callback_result {
                                return Ok(res);
                            } else {
                                tracing::error!("Failure in callback: {:?}", callback_result);
                            }
                        }

                        if path == "/auth/logout" {
                            return Ok(crate::auth::AuthMiddleware::handle_logout(&auth_managers, &req));
                        }

                        let session_manager = oauth_manager.session_manager();

                        if let Err(auth_response) =
                            crate::auth::AuthMiddleware::handle_service_auth(session_manager, oauth_manager, &mut req)
                        {
                            return Ok(auth_response);
                        }
                    }

                    return Ok(service.handle_http_request(req).await);
                }
            }

            return Ok::<_, crate::Error>(new_not_found_error());
        }
    });

    if let Err(err) = graceful_shutdown_watcher
        .watch(auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(tcp_stream, hyper_handler))
        .await
    {
        error!(listener = listener_name.as_ref(), "error serving HTTP connection: {err:?}");
    };
}

pub fn get_host(req: &Request<hyper::body::Incoming>) -> heapless::String<HOSTNAME_MAX_LENGTH> {
    // uri.host is present for HTTP/2 requests
    if let Some(host) = req.uri().host() {
        return heapless::String::from_str(host.trim()).unwrap_or_default();
    }

    // otherwise, in HTTP/1.x it should be present in the Host header
    if let Some(host) = req.headers().get(http::header::HOST) {
        return heapless::String::from_str(host.to_str().unwrap_or_default().trim()).unwrap_or_default();
    }

    return heapless::String::new();
}
