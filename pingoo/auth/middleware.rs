use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{Error, body::Incoming};

use super::{OAuthManager, SessionManager};

pub struct AuthMiddleware {
    session_manager: Arc<SessionManager>,
    oauth_manager: Option<Arc<OAuthManager>>,
    required: bool,
    public_paths: Vec<String>,
}

pub struct AuthMiddlewareConfig {
    pub required: bool,
    pub public_paths: Vec<String>,
}

impl Default for AuthMiddlewareConfig {
    fn default() -> Self {
        Self {
            required: true,
            public_paths: vec![
                "/health".to_string(),
                "/auth/login".to_string(),
                "/auth/callback".to_string(),
                "/auth/logout".to_string(),
            ],
        }
    }
}

impl AuthMiddleware {
    pub fn new(
        session_manager: Arc<SessionManager>,
        oauth_manager: Option<Arc<OAuthManager>>,
        config: AuthMiddlewareConfig,
    ) -> Self {
        Self {
            session_manager,
            oauth_manager,
            required: config.required,
            public_paths: config.public_paths,
        }
    }

    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| path.starts_with(p))
    }

    pub async fn authenticate(
        &self,
        mut req: Request<Incoming>,
    ) -> Result<Request<Incoming>, Response<BoxBody<Bytes, Error>>> {
        let path = req.uri().path();

        if self.is_public_path(path) {
            return Ok(req);
        }

        if !self.required && self.oauth_manager.is_none() {
            return Ok(req);
        }

        match self.session_manager.get_session(&req) {
            Ok(session) => {
                Self::add_user_headers(&mut req, &session);
                self.session_manager.update_last_seen(&req);
                Ok(req)
            }
            Err(_) => {
                if self.oauth_manager.is_some() && self.required {
                    let oauth = self.oauth_manager.as_ref().unwrap();
                    match oauth.start_auth_flow(&req) {
                        Ok(redirect_response) => {
                            let (parts, body) = redirect_response.into_parts();
                            let boxed_body = http_body_util::Full::new(Bytes::from(body))
                                .map_err(|never| match never {})
                                .boxed();
                            Err(Response::from_parts(parts, boxed_body))
                        }
                        Err(e) => {
                            Err(self.error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("OAuth error: {}", e)))
                        }
                    }
                } else if self.required {
                    Err(self.error_response(StatusCode::UNAUTHORIZED, "Authentication required"))
                } else {
                    Ok(req)
                }
            }
        }
    }

    pub fn handle_service_auth<B>(
        session_manager: &Arc<SessionManager>,
        oauth_manager: &Arc<OAuthManager>,
        req: &mut Request<B>,
    ) -> Result<(), Response<BoxBody<Bytes, Error>>> {
        match session_manager.get_session(req) {
            Ok(session) => {
                Self::add_user_headers(req, &session);
                session_manager.update_last_seen(req);
                Ok(())
            }
            Err(_) => match oauth_manager.start_auth_flow(req) {
                Ok(redirect_response) => {
                    let (parts, body) = redirect_response.into_parts();
                    let boxed_body = http_body_util::Full::new(Bytes::from(body))
                        .map_err(|never| match never {})
                        .boxed();
                    Err(Response::from_parts(parts, boxed_body))
                }
                Err(_e) => {
                    let error_body = http_body_util::Full::new(Bytes::from("Authentication error"))
                        .map_err(|never| match never {})
                        .boxed();
                    Err(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(error_body)
                        .unwrap())
                }
            },
        }
    }

    pub async fn handle_oauth_callback<B>(
        _service_name: String,
        auth_manager: &Arc<OAuthManager>,
        req: &Request<B>,
    ) -> Option<Response<BoxBody<Bytes, Error>>> {
        let query = req.uri().query()?;

        let code_state_result = extract_state_code(query);
        if let Err(err) = code_state_result {
            return Some(Self::build_error_response(StatusCode::BAD_REQUEST, format!("Callback error: {err}").as_str()));
        }
        let (code, state) = code_state_result.unwrap();

        if auth_manager.session_manager().get_oauth_state(state).is_some() {
            return match auth_manager.handle_callback(code, state).await {
                Ok((session, original_url)) => {
                    let mut response = Response::builder()
                        .status(StatusCode::FOUND)
                        .header(header::LOCATION, original_url)
                        .body(
                            http_body_util::Full::new(Bytes::new())
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap();

                    if let Err(_e) = auth_manager
                        .session_manager()
                        .set_session_cookie(&mut response, &session)
                    {
                        return Some(Self::build_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Authentication failed",
                        ));
                    }

                    Some(response)
                }
                Err(_e) => Some(Self::build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication failed",
                )),
            };
        }

        Some(Self::build_error_response(
            StatusCode::BAD_REQUEST,
            "Invalid callback: state not found or expired",
        ))
    }

    pub fn handle_logout<B>(
        auth_managers: &std::collections::HashMap<String, Arc<OAuthManager>>,
        req: &Request<B>,
    ) -> Response<BoxBody<Bytes, Error>> {
        let mut temp_req_builder = Request::builder();

        for (name, value) in req.headers() {
            temp_req_builder = temp_req_builder.header(name, value);
        }

        let temp_req = temp_req_builder
            .uri(req.uri().clone())
            .method(req.method().clone())
            .version(req.version())
            .body(())
            .unwrap();

        let mut temp_response = Response::new(());

        for (_service_name, oauth_manager) in auth_managers {
            let _ = oauth_manager
                .session_manager()
                .delete_session(&temp_req, &mut temp_response);
        }

        let (parts, _body) = temp_response.into_parts();
        let mut response_builder = Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/");

        for (name, value) in parts.headers {
            if let Some(name) = name {
                response_builder = response_builder.header(name, value);
            }
        }

        response_builder
            .body(
                http_body_util::Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }

    fn build_error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, Error>> {
        let error_body = http_body_util::Full::new(Bytes::from(message.to_string()))
            .map_err(|never| match never {})
            .boxed();
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(error_body)
            .unwrap()
    }

    fn add_user_headers<B>(req: &mut Request<B>, session: &super::session::Session) {
        req.headers_mut().insert(
            "X-User-ID",
            session
                .user_id
                .parse()
                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
        );
        req.headers_mut().insert(
            "X-User-Email",
            session
                .email
                .parse()
                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
        );
        req.headers_mut().insert(
            "X-User-Name",
            session
                .name
                .parse()
                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
        );
    }

    fn error_response(&self, status: StatusCode, message: &str) -> Response<BoxBody<Bytes, Error>> {
        let body = http_body_util::Full::new(Bytes::from(message.to_string()))
            .map_err(|never| match never {})
            .boxed();

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(body)
            .unwrap()
    }
}

fn extract_state_code(qry_string: &str) -> Result<(&str, &str), String> {
    let code = qry_string
        .split('&')
        .find(|p| p.starts_with("code="))
        .and_then(|p| p.strip_prefix("code="));

    let state = qry_string
        .split('&')
        .find(|p| p.starts_with("state="))
        .and_then(|p| p.strip_prefix("state="));

    if let Some(code) = code
        && let Some(state) = state
    {
        return Ok((code, state));
    }

    let error = qry_string
        .split('&')
        .find(|p| p.starts_with("error="))
        .and_then(|p| p.strip_prefix("error="));
    if let Some(error) = error {
        return Err(error.to_string());
    }
    let error_msg = format!("Unknown error, code: {:?}, state: {:?}", code.clone(), state.clone());

    Err(error_msg)
}

pub struct AuthContext {
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl AuthContext {
    pub fn from_request<B>(req: &Request<B>) -> Self {
        Self {
            user_id: req
                .headers()
                .get("X-User-ID")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            email: req
                .headers()
                .get("X-User-Email")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            name: req
                .headers()
                .get("X-User-Name")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.user_id.is_some()
    }
}
