use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{JwtValidator, SessionManager, session::Session};

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("Invalid authorization code")]
    InvalidCode,
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("User info fetch failed: {0}")]
    UserInfoFetch(String),
    #[error("Invalid state parameter")]
    InvalidState,
    #[error("Session error: {0}")]
    Session(String),
    #[error("HTTP error: {0}")]
    Http(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

pub struct OAuthConfig {
    pub provider: OAuthProvider,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum OAuthProvider {
    Google,
    GitHub,
    Custom {
        auth_url: String,
        token_url: String,
        userinfo_url: String,
    },
}

impl OAuthProvider {
    fn auth_url(&self) -> &str {
        match self {
            OAuthProvider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuthProvider::GitHub => "https://github.com/login/oauth/authorize",
            OAuthProvider::Custom { auth_url, .. } => auth_url,
        }
    }

    fn token_url(&self) -> &str {
        match self {
            OAuthProvider::Google => "https://oauth2.googleapis.com/token",
            OAuthProvider::GitHub => "https://github.com/login/oauth/access_token",
            OAuthProvider::Custom { token_url, .. } => token_url,
        }
    }

    fn userinfo_url(&self) -> &str {
        match self {
            OAuthProvider::Google => "https://www.googleapis.com/oauth2/v2/userinfo",
            OAuthProvider::GitHub => "https://api.github.com/user",
            OAuthProvider::Custom { userinfo_url, .. } => userinfo_url,
        }
    }
}

pub struct OAuthManager {
    config: OAuthConfig,
    session_manager: Arc<SessionManager>,
    jwt_validator: Option<Arc<JwtValidator>>,
    http_client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        http_body_util::Full<bytes::Bytes>,
    >,
}

impl OAuthManager {
    pub fn new(
        config: OAuthConfig,
        session_manager: Arc<SessionManager>,
        jwt_validator: Option<Arc<JwtValidator>>,
    ) -> Self {
        let tls_config =
            rustls::ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
                .with_safe_default_protocol_versions()
                .expect("error setting up TLS versions")
                .with_native_roots()
                .expect("error loading native root certs")
                .with_no_client_auth();

        let mut http_connector = hyper_util::client::legacy::connect::HttpConnector::new();
        http_connector.set_connect_timeout(Some(Duration::from_secs(10)));
        http_connector.enforce_http(false); // Allow HTTPS scheme

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(http_connector);

        let http_client = Client::builder(TokioExecutor::new()).build(https_connector);

        Self {
            config,
            session_manager,
            jwt_validator,
            http_client,
        }
    }

    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    pub fn get_auth_url(&self, state: &str) -> String {
        let scopes = self.config.scopes.join(" ");
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            self.config.provider.auth_url(),
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_url),
            urlencoding::encode(&scopes),
            urlencoding::encode(state)
        )
    }

    pub fn start_auth_flow<B>(&self, request: &Request<B>) -> Result<Response<String>, OAuthError> {
        let state = self
            .session_manager
            .generate_state()
            .map_err(|e| OAuthError::Session(e.to_string()))?;

        let original_url = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string();

        self.session_manager
            .store_oauth_state(state.clone(), original_url.clone());

        tracing::debug!("Starting OAuth flow - state: {}, original_url: {}", state, original_url);

        let auth_url = self.get_auth_url(&state);

        Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, auth_url)
            .body("Redirecting...".to_string())
            .map_err(|e| OAuthError::Http(e.to_string()))
    }

    pub async fn handle_callback(&self, code: &str, state: &str) -> Result<(Session, String), OAuthError> {
        let original_url = self
            .session_manager
            .get_oauth_state(state)
            .ok_or(OAuthError::InvalidState)?;

        self.session_manager.delete_oauth_state(state);

        let token_response = self.exchange_code_for_token(code).await?;

        let user_info = if let Some(ref id_token) = token_response.id_token {
            tracing::debug!("Got id_token for {}", id_token);
            if let Some(ref validator) = self.jwt_validator {
                let claims = validator
                    .validate(id_token)
                    .await
                    .map_err(|e| OAuthError::TokenExchange(e.to_string()))?;

                UserInfo {
                    id: claims.registered.sub.unwrap_or_default(),
                    email: claims.email.unwrap_or_default(),
                    name: claims.name.unwrap_or_default(),
                    picture: claims.picture,
                    email_verified: claims.email_verified,
                }
            } else {
                self.fetch_user_info(&token_response.access_token).await?
            }
        } else {
            self.fetch_user_info(&token_response.access_token).await?
        };

        let session = self
            .session_manager
            .create_session(user_info.id, user_info.email, user_info.name, user_info.picture)
            .map_err(|e| OAuthError::Session(e.to_string()))?;

        Ok((session, original_url))
    }

    async fn exchange_code_for_token(&self, code: &str) -> Result<TokenResponse, OAuthError> {
        let body = format!(
            "grant_type=authorization_code&client_id={}&client_secret={}&redirect_uri={}&code={}",
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.client_secret),
            urlencoding::encode(&self.config.redirect_url),
            urlencoding::encode(code)
        );

        let token_url = self.config.provider.token_url();
        tracing::debug!("Exchanging code for token at: {}", token_url);
        tracing::debug!("Token URL length: {}, bytes: {:?}", token_url.len(), token_url.as_bytes());

        let uri: Uri = token_url.parse().map_err(|e| {
            tracing::error!("Failed to parse token URL '{}': {}", token_url, e);
            OAuthError::TokenExchange(format!("Invalid token URL '{}': {}", token_url, e))
        })?;

        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| OAuthError::Http(e.to_string()))?;

        let resp = self.http_client.request(req).await.map_err(|e| {
            tracing::error!("Token exchange HTTP request failed: {:?}", e);
            OAuthError::TokenExchange(format!("client error: {:?}", e))
        })?;

        let status = resp.status();
        let body_bytes = resp
            .collect()
            .await
            .map_err(|e| OAuthError::TokenExchange(e.to_string()))?
            .to_bytes();

        if !status.is_success() {
            let error_body = String::from_utf8_lossy(&body_bytes);
            tracing::error!("Token exchange failed - HTTP {}: {}", status, error_body);
            return Err(OAuthError::TokenExchange(format!("HTTP {}: {}", status, error_body)));
        }

        serde_json::from_slice(&body_bytes).map_err(|e| {
            let body_preview = String::from_utf8_lossy(&body_bytes);
            tracing::error!("Failed to parse token response: {} - body: {}", e, body_preview);
            OAuthError::TokenExchange(format!("Invalid JSON response: {}", e))
        })
    }

    async fn fetch_user_info(&self, access_token: &str) -> Result<UserInfo, OAuthError> {
        let uri: Uri = self
            .config
            .provider
            .userinfo_url()
            .parse()
            .map_err(|e| OAuthError::UserInfoFetch(format!("Invalid userinfo URL: {}", e)))?;

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, "pingoo-oauth-client")
            .body(Full::new(Bytes::new()))
            .map_err(|e| OAuthError::Http(e.to_string()))?;

        let resp = self
            .http_client
            .request(req)
            .await
            .map_err(|e| OAuthError::UserInfoFetch(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OAuthError::UserInfoFetch(format!("HTTP {}", resp.status())));
        }

        let body_bytes = resp
            .collect()
            .await
            .map_err(|e| OAuthError::UserInfoFetch(e.to_string()))?
            .to_bytes();

        let raw_userinfo: serde_json::Value =
            serde_json::from_slice(&body_bytes).map_err(|e| OAuthError::UserInfoFetch(e.to_string()))?;

        self.parse_user_info(&raw_userinfo)
    }

    fn parse_user_info(&self, data: &serde_json::Value) -> Result<UserInfo, OAuthError> {
        let id = match &self.config.provider {
            OAuthProvider::Google => data["sub"].as_str(),
            OAuthProvider::GitHub => data["id"].as_str(),
            OAuthProvider::Custom { .. } => data["id"].as_str().or(data["sub"].as_str()),
        }
        .unwrap_or("")
        .to_string();

        let email = data["email"].as_str().unwrap_or("").to_string();
        let name = data["name"].as_str().unwrap_or("").to_string();
        let picture = data["picture"].as_str().map(|s| s.to_string());
        let email_verified = data["email_verified"].as_bool();

        Ok(UserInfo {
            id,
            email,
            name,
            picture,
            email_verified,
        })
    }
}
