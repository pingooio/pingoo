use std::{sync::Arc, time::Duration};

use cookie::Cookie;
use http::{HeaderValue, Request, Response, header};
use thiserror::Error;

use super::{Session, SessionCrypto, SessionStore};

const COOKIE_NAME: &str = "_pingoo_auth_";

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Session not found")]
    NotFound,
    #[error("Session expired")]
    Expired,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Cookie error: {0}")]
    Cookie(String),
}

pub struct SessionConfig {
    pub encrypt_key: [u8; 32],
    pub sign_key: [u8; 32],
    pub domain: Option<String>,
    pub secure: bool,
    pub duration: Duration,
}

impl SessionConfig {
    pub fn new(encrypt_key: [u8; 32], sign_key: [u8; 32]) -> Self {
        Self {
            encrypt_key,
            sign_key,
            domain: None,
            secure: true,
            duration: Duration::from_secs(86400),
        }
    }
}

pub struct SessionManager {
    store: Arc<SessionStore>,
    crypto: Arc<SessionCrypto>,
    config: SessionConfig,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Result<Self, SessionError> {
        let crypto = SessionCrypto::new(&config.encrypt_key, &config.sign_key)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;

        Ok(Self {
            store: Arc::new(SessionStore::new(config.duration)),
            crypto: Arc::new(crypto),
            config,
        })
    }

    pub fn create_session(
        &self,
        user_id: String,
        email: String,
        name: String,
        picture: Option<String>,
    ) -> Result<Session, SessionError> {
        let session_id = self
            .crypto
            .generate_session_id()
            .map_err(|e| SessionError::Crypto(e.to_string()))?;

        let session = self.store.create(session_id, user_id, email, name, picture);

        Ok(session)
    }

    pub fn set_session_cookie<B>(&self, response: &mut Response<B>, session: &Session) -> Result<String, SessionError> {
        let encrypted = self
            .crypto
            .encrypt(session.id.as_bytes(), &self.config.encrypt_key)
            .map_err(|e| SessionError::Crypto(e.to_string()))?;

        let expiration = cookie::time::OffsetDateTime::from_unix_timestamp(session.expires_at.timestamp())
            .map_err(|e| SessionError::Cookie(format!("Invalid timestamp: {}", e)))?;

        let mut cookie = Cookie::build((COOKIE_NAME, encrypted))
            .http_only(true)
            .secure(self.config.secure)
            .expires(cookie::Expiration::DateTime(expiration))
            .build();

        if let Some(ref domain) = self.config.domain {
            cookie.set_domain(domain.clone());
        }

        let cookie_string = cookie.to_string();

        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie_string).map_err(|e| SessionError::Cookie(e.to_string()))?,
        );

        Ok(cookie_string)
    }

    pub fn get_session<B>(&self, request: &Request<B>) -> Result<Session, SessionError> {
        let session_id = self.get_session_id(request)?;
        let session = self.store.get(&session_id).ok_or(SessionError::NotFound)?;

        if session.expires_at < chrono::Utc::now() {
            self.store.delete(&session_id);
            return Err(SessionError::Expired);
        }

        Ok(session)
    }

    fn get_session_id<B>(&self, request: &Request<B>) -> Result<String, SessionError> {
        let cookies = request.headers().get(header::COOKIE).and_then(|f| f.to_str().ok());

        if let Some(cookies_list) = cookies.map(Cookie::split_parse) {
            for cookie_data in cookies_list.flatten() {
                if cookie_data.name() == COOKIE_NAME {
                    let decrypted = self
                        .crypto
                        .decrypt(cookie_data.value(), &self.config.encrypt_key)
                        .map_err(|e| SessionError::Crypto(e.to_string()))?;

                    return String::from_utf8(decrypted).map_err(|e| SessionError::Crypto(e.to_string()));
                }
            }
        }

        Err(SessionError::NotFound)
    }

    pub fn delete_session<B>(&self, request: &Request<B>, response: &mut Response<B>) -> Result<(), SessionError> {
        if let Ok(session_id) = self.get_session_id(request) {
            self.store.delete(&session_id);
        }

        self.clear_cookies(response)?;

        Ok(())
    }

    fn clear_cookies<B>(&self, response: &mut Response<B>) -> Result<(), SessionError> {
        let mut cookie = Cookie::build((COOKIE_NAME, ""))
            .path("/")
            .http_only(true)
            .secure(self.config.secure)
            .same_site(cookie::SameSite::Lax)
            .max_age(cookie::time::Duration::seconds(0))
            .build();

        if let Some(ref domain) = self.config.domain {
            cookie.set_domain(domain.clone());
        }

        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie.to_string()).map_err(|e| SessionError::Cookie(e.to_string()))?,
        );

        Ok(())
    }

    pub fn update_last_seen<B>(&self, request: &Request<B>) {
        if let Ok(session_id) = self.get_session_id(request) {
            self.store.update_last_seen(&session_id);
        }
    }

    pub fn generate_state(&self) -> Result<String, SessionError> {
        self.crypto
            .generate_state()
            .map_err(|e| SessionError::Crypto(e.to_string()))
    }

    pub fn store_oauth_state(&self, state: String, original_url: String) {
        self.store.store_oauth_state(state, original_url);
    }

    pub fn get_oauth_state(&self, state: &str) -> Option<String> {
        self.store.get_oauth_state(state)
    }

    pub fn delete_oauth_state(&self, state: &str) {
        self.store.delete_oauth_state(state);
    }

    pub fn cleanup_expired(&self) -> usize {
        self.store.cleanup_expired() + self.store.cleanup_expired_states()
    }
}
