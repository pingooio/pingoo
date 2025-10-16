use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::{
    config::{AuthConfig, AuthProvider, ServiceConfig},
    Error,
};

use super::{
    JwtValidator, OAuthConfig, OAuthManager, OAuthProvider, ProviderConfig, RsaJwksProvider, SessionConfig,
    SessionManager, ValidationConfig,
};

pub struct AuthManagerBuilder {
    services: Vec<ServiceConfig>,
}

impl AuthManagerBuilder {
    pub fn new(services: Vec<ServiceConfig>) -> Self {
        Self { services }
    }

    pub fn build(self) -> Result<HashMap<String, Arc<OAuthManager>>, Error> {
        let services_with_auth: Vec<_> = self.services.iter().filter(|s| s.auth.is_some()).collect();

        if services_with_auth.is_empty() {
            return Ok(HashMap::new());
        }

        let jwks_provider = self.create_jwks_provider(&services_with_auth)?;

        // All services must share the same session manager so sessions work across services
        let shared_session_manager = self.create_session_manager()?;

        services_with_auth
            .iter()
            .map(|service_config| {
                let auth = service_config.auth.as_ref().unwrap();
                let oauth_manager = self.create_oauth_manager(auth, jwks_provider.clone(), shared_session_manager.clone())?;
                Ok((service_config.name.clone(), Arc::new(oauth_manager)))
            })
            .collect::<Result<HashMap<String, Arc<OAuthManager>>, Error>>()
    }

    fn create_jwks_provider(
        &self,
        services_with_auth: &[&ServiceConfig],
    ) -> Result<Arc<RsaJwksProvider>, Error> {
        let jwks_configs: Vec<ProviderConfig> = services_with_auth
            .iter()
            .map(|s| {
                let auth = s.auth.as_ref().unwrap();
                self.provider_config_for_auth(&auth.provider)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Arc::new(RsaJwksProvider::new(jwks_configs)))
    }

    fn create_oauth_manager(
        &self,
        auth: &AuthConfig,
        jwks_provider: Arc<RsaJwksProvider>,
        session_manager: Arc<SessionManager>,
    ) -> Result<OAuthManager, Error> {
        let jwt_validator = self.create_jwt_validator(auth, jwks_provider)?;
        let oauth_config = self.create_oauth_config(auth)?;

        Ok(OAuthManager::new(oauth_config, session_manager, Some(jwt_validator)))
    }

    fn provider_config_for_auth(&self, provider: &AuthProvider) -> Result<ProviderConfig, Error> {
        match provider {
            AuthProvider::Google => Ok(ProviderConfig::google()),
            AuthProvider::GitHub => Ok(ProviderConfig::github()),
            AuthProvider::Custom => Err(Error::Config(
                "Auth0 provider requires domain configuration (not yet supported in config)".to_string(),
            )),
        }
    }

    fn create_jwt_validator(
        &self,
        auth: &AuthConfig,
        jwks_provider: Arc<RsaJwksProvider>,
    ) -> Result<Arc<JwtValidator>, Error> {
        let issuer = self.issuer_for_provider(&auth.provider);

        let validation_config = ValidationConfig {
            allowed_issuers: vec![issuer.to_string()],
            allowed_audiences: vec![auth.client_id.clone()],
            clock_skew: Duration::from_secs(300),
            require_exp: true,
            require_nbf: false,
        };

        Ok(Arc::new(JwtValidator::new(jwks_provider, validation_config)))
    }

    fn create_session_manager(&self) -> Result<Arc<SessionManager>, Error> {
        let (encrypt_key, sign_key) = crate::auth::session::SessionCrypto::generate_keys()
            .map_err(|e| Error::Config(format!("Failed to generate session keys: {}", e)))?;

        let session_config = SessionConfig::new(encrypt_key, sign_key);
        let session_manager = SessionManager::new(session_config)
            .map_err(|e| Error::Config(format!("Failed to create session manager: {}", e)))?;

        Ok(Arc::new(session_manager))
    }

    fn create_oauth_config(&self, auth: &AuthConfig) -> Result<OAuthConfig, Error> {
        let oauth_provider = self.oauth_provider_for_auth(&auth.provider)?;
        let scopes = self.scopes_for_provider(&auth.provider);

        Ok(OAuthConfig {
            provider: oauth_provider,
            client_id: auth.client_id.clone(),
            client_secret: auth.client_secret.clone(),
            redirect_url: auth.redirect_url.clone(),
            scopes,
        })
    }

    fn oauth_provider_for_auth(&self, provider: &AuthProvider) -> Result<OAuthProvider, Error> {
        match provider {
            AuthProvider::Google => Ok(OAuthProvider::Google),
            AuthProvider::GitHub => Ok(OAuthProvider::GitHub),
            AuthProvider::Custom => Err(Error::Config("Custom not yet supported".to_string())),
        }
    }

    fn issuer_for_provider(&self, provider: &AuthProvider) -> &str {
        match provider {
            AuthProvider::Google => "https://accounts.google.com",
            AuthProvider::GitHub => "https://github.com/login/oauth",
            AuthProvider::Custom => "",
        }
    }

    fn scopes_for_provider(&self, _provider: &AuthProvider) -> Vec<String> {
        if _provider == &AuthProvider::GitHub {
            return vec!["user:email".to_string(),  "read:org".to_string()]
        }
        vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
    }
}
