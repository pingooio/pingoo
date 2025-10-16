# Zero-Trust Authentication Module for Pingoo

This module provides enterprise-grade OAuth/OIDC authentication with zero-trust principles for the Pingoo edge server.

## Security Features

- **Zero-Trust Architecture**: Every request validated, no implicit trust
- **Cryptographic Security**:
  - AES-256-GCM for session encryption
  - HMAC-SHA256 for cookie signatures
  - Constant-time comparisons for all secrets
  - Memory zeroization for sensitive data
- **JWT Validation**: RS256 signature verification with JWKS caching
- **Secure Cookies**: HttpOnly, Secure, SameSite attributes
- **Session Management**: In-memory store with expiration and renewal

## Architecture

```
┌─────────────────┐
│  HTTP Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Auth Middleware │  ← Zero-trust validation
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌────────────┐
│Session │ │OAuth Flow  │
│Manager │ │(if needed) │
└────┬───┘ └──────┬─────┘
     │            │
     ▼            ▼
┌──────────────────────┐
│  Backend Services    │
│ (with user headers)  │
└──────────────────────┘
```

## Components

### 1. JWKS Provider (`jwks.rs`)

Fetches and caches public keys from OAuth providers.

```rust
use auth::{JwksProvider, ProviderConfig};

let providers = vec![
    ProviderConfig::google(),
    ProviderConfig::microsoft(Some("tenant-id")),
    ProviderConfig::auth0("your-domain.auth0.com"),
];

let jwks_provider = Arc::new(JwksProvider::new(providers));
```

### 2. JWT Validator (`jwt_validator.rs`)

Validates ID tokens with signature and claims verification.

```rust
use auth::{JwtValidator, ValidationConfig};

let config = ValidationConfig {
    allowed_issuers: vec!["https://accounts.google.com".to_string()],
    allowed_audiences: vec!["your-client-id".to_string()],
    clock_skew: Duration::from_secs(300),
    require_exp: true,
    require_nbf: false,
};

let validator = Arc::new(JwtValidator::new(jwks_provider, config));
```

### 3. Session Manager (`session/manager.rs`)

Manages encrypted session cookies.

```rust
use auth::session::{SessionConfig, SessionManager};

let (encrypt_key, sign_key) = SessionCrypto::generate_keys()?;

let session_config = SessionConfig {
    encrypt_key,
    sign_key,
    domain: Some("example.com".to_string()),
    secure: true,
    duration: Duration::from_secs(86400), // 24 hours
};

let session_manager = Arc::new(SessionManager::new(session_config)?);
```

### 4. OAuth Manager (`oauth.rs`)

Handles OAuth2/OIDC authentication flows.

```rust
use auth::{OAuthConfig, OAuthManager, OAuthProvider};

let oauth_config = OAuthConfig {
    provider: OAuthProvider::Google,
    client_id: "your-client-id".to_string(),
    client_secret: "your-client-secret".to_string(),
    redirect_url: "https://example.com/auth/callback".to_string(),
    scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
};

let oauth_manager = Arc::new(OAuthManager::new(
    oauth_config,
    session_manager.clone(),
    Some(validator),
));
```

### 5. Auth Middleware (`middleware.rs`)

HTTP middleware for request authentication.

```rust
use auth::{AuthMiddleware, AuthMiddlewareConfig};

let auth_config = AuthMiddlewareConfig {
    required: true,
    public_paths: vec![
        "/health".to_string(),
        "/auth/login".to_string(),
        "/auth/callback".to_string(),
        "/auth/logout".to_string(),
    ],
};

let auth_middleware = Arc::new(AuthMiddleware::new(
    session_manager,
    Some(oauth_manager.clone()),
    auth_config,
));
```

## Complete Usage Example

```rust
use std::sync::Arc;
use std::time::Duration;
use auth::{
    JwksProvider, JwtValidator, ValidationConfig, ProviderConfig,
    SessionManager, SessionConfig, SessionCrypto,
    OAuthManager, OAuthConfig, OAuthProvider,
    AuthMiddleware, AuthMiddlewareConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup JWKS provider
    let jwks_provider = Arc::new(JwksProvider::new(vec![
        ProviderConfig::google(),
    ]));

    // 2. Setup JWT validator
    let validation_config = ValidationConfig {
        allowed_issuers: vec!["https://accounts.google.com".to_string()],
        allowed_audiences: vec!["your-client-id.apps.googleusercontent.com".to_string()],
        clock_skew: Duration::from_secs(300),
        require_exp: true,
        require_nbf: false,
    };
    let jwt_validator = Arc::new(JwtValidator::new(jwks_provider, validation_config));

    // 3. Setup session manager
    let (encrypt_key, sign_key) = SessionCrypto::generate_keys()?;
    let session_config = SessionConfig {
        encrypt_key,
        sign_key,
        domain: Some("example.com".to_string()),
        secure: true,
        duration: Duration::from_secs(86400),
    };
    let session_manager = Arc::new(SessionManager::new(session_config)?);

    // 4. Setup OAuth manager
    let oauth_config = OAuthConfig {
        provider: OAuthProvider::Google,
        client_id: std::env::var("OAUTH_CLIENT_ID")?,
        client_secret: std::env::var("OAUTH_CLIENT_SECRET")?,
        redirect_url: "https://example.com/auth/callback".to_string(),
        scopes: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
    };
    let oauth_manager = Arc::new(OAuthManager::new(
        oauth_config,
        session_manager.clone(),
        Some(jwt_validator),
    ));

    // 5. Setup auth middleware
    let auth_middleware = Arc::new(AuthMiddleware::new(
        session_manager.clone(),
        Some(oauth_manager.clone()),
        AuthMiddlewareConfig::default(),
    ));

    // 6. Use in request handler
    // In your HTTP service handler:
    let authenticated_request = match auth_middleware.authenticate(request).await {
        Ok(req) => req,
        Err(redirect_response) => return Ok(redirect_response),
    };

    // Request now has user headers:
    // X-User-ID, X-User-Email, X-User-Name

    Ok(())
}
```

## OAuth Callback Handler

```rust
async fn handle_oauth_callback(
    code: &str,
    state: &str,
    oauth_manager: Arc<OAuthManager>,
) -> Result<Response<String>, OAuthError> {
    let (session, redirect_url) = oauth_manager
        .handle_callback(code, state)
        .await?;

    let mut response = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, redirect_url)
        .body("Redirecting...".to_string())?;

    session_manager.set_session_cookie(&mut response, &session)?;

    Ok(response)
}
```

## Configuration Best Practices

1. **Key Generation**: Always use cryptographically secure random keys

   ```rust
   let (encrypt_key, sign_key) = SessionCrypto::generate_keys()?;
   ```

2. **Secure Cookies**: Enable secure flag in production

   ```rust
   secure: true,  // HTTPS only
   ```

3. **Session Duration**: Balance security and UX

   ```rust
   duration: Duration::from_secs(86400),  // 24 hours
   ```

4. **Clock Skew**: Account for time synchronization issues

   ```rust
   clock_skew: Duration::from_secs(300),  // 5 minutes
   ```

5. **JWKS Caching**: Reduce external calls

   ```rust
   cache_ttl: Duration::from_secs(3600),  // 1 hour
   ```

## Integration with Pingoo Listeners

The auth middleware integrates seamlessly with pingoo's HTTP listeners:

```rust
// In http_listener.rs
let auth_middleware = Arc::new(AuthMiddleware::new(
    session_manager,
    Some(oauth_manager),
    AuthMiddlewareConfig::default(),
));

// In request handler
let authenticated_request = match auth_middleware.authenticate(req).await {
    Ok(req) => req,
    Err(response) => return Ok(response),
};

// Backend receives authenticated request with user headers
proxy_request_to_backend(authenticated_request).await
```

## Security Considerations

1. **Zero-Trust**: Every request is validated independently
2. **No Token Storage**: Sessions are stateless on the client side (encrypted cookies)
3. **Constant-Time Comparisons**: Prevent timing attacks on secrets
4. **Memory Safety**: Sensitive data is zeroized after use
5. **TLS Required**: Secure cookies only work over HTTPS
6. **Limited Dependencies**: Minimal attack surface using aws-lc-rs

## Performance

- JWKS keys cached in-memory (DashMap)
- Session lookups: O(1) with concurrent access
- Signature verification: Hardware-accelerated via aws-lc-rs
- Zero allocations in hot path (where possible)

## Testing

```bash
# Run tests with logging
RUST_LOG=debug cargo test -p pingoo -- auth --nocapture

# Test specific component
cargo test -p pingoo session::crypto::tests
```

## Monitoring

Track these metrics:

- Active sessions: `session_manager.store.count()`
- JWKS cache size: `jwks_provider.cache_size()`
- Auth failures: Log via tracing
- Session expiration: Periodic cleanup via `session_manager.cleanup_expired()`

## Migration from Sekisho

Key differences:

- **Language**: Go → Rust (memory safety, performance)
- **Crypto**: Standard library → aws-lc-rs (FIPS-ready)
- **Storage**: Same (in-memory with DashMap)
- **API**: Similar patterns, Rust async/await

The architecture mirrors sekisho's design while leveraging Rust's safety guarantees and zero-cost abstractions.
