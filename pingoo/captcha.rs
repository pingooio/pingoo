use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

use aws_lc_rs::digest::{self, SHA256};
use bytes::Bytes;
use chrono::Utc;
use cookie::Cookie;
use http::{HeaderValue, Request, Response, header};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use mime_guess::mime;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{debug, error};
use uuid::Uuid;

use crate::{
    Error, config,
    crypto_utils::constant_time_compare,
    services::http_utils::{EmptyJsonBody, get_path, new_internal_error_response_500, new_not_found_error},
};

pub const CAPTCHA_COOKIE: &str = "__pingoo_captcha";
pub const CAPTCHA_VERIFIED_COOKIE: &str = "__pingoo_captcha_verified";

pub const CAPTCHA_JWT_ISSUER: &str = "pingoo";
const CAPTCHA_VERIFIED_JWT_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24); // 24 hours
const CAPTCHA_JWT_EXPIRATION: Duration = Duration::from_secs(60 * 10); // 10 minutes
const PROOF_OF_WORK_DIFFICULTY: u8 = 1;
const JWT_VALDIATION_OPTIONS: &jwt::ValidateOptions = &jwt::ValidateOptions {
    allowed_time_drift: Duration::from_secs(5), // pingoo runs on controlled servers so this should not be a problem
    nbf: true,
    exp: true,
    aud: &[CAPTCHA_JWT_ISSUER],
    iss: &[CAPTCHA_JWT_ISSUER],
};

pub struct CaptchaManager {
    signing_key: Arc<jwt::Key>,
    verifying_keys: HashMap<String, Arc<jwt::Key>>,
}

#[derive(Debug, Serialize)]
struct CaptchaInitResponseBody {
    /// a 32-byte random challenge encoded to base64
    pub challenge: heapless::String<44>,
    /// the number of leading zeroes when computing the proof-of-work
    pub difficulty: u8,
}

#[derive(Debug, Deserialize)]
struct CaptchaVerifyRequestBody {
    /// the hex-encoded hash computed by the client
    #[serde(with = "hex")]
    pub hash: [u8; 32],
    /// the nonce combined with the challenge during the proof-of-work
    pub nonce: String,
}

/// CaptchaCookieJwtClaims are sent as a JWT in a cookie when initializing the challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaCookieJwtClaims {
    pub challenge: String,
    pub difficulty: u8,

    #[serde(flatten)]
    registered_claims: jwt::RegisteredClaims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaVerifiedCookieJwtClaims {
    pub challenge_passed: bool,

    #[serde(flatten)]
    registered_claims: jwt::RegisteredClaims,
}

impl CaptchaManager {
    pub async fn new() -> Result<Self, Error> {
        // check if JWKS file exists
        let (signing_key, verifying_keys) = if fs::try_exists(config::CAPTCHA_JWKS_PATH)
            .await
            .map_err(|err| Error::Config(format!("error reading captcha JWKS file: {err}")))?
        {
            // if it exists, read it
            let jwks_file_content = fs::read(config::CAPTCHA_JWKS_PATH)
                .await
                .map_err(|err| Error::Config(format!("error reading captcha JWKS file: {err}")))?;
            let jwks: jwt::Jwks = serde_json::from_slice(&jwks_file_content)
                .map_err(|err| Error::Config(format!("error parsing captcha JWKS file: {err}")))?;

            let keys = jwks
                .keys
                .into_iter()
                .map(|jwk| {
                    validate_jwk(&jwk)?;
                    jwk.try_into()
                        .map(Arc::<jwt::Key>::new)
                        .map_err(|err| Error::Unspecified(err.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            if keys.is_empty() {
                return Err(Error::Config("captcha JWKS file is empty".to_string()));
            }
            (
                keys[0].clone(),
                HashMap::from_iter(keys.into_iter().map(|key| (key.id.clone(), key))),
            )
        } else {
            // if the JWKS file doesn't exist, we create it
            let key_id = Uuid::new_v7().to_string();
            let signing_key = Arc::new(jwt::Key::generate_ed25519(key_id).map_err(|err| {
                Error::Unspecified(format!("captcha: error generating captcha JWT signing key: {err}"))
            })?);
            save_jwt_keys(&[&signing_key], config::CAPTCHA_JWKS_PATH).await?;
            (signing_key.clone(), HashMap::from_iter([(signing_key.id.clone(), signing_key)]))
        };

        return Ok(CaptchaManager {
            signing_key,
            verifying_keys,
        });
    }

    pub fn validate_captcha_verified_cookie(&self, cookie_str: &str, client_id: &str) -> Result<(), Error> {
        // TODO: improve this flow
        let jwt_header = match jwt::parse_header(&cookie_str) {
            Ok(header) => header,
            Err(_) => return Err(Error::Unspecified("JWT is not valid".to_string())),
        };

        let jwt_key = match self
            .verifying_keys
            .get(jwt_header.kid.as_ref().map(|kid| kid.as_str()).unwrap_or_default())
        {
            Some(key) => key,
            None => {
                return Err(Error::Unspecified("JWT is not valid".to_string()));
            }
        };

        // TODO: correct errors
        let token: jwt::ParsedJwt<CaptchaVerifiedCookieJwtClaims> =
            jwt::parse_and_verify(&jwt_key, cookie_str, JWT_VALDIATION_OPTIONS)
                .map_err(|err| Error::Unspecified(format!("JWT is not valid: {err}")))?;

        if !constant_time_compare(
            client_id.as_bytes(),
            token.claims.registered_claims.sub.unwrap_or_default().as_bytes(),
        ) || token.claims.challenge_passed != true
        {
            return Err(Error::Unspecified("JWT is not valid".to_string()));
        }

        return Ok(());
    }

    pub async fn serve_captcha_request(
        &self,
        req: Request<Incoming>,
        cookies: Vec<Cookie<'_>>,
        client_id: &str,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let path = get_path(&req);
        if path.starts_with("/__pingoo/captcha/assets") {
            return self.serve_asset(path);
        } else if path == "/__pingoo/captcha/api/init" {
            return self.api_init(client_id).await;
        } else if path == "/__pingoo/captcha/api/verify" {
            return self.api_verify(req, cookies, client_id).await;
        }

        return new_not_found_error();
    }

    pub fn serve_captcha(&self) -> Response<BoxBody<Bytes, hyper::Error>> {
        let res_body = Full::new(Bytes::from(
            ::captcha::Assets::get("index.html")
                .expect("index.html not found for captcha")
                .data
                .to_vec(),
        ))
        .map_err(|never| match never {})
        .boxed();

        return Response::builder()
            .status(403)
            .header(header::CONTENT_TYPE, mime::TEXT_HTML.as_ref())
            .header(header::CACHE_CONTROL, "public, no-cache, must-revalidate")
            .body(res_body)
            .expect("error building captcha index.html");
    }

    async fn api_init(&self, client_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        let challenge_raw: [u8; 32] = rand::random();
        // 32 bytes encoded to base64 = 44 bytes
        let challenge =
            encode_to_base64_heapless::<44, _>(&challenge_raw, &base64::engine::general_purpose::URL_SAFE_NO_PAD);

        let captcha_cookie =
            match generate_captcha_cookie(&self.signing_key, client_id, &challenge, PROOF_OF_WORK_DIFFICULTY) {
                Ok(cookie) => cookie,
                Err(err) => {
                    error!("captcha: error encoding init API response: {err}");
                    // TODO: internal error JSON
                    return new_internal_error_response_500();
                }
            };

        let response_payload = CaptchaInitResponseBody {
            challenge,
            difficulty: PROOF_OF_WORK_DIFFICULTY,
        };
        let response_body = match serde_json::to_vec(&response_payload) {
            Ok(json) => Full::new(Bytes::from(json)).map_err(|never| match never {}).boxed(),
            Err(err) => {
                error!("captcha: error encoding init API response: {err}");
                // TODO: internal error JSON
                return new_internal_error_response_500();
            }
        };

        let set_cookie_header = match HeaderValue::from_str(&captcha_cookie.to_string()) {
            Ok(header) => header,
            Err(err) => {
                error!("captcha: error converting cookie to HTTP header: {err}");
                // TODO: internal error JSON
                return new_internal_error_response_500();
            }
        };

        return Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::CACHE_CONTROL, "public, no-cache, must-revalidate")
            .header(header::SET_COOKIE, set_cookie_header)
            .body(response_body)
            .expect("error building captcha API init response");
    }

    async fn api_verify(
        &self,
        req: Request<Incoming>,
        cookies: Vec<Cookie<'_>>,
        client_id: &str,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let captcha_jwt_from_cookie = match cookies.iter().find(|cookie| cookie.name() == CAPTCHA_COOKIE) {
            Some(cookie) => cookie.value(),
            None => {
                debug!("captcha cookie is missing");
                return new_internal_error_response_500(); // TODO: return JSON response
            }
        };

        // TODO: improve this flow
        let jwt_header = match jwt::parse_header(&captcha_jwt_from_cookie) {
            Ok(header) => header,
            Err(_) => {
                return new_internal_error_response_500();
            } // TODO: return JSON response
        };

        let jwt_key = match self
            .verifying_keys
            .get(jwt_header.kid.as_ref().map(|kid| kid.as_str()).unwrap_or_default())
        {
            Some(key) => key,
            None => {
                debug!("JWT key not found: {}", jwt_header.kid.unwrap_or_default().as_str());
                return new_internal_error_response_500(); // TODO: return JSON response
            }
        };

        let challenge_token_claims: CaptchaCookieJwtClaims =
            match jwt::parse_and_verify(&jwt_key, &captcha_jwt_from_cookie, JWT_VALDIATION_OPTIONS) {
                Ok(jwt) => jwt.claims,
                Err(err) => {
                    debug!("JWT from captcha cookie is not valid: {err}");
                    return new_internal_error_response_500(); // TODO: return JSON response
                }
            };

        let body = match req.collect().await {
            Ok(body) => body,
            Err(err) => {
                debug!("error reading request body: {err}");
                return new_internal_error_response_500(); // TODO: return JSON response
            }
        };

        let input: CaptchaVerifyRequestBody = match serde_json::from_reader(body.to_bytes().as_ref()) {
            Ok(body) => body,
            Err(err) => {
                debug!("error parsing request body: {err}");
                return new_internal_error_response_500(); // TODO: return JSON response
            }
        };

        if !constant_time_compare(
            client_id.as_bytes(),
            challenge_token_claims
                .registered_claims
                .sub
                .unwrap_or_default()
                .as_bytes(),
        ) {
            debug!("client id is not valid");
            return new_internal_error_response_500(); // TODO: return JSON response
        }

        // ensure that the number of leading zeroes match the difficulty
        let mut hash_hex = [0u8; 64];
        hex::encode_to_slice(&input.hash, &mut hash_hex).expect("error encoding hash to hex");
        let leading_zeroes = hash_hex.iter().take_while(|&&character| character == '0' as u8).count();
        if leading_zeroes < (challenge_token_claims.difficulty as usize) {
            debug!(
                "leading zeroes don't match: got {leading_zeroes}, expected: {}",
                challenge_token_claims.difficulty
            );
            return new_internal_error_response_500(); // TODO: return JSON response
        }

        // verify that the given hash == SHA-256(challenge || nonce)
        let mut verification_buffer: Vec<u8> =
            Vec::with_capacity(challenge_token_claims.challenge.len() + input.nonce.len());
        verification_buffer.extend_from_slice(challenge_token_claims.challenge.as_bytes());
        verification_buffer.extend_from_slice(input.nonce.as_bytes());

        let hash = digest::digest(&SHA256, &verification_buffer);
        if !constant_time_compare(hash.as_ref(), &input.hash) {
            debug!("proof of work hash is not valid");
            return new_internal_error_response_500(); // TODO: return JSON response
        }

        // Finally we can issue a JWT certifying that the client has passed the challenge
        let response_new_cookies = match generate_captcha_verified_cookies(
            &self.signing_key,
            // jwt_signing_key.id,
            &client_id,
        ) {
            Ok(cookies) => cookies,
            Err(err) => {
                error!("error generating captcha verified cookies: {err}");
                return new_internal_error_response_500(); // TODO: return JSON response
            }
        };

        let response_body = match serde_json::to_vec(&EmptyJsonBody {}) {
            Ok(json) => Full::new(Bytes::from(json)).map_err(|never| match never {}).boxed(),
            Err(err) => {
                error!("captcha: error encoding verify API response: {err}");
                // TODO: internal error JSON
                return new_internal_error_response_500();
            }
        };

        let mut res = Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .header(header::CACHE_CONTROL, "public, no-cache, must-revalidate");

        for cookie in response_new_cookies {
            let set_cookie_header_value = match HeaderValue::from_str(&cookie.to_string()) {
                Ok(header) => header,
                Err(err) => {
                    error!("captcha: error converting cookie to HTTP header: {err}");
                    // TODO: internal error JSON
                    return new_internal_error_response_500();
                }
            };
            match res.headers_mut() {
                Some(headers) => {
                    headers.append(header::SET_COOKIE, set_cookie_header_value);
                }
                None => {
                    error!("captcha: error inserting cookie in verify response");
                    return new_internal_error_response_500();
                }
            }
        }

        return res
            .body(response_body)
            .expect("error building captcha API verify response");
    }

    fn serve_asset(&self, path: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
        match ::captcha::Assets::get(path.trim_start_matches('/')) {
            Some(asset) => {
                let content_type = mime_guess::from_path(&path).first_or_octet_stream();

                let res_body = Full::new(Bytes::from(asset.data.to_vec()))
                    .map_err(|never| match never {})
                    .boxed();

                return Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, content_type.as_ref())
                    .header(header::CACHE_CONTROL, "public, no-cache, must-revalidate")
                    .body(res_body)
                    .expect("error building captcha asset response");
            }
            None => return new_not_found_error(),
        }
    }
}

// client_id binds a JWT to a specific client of a specific site
pub fn generate_captcha_client_id(ip: IpAddr, user_agent: &str, hostname: &str) -> heapless::String<44> {
    let mut hasher = digest::Context::new(&digest::SHA256);
    match ip {
        IpAddr::V4(ipv4_addr) => hasher.update(&ipv4_addr.octets()),
        IpAddr::V6(ipv6_addr) => hasher.update(&ipv6_addr.octets()),
    }
    hasher.update(user_agent.as_bytes());
    hasher.update(hostname.as_bytes());
    let hash: [u8; 32] = hasher.finish().as_ref().try_into().unwrap();

    // 32 bytes encoded to base64 = 44 bytes
    return encode_to_base64_heapless::<44, _>(&hash, &base64::engine::general_purpose::URL_SAFE_NO_PAD);
}

pub fn generate_captcha_cookie(
    key: &jwt::Key,
    // key_id: Uuid,
    client_id: &str,
    challenge: &str,
    difficulty: u8,
) -> Result<Cookie<'static>, jwt::Error> {
    let now = Utc::now();
    let jwt_expires_at = now + CAPTCHA_JWT_EXPIRATION;
    let claims = CaptchaCookieJwtClaims {
        challenge: challenge.to_string(),
        difficulty,
        registered_claims: jwt::RegisteredClaims {
            iss: Some(CAPTCHA_JWT_ISSUER.to_string()),
            sub: Some(client_id.to_string()),
            aud: Some(CAPTCHA_JWT_ISSUER.to_string()),
            exp: Some(jwt_expires_at.timestamp()),
            nbf: Some(now.timestamp()),
            iat: Some(now.timestamp()),
            jti: Some(Uuid::new_v7().to_string()),
        },
    };
    let header = jwt::Header {
        typ: jwt::TokenType::JWT,
        alg: jwt::Algorithm::EdDSA,
        cty: None,
        jku: None,
        // jwk: None,
        kid: Some(key.id.clone()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let token = jwt::sign(key, &header, &claims)?;

    let mut challenge_cookie = cookie::Cookie::new(CAPTCHA_COOKIE, token);
    challenge_cookie.set_secure(true);
    challenge_cookie.set_http_only(true);
    challenge_cookie.set_same_site(cookie::SameSite::Lax);
    challenge_cookie.set_path("/");
    challenge_cookie
        .set_expires(cookie::time::OffsetDateTime::from_unix_timestamp(jwt_expires_at.timestamp() - 60).unwrap());

    return Ok(challenge_cookie);
}

pub fn generate_captcha_verified_cookies(
    key: &jwt::Key,
    // key_id: Uuid,
    client_id: &str,
) -> Result<Vec<Cookie<'static>>, jwt::Error> {
    let now = Utc::now();
    let jwt_expires_at = now + CAPTCHA_VERIFIED_JWT_EXPIRATION;
    let claims = CaptchaVerifiedCookieJwtClaims {
        challenge_passed: true,
        registered_claims: jwt::RegisteredClaims {
            iss: Some(CAPTCHA_JWT_ISSUER.to_string()),
            sub: Some(client_id.to_string()),
            aud: Some(CAPTCHA_JWT_ISSUER.to_string()),
            exp: Some(jwt_expires_at.timestamp()),
            nbf: Some(now.timestamp()),
            iat: Some(now.timestamp()),
            jti: Some(Uuid::new_v7().to_string()),
        },
    };
    let header = jwt::Header {
        typ: jwt::TokenType::JWT,
        alg: jwt::Algorithm::EdDSA,
        cty: None,
        jku: None,
        // jwk: None,
        kid: Some(key.id.clone()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
    };

    let token = jwt::sign(&key, &header, &claims)?;

    let mut challenge_verified_cookie = cookie::Cookie::new(CAPTCHA_VERIFIED_COOKIE, token);
    challenge_verified_cookie.set_secure(true);
    challenge_verified_cookie.set_http_only(true);
    challenge_verified_cookie.set_same_site(cookie::SameSite::Lax);
    challenge_verified_cookie.set_path("/");
    // the cookie is valid for a shorter amount of time than the JWT to avoid reeiving invalid JWT and confusing users
    challenge_verified_cookie
        .set_expires(cookie::time::OffsetDateTime::from_unix_timestamp(jwt_expires_at.timestamp() - 60).unwrap());

    // remove the captcha cookie
    let mut challenge_cookie = cookie::Cookie::new(CAPTCHA_COOKIE, "");
    challenge_cookie.set_secure(true);
    challenge_cookie.set_http_only(true);
    challenge_cookie.set_same_site(cookie::SameSite::Lax);
    challenge_cookie.set_path("/");
    challenge_cookie.set_expires(cookie::time::OffsetDateTime::from_unix_timestamp(0).unwrap());

    return Ok(vec![challenge_verified_cookie, challenge_cookie]);
}

fn validate_jwk(jwk: &jwt::Jwk) -> Result<(), Error> {
    if jwk.kid.trim().is_empty() {
        return Err(Error::Unspecified("JWK key ID is empty".to_string()));
    }

    if jwk.algorithm != jwt::Algorithm::EdDSA {
        return Err(Error::Unspecified(format!(
            "captcha: JWT algorithm {:?} not suported for key {}. Only {:?} is currently supported.",
            jwk.algorithm,
            jwk.kid,
            jwt::Algorithm::EdDSA
        )));
    }

    // TODO: validate x, y, d length
    match &jwk.crypto {
        jwt::JwkCrypto::Okp { curve: _, x: _, d } => {
            if d.is_none() {
                return Err(Error::Unspecified(format!(
                    "captcha: Private key is missing for key {}",
                    jwk.kid
                )));
            }
        }
        jwt::JwkCrypto::Ec {
            curve: _,
            x: _,
            y: _,
            d,
        } => {
            if d.is_none() {
                return Err(Error::Unspecified(format!(
                    "captcha: Private key is missing for key {}",
                    jwk.kid
                )));
            }
        }
        jwt::JwkCrypto::Oct { key } => {
            if key.len() < 32 {
                return Err(Error::Unspecified(format!("captcha: key is too short for key {}", jwk.kid)));
            }
        }
    }

    // if jwk.kty != jwt::KeyType::OKP
    // if jwk.r#use != jwt::KeyUse::Sign

    return Ok(());
}

async fn save_jwt_keys(keys: &[&jwt::Key], path: &str) -> Result<(), Error> {
    let jwks = jwt::Jwks {
        keys: keys.iter().map(|&key| key.into()).collect(),
    };

    let jwks_json = serde_json::to_vec_pretty(&jwks)
        .map_err(|err| Error::Unspecified(format!("error converting JWKS to JSON: {err}")))?;
    fs::write(&path, &jwks_json)
        .await
        .map_err(|err| Error::Config(format!("error writing JWKS file {path}: {err}")))?;

    return Ok(());
}

fn encode_to_base64_heapless<const N: usize, E: base64::Engine>(data: &[u8], engine: &E) -> heapless::String<N> {
    let mut base64_buf = [0u8; N];
    engine
        .encode_slice(data, &mut base64_buf)
        .expect("error encoding to base64");
    let mut ret = heapless::String::new();
    unsafe {
        // this is safe because base64 checks that the output buffer is of the correct size before writing to it
        // and we only write ascii characters (base64)
        let _ = ret.push_str(str::from_utf8_unchecked(&base64_buf));
    }

    return ret;
}
