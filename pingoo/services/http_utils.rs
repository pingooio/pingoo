use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use serde::Serialize;

use crate::{
    config::ServiceConfig,
    request_context::RequestContext,
    service_discovery::service_registry::ServiceRegistry,
    services::{HttpService, http_proxy_service::HttpProxyService, http_static_site_service::StaticSiteService},
};

pub const CACHE_CONTROL_NO_CACHE: HeaderValue =
    HeaderValue::from_static("private, no-cache, no-store, must-revalidate");
pub const CACHE_CONTROL_DYNAMIC: HeaderValue = HeaderValue::from_static("public, no-cache, must-revalidate");

#[derive(Clone)]
pub struct RequestExtensionContext(pub RequestContext);

// #[derive(Clone)]
// pub struct ReqExtensionCookies(pub Arc<Vec<Cookie<'static>>>);

#[derive(Debug, Serialize)]
pub struct EmptyJsonBody {}

pub fn new_http_service(config: ServiceConfig, service_registry: Arc<ServiceRegistry>) -> Arc<dyn HttpService> {
    if config.r#static.is_some() {
        return Arc::new(StaticSiteService::new(config));
    } else if config.http_proxy.is_some() {
        return Arc::new(HttpProxyService::new(config, service_registry));
    }

    unreachable!("HTTP service type not handled");
}

pub fn new_internal_error_response_500() -> Response<BoxBody<Bytes, hyper::Error>> {
    const INTERNAL_ERROR_MESSAGE: &[u8] = b"500 Internal Server Error";
    let res_body = Full::new(Bytes::from_static(INTERNAL_ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_internal_error_response_500");
}

// TODO
pub fn new_bad_gateway_error() -> Response<BoxBody<Bytes, hyper::Error>> {
    const ERROR_MESSAGE: &[u8] = b"502 Bad Gateway";
    let res_body = Full::new(Bytes::from_static(ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_bad_gateway_error");
}

pub fn new_not_found_error() -> Response<BoxBody<Bytes, hyper::Error>> {
    const NOT_FOUND_ERROR_MESSAGE: &[u8] = b"404 Not Found.";
    let res_body = Full::new(Bytes::from_static(NOT_FOUND_ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_not_found_error_404");
}

pub fn new_blocked_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    const ERROR_MESSAGE: &[u8] = b"Permission Denied";
    let res_body = Full::new(Bytes::from_static(ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building blocked_response");
}

pub fn new_method_not_allowed_error() -> Response<BoxBody<Bytes, hyper::Error>> {
    const ERROR_MESSAGE: &[u8] = b"405 Method Not Allowed";
    let res_body = Full::new(Bytes::from_static(ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_method_not_allowed_error");
}

pub fn get_path(req: &Request<Incoming>) -> &str {
    req.uri().path().trim_end_matches('/')
}
