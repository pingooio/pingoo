use std::{
    fs::Metadata,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::PathBuf,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use aws_lc_rs::digest;
use bytes::Bytes;
use futures::TryStreamExt;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use moka::future::Cache;
use tokio::fs::{self, File};
use tokio_util::io::ReaderStream;
use tracing::{error, warn};

use crate::{
    config::{ServiceConfig, StaticSiteServiceConfig},
    services::{
        HttpService,
        http_utils::{
            CACHE_CONTROL_DYNAMIC, new_internal_error_response_500, new_method_not_allowed_error, new_not_found_error,
        },
    },
};

const CACHING_FILE_SIZE_LIMIT: u64 = 500_000; // 500 KB
// only cache the 500 most popular files
const CACHE_CAPACITY: u64 = 500;

pub struct StaticSiteService {
    name: Arc<String>,
    route: Option<rules::CompiledExpression>,
    config: StaticSiteServiceConfig,
    /// in-memory cache for popular files
    cache: Cache<PathBuf, Arc<CachedFile>>,
}

#[derive(Clone)]
struct CachedFile {
    /// Unix timestamp (nanoseconds) of the file's last modification
    modified_at: u128,
    /// size in bytes
    size: u64,
    /// content of the file
    data: Bytes,
}

impl StaticSiteService {
    pub fn new(config: ServiceConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(CACHE_CAPACITY)
            // Time to live (TTL): 1 hour
            .time_to_idle(Duration::from_secs(3600))
            .build();
        return StaticSiteService {
            config: config.r#static.unwrap(),
            route: config.route,
            name: Arc::new(config.name),
            cache,
        };
    }
}

#[async_trait::async_trait]
impl HttpService for StaticSiteService {
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

    async fn handle_http_request(&self, req: Request<hyper::body::Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
        let url_path = req.uri().path().trim_start_matches('/').trim_end_matches('/').trim();

        if req.method() != Method::GET && req.method() != Method::HEAD {
            return new_method_not_allowed_error();
        }

        // prevent directory traversal and other similar attacks
        if url_path.contains("/..") || url_path.contains("../") || url_path.contains("//") {
            return new_not_found_error();
        }

        let mut file_path = PathBuf::from(&self.config.root);
        file_path.push(url_path);

        let file_metadata = match fs::metadata(&file_path).await {
            Ok(metadata) if metadata.is_dir() => {
                // if it's a directory, we try the directory/index.html file
                file_path.push("index.html");
                match try_metadata(&file_path).await {
                    Ok(metadata) => metadata,
                    Err(res) => return res,
                }
            }
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if file_path.extension().is_some() {
                    return new_not_found_error();
                }

                // prettify URLs
                // if the path has not extension and was not found, we try path + ".html"
                // e.g. /page -> path.html
                file_path.set_extension("html");
                match try_metadata(&file_path).await {
                    Ok(metadata) => metadata,
                    Err(res) => return res,
                }
            }
            Err(err) => {
                error!("error getting metadata for static file: {file_path:?}: {err}");
                return new_internal_error_response_500();
            }
        };

        // get the file extension from its content type
        let file_extension = file_path.extension().unwrap_or_default().to_str().unwrap_or_default();
        let content_type = mime_guess::from_ext(file_extension).first_or_octet_stream().to_string();
        // Unix timestamp (nanoseconds) of the file's last modification time
        let file_size = file_metadata.size();
        let mut res = Response::builder()
            .header(header::CONTENT_LENGTH, file_size.to_string())
            .header(header::CONTENT_TYPE, &content_type)
            .header(header::CACHE_CONTROL, CACHE_CONTROL_DYNAMIC);

        // only files with accessible metadata are eligible for etag and (maybe) caching
        if let Some(file_modified_at) = file_metadata
            .modified()
            .ok()
            .map(|modified| modified.duration_since(UNIX_EPOCH).map(|modified| modified.as_nanos()))
            .and_then(|modified| modified.ok())
        {
            // TODO: using size + modification time for Etag may not be good enough.
            // But, how to compute Etag for files that are too big and thus need to be streamed back?
            // It's these larger files that may benefit the most from ETag caching.
            let mut etag_hasher = digest::Context::new(&digest::SHA256);
            etag_hasher.update(file_path.as_os_str().as_bytes());
            etag_hasher.update(&file_size.to_le_bytes());
            etag_hasher.update(&file_modified_at.to_le_bytes());
            let etag_hash = etag_hasher.finish();
            let etag = format!("\"{}\"", hex::encode(etag_hash.as_ref()));

            res = res.header(header::ETAG, &etag);

            // if the file's etag matches the request's IF_NONE_MATCH header:
            // send back a 304 NOT_MODIFIED response
            if let Some(if_none_match_header) = req.headers().get(header::IF_NONE_MATCH).map(|header| {
                header
                    .to_str()
                    .unwrap_or_default()
                    .trim()
                    .trim_start_matches("W/")
                    .trim_matches('"')
            }) && (req.method() == Method::GET || req.method() == Method::HEAD)
                && etag.trim_matches('"') == if_none_match_header
            {
                let response = match res
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
                {
                    Ok(response) => response,
                    Err(err) => {
                        error!("error building HTTP response for NOT_MODIFIED file: {err:?}");
                        new_internal_error_response_500()
                    }
                };
                return response;
            }

            // if the file is of reasonnable size, cache it in memory
            if file_size <= CACHING_FILE_SIZE_LIMIT {
                // if a cache entry is available for this file
                if let Some(cached_file) = self.cache.get(&file_path).await {
                    if cached_file.modified_at == file_modified_at && cached_file.size == file_size {
                        // otherwise send back the entire file from cache
                        let response = match res.status(StatusCode::OK).body(
                            Full::new(cached_file.data.clone())
                                .map_err(|never| match never {})
                                .boxed(),
                        ) {
                            Ok(response) => response,
                            Err(err) => {
                                error!("error building HTTP response for cached static file: {err:?}");
                                new_internal_error_response_500()
                            }
                        };
                        return response;
                    } else {
                        // file is cached but has been modified: remove it from the cache.
                        self.cache.remove(&file_path).await;
                    }
                }

                // file is eligible for caching but not cached yet: read it and cache it
                let file_content = match fs::read(&file_path).await {
                    Ok(file) => Bytes::from_owner(file),
                    Err(err) => {
                        error!("error reading static file: {file_path:?}: {err:?}");
                        return new_internal_error_response_500();
                    }
                };

                let file_to_cache = CachedFile {
                    modified_at: file_modified_at,
                    size: file_size,
                    data: file_content.clone(), // cloning Bytes is cheap
                };
                self.cache.insert(file_path, Arc::new(file_to_cache)).await;

                let response = match res
                    .status(StatusCode::OK)
                    .body(Full::new(file_content).map_err(|_| unreachable!()).boxed())
                {
                    Ok(response) => response,
                    Err(err) => {
                        error!("error building HTTP response for cached static file: {err:?}");
                        new_internal_error_response_500()
                    }
                };
                return response;
            }
        }

        // file is not eligible for caching: send a streaming response from the filesystem
        let file = match File::open(&file_path).await {
            Ok(file) => file,
            Err(err) => {
                error!("error opening static file: {file_path:?}: {err:?}");
                return new_internal_error_response_500();
            }
        };

        // Wrap to a tokio_util::io::ReaderStream and convert to http_body_util::BoxBody
        let stream_body = StreamBody::new(ReaderStream::new(file).map_ok(Frame::data).map_err(|_| unreachable!()));
        let response = match res.status(StatusCode::OK).body(stream_body.boxed()) {
            Ok(response) => response,
            Err(err) => {
                error!("error building HTTP response for static file: {file_path:?}: {err:?}");
                return new_internal_error_response_500();
            }
        };
        return response;
    }
}

async fn try_metadata(path: &PathBuf) -> Result<Metadata, Response<BoxBody<Bytes, hyper::Error>>> {
    match fs::metadata(&path).await {
        Ok(metadata) if metadata.is_dir() => Err(new_not_found_error()),
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(new_not_found_error()),
        Err(err) => {
            error!("error getting metadata for static file: {path:?}: {err}");
            Err(new_internal_error_response_500())
        }
    }
}
