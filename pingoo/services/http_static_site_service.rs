use std::{fs::Metadata, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc};

use bytes::Bytes;
use futures::TryStreamExt;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use tokio::fs::{self, File};
use tokio_util::io::ReaderStream;
use tracing::{error, warn};

use crate::{
    config::{ServiceConfig, StaticSiteServiceConfig},
    services::{
        HttpService,
        http_utils::{new_internal_error_response_500, new_not_found_error},
    },
};

pub struct StaticSiteService {
    name: Arc<String>,
    route: Option<rules::CompiledExpression>,
    config: StaticSiteServiceConfig,
}

impl StaticSiteService {
    pub fn new(config: ServiceConfig) -> Self {
        return StaticSiteService {
            config: config.r#static.unwrap(),
            route: config.route,
            name: Arc::new(config.name),
        };
    }
}

#[async_trait::async_trait]
impl HttpService for StaticSiteService {
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
        let url_path = req.uri().path().trim_start_matches('/').trim_end_matches('/');

        if url_path.contains("/..") || url_path.contains("../") {
            return new_not_found_error(self.config.not_found.status_code);
        }

        let mut local_path = PathBuf::from(&self.config.root);
        local_path.push(url_path);

        let file_metadata = match fs::metadata(&local_path).await {
            Ok(metadata) if metadata.is_dir() => {
                // if it's a directory, we try the directory/index.html file
                local_path.push("index.html");
                match try_metadata(&local_path, self.config.not_found.status_code).await {
                    Ok(metadata) => metadata,
                    Err(res) => return res,
                }
            }
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if local_path.extension().is_some() {
                    return new_not_found_error(self.config.not_found.status_code);
                }

                // prettify URLs
                // if the path has not extension and was not found, we try path + ".html"
                // e.g. /page -> path.html
                local_path.set_extension("html");
                match try_metadata(&local_path, self.config.not_found.status_code).await {
                    Ok(metadata) => metadata,
                    Err(res) => return res,
                }
            }
            Err(err) => {
                error!("error getting metadata for static file: {local_path:?}: {err}");
                return new_internal_error_response_500();
            }
        };

        // get the file extension from its content type
        let file_extension = local_path.extension().unwrap_or_default().to_str().unwrap_or_default();
        let content_type = mime_guess::from_ext(file_extension).first_or_octet_stream();

        let file = match File::open(&local_path).await {
            Ok(file) => file,
            Err(err) => {
                error!("error opening static file: {local_path:?}: {err:?}");
                return new_internal_error_response_500();
            }
        };

        // Wrap to a tokio_util::io::ReaderStream
        let reader_stream = ReaderStream::new(file);

        // Convert to http_body_util::BoxBody
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data).map_err(|_| unreachable!()));
        let boxed_body = stream_body.boxed();

        let response = match Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_LENGTH, file_metadata.size().to_string())
            .header(header::CONTENT_TYPE, content_type.to_string())
            .body(boxed_body)
        {
            Ok(response) => response,
            Err(err) => {
                error!("error building HTTP response for static file: {local_path:?}: {err:?}");
                return new_internal_error_response_500();
            }
        };
        return response;
    }
}

async fn try_metadata(
    path: &PathBuf,
    not_found_status_code: StatusCode,
) -> Result<Metadata, Response<BoxBody<Bytes, hyper::Error>>> {
    match fs::metadata(&path).await {
        Ok(metadata) if metadata.is_dir() => Err(new_not_found_error(not_found_status_code)),
        Ok(metadata) => Ok(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(new_not_found_error(not_found_status_code)),
        Err(err) => {
            error!("error getting metadata for static file: {path:?}: {err}");
            Err(new_internal_error_response_500())
        }
    }
}
