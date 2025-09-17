use std::process::Stdio;

use tokio::process::Command;
use tracing::debug;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod server;

mod captcha;
mod crypto_utils;
mod error;
mod geoip;
mod jwt_utils;
mod listeners;
mod lists;
mod request_context;
mod rules;
mod service_discovery;
mod services;
mod tls;

pub use error::Error;

use crate::server::Server;

// We don't use mimalloc in debug builds to speedup compilation
// #[cfg(not(debug_assertions))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_filter(EnvFilter::try_from_env("PINGOO_LOG").unwrap_or_else(|_| EnvFilter::new("info"))),
        )
        .try_init()
        .unwrap();

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|err| Error::Config(format!("error setting up rustls crypto provider: {err:?}")))?;

    let config = config::load_and_validate(None)?;

    match &config.child_process {
        None => {}
        Some(child_process_config) => {
            debug!("starting child process: {:?}", &child_process_config.command);
            let mut command = Command::new(&child_process_config.command[0]);
            if child_process_config.command.len() > 1 {
                command.args(&child_process_config.command[1..]);
            }

            // TODO: handle situation where the child exit early due to an error.
            // Give the child a short window of time and check if it has exited.
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|err| {
                    Error::Unspecified(format!(
                        "error starting child process ({:?}): {err}",
                        &child_process_config.command
                    ))
                })?;
        }
    };

    let server = Server::new(config);
    server.run().await?;

    return Ok(());
}
