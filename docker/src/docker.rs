mod client;
pub mod containers;
mod error;
pub mod model;

pub use client::Client;
pub use error::Error;

pub const DEFAULT_DOCKER_SOCKET: &str = "/var/run/docker.sock";
