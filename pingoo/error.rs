use std::io;
use std::net::SocketAddr;

use crate::geoip;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Config(String),
    #[error("error loading config: {0}")]
    Unspecified(String),
    #[error("error listening {listener} on {address}: {err}")]
    Listening {
        listener: String,
        address: SocketAddr,
        err: std::io::Error,
    },
    #[error("{0}")]
    Tls(String),
    #[error("{0}")]
    IO(String),
}

impl From<geoip::Error> for Error {
    fn from(err: geoip::Error) -> Self {
        Error::Unspecified(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IO(err.to_string())
    }
}
