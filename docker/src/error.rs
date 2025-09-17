#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connecting to docker socket: {0}")]
    Connecting(Box<dyn std::error::Error>),
    #[error("{0}")]
    Unspecified(String),
}
