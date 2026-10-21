use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArcError {
    #[error("Serialization/Deserialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Schema Canonicalization error: {0}")]
    Canonicalization(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}
