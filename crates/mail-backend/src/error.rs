use crate::QueryParseError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub type Result<T, E = BackendError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Database,
    Io,
    InvalidInput,
    MessageTooLarge,
    Parse,
    Query,
    NotFound,
    Conflict,
    CorruptBlob,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("database error: {0}")]
    Database(#[from] turso::Error),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("message is {actual} bytes; configured maximum is {limit}")]
    MessageTooLarge { actual: usize, limit: usize },
    #[error("message could not be parsed as RFC 5322/MIME")]
    Parse,
    #[error(transparent)]
    Query(#[from] QueryParseError),
    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: String },
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("blob {hash} failed its content hash check")]
    CorruptBlob { hash: String },
    #[error("serialized state is invalid: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl BackendError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Database(_) => ErrorCode::Database,
            Self::Io { .. } => ErrorCode::Io,
            Self::InvalidInput(_) => ErrorCode::InvalidInput,
            Self::MessageTooLarge { .. } => ErrorCode::MessageTooLarge,
            Self::Parse => ErrorCode::Parse,
            Self::Query(_) => ErrorCode::Query,
            Self::NotFound { .. } => ErrorCode::NotFound,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::CorruptBlob { .. } => ErrorCode::CorruptBlob,
            Self::Serialization(_) => ErrorCode::InvalidInput,
        }
    }
}
