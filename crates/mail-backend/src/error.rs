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
    StorageFull,
    StorageQuotaExceeded,
    Parse,
    Query,
    Imap,
    CredentialStore,
    SearchIndex,
    NotFound,
    Conflict,
    CorruptBlob,
    ContentUnavailable,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("database error: {0}")]
    Database(#[source] turso::Error),
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
    #[error("storage is full; {required_bytes} bytes are required and {available_bytes:?} are available")]
    StorageFull {
        path: Option<PathBuf>,
        required_bytes: u64,
        available_bytes: Option<u64>,
    },
    #[error("storage quota for {scope} would be exceeded: {used} used + {requested} requested > {limit}")]
    StorageQuotaExceeded {
        scope: String,
        used: u64,
        requested: u64,
        limit: u64,
    },
    #[error("message could not be parsed as RFC 5322/MIME")]
    Parse,
    #[error(transparent)]
    Query(#[from] QueryParseError),
    #[error("IMAP protocol error: {0}")]
    Imap(String),
    #[error("credential store error: {0}")]
    CredentialStore(String),
    #[error("search index error: {0}")]
    SearchIndex(String),
    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: String },
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("blob {hash} failed its content hash check")]
    CorruptBlob { hash: String },
    #[error("message content is unavailable for {id}: {state}")]
    ContentUnavailable { id: String, state: String },
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
            Self::StorageFull { .. } => ErrorCode::StorageFull,
            Self::StorageQuotaExceeded { .. } => ErrorCode::StorageQuotaExceeded,
            Self::Parse => ErrorCode::Parse,
            Self::Query(_) => ErrorCode::Query,
            Self::Imap(_) => ErrorCode::Imap,
            Self::CredentialStore(_) => ErrorCode::CredentialStore,
            Self::SearchIndex(_) => ErrorCode::SearchIndex,
            Self::NotFound { .. } => ErrorCode::NotFound,
            Self::Conflict(_) => ErrorCode::Conflict,
            Self::CorruptBlob { .. } => ErrorCode::CorruptBlob,
            Self::ContentUnavailable { .. } => ErrorCode::ContentUnavailable,
            Self::Serialization(_) => ErrorCode::InvalidInput,
        }
    }
}

impl From<turso::Error> for BackendError {
    fn from(error: turso::Error) -> Self {
        if is_storage_full_message(&error.to_string()) {
            storage_full_unknown()
        } else {
            Self::Database(error)
        }
    }
}

pub(crate) fn is_storage_full_message(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("database or disk is full")
        || detail.contains("sqlite_full")
        || detail.contains("no space left on device")
        || detail.contains("disk quota exceeded")
        || detail.contains("not enough space on the disk")
}

pub(crate) fn storage_full_unknown() -> BackendError {
    BackendError::StorageFull {
        path: None,
        required_bytes: 1,
        available_bytes: None,
    }
}

pub(crate) fn io_error(path: PathBuf, source: std::io::Error) -> BackendError {
    let raw = source.raw_os_error();
    #[cfg(unix)]
    let storage_full = matches!(raw, Some(28 | 122));
    #[cfg(windows)]
    let storage_full = matches!(raw, Some(39 | 112));
    #[cfg(not(any(unix, windows)))]
    let storage_full = false;
    if storage_full {
        BackendError::StorageFull {
            path: Some(path),
            required_bytes: 1,
            available_bytes: None,
        }
    } else {
        BackendError::Io { path, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_database_and_filesystem_full_failures() {
        assert!(is_storage_full_message(
            "SQLite error: database or disk is full"
        ));
        assert!(is_storage_full_message(
            "No space left on device (os error 28)"
        ));
        assert!(!is_storage_full_message("permission denied"));

        #[cfg(unix)]
        assert_eq!(
            io_error(
                PathBuf::from("profile"),
                std::io::Error::from_raw_os_error(28)
            )
            .code(),
            ErrorCode::StorageFull
        );
    }
}
