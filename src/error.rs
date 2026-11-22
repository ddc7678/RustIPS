//! Error types shared across the daemon and CLI.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration not found at {path}: run `rustips setup` first")]
    ConfigMissing { path: PathBuf },

    #[error(
        "configuration not found at {path}, but existing state was found at {db}.\n\
         Refusing to treat this as a new install.\n\
         Recover the configuration with `rustips setup --recover`, or archive the old\n\
         state explicitly with `rustips setup --fresh --force`."
    )]
    Recovery { path: PathBuf, db: PathBuf },

    #[error("{path}:{line}: {message}")]
    ConfigInvalid {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("enforcement error: {0}")]
    Enforce(String),

    #[error("capture error: {0}")]
    Capture(String),

    #[error("not permitted: {0} (are you root?)")]
    Permission(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}
