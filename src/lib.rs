pub mod compression;
pub mod index;
pub mod mime_parser;
pub mod security;
pub mod storage;

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LumeError {
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database Error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("Compression Error: {0}")]
    Compression(String),
    #[error("MIME Parsing Error: {0}")]
    Mime(String),
    #[error("Data Corruption Detected! Checksum mismatch.")]
    Corruption,
    #[error("Permission Denied: Invalid Credentials or Access Level")]
    AccessDenied,
    #[error("Security Error: {0}")]
    Security(String),
}

pub struct LumeEngine {
    pub storage_root: PathBuf,
    pub db: std::sync::Mutex<rusqlite::Connection>,
    pub active_dict_version: u32,
    pub compression_manager: compression::CompressionManager,
}

impl LumeEngine {
    pub fn new(root: PathBuf) -> Result<Self, LumeError> {
        std::fs::create_dir_all(&root)?;
        let db_path = root.join("lume_meta.sqlite");
        let db = rusqlite::Connection::open(db_path)?;

        // Enable Write-Ahead Logging for high concurrency support with Axum
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;",
        )?;

        Ok(Self {
            storage_root: root,
            db: std::sync::Mutex::new(db),
            active_dict_version: 0,
            compression_manager: compression::CompressionManager::new(),
        })
    }
}
