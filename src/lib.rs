//! # Lume Core Library
//!
//! The Lume Engine is a secure, failure-resistant local MTA storage engine.
//! It provides strong atomic storage, Zstandard dictionary compression, and
//! embedded SQLite indexing for metadata.

pub mod api;
pub mod compression;
pub mod index;
pub mod mime_parser;
pub mod security;
pub mod storage;

use std::path::PathBuf;
use thiserror::Error;

/// Represents all possible errors that can occur within the Lume Engine.
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

/// The core engine struct coordinating storage, compression, and indexing.
pub struct LumeEngine {
    /// The root directory where `.lmail` payload files are securely stored.
    pub storage_root: PathBuf,
    /// Thread-safe connection to the local SQLite indexing database.
    pub db: std::sync::Mutex<rusqlite::Connection>,
    /// The current Zstandard dictionary ID used for compressing new messages.
    pub active_dict_version: u32,
    /// The manager responsible for compressing and decompressing payloads.
    pub compression_manager: compression::CompressionManager,
}

impl LumeEngine {
    /// Initializes a new instance of the Lume Engine.
    ///
    /// This creates the necessary storage directories and initializes the SQLite
    /// database connection with Write-Ahead Logging (WAL) enabled for high concurrency.
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
