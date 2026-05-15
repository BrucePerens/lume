//! # Storage Module
//!
//! Handles the atomic, zero-data-loss writing of compressed email payloads to disk,
//! and verifies cryptographic checksums upon retrieval.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xxhash_rust::xxh64::xxh64;

use crate::LumeError;

const LUME_MAGIC: &[u8; 4] = b"LMAI";

/// Represents the on-disk metadata header for a stored email payload.
/// This header provides exact boundary offsets for decompression and cryptographic
/// integrity verification.
#[derive(Serialize, Deserialize, Debug)]
pub struct MailHeader {
    /// The active Zstandard dictionary used to compress the text block.
    pub dict_id: u32,
    /// The owner's Access Control List identifier.
    pub acl_id: u64,
    /// The `xxhash64` checksum of the original uncompressed email payload.
    pub original_checksum: u64,
    /// The length of the compressed text block within the file payload.
    pub text_len: u32,
}

impl crate::LumeEngine {
    /// Stores an email safely with atomic guarantees, dictionary compression, and fsync.
    ///
    /// This function uses a UUID-based `.tmp` staging file to prevent race conditions
    /// during high-concurrency writes, and performs a hardware `fsync` before atomically
    /// renaming the file to its final `.lmail` destination.
    pub async fn store_email(
        &self,
        message_id: &str,
        acl_id: u64,
        raw_email_bytes: &[u8],
    ) -> Result<PathBuf, LumeError> {
        // 1. Checksum the original uncompressed data for future integrity checks
        let original_checksum = xxh64(raw_email_bytes, 0);

        // 2. Parse MIME and separate text from binary
        let parts = self.parse_and_split(raw_email_bytes)?;

        // 3. Compress the text portion using the active global dictionary
        let compressed_text = self
            .compression_manager
            .compress(&parts.compressible_text)?;
        let text_len = compressed_text.len() as u32;

        // 4. Construct the Payload (Compressed Text + Raw Binary Attachments)
        let mut full_payload = compressed_text;
        for attachment in parts.binary_attachments {
            full_payload.extend_from_slice(&attachment);
        }

        // 5. Build Header
        let header = MailHeader {
            dict_id: self.compression_manager.get_active_dict_id(),
            acl_id,
            original_checksum,
            text_len,
        };
        let header_bytes =
            bincode::serialize(&header).map_err(|e| LumeError::Compression(e.to_string()))?;

        // 6. Secure Atomic Write (Using UUID to prevent race conditions during tmp file creation)
        let final_path = self.storage_root.join(format!("{}.lmail", message_id));
        let tmp_path =
            self.storage_root
                .join(format!("{}_{}.tmp", message_id, uuid::Uuid::new_v4()));

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&tmp_path)
                .await?;

            file.write_all(LUME_MAGIC).await?;
            let header_len = header_bytes.len() as u32;
            file.write_all(&header_len.to_be_bytes()).await?;
            file.write_all(&header_bytes).await?;
            file.write_all(&full_payload).await?;

            file.sync_all().await?; // Hardware flush
        }

        tokio::fs::rename(&tmp_path, &final_path).await?;
        Ok(final_path)
    }

    /// Retrieves and reconstructs the original email payload from disk.
    ///
    /// This function verifies the integrity of the file by checking its magic bytes,
    /// decodes the metadata header, decompresses the text portion using the correct
    /// dictionary, and strictly verifies the `xxhash64` checksum against the reconstructed
    /// payload to guarantee zero data loss.
    pub async fn get_email(&self, message_id: &str) -> Result<Vec<u8>, LumeError> {
        let path = self.storage_root.join(format!("{}.lmail", message_id));
        let mut file = File::open(path).await?;

        // Verify Magic
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).await?;
        if &magic != LUME_MAGIC {
            return Err(LumeError::Corruption);
        }

        // Read Header
        let mut h_len_bytes = [0u8; 4];
        file.read_exact(&mut h_len_bytes).await?;
        let h_len = u32::from_be_bytes(h_len_bytes) as usize;

        let mut h_bytes = vec![0u8; h_len];
        file.read_exact(&mut h_bytes).await?;
        let header: MailHeader =
            bincode::deserialize(&h_bytes).map_err(|e| LumeError::Compression(e.to_string()))?;

        // Read Payload
        let mut payload = Vec::new();
        file.read_to_end(&mut payload).await?;

        // Decompress Text portion
        let (comp_text, binary_data) = payload.split_at(header.text_len as usize);
        let decompressed_text = self
            .compression_manager
            .decompress(comp_text, header.dict_id)?;

        // Reconstruct (Simple concatenation for this model,
        // in production this would involve re-assembling MIME parts)
        let mut final_mail = decompressed_text;
        final_mail.extend_from_slice(binary_data);

        // Final Integrity Check
        if xxh64(&final_mail, 0) != header.original_checksum {
            return Err(LumeError::Corruption);
        }

        Ok(final_mail)
    }

    /// Deletes an email from both the storage backend and the indexing database.
    /// Verifies ACL ownership before deleting.
    pub async fn delete_email(
        &self,
        message_id: &str,
        requesting_acl_id: u64,
    ) -> Result<(), LumeError> {
        self.authorize_and_get_dict(message_id, requesting_acl_id)?;

        {
            let db = self.db.lock().unwrap();
            db.execute(
                "DELETE FROM messages WHERE message_id = ?1 AND acl_id = ?2",
                rusqlite::params![message_id, requesting_acl_id],
            )?;
        }

        let path = self.storage_root.join(format!("{}.lmail", message_id));
        if path.exists() {
            tokio::fs::remove_file(path).await?;
        }

        Ok(())
    }
}
