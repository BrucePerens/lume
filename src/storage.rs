use rkyv::{Archive, Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xxhash_rust::xxh64::xxh64;

use crate::LumeError;

const LUME_MAGIC: &[u8; 4] = b"LMAI";

#[derive(Archive, Serialize, Deserialize, Debug)]
pub struct MailHeader {
    pub dict_id: u32,
    pub acl_id: u64,
    pub original_checksum: u64,
    pub text_len: u32,
}

impl crate::LumeEngine {
    pub async fn store_email(
        &self,
        message_id: &str,
        acl_id: u64,
        raw_email_bytes: &[u8],
    ) -> Result<PathBuf, LumeError> {
        let original_checksum = xxh64(raw_email_bytes, 0);
        let parts = self.parse_and_split(raw_email_bytes)?;
        let compressed_text = self
            .compression_manager
            .compress(&parts.compressible_text)?;
        let text_len = compressed_text.len() as u32;

        let mut full_payload = compressed_text;
        for attachment in parts.binary_attachments {
            full_payload.extend_from_slice(&attachment);
        }

        let header = MailHeader {
            dict_id: self.compression_manager.get_active_dict_id(),
            acl_id,
            original_checksum,
            text_len,
        };

        let header_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&header)
            .map_err(|e| LumeError::Compression(e.to_string()))?
            .to_vec();

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

            file.sync_all().await?;
        }

        tokio::fs::rename(&tmp_path, &final_path).await?;
        Ok(final_path)
    }

    pub async fn get_email(&self, message_id: &str) -> Result<Vec<u8>, LumeError> {
        let path = self.storage_root.join(format!("{}.lmail", message_id));
        let mut file = File::open(path).await?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).await?;
        if &magic != LUME_MAGIC {
            return Err(LumeError::Corruption);
        }

        let mut h_len_bytes = [0u8; 4];
        file.read_exact(&mut h_len_bytes).await?;
        let h_len = u32::from_be_bytes(h_len_bytes) as usize;

        let mut h_bytes = vec![0u8; h_len];
        file.read_exact(&mut h_bytes).await?;

        let header = rkyv::from_bytes::<MailHeader, rkyv::rancor::Error>(&h_bytes)
            .map_err(|e| LumeError::Compression(e.to_string()))?;

        let mut payload = Vec::new();
        file.read_to_end(&mut payload).await?;

        let (comp_text, binary_data) = payload.split_at(header.text_len as usize);
        let decompressed_text = self
            .compression_manager
            .decompress(comp_text, header.dict_id)?;

        let mut final_mail = decompressed_text;
        final_mail.extend_from_slice(binary_data);

        if xxh64(&final_mail, 0) != header.original_checksum {
            return Err(LumeError::Corruption);
        }

        Ok(final_mail)
    }

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
                rusqlite::params![message_id, requesting_acl_id as i64],
            )?;
        }

        let path = self.storage_root.join(format!("{}.lmail", message_id));
        if path.exists() {
            tokio::fs::remove_file(path).await?;
        }

        Ok(())
    }
}
