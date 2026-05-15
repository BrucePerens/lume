use rusqlite::{params, Connection, Result as SqlResult};
use crate::{LumeEngine, LumeError, storage::MailHeader, security};

impl LumeEngine {
    pub fn init_db(db: &Connection) -> SqlResult<()> {
        // Mail metadata table
        db.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                acl_id INTEGER NOT NULL,
                dict_id INTEGER NOT NULL,
                subject TEXT,
                sender TEXT,
                date_received DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        
        // Secure Users table
        db.execute(
            "CREATE TABLE IF NOT EXISTS users (
                acl_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )",
            [],
        )?;
        
        db.execute("CREATE INDEX IF NOT EXISTS idx_acl ON messages (acl_id)", [])?;
        Ok(())
    }

    /// Creates a new user with a securely hashed password.
    pub fn register_user(&self, username: &str, plaintext_password: &str) -> Result<u64, LumeError> {
        let hash = security::hash_password(plaintext_password)?;
        
        self.db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
            params![username, hash],
        )?;
        
        let acl_id = self.db.last_insert_rowid() as u64;
        Ok(acl_id)
    }

    /// Authenticates a user and returns their acl_id if successful.
    pub fn authenticate_user(&self, username: &str, plaintext_password: &str) -> Result<u64, LumeError> {
        let mut stmt = self.db.prepare("SELECT acl_id, password_hash FROM users WHERE username = ?1")?;
        
        let mut rows = stmt.query(params![username])?;
        
        if let Some(row) = rows.next()? {
            let acl_id: u64 = row.get(0)?;
            let hash: String = row.get(1)?;
            
            if security::verify_password(plaintext_password, &hash)? {
                return Ok(acl_id);
            }
        }
        
        // Generic error to prevent timing/enumeration attacks
        Err(LumeError::AccessDenied)
    }

    pub fn index_message(&self, message_id: &str, header: &MailHeader, subject: &str, sender: &str) -> Result<(), LumeError> {
        self.db.execute(
            "INSERT INTO messages (message_id, acl_id, dict_id, subject, sender) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![message_id, header.acl_id, header.dict_id, subject, sender],
        )?;
        Ok(())
    }

    pub fn authorize_and_get_dict(&self, message_id: &str, requesting_acl_id: u64) -> Result<u32, LumeError> {
        let mut stmt = self.db.prepare("SELECT dict_id FROM messages WHERE message_id = ?1 AND acl_id = ?2")?;
        let mut rows = stmt.query(params![message_id, requesting_acl_id])?;
        
        if let Some(row) = rows.next()? { Ok(row.get(0)?) } else { Err(LumeError::AccessDenied) }
    }
}
