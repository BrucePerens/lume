# lume
Secure, failure-resistant email store with distributed compression and indexing.

## Architecture

Lume is designed as a secure, high-performance local MTA storage engine. It strictly separates the highly-compressible MIME text payload from incompressible binary attachments.

### Key Features
* **Zstandard Dictionary Compression:** Analyzes email corpus to build localized dictionaries, yielding massive compression ratios on standard email text.
* **Atomic Storage:** Emails are stored with `.tmp` staging and `fsync` guarantees to prevent corruption during unexpected termination.
* **OS-Level Sandboxing:** Operates in a highly constrained environment. Drops to a dedicated unprivileged user via `setresuid` and jails itself into its data directory via `chroot`.
* **Zero-Unsafe Rust:** Completely avoids `unsafe` blocks, relying strictly on the borrow checker for memory safety.
* **Cryptographic Integrity:** Payload verification utilizes xxhash64 for instant tamper and corruption detection.

## Developer Documentation: Rust Library (AI Integration Guide)

This section provides comprehensive signatures and behavioral contracts for the `lume` crate, allowing autonomous agents to integrate the library without reading the source code.

### Core Structure: `LumeEngine`
The `LumeEngine` struct is the primary entry point. It manages disk access, SQLite indexing, and Zstandard compression dictionaries.

```rust
// Core Engine Initialization
pub fn new(root: std::path::PathBuf) -> Result<Self, LumeError>;
pub fn init_db(db_mutex: &std::sync::Mutex<rusqlite::Connection>) -> rusqlite::Result<()>;
```

### Access Control & User Management
User identities are cryptographically hashed (Argon2id) and mapped to integer ACL IDs.

```rust
// Registers a new user and returns their generated acl_id.
pub fn register_user(&self, username: &str, plaintext_password: &str) -> Result<u64, LumeError>;

// Authenticates a user. Implements constant-time fallback logic for non-existent users.
pub fn authenticate_user(&self, username: &str, plaintext_password: &str) -> Result<u64, LumeError>;
```

### Storage and Retrieval
Emails are stored as `.lmail` files with atomic fsync guarantees. The payload is checked via `xxhash64`.

```rust
// 1. Store the payload atomically. Returns the final PathBuf of the .lmail file.
pub async fn store_email(&self, message_id: &str, acl_id: u64, raw_email_bytes: &[u8]) -> Result<std::path::PathBuf, LumeError>;

// 2. Index the metadata in SQLite. Requires a `MailHeader` struct.
pub fn index_message(&self, message_id: &str, header: &crate::storage::MailHeader, subject: &str, sender: &str) -> Result<(), LumeError>;

// Retrieve the email. Fails with `LumeError::Corruption` if the checksum is invalid.
pub async fn get_email(&self, message_id: &str) -> Result<Vec<u8>, LumeError>;

// Delete an email securely from both SQLite and the filesystem.
// Validates `requesting_acl_id` against the owner before deletion.
pub async fn delete_email(&self, message_id: &str, requesting_acl_id: u64) -> Result<(), LumeError>;
```

### Authorization & Search

```rust
// Verifies if the requesting_acl_id owns the message_id. Returns the dict_id needed for decompression.
pub fn authorize_and_get_dict(&self, message_id: &str, requesting_acl_id: u64) -> Result<u32, LumeError>;

// Search indexing database. Returns a Vector of message_ids.
pub fn search_by_sender(&self, requesting_acl_id: u64, sender: &str) -> Result<Vec<String>, LumeError>;
pub fn search_by_subject(&self, requesting_acl_id: u64, subject_query: &str) -> Result<Vec<String>, LumeError>;
```

### Types & Errors
* `MailHeader`: Struct containing `dict_id: u32`, `acl_id: u64`, `original_checksum: u64`, and `text_len: u32`.
* `LumeError`: Enum wrapping std `Io`, `Db` (rusqlite), `Compression`, `Mime`, `Corruption`, `AccessDenied`, and `Security` errors.

## Developer Documentation: HTTP Daemon API (AI Integration Guide)

The daemon provides a secure REST API for external applications. It enforces strict OS sandboxing, TLS, and HTTP Basic Authentication.

* **Base URL:** `/` (Port 8443 by default, or an ephemeral port in `--dev-mode`)
* **Authentication:** `HTTP Basic Auth`. Credentials must match a user registered via the internal engine (e.g., `admin:super_secret_password`).
* **Security Headers Required/Enforced:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`.

### 1. Store Email
**Endpoint:** `POST /mail`
**Auth:** HTTP Basic

**Request Payload (`application/json`):**
*Note: `raw_content` must be a JSON array of 8-bit unsigned integers representing the raw byte stream of the email.*
```json
{
  "message_id": "string (unique identifier)",
  "subject": "string",
  "sender": "string (email address)",
  "raw_content": [84, 104, 105, 115, 32, 105, 115, 32, 97, 110, 32, 101, 109, 97, 105, 108]
}
```

**Responses:**
* `201 Created`: Email successfully compressed, stored atomically, and indexed.
* `401 Unauthorized`: Invalid credentials.
* `500 Internal Server Error`: Disk failure or SQLite lock issue.

### 2. Retrieve Email
**Endpoint:** `GET /mail/:message_id`
**Auth:** HTTP Basic

**Responses:**
* `200 OK`: Returns the UTF-8 lossy representation of the email.
  ```json
  {
    "message_id": "string",
    "content": "string (The fully decompressed and reconstructed email content)"
  }
  ```
* `401 Unauthorized`: Invalid credentials.
* `403 Forbidden`: The authenticated user does not own the requested `message_id`.
* `404 Not Found`: Message does not exist.
* `500 Internal Server Error`: The payload failed its `xxhash64` cryptographic integrity check (`LumeError::Corruption`).

## Building and Running

### Prerequisites
* Rust 1.70+
* Python 3.9+ (For the admin disaster-recovery tool)

### Setup
```bash
cargo build --release
```

To run the daemon locally (Requires root for `chroot` and privilege dropping):
```bash
sudo ./target/release/lume
```

### Testing
Run the comprehensive integration test suite using standard Cargo workflows:
```bash
cargo test
```

## Admin & Disaster Recovery Tools
Lume includes a Python-based utility to interact directly with the binary files without relying on the Rust daemon or SQLite index. This ensures data recovery is always possible.

Install Python dependencies locally:
```bash
python3 install_deps.py
```

Check the vault for corruption:
```bash
python3 lume_admin.py check --dir /var/lib/lume/data
```

Rebuild the SQLite index entirely from the file metadata:
```bash
python3 lume_admin.py rebuild --dir /var/lib/lume/data
```

## License
Licensed under the GNU Affero General Public License Version 3 (AGPL-3.0). See the `LICENSE` file for more details.
