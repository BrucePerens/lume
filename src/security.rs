use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use nix::unistd::{chroot, setresgid, setresuid, Gid, Uid};
use std::path::Path;

use crate::LumeError;

/// Hashes a plaintext password using Argon2id, producing a web-standard PHC string.
pub fn hash_password(password: &str) -> Result<String, LumeError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| LumeError::Security(format!("Hashing failed: {}", e)))?
        .to_string();
        
    Ok(password_hash)
}

/// Verifies a plaintext password against a stored PHC hash string.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, LumeError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| LumeError::Security(format!("Invalid hash format: {}", e)))?;
        
    let is_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();
        
    Ok(is_valid)
}

/// Secures the process by restricting the filesystem view and dropping root privileges.
/// MUST be called after all privileged operations (like binding ports < 1024) are complete.
pub fn secure_process(jail_dir: &Path, target_uid: u32, target_gid: u32) -> Result<(), LumeError> {
    // 1. Chroot to the jail directory
    chroot(jail_dir).map_err(|e| LumeError::Security(format!("Failed to chroot: {}", e)))?;
    
    // Change working directory to the new root to ensure path resolution works securely
    std::env::set_current_dir("/").map_err(|e| LumeError::Security(format!("Failed to chdir: {}", e)))?;

    // 2. Drop Group Privileges safely
    let gid = Gid::from_raw(target_gid);
    setresgid(gid, gid, gid)
        .map_err(|e| LumeError::Security(format!("Failed to drop GID privileges: {}", e)))?;

    // 3. Drop User Privileges safely
    let uid = Uid::from_raw(target_uid);
    setresuid(uid, uid, uid)
        .map_err(|e| LumeError::Security(format!("Failed to drop UID privileges: {}", e)))?;

    Ok(())
}
