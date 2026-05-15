use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use nix::unistd::{chroot, setresgid, setresuid, Gid, Uid};
use rand::rngs::OsRng;
use std::path::Path;

use crate::LumeError;

pub fn hash_password(password: &str) -> Result<String, LumeError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| LumeError::Security(format!("Hashing failed: {}", e)))?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, LumeError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| LumeError::Security(format!("Invalid hash format: {}", e)))?;

    let is_valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok();

    Ok(is_valid)
}

pub fn chown_recursive(path: &Path, target_uid: u32, target_gid: u32) -> Result<(), LumeError> {
    use nix::unistd::{chown, Gid, Uid};
    let u = Uid::from_raw(target_uid);
    let g = Gid::from_raw(target_gid);

    let mut dirs = vec![path.to_path_buf()];
    while let Some(current_dir) = dirs.pop() {
        chown(&current_dir, Some(u), Some(g))
            .map_err(|e| LumeError::Security(format!("Failed to chown: {}", e)))?;

        if let Ok(entries) = std::fs::read_dir(&current_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                chown(&p, Some(u), Some(g))
                    .map_err(|e| LumeError::Security(format!("Failed to chown: {}", e)))?;
                if p.is_dir() {
                    dirs.push(p);
                }
            }
        }
    }
    Ok(())
}

pub fn secure_process(jail_dir: &Path, target_uid: u32, target_gid: u32) -> Result<(), LumeError> {
    chroot(jail_dir).map_err(|e| LumeError::Security(format!("Failed to chroot: {}", e)))?;

    std::env::set_current_dir("/")
        .map_err(|e| LumeError::Security(format!("Failed to chdir: {}", e)))?;

    let gid = Gid::from_raw(target_gid);
    setresgid(gid, gid, gid)
        .map_err(|e| LumeError::Security(format!("Failed to drop GID privileges: {}", e)))?;

    let uid = Uid::from_raw(target_uid);
    setresuid(uid, uid, uid)
        .map_err(|e| LumeError::Security(format!("Failed to drop UID privileges: {}", e)))?;

    Ok(())
}
