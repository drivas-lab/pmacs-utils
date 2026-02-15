//! Secure credential storage using OS-native keychain
//!
//! Uses Windows Credential Manager, macOS Keychain, or Linux Secret Service
//! to securely store VPN passwords. Falls back to file-based storage for
//! headless servers where keyring is unavailable.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use keyring::Entry;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info};

const SERVICE_NAME: &str = "pmacs-vpn";
const CREDENTIALS_FILENAME: &str = ".credentials";

/// Get the path to the credentials file
fn credentials_file_path() -> Option<PathBuf> {
    // Try dirs::config_dir first (respects XDG_CONFIG_HOME)
    if let Some(config) = dirs::config_dir() {
        return Some(config.join("pmacs-vpn").join(CREDENTIALS_FILENAME));
    }

    // Fallback: check XDG_CONFIG_HOME directly
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return Some(
            PathBuf::from(xdg)
                .join("pmacs-vpn")
                .join(CREDENTIALS_FILENAME),
        );
    }

    // Fallback: use HOME/.config
    if let Ok(home) = std::env::var("HOME") {
        return Some(
            PathBuf::from(home)
                .join(".config")
                .join("pmacs-vpn")
                .join(CREDENTIALS_FILENAME),
        );
    }

    // Last resort on Unix
    #[cfg(unix)]
    if let Some(home) = dirs::home_dir() {
        return Some(
            home.join(".config")
                .join("pmacs-vpn")
                .join(CREDENTIALS_FILENAME),
        );
    }

    None
}

/// Simple obfuscation for file storage (not encryption, but prevents casual viewing)
/// Format: base64(username:base64(password))
fn encode_credentials(username: &str, password: &str) -> String {
    let password_b64 = BASE64.encode(password.as_bytes());
    let combined = format!("{}:{}", username, password_b64);
    BASE64.encode(combined.as_bytes())
}

/// Decode obfuscated credentials
fn decode_credentials(encoded: &str) -> Option<(String, String)> {
    let combined = BASE64.decode(encoded).ok()?;
    let combined_str = String::from_utf8(combined).ok()?;
    let (username, password_b64) = combined_str.split_once(':')?;
    let password_bytes = BASE64.decode(password_b64).ok()?;
    let password = String::from_utf8(password_bytes).ok()?;
    Some((username.to_string(), password))
}

/// Store password to file (fallback for headless servers)
fn store_password_file(username: &str, password: &str) -> Result<(), String> {
    let path = credentials_file_path()
        .ok_or_else(|| "Could not determine config directory".to_string())?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {}", e))?;
    }

    let encoded = encode_credentials(username, password);
    fs::write(&path, &encoded).map_err(|e| format!("Failed to write credentials file: {}", e))?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, permissions)
            .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    }

    info!("Password stored to file for user: {}", username);
    Ok(())
}

/// Retrieve password from file (fallback for headless servers)
fn get_password_file(username: &str) -> Option<String> {
    let path = match credentials_file_path() {
        Some(p) => {
            debug!("Credentials file path: {:?}", p);
            p
        }
        None => {
            debug!("Could not determine credentials file path");
            return None;
        }
    };

    if !path.exists() {
        debug!("Credentials file does not exist: {:?}", path);
        return None;
    }

    let encoded = match fs::read_to_string(&path) {
        Ok(s) => {
            debug!("Read credentials file ({} bytes)", s.len());
            s
        }
        Err(e) => {
            debug!("Failed to read credentials file: {}", e);
            return None;
        }
    };

    let (stored_user, password) = match decode_credentials(encoded.trim()) {
        Some(creds) => creds,
        None => {
            debug!("Failed to decode credentials from file");
            return None;
        }
    };

    if stored_user == username {
        info!("Retrieved password from file for user: {}", username);
        Some(password)
    } else {
        debug!(
            "Stored username ({}) doesn't match requested ({})",
            stored_user, username
        );
        None
    }
}

/// Delete password file
fn delete_password_file() -> Result<(), String> {
    let path = match credentials_file_path() {
        Some(p) => p,
        None => return Ok(()), // No config dir, nothing to delete
    };

    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("Failed to delete credentials file: {}", e))?;
        info!("Credentials file deleted");
    }
    Ok(())
}

/// Store a password securely in the OS credential manager AND file
/// Always stores to both locations to ensure headless services can access it
pub fn store_password(username: &str, password: &str) -> Result<(), String> {
    // Always store to file first (for headless/systemd contexts)
    store_password_file(username, password)?;

    // Also try keyring (for interactive contexts)
    match Entry::new(SERVICE_NAME, username) {
        Ok(entry) => match entry.set_password(password) {
            Ok(()) => {
                info!("Password also stored in keychain for user: {}", username);
            }
            Err(e) => {
                debug!("Keyring storage failed (file fallback available): {}", e);
            }
        },
        Err(e) => {
            debug!("Keyring unavailable (file fallback available): {}", e);
        }
    }

    Ok(())
}

/// Retrieve a stored password from the OS credential manager
/// Falls back to file storage if keyring is unavailable
pub fn get_password(username: &str) -> Option<String> {
    debug!("Looking for password for user: {}", username);

    // Try keyring first
    match Entry::new(SERVICE_NAME, username) {
        Ok(entry) => match entry.get_password() {
            Ok(password) => {
                info!(
                    "Retrieved stored password from keychain for user: {}",
                    username
                );
                return Some(password);
            }
            Err(keyring::Error::NoEntry) => {
                debug!("No keychain entry for user: {}", username);
            }
            Err(e) => {
                debug!("Keyring retrieval failed: {}", e);
            }
        },
        Err(e) => {
            debug!("Keyring entry creation failed: {}", e);
        }
    }

    // Fall back to file storage
    debug!("Trying file-based credential storage");
    get_password_file(username)
}

/// Delete a stored password from the OS credential manager and file
pub fn delete_password(username: &str) -> Result<(), String> {
    let mut errors = Vec::new();

    // Try to delete from keyring
    if let Ok(entry) = Entry::new(SERVICE_NAME, username) {
        match entry.delete_credential() {
            Ok(()) => {
                info!("Password deleted from keychain for user: {}", username);
            }
            Err(keyring::Error::NoEntry) => {
                debug!("No keychain password to delete for user: {}", username);
            }
            Err(e) => {
                errors.push(format!("Keyring: {}", e));
            }
        }
    }

    // Also delete from file
    if let Err(e) = delete_password_file() {
        errors.push(format!("File: {}", e));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Check if a password is stored for a user
pub fn has_password(username: &str) -> bool {
    get_password(username).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a working credential manager
    // They may fail in CI environments without proper setup

    #[test]
    #[ignore] // Requires credential manager access
    fn test_store_and_retrieve() {
        let username = "test-pmacs-vpn-user";
        let password = "test-password-12345";

        // Clean up any existing entry
        let _ = delete_password(username);

        // Store
        store_password(username, password).unwrap();

        // Retrieve
        let retrieved = get_password(username);
        assert_eq!(retrieved, Some(password.to_string()));

        // Clean up
        delete_password(username).unwrap();

        // Verify deleted
        assert!(get_password(username).is_none());
    }
}
