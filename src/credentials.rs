//! Secure credential storage using OS-native keychain
//!
//! Uses Windows Credential Manager, macOS Keychain, or Linux Secret Service
//! to securely store VPN passwords.

use keyring::Entry;
use tracing::{debug, info, warn};

const SERVICE_NAME: &str = "pmacs-vpn";

/// Store a password securely in the OS credential manager
pub fn store_password(username: &str, password: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, username)
        .map_err(|e| format!("Failed to create keyring entry: {}", e))?;

    entry
        .set_password(password)
        .map_err(|e| format!("Failed to store password: {}", e))?;

    info!("Password stored securely for user: {}", username);
    Ok(())
}

/// Retrieve a stored password from the OS credential manager
pub fn get_password(username: &str) -> Option<String> {
    let entry = Entry::new(SERVICE_NAME, username).ok()?;

    match entry.get_password() {
        Ok(password) => {
            debug!("Retrieved stored password for user: {}", username);
            Some(password)
        }
        Err(keyring::Error::NoEntry) => {
            debug!("No stored password for user: {}", username);
            None
        }
        Err(e) => {
            warn!("Failed to retrieve password: {}", e);
            None
        }
    }
}

/// Delete a stored password from the OS credential manager
pub fn delete_password(username: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, username)
        .map_err(|e| format!("Failed to create keyring entry: {}", e))?;

    match entry.delete_credential() {
        Ok(()) => {
            info!("Password deleted for user: {}", username);
            Ok(())
        }
        Err(keyring::Error::NoEntry) => {
            debug!("No password to delete for user: {}", username);
            Ok(())
        }
        Err(e) => Err(format!("Failed to delete password: {}", e)),
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
