//! Native Linux dialogs using zenity/kdialog
//!
//! Linux doesn't have the same security restrictions as macOS,
//! so command-line dialog tools work fine from background threads.

use std::process::Command;

/// Check if any dialog tool is available
pub fn is_available() -> bool {
    has_zenity() || has_kdialog()
}

fn has_zenity() -> bool {
    Command::new("which")
        .arg("zenity")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn has_kdialog() -> bool {
    Command::new("which")
        .arg("kdialog")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Prompt for credentials using zenity or kdialog
pub fn prompt_credentials(title: &str, _message: &str) -> Option<(String, String)> {
    // Try zenity first
    if has_zenity() {
        if let Some(creds) = prompt_zenity(title) {
            return Some(creds);
        }
    }

    // Fall back to kdialog
    if has_kdialog() {
        if let Some(creds) = prompt_kdialog(title) {
            return Some(creds);
        }
    }

    tracing::warn!("No dialog tool available (zenity or kdialog)");
    None
}

fn prompt_zenity(title: &str) -> Option<(String, String)> {
    // Username
    let username = Command::new("zenity")
        .args(["--entry", "--title", title, "--text", "Username (PennKey):"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    if username.is_empty() {
        return None;
    }

    // Password
    let password = Command::new("zenity")
        .args(["--password", "--title", title])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    if password.is_empty() {
        return None;
    }

    Some((username, password))
}

fn prompt_kdialog(title: &str) -> Option<(String, String)> {
    // Username
    let username = Command::new("kdialog")
        .args(["--title", title, "--inputbox", "Username (PennKey):"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    if username.is_empty() {
        return None;
    }

    // Password
    let password = Command::new("kdialog")
        .args(["--title", title, "--password", "Password:"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

    if password.is_empty() {
        return None;
    }

    Some((username, password))
}

/// Prompt for password only
pub fn prompt_password(title: &str, username: &str) -> Option<String> {
    let message = format!("Password for {}:", username);

    if has_zenity() {
        let password = Command::new("zenity")
            .args(["--password", "--title", title, "--text", &message])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

        if !password.is_empty() {
            return Some(password);
        }
    }

    if has_kdialog() {
        let password = Command::new("kdialog")
            .args(["--title", title, "--password", &message])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;

        if !password.is_empty() {
            return Some(password);
        }
    }

    None
}

/// Show a message dialog
pub fn show_message(title: &str, message: &str, is_error: bool) {
    if has_zenity() {
        let icon = if is_error { "--error" } else { "--info" };
        let _ = Command::new("zenity")
            .args([icon, "--title", title, "--text", message])
            .status();
    } else if has_kdialog() {
        let cmd = if is_error { "--error" } else { "--msgbox" };
        let _ = Command::new("kdialog")
            .args(["--title", title, cmd, message])
            .status();
    } else {
        // Fall back to logging
        if is_error {
            tracing::error!("{}: {}", title, message);
        } else {
            tracing::info!("{}: {}", title, message);
        }
    }
}
