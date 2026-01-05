//! Cross-platform native dialogs for credential prompts
//!
//! This module provides native dialog implementations for each platform,
//! avoiding osascript on macOS which gets SIGKILL'd when prompting for
//! passwords from background threads (security measure).

#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

/// Prompt for VPN credentials (username + password)
///
/// Returns `Some((username, password))` if the user provided credentials,
/// or `None` if cancelled.
///
/// On macOS, this must be called from the main thread.
pub fn prompt_credentials(title: &str, message: &str) -> Option<(String, String)> {
    #[cfg(target_os = "macos")]
    return mac::prompt_credentials(title, message);

    #[cfg(target_os = "windows")]
    return windows::prompt_credentials(title, message);

    #[cfg(target_os = "linux")]
    return linux::prompt_credentials(title, message);
}

/// Prompt for password only (username already known)
///
/// Returns `Some(password)` if the user provided a password, or `None` if cancelled.
///
/// On macOS, this must be called from the main thread.
pub fn prompt_password(title: &str, username: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    return mac::prompt_password(title, username);

    #[cfg(target_os = "windows")]
    return windows::prompt_password(title, username);

    #[cfg(target_os = "linux")]
    return linux::prompt_password(title, username);
}

/// Show a simple message dialog
pub fn show_message(title: &str, message: &str, is_error: bool) {
    #[cfg(target_os = "macos")]
    mac::show_message(title, message, is_error);

    #[cfg(target_os = "windows")]
    windows::show_message(title, message, is_error);

    #[cfg(target_os = "linux")]
    linux::show_message(title, message, is_error);
}

/// Check if native dialogs are available
///
/// On Linux, this checks if zenity or kdialog is installed.
/// On macOS and Windows, this always returns true.
pub fn is_available() -> bool {
    #[cfg(target_os = "macos")]
    return true;

    #[cfg(target_os = "windows")]
    return true;

    #[cfg(target_os = "linux")]
    return linux::is_available();
}
