//! Cross-platform native dialogs for credential prompts
//!
//! Windows uses CredUI; Linux uses zenity/kdialog. macOS has an NSAlert
//! implementation in `mac.rs`, but it requires objc2 dependencies and
//! main-thread dispatch that the tray's worker thread cannot satisfy, so it
//! is not compiled yet — macOS reports dialogs unavailable and callers fall
//! back to a clean error instead of hanging on a console prompt.

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;

/// Prompt for VPN credentials (username + password)
///
/// Returns `Some((username, password))` if the user provided credentials,
/// or `None` if cancelled or dialogs are unavailable on this platform.
pub fn prompt_credentials(title: &str, message: &str) -> Option<(String, String)> {
    #[cfg(target_os = "windows")]
    return windows::prompt_credentials(title, message);

    #[cfg(target_os = "linux")]
    return linux::prompt_credentials(title, message);

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (title, message);
        tracing::warn!("Native credential dialogs are not supported on this platform");
        None
    }
}

/// Prompt for password only (username already known)
///
/// Returns `Some(password)` if the user provided a password, or `None` if
/// cancelled or dialogs are unavailable on this platform.
pub fn prompt_password(title: &str, username: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    return windows::prompt_password(title, username);

    #[cfg(target_os = "linux")]
    return linux::prompt_password(title, username);

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (title, username);
        tracing::warn!("Native password dialogs are not supported on this platform");
        None
    }
}

/// Show a simple message dialog
pub fn show_message(title: &str, message: &str, is_error: bool) {
    #[cfg(target_os = "windows")]
    windows::show_message(title, message, is_error);

    #[cfg(target_os = "linux")]
    linux::show_message(title, message, is_error);

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        if is_error {
            tracing::error!("{}: {}", title, message);
        } else {
            tracing::info!("{}: {}", title, message);
        }
    }
}

/// Check if native dialogs are available on this platform
pub fn is_available() -> bool {
    #[cfg(target_os = "windows")]
    return true;

    #[cfg(target_os = "linux")]
    return linux::is_available();

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    return false;
}
