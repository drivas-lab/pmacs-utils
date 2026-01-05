//! Native Windows dialogs
//!
//! Uses rpassword for terminal password prompts.
//! Native GUI dialogs are a future enhancement.

/// Prompt for credentials - currently uses terminal fallback
pub fn prompt_credentials(_title: &str, _message: &str) -> Option<(String, String)> {
    // Windows tray currently works with cached credentials
    // Native Win32 dialog is a future enhancement
    tracing::warn!("Native Windows credential dialog not yet implemented");
    None
}

/// Prompt for password only - currently uses terminal fallback
pub fn prompt_password(_title: &str, _username: &str) -> Option<String> {
    tracing::warn!("Native Windows password dialog not yet implemented");
    None
}

/// Show a message dialog
pub fn show_message(title: &str, message: &str, is_error: bool) {
    // For now, just log
    if is_error {
        tracing::error!("{}: {}", title, message);
    } else {
        tracing::info!("{}: {}", title, message);
    }
}
