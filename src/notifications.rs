//! Windows toast notifications for VPN status updates

#[cfg(windows)]
use winrt_notification::{Duration, Sound, Toast};

/// App ID for toast notifications
/// Using PowerShell's AUMID for compatibility (custom app IDs require registration)
#[cfg(windows)]
const APP_ID: &str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";

/// Show a toast notification (Windows only, no-op on other platforms)
#[allow(unused_variables)]
pub fn show_notification(title: &str, message: &str) {
    #[cfg(windows)]
    {
        if let Err(e) = Toast::new(APP_ID)
            .title(title)
            .text1(message)
            .duration(Duration::Short)
            .show()
        {
            tracing::warn!("Failed to show notification: {}", e);
        }
    }
}

/// Show a notification with sound
#[allow(unused_variables)]
pub fn show_notification_with_sound(title: &str, message: &str) {
    #[cfg(windows)]
    {
        if let Err(e) = Toast::new(APP_ID)
            .title(title)
            .text1(message)
            .sound(Some(Sound::Default))
            .duration(Duration::Short)
            .show()
        {
            tracing::warn!("Failed to show notification: {}", e);
        }
    }
}

/// Notify that DUO push was sent
pub fn notify_duo_push() {
    show_notification("PMACS VPN", "Check your phone for DUO push");
}

/// Notify successful connection
pub fn notify_connected() {
    show_notification_with_sound("PMACS VPN", "Connected successfully");
}

/// Notify disconnection
pub fn notify_disconnected() {
    show_notification("PMACS VPN", "Disconnected");
}

/// Notify that setup is required
pub fn notify_setup_required() {
    show_notification("PMACS VPN", "Setup required - right-click tray icon");
}

/// Notify connection error
#[allow(unused_variables)]
pub fn notify_error(message: &str) {
    #[cfg(windows)]
    {
        let msg = format!("Connection failed: {}", message);
        show_notification("PMACS VPN", &msg);
    }
}
