//! Cross-platform notifications for VPN status updates

#[cfg(windows)]
use winrt_notification::{Duration, Sound, Toast};

#[cfg(not(windows))]
use notify_rust::Notification;

/// App ID for toast notifications
/// Using PowerShell's AUMID for compatibility (custom app IDs require registration)
#[cfg(windows)]
const APP_ID: &str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";

/// Show a toast notification
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

    #[cfg(not(windows))]
    {
        if let Err(e) = Notification::new()
            .summary(title)
            .body(message)
            .timeout(notify_rust::Timeout::Milliseconds(5000))
            .show()
        {
            tracing::warn!("Failed to show notification: {}", e);
        }
    }
}

/// Show notification with sound (platform-specific)
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

    #[cfg(not(windows))]
    {
        // notify-rust doesn't have cross-platform sound, just show normally
        // macOS will use system notification sound if enabled in preferences
        if let Err(e) = Notification::new()
            .summary(title)
            .body(message)
            .timeout(notify_rust::Timeout::Milliseconds(5000))
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
pub fn notify_error(message: &str) {
    let msg = format!("Connection failed: {}", message);
    show_notification("PMACS VPN", &msg);
}
