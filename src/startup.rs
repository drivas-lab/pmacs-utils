//! Platform-specific startup registration
//!
//! Manages the "Start at login" feature:
//! - Windows: Registry key in HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//! - macOS: LaunchAgent plist in ~/Library/LaunchAgents/
//! - Linux: Not yet implemented

use thiserror::Error;

#[cfg(windows)]
use windows::Win32::Foundation::ERROR_SUCCESS;
#[cfg(windows)]
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ, RegCloseKey, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

#[cfg(windows)]
use windows::core::PCWSTR;

#[cfg(windows)]
const APP_NAME: &str = "PMACS VPN";

#[derive(Error, Debug)]
pub enum StartupError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// =============================================================================
// Windows Implementation
// =============================================================================

/// Check if startup is enabled (Windows)
#[cfg(windows)]
pub fn is_start_at_login_enabled() -> bool {
    unsafe {
        let subkey = to_wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
        let mut hkey: HKEY = HKEY::default();

        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != ERROR_SUCCESS {
            return false;
        }

        let value_name = to_wide(APP_NAME);
        let result = RegQueryValueExW(
            hkey,
            PCWSTR::from_raw(value_name.as_ptr()),
            None,
            None,
            None,
            None,
        );

        let _ = RegCloseKey(hkey);
        result == ERROR_SUCCESS
    }
}

/// Enable start at login (Windows)
#[cfg(windows)]
pub fn enable_start_at_login() -> Result<(), StartupError> {
    let exe_path = std::env::current_exe()
        .map_err(|e| StartupError::Other(format!("Failed to get exe path: {}", e)))?;

    // Command: "path\to\pmacs-vpn.exe" tray --launched-at-login
    let command = format!("\"{}\" tray --launched-at-login", exe_path.display());

    unsafe {
        let subkey = to_wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
        let mut hkey: HKEY = HKEY::default();

        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(subkey.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey,
        );

        if result != ERROR_SUCCESS {
            return Err(StartupError::Other(format!(
                "Failed to open registry key: {:?}",
                result
            )));
        }

        let value_name = to_wide(APP_NAME);
        let value_data = to_wide(&command);
        let value_bytes: &[u8] =
            std::slice::from_raw_parts(value_data.as_ptr() as *const u8, value_data.len() * 2);

        let result = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(value_name.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );

        let _ = RegCloseKey(hkey);
        if result != ERROR_SUCCESS {
            return Err(StartupError::Other(format!(
                "Failed to set registry value: {:?}",
                result
            )));
        }

        tracing::info!("Enabled start at login (Windows registry)");
        Ok(())
    }
}

/// Disable start at login (Windows)
#[cfg(windows)]
pub fn disable_start_at_login() -> Result<(), StartupError> {
    unsafe {
        let subkey = to_wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
        let mut hkey: HKEY = HKEY::default();

        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR::from_raw(subkey.as_ptr()),
            0,
            KEY_WRITE,
            &mut hkey,
        );

        if result != ERROR_SUCCESS {
            return Err(StartupError::Other(format!(
                "Failed to open registry key: {:?}",
                result
            )));
        }

        let value_name = to_wide(APP_NAME);
        let result = RegDeleteValueW(hkey, PCWSTR::from_raw(value_name.as_ptr()));

        let _ = RegCloseKey(hkey);
        // Ignore "not found" error (2 = ERROR_FILE_NOT_FOUND)
        if result != ERROR_SUCCESS && result.0 != 2 {
            return Err(StartupError::Other(format!(
                "Failed to delete registry value: {:?}",
                result
            )));
        }

        tracing::info!("Disabled start at login (Windows registry)");
        Ok(())
    }
}

// =============================================================================
// macOS Implementation
// =============================================================================

/// LaunchAgent plist path
#[cfg(target_os = "macos")]
fn launchagent_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join("Library/LaunchAgents/com.pmacs.vpn.plist"))
}

/// Enable start at login (macOS)
#[cfg(target_os = "macos")]
pub fn enable_start_at_login() -> Result<(), StartupError> {
    use std::fs;

    let plist_path = launchagent_path()
        .ok_or_else(|| StartupError::Other("Could not find home directory".into()))?;

    // Get path to current executable
    let exe_path = std::env::current_exe()
        .map_err(|e| StartupError::Other(format!("Could not get executable path: {}", e)))?;

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pmacs.vpn</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>tray</string>
        <string>--launched-at-login</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PMACS_VPN_LAUNCHED_AT_LOGIN</key>
        <string>1</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
"#,
        exe_path.display()
    );

    // Create LaunchAgents directory if needed
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&plist_path, plist_content)?;
    tracing::info!("Created LaunchAgent: {}", plist_path.display());
    Ok(())
}

/// Disable start at login (macOS)
#[cfg(target_os = "macos")]
pub fn disable_start_at_login() -> Result<(), StartupError> {
    let plist_path = launchagent_path()
        .ok_or_else(|| StartupError::Other("Could not find home directory".into()))?;

    if plist_path.exists() {
        std::fs::remove_file(&plist_path)?;
        tracing::info!("Removed LaunchAgent: {}", plist_path.display());
    }
    Ok(())
}

/// Check if start at login is enabled (macOS)
#[cfg(target_os = "macos")]
pub fn is_start_at_login_enabled() -> bool {
    launchagent_path().map(|p| p.exists()).unwrap_or(false)
}

// =============================================================================
// Linux Implementation (XDG autostart)
// =============================================================================

/// XDG autostart desktop file path
#[cfg(target_os = "linux")]
fn autostart_path() -> Option<std::path::PathBuf> {
    // Use XDG_CONFIG_HOME or fallback to ~/.config
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|h| h.join(".config"))
                .unwrap_or_default()
        });

    if config_dir.as_os_str().is_empty() {
        return None;
    }

    Some(config_dir.join("autostart/pmacs-vpn.desktop"))
}

/// Enable start at login (Linux)
#[cfg(target_os = "linux")]
pub fn enable_start_at_login() -> Result<(), StartupError> {
    use std::fs;

    let desktop_path = autostart_path()
        .ok_or_else(|| StartupError::Other("Could not find config directory".into()))?;

    let exe_path = std::env::current_exe()
        .map_err(|e| StartupError::Other(format!("Could not get executable path: {}", e)))?;

    let desktop_content = format!(
        r#"[Desktop Entry]
Type=Application
Name=PMACS VPN
Comment=Split-tunnel VPN for PMACS
Exec={} tray --launched-at-login
Icon=network-vpn
Terminal=false
Categories=Network;
StartupNotify=false
X-GNOME-Autostart-enabled=true
"#,
        exe_path.display()
    );

    // Create autostart directory if needed
    if let Some(parent) = desktop_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&desktop_path, desktop_content)?;
    tracing::info!("Created XDG autostart: {}", desktop_path.display());
    Ok(())
}

/// Disable start at login (Linux)
#[cfg(target_os = "linux")]
pub fn disable_start_at_login() -> Result<(), StartupError> {
    let desktop_path = autostart_path()
        .ok_or_else(|| StartupError::Other("Could not find config directory".into()))?;

    if desktop_path.exists() {
        std::fs::remove_file(&desktop_path)?;
        tracing::info!("Removed XDG autostart: {}", desktop_path.display());
    }
    Ok(())
}

/// Check if start at login is enabled (Linux)
#[cfg(target_os = "linux")]
pub fn is_start_at_login_enabled() -> bool {
    autostart_path().map(|p| p.exists()).unwrap_or(false)
}

// =============================================================================
// Legacy function names (for backward compatibility)
// =============================================================================

/// Check if startup is enabled (legacy name)
pub fn is_startup_enabled() -> bool {
    is_start_at_login_enabled()
}

/// Enable startup (legacy name)
pub fn enable_startup() -> Result<(), String> {
    enable_start_at_login().map_err(|e| e.to_string())
}

/// Disable startup (legacy name)
pub fn disable_startup() -> Result<(), String> {
    disable_start_at_login().map_err(|e| e.to_string())
}

/// Toggle startup state
pub fn toggle_startup() -> Result<bool, String> {
    if is_startup_enabled() {
        disable_startup()?;
        Ok(false)
    } else {
        enable_startup()?;
        Ok(true)
    }
}
