//! Windows startup registration
//!
//! Manages the "Start with Windows" feature by adding/removing
//! a registry key in HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
//! This makes the app visible in Task Manager's Startup tab.

#[cfg(windows)]
use windows::Win32::Foundation::ERROR_SUCCESS;
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ,
};

#[cfg(windows)]
use windows::core::PCWSTR;

const APP_NAME: &str = "PMACS VPN";

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Check if startup is enabled
#[cfg(windows)]
pub fn is_startup_enabled() -> bool {
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

#[cfg(not(windows))]
pub fn is_startup_enabled() -> bool {
    false
}

/// Enable startup (add to registry)
#[cfg(windows)]
pub fn enable_startup() -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get exe path: {}", e))?;

    // Command: "path\to\pmacs-vpn.exe" tray
    let command = format!("\"{}\" tray", exe_path.display());

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
            return Err(format!("Failed to open registry key: {:?}", result));
        }

        let value_name = to_wide(APP_NAME);
        let value_data = to_wide(&command);
        let value_bytes: &[u8] = std::slice::from_raw_parts(
            value_data.as_ptr() as *const u8,
            value_data.len() * 2,
        );

        let result = RegSetValueExW(
            hkey,
            PCWSTR::from_raw(value_name.as_ptr()),
            0,
            REG_SZ,
            Some(value_bytes),
        );

        let _ = RegCloseKey(hkey);
        if result != ERROR_SUCCESS {
            return Err(format!("Failed to set registry value: {:?}", result));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn enable_startup() -> Result<(), String> {
    Err("Startup registration not supported on this platform".into())
}

/// Disable startup (remove from registry)
#[cfg(windows)]
pub fn disable_startup() -> Result<(), String> {
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
            return Err(format!("Failed to open registry key: {:?}", result));
        }

        let value_name = to_wide(APP_NAME);
        let result = RegDeleteValueW(
            hkey,
            PCWSTR::from_raw(value_name.as_ptr()),
        );

        let _ = RegCloseKey(hkey);
        // Ignore "not found" error (2 = ERROR_FILE_NOT_FOUND)
        if result != ERROR_SUCCESS && result.0 != 2 {
            return Err(format!("Failed to delete registry value: {:?}", result));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn disable_startup() -> Result<(), String> {
    Ok(())
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
