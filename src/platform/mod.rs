//! Platform-specific implementations

#[cfg(target_os = "macos")]
pub mod mac;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("Failed to add route: {0}")]
    AddRouteError(String),
    #[error("Failed to delete route: {0}")]
    DeleteRouteError(String),
    #[error("Failed to update hosts file: {0}")]
    HostsError(String),
    #[error("Unsupported platform")]
    UnsupportedPlatform,
}

/// Platform-agnostic routing interface
pub trait RoutingManager {
    fn add_route(&self, destination: &str, gateway: &str) -> Result<(), PlatformError>;
    fn delete_route(&self, destination: &str) -> Result<(), PlatformError>;
}

/// Get the appropriate routing manager for the current platform
pub fn get_routing_manager() -> Result<Box<dyn RoutingManager>, PlatformError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(mac::MacRoutingManager::new()))
    }

    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxRoutingManager::new()))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsRoutingManager::new()))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(PlatformError::UnsupportedPlatform)
    }
}

/// Get the interface index for a given name (Windows only)
#[cfg(target_os = "windows")]
pub fn get_interface_index(name: &str) -> Option<u32> {
    windows::get_interface_index(name)
}

/// Get a routing manager bound to a specific interface (for TUN devices)
///
/// On Windows, this looks up the interface index for proper routing.
/// On other platforms, this is currently equivalent to get_routing_manager().
pub fn get_routing_manager_for_interface(
    interface_name: &str,
) -> Result<Box<dyn RoutingManager>, PlatformError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(mac::MacRoutingManager::with_interface(
            interface_name.to_string(),
        )))
    }

    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxRoutingManager::with_interface(
            interface_name.to_string(),
        )))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsRoutingManager::with_interface(
            interface_name,
        )))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = interface_name;
        Err(PlatformError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_error_display() {
        let err = PlatformError::AddRouteError("test error".to_string());
        assert_eq!(err.to_string(), "Failed to add route: test error");

        let err = PlatformError::DeleteRouteError("delete failed".to_string());
        assert_eq!(err.to_string(), "Failed to delete route: delete failed");

        let err = PlatformError::HostsError("hosts issue".to_string());
        assert_eq!(err.to_string(), "Failed to update hosts file: hosts issue");

        let err = PlatformError::UnsupportedPlatform;
        assert_eq!(err.to_string(), "Unsupported platform");
    }

    #[test]
    fn test_get_routing_manager_returns_ok() {
        // On supported platforms (macOS, Linux, Windows), this should succeed
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            let result = get_routing_manager();
            assert!(result.is_ok());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_mac_routing_manager_creation() {
        // Just verify it can be created without panicking
        let _ = mac::MacRoutingManager::new();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_routing_manager_creation() {
        let _ = linux::LinuxRoutingManager::new();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_routing_manager_creation() {
        let _ = windows::WindowsRoutingManager::new();
    }
}
