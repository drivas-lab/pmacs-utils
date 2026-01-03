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
