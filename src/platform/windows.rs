//! Windows-specific routing implementation

use super::{PlatformError, RoutingManager};
use std::process::Command;

pub struct WindowsRoutingManager;

impl WindowsRoutingManager {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsRoutingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingManager for WindowsRoutingManager {
    fn add_route(&self, destination: &str, gateway: &str) -> Result<(), PlatformError> {
        let output = Command::new("route")
            .args(["add", destination, "mask", "255.255.255.255", gateway])
            .output()
            .map_err(|e| PlatformError::AddRouteError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PlatformError::AddRouteError(stderr.to_string()));
        }

        Ok(())
    }

    fn delete_route(&self, destination: &str) -> Result<(), PlatformError> {
        let output = Command::new("route")
            .args(["delete", destination])
            .output()
            .map_err(|e| PlatformError::DeleteRouteError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PlatformError::DeleteRouteError(stderr.to_string()));
        }

        Ok(())
    }
}
