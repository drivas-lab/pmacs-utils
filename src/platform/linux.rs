//! Linux-specific routing implementation

use super::{PlatformError, RoutingManager};
use std::process::Command;

pub struct LinuxRoutingManager {
    interface_name: Option<String>,
}

impl LinuxRoutingManager {
    pub fn new() -> Self {
        Self {
            interface_name: None,
        }
    }

    pub fn with_interface(interface_name: String) -> Self {
        Self {
            interface_name: Some(interface_name),
        }
    }
}

impl Default for LinuxRoutingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingManager for LinuxRoutingManager {
    fn add_route(&self, destination: &str, gateway: &str) -> Result<(), PlatformError> {
        let output = if let Some(ref iface) = self.interface_name {
            Command::new("ip")
                .args(["route", "add", destination, "dev", iface])
                .output()
                .map_err(|e| PlatformError::AddRouteError(e.to_string()))?
        } else {
            Command::new("ip")
                .args(["route", "add", destination, "via", gateway])
                .output()
                .map_err(|e| PlatformError::AddRouteError(e.to_string()))?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PlatformError::AddRouteError(stderr.to_string()));
        }

        Ok(())
    }

    fn delete_route(&self, destination: &str) -> Result<(), PlatformError> {
        let output = Command::new("ip")
            .args(["route", "delete", destination])
            .output()
            .map_err(|e| PlatformError::DeleteRouteError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PlatformError::DeleteRouteError(stderr.to_string()));
        }

        Ok(())
    }
}
