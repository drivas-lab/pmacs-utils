//! Windows-specific routing implementation

use super::{PlatformError, RoutingManager};
use std::process::Command;
use tracing::{debug, info, warn};

pub struct WindowsRoutingManager {
    /// Interface index for the TUN device (if known)
    interface_index: Option<u32>,
}

impl WindowsRoutingManager {
    pub fn new() -> Self {
        Self {
            interface_index: None,
        }
    }

    /// Create a routing manager with a specific interface
    pub fn with_interface(interface_name: &str) -> Self {
        let index = get_interface_index(interface_name);
        if let Some(idx) = index {
            info!("Using interface {} (index {})", interface_name, idx);
        } else {
            warn!(
                "Could not find interface index for {}, routes may not work",
                interface_name
            );
        }
        Self {
            interface_index: index,
        }
    }
}

impl Default for WindowsRoutingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingManager for WindowsRoutingManager {
    fn add_route(&self, destination: &str, gateway: &str) -> Result<(), PlatformError> {
        // If we have an interface index, use it for proper routing
        // Otherwise fall back to gateway-based routing
        let output = if let Some(if_index) = self.interface_index {
            debug!(
                "Adding route {} via interface {} (on-link)",
                destination, if_index
            );
            // Use on-link routing (0.0.0.0 gateway) with interface index
            Command::new("route")
                .args([
                    "add",
                    destination,
                    "mask",
                    "255.255.255.255",
                    gateway, // Use the TUN IP as gateway
                    "metric",
                    "1", // Low metric = high priority
                    "if",
                    &if_index.to_string(),
                ])
                .output()
                .map_err(|e| PlatformError::AddRouteError(e.to_string()))?
        } else {
            debug!("Adding route {} via gateway {}", destination, gateway);
            Command::new("route")
                .args(["add", destination, "mask", "255.255.255.255", gateway])
                .output()
                .map_err(|e| PlatformError::AddRouteError(e.to_string()))?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Windows route command outputs to stdout, not stderr
            let msg = if stderr.trim().is_empty() {
                stdout.to_string()
            } else {
                stderr.to_string()
            };
            return Err(PlatformError::AddRouteError(msg));
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

/// Get the interface index for a given adapter name
fn get_interface_index(name: &str) -> Option<u32> {
    // Use PowerShell to get the interface index
    // Get-NetAdapter -Name "wintun" | Select-Object -ExpandProperty ifIndex
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifIndex",
                name
            ),
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        debug!("PowerShell Get-NetAdapter failed for {}", name);
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let index_str = stdout.trim();
    debug!("Interface {} has index: {}", name, index_str);

    index_str.parse().ok()
}
