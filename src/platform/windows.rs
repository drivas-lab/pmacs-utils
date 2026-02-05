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
            // Use on-link routing with interface index
            // Gateway must be 0.0.0.0 for point-to-point interfaces like wintun.
            // Using the TUN IP as gateway causes Windows to try routing TO
            // that IP instead of through the interface directly.
            Command::new("route")
                .args([
                    "add",
                    destination,
                    "mask",
                    "255.255.255.255",
                    "0.0.0.0", // On-link: no gateway, use interface directly
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
pub fn get_interface_index(name: &str) -> Option<u32> {
    // Try multiple approaches since Wintun adapters can be tricky to find

    // Approach 1: Get-NetAdapter by exact name
    if let Some(idx) = try_get_netadapter_index(name) {
        return Some(idx);
    }

    // Approach 2: Get-NetAdapter with wildcard (case-insensitive, partial match)
    if let Some(idx) = try_get_netadapter_index(&format!("*{}*", name)) {
        return Some(idx);
    }

    // Approach 3: Use netsh to list interfaces and find by name
    if let Some(idx) = try_netsh_interface_index(name) {
        return Some(idx);
    }

    debug!("Could not find interface index for {} using any method", name);
    None
}

fn try_get_netadapter_index(name: &str) -> Option<u32> {
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
    if index_str.is_empty() {
        return None;
    }
    debug!("Interface {} has index: {}", name, index_str);
    index_str.parse().ok()
}

fn try_netsh_interface_index(name: &str) -> Option<u32> {
    // netsh interface ipv4 show interfaces
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let name_lower = name.to_lowercase();

    // Parse output format: "Idx  Met  MTU   State  Name"
    for line in stdout.lines().skip(3) {
        // Skip header lines
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let iface_name = parts[4..].join(" ").to_lowercase();
            if iface_name.contains(&name_lower)
                && let Ok(idx) = parts[0].parse::<u32>() {
                    debug!("Found interface {} with index {} via netsh", name, idx);
                    return Some(idx);
            }
        }
    }
    None
}
