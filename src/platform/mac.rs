//! macOS-specific routing implementation
//!
//! On macOS, we use the `route` command to manage routing table entries.
//! For VPN split-tunneling, routes are added with `-interface` to direct
//! traffic through the tunnel device (e.g., utun9).
//!
//! # Commands
//!
//! ```bash
//! # Add route through tunnel interface
//! route -n add -host 172.16.38.40 -interface utun9
//!
//! # Delete route
//! route -n delete -host 172.16.38.40
//! ```

use super::{PlatformError, RoutingManager};
use std::process::Command;
use tracing::{debug, warn};

pub struct MacRoutingManager;

impl MacRoutingManager {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacRoutingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingManager for MacRoutingManager {
    /// Add a route for a host through a tunnel interface
    ///
    /// # Arguments
    /// * `destination` - IP address to route (e.g., "172.16.38.40")
    /// * `interface` - Tunnel device name (e.g., "utun9")
    fn add_route(&self, destination: &str, interface: &str) -> Result<(), PlatformError> {
        debug!("Adding route: {} via interface {}", destination, interface);

        let output = Command::new("route")
            .args(["-n", "add", "-host", destination, "-interface", interface])
            .output()
            .map_err(|e| PlatformError::AddRouteError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.to_string();

            // "File exists" means route already exists - not a fatal error
            if stderr_str.contains("File exists") {
                warn!("Route already exists for {}, continuing", destination);
                return Ok(());
            }

            return Err(PlatformError::AddRouteError(stderr_str));
        }

        Ok(())
    }

    /// Delete a route for a host
    ///
    /// # Arguments
    /// * `destination` - IP address to remove route for
    fn delete_route(&self, destination: &str) -> Result<(), PlatformError> {
        debug!("Deleting route: {}", destination);

        let output = Command::new("route")
            .args(["-n", "delete", "-host", destination])
            .output()
            .map_err(|e| PlatformError::DeleteRouteError(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr_str = stderr.to_string();

            // "not in table" means route doesn't exist - not a fatal error during cleanup
            if stderr_str.contains("not in table") {
                warn!("Route not found for {}, continuing", destination);
                return Ok(());
            }

            return Err(PlatformError::DeleteRouteError(stderr_str));
        }

        Ok(())
    }
}
