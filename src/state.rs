//! VPN state persistence
//!
//! Tracks active routes and hosts entries to enable cleanup after crashes
//! or unexpected termination. State is stored in `~/.pmacs-vpn/state.json`.
//!
//! # State File Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "tunnel_device": "utun9",
//!   "gateway": "10.0.0.1",
//!   "routes": [
//!     {"hostname": "prometheus.pmacs.upenn.edu", "ip": "172.16.38.40"}
//!   ],
//!   "hosts_entries": [
//!     {"hostname": "prometheus.pmacs.upenn.edu", "ip": "172.16.38.40"}
//!   ],
//!   "connected_at": "2024-01-15T10:30:00Z"
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Failed to read state file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("Failed to parse state file: {0}")]
    ParseError(#[from] serde_json::Error),
    #[error("State directory not found: {0}")]
    DirectoryError(String),
}

/// A route entry (hostname to IP mapping)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteEntry {
    pub hostname: String,
    pub ip: IpAddr,
}

/// Persisted VPN state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnState {
    /// State file format version
    pub version: u32,
    /// Tunnel device name
    pub tunnel_device: String,
    /// VPN gateway IP
    pub gateway: IpAddr,
    /// Active routes
    pub routes: Vec<RouteEntry>,
    /// Hosts file entries we added
    pub hosts_entries: Vec<RouteEntry>,
    /// When the VPN was connected
    pub connected_at: String,
}

impl Default for VpnState {
    fn default() -> Self {
        Self {
            version: 1,
            tunnel_device: String::new(),
            gateway: "0.0.0.0".parse().unwrap(),
            routes: vec![],
            hosts_entries: vec![],
            connected_at: String::new(),
        }
    }
}

impl VpnState {
    /// Create a new state for a connection
    pub fn new(tunnel_device: String, gateway: IpAddr) -> Self {
        Self {
            version: 1,
            tunnel_device,
            gateway,
            routes: vec![],
            hosts_entries: vec![],
            connected_at: chrono_lite_now(),
        }
    }

    /// Add a route entry
    pub fn add_route(&mut self, hostname: String, ip: IpAddr) {
        self.routes.push(RouteEntry { hostname, ip });
    }

    /// Add a hosts entry
    pub fn add_hosts_entry(&mut self, hostname: String, ip: IpAddr) {
        self.hosts_entries.push(RouteEntry { hostname, ip });
    }

    /// Get the state file path
    /// Works on both Unix (HOME) and Windows (USERPROFILE/LOCALAPPDATA)
    pub fn state_file_path() -> Result<PathBuf, StateError> {
        // Try in order: HOME (Unix), USERPROFILE (Windows), LOCALAPPDATA (Windows)
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .or_else(|_| std::env::var("LOCALAPPDATA"))
            .map_err(|_| {
                StateError::DirectoryError(
                    "HOME/USERPROFILE/LOCALAPPDATA not set".into(),
                )
            })?;

        let state_dir = PathBuf::from(home).join(".pmacs-vpn");

        // Create directory if it doesn't exist
        if !state_dir.exists() {
            fs::create_dir_all(&state_dir)?;
        }

        Ok(state_dir.join("state.json"))
    }

    /// Load state from disk
    pub fn load() -> Result<Option<Self>, StateError> {
        let path = Self::state_file_path()?;

        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path)?;
        let state: VpnState = serde_json::from_str(&content)?;
        Ok(Some(state))
    }

    /// Save state to disk
    pub fn save(&self) -> Result<(), StateError> {
        let path = Self::state_file_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }

    /// Delete state file (on clean disconnect)
    pub fn delete() -> Result<(), StateError> {
        let path = Self::state_file_path()?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Check if there's an active state (for status command)
    pub fn is_active() -> bool {
        Self::load().ok().flatten().is_some()
    }
}

/// Simple timestamp without heavy chrono dependency
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_default() {
        let state = VpnState::default();
        assert_eq!(state.version, 1);
        assert!(state.routes.is_empty());
        assert!(state.hosts_entries.is_empty());
    }

    #[test]
    fn test_state_new() {
        let state = VpnState::new("utun9".to_string(), "10.0.0.1".parse().unwrap());
        assert_eq!(state.tunnel_device, "utun9");
        assert_eq!(state.gateway.to_string(), "10.0.0.1");
        assert!(!state.connected_at.is_empty());
    }

    #[test]
    fn test_add_route() {
        let mut state = VpnState::default();
        state.add_route("test.example.com".to_string(), "10.0.0.1".parse().unwrap());

        assert_eq!(state.routes.len(), 1);
        assert_eq!(state.routes[0].hostname, "test.example.com");
    }

    #[test]
    fn test_add_hosts_entry() {
        let mut state = VpnState::default();
        state.add_hosts_entry("test.example.com".to_string(), "10.0.0.1".parse().unwrap());

        assert_eq!(state.hosts_entries.len(), 1);
        assert_eq!(state.hosts_entries[0].hostname, "test.example.com");
    }

    #[test]
    fn test_state_serialization() {
        let mut state = VpnState::new("utun9".to_string(), "10.0.0.1".parse().unwrap());
        state.add_route(
            "test.example.com".to_string(),
            "172.16.38.40".parse().unwrap(),
        );

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("utun9"));
        assert!(json.contains("172.16.38.40"));

        let parsed: VpnState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tunnel_device, "utun9");
        assert_eq!(parsed.routes.len(), 1);
    }

    #[test]
    fn test_route_entry_equality() {
        let entry1 = RouteEntry {
            hostname: "test.example.com".to_string(),
            ip: "10.0.0.1".parse().unwrap(),
        };
        let entry2 = RouteEntry {
            hostname: "test.example.com".to_string(),
            ip: "10.0.0.1".parse().unwrap(),
        };
        assert_eq!(entry1, entry2);
    }
}
