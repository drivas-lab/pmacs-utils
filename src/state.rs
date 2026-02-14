//! VPN state persistence
//!
//! Tracks active routes and hosts entries to enable cleanup after crashes
//! or unexpected termination. State is stored in `~/.pmacs-vpn/state.json`.
//!
//! Also handles auth tokens for daemon mode (parent does auth, child uses token).
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
    /// Process ID of the VPN daemon (if running in background)
    #[serde(default)]
    pub pid: Option<u32>,
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
            pid: None,
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
            pid: None,
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
                StateError::DirectoryError("HOME/USERPROFILE/LOCALAPPDATA not set".into())
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
    /// Uses atomic write (temp file + rename) to prevent corruption on crash
    pub fn save(&self) -> Result<(), StateError> {
        let path = Self::state_file_path()?;
        let content = serde_json::to_string_pretty(self)?;

        // Write to temp file first for atomic operation
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, &content)?;

        // Atomic rename
        fs::rename(&temp_path, &path)?;
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

    /// Set the daemon PID
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = Some(pid);
    }

    /// Check if the daemon process is still running
    #[cfg(windows)]
    pub fn is_daemon_running(&self) -> bool {
        use std::process::Command;

        if let Some(pid) = self.pid {
            // Use tasklist to check if process exists
            let output = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    stdout.contains(&pid.to_string())
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Check if the daemon process is still running
    #[cfg(not(windows))]
    pub fn is_daemon_running(&self) -> bool {
        use nix::errno::Errno;
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        if let Some(pid) = self.pid {
            // EPERM means process exists but current user is not allowed to signal it.
            match kill(Pid::from_raw(pid as i32), None) {
                Ok(()) => true,
                Err(Errno::EPERM) => true,
                Err(Errno::ESRCH) => false,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Kill the daemon process
    #[cfg(windows)]
    pub fn kill_daemon(&self) -> Result<(), StateError> {
        if let Some(pid) = self.pid {
            // Use Windows API directly for better reliability
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_TERMINATE, TerminateProcess,
            };

            unsafe {
                match OpenProcess(PROCESS_TERMINATE, false, pid) {
                    Ok(handle) => {
                        let result = TerminateProcess(handle, 1);
                        let _ = CloseHandle(handle);
                        if result.is_err() {
                            tracing::warn!("TerminateProcess failed for PID {}", pid);
                        } else {
                            tracing::info!("Terminated daemon process {}", pid);
                        }
                    }
                    Err(e) => {
                        // Process might already be dead
                        tracing::debug!("Could not open process {}: {}", pid, e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Kill the daemon process
    #[cfg(not(windows))]
    pub fn kill_daemon(&self) -> Result<(), StateError> {
        use std::process::Command;

        if let Some(pid) = self.pid {
            let status = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .map_err(StateError::ReadError)?;

            if !status.success() {
                // Process might already be dead, which is fine
                tracing::warn!("kill returned non-zero for PID {}", pid);
            }
        }
        Ok(())
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

/// Auth token for passing credentials from parent to daemon child
/// Stored temporarily in ~/.pmacs-vpn/auth-token.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Gateway URL
    pub gateway: String,
    /// Username
    pub username: String,
    /// Auth cookie from login
    pub auth_cookie: String,
    /// Portal name from login
    pub portal: String,
    /// Domain from login
    pub domain: String,
    /// Hosts to route
    pub hosts: Vec<String>,
    /// Use aggressive keepalive
    pub keep_alive: bool,
    /// Created timestamp (for expiry check)
    pub created_at: u64,
    /// IPC path for tray-daemon communication
    #[serde(default)]
    pub ipc_path: Option<String>,
}

impl AuthToken {
    /// Create a new auth token
    pub fn new(
        gateway: String,
        username: String,
        auth_cookie: String,
        portal: String,
        domain: String,
        hosts: Vec<String>,
        keep_alive: bool,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            gateway,
            username,
            auth_cookie,
            portal,
            domain,
            hosts,
            keep_alive,
            created_at,
            ipc_path: None,
        }
    }

    /// Create a new auth token with IPC path
    #[allow(clippy::too_many_arguments)]
    pub fn with_ipc_path(
        gateway: String,
        username: String,
        auth_cookie: String,
        portal: String,
        domain: String,
        hosts: Vec<String>,
        keep_alive: bool,
        ipc_path: String,
    ) -> Self {
        let mut token = Self::new(
            gateway,
            username,
            auth_cookie,
            portal,
            domain,
            hosts,
            keep_alive,
        );
        token.ipc_path = Some(ipc_path);
        token
    }

    /// Get the auth token file path
    fn token_file_path() -> Result<PathBuf, StateError> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .or_else(|_| std::env::var("LOCALAPPDATA"))
            .map_err(|_| {
                StateError::DirectoryError("HOME/USERPROFILE/LOCALAPPDATA not set".into())
            })?;

        let state_dir = PathBuf::from(home).join(".pmacs-vpn");
        if !state_dir.exists() {
            fs::create_dir_all(&state_dir)?;
        }

        Ok(state_dir.join("auth-token.json"))
    }

    /// Save auth token (called by parent before spawning daemon)
    /// Uses atomic write (write to temp, then rename) with restrictive permissions
    pub fn save(&self) -> Result<PathBuf, StateError> {
        let path = Self::token_file_path()?;
        let content = serde_json::to_string_pretty(self)?;

        // Write to temp file first for atomic operation
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, &content)?;

        // Set restrictive permissions (0600) on Unix before rename
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&temp_path, perms)?;
        }

        // Atomic rename
        fs::rename(&temp_path, &path)?;
        Ok(path)
    }

    /// Load auth token (called by daemon child)
    pub fn load() -> Result<Option<Self>, StateError> {
        let path = Self::token_file_path()?;
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path)?;
        let token: AuthToken = serde_json::from_str(&content)?;

        // Check if token is expired (5 minutes max)
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now - token.created_at > 300 {
            // Token expired, delete it
            let _ = Self::delete();
            return Ok(None);
        }

        Ok(Some(token))
    }

    /// Delete auth token file (called after daemon starts)
    pub fn delete() -> Result<(), StateError> {
        let path = Self::token_file_path()?;
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
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

    #[test]
    fn test_state_pid_default_none() {
        let state = VpnState::default();
        assert!(state.pid.is_none());
    }

    #[test]
    fn test_state_set_pid() {
        let mut state = VpnState::default();
        assert!(state.pid.is_none());

        state.set_pid(12345);
        assert_eq!(state.pid, Some(12345));
    }

    #[test]
    fn test_state_pid_serialization() {
        let mut state = VpnState::new("utun9".to_string(), "10.0.0.1".parse().unwrap());
        state.set_pid(99999);

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("99999"));
        assert!(json.contains("\"pid\":99999"));

        let parsed: VpnState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, Some(99999));
    }

    #[test]
    fn test_state_pid_deserialization_missing() {
        // Old state files without pid field should deserialize with pid=None
        let json = r#"{
            "version": 1,
            "tunnel_device": "utun9",
            "gateway": "10.0.0.1",
            "routes": [],
            "hosts_entries": [],
            "connected_at": "12345"
        }"#;

        let parsed: VpnState = serde_json::from_str(json).unwrap();
        assert!(parsed.pid.is_none());
    }

    #[test]
    fn test_is_daemon_running_no_pid() {
        let state = VpnState::default();
        assert!(!state.is_daemon_running());
    }
}
