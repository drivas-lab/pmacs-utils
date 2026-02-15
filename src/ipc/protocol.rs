//! IPC protocol for tray-daemon communication
//!
//! Uses length-prefixed JSON framing:
//! - 4-byte big-endian length prefix
//! - JSON payload (max 1MB)

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum message size (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// IPC path for daemon communication
#[cfg(windows)]
pub fn ipc_path() -> String {
    r"\\.\pipe\pmacs-vpn-daemon".to_string()
}

#[cfg(not(windows))]
pub fn ipc_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/.pmacs-vpn/daemon.sock", home)
}

/// Requests from tray to daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrayRequest {
    /// Get current daemon status
    GetStatus,
    /// Request graceful disconnect
    Disconnect,
    /// Ping to check if daemon is alive
    Ping,
}

/// Responses from daemon to tray
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Current daemon status
    Status(DaemonStatus),
    /// Disconnect acknowledged
    Disconnected,
    /// Ping response
    Pong,
    /// Error occurred
    Error(String),
}

/// Daemon status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// TUN device name
    pub tunnel_device: String,
    /// VPN gateway IP
    pub gateway: String,
    /// When the VPN was connected (Unix timestamp as string)
    pub connected_at: String,
    /// Connection uptime in seconds
    pub uptime_secs: u64,
}

/// Read a length-prefixed JSON message from an async reader
pub async fn read_message<R, T>(reader: &mut R) -> io::Result<T>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    // Read 4-byte length prefix (big-endian)
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate length
    if len > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Message too large: {} bytes (max {})",
                len, MAX_MESSAGE_SIZE
            ),
        ));
    }

    // Read JSON payload
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    // Deserialize
    serde_json::from_slice(&buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON parse error: {}", e),
        )
    })
}

/// Write a length-prefixed JSON message to an async writer
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    // Serialize to JSON
    let json = serde_json::to_vec(message).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON serialize error: {}", e),
        )
    })?;

    // Validate length
    if json.len() > MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Message too large: {} bytes (max {})",
                json.len(),
                MAX_MESSAGE_SIZE
            ),
        ));
    }

    // Write 4-byte length prefix (big-endian)
    let len_buf = (json.len() as u32).to_be_bytes();
    writer.write_all(&len_buf).await?;

    // Write JSON payload
    writer.write_all(&json).await?;
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tray_request_serialization() {
        let req = TrayRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Ping"));

        let req = TrayRequest::GetStatus;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("GetStatus"));
    }

    #[test]
    fn test_daemon_response_serialization() {
        let resp = DaemonResponse::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("Pong"));

        let status = DaemonStatus {
            tunnel_device: "tun0".to_string(),
            gateway: "10.0.0.1".to_string(),
            connected_at: "12345".to_string(),
            uptime_secs: 100,
        };
        let resp = DaemonResponse::Status(status);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("tun0"));
        assert!(json.contains("10.0.0.1"));
    }

    #[test]
    fn test_ipc_path() {
        let path = ipc_path();
        #[cfg(windows)]
        assert!(path.starts_with(r"\\.\pipe\"));
        #[cfg(not(windows))]
        assert!(path.contains("daemon.sock"));
    }
}
