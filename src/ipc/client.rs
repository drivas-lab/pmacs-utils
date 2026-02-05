//! IPC client for tray-side communication
//!
//! Connects to the daemon via named pipe (Windows) or Unix socket (Linux/macOS)
//! and provides methods to ping, get status, and request disconnect.

use super::protocol::{
    ipc_path, read_message, write_message, DaemonResponse, DaemonStatus, TrayRequest,
};
use std::io;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

#[cfg(windows)]
use interprocess::local_socket::tokio::prelude::*;
#[cfg(windows)]
use interprocess::local_socket::GenericFilePath;

#[cfg(not(windows))]
use tokio::net::UnixStream;

/// Timeout for IPC operations
const IPC_TIMEOUT: Duration = Duration::from_secs(2);

/// IPC client for communicating with the daemon
pub struct IpcClient {
    ipc_path: String,
}

impl IpcClient {
    /// Create a new IPC client using the default path
    pub fn new() -> Self {
        Self {
            ipc_path: ipc_path(),
        }
    }

    /// Create a new IPC client with a custom path
    pub fn with_path(ipc_path: String) -> Self {
        Self { ipc_path }
    }

    /// Ping the daemon to check if it's alive
    ///
    /// Returns Ok(()) if daemon responds, Err if unreachable or timeout
    pub async fn ping(&self) -> io::Result<()> {
        let response = self.send_request(TrayRequest::Ping).await?;
        match response {
            DaemonResponse::Pong => Ok(()),
            DaemonResponse::Error(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response to ping",
            )),
        }
    }

    /// Get daemon status
    ///
    /// Returns daemon status or error if unreachable
    pub async fn get_status(&self) -> io::Result<DaemonStatus> {
        let response = self.send_request(TrayRequest::GetStatus).await?;
        match response {
            DaemonResponse::Status(status) => Ok(status),
            DaemonResponse::Error(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response to GetStatus",
            )),
        }
    }

    /// Request daemon to disconnect
    ///
    /// Returns Ok(()) if daemon acknowledges, Err if unreachable
    pub async fn disconnect(&self) -> io::Result<()> {
        let response = self.send_request(TrayRequest::Disconnect).await?;
        match response {
            DaemonResponse::Disconnected => Ok(()),
            DaemonResponse::Error(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected response to Disconnect",
            )),
        }
    }

    /// Check if daemon is reachable (non-blocking ping)
    pub async fn is_daemon_alive(&self) -> bool {
        self.ping().await.is_ok()
    }

    /// Send a request to the daemon and wait for response
    #[cfg(windows)]
    async fn send_request(&self, request: TrayRequest) -> io::Result<DaemonResponse> {
        debug!("Sending IPC request: {:?}", request);

        // Connect with timeout
        let name = self.ipc_path.clone().to_fs_name::<GenericFilePath>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let stream = match timeout(IPC_TIMEOUT, interprocess::local_socket::tokio::Stream::connect(name)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!("Failed to connect to IPC: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                debug!("IPC connect timeout");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Connect timeout"));
            }
        };

        let (mut reader, mut writer) = stream.split();

        // Send request with timeout
        match timeout(IPC_TIMEOUT, write_message(&mut writer, &request)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "Write timeout")),
        }

        // Read response with timeout
        match timeout(IPC_TIMEOUT, read_message(&mut reader)).await {
            Ok(Ok(response)) => {
                debug!("Received IPC response: {:?}", response);
                Ok(response)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Read timeout")),
        }
    }

    /// Send a request to the daemon and wait for response
    #[cfg(not(windows))]
    async fn send_request(&self, request: TrayRequest) -> io::Result<DaemonResponse> {
        debug!("Sending IPC request: {:?}", request);

        // Connect with timeout
        let stream = match timeout(IPC_TIMEOUT, UnixStream::connect(&self.ipc_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!("Failed to connect to IPC: {}", e);
                return Err(e);
            }
            Err(_) => {
                debug!("IPC connect timeout");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Connect timeout"));
            }
        };

        let (mut reader, mut writer) = stream.into_split();

        // Send request with timeout
        match timeout(IPC_TIMEOUT, write_message(&mut writer, &request)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "Write timeout")),
        }

        // Read response with timeout
        match timeout(IPC_TIMEOUT, read_message(&mut reader)).await {
            Ok(Ok(response)) => {
                debug!("Received IPC response: {:?}", response);
                Ok(response)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Read timeout")),
        }
    }
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Try to ping the daemon (convenience function)
///
/// Returns true if daemon is alive, false otherwise
pub async fn daemon_is_alive() -> bool {
    IpcClient::new().is_daemon_alive().await
}

/// Try to ping daemon with custom path (convenience function)
pub async fn daemon_is_alive_at(ipc_path: &str) -> bool {
    IpcClient::with_path(ipc_path.to_string())
        .is_daemon_alive()
        .await
}
