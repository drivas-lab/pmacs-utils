//! IPC server for daemon-side communication
//!
//! Listens on a named pipe (Windows) or Unix socket (Linux/macOS)
//! and handles requests from the tray application.

use super::protocol::{read_message, write_message, DaemonResponse, DaemonStatus, TrayRequest};
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use interprocess::local_socket::tokio::{prelude::*, Stream};
#[cfg(windows)]
use interprocess::local_socket::{GenericFilePath, ListenerOptions};

#[cfg(not(windows))]
use tokio::net::{UnixListener, UnixStream};

/// Shared daemon state accessible by IPC server
pub struct DaemonState {
    pub tunnel_device: String,
    pub gateway: String,
    pub connected_at: String,
    start_time: u64,
}

impl DaemonState {
    pub fn new(tunnel_device: String, gateway: String, connected_at: String) -> Self {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            tunnel_device,
            gateway,
            connected_at,
            start_time,
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.start_time)
    }

    pub fn to_status(&self) -> DaemonStatus {
        DaemonStatus {
            tunnel_device: self.tunnel_device.clone(),
            gateway: self.gateway.clone(),
            connected_at: self.connected_at.clone(),
            uptime_secs: self.uptime_secs(),
        }
    }
}

/// IPC server that handles tray requests
pub struct IpcServer {
    state: Arc<RwLock<DaemonState>>,
    shutdown_tx: broadcast::Sender<()>,
    ipc_path: String,
}

impl IpcServer {
    /// Create a new IPC server with the given daemon state
    pub fn new(
        ipc_path: String,
        state: DaemonState,
    ) -> (Self, broadcast::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let server = Self {
            state: Arc::new(RwLock::new(state)),
            shutdown_tx,
            ipc_path,
        };

        (server, shutdown_rx)
    }

    /// Get a sender to trigger shutdown
    pub fn shutdown_sender(&self) -> broadcast::Sender<()> {
        self.shutdown_tx.clone()
    }

    /// Run the IPC server (call in a spawned task)
    #[cfg(windows)]
    pub async fn run(self) -> io::Result<()> {
        info!("Starting IPC server on {}", self.ipc_path);

        // Create listener options with the named pipe path
        let name = self.ipc_path.clone().to_fs_name::<GenericFilePath>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let listener = ListenerOptions::new()
            .name(name)
            .create_tokio()
            .map_err(|e| {
                error!("Failed to create IPC listener: {}", e);
                io::Error::new(io::ErrorKind::AddrInUse, e.to_string())
            })?;

        info!("IPC server listening");

        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let state = self.state.clone();
                    let shutdown_tx = self.shutdown_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client_windows(stream, state, shutdown_tx).await {
                            debug!("Client disconnected: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept IPC connection: {}", e);
                }
            }
        }
    }

    /// Run the IPC server (call in a spawned task)
    #[cfg(not(windows))]
    pub async fn run(self) -> io::Result<()> {
        info!("Starting IPC server on {}", self.ipc_path);

        // Remove existing socket file if present
        let _ = std::fs::remove_file(&self.ipc_path);

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&self.ipc_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.ipc_path)?;

        // Set socket permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&self.ipc_path, perms);
        }

        info!("IPC server listening");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = self.state.clone();
                    let shutdown_tx = self.shutdown_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client_unix(stream, state, shutdown_tx).await {
                            debug!("Client disconnected: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept IPC connection: {}", e);
                }
            }
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        // Clean up socket file on Unix
        #[cfg(not(windows))]
        {
            let _ = std::fs::remove_file(&self.ipc_path);
        }
    }
}

/// Handle a client connection (Windows)
#[cfg(windows)]
async fn handle_client_windows(
    stream: Stream,
    state: Arc<RwLock<DaemonState>>,
    shutdown_tx: broadcast::Sender<()>,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.split();

    loop {
        let request: TrayRequest = match read_message(&mut reader).await {
            Ok(req) => req,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(()); // Client closed connection
            }
            Err(e) => return Err(e),
        };

        debug!("Received IPC request: {:?}", request);

        let response = match request {
            TrayRequest::Ping => DaemonResponse::Pong,
            TrayRequest::GetStatus => {
                let state = state.read().await;
                DaemonResponse::Status(state.to_status())
            }
            TrayRequest::Disconnect => {
                info!("Received disconnect request via IPC");
                let _ = shutdown_tx.send(());
                DaemonResponse::Disconnected
            }
        };

        write_message(&mut writer, &response).await?;
    }
}

/// Handle a client connection (Unix)
#[cfg(not(windows))]
async fn handle_client_unix(
    stream: UnixStream,
    state: Arc<RwLock<DaemonState>>,
    shutdown_tx: broadcast::Sender<()>,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    loop {
        let request: TrayRequest = match read_message(&mut reader).await {
            Ok(req) => req,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(()); // Client closed connection
            }
            Err(e) => return Err(e),
        };

        debug!("Received IPC request: {:?}", request);

        let response = match request {
            TrayRequest::Ping => DaemonResponse::Pong,
            TrayRequest::GetStatus => {
                let state = state.read().await;
                DaemonResponse::Status(state.to_status())
            }
            TrayRequest::Disconnect => {
                info!("Received disconnect request via IPC");
                let _ = shutdown_tx.send(());
                DaemonResponse::Disconnected
            }
        };

        write_message(&mut writer, &response).await?;
    }
}

/// Clean up IPC socket file (call on daemon exit)
#[cfg(not(windows))]
pub fn cleanup_ipc(ipc_path: &str) {
    let _ = std::fs::remove_file(ipc_path);
}

#[cfg(windows)]
pub fn cleanup_ipc(_ipc_path: &str) {
    // Named pipes are cleaned up automatically on Windows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::client::IpcClient;

    /// Generate a unique IPC path for testing (avoids conflict with running daemon)
    fn test_ipc_path() -> String {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        #[cfg(windows)]
        {
            format!(r"\\.\pipe\pmacs-vpn-test-{}-{}", id, ts)
        }
        #[cfg(not(windows))]
        {
            format!("/tmp/pmacs-vpn-test-{}-{}.sock", id, ts)
        }
    }

    #[tokio::test]
    async fn test_ipc_ping_pong() {
        let ipc_path = test_ipc_path();
        let state = DaemonState::new(
            "tun0".to_string(),
            "10.0.0.1".to_string(),
            "12345".to_string(),
        );

        let (server, _shutdown_rx) = IpcServer::new(ipc_path.clone(), state);

        // Start server in background
        let server_handle = tokio::spawn(async move {
            // Server runs until we abort it
            let _ = server.run().await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Test ping
        let client = IpcClient::with_path(ipc_path.clone());
        let result = client.ping().await;
        assert!(result.is_ok(), "Ping should succeed: {:?}", result.err());

        // Test get_status
        let status = client.get_status().await;
        assert!(status.is_ok(), "GetStatus should succeed: {:?}", status.err());
        let status = status.unwrap();
        assert_eq!(status.tunnel_device, "tun0");
        assert_eq!(status.gateway, "10.0.0.1");

        // Cleanup
        server_handle.abort();
        cleanup_ipc(&ipc_path);
    }

    #[tokio::test]
    async fn test_ipc_disconnect_triggers_shutdown() {
        let ipc_path = test_ipc_path();
        let state = DaemonState::new(
            "tun0".to_string(),
            "10.0.0.1".to_string(),
            "12345".to_string(),
        );

        let (server, mut shutdown_rx) = IpcServer::new(ipc_path.clone(), state);

        // Start server in background
        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Send disconnect request
        let client = IpcClient::with_path(ipc_path.clone());
        let result = client.disconnect().await;
        assert!(result.is_ok(), "Disconnect should succeed: {:?}", result.err());

        // Check that shutdown was triggered
        let shutdown_received = tokio::time::timeout(
            tokio::time::Duration::from_millis(500),
            shutdown_rx.recv(),
        )
        .await;
        assert!(shutdown_received.is_ok(), "Should receive shutdown signal");

        // Cleanup
        server_handle.abort();
        cleanup_ipc(&ipc_path);
    }

    #[tokio::test]
    async fn test_ipc_client_fails_when_no_server() {
        let ipc_path = test_ipc_path();

        // No server running
        let client = IpcClient::with_path(ipc_path);
        let result = client.ping().await;
        assert!(result.is_err(), "Ping should fail when no server");
    }

    #[test]
    fn test_daemon_state_uptime() {
        let state = DaemonState::new(
            "tun0".to_string(),
            "10.0.0.1".to_string(),
            "12345".to_string(),
        );

        // Uptime should be 0 or very close to it
        assert!(state.uptime_secs() < 2);
    }
}
