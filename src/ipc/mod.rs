//! IPC module for tray-daemon communication
//!
//! Provides cross-platform IPC using:
//! - Named pipes on Windows (`\\.\pipe\pmacs-vpn-daemon`)
//! - Unix sockets on Linux/macOS (`~/.pmacs-vpn/daemon.sock`)
//!
//! # Protocol
//!
//! Messages use length-prefixed JSON framing:
//! - 4-byte big-endian length prefix
//! - JSON payload (max 1MB)
//!
//! # Usage
//!
//! ## Daemon side (server)
//!
//! ```ignore
//! use pmacs_vpn::ipc::{IpcServer, DaemonState, protocol::ipc_path};
//!
//! let state = DaemonState::new(
//!     "tun0".to_string(),
//!     "10.0.0.1".to_string(),
//!     "12345".to_string(),
//! );
//! let (server, shutdown_rx) = IpcServer::new(ipc_path(), state);
//!
//! // Run server in background
//! tokio::spawn(async move { server.run().await });
//!
//! // Wait for shutdown signal (from IPC disconnect request or Ctrl+C)
//! let _ = shutdown_rx.recv().await;
//! ```
//!
//! ## Tray side (client)
//!
//! ```ignore
//! use pmacs_vpn::ipc::IpcClient;
//!
//! let client = IpcClient::new();
//!
//! // Check if daemon is alive
//! if client.ping().await.is_ok() {
//!     println!("Daemon is running");
//! }
//!
//! // Get status
//! if let Ok(status) = client.get_status().await {
//!     println!("Connected for {} seconds", status.uptime_secs);
//! }
//!
//! // Request disconnect
//! let _ = client.disconnect().await;
//! ```

pub mod client;
pub mod protocol;
pub mod server;

pub use client::{daemon_is_alive, IpcClient};
pub use protocol::{ipc_path, DaemonResponse, DaemonStatus, TrayRequest};
pub use server::{cleanup_ipc, DaemonState, IpcServer};
