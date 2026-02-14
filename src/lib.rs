//! PMACS VPN - Split-tunnel VPN toolkit for PMACS cluster access
//!
//! This crate provides split-tunnel VPN functionality for accessing PMACS
//! cluster resources using a native GlobalProtect implementation. Routes only
//! specified hosts through the VPN tunnel while keeping other traffic on the
//! normal network.
//!
//! # Architecture
//!
//! - `config`: Configuration file handling (TOML)
//! - `gp`: Native GlobalProtect protocol implementation
//! - `platform`: Cross-platform routing (macOS, Linux, Windows)
//! - `vpn`: VPN routing and hosts file management
//! - `state`: Persistent state for crash recovery

pub mod config;
pub mod credentials;
pub mod gp;
pub mod ipc;
pub mod launchd;
pub mod macos_permissions;
pub mod notifications;
pub mod platform;
pub mod startup;
pub mod state;
pub mod tray;
pub mod vpn;

pub use config::{Config, DuoMethod, Preferences, VpnConfig};
pub use credentials::{delete_password, get_password, store_password};
pub use state::{AuthToken, VpnState};
