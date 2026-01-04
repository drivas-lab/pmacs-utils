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
//! - `openconnect`: Legacy OpenConnect script integration (deprecated)
//! - `state`: Persistent state for crash recovery
//!
//! # Usage
//!
//! As an OpenConnect script:
//! ```bash
//! sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
//!   -s 'pmacs-vpn script'
//! ```

pub mod config;
pub mod credentials;
pub mod gp;
pub mod notifications;
pub mod openconnect;
pub mod platform;
pub mod startup;
pub mod state;
pub mod tray;
pub mod vpn;

pub use config::{Config, DuoMethod, Preferences, VpnConfig};
pub use credentials::{delete_password, get_password, store_password};
pub use openconnect::handle_script_mode;
pub use state::{AuthToken, VpnState};
