//! PMACS VPN - Split-tunnel VPN toolkit for PMACS cluster access
//!
//! This crate provides split-tunnel VPN functionality for accessing PMACS
//! cluster resources. It integrates with OpenConnect to route only specified
//! hosts through the VPN tunnel while keeping other traffic on the normal
//! network.
//!
//! # Architecture
//!
//! - `config`: Configuration file handling (TOML)
//! - `platform`: Cross-platform routing (macOS, Linux, Windows)
//! - `vpn`: VPN routing and hosts file management
//! - `openconnect`: OpenConnect script integration
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
pub mod openconnect;
pub mod platform;
pub mod state;
pub mod vpn;

pub use config::Config;
pub use openconnect::handle_script_mode;
pub use state::VpnState;
