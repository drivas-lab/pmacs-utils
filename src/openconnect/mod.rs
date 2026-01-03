//! OpenConnect integration module
//!
//! This module handles the integration with OpenConnect VPN client.
//! OpenConnect invokes our binary as a script with environment variables
//! describing the VPN connection state.
//!
//! # Usage
//!
//! ```bash
//! sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME \
//!   -s 'pmacs-vpn script'
//! ```
//!
//! # Lifecycle
//!
//! OpenConnect calls the script with `reason` set to:
//! - `connect`: VPN tunnel is established, configure routing
//! - `disconnect`: VPN is shutting down, cleanup
//! - `reconnect`: VPN reconnected after brief disconnect

pub mod env;
pub mod script;

pub use env::OpenConnectEnv;
pub use script::{handle_script_mode, ScriptError};
