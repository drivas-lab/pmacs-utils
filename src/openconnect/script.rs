//! OpenConnect script mode handler
//!
//! This module implements the core logic for handling OpenConnect lifecycle events.
//! When invoked as a script, we:
//!
//! 1. Parse environment variables from OpenConnect
//! 2. On connect: resolve hosts → add routes → update /etc/hosts → save state
//! 3. On disconnect: remove routes → restore /etc/hosts → delete state
//!
//! # Error Handling
//!
//! Errors during script execution are logged and returned as exit codes.
//! OpenConnect expects exit code 0 for success, non-zero for failure.

use crate::config::Config;
use crate::openconnect::env::{OpenConnectEnv, Reason};
use crate::platform::{get_routing_manager, PlatformError};
use crate::state::VpnState;
use crate::vpn::hosts::HostsManager;
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Environment parsing failed: {0}")]
    EnvError(#[from] crate::openconnect::env::EnvError),
    #[error("Config error: {0}")]
    ConfigError(#[from] crate::config::ConfigError),
    #[error("State error: {0}")]
    StateError(#[from] crate::state::StateError),
    #[error("Platform error: {0}")]
    PlatformError(#[from] PlatformError),
    #[error("Hosts file error: {0}")]
    HostsError(#[from] crate::vpn::hosts::HostsError),
    #[error("DNS resolution failed for {host}: {message}")]
    DnsError { host: String, message: String },
    #[error("No VPN DNS servers available")]
    NoDnsServers,
}

/// Main entry point for script mode
///
/// Called when `pmacs-vpn script` is invoked by OpenConnect.
/// Reads environment variables and dispatches to the appropriate handler.
pub fn handle_script_mode() -> Result<(), ScriptError> {
    let env = OpenConnectEnv::from_env()?;

    info!(
        "Script mode: reason={:?}, tunnel={}",
        env.reason, env.tunnel_device
    );

    match env.reason {
        Reason::PreInit => {
            debug!("Pre-init phase, nothing to do");
            Ok(())
        }
        Reason::Connect => handle_connect(&env),
        Reason::Disconnect => handle_disconnect(&env),
        Reason::Reconnect => {
            info!("Reconnect detected, treating as fresh connect");
            // Clean up any stale state first
            let _ = handle_disconnect(&env);
            handle_connect(&env)
        }
    }
}

/// Handle VPN connect event
///
/// 1. Load config to get list of hosts to route
/// 2. Resolve each host using VPN's DNS
/// 3. Add route for each resolved IP through tunnel
/// 4. Update /etc/hosts with resolved names
/// 5. Save state for later cleanup
fn handle_connect(env: &OpenConnectEnv) -> Result<(), ScriptError> {
    info!(
        "Connecting: tunnel={}, gateway={}, dns={:?}",
        env.tunnel_device, env.gateway, env.dns_servers
    );

    // Load config
    let config = load_config()?;
    info!("Routing {} hosts through VPN", config.hosts.len());

    // Create VPN DNS resolver
    let resolver = create_vpn_resolver(&env.dns_servers)?;

    // Initialize state
    let mut state = VpnState::new(env.tunnel_device.clone(), env.gateway);

    // Get routing manager
    let routing_manager = get_routing_manager()?;

    // Resolve and route each host
    let mut hosts_map: HashMap<String, IpAddr> = HashMap::new();

    for hostname in &config.hosts {
        match resolve_with_vpn_dns(&resolver, hostname) {
            Ok(ip) => {
                info!("Resolved {} -> {}", hostname, ip);

                // Add route
                match routing_manager.add_route(&ip.to_string(), &env.tunnel_device) {
                    Ok(()) => {
                        info!("Added route: {} via {}", ip, env.tunnel_device);
                        state.add_route(hostname.clone(), ip);
                        hosts_map.insert(hostname.clone(), ip);
                    }
                    Err(e) => {
                        // Log but continue - route might already exist
                        warn!("Failed to add route for {}: {}", ip, e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to resolve {}: {}", hostname, e);
                // Continue with other hosts
            }
        }
    }

    // Update /etc/hosts
    if !hosts_map.is_empty() {
        let hosts_manager = HostsManager::new();
        match hosts_manager.add_entries(&hosts_map) {
            Ok(()) => {
                info!("Updated /etc/hosts with {} entries", hosts_map.len());
                for (hostname, ip) in &hosts_map {
                    state.add_hosts_entry(hostname.clone(), *ip);
                }
            }
            Err(e) => {
                warn!("Failed to update /etc/hosts: {} (continuing anyway)", e);
            }
        }
    }

    // Save state for cleanup
    state.save()?;
    info!("State saved, {} routes active", state.routes.len());

    Ok(())
}

/// Handle VPN disconnect event
///
/// 1. Load saved state
/// 2. Remove all routes we added
/// 3. Remove /etc/hosts entries
/// 4. Delete state file
fn handle_disconnect(env: &OpenConnectEnv) -> Result<(), ScriptError> {
    info!("Disconnecting: tunnel={}", env.tunnel_device);

    // Load state
    let state = match VpnState::load()? {
        Some(s) => s,
        None => {
            info!("No state file found, nothing to clean up");
            return Ok(());
        }
    };

    // Get routing manager
    let routing_manager = get_routing_manager()?;

    // Remove routes
    for route in &state.routes {
        match routing_manager.delete_route(&route.ip.to_string()) {
            Ok(()) => {
                info!("Removed route: {}", route.ip);
            }
            Err(e) => {
                warn!("Failed to remove route {}: {} (continuing)", route.ip, e);
            }
        }
    }

    // Remove /etc/hosts entries
    if !state.hosts_entries.is_empty() {
        let hosts_manager = HostsManager::new();
        match hosts_manager.remove_entries() {
            Ok(()) => {
                info!("Cleaned up /etc/hosts");
            }
            Err(e) => {
                warn!("Failed to clean /etc/hosts: {} (continuing)", e);
            }
        }
    }

    // Delete state file
    VpnState::delete()?;
    info!("State file deleted, cleanup complete");

    Ok(())
}

/// Load config from default locations
fn load_config() -> Result<Config, ScriptError> {
    // Try current directory first
    let local_config = std::path::PathBuf::from("pmacs-vpn.toml");
    if local_config.exists() {
        return Ok(Config::load(&local_config)?);
    }

    // Try home directory
    if let Ok(home) = std::env::var("HOME") {
        let home_config = std::path::PathBuf::from(home)
            .join(".pmacs-vpn")
            .join("config.toml");
        if home_config.exists() {
            return Ok(Config::load(&home_config)?);
        }
    }

    // Use defaults
    info!("No config file found, using defaults");
    Ok(Config::default())
}

/// Create a DNS resolver that uses the VPN's DNS servers
fn create_vpn_resolver(dns_servers: &[IpAddr]) -> Result<Resolver, ScriptError> {
    if dns_servers.is_empty() {
        return Err(ScriptError::NoDnsServers);
    }

    let mut config = ResolverConfig::new();

    for &ip in dns_servers {
        let socket_addr = std::net::SocketAddr::new(ip, 53);
        config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
    }

    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 2;

    Resolver::new(config, opts).map_err(|e| ScriptError::DnsError {
        host: "resolver".to_string(),
        message: e.to_string(),
    })
}

/// Resolve a hostname using the VPN DNS resolver
fn resolve_with_vpn_dns(resolver: &Resolver, hostname: &str) -> Result<IpAddr, ScriptError> {
    let response = resolver
        .lookup_ip(hostname)
        .map_err(|e| ScriptError::DnsError {
            host: hostname.to_string(),
            message: e.to_string(),
        })?;

    response.iter().next().ok_or_else(|| ScriptError::DnsError {
        host: hostname.to_string(),
        message: "No IP addresses returned".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_error_display() {
        let err = ScriptError::NoDnsServers;
        assert_eq!(err.to_string(), "No VPN DNS servers available");

        let err = ScriptError::DnsError {
            host: "test.example.com".to_string(),
            message: "timeout".to_string(),
        };
        assert!(err.to_string().contains("test.example.com"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_load_config_returns_default() {
        // When no config file exists, should return defaults
        let config = load_config().unwrap();
        assert_eq!(config.vpn.gateway, "psomvpn.uphs.upenn.edu");
    }
}
