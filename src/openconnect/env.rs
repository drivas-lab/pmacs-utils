//! OpenConnect environment variable parsing
//!
//! When OpenConnect invokes us as a script, it sets environment variables
//! with connection details. This module parses those variables.
//!
//! # Key Variables
//!
//! | Variable | Example | Description |
//! |----------|---------|-------------|
//! | `reason` | `connect` | Lifecycle event |
//! | `TUNDEV` | `utun9` | Tunnel device name |
//! | `VPNGATEWAY` | `10.0.0.1` | VPN gateway IP |
//! | `INTERNAL_IP4_ADDRESS` | `10.0.0.100` | Client's VPN IP |
//! | `INTERNAL_IP4_DNS` | `10.0.0.2` | VPN DNS server(s) |
//! | `INTERNAL_IP4_NETMASK` | `255.255.255.0` | VPN netmask |

use std::env;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnvError {
    #[error("Missing required environment variable: {0}")]
    MissingVar(String),
    #[error("Invalid IP address in {var}: {value}")]
    InvalidIp { var: String, value: String },
    #[error("Unknown reason: {0}")]
    UnknownReason(String),
}

/// The reason OpenConnect is invoking the script
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Pre-initialization (before tunnel is created)
    PreInit,
    /// VPN tunnel established, configure routing
    Connect,
    /// VPN shutting down, cleanup
    Disconnect,
    /// VPN reconnected after brief disconnect
    Reconnect,
}

impl std::str::FromStr for Reason {
    type Err = EnvError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pre-init" => Ok(Reason::PreInit),
            "connect" => Ok(Reason::Connect),
            "disconnect" => Ok(Reason::Disconnect),
            "reconnect" => Ok(Reason::Reconnect),
            _ => Err(EnvError::UnknownReason(s.to_string())),
        }
    }
}

/// Parsed OpenConnect environment variables
#[derive(Debug, Clone)]
pub struct OpenConnectEnv {
    /// Lifecycle event (connect, disconnect, reconnect)
    pub reason: Reason,
    /// Tunnel device name (e.g., "utun9" on macOS, "tun0" on Linux)
    pub tunnel_device: String,
    /// VPN gateway IP address
    pub gateway: IpAddr,
    /// Client's assigned VPN IP address
    pub internal_ip: IpAddr,
    /// VPN DNS server(s), space-separated if multiple
    pub dns_servers: Vec<IpAddr>,
    /// VPN netmask (optional)
    pub netmask: Option<String>,
}

impl OpenConnectEnv {
    /// Parse OpenConnect environment variables from the current process
    pub fn from_env() -> Result<Self, EnvError> {
        Self::from_env_fn(|key| env::var(key))
    }

    /// Parse environment using a custom getter (for testing)
    pub fn from_env_fn<F>(get_var: F) -> Result<Self, EnvError>
    where
        F: Fn(&str) -> Result<String, env::VarError>,
    {
        let reason_str = get_var("reason").map_err(|_| EnvError::MissingVar("reason".into()))?;
        let reason: Reason = reason_str.parse()?;

        // For pre-init, we don't have tunnel info yet
        if reason == Reason::PreInit {
            return Ok(Self {
                reason,
                tunnel_device: String::new(),
                gateway: "0.0.0.0".parse().unwrap(),
                internal_ip: "0.0.0.0".parse().unwrap(),
                dns_servers: vec![],
                netmask: None,
            });
        }

        let tunnel_device = get_var("TUNDEV").map_err(|_| EnvError::MissingVar("TUNDEV".into()))?;

        let gateway_str =
            get_var("VPNGATEWAY").map_err(|_| EnvError::MissingVar("VPNGATEWAY".into()))?;
        let gateway = gateway_str.parse().map_err(|_| EnvError::InvalidIp {
            var: "VPNGATEWAY".into(),
            value: gateway_str,
        })?;

        let internal_ip_str = get_var("INTERNAL_IP4_ADDRESS")
            .map_err(|_| EnvError::MissingVar("INTERNAL_IP4_ADDRESS".into()))?;
        let internal_ip = internal_ip_str.parse().map_err(|_| EnvError::InvalidIp {
            var: "INTERNAL_IP4_ADDRESS".into(),
            value: internal_ip_str,
        })?;

        let dns_servers = get_var("INTERNAL_IP4_DNS")
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();

        let netmask = get_var("INTERNAL_IP4_NETMASK").ok();

        Ok(Self {
            reason,
            tunnel_device,
            gateway,
            internal_ip,
            dns_servers,
            netmask,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Helper to create a mock environment getter
    fn make_getter(
        vars: HashMap<String, String>,
    ) -> impl Fn(&str) -> Result<String, env::VarError> {
        move |key: &str| vars.get(key).cloned().ok_or(env::VarError::NotPresent)
    }

    #[test]
    fn test_parse_connect_env() {
        let mut vars = HashMap::new();
        vars.insert("reason".to_string(), "connect".to_string());
        vars.insert("TUNDEV".to_string(), "utun9".to_string());
        vars.insert("VPNGATEWAY".to_string(), "10.0.0.1".to_string());
        vars.insert("INTERNAL_IP4_ADDRESS".to_string(), "10.0.0.100".to_string());
        vars.insert(
            "INTERNAL_IP4_DNS".to_string(),
            "10.0.0.2 10.0.0.3".to_string(),
        );
        vars.insert(
            "INTERNAL_IP4_NETMASK".to_string(),
            "255.255.255.0".to_string(),
        );

        let env = OpenConnectEnv::from_env_fn(make_getter(vars)).unwrap();

        assert_eq!(env.reason, Reason::Connect);
        assert_eq!(env.tunnel_device, "utun9");
        assert_eq!(env.gateway.to_string(), "10.0.0.1");
        assert_eq!(env.internal_ip.to_string(), "10.0.0.100");
        assert_eq!(env.dns_servers.len(), 2);
        assert_eq!(env.netmask, Some("255.255.255.0".to_string()));
    }

    #[test]
    fn test_parse_disconnect_env() {
        let mut vars = HashMap::new();
        vars.insert("reason".to_string(), "disconnect".to_string());
        vars.insert("TUNDEV".to_string(), "utun9".to_string());
        vars.insert("VPNGATEWAY".to_string(), "10.0.0.1".to_string());
        vars.insert("INTERNAL_IP4_ADDRESS".to_string(), "10.0.0.100".to_string());

        let env = OpenConnectEnv::from_env_fn(make_getter(vars)).unwrap();

        assert_eq!(env.reason, Reason::Disconnect);
    }

    #[test]
    fn test_parse_preinit_env() {
        let mut vars = HashMap::new();
        vars.insert("reason".to_string(), "pre-init".to_string());

        let env = OpenConnectEnv::from_env_fn(make_getter(vars)).unwrap();

        assert_eq!(env.reason, Reason::PreInit);
        assert!(env.tunnel_device.is_empty());
    }

    #[test]
    fn test_missing_reason() {
        let vars = HashMap::new();
        let result = OpenConnectEnv::from_env_fn(make_getter(vars));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EnvError::MissingVar(_)));
    }

    #[test]
    fn test_unknown_reason() {
        let mut vars = HashMap::new();
        vars.insert("reason".to_string(), "unknown_event".to_string());

        let result = OpenConnectEnv::from_env_fn(make_getter(vars));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EnvError::UnknownReason(_)));
    }

    #[test]
    fn test_invalid_ip() {
        let mut vars = HashMap::new();
        vars.insert("reason".to_string(), "connect".to_string());
        vars.insert("TUNDEV".to_string(), "utun9".to_string());
        vars.insert("VPNGATEWAY".to_string(), "not-an-ip".to_string());
        vars.insert("INTERNAL_IP4_ADDRESS".to_string(), "10.0.0.100".to_string());

        let result = OpenConnectEnv::from_env_fn(make_getter(vars));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EnvError::InvalidIp { .. }));
    }

    #[test]
    fn test_reason_parse() {
        assert_eq!("connect".parse::<Reason>().unwrap(), Reason::Connect);
        assert_eq!("disconnect".parse::<Reason>().unwrap(), Reason::Disconnect);
        assert_eq!("reconnect".parse::<Reason>().unwrap(), Reason::Reconnect);
        assert_eq!("pre-init".parse::<Reason>().unwrap(), Reason::PreInit);
        assert!("invalid".parse::<Reason>().is_err());
    }
}
