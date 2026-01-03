//! Route table manipulation for split-tunnel VPN

use crate::platform::{get_routing_manager, PlatformError};
use std::net::{IpAddr, ToSocketAddrs};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RoutingError {
    #[error("DNS resolution failed for {host}: {source}")]
    DnsError {
        host: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Platform error: {0}")]
    PlatformError(#[from] PlatformError),
    #[error("No IP addresses found for host: {0}")]
    NoAddressFound(String),
}

pub struct VpnRouter {
    gateway: String,
}

impl VpnRouter {
    pub fn new(gateway: String) -> Result<Self, RoutingError> {
        Ok(Self { gateway })
    }

    pub fn resolve_host(&self, hostname: &str) -> Result<IpAddr, RoutingError> {
        // Use std::net::ToSocketAddrs which works without runtime conflicts
        let addr_str = format!("{}:0", hostname);
        let addrs = addr_str
            .to_socket_addrs()
            .map_err(|e| RoutingError::DnsError {
                host: hostname.to_string(),
                source: Box::new(e),
            })?;

        addrs
            .into_iter()
            .next()
            .map(|a| a.ip())
            .ok_or_else(|| RoutingError::NoAddressFound(hostname.to_string()))
    }

    pub fn add_host_route(&self, hostname: &str) -> Result<IpAddr, RoutingError> {
        let ip = self.resolve_host(hostname)?;
        let manager = get_routing_manager()?;
        manager.add_route(&ip.to_string(), &self.gateway)?;
        Ok(ip)
    }

    pub fn remove_host_route(&self, hostname: &str) -> Result<(), RoutingError> {
        let ip = self.resolve_host(hostname)?;
        let manager = get_routing_manager()?;
        manager.delete_route(&ip.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformError;

    #[test]
    fn test_routing_error_display() {
        let err = RoutingError::NoAddressFound("test.example.com".to_string());
        assert_eq!(
            err.to_string(),
            "No IP addresses found for host: test.example.com"
        );

        let platform_err = PlatformError::AddRouteError("permission denied".to_string());
        let err = RoutingError::PlatformError(platform_err);
        assert!(err.to_string().contains("Platform error"));
    }

    #[test]
    fn test_vpn_router_creation() {
        let router = VpnRouter::new("10.0.0.1".to_string());
        assert!(router.is_ok());

        let router = router.unwrap();
        assert_eq!(router.gateway, "10.0.0.1");
    }

    #[test]
    fn test_resolve_known_host() {
        // This test requires network access
        let router = VpnRouter::new("10.0.0.1".to_string()).unwrap();

        // Use localhost which should always resolve
        let result = router.resolve_host("localhost");
        // localhost might not be configured on all systems, so we just check it doesn't panic
        // On most systems it should resolve to 127.0.0.1 or ::1
        if let Ok(ip) = result {
            let ip_str = ip.to_string();
            assert!(ip_str == "127.0.0.1" || ip_str == "::1");
        }
    }

    #[test]
    fn test_resolve_nonexistent_host() {
        let router = VpnRouter::new("10.0.0.1".to_string()).unwrap();

        // Use a definitely nonexistent domain
        let result = router.resolve_host("this-domain-definitely-does-not-exist-12345.invalid");
        assert!(result.is_err());

        if let Err(RoutingError::DnsError { host, .. }) = result {
            assert!(host.contains("this-domain-definitely-does-not-exist"));
        }
    }

    #[test]
    fn test_routing_error_from_platform_error() {
        let platform_err = PlatformError::DeleteRouteError("route not found".to_string());
        let routing_err: RoutingError = platform_err.into();

        match routing_err {
            RoutingError::PlatformError(e) => {
                assert!(e.to_string().contains("route not found"));
            }
            _ => panic!("Expected PlatformError variant"),
        }
    }

    #[test]
    fn test_vpn_router_gateway_stored() {
        let gateway = "192.168.1.1".to_string();
        let router = VpnRouter::new(gateway.clone()).unwrap();
        assert_eq!(router.gateway, gateway);
    }
}
