//! Route table manipulation for split-tunnel VPN

use crate::platform::{get_routing_manager, PlatformError};
use std::net::IpAddr;
use thiserror::Error;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

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
    resolver: Resolver,
}

impl VpnRouter {
    pub fn new(gateway: String) -> Result<Self, RoutingError> {
        let resolver =
            Resolver::new(ResolverConfig::default(), ResolverOpts::default()).map_err(|e| {
                RoutingError::DnsError {
                    host: "resolver".to_string(),
                    source: Box::new(e),
                }
            })?;

        Ok(Self { gateway, resolver })
    }

    pub fn resolve_host(&self, hostname: &str) -> Result<IpAddr, RoutingError> {
        let response = self
            .resolver
            .lookup_ip(hostname)
            .map_err(|e| RoutingError::DnsError {
                host: hostname.to_string(),
                source: Box::new(e),
            })?;

        response
            .iter()
            .next()
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
