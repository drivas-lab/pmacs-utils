//! Route table manipulation for split-tunnel VPN
//!
//! Provides DNS resolution (system or VPN-specific) and route management.

use crate::platform::{get_routing_manager, get_routing_manager_for_interface, PlatformError};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

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
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    #[error("DNS query failed: {0}")]
    DnsQueryFailed(String),
}

pub struct VpnRouter {
    gateway: String,
    interface_name: Option<String>,
}

impl VpnRouter {
    pub fn new(gateway: String) -> Result<Self, RoutingError> {
        info!("Creating VpnRouter with gateway: {}", gateway);
        Ok(Self {
            gateway,
            interface_name: None,
        })
    }

    /// Create a router bound to a specific interface (recommended for TUN devices)
    pub fn with_interface(gateway: String, interface_name: String) -> Result<Self, RoutingError> {
        info!(
            "Creating VpnRouter with gateway: {} interface: {}",
            gateway, interface_name
        );
        Ok(Self {
            gateway,
            interface_name: Some(interface_name),
        })
    }

    /// Get the gateway IP
    pub fn gateway(&self) -> &str {
        &self.gateway
    }

    /// Get the routing manager (interface-aware if configured)
    fn get_manager(&self) -> Result<Box<dyn crate::platform::RoutingManager>, RoutingError> {
        if let Some(ref iface) = self.interface_name {
            Ok(get_routing_manager_for_interface(iface)?)
        } else {
            Ok(get_routing_manager()?)
        }
    }

    /// Resolve hostname using system DNS (std::net)
    pub fn resolve_host(&self, hostname: &str) -> Result<IpAddr, RoutingError> {
        debug!("Resolving {} via system DNS", hostname);
        let addr_str = format!("{}:0", hostname);
        let addrs = addr_str
            .to_socket_addrs()
            .map_err(|e| RoutingError::DnsError {
                host: hostname.to_string(),
                source: Box::new(e),
            })?;

        let ip = addrs
            .into_iter()
            .next()
            .map(|a| a.ip())
            .ok_or_else(|| RoutingError::NoAddressFound(hostname.to_string()))?;

        info!("System DNS resolved {} -> {}", hostname, ip);
        Ok(ip)
    }

    /// Resolve hostname using specific DNS servers (e.g., VPN DNS)
    ///
    /// Sends a UDP DNS query directly to the specified DNS servers.
    /// This bypasses system DNS configuration.
    pub fn resolve_with_dns(
        &self,
        hostname: &str,
        dns_servers: &[IpAddr],
    ) -> Result<IpAddr, RoutingError> {
        if dns_servers.is_empty() {
            warn!("No DNS servers provided, falling back to system DNS");
            return self.resolve_host(hostname);
        }

        debug!(
            "Resolving {} via VPN DNS servers: {:?}",
            hostname, dns_servers
        );

        // Build DNS query packet
        let query = build_dns_query(hostname);

        for dns_server in dns_servers {
            debug!("Trying DNS server: {}", dns_server);

            let server_addr = SocketAddr::new(*dns_server, 53);

            match query_dns_server(&query, server_addr) {
                Ok(ip) => {
                    info!("VPN DNS resolved {} -> {} (via {})", hostname, ip, dns_server);
                    return Ok(IpAddr::V4(ip));
                }
                Err(e) => {
                    warn!("DNS query to {} failed: {}", dns_server, e);
                    continue;
                }
            }
        }

        Err(RoutingError::DnsQueryFailed(format!(
            "All DNS servers failed for {}",
            hostname
        )))
    }

    /// Add a route for a hostname (resolves via system DNS)
    pub fn add_host_route(&self, hostname: &str) -> Result<IpAddr, RoutingError> {
        let ip = self.resolve_host(hostname)?;
        self.add_ip_route_internal(&ip)?;
        Ok(ip)
    }

    /// Add a route for a hostname using VPN DNS servers
    pub fn add_host_route_with_dns(
        &self,
        hostname: &str,
        dns_servers: &[IpAddr],
    ) -> Result<IpAddr, RoutingError> {
        let ip = self.resolve_with_dns(hostname, dns_servers)?;
        self.add_ip_route_internal(&ip)?;
        Ok(ip)
    }

    /// Add a route by IP address directly (bypasses DNS)
    ///
    /// Use this for testing or when you already know the IP.
    pub fn add_ip_route(&self, ip_str: &str) -> Result<IpAddr, RoutingError> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| RoutingError::InvalidIpAddress(ip_str.to_string()))?;
        self.add_ip_route_internal(&ip)?;
        Ok(ip)
    }

    /// Internal route addition
    fn add_ip_route_internal(&self, ip: &IpAddr) -> Result<(), RoutingError> {
        info!("Adding route: {} via gateway {}", ip, self.gateway);
        let manager = self.get_manager()?;
        manager.add_route(&ip.to_string(), &self.gateway)?;
        info!("Route added successfully: {} -> {}", ip, self.gateway);
        Ok(())
    }

    /// Remove a route for a hostname
    pub fn remove_host_route(&self, hostname: &str) -> Result<(), RoutingError> {
        let ip = self.resolve_host(hostname)?;
        self.remove_ip_route(&ip.to_string())
    }

    /// Remove a route by IP address
    pub fn remove_ip_route(&self, ip_str: &str) -> Result<(), RoutingError> {
        info!("Removing route: {}", ip_str);
        let manager = self.get_manager()?;
        manager.delete_route(ip_str)?;
        info!("Route removed: {}", ip_str);
        Ok(())
    }
}

/// Build a minimal DNS A record query packet
fn build_dns_query(hostname: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Header (12 bytes)
    // Transaction ID (random-ish)
    let id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0xFFFF) as u16;
    packet.extend_from_slice(&id.to_be_bytes());

    // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x01, 0x00]);

    // QDCOUNT = 1 (one question)
    packet.extend_from_slice(&[0x00, 0x01]);

    // ANCOUNT, NSCOUNT, ARCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Question section
    // Encode hostname as DNS labels
    for label in hostname.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // End of name

    // QTYPE = A (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    // QCLASS = IN (0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Send DNS query to server and parse response
fn query_dns_server(query: &[u8], server: SocketAddr) -> Result<Ipv4Addr, String> {
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind failed: {}", e))?;

    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set timeout failed: {}", e))?;

    // Send query
    socket
        .send_to(query, server)
        .map_err(|e| format!("send failed: {}", e))?;

    // Receive response
    let mut response = [0u8; 512];
    let (len, _) = socket
        .recv_from(&mut response)
        .map_err(|e| format!("recv failed: {}", e))?;

    if len < 12 {
        return Err("response too short".to_string());
    }

    // Check response code (RCODE in lower 4 bits of byte 3)
    let rcode = response[3] & 0x0F;
    if rcode != 0 {
        return Err(format!("DNS error code: {}", rcode));
    }

    // Check answer count
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    if ancount == 0 {
        return Err("no answers in response".to_string());
    }

    // Skip question section to find answer
    // Header is 12 bytes, then question section
    let mut pos = 12;

    // Skip question name (look for 0x00 terminator or pointer)
    while pos < len && response[pos] != 0 {
        if response[pos] & 0xC0 == 0xC0 {
            // Pointer, skip 2 bytes
            pos += 2;
            break;
        }
        pos += 1 + response[pos] as usize;
    }
    if response[pos] == 0 {
        pos += 1; // Skip null terminator
    }
    pos += 4; // Skip QTYPE and QCLASS

    // Parse first answer
    // Skip answer name (might be pointer)
    while pos < len {
        if response[pos] & 0xC0 == 0xC0 {
            pos += 2;
            break;
        } else if response[pos] == 0 {
            pos += 1;
            break;
        }
        pos += 1 + response[pos] as usize;
    }

    if pos + 10 > len {
        return Err("answer section truncated".to_string());
    }

    // Read TYPE (2 bytes)
    let atype = u16::from_be_bytes([response[pos], response[pos + 1]]);
    pos += 2;

    // Skip CLASS (2 bytes) and TTL (4 bytes)
    pos += 6;

    // Read RDLENGTH
    let rdlength = u16::from_be_bytes([response[pos], response[pos + 1]]) as usize;
    pos += 2;

    // If TYPE is A (1) and RDLENGTH is 4, parse IPv4 address
    if atype == 1 && rdlength == 4 && pos + 4 <= len {
        let ip = Ipv4Addr::new(
            response[pos],
            response[pos + 1],
            response[pos + 2],
            response[pos + 3],
        );
        return Ok(ip);
    }

    Err(format!("unexpected answer type: {} length: {}", atype, rdlength))
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

        let err = RoutingError::InvalidIpAddress("not-an-ip".to_string());
        assert!(err.to_string().contains("Invalid IP address"));

        let err = RoutingError::DnsQueryFailed("timeout".to_string());
        assert!(err.to_string().contains("DNS query failed"));
    }

    #[test]
    fn test_vpn_router_creation() {
        let router = VpnRouter::new("10.0.0.1".to_string());
        assert!(router.is_ok());

        let router = router.unwrap();
        assert_eq!(router.gateway(), "10.0.0.1");
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
        assert_eq!(router.gateway(), gateway);
    }

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("example.com");

        // Verify header structure
        assert!(query.len() >= 12, "Query should have at least 12 byte header");

        // Flags at bytes 2-3 should be 0x01 0x00 (standard query, RD=1)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);

        // QDCOUNT should be 1
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);

        // Question should contain "example" and "com" labels
        // After 12-byte header: 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0
        assert_eq!(query[12], 7); // length of "example"
        assert_eq!(query[20], 3); // length of "com"
    }

    #[test]
    fn test_resolve_with_dns_empty_servers_fallback() {
        let router = VpnRouter::new("10.0.0.1".to_string()).unwrap();

        // With empty DNS servers, should fall back to system DNS
        let result = router.resolve_with_dns("localhost", &[]);
        // May or may not resolve depending on system, but shouldn't panic
        if let Ok(ip) = result {
            let ip_str = ip.to_string();
            assert!(ip_str == "127.0.0.1" || ip_str == "::1");
        }
    }

    #[test]
    fn test_resolve_with_public_dns() {
        // Test with Google's public DNS (8.8.8.8) for a well-known domain
        // This test requires network access
        let router = VpnRouter::new("10.0.0.1".to_string()).unwrap();
        let dns_servers = vec!["8.8.8.8".parse().unwrap()];

        let result = router.resolve_with_dns("google.com", &dns_servers);

        // Should successfully resolve (network permitting)
        if let Ok(ip) = result {
            // Google.com should resolve to some IP
            assert!(!ip.is_loopback());
        }
        // If it fails, that's OK - network might not be available
    }

    #[test]
    fn test_add_ip_route_validation() {
        let router = VpnRouter::new("10.0.0.1".to_string()).unwrap();

        // Invalid IP should fail
        let result = router.add_ip_route("not-an-ip");
        assert!(matches!(result, Err(RoutingError::InvalidIpAddress(_))));

        // Valid IP format (won't actually add route without admin, but validates parsing)
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(ip.is_ipv4());
    }
}
