//! TUN device wrapper for cross-platform tunnel operations
//!
//! Provides a simplified async interface to TUN devices on Mac, Linux, and Windows.

use crate::gp::auth::TunnelConfig;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};
use tun::AbstractDevice;

/// TUN device errors
#[derive(Error, Debug)]
pub enum TunError {
    #[error("TUN device creation failed: {0}")]
    CreationFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("TUN device not configured")]
    NotConfigured,

    #[error("Invalid packet size: {0}")]
    InvalidPacketSize(usize),
}

/// Cross-platform async TUN device wrapper
pub struct TunDevice {
    device: tun::AsyncDevice,
    name: String,
    mtu: usize,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration
    ///
    /// # Arguments
    /// * `config` - Tunnel configuration from getconfig
    ///
    /// # Returns
    /// A configured TUN device ready for async packet I/O
    ///
    /// # Platform Notes
    /// - macOS: Creates utunN device
    /// - Linux: Creates tun0/tun1/etc.
    /// - Windows: Extracts embedded wintun.dll automatically
    pub async fn create(config: &TunnelConfig) -> Result<Self, TunError> {
        info!(
            "Creating TUN device with IP {} MTU {}",
            config.internal_ip, config.mtu
        );

        #[cfg(windows)]
        ensure_wintun_dll()?;

        let mut tun_config = tun::Configuration::default();

        // Set IP address
        tun_config
            .address(config.internal_ip)
            .netmask(
                // Use /32 for point-to-point
                match config.internal_ip {
                    std::net::IpAddr::V4(_) => {
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255))
                    }
                    std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                    )),
                },
            )
            .mtu(config.mtu)
            .up();

        // Create async device directly (tun 0.8 API)
        let device = tun::create_as_async(&tun_config)
            .map_err(|e| TunError::CreationFailed(e.to_string()))?;

        let name = device
            .tun_name()
            .map_err(|e| TunError::CreationFailed(e.to_string()))?;

        info!("TUN device created: {}", name);

        Ok(Self {
            device,
            name,
            mtu: config.mtu as usize,
        })
    }

    /// Read a packet from the TUN device (outbound traffic from host)
    ///
    /// This is async and non-blocking - suitable for use in tokio::select!
    /// Returns the number of bytes read. The buffer should be at least MTU size.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        if buf.len() < self.mtu {
            debug!("Warning: read buffer smaller than MTU");
        }

        let n = self.device.read(buf).await?;
        debug!("Read {} bytes from TUN", n);

        if n > self.mtu {
            return Err(TunError::InvalidPacketSize(n));
        }

        Ok(n)
    }

    /// Write a packet to the TUN device (inbound traffic to host)
    ///
    /// This is async and non-blocking.
    /// Returns the number of bytes written.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        if buf.is_empty() {
            return Ok(0);
        }

        if buf.len() > self.mtu {
            return Err(TunError::InvalidPacketSize(buf.len()));
        }

        let n = self.device.write(buf).await?;
        debug!("Wrote {} bytes to TUN", n);

        Ok(n)
    }

    /// Get the device name (e.g., "utun9" on Mac, "tun0" on Linux)
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured MTU
    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

/// Embedded wintun.dll for Windows (from wintun.net, see assets/wintun-LICENSE.txt)
#[cfg(windows)]
static WINTUN_DLL: &[u8] = include_bytes!("../../assets/wintun.dll");

/// Ensure wintun.dll is available on Windows
///
/// Extracts the embedded wintun.dll to the executable's directory if not present.
/// The DLL is signed by WireGuard LLC and distributed under their prebuilt binaries license.
#[cfg(windows)]
fn ensure_wintun_dll() -> Result<(), TunError> {
    let exe_dir = std::env::current_exe()
        .map_err(|e| TunError::CreationFailed(format!("Cannot find executable path: {}", e)))?
        .parent()
        .ok_or_else(|| TunError::CreationFailed("Cannot find executable directory".to_string()))?
        .to_path_buf();

    let dll_path = exe_dir.join("wintun.dll");

    if !dll_path.exists() {
        info!("Extracting embedded wintun.dll to {}", dll_path.display());
        std::fs::write(&dll_path, WINTUN_DLL)
            .map_err(|e| TunError::CreationFailed(format!("Failed to write wintun.dll: {}", e)))?;
    } else {
        debug!("Found existing wintun.dll at {}", dll_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtu_validation() {
        // This test doesn't require root/admin privileges

        let err = TunError::InvalidPacketSize(2000);
        assert!(err.to_string().contains("2000"));
    }

    // Note: Actual TUN device creation tests require root/admin privileges
    // and are skipped in CI. Manual testing required.

    #[tokio::test]
    #[ignore] // Requires root/admin
    async fn test_tun_device_creation() {
        use std::net::IpAddr;

        let config = TunnelConfig {
            mtu: 1400,
            internal_ip: "10.0.1.100".parse::<IpAddr>().unwrap(),
            internal_ip6: None,
            dns_servers: vec![],
            timeout_seconds: 3600,
        };

        let result = TunDevice::create(&config).await;

        // This will fail without root but we can check the error message
        if let Err(e) = result {
            println!("TUN creation failed (expected without root): {}", e);
        }
    }
}
