//! GlobalProtect SSL tunnel implementation
//!
//! Establishes an SSL tunnel to the gateway and handles bidirectional packet I/O
//! between the TUN device and the gateway.

use crate::gp::auth::TunnelConfig;
use crate::gp::packet::GpPacket;
use crate::gp::tun::TunDevice;
use rustls::RootCertStore;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::interval;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

/// Tunnel errors
#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("TLS connection failed: {0}")]
    TlsError(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("TUN device error: {0}")]
    TunError(#[from] crate::gp::tun::TunError),

    #[error("Packet framing error: {0}")]
    FrameError(#[from] crate::gp::packet::FrameError),

    #[error("Tunnel setup failed: {0}")]
    SetupFailed(String),

    #[error("Tunnel disconnected")]
    Disconnected,
}

const KEEPALIVE_INTERVAL_SECS: u64 = 30;

/// SSL tunnel connection to GlobalProtect gateway
pub struct SslTunnel {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    tun: TunDevice,
    keepalive_interval: Duration,
}

impl SslTunnel {
    /// Connect to gateway and establish SSL tunnel
    ///
    /// # Arguments
    /// * `gateway` - Gateway hostname
    /// * `username` - Username from login
    /// * `auth_cookie` - Authentication cookie from login
    /// * `config` - Tunnel configuration from getconfig
    ///
    /// # Returns
    /// Established SSL tunnel ready for packet I/O
    pub async fn connect(
        gateway: &str,
        username: &str,
        auth_cookie: &str,
        config: &TunnelConfig,
    ) -> Result<Self, TunnelError> {
        info!("Establishing SSL tunnel to {}", gateway);

        // 1. Create TUN device first
        let tun = TunDevice::create(config).await?;
        info!("TUN device created: {}", tun.name());

        // 2. TCP connect to gateway:443
        debug!("Connecting to {}:443", gateway);
        let tcp = TcpStream::connect((gateway, 443)).await?;
        tcp.set_nodelay(true)?;

        // 3. TLS handshake
        let stream = tls_connect(gateway, tcp).await?;
        info!("TLS handshake completed");

        let mut tunnel = Self {
            stream,
            tun,
            keepalive_interval: Duration::from_secs(KEEPALIVE_INTERVAL_SECS),
        };

        // 4. Send tunnel request
        tunnel.send_tunnel_request(username, auth_cookie).await?;

        // 5. Wait for "START_TUNNEL" response
        tunnel.wait_for_start().await?;

        info!("SSL tunnel established");
        Ok(tunnel)
    }

    /// Get the TUN device name
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Send tunnel connection request
    async fn send_tunnel_request(&mut self, username: &str, auth_cookie: &str) -> Result<(), TunnelError> {
        debug!("Sending tunnel request for user: {}", username);

        let request = format!(
            "GET /ssl-tunnel-connect.sslvpn?user={}&authcookie={} HTTP/1.1\r\n\
             Host: gateway\r\n\
             Connection: keep-alive\r\n\
             User-Agent: PAN GlobalProtect\r\n\
             \r\n",
            username, auth_cookie
        );

        self.stream.write_all(request.as_bytes()).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Wait for "START_TUNNEL" response from gateway
    async fn wait_for_start(&mut self) -> Result<(), TunnelError> {
        debug!("Waiting for START_TUNNEL response");

        let mut buf = vec![0u8; 4096];
        let n = self.stream.read(&mut buf).await?;

        if n == 0 {
            return Err(TunnelError::SetupFailed(
                "Connection closed before START_TUNNEL".to_string(),
            ));
        }

        let response = String::from_utf8_lossy(&buf[..n]);
        debug!("Tunnel response: {}", response);

        if !response.contains("START_TUNNEL") {
            return Err(TunnelError::SetupFailed(format!(
                "Expected START_TUNNEL, got: {}",
                response
            )));
        }

        Ok(())
    }

    /// Run the tunnel event loop
    ///
    /// This function runs until the tunnel is disconnected or an error occurs.
    /// It handles:
    /// - Reading packets from TUN and sending to gateway
    /// - Reading packets from gateway and writing to TUN
    /// - Sending keepalive packets periodically
    pub async fn run(&mut self) -> Result<(), TunnelError> {
        info!("Starting tunnel event loop");

        let mtu = self.tun.mtu();
        let mut keepalive = interval(self.keepalive_interval);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let mut tun_buf = vec![0u8; mtu + 128];
            let mut net_buf = vec![0u8; mtu + 128];

            tokio::select! {
                // Packet from gateway → decrypt and write to TUN
                result = self.recv_packet(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            debug!("Gateway read {} bytes", n);
                            self.tun.write(&net_buf[..n])?;
                        }
                        Ok(_) => {
                            // Keepalive or empty packet
                            debug!("Received keepalive");
                        }
                        Err(TunnelError::Disconnected) => {
                            info!("Tunnel disconnected");
                            return Err(TunnelError::Disconnected);
                        }
                        Err(e) => {
                            error!("Gateway read error: {}", e);
                            return Err(e);
                        }
                    }

                    // Try to read from TUN (best effort, ignore errors)
                    if let Ok(n) = self.tun.read(&mut tun_buf) {
                        if n > 0 {
                            debug!("TUN read {} bytes", n);
                            self.send_packet(&tun_buf[..n]).await?;
                        }
                    }
                }

                // Send keepalive periodically
                _ = keepalive.tick() => {
                    debug!("Sending keepalive");
                    self.send_keepalive().await?;

                    // Try to read from TUN while we're here (best effort)
                    if let Ok(n) = self.tun.read(&mut tun_buf) {
                        if n > 0 {
                            debug!("TUN read {} bytes", n);
                            self.send_packet(&tun_buf[..n]).await?;
                        }
                    }
                }
            }
        }
    }

    /// Send a packet to the gateway
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), TunnelError> {
        let gp_packet = GpPacket::from_ip_packet(packet.to_vec())
            .ok_or_else(|| TunnelError::SetupFailed("Invalid IP packet".to_string()))?;

        let frame = gp_packet.encode();
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Receive a packet from the gateway
    ///
    /// Returns the number of bytes in the payload (0 for keepalives)
    async fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunnelError> {
        // Read the 16-byte header first
        let mut header = [0u8; 16];
        self.stream.read_exact(&mut header).await.map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                TunnelError::Disconnected
            } else {
                TunnelError::IoError(e)
            }
        })?;

        // Parse length from header
        let len = u16::from_be_bytes([header[6], header[7]]) as usize;

        if len == 0 {
            // Keepalive packet
            return Ok(0);
        }

        // Read the payload
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;

        // Decode the full frame
        let mut frame = Vec::with_capacity(16 + len);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload);

        let packet = GpPacket::decode(&frame)?;

        if packet.is_keepalive() {
            return Ok(0);
        }

        if packet.payload.len() > buf.len() {
            warn!(
                "Received packet larger than buffer: {} > {}",
                packet.payload.len(),
                buf.len()
            );
            return Ok(0);
        }

        buf[..packet.payload.len()].copy_from_slice(&packet.payload);
        Ok(packet.payload.len())
    }

    /// Send a keepalive packet
    async fn send_keepalive(&mut self) -> Result<(), TunnelError> {
        let keepalive = GpPacket::keepalive();
        let frame = keepalive.encode();
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// Establish TLS connection to gateway
async fn tls_connect(
    gateway: &str,
    tcp: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TunnelError> {
    // Load webpki root certificates
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
    );

    // Create TLS config
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // Perform TLS handshake
    let domain = rustls::pki_types::ServerName::try_from(gateway.to_string())
        .map_err(|e| TunnelError::TlsError(format!("Invalid domain: {}", e)))?;

    let stream = connector
        .connect(domain, tcp)
        .await
        .map_err(|e| TunnelError::TlsError(e.to_string()))?;

    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_interval() {
        let interval = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
        assert!(interval.as_secs() > 0);
        assert!(interval.as_secs() < 60); // Reasonable keepalive
    }

    // Note: Full tunnel tests require real VPN credentials and are tested manually
}
