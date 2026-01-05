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
use std::time::{Duration, Instant};
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

    #[error("Session expired")]
    SessionExpired,
}

const KEEPALIVE_INTERVAL_SECS: u64 = 30;
const AGGRESSIVE_KEEPALIVE_SECS: u64 = 10;
const SESSION_LIFETIME_SECS: u64 = 16 * 60 * 60; // 16 hours
const SESSION_WARNING_SECS: u64 = 15 * 60 * 60;  // Warn at 15 hours

/// SSL tunnel connection to GlobalProtect gateway
pub struct SslTunnel {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    tun: TunDevice,
    keepalive_interval: Duration,
    session_start: Instant,
    last_warning_hour: u64,
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
        Self::connect_with_options(gateway, username, auth_cookie, config, false).await
    }

    /// Connect with configurable keepalive behavior
    ///
    /// # Arguments
    /// * `aggressive_keepalive` - Use shorter keepalive interval (10s vs 30s)
    pub async fn connect_with_options(
        gateway: &str,
        username: &str,
        auth_cookie: &str,
        config: &TunnelConfig,
        aggressive_keepalive: bool,
    ) -> Result<Self, TunnelError> {
        info!("Establishing SSL tunnel to {}", gateway);

        // 1. TCP connect to gateway:443 FIRST (before TUN to avoid routing conflicts)
        info!("TCP connecting to {}:443...", gateway);
        let tcp = TcpStream::connect((gateway, 443)).await?;
        tcp.set_nodelay(true)?;
        info!("TCP connected");

        // 2. TLS handshake
        info!("Starting TLS handshake...");
        let stream = tls_connect(gateway, tcp).await?;
        info!("TLS handshake completed");

        // 3. Create TUN device (after TCP/TLS is established)
        info!("Creating TUN device...");
        let tun = TunDevice::create(config).await?;
        info!("TUN device created: {}", tun.name());

        let keepalive_secs = if aggressive_keepalive {
            info!("Using aggressive keepalive ({}s)", AGGRESSIVE_KEEPALIVE_SECS);
            AGGRESSIVE_KEEPALIVE_SECS
        } else {
            KEEPALIVE_INTERVAL_SECS
        };

        let mut tunnel = Self {
            stream,
            tun,
            keepalive_interval: Duration::from_secs(keepalive_secs),
            session_start: Instant::now(),
            last_warning_hour: 0,
        };

        // 4. Send tunnel request
        tunnel.send_tunnel_request(gateway, username, auth_cookie).await?;

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
    async fn send_tunnel_request(
        &mut self,
        gateway: &str,
        username: &str,
        auth_cookie: &str,
    ) -> Result<(), TunnelError> {
        debug!("Sending tunnel request for user: {}", username);

        let request = format!(
            "GET /ssl-tunnel-connect.sslvpn?user={}&authcookie={} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: keep-alive\r\n\
             User-Agent: PAN GlobalProtect\r\n\
             \r\n",
            username, auth_cookie, gateway
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

    /// Check session lifetime and print warnings
    fn check_session_expiry(&mut self) -> Result<(), TunnelError> {
        let elapsed = self.session_start.elapsed().as_secs();

        // Check for session expiry (16 hours)
        if elapsed >= SESSION_LIFETIME_SECS {
            error!("Session lifetime exceeded (16 hours). Disconnecting.");
            return Err(TunnelError::SessionExpired);
        }

        // Warn at 15hr, 15hr30, 15hr45, 15hr55
        if elapsed >= SESSION_WARNING_SECS {
            let hours = elapsed / 3600;
            let mins = (elapsed % 3600) / 60;
            let remaining_mins = (SESSION_LIFETIME_SECS - elapsed) / 60;

            // Warn at specific intervals (don't spam)
            let warning_key = hours * 60 + mins / 15; // Warn every 15 mins after 15hr
            if warning_key > self.last_warning_hour {
                self.last_warning_hour = warning_key;
                warn!(
                    "Session expires in {} minutes (connected {}h{}m)",
                    remaining_mins, hours, mins % 60
                );
                eprintln!(
                    "\n*** WARNING: VPN session expires in {} minutes. Reconnect soon. ***\n",
                    remaining_mins
                );
            }
        }

        Ok(())
    }

    /// Run the tunnel event loop
    ///
    /// This function runs until the tunnel is disconnected or an error occurs.
    /// It handles three concurrent operations using tokio::select!:
    /// - Reading packets from TUN and sending to gateway (outbound)
    /// - Reading packets from gateway and writing to TUN (inbound)
    /// - Sending keepalive packets periodically
    ///
    /// The async TUN device ensures outbound packets are processed immediately
    /// rather than waiting for network events or keepalive ticks.
    pub async fn run(&mut self) -> Result<(), TunnelError> {
        info!("Starting tunnel event loop");

        let mtu = self.tun.mtu();
        let mut keepalive = interval(self.keepalive_interval);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Session check timer (every 5 minutes)
        let mut session_check = interval(Duration::from_secs(300));
        session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Pre-allocate buffers outside the loop to avoid repeated allocation
        let mut tun_buf = vec![0u8; mtu + 128];
        let mut net_header = [0u8; 16];

        loop {
            tokio::select! {
                // Priority 1: Outbound traffic (TUN → Gateway)
                // Packets from applications destined for VPN network
                result = self.tun.read(&mut tun_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            debug!("TUN read {} bytes (outbound)", n);
                            self.send_packet(&tun_buf[..n]).await?;
                        }
                        Ok(_) => {
                            // Empty read, continue
                        }
                        Err(e) => {
                            error!("TUN read error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // Priority 2: Inbound traffic (Gateway → TUN)
                // Packets from VPN network destined for local applications
                result = self.stream.read_exact(&mut net_header) => {
                    match result {
                        Ok(_) => {
                            // Parse length from header
                            let len = u16::from_be_bytes([net_header[6], net_header[7]]) as usize;

                            if len == 0 {
                                // Keepalive packet from gateway
                                debug!("Received keepalive from gateway");
                                continue;
                            }

                            // Read the payload
                            let mut payload = vec![0u8; len];
                            self.stream.read_exact(&mut payload).await?;

                            // Decode the full frame
                            let mut frame = Vec::with_capacity(16 + len);
                            frame.extend_from_slice(&net_header);
                            frame.extend_from_slice(&payload);

                            let packet = GpPacket::decode(&frame)?;

                            if packet.is_keepalive() {
                                debug!("Received keepalive (data packet)");
                                continue;
                            }

                            debug!("Gateway read {} bytes (inbound)", packet.payload.len());

                            // Write to TUN (deliver to local applications)
                            if !packet.payload.is_empty() {
                                self.tun.write(&packet.payload).await?;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            info!("Tunnel disconnected (EOF)");
                            return Err(TunnelError::Disconnected);
                        }
                        Err(e) => {
                            error!("Gateway read error: {}", e);
                            return Err(TunnelError::IoError(e));
                        }
                    }
                }

                // Priority 3: Keepalive timer
                _ = keepalive.tick() => {
                    debug!("Sending keepalive");
                    self.send_keepalive().await?;
                }

                // Priority 4: Session expiry check
                _ = session_check.tick() => {
                    self.check_session_expiry()?;
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
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

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
