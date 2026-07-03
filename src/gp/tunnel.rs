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

    #[error("Connection timeout (no data received)")]
    Timeout,

    #[error("Session expired")]
    SessionExpired,
}

const KEEPALIVE_INTERVAL_SECS: u64 = 30;
const AGGRESSIVE_KEEPALIVE_SECS: u64 = 10;
const DEFAULT_INBOUND_TIMEOUT_SECS: u64 = 45; // Faster dead tunnel detection (was 90s)
const SESSION_LIFETIME_SECS: u64 = 16 * 60 * 60; // 16 hours
const SESSION_WARNING_SECS: u64 = 15 * 60 * 60; // Warn at 15 hours

/// Requested send/recv buffer size for the gateway TCP socket.
/// Throughput of a single TCP stream tops out near buffer/RTT, so the OS
/// defaults (a few hundred KB) cap a 200ms-RTT tunnel near 1 MB/s.
const SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Maximum outbound TUN packets coalesced into a single TLS write.
const MAX_BATCH_PACKETS: usize = 64;

/// Smoothed-RTT level (ms) treated as a degradation strike.
const WEDGE_RTT_THRESHOLD_MS: u32 = 2000;

/// Consecutive strikes (sampled every 10s) before the stream is rebuilt.
const WEDGE_STRIKES: u32 = 3;

/// Minimum spacing between in-place stream rebuilds.
const REBUILD_COOLDOWN_SECS: u64 = 60;

/// Detects a wedged-but-alive tunnel session from kernel RTT samples.
///
/// A meltdown session keeps trickling keepalives (so the inbound timeout
/// never fires) while the TCP smoothed RTT sits at multiple seconds. The
/// detector trips after `strikes_needed` consecutive samples at or above
/// `threshold_ms`; a healthy sample resets it, a missing sample (platform
/// without kernel RTT, or getsockopt failure) leaves it unchanged.
struct WedgeDetector {
    threshold_ms: u32,
    strikes_needed: u32,
    strikes: u32,
}

impl WedgeDetector {
    fn new(threshold_ms: u32, strikes_needed: u32) -> Self {
        Self {
            threshold_ms,
            strikes_needed,
            strikes: 0,
        }
    }

    /// Record an RTT sample; returns true while the detector is tripped.
    fn record(&mut self, srtt_ms: Option<u32>) -> bool {
        match srtt_ms {
            Some(ms) if ms >= self.threshold_ms => self.strikes += 1,
            Some(_) => self.strikes = 0,
            None => {}
        }
        self.strikes >= self.strikes_needed
    }

    fn reset(&mut self) {
        self.strikes = 0;
    }
}

/// Enlarge the gateway socket's send/recv buffers, returning the sizes the
/// kernel actually granted. Failure to enlarge is logged, never fatal.
fn tune_socket_buffers(tcp: &TcpStream) -> (usize, usize) {
    let sock = socket2::SockRef::from(tcp);
    if let Err(e) = sock.set_send_buffer_size(SOCKET_BUFFER_BYTES) {
        warn!("Could not enlarge send buffer: {}", e);
    }
    if let Err(e) = sock.set_recv_buffer_size(SOCKET_BUFFER_BYTES) {
        warn!("Could not enlarge recv buffer: {}", e);
    }
    let snd = sock.send_buffer_size().unwrap_or(0);
    let rcv = sock.recv_buffer_size().unwrap_or(0);
    info!(
        "Gateway socket buffers: send {} KiB, recv {} KiB",
        snd / 1024,
        rcv / 1024
    );
    (snd, rcv)
}

/// Kernel-reported smoothed RTT of the gateway TCP connection, in ms.
/// Returns None where the platform exposes no per-connection RTT.
#[cfg(target_os = "macos")]
fn tcp_srtt_ms(stream: &TcpStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut info: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    // tcpi_srtt is already in milliseconds on macOS.
    (rc == 0).then_some(info.tcpi_srtt)
}

/// Kernel-reported smoothed RTT of the gateway TCP connection, in ms.
/// Returns None where the platform exposes no per-connection RTT.
#[cfg(target_os = "linux")]
fn tcp_srtt_ms(stream: &TcpStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    // tcpi_rtt is in microseconds on Linux.
    (rc == 0).then_some(info.tcpi_rtt / 1000)
}

/// Kernel-reported smoothed RTT of the gateway TCP connection, in ms.
/// Returns None where the platform exposes no per-connection RTT.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn tcp_srtt_ms(_stream: &TcpStream) -> Option<u32> {
    None
}

/// SSL tunnel connection to GlobalProtect gateway
pub struct SslTunnel {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    tun: TunDevice,
    keepalive_interval: Duration,
    inbound_timeout: Duration,
    session_start: Instant,
    last_inbound: Instant,
    last_warning_hour: u64,
    // Retained so a wedged stream can be re-established in place with the
    // same session (TUN device, internal IP, and routes all stay up).
    gateway: String,
    username: String,
    auth_cookie: String,
    wedge: WedgeDetector,
    last_rebuild: Option<Instant>,
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
        Self::connect_with_options(gateway, username, auth_cookie, config, false, None).await
    }

    /// Connect with configurable keepalive and timeout behavior
    ///
    /// # Arguments
    /// * `aggressive_keepalive` - Use shorter keepalive interval (10s vs 30s)
    /// * `inbound_timeout_secs` - Override inbound timeout (None uses default 45s)
    pub async fn connect_with_options(
        gateway: &str,
        username: &str,
        auth_cookie: &str,
        config: &TunnelConfig,
        aggressive_keepalive: bool,
        inbound_timeout_secs: Option<u64>,
    ) -> Result<Self, TunnelError> {
        info!("Establishing SSL tunnel to {}", gateway);

        // 1. TCP + TLS + tunnel request, through START_TUNNEL
        // (before TUN creation, so a refused session never creates a device)
        let stream = establish_stream(gateway, username, auth_cookie).await?;

        // 2. Create TUN device
        info!("Creating TUN device...");
        let tun = TunDevice::create(config).await?;
        info!("TUN device created: {}", tun.name());

        let keepalive_secs = if aggressive_keepalive {
            info!(
                "Using aggressive keepalive ({}s)",
                AGGRESSIVE_KEEPALIVE_SECS
            );
            AGGRESSIVE_KEEPALIVE_SECS
        } else {
            KEEPALIVE_INTERVAL_SECS
        };

        let timeout_secs = inbound_timeout_secs.unwrap_or(DEFAULT_INBOUND_TIMEOUT_SECS);
        info!("Inbound timeout: {}s", timeout_secs);

        let now = Instant::now();
        let tunnel = Self {
            stream,
            tun,
            keepalive_interval: Duration::from_secs(keepalive_secs),
            inbound_timeout: Duration::from_secs(timeout_secs),
            session_start: now,
            last_inbound: now,
            last_warning_hour: 0,
            gateway: gateway.to_string(),
            username: username.to_string(),
            auth_cookie: auth_cookie.to_string(),
            wedge: WedgeDetector::new(WEDGE_RTT_THRESHOLD_MS, WEDGE_STRIKES),
            last_rebuild: None,
        };

        info!("SSL tunnel established");
        Ok(tunnel)
    }

    /// Get the TUN device name
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Re-establish the gateway TCP/TLS stream in place, reusing the live
    /// session's auth cookie. The TUN device, internal IP, and routes are
    /// untouched, so applications see a brief stall instead of a teardown.
    async fn rebuild_stream(&mut self) -> Result<(), TunnelError> {
        info!("Rebuilding gateway stream in place (TUN and routes preserved)");
        let stream = tokio::time::timeout(
            Duration::from_secs(30),
            establish_stream(&self.gateway, &self.username, &self.auth_cookie),
        )
        .await
        .map_err(|_| TunnelError::Timeout)??;
        self.stream = stream;
        self.last_inbound = Instant::now();
        self.wedge.reset();
        info!("Gateway stream rebuilt");
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
                    remaining_mins,
                    hours,
                    mins % 60
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

        // Inbound timeout check (every 10 seconds)
        let mut timeout_check = interval(Duration::from_secs(10));
        timeout_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Pre-allocate buffers outside the loop to avoid repeated allocation
        let mut tun_buf = vec![0u8; mtu + 128];
        let mut out_buf: Vec<u8> = Vec::with_capacity((mtu + 144) * MAX_BATCH_PACKETS);

        // Persistent header buffer for cancel-safe reads
        // (read_exact in select! is not cancel-safe - partial reads would be lost)
        let mut header_buf = [0u8; 16];
        let mut header_pos = 0usize;

        loop {
            tokio::select! {
                // Priority 1: Outbound traffic (TUN → Gateway)
                // Packets from applications destined for VPN network.
                // Already-queued packets are drained into the same buffer so a
                // burst costs one TLS write instead of one record per packet.
                result = self.tun.read(&mut tun_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            debug!("TUN read {} bytes (outbound)", n);
                            out_buf.clear();
                            encode_ip_packet(&tun_buf[..n], &mut out_buf)?;
                            let mut batched = 1usize;
                            while batched < MAX_BATCH_PACKETS {
                                match poll_immediate(self.tun.read(&mut tun_buf)) {
                                    Some(Ok(n)) if n > 0 => {
                                        encode_ip_packet(&tun_buf[..n], &mut out_buf)?;
                                        batched += 1;
                                    }
                                    Some(Ok(_)) => break,
                                    Some(Err(e)) => {
                                        error!("TUN read error: {}", e);
                                        return Err(e.into());
                                    }
                                    None => break,
                                }
                            }
                            if batched > 1 {
                                debug!("Coalesced {} outbound packets into one write ({} bytes)", batched, out_buf.len());
                            }
                            self.stream.write_all(&out_buf).await?;
                            self.stream.flush().await?;
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
                // Uses cancel-safe incremental read (not read_exact) to avoid losing
                // partial data if another select! branch wins mid-read
                result = self.stream.read(&mut header_buf[header_pos..]) => {
                    match result {
                        Ok(0) => {
                            info!("Tunnel disconnected (EOF)");
                            return Err(TunnelError::Disconnected);
                        }
                        Ok(n) => {
                            // Any data from gateway = connection is alive
                            self.last_inbound = Instant::now();
                            header_pos += n;

                            // Wait until we have the full 16-byte header
                            if header_pos < 16 {
                                continue;
                            }

                            // Full header received, reset for next packet
                            header_pos = 0;

                            // Parse length from header
                            let len = u16::from_be_bytes([header_buf[6], header_buf[7]]) as usize;

                            if len == 0 {
                                // Keepalive packet from gateway
                                debug!("Received keepalive from gateway");
                                continue;
                            }

                            // Read the payload (committed read - not in select!).
                            // Bounded: a stream dying mid-frame would otherwise
                            // block here forever, out of reach of every timer.
                            let mut payload = vec![0u8; len];
                            tokio::time::timeout(
                                self.inbound_timeout,
                                self.stream.read_exact(&mut payload),
                            )
                            .await
                            .map_err(|_| TunnelError::Timeout)??;

                            // Decode the full frame
                            let mut frame = Vec::with_capacity(16 + len);
                            frame.extend_from_slice(&header_buf);
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

                // Priority 5: Inbound timeout and wedge check
                _ = timeout_check.tick() => {
                    let elapsed = self.last_inbound.elapsed();
                    if elapsed >= self.inbound_timeout {
                        error!(
                            "No data from gateway in {}s (timeout: {}s)",
                            elapsed.as_secs(), self.inbound_timeout.as_secs()
                        );
                        return Err(TunnelError::Timeout);
                    }

                    // A wedged-but-alive session trickles keepalives (so the
                    // timeout above never fires) while TCP RTT sits at multiple
                    // seconds. Rebuild just the stream; TUN and routes stay up.
                    let srtt = tcp_srtt_ms(self.stream.get_ref().0);
                    if self.wedge.record(srtt) && self.rebuild_allowed() {
                        warn!(
                            "Tunnel wedged: smoothed RTT {}ms over {} consecutive checks; rebuilding stream",
                            srtt.unwrap_or(0), WEDGE_STRIKES
                        );
                        self.last_rebuild = Some(Instant::now());
                        if let Err(e) = self.rebuild_stream().await {
                            error!("Stream rebuild failed: {}", e);
                            return Err(e);
                        }
                        // Drop any half-read frame from the dead stream.
                        header_pos = 0;
                    }
                }
            }
        }
    }

    /// Whether enough time has passed since the last in-place rebuild.
    fn rebuild_allowed(&self) -> bool {
        self.last_rebuild
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(REBUILD_COOLDOWN_SECS))
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

/// Frame one IP packet from the TUN device onto the outbound buffer.
fn encode_ip_packet(packet: &[u8], out: &mut Vec<u8>) -> Result<(), TunnelError> {
    let gp_packet = GpPacket::from_ip_packet(packet.to_vec())
        .ok_or_else(|| TunnelError::SetupFailed("Invalid IP packet".to_string()))?;
    gp_packet.encode_into(out);
    Ok(())
}

/// Poll a future exactly once; Some(output) if it is already ready.
///
/// Used to opportunistically drain TUN packets that are queued right now.
/// A Pending result registers only a no-op waker, which is safe here: the
/// select! loop re-polls the TUN read with its real waker on the very next
/// iteration, and readiness is not lost in between.
fn poll_immediate<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

/// Establish the gateway data stream: TCP connect, buffer tuning, TLS
/// handshake, tunnel request, and the START_TUNNEL acknowledgement.
async fn establish_stream(
    gateway: &str,
    username: &str,
    auth_cookie: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TunnelError> {
    info!("TCP connecting to {}:443...", gateway);
    let tcp = TcpStream::connect((gateway, 443)).await?;
    tcp.set_nodelay(true)?;
    tune_socket_buffers(&tcp);
    info!("TCP connected");

    info!("Starting TLS handshake...");
    let mut stream = tls_connect(gateway, tcp).await?;
    info!("TLS handshake completed");

    send_tunnel_request(&mut stream, gateway, username, auth_cookie).await?;
    wait_for_start(&mut stream).await?;

    Ok(stream)
}

/// Send tunnel connection request
async fn send_tunnel_request(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
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

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

/// Wait for "START_TUNNEL" response from gateway
async fn wait_for_start(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<(), TunnelError> {
    debug!("Waiting for START_TUNNEL response");

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;

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

    #[test]
    fn wedge_detector_trips_only_after_consecutive_high_rtt() {
        let mut d = WedgeDetector::new(2000, 3);
        assert!(!d.record(Some(50)));
        assert!(!d.record(Some(2500)));
        assert!(!d.record(Some(3000)));
        assert!(d.record(Some(4000)));
    }

    #[test]
    fn wedge_detector_healthy_sample_resets_strikes() {
        let mut d = WedgeDetector::new(2000, 3);
        assert!(!d.record(Some(9000)));
        assert!(!d.record(Some(9000)));
        assert!(!d.record(Some(100)));
        assert!(!d.record(Some(9000)));
        assert!(!d.record(Some(9000)));
        assert!(d.record(Some(9000)));
    }

    #[test]
    fn wedge_detector_missing_sample_neither_strikes_nor_resets() {
        let mut d = WedgeDetector::new(2000, 3);
        assert!(!d.record(Some(9000)));
        assert!(!d.record(Some(9000)));
        assert!(!d.record(None));
        assert!(d.record(Some(9000)));
    }

    #[test]
    fn wedge_detector_reset_clears_tripped_state() {
        let mut d = WedgeDetector::new(2000, 3);
        for _ in 0..2 {
            d.record(Some(9000));
        }
        assert!(d.record(Some(9000)));
        d.reset();
        assert!(!d.record(Some(9000)));
    }

    #[tokio::test]
    async fn tune_socket_buffers_reports_enlarged_buffers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.unwrap();
        let _server = server.unwrap();

        let (snd, rcv) = tune_socket_buffers(&client);
        assert!(snd >= 512 * 1024, "send buffer too small: {}", snd);
        assert!(rcv >= 512 * 1024, "recv buffer too small: {}", rcv);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn tcp_srtt_readable_on_established_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut client = client.unwrap();
        let (mut server, _) = server.unwrap();

        // One round trip so the kernel has an RTT estimate.
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        server.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();

        assert!(
            tcp_srtt_ms(&client).is_some(),
            "kernel RTT should be readable on {}",
            std::env::consts::OS
        );
    }

    // Note: Full tunnel tests require real VPN credentials and are tested manually
}
