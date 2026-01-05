/// GlobalProtect protocol implementation
///
/// This module provides native GlobalProtect VPN client functionality,
/// eliminating the need for OpenConnect as a dependency.
pub mod auth;
pub mod packet;
pub mod tun;
pub mod tunnel;

pub use auth::{AuthError, LoginResponse, PreloginResponse, TunnelConfig};
pub use packet::{FrameError, GpPacket};
pub use tun::{TunDevice, TunError};
pub use tunnel::{SslTunnel, TunnelError};
