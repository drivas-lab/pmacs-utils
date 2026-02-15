//! GlobalProtect SSL tunnel packet framing
//!
//! Implements the packet format for GlobalProtect SSL tunnel:
//! ```text
//! [magic:4][ethertype:2][len:2][type:8][payload:N]
//! ```
//!
//! - Magic: 0x1a2b3c4d
//! - Ethertype: 0x0800 (IPv4) or 0x86dd (IPv6), 0x0000 for keepalive
//! - Length: payload size in bytes, big-endian (0 = keepalive)
//! - Type: 0x01000000 00000000 for data, 0x00000000 00000000 for keepalive
//!
//! Reference: OpenConnect gpst.c

use thiserror::Error;

/// Packet framing errors
#[derive(Error, Debug)]
pub enum FrameError {
    #[error("Packet too short (minimum {0} bytes)")]
    TooShort(usize),

    #[error("Invalid magic header")]
    BadMagic,

    #[error("Invalid ethertype: {0:#x}")]
    InvalidEthertype(u16),

    #[error("Packet length mismatch: expected {expected}, got {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

const MAGIC: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];
const HEADER_SIZE: usize = 16;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// A GlobalProtect packet
#[derive(Debug, Clone, PartialEq)]
pub struct GpPacket {
    /// Ethertype (IPv4 or IPv6)
    pub ethertype: u16,
    /// IP packet payload (empty for keepalives)
    pub payload: Vec<u8>,
}

impl GpPacket {
    /// Create a new IPv4 packet
    pub fn ipv4(payload: Vec<u8>) -> Self {
        Self {
            ethertype: ETHERTYPE_IPV4,
            payload,
        }
    }

    /// Create a new IPv6 packet
    pub fn ipv6(payload: Vec<u8>) -> Self {
        Self {
            ethertype: ETHERTYPE_IPV6,
            payload,
        }
    }

    /// Create a keepalive packet (empty payload)
    pub fn keepalive() -> Self {
        Self {
            ethertype: 0x0000,
            payload: Vec::new(),
        }
    }

    /// Check if this is a keepalive packet
    pub fn is_keepalive(&self) -> bool {
        self.payload.is_empty()
    }

    /// Detect IP version from payload and create appropriate packet
    ///
    /// Returns None if payload is too short to determine version
    pub fn from_ip_packet(payload: Vec<u8>) -> Option<Self> {
        if payload.is_empty() {
            return Some(Self::keepalive());
        }

        // Check IP version in first nibble
        let version = (payload[0] >> 4) & 0x0F;
        match version {
            4 => Some(Self::ipv4(payload)),
            6 => Some(Self::ipv6(payload)),
            _ => None,
        }
    }

    /// Encode packet into wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(HEADER_SIZE + self.payload.len());

        // Magic
        frame.extend_from_slice(&MAGIC);

        // Ethertype
        frame.extend_from_slice(&self.ethertype.to_be_bytes());

        // Length
        let len = self.payload.len() as u16;
        frame.extend_from_slice(&len.to_be_bytes());

        // Type field (bytes 8-15):
        // - Data packets: 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        // - Keepalives:   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        // Per OpenConnect gpst.c: "Always \x01\0\0\0\0\0\0\0" for data
        if self.payload.is_empty() {
            frame.extend_from_slice(&[0u8; 8]);
        } else {
            frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        // Payload
        frame.extend_from_slice(&self.payload);

        frame
    }

    /// Decode packet from wire format
    pub fn decode(frame: &[u8]) -> Result<Self, FrameError> {
        if frame.len() < HEADER_SIZE {
            return Err(FrameError::TooShort(HEADER_SIZE));
        }

        // Check magic
        if frame[0..4] != MAGIC {
            return Err(FrameError::BadMagic);
        }

        // Parse ethertype
        let ethertype = u16::from_be_bytes([frame[4], frame[5]]);

        // Parse length
        let len = u16::from_be_bytes([frame[6], frame[7]]) as usize;

        // Keepalive packet
        if len == 0 {
            return Ok(Self::keepalive());
        }

        // Check we have enough data
        if frame.len() < HEADER_SIZE + len {
            return Err(FrameError::LengthMismatch {
                expected: HEADER_SIZE + len,
                actual: frame.len(),
            });
        }

        // Extract payload
        let payload = frame[HEADER_SIZE..HEADER_SIZE + len].to_vec();

        Ok(Self { ethertype, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_ipv4() {
        let payload = vec![
            0x45, 0x00, 0x00, 0x54, // IPv4 header start
            0x00, 0x00, 0x40, 0x00, 0x40, 0x01,
        ];
        let packet = GpPacket::ipv4(payload.clone());

        let encoded = packet.encode();
        assert_eq!(encoded.len(), HEADER_SIZE + payload.len());

        // Check magic
        assert_eq!(&encoded[0..4], &MAGIC);

        // Check ethertype
        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), ETHERTYPE_IPV4);

        // Check length
        assert_eq!(
            u16::from_be_bytes([encoded[6], encoded[7]]),
            payload.len() as u16
        );

        // Check type field: data packets must have 0x01 at byte 8
        assert_eq!(encoded[8], 0x01, "Data packets must have type byte 0x01");
        assert_eq!(
            &encoded[9..16],
            &[0u8; 7],
            "Remaining type bytes must be zero"
        );

        // Decode
        let decoded = GpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_encode_decode_ipv6() {
        let payload = vec![
            0x60, 0x00, 0x00, 0x00, // IPv6 header start
            0x00, 0x28, 0x3a, 0x40,
        ];
        let packet = GpPacket::ipv6(payload.clone());

        let encoded = packet.encode();
        let decoded = GpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_keepalive() {
        let packet = GpPacket::keepalive();
        assert!(packet.is_keepalive());

        let encoded = packet.encode();
        assert_eq!(encoded.len(), HEADER_SIZE);

        // Length should be 0
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 0);

        // Type field should be all zeros for keepalive
        assert_eq!(
            &encoded[8..16],
            &[0u8; 8],
            "Keepalive type bytes must be zero"
        );

        let decoded = GpPacket::decode(&encoded).unwrap();
        assert!(decoded.is_keepalive());
    }

    #[test]
    fn test_from_ip_packet_ipv4() {
        let ipv4_payload = vec![0x45, 0x00, 0x00, 0x28]; // Version 4
        let packet = GpPacket::from_ip_packet(ipv4_payload.clone()).unwrap();
        assert_eq!(packet.ethertype, ETHERTYPE_IPV4);
        assert_eq!(packet.payload, ipv4_payload);
    }

    #[test]
    fn test_from_ip_packet_ipv6() {
        let ipv6_payload = vec![0x60, 0x00, 0x00, 0x00]; // Version 6
        let packet = GpPacket::from_ip_packet(ipv6_payload.clone()).unwrap();
        assert_eq!(packet.ethertype, ETHERTYPE_IPV6);
        assert_eq!(packet.payload, ipv6_payload);
    }

    #[test]
    fn test_decode_bad_magic() {
        let mut frame = vec![0u8; HEADER_SIZE + 10];
        frame[0..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Bad magic

        let result = GpPacket::decode(&frame);
        assert!(matches!(result, Err(FrameError::BadMagic)));
    }

    #[test]
    fn test_decode_too_short() {
        let frame = vec![0u8; 10]; // Less than HEADER_SIZE
        let result = GpPacket::decode(&frame);
        assert!(matches!(result, Err(FrameError::TooShort(_))));
    }

    #[test]
    fn test_decode_length_mismatch() {
        let mut frame = vec![0u8; HEADER_SIZE];
        frame[0..4].copy_from_slice(&MAGIC);
        frame[6..8].copy_from_slice(&100u16.to_be_bytes()); // Claims 100 bytes payload

        let result = GpPacket::decode(&frame);
        assert!(matches!(result, Err(FrameError::LengthMismatch { .. })));
    }
}
