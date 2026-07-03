//! Acceptance tests for the throughput/wedge-detection hardening
//! (outbound packet batching, bounded mid-frame reads) added on top of
//! the GlobalProtect SSL tunnel, exercised from outside the crate
//! boundary through the public `pmacs_vpn::gp` API.
//!
//! Socket-buffer tuning, the wedge detector, and the outbound-batching
//! loop itself are private to `src/gp/tunnel.rs` and are covered by
//! acceptance-style tests added inside that module's own `#[cfg(test)]`
//! block instead (Rust privacy puts them out of reach here). Likewise
//! ESP-offer observability lives in `src/gp/auth.rs`'s own test module.
//!
//! Run with: cargo test --test tunnel_hardening_acceptance -- --test-threads=1

// ============================================================================
// Outbound batching: wire format must stay a valid, ordered GP-frame stream
// ============================================================================

mod outbound_batching {
    use pmacs_vpn::gp::GpPacket;

    // BREAKS IF: coalescing several queued TUN packets into one TLS write
    // drops, reorders, or corrupts a frame, so an application's packet
    // silently vanishes or arrives as garbage on the wire.
    #[test]
    fn concatenated_frames_each_decode_to_the_original_packet_in_order() {
        let packets = vec![
            GpPacket::ipv4(vec![0x45, 0x00, 0x00, 0x14, 0xaa, 0xbb]),
            GpPacket::ipv6(vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0x40]),
            GpPacket::ipv4(vec![0x45, 0x11, 0x22, 0x33]),
            GpPacket::keepalive(),
            GpPacket::ipv4(vec![0x45, 0xff]),
        ];

        // Mirrors SslTunnel::run's batching loop: one shared buffer, every
        // queued packet's frame appended to it, then (conceptually) written
        // to the gateway stream in a single write_all.
        let mut wire = Vec::new();
        for p in &packets {
            p.encode_into(&mut wire);
        }

        // Walk the batch exactly the way a reader draining the socket
        // would: decode one frame, advance by its encoded length, repeat.
        let mut offset = 0;
        for (i, expected) in packets.iter().enumerate() {
            let decoded = GpPacket::decode(&wire[offset..])
                .unwrap_or_else(|e| panic!("frame {i} at offset {offset} failed to decode: {e}"));
            assert_eq!(
                &decoded, expected,
                "frame {i} at offset {offset} does not match the packet queued at this position \
                 (reordered or corrupted by batching)"
            );
            offset += decoded.encode().len();
        }
        assert_eq!(
            offset,
            wire.len(),
            "trailing bytes left over after decoding every frame in the batch"
        );
    }

    // BREAKS IF: a burst near the real batch cap (SslTunnel's
    // MAX_BATCH_PACKETS = 64) reorders, drops, or merges frames -
    // corruption that would only show up under load, not in a two-packet
    // smoke test.
    #[test]
    fn a_full_size_batch_of_64_packets_preserves_order_and_content() {
        let mut packets = Vec::new();
        for i in 0..64u8 {
            // Distinct payload per packet so a reorder or duplicate is
            // detectable, not just "some frame decoded".
            packets.push(GpPacket::ipv4(vec![0x45, i, i.wrapping_mul(7), 0x00]));
        }

        let mut wire = Vec::new();
        for p in &packets {
            p.encode_into(&mut wire);
        }

        let mut offset = 0;
        for (i, expected) in packets.iter().enumerate() {
            let decoded = GpPacket::decode(&wire[offset..])
                .unwrap_or_else(|e| panic!("packet {i} failed to decode: {e}"));
            assert_eq!(
                decoded.payload, expected.payload,
                "packet {i} payload does not match: batch corrupted or reordered"
            );
            offset += decoded.encode().len();
        }
        assert_eq!(offset, wire.len());
    }

    // BREAKS IF: batching changes the on-wire framing so a batched frame
    // disagrees byte-for-byte with the single-packet format (magic,
    // length, or type byte drift), breaking a gateway that expects
    // identical framing regardless of how frames were grouped for sending.
    #[test]
    fn batched_frame_bytes_are_byte_identical_to_a_standalone_encode() {
        let a = GpPacket::ipv4(vec![0x45, 0x01, 0x02, 0x03]);
        let b = GpPacket::ipv4(vec![0x45, 0x04, 0x05, 0x06]);

        let standalone_a = a.encode();
        let standalone_b = b.encode();

        let mut batched = Vec::new();
        a.encode_into(&mut batched);
        b.encode_into(&mut batched);

        assert_eq!(
            &batched[..standalone_a.len()],
            &standalone_a[..],
            "first frame's bytes changed when batched vs. sent alone"
        );
        assert_eq!(
            &batched[standalone_a.len()..],
            &standalone_b[..],
            "second frame's bytes changed when batched vs. sent alone"
        );

        // Explicit framing check per the wire spec: magic 0x1a2b3c4d,
        // big-endian length, type byte 0x01 for data.
        assert_eq!(
            &batched[0..4],
            &[0x1a, 0x2b, 0x3c, 0x4d],
            "magic must be unchanged by batching"
        );
        assert_eq!(
            &batched[6..8],
            &4u16.to_be_bytes(),
            "length field must be big-endian and unaffected by batching"
        );
        assert_eq!(
            batched[8], 0x01,
            "data type byte must still be 0x01 after batching"
        );
    }
}

// ============================================================================
// Bounded reads: a stream stalled mid-frame must time out, not hang
// ============================================================================

mod bounded_inbound_reads {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // BREAKS IF: a gateway that delivers a frame header but never sends the
    // payload hangs the tunnel forever instead of surfacing a bounded
    // error. This exercises the exact primitive combination used at the
    // payload `read_exact` between header and full frame in
    // SslTunnel::run (src/gp/tunnel.rs): `tokio::time::timeout(bound,
    // stream.read_exact(buf))`. Constructing a real SslTunnel requires a
    // live TUN device and TLS gateway that aren't available here, so this
    // proves the primitive is sound on a raw loopback socket; the wiring
    // of this exact pattern into `run()` is confirmed by code inspection.
    #[tokio::test]
    async fn read_exact_wrapped_in_timeout_errors_out_when_payload_never_arrives() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Header claims a 100-byte payload that is never sent, exactly
            // the "stream stops mid-frame" scenario in the acceptance
            // criteria.
            let mut header = [0u8; 16];
            header[6..8].copy_from_slice(&100u16.to_be_bytes());
            sock.write_all(&header).await.unwrap();
            // Keep the connection open (no EOF, no payload, no close) so
            // the only way out for the reader is the timeout.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut header_buf = [0u8; 16];
        client.read_exact(&mut header_buf).await.unwrap();
        let len = u16::from_be_bytes([header_buf[6], header_buf[7]]) as usize;
        assert_eq!(len, 100);

        let mut payload = vec![0u8; len];
        let bound = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(bound, client.read_exact(&mut payload)).await;
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a stream that stalls mid-frame must surface a timeout error, not hang forever"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout took {elapsed:?}, far longer than the configured {bound:?} bound - \
             this would hang the tunnel indefinitely in practice"
        );

        server.abort();
    }

    // Positive control: a payload that does arrive, comfortably inside the
    // bound, must not be spuriously timed out. Without this, a test suite
    // that only checks the failure case could pass even if the timeout
    // were wired to fire immediately regardless of incoming data.
    #[tokio::test]
    async fn read_exact_wrapped_in_timeout_succeeds_when_payload_arrives_in_time() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 16];
            header[6..8].copy_from_slice(&4u16.to_be_bytes());
            sock.write_all(&header).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            sock.write_all(&[0xde, 0xad, 0xbe, 0xef]).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut header_buf = [0u8; 16];
        client.read_exact(&mut header_buf).await.unwrap();
        let len = u16::from_be_bytes([header_buf[6], header_buf[7]]) as usize;

        let mut payload = vec![0u8; len];
        let result =
            tokio::time::timeout(Duration::from_millis(500), client.read_exact(&mut payload)).await;

        assert!(
            result.is_ok(),
            "payload arriving comfortably inside the bound must not be timed out"
        );
        result.unwrap().unwrap();
        assert_eq!(payload, vec![0xde, 0xad, 0xbe, 0xef]);

        server.await.unwrap();
    }
}

// ============================================================================
// Wiring: the public surface the acceptance criteria depend on must exist
// ============================================================================

mod wiring {
    // BREAKS IF: the Timeout error variant SslTunnel::run returns on a
    // stalled mid-frame read (and on inbound-timeout expiry generally)
    // stops being part of the public error surface that callers match on
    // to detect and reconnect.
    #[test]
    fn tunnel_timeout_error_variant_is_public() {
        let _ = pmacs_vpn::gp::TunnelError::Timeout;
    }

    // BREAKS IF: GpPacket::encode_into (the batching primitive the tunnel
    // loop relies on to append multiple frames into one buffer) is
    // removed or made private, silently reverting to one write per packet.
    #[test]
    fn batching_primitive_is_public() {
        let _ = pmacs_vpn::gp::GpPacket::encode_into;
    }
}
