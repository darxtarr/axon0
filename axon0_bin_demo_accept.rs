/// AXON/0 Demo: Acceptor
///
/// Listens on port 52020, accepts one TCP connection, completes handshake,
/// and prints information about incoming DATA Songs.
use std::net::TcpListener;

use axon0::conn::{ConnConfig, Role, SecurityPolicy};
use axon0::handshake::Capabilities;
use axon0::io::{AxonConn, AxonEvent};

fn main() {
    println!("AXON/0 Demo Acceptor");
    println!("====================");
    println!();

    // Configure acceptor
    let config = ConnConfig {
        role: Role::Acceptor,
        node_id: b"ACCEPTOR_NODE_01".to_vec(),
        capabilities: Capabilities::new(
            Capabilities::HLC_SUPPORTED
                | Capabilities::CHECKSUM_SUPPORTED
                | Capabilities::SIGNATURE_SUPPORTED,
        ),
        security_policy: SecurityPolicy::permissive(),
        ed25519_pubkey: None, // TrustedLan mode for demo
    };

    println!("Node ID: {:?}", String::from_utf8_lossy(&config.node_id));
    println!("Security policy: Permissive (TrustedLan/Checksummed/Signed)");
    println!();

    // Listen on port 52020
    let listener = TcpListener::bind("127.0.0.1:52020").expect("Failed to bind to port 52020");
    println!("Listening on 127.0.0.1:52020");
    println!("Waiting for connection...");
    println!();

    // Accept one connection
    let (stream, addr) = listener.accept().expect("Failed to accept connection");
    println!("Accepted connection from {}", addr);

    // Create AxonConn wrapper
    let mut conn = AxonConn::new(stream, config);

    // Complete handshake
    println!("Starting handshake...");
    match conn.accept_handshake() {
        Ok(active) => {
            println!("✓ Handshake completed successfully!");
            println!("  Remote node ID: {:?}", String::from_utf8_lossy(&active.remote_node_id));
            println!("  Security mode: {:?}", active.security_mode);
            println!("  Capabilities: 0x{:08x}", active.capabilities.0);
            println!("  HLC: ({}, {})", conn.hlc().physical_ms, conn.hlc().logical);
            println!();
        }
        Err(e) => {
            eprintln!("✗ Handshake failed: {:?}", e);
            return;
        }
    }

    // Main event loop - receive and print DATA Songs
    println!("Connection active. Waiting for DATA Songs...");
    println!("(Press Ctrl+C to exit)");
    println!();

    loop {
        match conn.poll_once() {
            Ok(Some(event)) => match event {
                AxonEvent::DataReceived {
                    stream_id,
                    data,
                    end_of_stream,
                } => {
                    println!("📦 Received DATA:");
                    println!("  Stream ID: {}", stream_id);
                    println!("  Size: {} bytes", data.len());
                    println!("  End of stream: {}", end_of_stream);
                    println!("  Data: {:?}", String::from_utf8_lossy(&data));
                    println!("  HLC: ({}, {})", conn.hlc().physical_ms, conn.hlc().logical);
                    println!();

                    if end_of_stream {
                        println!("Stream ended. Closing connection.");
                        break;
                    }
                }
                AxonEvent::PingReceived { nonce } => {
                    println!("🏓 Received PING (auto-replied with PONG)");
                    println!("  Nonce: {:?}", nonce);
                    println!();
                }
                AxonEvent::PongReceived { nonce } => {
                    println!("🏓 Received PONG");
                    println!("  Nonce: {:?}", nonce);
                    println!();
                }
                AxonEvent::Closed(reason, text) => {
                    println!("🔌 Connection closed:");
                    println!("  Reason: {:?}", reason);
                    if let Some(text) = text {
                        println!("  Message: {}", text);
                    }
                    break;
                }
                _ => {}
            },
            Ok(None) => {
                // No event, continue
            }
            Err(e) => {
                eprintln!("✗ Error: {:?}", e);
                break;
            }
        }
    }

    println!();
    println!("Demo acceptor exiting.");
}
