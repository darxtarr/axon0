/// AXON/0 Demo: Initiator
///
/// Connects to 127.0.0.1:52020, completes handshake, sends a DATA Song,
/// and closes gracefully.
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use axon0::conn::{ConnConfig, Role, SecurityPolicy};
use axon0::handshake::{Capabilities, ReasonCode};
use axon0::io::AxonConn;

fn main() {
    println!("AXON/0 Demo Initiator");
    println!("=====================");
    println!();

    // Configure initiator
    let config = ConnConfig {
        role: Role::Initiator,
        node_id: b"INITIATOR_NODE_1".to_vec(),
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

    // Connect to acceptor
    println!("Connecting to 127.0.0.1:52020...");
    let stream = match TcpStream::connect("127.0.0.1:52020") {
        Ok(s) => {
            println!("✓ Connected!");
            s
        }
        Err(e) => {
            eprintln!("✗ Connection failed: {}", e);
            eprintln!("  Make sure the acceptor (axon0-demo-accept) is running first.");
            return;
        }
    };

    // Create AxonConn wrapper
    let mut conn = AxonConn::new(stream, config);

    // Complete handshake
    println!();
    println!("Starting handshake...");
    match conn.initiate_handshake() {
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

    // Send a DATA Song
    println!("Sending DATA Song...");
    let message = b"Hello from AXON/0! This is the first DATA frame on the obsidian glass.";
    match conn.send_data(1, message.to_vec(), false) {
        Ok(_) => {
            println!("✓ Sent {} bytes on stream 1", message.len());
            println!("  Message: {:?}", String::from_utf8_lossy(message));
            println!("  HLC: ({}, {})", conn.hlc().physical_ms, conn.hlc().logical);
            println!();
        }
        Err(e) => {
            eprintln!("✗ Failed to send DATA: {:?}", e);
            return;
        }
    }

    // Wait a moment for the message to be received
    thread::sleep(Duration::from_millis(100));

    // Send another DATA Song with end_of_stream
    println!("Sending final DATA Song (end of stream)...");
    let goodbye = b"Goodbye! Closing stream.";
    match conn.send_data(1, goodbye.to_vec(), true) {
        Ok(_) => {
            println!("✓ Sent {} bytes on stream 1 (EOS)", goodbye.len());
            println!("  Message: {:?}", String::from_utf8_lossy(goodbye));
            println!("  HLC: ({}, {})", conn.hlc().physical_ms, conn.hlc().logical);
            println!();
        }
        Err(e) => {
            eprintln!("✗ Failed to send DATA: {:?}", e);
            return;
        }
    }

    // Wait a moment before closing
    thread::sleep(Duration::from_millis(100));

    // Close gracefully
    println!("Closing connection gracefully...");
    match conn.close(ReasonCode::Normal, Some("Demo complete".to_string())) {
        Ok(_) => {
            println!("✓ CLOSE sent");
        }
        Err(e) => {
            eprintln!("✗ Failed to send CLOSE: {:?}", e);
        }
    }

    println!();
    println!("Demo initiator exiting.");
}
