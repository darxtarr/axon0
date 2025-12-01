// axon0-bells-dump: Human-readable Bell log viewer
//
// Reads binary Bell log files and prints formatted output.
//
// Usage:
//   axon0-bells-dump /path/to/log.bell
//
// Output format (one line per Bell):
//   2025-12-01T23:12:34.123Z INFO  Conn=3 Song=17 SongSent bytes=1024 frames=2
//   2025-12-01T23:12:34.125Z WARN  Conn=3 HandshakeFailed reason="signature mismatch"

use axon0::bell::{Bell, BellDetails};
use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <bell-log-file>", args[0]);
        eprintln!("\nReads an AXON/0 Bell log and prints human-readable output.");
        process::exit(1);
    }

    let path = &args[1];

    if let Err(e) = dump_bells(path) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn dump_bells(path: &str) -> io::Result<()> {
    let mut file = File::open(path)?;

    // Read and verify header
    let mut header = [0u8; 5];
    file.read_exact(&mut header)?;

    if &header[0..4] != b"BELL" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid Bell file: missing BELL magic header",
        ));
    }

    let version = header[4];
    if version != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unsupported Bell format version: {}", version),
        ));
    }

    // Read remaining file as TLV stream
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    // Decode Bells one by one
    let mut offset = 0;
    let mut bell_count = 0;

    while offset < contents.len() {
        // Try to decode next Bell
        // We don't know the length upfront, so we'll try to decode from current offset
        // and use TLV length fields to determine how much to consume.

        match decode_one_bell(&contents[offset..]) {
            Ok((bell, consumed)) => {
                print_bell(&bell);
                offset += consumed;
                bell_count += 1;
            }
            Err(e) => {
                eprintln!("\nWarning: Failed to decode Bell at offset {}: {}", offset, e);
                eprintln!("Successfully decoded {} Bells before error.", bell_count);
                break;
            }
        }
    }

    if bell_count == 0 {
        println!("No Bells found in file (empty log).");
    } else {
        eprintln!("\nTotal: {} Bells", bell_count);
    }

    Ok(())
}

/// Decode one Bell from byte slice, returning (Bell, bytes_consumed)
fn decode_one_bell(bytes: &[u8]) -> Result<(Bell, usize), String> {
    // We need to parse TLV records to find the end of this Bell
    // Each TLV is: tag(1) + len(2) + value(len)

    let mut offset = 0;
    let mut tlv_count = 0;

    // Parse TLVs until we've consumed all fields of a Bell
    // We know a Bell has at least: time, level, kind (3 TLVs minimum)
    while offset < bytes.len() && tlv_count < 10 {  // arbitrary safety limit
        if bytes.len() - offset < 3 {
            return Err("Truncated TLV header".to_string());
        }

        let _tag = bytes[offset];
        let len = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize;
        offset += 3;

        if bytes.len() - offset < len {
            return Err("Truncated TLV value".to_string());
        }

        offset += len;
        tlv_count += 1;

        // Heuristic: if we've seen at least 3 TLVs, try to decode
        // If it succeeds, we've found a complete Bell
        if tlv_count >= 3 {
            if let Ok(bell) = Bell::decode(&bytes[0..offset]) {
                return Ok((bell, offset));
            }
        }
    }

    // If we exit loop without decoding, something went wrong
    Err("Could not find valid Bell record".to_string())
}

fn print_bell(bell: &Bell) {
    // Format timestamp (HLC physical time as ISO8601)
    let secs = bell.time.physical_ms / 1000;
    let millis = bell.time.physical_ms % 1000;

    // Simple ISO8601-ish format (YYYY-MM-DDTHH:MM:SS.sssZ)
    // For v0, we'll just show Unix timestamp + millis
    // (Proper date formatting would need chrono or time crate)
    let timestamp = format!("{}.{:03}s", secs, millis);

    // Level
    let level = format!("{:5}", format!("{:?}", bell.level).to_uppercase());

    // Connection and Song IDs (if present)
    let mut ctx = String::new();
    if let Some(conn) = bell.conn_id {
        ctx.push_str(&format!(" Conn={}", conn));
    }
    if let Some(song) = bell.song_id {
        ctx.push_str(&format!(" Song={}", song));
    }

    // Kind
    let kind = format!("{:?}", bell.kind);

    // Details
    let details = format_details(&bell.details);

    println!("{} {}{} {} {}", timestamp, level, ctx, kind, details);
}

fn format_details(details: &BellDetails) -> String {
    match details {
        BellDetails::None => String::new(),
        BellDetails::Error { code, message } => {
            format!("code={} msg=\"{}\"", code, message)
        }
        BellDetails::HandshakeResult {
            security_mode,
            peer_id,
            success,
            reason,
        } => {
            let mut parts = vec![
                format!("security_mode={}", security_mode),
                format!("success={}", success),
            ];
            if let Some(pid) = peer_id {
                parts.push(format!("peer_id={}", hex_short(pid)));
            }
            if let Some(r) = reason {
                parts.push(format!("reason=\"{}\"", r));
            }
            parts.join(" ")
        }
        BellDetails::ConnectionInfo {
            remote_addr,
            local_addr,
        } => {
            format!("remote={} local={}", remote_addr, local_addr)
        }
        BellDetails::PayloadStats { bytes, frame_count } => {
            format!("bytes={} frames={}", bytes, frame_count)
        }
        BellDetails::SongMeta {
            frame_type,
            stream_id,
            payload_len,
        } => {
            format!(
                "frame_type={} stream={} payload_len={}",
                frame_type, stream_id, payload_len
            )
        }
        BellDetails::RetryInfo {
            attempt,
            backoff_ms,
            reason,
        } => {
            format!(
                "attempt={} backoff={}ms reason=\"{}\"",
                attempt, backoff_ms, reason
            )
        }
    }
}

/// Format byte slice as short hex string (first 8 bytes)
fn hex_short(bytes: &[u8]) -> String {
    let display = &bytes[..bytes.len().min(8)];
    let hex: String = display.iter().map(|b| format!("{:02x}", b)).collect();
    if bytes.len() > 8 {
        format!("{}...", hex)
    } else {
        hex
    }
}
