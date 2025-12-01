// AXON/0 Bell (introspection event) system
//
// Bells are structured trace events emitted at key decision points in the AXON/0 stack.
// They are:
//   - NOT part of the wire protocol (local observability only)
//   - Designed for AI/agent consumption (stable enums, correlatable IDs, HLC timeline)
//   - Pluggable (host app provides BellSink, or Bells are no-op)
//   - Compact binary format (TLV records in append-only files)
//
// Philosophy:
//   Songs = what nodes say to each other
//   Bells = what a node says about itself

use crate::hlc::Hlc;

/// Severity level for Bell events (standard log levels)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BellLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// Event type taxonomy
///
/// Stable enum that AI agents can learn once and correlate across nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum BellKind {
    // Connection lifecycle
    ConnectionOpened = 100,
    ConnectionClosed = 101,
    ConnectionError = 102,

    // Handshake
    HandshakeStarted = 200,
    HandshakeCompleted = 201,
    HandshakeFailed = 202,

    // Song send/receive
    SongSent = 300,
    SongReceived = 301,
    SongDropped = 302,

    // Frame-level events
    FrameSent = 400,
    FrameReceived = 401,
    FrameParseError = 402,

    // Retry and backpressure
    RetryScheduled = 500,
    BackpressureApplied = 501,

    // Generic error
    ErrorRaised = 900,
}

/// Event-specific payload
///
/// Small, structured details about what happened.
/// Keep variants focused and minimal.
#[derive(Debug, Clone, PartialEq)]
pub enum BellDetails {
    /// No additional details
    None,

    /// Generic error event
    Error {
        code: u32,
        message: String,
    },

    /// Handshake outcome
    HandshakeResult {
        security_mode: u8,
        peer_id: Option<Vec<u8>>, // raw bytes, 16-byte node ID
        success: bool,
        reason: Option<String>,
    },

    /// Connection info
    ConnectionInfo {
        remote_addr: String, // "192.168.1.42:7777"
        local_addr: String,
    },

    /// Song/frame statistics
    PayloadStats {
        bytes: u64,
        frame_count: u32,
    },

    /// Song metadata
    SongMeta {
        frame_type: u8,  // FrameType as u8
        stream_id: u64,
        payload_len: u32,
    },

    /// Retry details
    RetryInfo {
        attempt: u32,
        backoff_ms: u64,
        reason: String,
    },
}

/// A Bell: single introspection event emitted by AXON/0
#[derive(Debug, Clone)]
pub struct Bell {
    /// When this happened (HLC timestamp)
    pub time: Hlc,

    /// Severity level
    pub level: BellLevel,

    /// Event type
    pub kind: BellKind,

    /// Connection ID (if event is scoped to a connection)
    pub conn_id: Option<u64>,

    /// Song ID (if event is scoped to a specific Song)
    pub song_id: Option<u64>,

    /// Event-specific payload
    pub details: BellDetails,
}

impl Bell {
    /// Create a new Bell with minimal fields
    pub fn new(time: Hlc, level: BellLevel, kind: BellKind) -> Self {
        Self {
            time,
            level,
            kind,
            conn_id: None,
            song_id: None,
            details: BellDetails::None,
        }
    }

    /// Builder: attach connection ID
    pub fn with_conn(mut self, conn_id: u64) -> Self {
        self.conn_id = Some(conn_id);
        self
    }

    /// Builder: attach song ID
    pub fn with_song(mut self, song_id: u64) -> Self {
        self.song_id = Some(song_id);
        self
    }

    /// Builder: attach details
    pub fn with_details(mut self, details: BellDetails) -> Self {
        self.details = details;
        self
    }
}

/// BellSink trait: pluggable backend for Bell emission
///
/// Host application implements this to control where Bells go:
///   - File writer (binary TLV log)
///   - In-memory ring buffer
///   - Network forwarder to trace aggregator
///   - No-op (if observability not needed)
///
/// AXON/0 holds an Option<Arc<dyn BellSink>> and calls emit() at key points.
pub trait BellSink: Send + Sync + 'static {
    /// Emit a Bell event
    ///
    /// Implementation should be fast (non-blocking write, or async dispatch).
    /// AXON/0 will call this from hot paths (Song send/receive).
    fn emit(&self, bell: Bell);

    /// Optional: flush buffered Bells to stable storage
    ///
    /// Called during graceful shutdown or explicit sync points.
    fn flush(&self) {}
}

// ────────────────────────────────────────────────────────────────────────────
// Binary encoding for Bells (TLV format)
//
// File format:
//   Magic: "BELL" (0x42 0x45 0x4C 0x4C)
//   Version: u8 (0x00 for v0)
//   Records: stream of TLV-encoded Bell structs
//
// Each Bell record is a TLV document with tags:
//   0x01: time (HLC: u64 physical_ms + u16 logical)
//   0x02: level (u8)
//   0x03: kind (u16)
//   0x04: conn_id (u64, optional)
//   0x05: song_id (u64, optional)
//   0x06: details (nested TLV, variant-specific)

use crate::tlv::{decode_tlvs, encode_tlvs, Tlv};

const BELL_MAGIC: &[u8; 4] = b"BELL";
const BELL_VERSION: u8 = 0;

// TLV tags for Bell encoding
const TAG_TIME: u8 = 0x01;
const TAG_LEVEL: u8 = 0x02;
const TAG_KIND: u8 = 0x03;
const TAG_CONN_ID: u8 = 0x04;
const TAG_SONG_ID: u8 = 0x05;
const TAG_DETAILS: u8 = 0x06;

// TLV tags for BellDetails variants (nested inside TAG_DETAILS)
const DETAIL_NONE: u8 = 0x00;
const DETAIL_ERROR: u8 = 0x01;
const DETAIL_HANDSHAKE: u8 = 0x02;
const DETAIL_CONNECTION: u8 = 0x03;
const DETAIL_STATS: u8 = 0x04;
const DETAIL_SONG_META: u8 = 0x05;
const DETAIL_RETRY: u8 = 0x06;

impl Bell {
    /// Encode Bell as TLV record
    pub fn encode(&self) -> Vec<u8> {
        let mut tlvs = Vec::new();

        // Time (HLC: 8 bytes physical_ms + 4 bytes logical)
        let mut time_bytes = Vec::with_capacity(12);
        time_bytes.extend_from_slice(&self.time.physical_ms.to_be_bytes());
        time_bytes.extend_from_slice(&self.time.logical.to_be_bytes());
        tlvs.push(Tlv::new(TAG_TIME, time_bytes));

        // Level (u8)
        tlvs.push(Tlv::new(TAG_LEVEL, vec![self.level as u8]));

        // Kind (u16)
        tlvs.push(Tlv::new(TAG_KIND, (self.kind as u16).to_be_bytes().to_vec()));

        // Optional conn_id
        if let Some(conn_id) = self.conn_id {
            tlvs.push(Tlv::new(TAG_CONN_ID, conn_id.to_be_bytes().to_vec()));
        }

        // Optional song_id
        if let Some(song_id) = self.song_id {
            tlvs.push(Tlv::new(TAG_SONG_ID, song_id.to_be_bytes().to_vec()));
        }

        // Details (nested TLV)
        let details_bytes = self.encode_details();
        if !details_bytes.is_empty() {
            tlvs.push(Tlv::new(TAG_DETAILS, details_bytes));
        }

        encode_tlvs(&tlvs)
    }

    /// Encode BellDetails as nested TLV
    fn encode_details(&self) -> Vec<u8> {
        let mut inner_tlvs = Vec::new();

        match &self.details {
            BellDetails::None => {
                inner_tlvs.push(Tlv::new(DETAIL_NONE, vec![]));
            }
            BellDetails::Error { code, message } => {
                inner_tlvs.push(Tlv::new(DETAIL_ERROR, vec![])); // variant tag
                inner_tlvs.push(Tlv::new(0x01, code.to_be_bytes().to_vec()));
                inner_tlvs.push(Tlv::new(0x02, message.as_bytes().to_vec()));
            }
            BellDetails::HandshakeResult {
                security_mode,
                peer_id,
                success,
                reason,
            } => {
                inner_tlvs.push(Tlv::new(DETAIL_HANDSHAKE, vec![]));
                inner_tlvs.push(Tlv::new(0x01, vec![*security_mode]));
                if let Some(pid) = peer_id {
                    inner_tlvs.push(Tlv::new(0x02, pid.clone()));
                }
                inner_tlvs.push(Tlv::new(0x03, vec![*success as u8]));
                if let Some(r) = reason {
                    inner_tlvs.push(Tlv::new(0x04, r.as_bytes().to_vec()));
                }
            }
            BellDetails::ConnectionInfo {
                remote_addr,
                local_addr,
            } => {
                inner_tlvs.push(Tlv::new(DETAIL_CONNECTION, vec![]));
                inner_tlvs.push(Tlv::new(0x01, remote_addr.as_bytes().to_vec()));
                inner_tlvs.push(Tlv::new(0x02, local_addr.as_bytes().to_vec()));
            }
            BellDetails::PayloadStats { bytes, frame_count } => {
                inner_tlvs.push(Tlv::new(DETAIL_STATS, vec![]));
                inner_tlvs.push(Tlv::new(0x01, bytes.to_be_bytes().to_vec()));
                inner_tlvs.push(Tlv::new(0x02, frame_count.to_be_bytes().to_vec()));
            }
            BellDetails::SongMeta {
                frame_type,
                stream_id,
                payload_len,
            } => {
                inner_tlvs.push(Tlv::new(DETAIL_SONG_META, vec![]));
                inner_tlvs.push(Tlv::new(0x01, vec![*frame_type]));
                inner_tlvs.push(Tlv::new(0x02, stream_id.to_be_bytes().to_vec()));
                inner_tlvs.push(Tlv::new(0x03, payload_len.to_be_bytes().to_vec()));
            }
            BellDetails::RetryInfo {
                attempt,
                backoff_ms,
                reason,
            } => {
                inner_tlvs.push(Tlv::new(DETAIL_RETRY, vec![]));
                inner_tlvs.push(Tlv::new(0x01, attempt.to_be_bytes().to_vec()));
                inner_tlvs.push(Tlv::new(0x02, backoff_ms.to_be_bytes().to_vec()));
                inner_tlvs.push(Tlv::new(0x03, reason.as_bytes().to_vec()));
            }
        }

        encode_tlvs(&inner_tlvs)
    }

    /// Decode Bell from TLV record
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let tlvs = decode_tlvs(bytes).map_err(|e| format!("{:?}", e))?;

        let mut time_opt = None;
        let mut level_opt = None;
        let mut kind_opt = None;
        let mut conn_id = None;
        let mut song_id = None;
        let mut details = BellDetails::None;

        for tlv in tlvs {
            match tlv.t {
                TAG_TIME => {
                    if tlv.value.len() != 12 {
                        return Err("Invalid time encoding".to_string());
                    }
                    let physical_ms = u64::from_be_bytes(tlv.value[0..8].try_into().unwrap());
                    let logical = u32::from_be_bytes(tlv.value[8..12].try_into().unwrap());
                    time_opt = Some(Hlc {
                        physical_ms,
                        logical,
                    });
                }
                TAG_LEVEL => {
                    if tlv.value.len() != 1 {
                        return Err("Invalid level encoding".to_string());
                    }
                    level_opt = Some(match tlv.value[0] {
                        0 => BellLevel::Trace,
                        1 => BellLevel::Debug,
                        2 => BellLevel::Info,
                        3 => BellLevel::Warn,
                        4 => BellLevel::Error,
                        _ => return Err("Unknown BellLevel".to_string()),
                    });
                }
                TAG_KIND => {
                    if tlv.value.len() != 2 {
                        return Err("Invalid kind encoding".to_string());
                    }
                    let kind_u16 = u16::from_be_bytes(tlv.value[0..2].try_into().unwrap());
                    kind_opt = Some(match kind_u16 {
                        100 => BellKind::ConnectionOpened,
                        101 => BellKind::ConnectionClosed,
                        102 => BellKind::ConnectionError,
                        200 => BellKind::HandshakeStarted,
                        201 => BellKind::HandshakeCompleted,
                        202 => BellKind::HandshakeFailed,
                        300 => BellKind::SongSent,
                        301 => BellKind::SongReceived,
                        302 => BellKind::SongDropped,
                        400 => BellKind::FrameSent,
                        401 => BellKind::FrameReceived,
                        402 => BellKind::FrameParseError,
                        500 => BellKind::RetryScheduled,
                        501 => BellKind::BackpressureApplied,
                        900 => BellKind::ErrorRaised,
                        _ => return Err(format!("Unknown BellKind: {}", kind_u16)),
                    });
                }
                TAG_CONN_ID => {
                    if tlv.value.len() != 8 {
                        return Err("Invalid conn_id encoding".to_string());
                    }
                    conn_id = Some(u64::from_be_bytes(tlv.value[0..8].try_into().unwrap()));
                }
                TAG_SONG_ID => {
                    if tlv.value.len() != 8 {
                        return Err("Invalid song_id encoding".to_string());
                    }
                    song_id = Some(u64::from_be_bytes(tlv.value[0..8].try_into().unwrap()));
                }
                TAG_DETAILS => {
                    details = Self::decode_details(&tlv.value)?;
                }
                _ => {} // ignore unknown tags (forward compat)
            }
        }

        Ok(Bell {
            time: time_opt.ok_or("Missing time field")?,
            level: level_opt.ok_or("Missing level field")?,
            kind: kind_opt.ok_or("Missing kind field")?,
            conn_id,
            song_id,
            details,
        })
    }

    /// Decode BellDetails from nested TLV
    fn decode_details(bytes: &[u8]) -> Result<BellDetails, String> {
        let inner_tlvs = decode_tlvs(bytes).map_err(|e| format!("{:?}", e))?;
        if inner_tlvs.is_empty() {
            return Ok(BellDetails::None);
        }

        let variant_tag = inner_tlvs[0].t;
        match variant_tag {
            DETAIL_NONE => Ok(BellDetails::None),
            DETAIL_ERROR => {
                let mut code = 0;
                let mut message = String::new();
                for tlv in &inner_tlvs[1..] {
                    match tlv.t {
                        0x01 => code = u32::from_be_bytes(tlv.value[0..4].try_into().unwrap()),
                        0x02 => message = String::from_utf8_lossy(&tlv.value).to_string(),
                        _ => {}
                    }
                }
                Ok(BellDetails::Error { code, message })
            }
            DETAIL_HANDSHAKE => {
                let mut security_mode = 0;
                let mut peer_id = None;
                let mut success = false;
                let mut reason = None;
                for tlv in &inner_tlvs[1..] {
                    match tlv.t {
                        0x01 => security_mode = tlv.value[0],
                        0x02 => peer_id = Some(tlv.value.clone()),
                        0x03 => success = tlv.value[0] != 0,
                        0x04 => reason = Some(String::from_utf8_lossy(&tlv.value).to_string()),
                        _ => {}
                    }
                }
                Ok(BellDetails::HandshakeResult {
                    security_mode,
                    peer_id,
                    success,
                    reason,
                })
            }
            DETAIL_CONNECTION => {
                let mut remote_addr = String::new();
                let mut local_addr = String::new();
                for tlv in &inner_tlvs[1..] {
                    match tlv.t {
                        0x01 => remote_addr = String::from_utf8_lossy(&tlv.value).to_string(),
                        0x02 => local_addr = String::from_utf8_lossy(&tlv.value).to_string(),
                        _ => {}
                    }
                }
                Ok(BellDetails::ConnectionInfo {
                    remote_addr,
                    local_addr,
                })
            }
            DETAIL_STATS => {
                let mut bytes = 0;
                let mut frame_count = 0;
                for tlv in &inner_tlvs[1..] {
                    match tlv.t {
                        0x01 => bytes = u64::from_be_bytes(tlv.value[0..8].try_into().unwrap()),
                        0x02 => {
                            frame_count = u32::from_be_bytes(tlv.value[0..4].try_into().unwrap())
                        }
                        _ => {}
                    }
                }
                Ok(BellDetails::PayloadStats { bytes, frame_count })
            }
            DETAIL_SONG_META => {
                let mut frame_type = 0;
                let mut stream_id = 0;
                let mut payload_len = 0;
                for tlv in &inner_tlvs[1..] {
                    match tlv.t {
                        0x01 => frame_type = tlv.value[0],
                        0x02 => stream_id = u64::from_be_bytes(tlv.value[0..8].try_into().unwrap()),
                        0x03 => {
                            payload_len = u32::from_be_bytes(tlv.value[0..4].try_into().unwrap())
                        }
                        _ => {}
                    }
                }
                Ok(BellDetails::SongMeta {
                    frame_type,
                    stream_id,
                    payload_len,
                })
            }
            DETAIL_RETRY => {
                let mut attempt = 0;
                let mut backoff_ms = 0;
                let mut reason = String::new();
                for tlv in &inner_tlvs[1..] {
                    match tlv.t {
                        0x01 => attempt = u32::from_be_bytes(tlv.value[0..4].try_into().unwrap()),
                        0x02 => {
                            backoff_ms = u64::from_be_bytes(tlv.value[0..8].try_into().unwrap())
                        }
                        0x03 => reason = String::from_utf8_lossy(&tlv.value).to_string(),
                        _ => {}
                    }
                }
                Ok(BellDetails::RetryInfo {
                    attempt,
                    backoff_ms,
                    reason,
                })
            }
            _ => Err(format!("Unknown BellDetails variant: {}", variant_tag)),
        }
    }
}

/// File header for Bell trace files
pub fn bell_file_header() -> Vec<u8> {
    let mut header = Vec::with_capacity(5);
    header.extend_from_slice(BELL_MAGIC);
    header.push(BELL_VERSION);
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bell_encode_decode_minimal() {
        let hlc = Hlc::new(1_735_000_000_000);
        let bell = Bell::new(hlc, BellLevel::Info, BellKind::ConnectionOpened);

        let encoded = bell.encode();
        let decoded = Bell::decode(&encoded).unwrap();

        assert_eq!(decoded.time, hlc);
        assert_eq!(decoded.level, BellLevel::Info);
        assert_eq!(decoded.kind, BellKind::ConnectionOpened);
        assert_eq!(decoded.conn_id, None);
        assert_eq!(decoded.song_id, None);
        assert_eq!(decoded.details, BellDetails::None);
    }

    #[test]
    fn bell_encode_decode_with_ids() {
        let hlc = Hlc::new(1_735_000_000_000);
        let bell = Bell::new(hlc, BellLevel::Debug, BellKind::SongSent)
            .with_conn(42)
            .with_song(1337);

        let encoded = bell.encode();
        let decoded = Bell::decode(&encoded).unwrap();

        assert_eq!(decoded.conn_id, Some(42));
        assert_eq!(decoded.song_id, Some(1337));
    }

    #[test]
    fn bell_encode_decode_error_details() {
        let hlc = Hlc::new(1_735_000_000_000);
        let bell = Bell::new(hlc, BellLevel::Error, BellKind::ErrorRaised).with_details(
            BellDetails::Error {
                code: 500,
                message: "Connection timeout".to_string(),
            },
        );

        let encoded = bell.encode();
        let decoded = Bell::decode(&encoded).unwrap();

        match decoded.details {
            BellDetails::Error { code, message } => {
                assert_eq!(code, 500);
                assert_eq!(message, "Connection timeout");
            }
            _ => panic!("Expected Error details"),
        }
    }

    #[test]
    fn bell_encode_decode_handshake_details() {
        let hlc = Hlc::new(1_735_000_000_000);
        let peer_id = vec![0x42; 16];

        let bell =
            Bell::new(hlc, BellLevel::Info, BellKind::HandshakeCompleted).with_details(
                BellDetails::HandshakeResult {
                    security_mode: 0,
                    peer_id: Some(peer_id.clone()),
                    success: true,
                    reason: Some("Trusted-LAN".to_string()),
                },
            );

        let encoded = bell.encode();
        let decoded = Bell::decode(&encoded).unwrap();

        match decoded.details {
            BellDetails::HandshakeResult {
                security_mode,
                peer_id: pid,
                success,
                reason,
            } => {
                assert_eq!(security_mode, 0);
                assert_eq!(pid, Some(peer_id));
                assert!(success);
                assert_eq!(reason, Some("Trusted-LAN".to_string()));
            }
            _ => panic!("Expected HandshakeResult details"),
        }
    }

    #[test]
    fn bell_file_header_format() {
        let header = bell_file_header();
        assert_eq!(header.len(), 5);
        assert_eq!(&header[0..4], b"BELL");
        assert_eq!(header[4], 0); // version 0
    }
}
