/// Handshake and control frame helpers for AXON/0
///
/// This module provides ergonomic, typed APIs over the generic Song/TLV wire format
/// for handshake and control frames as specified in axon0_doc_spec_handshake.md
use crate::frame::{Flags, FrameType, SongHeader};
use crate::hlc::Hlc;
use crate::song::{Payload, Song};
use crate::tlv::Tlv;

/// TLV type codes from spec §5 and handshake doc
pub mod tlv_types {
    // Handshake TLVs (spec §5 and handshake doc)
    pub const NODE_ID: u8 = 0x01;
    pub const CAPABILITIES: u8 = 0x02;
    pub const SECURITY_MODE: u8 = 0x03;
    pub const PUBKEY: u8 = 0x04;
    pub const RESULT: u8 = 0x05;

    // Flow control TLVs (spec §5)
    pub const STREAM_ID: u8 = 0x10;
    pub const RANGE_START: u8 = 0x11;
    pub const RANGE_END: u8 = 0x12;

    // Keepalive/diagnostic TLVs (spec §5)
    pub const NONCE: u8 = 0x20;

    // Close/error TLVs (spec §5)
    pub const REASON_CODE: u8 = 0x21;
    pub const REASON_TEXT: u8 = 0x22;
}

/// Security modes (handshake doc §3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityMode {
    TrustedLan = 0x00,
    Checksummed = 0x01,
    Signed = 0x02,
}

impl SecurityMode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(SecurityMode::TrustedLan),
            0x01 => Some(SecurityMode::Checksummed),
            0x02 => Some(SecurityMode::Signed),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the most secure mode (for policy decisions)
    pub fn most_secure(modes: &[SecurityMode]) -> Option<SecurityMode> {
        if modes.contains(&SecurityMode::Signed) {
            Some(SecurityMode::Signed)
        } else if modes.contains(&SecurityMode::Checksummed) {
            Some(SecurityMode::Checksummed)
        } else if modes.contains(&SecurityMode::TrustedLan) {
            Some(SecurityMode::TrustedLan)
        } else {
            None
        }
    }
}

/// Capabilities bitfield (handshake doc §7)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const HLC_SUPPORTED: u32 = 1 << 0;
    pub const CHECKSUM_SUPPORTED: u32 = 1 << 1;
    pub const SIGNATURE_SUPPORTED: u32 = 1 << 2;
    pub const COMPRESSION_SUPPORTED: u32 = 1 << 3;
    pub const MULTI_STREAM_SUPPORTED: u32 = 1 << 4;

    pub fn new(bits: u32) -> Self {
        Capabilities(bits)
    }

    pub fn empty() -> Self {
        Capabilities(0)
    }

    pub fn has(self, bit: u32) -> bool {
        self.0 & bit != 0
    }

    pub fn intersection(self, other: Capabilities) -> Capabilities {
        Capabilities(self.0 & other.0)
    }

    pub fn to_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 4 {
            Some(Capabilities(u32::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ])))
        } else {
            None
        }
    }
}

/// RESULT codes (handshake doc §5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResultCode {
    Ok = 0x00,
    ErrorUnsupportedVersion = 0x01,
    ErrorUnsupportedSecurityMode = 0x02,
    ErrorCapabilityMismatch = 0x03,
    ErrorPolicy = 0x04,
    ErrorInternal = 0x05,
}

impl ResultCode {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(ResultCode::Ok),
            0x01 => Some(ResultCode::ErrorUnsupportedVersion),
            0x02 => Some(ResultCode::ErrorUnsupportedSecurityMode),
            0x03 => Some(ResultCode::ErrorCapabilityMismatch),
            0x04 => Some(ResultCode::ErrorPolicy),
            0x05 => Some(ResultCode::ErrorInternal),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn is_ok(self) -> bool {
        matches!(self, ResultCode::Ok)
    }
}

/// REASON_CODE values for CLOSE frames (handshake doc §8)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ReasonCode {
    Normal = 0x0000,
    ProtocolError = 0x0001,
    SecurityError = 0x0002,
    CapabilityError = 0x0003,
    VersionMismatch = 0x0004,
    InternalError = 0x0005,
}

impl ReasonCode {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(ReasonCode::Normal),
            0x0001 => Some(ReasonCode::ProtocolError),
            0x0002 => Some(ReasonCode::SecurityError),
            0x0003 => Some(ReasonCode::CapabilityError),
            0x0004 => Some(ReasonCode::VersionMismatch),
            0x0005 => Some(ReasonCode::InternalError),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn to_bytes(self) -> [u8; 2] {
        self.as_u16().to_be_bytes()
    }
}

/// Parsed HELLO fields (handshake doc §4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloFields {
    pub node_id: Vec<u8>,
    pub capabilities: Capabilities,
    pub security_mode: SecurityMode,
    pub pubkey: Option<Vec<u8>>, // 32 bytes if Signed mode
}

impl HelloFields {
    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self, &'static str> {
        let mut node_id = None;
        let mut capabilities = None;
        let mut security_mode = None;
        let mut pubkey = None;

        for tlv in tlvs {
            match tlv.t {
                tlv_types::NODE_ID => {
                    if tlv.value.len() < 8 || tlv.value.len() > 64 {
                        return Err("NODE_ID must be 8-64 bytes");
                    }
                    node_id = Some(tlv.value.clone());
                }
                tlv_types::CAPABILITIES => {
                    capabilities = Capabilities::from_bytes(&tlv.value);
                }
                tlv_types::SECURITY_MODE => {
                    if tlv.value.len() != 1 {
                        return Err("SECURITY_MODE must be 1 byte");
                    }
                    security_mode = SecurityMode::from_u8(tlv.value[0]);
                }
                tlv_types::PUBKEY => {
                    if tlv.value.len() != 32 {
                        return Err("PUBKEY must be 32 bytes (Ed25519)");
                    }
                    pubkey = Some(tlv.value.clone());
                }
                _ => {} // ignore unknown TLVs
            }
        }

        Ok(HelloFields {
            node_id: node_id.ok_or("NODE_ID required")?,
            capabilities: capabilities.ok_or("CAPABILITIES required")?,
            security_mode: security_mode.ok_or("SECURITY_MODE required")?,
            pubkey,
        })
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::new(tlv_types::NODE_ID, self.node_id.clone()),
            Tlv::new(tlv_types::CAPABILITIES, self.capabilities.to_bytes().to_vec()),
            Tlv::new(tlv_types::SECURITY_MODE, vec![self.security_mode.as_u8()]),
        ];

        if let Some(ref pubkey) = self.pubkey {
            tlvs.push(Tlv::new(tlv_types::PUBKEY, pubkey.clone()));
        }

        tlvs
    }
}

/// Parsed HELLO_ACK fields (handshake doc §5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAckFields {
    pub node_id: Vec<u8>,
    pub capabilities: Capabilities,
    pub security_mode: SecurityMode,
    pub result: ResultCode,
    pub pubkey: Option<Vec<u8>>,
}

impl HelloAckFields {
    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self, &'static str> {
        let mut node_id = None;
        let mut capabilities = None;
        let mut security_mode = None;
        let mut result = None;
        let mut pubkey = None;

        for tlv in tlvs {
            match tlv.t {
                tlv_types::NODE_ID => {
                    if tlv.value.len() < 8 || tlv.value.len() > 64 {
                        return Err("NODE_ID must be 8-64 bytes");
                    }
                    node_id = Some(tlv.value.clone());
                }
                tlv_types::CAPABILITIES => {
                    capabilities = Capabilities::from_bytes(&tlv.value);
                }
                tlv_types::SECURITY_MODE => {
                    if tlv.value.len() != 1 {
                        return Err("SECURITY_MODE must be 1 byte");
                    }
                    security_mode = SecurityMode::from_u8(tlv.value[0]);
                }
                tlv_types::RESULT => {
                    if tlv.value.len() != 1 {
                        return Err("RESULT must be 1 byte");
                    }
                    result = ResultCode::from_u8(tlv.value[0]);
                }
                tlv_types::PUBKEY => {
                    if tlv.value.len() != 32 {
                        return Err("PUBKEY must be 32 bytes (Ed25519)");
                    }
                    pubkey = Some(tlv.value.clone());
                }
                _ => {}
            }
        }

        Ok(HelloAckFields {
            node_id: node_id.ok_or("NODE_ID required")?,
            capabilities: capabilities.ok_or("CAPABILITIES required")?,
            security_mode: security_mode.ok_or("SECURITY_MODE required")?,
            result: result.ok_or("RESULT required")?,
            pubkey,
        })
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![
            Tlv::new(tlv_types::NODE_ID, self.node_id.clone()),
            Tlv::new(tlv_types::CAPABILITIES, self.capabilities.to_bytes().to_vec()),
            Tlv::new(tlv_types::SECURITY_MODE, vec![self.security_mode.as_u8()]),
            Tlv::new(tlv_types::RESULT, vec![self.result.as_u8()]),
        ];

        if let Some(ref pubkey) = self.pubkey {
            tlvs.push(Tlv::new(tlv_types::PUBKEY, pubkey.clone()));
        }

        tlvs
    }
}

/// Parsed CLOSE fields (handshake doc §8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFields {
    pub reason_code: ReasonCode,
    pub reason_text: Option<String>,
}

impl CloseFields {
    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self, &'static str> {
        let mut reason_code = None;
        let mut reason_text = None;

        for tlv in tlvs {
            match tlv.t {
                tlv_types::REASON_CODE => {
                    if tlv.value.len() != 2 {
                        return Err("REASON_CODE must be 2 bytes");
                    }
                    let code = u16::from_be_bytes([tlv.value[0], tlv.value[1]]);
                    reason_code = ReasonCode::from_u16(code);
                }
                tlv_types::REASON_TEXT => {
                    reason_text = String::from_utf8(tlv.value.clone()).ok();
                }
                _ => {}
            }
        }

        Ok(CloseFields {
            reason_code: reason_code.ok_or("REASON_CODE required")?,
            reason_text,
        })
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut tlvs = vec![Tlv::new(
            tlv_types::REASON_CODE,
            self.reason_code.to_bytes().to_vec(),
        )];

        if let Some(ref text) = self.reason_text {
            tlvs.push(Tlv::new(tlv_types::REASON_TEXT, text.as_bytes().to_vec()));
        }

        tlvs
    }
}

/// Parsed PING/PONG fields (spec §4.7)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingPongFields {
    pub nonce: Vec<u8>,
}

impl PingPongFields {
    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self, &'static str> {
        for tlv in tlvs {
            if tlv.t == tlv_types::NONCE {
                return Ok(PingPongFields {
                    nonce: tlv.value.clone(),
                });
            }
        }
        Err("NONCE required")
    }

    pub fn to_tlvs(&self) -> Vec<Tlv> {
        vec![Tlv::new(tlv_types::NONCE, self.nonce.clone())]
    }
}

/// Ergonomic Song constructors for control frames
impl Song {
    /// Construct a HELLO Song (handshake doc §4)
    pub fn hello(hlc: Hlc, fields: HelloFields) -> Self {
        let tlvs = fields.to_tlvs();
        Song {
            header: SongHeader::from_hlc(0, FrameType::Hello, Flags(0), 0, 0, hlc),
            payload: Payload::Tlv(tlvs),
            checksum: None,
            signature: None,
        }
    }

    /// Construct a HELLO_ACK Song (handshake doc §5)
    pub fn hello_ack(hlc: Hlc, fields: HelloAckFields) -> Self {
        let tlvs = fields.to_tlvs();
        Song {
            header: SongHeader::from_hlc(0, FrameType::HelloAck, Flags(0), 0, 0, hlc),
            payload: Payload::Tlv(tlvs),
            checksum: None,
            signature: None,
        }
    }

    /// Construct a CLOSE Song (handshake doc §8)
    pub fn close(hlc: Hlc, fields: CloseFields) -> Self {
        let tlvs = fields.to_tlvs();
        Song {
            header: SongHeader::from_hlc(0, FrameType::Close, Flags(0), 0, 0, hlc),
            payload: Payload::Tlv(tlvs),
            checksum: None,
            signature: None,
        }
    }

    /// Construct a PING Song (spec §4.7)
    pub fn ping(hlc: Hlc, nonce: Vec<u8>) -> Self {
        let fields = PingPongFields { nonce };
        let tlvs = fields.to_tlvs();
        Song {
            header: SongHeader::from_hlc(0, FrameType::Ping, Flags(0), 0, 0, hlc),
            payload: Payload::Tlv(tlvs),
            checksum: None,
            signature: None,
        }
    }

    /// Construct a PONG Song (spec §4.7)
    pub fn pong(hlc: Hlc, nonce: Vec<u8>) -> Self {
        let fields = PingPongFields { nonce };
        let tlvs = fields.to_tlvs();
        Song {
            header: SongHeader::from_hlc(0, FrameType::Pong, Flags(0), 0, 0, hlc),
            payload: Payload::Tlv(tlvs),
            checksum: None,
            signature: None,
        }
    }

    /// Construct a DATA Song (spec §4.4)
    pub fn data(hlc: Hlc, stream_id: u32, data: Vec<u8>, end_of_stream: bool) -> Self {
        let flags = if end_of_stream {
            Flags(Flags::END_OF_STREAM)
        } else {
            Flags(0)
        };

        Song {
            header: SongHeader::from_hlc(0, FrameType::Data, flags, 0, stream_id, hlc),
            payload: Payload::Raw(data),
            checksum: None,
            signature: None,
        }
    }

    /// Parse HELLO fields from a Song
    pub fn parse_hello(&self) -> Result<HelloFields, &'static str> {
        if self.header.frame_type != FrameType::Hello {
            return Err("Not a HELLO frame");
        }
        match &self.payload {
            Payload::Tlv(tlvs) => HelloFields::from_tlvs(tlvs),
            _ => Err("HELLO must have TLV payload"),
        }
    }

    /// Parse HELLO_ACK fields from a Song
    pub fn parse_hello_ack(&self) -> Result<HelloAckFields, &'static str> {
        if self.header.frame_type != FrameType::HelloAck {
            return Err("Not a HELLO_ACK frame");
        }
        match &self.payload {
            Payload::Tlv(tlvs) => HelloAckFields::from_tlvs(tlvs),
            _ => Err("HELLO_ACK must have TLV payload"),
        }
    }

    /// Parse CLOSE fields from a Song
    pub fn parse_close(&self) -> Result<CloseFields, &'static str> {
        if self.header.frame_type != FrameType::Close {
            return Err("Not a CLOSE frame");
        }
        match &self.payload {
            Payload::Tlv(tlvs) => CloseFields::from_tlvs(tlvs),
            _ => Err("CLOSE must have TLV payload"),
        }
    }
}
