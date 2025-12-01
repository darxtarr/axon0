use std::convert::TryFrom;

use crate::hlc::Hlc;

pub const AXON0_HEADER_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Hello = 0x01,
    HelloAck = 0x02,
    Close = 0x03,
    Data = 0x10,
    Ack = 0x11,
    Nack = 0x12,
    Ping = 0x20,
    Pong = 0x21,
}

impl TryFrom<u8> for FrameType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, ()> {
        use FrameType::*;
        Ok(match value {
            0x01 => Hello,
            0x02 => HelloAck,
            0x03 => Close,
            0x10 => Data,
            0x11 => Ack,
            0x12 => Nack,
            0x20 => Ping,
            0x21 => Pong,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(pub u8);

impl Flags {
    pub const CHECKSUM: u8 = 0x01;
    pub const SIGNATURE: u8 = 0x02;
    pub const END_OF_STREAM: u8 = 0x04;
    pub const RESERVED_MASK: u8 = 0xF8; // bits 3-7 must be 0

    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Check if reserved bits are all zero (as required by spec §3)
    pub fn reserved_bits_valid(self) -> bool {
        self.0 & Self::RESERVED_MASK == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SongHeader {
    pub ver: u8,
    pub frame_type: FrameType,
    pub flags: Flags,
    pub payload_len: u32,
    pub hlc_physical_ms: u64,
    pub hlc_logical: u32,
    pub stream_id: u32,
}

impl SongHeader {
    /// Construct a SongHeader from an HLC and other fields
    pub fn from_hlc(
        ver: u8,
        frame_type: FrameType,
        flags: Flags,
        payload_len: u32,
        stream_id: u32,
        hlc: Hlc,
    ) -> Self {
        Self {
            ver,
            frame_type,
            flags,
            payload_len,
            hlc_physical_ms: hlc.physical_ms,
            hlc_logical: hlc.logical,
            stream_id,
        }
    }

    /// Extract HLC from this header
    pub fn hlc(&self) -> Hlc {
        Hlc {
            physical_ms: self.hlc_physical_ms,
            logical: self.hlc_logical,
        }
    }

    pub fn encode(&self) -> [u8; AXON0_HEADER_LEN] {
        let mut buf = [0u8; AXON0_HEADER_LEN];

        buf[0] = self.ver;
        buf[1] = self.frame_type as u8;
        buf[2] = self.flags.0;
        buf[3] = 0; // rsvd0

        buf[4..8].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[8..16].copy_from_slice(&self.hlc_physical_ms.to_be_bytes());
        buf[16..20].copy_from_slice(&self.hlc_logical.to_be_bytes());
        buf[20..24].copy_from_slice(&self.stream_id.to_be_bytes());
        // rsvd1 = 0
        // buf[24..28] stays zero
        // buf[28..32] stays zero

        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < AXON0_HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        let ver = bytes[0];
        let frame_type = FrameType::try_from(bytes[1])
            .map_err(|_| DecodeError::UnknownFrameType(bytes[1]))?;
        let flags = Flags(bytes[2]);

        let payload_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let hlc_physical_ms = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let hlc_logical = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        let stream_id = u32::from_be_bytes(bytes[20..24].try_into().unwrap());

        Ok(SongHeader {
            ver,
            frame_type,
            flags,
            payload_len,
            hlc_physical_ms,
            hlc_logical,
            stream_id,
        })
    }
}

#[derive(Debug)]
pub enum DecodeError {
    TooShort,
    UnknownFrameType(u8),
}
