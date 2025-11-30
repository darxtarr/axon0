use crate::frame::{Flags, SongHeader, AXON0_HEADER_LEN};
use crate::tlv;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Raw(Vec<u8>),       // DATA frames
    Tlv(Vec<tlv::Tlv>), // control frames
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Song {
    pub header: SongHeader,
    pub payload: Payload,
    pub checksum: Option<[u8; 16]>,
    pub signature: Option<[u8; 64]>,
}

impl Song {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(AXON0_HEADER_LEN + self.header.payload_len as usize + 80);

        // header
        let mut header = self.header;
        header.payload_len = match &self.payload {
            Payload::Raw(bytes) => bytes.len() as u32,
            Payload::Tlv(tlvs) => tlv::encode_tlvs(tlvs).len() as u32,
        };
        buf.extend_from_slice(&header.encode());

        // payload
        match &self.payload {
            Payload::Raw(bytes) => buf.extend_from_slice(bytes),
            Payload::Tlv(tlvs) => buf.extend_from_slice(&tlv::encode_tlvs(tlvs)),
        }

        // trailer
        if let Some(checksum) = self.checksum {
            buf.extend_from_slice(&checksum);
        }
        if let Some(signature) = self.signature {
            buf.extend_from_slice(&signature);
        }

        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SongDecodeError> {
        if bytes.len() < AXON0_HEADER_LEN {
            return Err(SongDecodeError::TooShort);
        }

        let header =
            SongHeader::decode(&bytes[..AXON0_HEADER_LEN]).map_err(SongDecodeError::Header)?;

        let mut offset = AXON0_HEADER_LEN;
        let payload_len = header.payload_len as usize;

        if bytes.len() < offset + payload_len {
            return Err(SongDecodeError::TooShort);
        }

        let payload_bytes = &bytes[offset..offset + payload_len];
        offset += payload_len;

        let payload = match header.frame_type {
            // DATA is opaque
            crate::frame::FrameType::Data => Payload::Raw(payload_bytes.to_vec()),
            // everything else is TLV for now
            _ => {
                let tlvs = tlv::decode_tlvs(payload_bytes).map_err(SongDecodeError::Tlv)?;
                Payload::Tlv(tlvs)
            }
        };

        let mut checksum = None;
        let mut signature = None;

        if header.flags.has(Flags::CHECKSUM) {
            if bytes.len() < offset + 16 {
                return Err(SongDecodeError::TooShort);
            }
            let mut c = [0u8; 16];
            c.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
            checksum = Some(c);
        }

        if header.flags.has(Flags::SIGNATURE) {
            if bytes.len() < offset + 64 {
                return Err(SongDecodeError::TooShort);
            }
            let mut s = [0u8; 64];
            s.copy_from_slice(&bytes[offset..offset + 64]);
            #[allow(unused_assignments)]
            {
                offset += 64;
            }
            signature = Some(s);
        }

        Ok(Song {
            header,
            payload,
            checksum,
            signature,
        })
    }
}

#[derive(Debug)]
pub enum SongDecodeError {
    TooShort,
    Header(crate::frame::DecodeError),
    Tlv(tlv::DecodeError),
}
