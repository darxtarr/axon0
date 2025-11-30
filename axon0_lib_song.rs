use crate::frame::{Flags, SongHeader, AXON0_HEADER_LEN};
use crate::tlv;

use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

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
    /// Compute BLAKE3-128 checksum over header + payload
    pub fn compute_checksum(&self) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new();

        // Hash header
        let mut header = self.header;
        header.payload_len = match &self.payload {
            Payload::Raw(bytes) => bytes.len() as u32,
            Payload::Tlv(tlvs) => tlv::encode_tlvs(tlvs).len() as u32,
        };
        hasher.update(&header.encode());

        // Hash payload
        match &self.payload {
            Payload::Raw(bytes) => {
                hasher.update(bytes);
            }
            Payload::Tlv(tlvs) => {
                hasher.update(&tlv::encode_tlvs(tlvs));
            }
        }

        let hash = hasher.finalize();
        let mut checksum = [0u8; 16];
        checksum.copy_from_slice(&hash.as_bytes()[..16]);
        checksum
    }

    /// Add checksum to this Song (computes and sets checksum field + flag)
    pub fn with_checksum(mut self) -> Self {
        let checksum = self.compute_checksum();
        self.header.flags.0 |= Flags::CHECKSUM;
        self.checksum = Some(checksum);
        self
    }

    /// Verify checksum (returns false if checksum missing or invalid)
    pub fn verify_checksum(&self) -> bool {
        if let Some(stored_checksum) = self.checksum {
            // Temporarily remove checksum and signature to recompute
            let mut temp = self.clone();
            temp.checksum = None;
            temp.signature = None;
            temp.header.flags.0 &= !(Flags::CHECKSUM | Flags::SIGNATURE);

            let computed = temp.compute_checksum();
            computed == stored_checksum
        } else {
            false
        }
    }

    /// Sign this Song with given key (computes checksum first, then signs header+payload+checksum)
    pub fn sign(mut self, signing_key: &SigningKey) -> Self {
        // Ensure checksum is present
        if self.checksum.is_none() {
            self = self.with_checksum();
        }

        // Sign header + payload + checksum
        let mut to_sign = Vec::new();

        let mut header = self.header;
        header.payload_len = match &self.payload {
            Payload::Raw(bytes) => bytes.len() as u32,
            Payload::Tlv(tlvs) => tlv::encode_tlvs(tlvs).len() as u32,
        };
        to_sign.extend_from_slice(&header.encode());

        match &self.payload {
            Payload::Raw(bytes) => to_sign.extend_from_slice(bytes),
            Payload::Tlv(tlvs) => to_sign.extend_from_slice(&tlv::encode_tlvs(tlvs)),
        }

        if let Some(checksum) = self.checksum {
            to_sign.extend_from_slice(&checksum);
        }

        let signature: Signature = signing_key.sign(&to_sign);
        self.header.flags.0 |= Flags::SIGNATURE;
        self.signature = Some(signature.to_bytes());
        self
    }

    /// Verify signature (returns false if signature missing or invalid)
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> bool {
        if let Some(sig_bytes) = self.signature {
            // Reconstruct what was signed (without signature flag/data)
            let mut temp = self.clone();
            temp.signature = None;
            temp.header.flags.0 &= !Flags::SIGNATURE;

            let mut to_verify = Vec::new();

            let mut header = temp.header;
            header.payload_len = match &temp.payload {
                Payload::Raw(bytes) => bytes.len() as u32,
                Payload::Tlv(tlvs) => tlv::encode_tlvs(tlvs).len() as u32,
            };
            to_verify.extend_from_slice(&header.encode());

            match &temp.payload {
                Payload::Raw(bytes) => to_verify.extend_from_slice(bytes),
                Payload::Tlv(tlvs) => to_verify.extend_from_slice(&tlv::encode_tlvs(tlvs)),
            }

            if let Some(checksum) = temp.checksum {
                to_verify.extend_from_slice(&checksum);
            }

            // Verify signature
            let signature = Signature::from_bytes(&sig_bytes);
            verifying_key.verify(&to_verify, &signature).is_ok()
        } else {
            false
        }
    }

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
