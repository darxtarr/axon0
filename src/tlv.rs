#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub t: u8,
    pub len: u16,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new<T: Into<Vec<u8>>>(t: u8, value: T) -> Self {
        let value = value.into();
        let len = value.len() as u16;
        Self { t, len, value }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.t);
        buf.extend_from_slice(&self.len.to_be_bytes());
        buf.extend_from_slice(&self.value);
    }
}

pub fn encode_tlvs(tlvs: &[Tlv]) -> Vec<u8> {
    let mut buf = Vec::new();
    for tlv in tlvs {
        tlv.encode(&mut buf);
    }
    buf
}

#[derive(Debug)]
pub enum DecodeError {
    Truncated,
}

pub fn decode_tlvs(mut bytes: &[u8]) -> Result<Vec<Tlv>, DecodeError> {
    let mut out = Vec::new();

    while !bytes.is_empty() {
        if bytes.len() < 3 {
            return Err(DecodeError::Truncated);
        }

        let t = bytes[0];
        let len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        bytes = &bytes[3..];

        if bytes.len() < len {
            return Err(DecodeError::Truncated);
        }

        let value = bytes[..len].to_vec();
        bytes = &bytes[len..];

        out.push(Tlv {
            t,
            len: len as u16,
            value,
        });
    }

    Ok(out)
}
