#[path = "axon0_lib_frame.rs"]
pub mod frame;
#[path = "axon0_lib_hlc.rs"]
pub mod hlc;
#[path = "axon0_lib_song.rs"]
pub mod song;
#[path = "axon0_lib_tlv.rs"]
pub mod tlv;

#[cfg(test)]
mod tests {
    use super::frame::*;
    use super::hlc::*;
    use super::song::*;
    use super::tlv::*;

    #[test]
    fn header_round_trip() {
        let hlc = Hlc {
            physical_ms: 1_735_000_000_000,
            logical: 7,
        };

        let header = SongHeader::from_hlc(
            0,
            FrameType::Data,
            Flags(Flags::CHECKSUM | Flags::END_OF_STREAM),
            1024,
            42,
            hlc,
        );

        let bytes = header.encode();
        let decoded = SongHeader::decode(&bytes).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(decoded.hlc(), hlc);
    }

    #[test]
    fn tlv_round_trip() {
        let tlvs = vec![
            Tlv::new(0x01, vec![1, 2, 3, 4]),
            Tlv::new(0x02, vec![]),
            Tlv::new(0x03, b"hello".to_vec()),
        ];

        let encoded = encode_tlvs(&tlvs);
        let decoded = decode_tlvs(&encoded).unwrap();
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn song_hello_round_trip() {
        // Build a HELLO message with NODE_ID and SECURITY_MODE TLVs
        let node_id = vec![0x42; 16]; // 16-byte node ID
        let security_mode = vec![0x00]; // Trusted-LAN

        let tlvs = vec![
            Tlv::new(0x01, node_id.clone()), // NODE_ID
            Tlv::new(0x03, security_mode),   // SECURITY_MODE
        ];

        let hlc = Hlc::new(1_735_000_000_000);

        let song = Song {
            header: SongHeader::from_hlc(0, FrameType::Hello, Flags(0), 0, 0, hlc),
            payload: Payload::Tlv(tlvs.clone()),
            checksum: None,
            signature: None,
        };

        let encoded = song.encode();
        let decoded = Song::decode(&encoded).unwrap();

        assert_eq!(decoded.header.frame_type, FrameType::Hello);
        assert_eq!(decoded.payload, Payload::Tlv(tlvs));
        assert_eq!(decoded.checksum, None);
        assert_eq!(decoded.signature, None);
    }

    #[test]
    fn song_with_checksum_and_signature() {
        let tlvs = vec![Tlv::new(0x01, vec![1, 2, 3])];

        let mut hlc = Hlc::new(1_735_000_000_000);
        hlc.tick_local(1_735_000_000_000);

        let song = Song {
            header: SongHeader::from_hlc(
                0,
                FrameType::HelloAck,
                Flags(Flags::CHECKSUM | Flags::SIGNATURE),
                0,
                0,
                hlc,
            ),
            payload: Payload::Tlv(tlvs.clone()),
            checksum: Some([0xAA; 16]),
            signature: Some([0xBB; 64]),
        };

        let encoded = song.encode();
        let decoded = Song::decode(&encoded).unwrap();

        assert_eq!(decoded.header.flags.0, Flags::CHECKSUM | Flags::SIGNATURE);
        assert_eq!(decoded.checksum, Some([0xAA; 16]));
        assert_eq!(decoded.signature, Some([0xBB; 64]));
    }

    #[test]
    fn song_data_frame() {
        let data = b"arbitrary application data".to_vec();

        let mut hlc = Hlc::new(1_735_000_000_000);
        for _ in 0..5 {
            hlc.tick_local(1_735_000_000_000);
        }

        let song = Song {
            header: SongHeader::from_hlc(
                0,
                FrameType::Data,
                Flags(Flags::END_OF_STREAM),
                0,
                42,
                hlc,
            ),
            payload: Payload::Raw(data.clone()),
            checksum: None,
            signature: None,
        };

        let encoded = song.encode();
        let decoded = Song::decode(&encoded).unwrap();

        assert_eq!(decoded.payload, Payload::Raw(data));
        assert_eq!(decoded.header.stream_id, 42);
        assert!(decoded.header.flags.has(Flags::END_OF_STREAM));
        assert_eq!(decoded.header.hlc().logical, 5); // verify HLC persisted
    }
}
