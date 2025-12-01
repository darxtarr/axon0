// Generate sample Bell log for testing
use axon0::bell::{Bell, BellDetails, BellKind, BellLevel, BellSink};
use axon0::bell_file::FileBellSink;
use axon0::hlc::Hlc;

fn main() {
    let sink = FileBellSink::open(".tmp/demo.bell").unwrap();

    let mut hlc = Hlc::new(1733011200000); // 2024-12-01 00:00:00

    // Simulate connection lifecycle
    sink.emit(
        Bell::new(hlc, BellLevel::Info, BellKind::ConnectionOpened)
            .with_conn(1)
            .with_details(BellDetails::ConnectionInfo {
                remote_addr: "192.168.1.42:7777".to_string(),
                local_addr: "192.168.1.10:55123".to_string(),
            }),
    );

    hlc.tick_local(hlc.physical_ms + 10);

    sink.emit(Bell::new(hlc, BellLevel::Debug, BellKind::HandshakeStarted).with_conn(1));

    hlc.tick_local(hlc.physical_ms + 25);

    sink.emit(
        Bell::new(hlc, BellLevel::Info, BellKind::HandshakeCompleted)
            .with_conn(1)
            .with_details(BellDetails::HandshakeResult {
                security_mode: 0,
                peer_id: Some(vec![0x42; 16]),
                success: true,
                reason: Some("Trusted-LAN".to_string()),
            }),
    );

    hlc.tick_local(hlc.physical_ms + 100);

    sink.emit(
        Bell::new(hlc, BellLevel::Debug, BellKind::SongSent)
            .with_conn(1)
            .with_song(17)
            .with_details(BellDetails::SongMeta {
                frame_type: 0,
                stream_id: 0,
                payload_len: 1024,
            }),
    );

    hlc.tick_local(hlc.physical_ms + 5);

    sink.emit(Bell::new(hlc, BellLevel::Debug, BellKind::SongReceived).with_conn(1).with_song(18));

    hlc.tick_local(hlc.physical_ms + 1000);

    sink.emit(
        Bell::new(hlc, BellLevel::Warn, BellKind::HandshakeFailed)
            .with_conn(2)
            .with_details(BellDetails::Error {
                code: 401,
                message: "Signature verification failed".to_string(),
            }),
    );

    hlc.tick_local(hlc.physical_ms + 50);

    sink.emit(
        Bell::new(hlc, BellLevel::Error, BellKind::ErrorRaised)
            .with_conn(2)
            .with_details(BellDetails::Error {
                code: 500,
                message: "Connection timeout".to_string(),
            }),
    );

    sink.flush();
    println!("Generated .tmp/demo.bell with 7 Bells");
}
