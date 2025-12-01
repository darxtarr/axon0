// File-based BellSink implementation
//
// Simple append-only Bell logger:
//   - Opens file (creates if needed)
//   - Writes magic header if new
//   - Appends Bell records as TLV blobs
//   - No rotation, no indexing, no async (v0 simplicity)
//
// Usage:
//   let sink = Arc::new(FileBellSink::open("axon0.bell")?);
//   node.emit_bell(Bell::new(...));

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

use crate::bell::{bell_file_header, Bell, BellSink};

/// File-based Bell sink (append-only binary log)
pub struct FileBellSink {
    file: Mutex<File>,
}

impl FileBellSink {
    /// Open or create a Bell log file
    ///
    /// If file is new (zero length), writes magic header.
    /// If file exists, assumes it already has valid header.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true) // need to check file length
            .open(path)?;

        // If file is empty, write magic header
        if file.metadata()?.len() == 0 {
            let header = bell_file_header();
            file.write_all(&header)?;
            file.flush()?;
        }

        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl BellSink for FileBellSink {
    fn emit(&self, bell: Bell) {
        // Best-effort logging in v0:
        // If lock fails or write fails, swallow error rather than panic.
        // This keeps observability issues from crashing the node.
        if let Ok(mut file) = self.file.lock() {
            let bytes = bell.encode();
            let _ = file.write_all(&bytes);
            // Skip flush() for perf; OS will batch writes
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bell::{Bell, BellKind, BellLevel};
    use crate::hlc::Hlc;
    use std::fs;
    use std::io::Read;

    #[test]
    fn file_bell_sink_creates_header() {
        let path = ".tmp/test_bells_header.bell";
        let _ = fs::remove_file(path); // clean slate

        let sink = FileBellSink::open(path).unwrap();
        drop(sink);

        // Check header exists
        let mut file = File::open(path).unwrap();
        let mut header = vec![0u8; 5];
        file.read_exact(&mut header).unwrap();

        assert_eq!(&header[0..4], b"BELL");
        assert_eq!(header[4], 0); // version 0

        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_bell_sink_appends_bells() {
        let path = ".tmp/test_bells_append.bell";
        let _ = fs::remove_file(path);

        let sink = FileBellSink::open(path).unwrap();

        // Emit a few bells
        let hlc = Hlc::new(1_735_000_000_000);
        sink.emit(Bell::new(hlc, BellLevel::Info, BellKind::ConnectionOpened));
        sink.emit(Bell::new(hlc, BellLevel::Debug, BellKind::SongSent).with_conn(42));
        sink.emit(Bell::new(hlc, BellLevel::Warn, BellKind::HandshakeFailed));

        sink.flush();
        drop(sink);

        // Read back and verify structure
        let mut file = File::open(path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        // Should have header + 3 TLV records
        assert!(contents.len() > 5); // header
        assert_eq!(&contents[0..4], b"BELL");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn file_bell_sink_reopens_existing() {
        let path = ".tmp/test_bells_reopen.bell";
        let _ = fs::remove_file(path);

        // First open: creates header
        let sink1 = FileBellSink::open(path).unwrap();
        let hlc = Hlc::new(1_735_000_000_000);
        sink1.emit(Bell::new(hlc, BellLevel::Info, BellKind::ConnectionOpened));
        sink1.flush();
        drop(sink1);

        let initial_size = fs::metadata(path).unwrap().len();

        // Second open: should not rewrite header
        let sink2 = FileBellSink::open(path).unwrap();
        sink2.emit(Bell::new(hlc, BellLevel::Debug, BellKind::SongReceived));
        sink2.flush();
        drop(sink2);

        let final_size = fs::metadata(path).unwrap().len();

        // Size should have grown (new bell), but header not duplicated
        assert!(final_size > initial_size);
        let expected_len = Bell::new(hlc, BellLevel::Debug, BellKind::SongReceived).encode().len() as u64;
        assert_eq!(final_size - initial_size, expected_len);

        let _ = fs::remove_file(path);
    }
}
