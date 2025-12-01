/// Thin I/O layer for AXON/0 connections
///
/// This module wraps Read + Write streams (typically TCP) and uses the pure
/// ConnState machine to handle handshakes and message exchange.
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bell::{Bell, BellDetails, BellKind, BellLevel, BellSink};
use crate::conn::{
    apply, initiate_close, initiate_handshake, ActiveState, ConnConfig, ConnState, Role,
    StateMachineError, Transition,
};
use crate::handshake::ReasonCode;
use crate::frame::{FrameType, AXON0_HEADER_LEN};
use crate::hlc::Hlc;
use crate::song::Song;

/// Type alias for node identifiers (16-byte IDs)
pub type NodeId = Vec<u8>;

/// Type alias for pluggable Bell sinks
pub type BellSinkObj = Arc<dyn BellSink + Send + Sync>;

/// Connection ID for Bell correlation
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConnId(u64);

impl ConnId {
    pub fn next() -> Self {
        static CONN_ID_GEN: AtomicU64 = AtomicU64::new(1);
        Self(CONN_ID_GEN.fetch_add(1, Ordering::Relaxed))
    }

    pub fn get(&self) -> u64 {
        self.0
    }
}

/// High-level events emitted by AxonConn
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxonEvent {
    /// Handshake completed successfully
    HandshakeCompleted(ActiveState),

    /// DATA frame received
    DataReceived {
        stream_id: u32,
        data: Vec<u8>,
        end_of_stream: bool,
    },

    /// PING received
    PingReceived { nonce: Vec<u8> },

    /// PONG received
    PongReceived { nonce: Vec<u8> },

    /// Connection closed (gracefully or with error)
    Closed(ReasonCode, Option<String>),
}

/// I/O errors
#[derive(Debug)]
pub enum IoError {
    /// Underlying I/O error (connection died, etc.)
    Io(std::io::Error),

    /// Protocol error from state machine
    Protocol(StateMachineError),

    /// Failed to decode Song
    DecodeError(String),

    /// Connection is in wrong state for this operation
    InvalidState(String),

    /// Handshake was rejected by remote
    HandshakeRejected(String),
}

impl From<std::io::Error> for IoError {
    fn from(e: std::io::Error) -> Self {
        IoError::Io(e)
    }
}

impl From<StateMachineError> for IoError {
    fn from(e: StateMachineError) -> Self {
        IoError::Protocol(e)
    }
}

/// AXON/0 connection wrapper over a Read + Write stream
pub struct AxonConn<T> {
    io: T,
    state: ConnState,
    cfg: ConnConfig,
    hlc: Hlc,

    // Bell instrumentation fields
    conn_id: ConnId,
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<NodeId>,
    bell_sink: Option<BellSinkObj>,
    next_song_seq: u64,
}

impl<T: Read + Write> AxonConn<T> {
    /// Create a new connection in Connecting state
    pub fn new(io: T, cfg: ConnConfig) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let conn_id = ConnId::next();

        let mut conn = Self {
            io,
            state: ConnState::Connecting,
            cfg,
            hlc: Hlc::new(now_ms),
            conn_id,
            local_addr: None,
            peer_addr: None,
            peer_node_id: None,
            bell_sink: None,
            next_song_seq: 0,
        };

        // Emit ConnectionOpened
        conn.emit_bell(BellLevel::Info, BellKind::ConnectionOpened, None, BellDetails::None);

        conn
    }

    /// Attach a Bell sink (builder pattern)
    pub fn with_bell_sink(mut self, sink: BellSinkObj) -> Self {
        self.bell_sink = Some(sink);
        self
    }

    /// Set connection addresses (builder pattern)
    pub fn with_addrs(mut self, local: SocketAddr, peer: SocketAddr) -> Self {
        self.local_addr = Some(local);
        self.peer_addr = Some(peer);
        self
    }

    /// Set connection addresses from Options (builder pattern)
    pub fn with_addrs_opt(mut self, local: Option<SocketAddr>, peer: Option<SocketAddr>) -> Self {
        self.local_addr = local;
        self.peer_addr = peer;
        self
    }

    /// Get current connection state
    pub fn state(&self) -> &ConnState {
        &self.state
    }

    /// Get current HLC
    pub fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// Update physical time (call periodically to keep HLC accurate)
    fn update_time(&mut self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.hlc.tick_local(now_ms);
    }

    /// Emit a Bell event (internal helper)
    fn emit_bell(
        &mut self,
        level: BellLevel,
        kind: BellKind,
        song_id: Option<u64>,
        details: BellDetails,
    ) {
        if let Some(sink) = self.bell_sink.clone() {
            self.update_time(); // Advance HLC for Bell
            let bell = Bell {
                time: self.hlc,
                level,
                kind,
                conn_id: Some(self.conn_id.get()),
                song_id,
                details,
            };
            sink.emit(bell);
        }
    }

    /// Handle connection close (emit Bell, update state)
    fn on_closed(&mut self) {
        if !matches!(self.state, ConnState::Closed(_, _)) {
            self.state = ConnState::Closed(ReasonCode::Normal, None);
            self.emit_bell(BellLevel::Info, BellKind::ConnectionClosed, None, BellDetails::None);
        }
    }

    /// Read one complete Song from the stream
    fn read_song(&mut self) -> Result<Song, IoError> {
        // Read 32-byte header
        let mut header_buf = [0u8; AXON0_HEADER_LEN];
        if let Err(e) = self.io.read_exact(&mut header_buf) {
            // I/O error - connection died
            self.emit_bell(
                BellLevel::Error,
                BellKind::ConnectionError,
                None,
                BellDetails::Error {
                    code: 0,
                    message: format!("I/O error reading header: {}", e),
                },
            );
            self.on_closed();
            return Err(IoError::Io(e));
        }

        let header = match crate::frame::SongHeader::decode(&header_buf) {
            Ok(h) => h,
            Err(e) => {
                // Parse error
                self.emit_bell(
                    BellLevel::Warn,
                    BellKind::FrameParseError,
                    None,
                    BellDetails::Error {
                        code: 1,
                        message: format!("Header decode failed: {:?}", e),
                    },
                );
                return Err(IoError::DecodeError(format!("Header decode failed: {:?}", e)));
            }
        };

        let payload_len = header.payload_len as usize;

        // Read payload
        let mut payload_buf = vec![0u8; payload_len];
        if payload_len > 0 {
            if let Err(e) = self.io.read_exact(&mut payload_buf) {
                self.emit_bell(
                    BellLevel::Error,
                    BellKind::ConnectionError,
                    None,
                    BellDetails::Error {
                        code: 0,
                        message: format!("I/O error reading payload: {}", e),
                    },
                );
                self.on_closed();
                return Err(IoError::Io(e));
            }
        }

        // Read trailer based on flags
        let mut trailer_buf = Vec::new();

        if header.flags.has(crate::frame::Flags::CHECKSUM) {
            let mut checksum = [0u8; 16];
            if let Err(e) = self.io.read_exact(&mut checksum) {
                self.emit_bell(
                    BellLevel::Error,
                    BellKind::ConnectionError,
                    None,
                    BellDetails::Error {
                        code: 0,
                        message: format!("I/O error reading checksum: {}", e),
                    },
                );
                self.on_closed();
                return Err(IoError::Io(e));
            }
            trailer_buf.extend_from_slice(&checksum);
        }

        if header.flags.has(crate::frame::Flags::SIGNATURE) {
            let mut signature = [0u8; 64];
            if let Err(e) = self.io.read_exact(&mut signature) {
                self.emit_bell(
                    BellLevel::Error,
                    BellKind::ConnectionError,
                    None,
                    BellDetails::Error {
                        code: 0,
                        message: format!("I/O error reading signature: {}", e),
                    },
                );
                self.on_closed();
                return Err(IoError::Io(e));
            }
            trailer_buf.extend_from_slice(&signature);
        }

        // Reconstruct full Song bytes and decode
        let mut full_bytes = Vec::with_capacity(AXON0_HEADER_LEN + payload_len + trailer_buf.len());
        full_bytes.extend_from_slice(&header_buf);
        full_bytes.extend_from_slice(&payload_buf);
        full_bytes.extend_from_slice(&trailer_buf);

        let song = match Song::decode(&full_bytes) {
            Ok(s) => s,
            Err(e) => {
                self.emit_bell(
                    BellLevel::Warn,
                    BellKind::FrameParseError,
                    None,
                    BellDetails::Error {
                        code: 2,
                        message: format!("Song decode failed: {:?}", e),
                    },
                );
                return Err(IoError::DecodeError(format!("Song decode failed: {:?}", e)));
            }
        };

        // Emit SongReceived
        let song_seq = self.next_song_seq;
        self.next_song_seq += 1;
        self.emit_bell(
            BellLevel::Debug,
            BellKind::SongReceived,
            Some(song_seq),
            BellDetails::SongMeta {
                frame_type: song.header.frame_type as u8,
                stream_id: song.header.stream_id as u64,
                payload_len: song.header.payload_len,
            },
        );

        Ok(song)
    }

    /// Write one Song to the stream
    fn write_song(&mut self, song: &Song) -> Result<(), IoError> {
        let bytes = song.encode();
        self.io.write_all(&bytes)?;
        self.io.flush()?;
        Ok(())
    }

    /// Process a transition from the state machine
    fn process_transition(&mut self, transition: Transition) -> Result<Option<AxonEvent>, IoError> {
        let old_state = std::mem::replace(&mut self.state, transition.new_state.clone());

        // Send any outgoing Songs
        for song in &transition.outgoing {
            self.write_song(song)?;
        }

        // Generate events based on state transitions
        match (&old_state, &transition.new_state) {
            (ConnState::Handshaking(_), ConnState::Active(active)) => {
                Ok(Some(AxonEvent::HandshakeCompleted(active.clone())))
            }
            (ConnState::Connecting, ConnState::Active(active)) => {
                Ok(Some(AxonEvent::HandshakeCompleted(active.clone())))
            }
            (_, ConnState::Closed(reason, text)) => {
                Ok(Some(AxonEvent::Closed(*reason, text.clone())))
            }
            _ => Ok(None),
        }
    }

    /// Initiator: send HELLO and complete handshake
    pub fn initiate_handshake(&mut self) -> Result<ActiveState, IoError> {
        if self.cfg.role != Role::Initiator {
            return Err(IoError::InvalidState(
                "Must be Initiator role to initiate handshake".to_string(),
            ));
        }

        // Emit HandshakeStarted
        self.emit_bell(BellLevel::Debug, BellKind::HandshakeStarted, None, BellDetails::None);

        self.update_time();

        // Send HELLO
        let transition = initiate_handshake(&self.cfg, &mut self.hlc);
        self.process_transition(transition)?;

        // Wait for HELLO_ACK
        loop {
            let song = self.read_song()?;
            self.update_time();

            let transition = apply(self.state.clone(), &self.cfg, &song, &mut self.hlc)?;

            if let Some(event) = self.process_transition(transition)? {
                match event {
                    AxonEvent::HandshakeCompleted(active) => {
                        // Emit HandshakeCompleted
                        self.peer_node_id = Some(active.remote_node_id.clone());
                        self.emit_bell(
                            BellLevel::Info,
                            BellKind::HandshakeCompleted,
                            None,
                            BellDetails::HandshakeResult {
                                security_mode: active.security_mode as u8,
                                peer_id: Some(active.remote_node_id.clone()),
                                success: true,
                                reason: None,
                            },
                        );
                        return Ok(active);
                    }
                    AxonEvent::Closed(reason, text) => {
                        // Emit HandshakeFailed
                        self.emit_bell(
                            BellLevel::Warn,
                            BellKind::HandshakeFailed,
                            None,
                            BellDetails::Error {
                                code: reason as u32,
                                message: text.clone().unwrap_or_default(),
                            },
                        );
                        return Err(IoError::HandshakeRejected(format!(
                            "Handshake failed: {:?} - {}",
                            reason,
                            text.unwrap_or_default()
                        )));
                    }
                    _ => {} // Continue waiting
                }
            }
        }
    }

    /// Acceptor: wait for HELLO and complete handshake
    pub fn accept_handshake(&mut self) -> Result<ActiveState, IoError> {
        if self.cfg.role != Role::Acceptor {
            return Err(IoError::InvalidState(
                "Must be Acceptor role to accept handshake".to_string(),
            ));
        }

        // Emit HandshakeStarted
        self.emit_bell(BellLevel::Debug, BellKind::HandshakeStarted, None, BellDetails::None);

        loop {
            let song = self.read_song()?;
            self.update_time();

            let transition = apply(self.state.clone(), &self.cfg, &song, &mut self.hlc)?;

            if let Some(event) = self.process_transition(transition)? {
                match event {
                    AxonEvent::HandshakeCompleted(active) => {
                        // Emit HandshakeCompleted
                        self.peer_node_id = Some(active.remote_node_id.clone());
                        self.emit_bell(
                            BellLevel::Info,
                            BellKind::HandshakeCompleted,
                            None,
                            BellDetails::HandshakeResult {
                                security_mode: active.security_mode as u8,
                                peer_id: Some(active.remote_node_id.clone()),
                                success: true,
                                reason: None,
                            },
                        );
                        return Ok(active);
                    }
                    AxonEvent::Closed(reason, text) => {
                        // Emit HandshakeFailed
                        self.emit_bell(
                            BellLevel::Warn,
                            BellKind::HandshakeFailed,
                            None,
                            BellDetails::Error {
                                code: reason as u32,
                                message: text.clone().unwrap_or_default(),
                            },
                        );
                        return Err(IoError::HandshakeRejected(format!(
                            "Handshake failed: {:?} - {}",
                            reason,
                            text.unwrap_or_default()
                        )));
                    }
                    _ => {} // Continue waiting
                }
            }
        }
    }

    /// Send a DATA Song
    pub fn send_data(
        &mut self,
        stream_id: u32,
        data: Vec<u8>,
        end_of_stream: bool,
    ) -> Result<(), IoError> {
        if !matches!(self.state, ConnState::Active(_)) {
            return Err(IoError::InvalidState(
                "Connection must be Active to send data".to_string(),
            ));
        }

        self.update_time();
        let song = Song::data(self.hlc, stream_id, data, end_of_stream);

        // Apply security mode if Active
        let song = if let ConnState::Active(ref active) = self.state {
            match active.security_mode {
                crate::handshake::SecurityMode::TrustedLan => song,
                crate::handshake::SecurityMode::Checksummed => song.with_checksum(),
                crate::handshake::SecurityMode::Signed => {
                    // For now, just add checksum. Full signing requires key management
                    song.with_checksum()
                }
            }
        } else {
            song
        };

        let song_seq = self.next_song_seq;
        self.next_song_seq += 1;

        // Emit SongSent
        self.emit_bell(
            BellLevel::Debug,
            BellKind::SongSent,
            Some(song_seq),
            BellDetails::SongMeta {
                frame_type: song.header.frame_type as u8,
                stream_id: song.header.stream_id as u64,
                payload_len: song.header.payload_len,
            },
        );

        self.write_song(&song)?;
        Ok(())
    }

    /// Send a PING
    pub fn send_ping(&mut self, nonce: Vec<u8>) -> Result<(), IoError> {
        if !matches!(self.state, ConnState::Active(_)) {
            return Err(IoError::InvalidState(
                "Connection must be Active to send ping".to_string(),
            ));
        }

        self.update_time();
        let song = Song::ping(self.hlc, nonce);
        self.write_song(&song)?;
        Ok(())
    }

    /// Send a PONG
    pub fn send_pong(&mut self, nonce: Vec<u8>) -> Result<(), IoError> {
        if !matches!(self.state, ConnState::Active(_)) {
            return Err(IoError::InvalidState(
                "Connection must be Active to send pong".to_string(),
            ));
        }

        self.update_time();
        let song = Song::pong(self.hlc, nonce);
        self.write_song(&song)?;
        Ok(())
    }

    /// Initiate graceful close
    pub fn close(&mut self, reason: ReasonCode, text: Option<String>) -> Result<(), IoError> {
        self.update_time();
        let transition = initiate_close(reason, text, &mut self.hlc);
        self.process_transition(transition)?;
        self.on_closed();
        Ok(())
    }

    /// Poll once: read one Song, process it, return any events
    pub fn poll_once(&mut self) -> Result<Option<AxonEvent>, IoError> {
        let song = self.read_song()?;
        self.update_time();

        // Handle specific frame types before state machine
        let event = match song.header.frame_type {
            FrameType::Data => {
                if let crate::song::Payload::Raw(data) = &song.payload {
                    Some(AxonEvent::DataReceived {
                        stream_id: song.header.stream_id,
                        data: data.clone(),
                        end_of_stream: song
                            .header
                            .flags
                            .has(crate::frame::Flags::END_OF_STREAM),
                    })
                } else {
                    None
                }
            }
            FrameType::Ping => {
                if let Ok(_fields) = song.parse_hello() {
                    // Parse as generic TLV
                    if let crate::song::Payload::Tlv(tlvs) = &song.payload {
                        // Extract NONCE TLV
                        let nonce = tlvs
                            .iter()
                            .find(|tlv| tlv.t == crate::handshake::tlv_types::NONCE)
                            .map(|tlv| tlv.value.clone())
                            .unwrap_or_default();

                        // Auto-respond with PONG
                        self.send_pong(nonce.clone())?;
                        Some(AxonEvent::PingReceived { nonce })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            FrameType::Pong => {
                if let crate::song::Payload::Tlv(tlvs) = &song.payload {
                    let nonce = tlvs
                        .iter()
                        .find(|tlv| tlv.t == crate::handshake::tlv_types::NONCE)
                        .map(|tlv| tlv.value.clone())
                        .unwrap_or_default();
                    Some(AxonEvent::PongReceived { nonce })
                } else {
                    None
                }
            }
            _ => {
                // Let state machine handle control frames
                let transition = apply(self.state.clone(), &self.cfg, &song, &mut self.hlc)?;
                self.process_transition(transition)?
            }
        };

        Ok(event)
    }
}
