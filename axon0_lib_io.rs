/// Thin I/O layer for AXON/0 connections
///
/// This module wraps Read + Write streams (typically TCP) and uses the pure
/// ConnState machine to handle handshakes and message exchange.
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::conn::{
    apply, initiate_close, initiate_handshake, ActiveState, ConnConfig, ConnState, Role,
    StateMachineError, Transition,
};
use crate::handshake::ReasonCode;
use crate::frame::{FrameType, AXON0_HEADER_LEN};
use crate::hlc::Hlc;
use crate::song::Song;

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
}

impl<T: Read + Write> AxonConn<T> {
    /// Create a new connection in Connecting state
    pub fn new(io: T, cfg: ConnConfig) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            io,
            state: ConnState::Connecting,
            cfg,
            hlc: Hlc::new(now_ms),
        }
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

    /// Read one complete Song from the stream
    fn read_song(&mut self) -> Result<Song, IoError> {
        // Read 32-byte header
        let mut header_buf = [0u8; AXON0_HEADER_LEN];
        self.io.read_exact(&mut header_buf)?;

        let header = crate::frame::SongHeader::decode(&header_buf)
            .map_err(|e| IoError::DecodeError(format!("Header decode failed: {:?}", e)))?;

        let payload_len = header.payload_len as usize;

        // Read payload
        let mut payload_buf = vec![0u8; payload_len];
        if payload_len > 0 {
            self.io.read_exact(&mut payload_buf)?;
        }

        // Read trailer based on flags
        let mut trailer_buf = Vec::new();

        if header.flags.has(crate::frame::Flags::CHECKSUM) {
            let mut checksum = [0u8; 16];
            self.io.read_exact(&mut checksum)?;
            trailer_buf.extend_from_slice(&checksum);
        }

        if header.flags.has(crate::frame::Flags::SIGNATURE) {
            let mut signature = [0u8; 64];
            self.io.read_exact(&mut signature)?;
            trailer_buf.extend_from_slice(&signature);
        }

        // Reconstruct full Song bytes and decode
        let mut full_bytes = Vec::with_capacity(AXON0_HEADER_LEN + payload_len + trailer_buf.len());
        full_bytes.extend_from_slice(&header_buf);
        full_bytes.extend_from_slice(&payload_buf);
        full_bytes.extend_from_slice(&trailer_buf);

        Song::decode(&full_bytes)
            .map_err(|e| IoError::DecodeError(format!("Song decode failed: {:?}", e)))
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
                    AxonEvent::HandshakeCompleted(active) => return Ok(active),
                    AxonEvent::Closed(reason, text) => {
                        return Err(IoError::HandshakeRejected(format!(
                            "Handshake failed: {:?} - {}",
                            reason,
                            text.unwrap_or_default()
                        )))
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

        loop {
            let song = self.read_song()?;
            self.update_time();

            let transition = apply(self.state.clone(), &self.cfg, &song, &mut self.hlc)?;

            if let Some(event) = self.process_transition(transition)? {
                match event {
                    AxonEvent::HandshakeCompleted(active) => return Ok(active),
                    AxonEvent::Closed(reason, text) => {
                        return Err(IoError::HandshakeRejected(format!(
                            "Handshake failed: {:?} - {}",
                            reason,
                            text.unwrap_or_default()
                        )))
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
