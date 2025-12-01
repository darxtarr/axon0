/// Connection state machine for AXON/0 handshake (handshake doc §9)
///
/// This module implements a pure, in-memory state machine for the AXON/0 handshake
/// without touching sockets or I/O. The core transition function is:
///
///   apply(state, incoming_song) -> (new_state, outgoing_songs)
///
/// This allows exhaustive testing of all handshake scenarios before integrating
/// with actual network code.
use crate::frame::FrameType;
use crate::handshake::{
    Capabilities, CloseFields, HelloAckFields, HelloFields, ReasonCode, ResultCode, SecurityMode,
};
use crate::hlc::Hlc;
use crate::song::Song;

/// Connection role (handshake doc §1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator - actively opens the connection (typically "client")
    Initiator,
    /// Acceptor - passively accepts connections (typically "server")
    Acceptor,
}

/// Security policy for mode selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// Supported security modes (must be non-empty)
    pub supported_modes: Vec<SecurityMode>,
    /// If true, prefer the strongest mode available in the intersection
    pub prefer_strongest: bool,
    /// If true, allow explicit downgrade requests from initiator
    pub allow_downgrade: bool,
}

impl SecurityPolicy {
    /// Default policy: support all modes, prefer strongest, allow downgrade
    pub fn permissive() -> Self {
        SecurityPolicy {
            supported_modes: vec![
                SecurityMode::TrustedLan,
                SecurityMode::Checksummed,
                SecurityMode::Signed,
            ],
            prefer_strongest: true,
            allow_downgrade: true,
        }
    }

    /// Strict policy: prefer strongest, no downgrade
    pub fn strict(supported: Vec<SecurityMode>) -> Self {
        SecurityPolicy {
            supported_modes: supported,
            prefer_strongest: true,
            allow_downgrade: false,
        }
    }

    /// Select a security mode given requested mode from initiator
    /// Returns (selected_mode, result_code)
    pub fn select_mode(
        &self,
        requested: SecurityMode,
    ) -> Result<SecurityMode, (SecurityMode, ResultCode)> {
        // Check if requested mode is supported
        if !self.supported_modes.contains(&requested) {
            // Return error with placeholder mode
            return Err((
                SecurityMode::TrustedLan,
                ResultCode::ErrorUnsupportedSecurityMode,
            ));
        }

        // If allow_downgrade, use requested mode
        // If prefer_strongest, use strongest available
        if self.allow_downgrade {
            Ok(requested)
        } else if self.prefer_strongest {
            // Use strongest mode we support
            Ok(SecurityMode::most_secure(&self.supported_modes)
                .unwrap_or(SecurityMode::TrustedLan))
        } else {
            Ok(requested)
        }
    }
}

/// Connection configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnConfig {
    pub role: Role,
    pub node_id: Vec<u8>,
    pub capabilities: Capabilities,
    pub security_policy: SecurityPolicy,
    pub ed25519_pubkey: Option<Vec<u8>>, // Required if Signed mode is supported
}

/// Handshake-specific state (Handshaking phase)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeState {
    pub hello_sent: bool,
    pub hello_received: Option<HelloFields>,
}

/// Active connection state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveState {
    pub remote_node_id: Vec<u8>,
    pub security_mode: SecurityMode,
    pub capabilities: Capabilities,
    pub remote_pubkey: Option<Vec<u8>>,
}

/// Connection state (handshake doc §9)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    /// Initial state - no connection yet
    Idle,

    /// TCP/stream connection in progress (not yet handshaking)
    Connecting,

    /// Handshake in progress
    Handshaking(HandshakeState),

    /// Active connection - handshake succeeded
    Active(ActiveState),

    /// Connection closed
    Closed(ReasonCode, Option<String>),
}

/// Transition result from state machine
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub new_state: ConnState,
    pub outgoing: Vec<Song>,
}

impl Transition {
    fn new(state: ConnState) -> Self {
        Transition {
            new_state: state,
            outgoing: Vec::new(),
        }
    }

    fn with_song(state: ConnState, song: Song) -> Self {
        Transition {
            new_state: state,
            outgoing: vec![song],
        }
    }
}

/// State machine errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateMachineError {
    /// Received unexpected frame type for current state
    UnexpectedFrameType(FrameType),
    /// Invalid message format or TLV parsing failed
    InvalidMessage(&'static str),
    /// Protocol version mismatch
    VersionMismatch(u8),
    /// Reserved bits not zero
    InvalidFlags,
}

/// Apply an incoming Song to the current state, producing a new state and any outgoing Songs
///
/// This is a pure function with no side effects - perfect for unit testing.
pub fn apply(
    state: ConnState,
    config: &ConnConfig,
    incoming: &Song,
    hlc: &mut Hlc,
) -> Result<Transition, StateMachineError> {
    // Validate version
    if incoming.header.ver != 0 {
        return Err(StateMachineError::VersionMismatch(incoming.header.ver));
    }

    // Validate reserved flags bits
    if !incoming.header.flags.reserved_bits_valid() {
        return Err(StateMachineError::InvalidFlags);
    }

    // Update HLC on receive
    let incoming_hlc = incoming.header.hlc();
    hlc.tick_receive(hlc.physical_ms, incoming_hlc);

    match state {
        ConnState::Idle => {
            // Idle state shouldn't receive messages - must move to Connecting first
            Err(StateMachineError::UnexpectedFrameType(
                incoming.header.frame_type,
            ))
        }

        ConnState::Connecting => {
            // In connecting state, only acceptor should receive HELLO
            if config.role == Role::Acceptor && incoming.header.frame_type == FrameType::Hello {
                handle_hello_as_acceptor(config, incoming, hlc)
            } else {
                Err(StateMachineError::UnexpectedFrameType(
                    incoming.header.frame_type,
                ))
            }
        }

        ConnState::Handshaking(ref hs_state) => {
            match incoming.header.frame_type {
                FrameType::Hello if config.role == Role::Acceptor => {
                    // Acceptor receives HELLO
                    handle_hello_as_acceptor(config, incoming, hlc)
                }
                FrameType::HelloAck if config.role == Role::Initiator => {
                    // Initiator receives HELLO_ACK
                    handle_hello_ack_as_initiator(config, incoming, hs_state, hlc)
                }
                FrameType::Close => {
                    // Either side receives CLOSE during handshake
                    handle_close(incoming)
                }
                _ => Err(StateMachineError::UnexpectedFrameType(
                    incoming.header.frame_type,
                )),
            }
        }

        ConnState::Active(_) => {
            // In active state, we only handle CLOSE (DATA/ACK/NACK/PING/PONG handled elsewhere)
            if incoming.header.frame_type == FrameType::Close {
                handle_close(incoming)
            } else {
                // Other frame types are valid but handled by higher-layer logic
                Ok(Transition::new(state))
            }
        }

        ConnState::Closed(_, _) => {
            // Closed state - ignore all incoming messages
            Ok(Transition::new(state))
        }
    }
}

/// Initiator starts the handshake by sending HELLO
pub fn initiate_handshake(config: &ConnConfig, hlc: &mut Hlc) -> Transition {
    hlc.tick_local(hlc.physical_ms);

    // Determine which security mode to request
    let requested_mode = if config.security_policy.prefer_strongest {
        SecurityMode::most_secure(&config.security_policy.supported_modes)
            .unwrap_or(SecurityMode::TrustedLan)
    } else {
        config.security_policy.supported_modes[0]
    };

    let hello_fields = HelloFields {
        node_id: config.node_id.clone(),
        capabilities: config.capabilities,
        security_mode: requested_mode,
        pubkey: if requested_mode == SecurityMode::Signed {
            config.ed25519_pubkey.clone()
        } else {
            None
        },
    };

    let hello = Song::hello(*hlc, hello_fields);

    Transition::with_song(
        ConnState::Handshaking(HandshakeState {
            hello_sent: true,
            hello_received: None,
        }),
        hello,
    )
}

/// Handle incoming HELLO as acceptor
fn handle_hello_as_acceptor(
    config: &ConnConfig,
    incoming: &Song,
    hlc: &mut Hlc,
) -> Result<Transition, StateMachineError> {
    let hello_fields = incoming
        .parse_hello()
        .map_err(StateMachineError::InvalidMessage)?;

    hlc.tick_local(hlc.physical_ms);

    // Negotiate security mode
    let (selected_mode, result_code) = match config
        .security_policy
        .select_mode(hello_fields.security_mode)
    {
        Ok(mode) => (mode, ResultCode::Ok),
        Err((placeholder_mode, err_code)) => (placeholder_mode, err_code),
    };

    // Compute capability intersection
    let negotiated_caps = config.capabilities.intersection(hello_fields.capabilities);

    let hello_ack_fields = HelloAckFields {
        node_id: config.node_id.clone(),
        capabilities: negotiated_caps,
        security_mode: selected_mode,
        result: result_code,
        pubkey: if selected_mode == SecurityMode::Signed {
            config.ed25519_pubkey.clone()
        } else {
            None
        },
    };

    let hello_ack = Song::hello_ack(*hlc, hello_ack_fields);

    if result_code.is_ok() {
        // Success - transition to Active
        Ok(Transition::with_song(
            ConnState::Active(ActiveState {
                remote_node_id: hello_fields.node_id,
                security_mode: selected_mode,
                capabilities: negotiated_caps,
                remote_pubkey: hello_fields.pubkey,
            }),
            hello_ack,
        ))
    } else {
        // Failed - send HELLO_ACK with error, then close
        // In a real implementation, we'd send CLOSE after HELLO_ACK
        Ok(Transition::with_song(
            ConnState::Closed(ReasonCode::SecurityError, None),
            hello_ack,
        ))
    }
}

/// Handle incoming HELLO_ACK as initiator
fn handle_hello_ack_as_initiator(
    _config: &ConnConfig,
    incoming: &Song,
    _hs_state: &HandshakeState,
    _hlc: &mut Hlc,
) -> Result<Transition, StateMachineError> {
    let hello_ack_fields = incoming
        .parse_hello_ack()
        .map_err(StateMachineError::InvalidMessage)?;

    if hello_ack_fields.result.is_ok() {
        // Handshake succeeded - transition to Active
        Ok(Transition::new(ConnState::Active(ActiveState {
            remote_node_id: hello_ack_fields.node_id,
            security_mode: hello_ack_fields.security_mode,
            capabilities: hello_ack_fields.capabilities,
            remote_pubkey: hello_ack_fields.pubkey,
        })))
    } else {
        // Handshake failed - close connection
        let reason = match hello_ack_fields.result {
            ResultCode::ErrorUnsupportedVersion => ReasonCode::VersionMismatch,
            ResultCode::ErrorUnsupportedSecurityMode => ReasonCode::SecurityError,
            ResultCode::ErrorCapabilityMismatch => ReasonCode::CapabilityError,
            ResultCode::ErrorPolicy => ReasonCode::SecurityError,
            ResultCode::ErrorInternal => ReasonCode::InternalError,
            ResultCode::Ok => ReasonCode::Normal, // shouldn't happen
        };

        Ok(Transition::new(ConnState::Closed(
            reason,
            Some("Handshake rejected by remote".to_string()),
        )))
    }
}

/// Handle incoming CLOSE
fn handle_close(incoming: &Song) -> Result<Transition, StateMachineError> {
    let close_fields = incoming
        .parse_close()
        .map_err(StateMachineError::InvalidMessage)?;

    Ok(Transition::new(ConnState::Closed(
        close_fields.reason_code,
        close_fields.reason_text,
    )))
}

/// Initiate graceful close
pub fn initiate_close(reason: ReasonCode, text: Option<String>, hlc: &mut Hlc) -> Transition {
    hlc.tick_local(hlc.physical_ms);

    let close_fields = CloseFields {
        reason_code: reason,
        reason_text: text.clone(),
    };

    let close = Song::close(*hlc, close_fields);

    Transition::with_song(ConnState::Closed(reason, text), close)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initiator_config() -> ConnConfig {
        ConnConfig {
            role: Role::Initiator,
            node_id: vec![0x01; 16],
            capabilities: Capabilities::new(
                Capabilities::HLC_SUPPORTED
                    | Capabilities::CHECKSUM_SUPPORTED
                    | Capabilities::SIGNATURE_SUPPORTED,
            ),
            security_policy: SecurityPolicy::permissive(),
            ed25519_pubkey: Some(vec![0xAA; 32]),
        }
    }

    fn acceptor_config() -> ConnConfig {
        ConnConfig {
            role: Role::Acceptor,
            node_id: vec![0x02; 16],
            capabilities: Capabilities::new(
                Capabilities::HLC_SUPPORTED
                    | Capabilities::CHECKSUM_SUPPORTED
                    | Capabilities::SIGNATURE_SUPPORTED,
            ),
            security_policy: SecurityPolicy::permissive(),
            ed25519_pubkey: Some(vec![0xBB; 32]),
        }
    }

    #[test]
    fn test_initiator_sends_hello() {
        let config = initiator_config();
        let mut hlc = Hlc::new(1_000_000);

        let transition = initiate_handshake(&config, &mut hlc);

        // Should move to Handshaking state
        assert!(matches!(
            transition.new_state,
            ConnState::Handshaking(_)
        ));

        // Should send exactly one HELLO
        assert_eq!(transition.outgoing.len(), 1);
        let hello = &transition.outgoing[0];
        assert_eq!(hello.header.frame_type, FrameType::Hello);

        // Verify HELLO fields
        let fields = hello.parse_hello().unwrap();
        assert_eq!(fields.node_id, config.node_id);
        assert_eq!(fields.capabilities, config.capabilities);
        assert!(fields.pubkey.is_some());
    }

    #[test]
    fn test_successful_handshake_trusted_lan() {
        let mut initiator_config = initiator_config();
        initiator_config.security_policy = SecurityPolicy {
            supported_modes: vec![SecurityMode::TrustedLan],
            prefer_strongest: false,
            allow_downgrade: true,
        };

        let mut acceptor_config = acceptor_config();
        acceptor_config.security_policy = SecurityPolicy {
            supported_modes: vec![SecurityMode::TrustedLan, SecurityMode::Checksummed],
            prefer_strongest: true,
            allow_downgrade: true,
        };

        let mut initiator_hlc = Hlc::new(1_000_000);
        let mut acceptor_hlc = Hlc::new(1_000_000);

        // Step 1: Initiator sends HELLO
        let init_trans = initiate_handshake(&initiator_config, &mut initiator_hlc);
        let hello = &init_trans.outgoing[0];

        // Step 2: Acceptor receives HELLO and sends HELLO_ACK
        let accept_trans = apply(
            ConnState::Connecting,
            &acceptor_config,
            hello,
            &mut acceptor_hlc,
        )
        .unwrap();

        // Acceptor should be in Active state
        assert!(matches!(accept_trans.new_state, ConnState::Active(_)));

        // Should send HELLO_ACK
        assert_eq!(accept_trans.outgoing.len(), 1);
        let hello_ack = &accept_trans.outgoing[0];
        assert_eq!(hello_ack.header.frame_type, FrameType::HelloAck);

        // Step 3: Initiator receives HELLO_ACK
        let init_final = apply(
            init_trans.new_state,
            &initiator_config,
            hello_ack,
            &mut initiator_hlc,
        )
        .unwrap();

        // Initiator should be in Active state
        if let ConnState::Active(state) = init_final.new_state {
            assert_eq!(state.security_mode, SecurityMode::TrustedLan);
            assert_eq!(state.remote_node_id, acceptor_config.node_id);
        } else {
            panic!("Expected Active state");
        }
    }

    #[test]
    fn test_successful_handshake_signed_mode() {
        let mut initiator_config = initiator_config();
        initiator_config.security_policy = SecurityPolicy {
            supported_modes: vec![SecurityMode::Signed],
            prefer_strongest: true,
            allow_downgrade: false,
        };

        let acceptor_config = acceptor_config();

        let mut initiator_hlc = Hlc::new(1_000_000);
        let mut acceptor_hlc = Hlc::new(1_000_000);

        // Initiator sends HELLO requesting Signed
        let init_trans = initiate_handshake(&initiator_config, &mut initiator_hlc);
        let hello = &init_trans.outgoing[0];

        let hello_fields = hello.parse_hello().unwrap();
        assert_eq!(hello_fields.security_mode, SecurityMode::Signed);
        assert!(hello_fields.pubkey.is_some());

        // Acceptor receives and accepts
        let accept_trans = apply(
            ConnState::Connecting,
            &acceptor_config,
            hello,
            &mut acceptor_hlc,
        )
        .unwrap();

        let hello_ack = &accept_trans.outgoing[0];
        let hello_ack_fields = hello_ack.parse_hello_ack().unwrap();
        assert_eq!(hello_ack_fields.result, ResultCode::Ok);
        assert_eq!(hello_ack_fields.security_mode, SecurityMode::Signed);
        assert!(hello_ack_fields.pubkey.is_some());
    }

    #[test]
    fn test_handshake_failure_unsupported_mode() {
        let mut initiator_config = initiator_config();
        initiator_config.security_policy = SecurityPolicy {
            supported_modes: vec![SecurityMode::Signed],
            prefer_strongest: true,
            allow_downgrade: false,
        };

        let mut acceptor_config = acceptor_config();
        acceptor_config.security_policy = SecurityPolicy {
            supported_modes: vec![SecurityMode::TrustedLan],
            prefer_strongest: true,
            allow_downgrade: false,
        };

        let mut initiator_hlc = Hlc::new(1_000_000);
        let mut acceptor_hlc = Hlc::new(1_000_000);

        // Initiator sends HELLO requesting Signed
        let init_trans = initiate_handshake(&initiator_config, &mut initiator_hlc);
        let hello = &init_trans.outgoing[0];

        // Acceptor rejects because Signed is not supported
        let accept_trans = apply(
            ConnState::Connecting,
            &acceptor_config,
            hello,
            &mut acceptor_hlc,
        )
        .unwrap();

        // Acceptor should be in Closed state
        assert!(matches!(accept_trans.new_state, ConnState::Closed(_, _)));

        // HELLO_ACK should indicate error
        let hello_ack = &accept_trans.outgoing[0];
        let hello_ack_fields = hello_ack.parse_hello_ack().unwrap();
        assert_eq!(
            hello_ack_fields.result,
            ResultCode::ErrorUnsupportedSecurityMode
        );

        // Initiator receives error HELLO_ACK
        let init_final = apply(
            init_trans.new_state,
            &initiator_config,
            hello_ack,
            &mut initiator_hlc,
        )
        .unwrap();

        // Initiator should close
        assert!(matches!(
            init_final.new_state,
            ConnState::Closed(ReasonCode::SecurityError, _)
        ));
    }

    #[test]
    fn test_security_policy_prefer_strongest() {
        let policy = SecurityPolicy {
            supported_modes: vec![
                SecurityMode::TrustedLan,
                SecurityMode::Checksummed,
                SecurityMode::Signed,
            ],
            prefer_strongest: true,
            allow_downgrade: false,
        };

        // Request TrustedLan but policy prefers strongest
        let result = policy.select_mode(SecurityMode::TrustedLan);
        assert_eq!(result.unwrap(), SecurityMode::Signed);
    }

    #[test]
    fn test_security_policy_allow_downgrade() {
        let policy = SecurityPolicy {
            supported_modes: vec![SecurityMode::TrustedLan, SecurityMode::Checksummed],
            prefer_strongest: true,
            allow_downgrade: true,
        };

        // Request TrustedLan and downgrade is allowed
        let result = policy.select_mode(SecurityMode::TrustedLan);
        assert_eq!(result.unwrap(), SecurityMode::TrustedLan);
    }

    #[test]
    fn test_capability_intersection() {
        let caps_a = Capabilities::new(
            Capabilities::HLC_SUPPORTED
                | Capabilities::CHECKSUM_SUPPORTED
                | Capabilities::MULTI_STREAM_SUPPORTED,
        );

        let caps_b = Capabilities::new(
            Capabilities::HLC_SUPPORTED
                | Capabilities::CHECKSUM_SUPPORTED
                | Capabilities::SIGNATURE_SUPPORTED,
        );

        let intersection = caps_a.intersection(caps_b);

        // Should only have HLC and CHECKSUM
        assert!(intersection.has(Capabilities::HLC_SUPPORTED));
        assert!(intersection.has(Capabilities::CHECKSUM_SUPPORTED));
        assert!(!intersection.has(Capabilities::SIGNATURE_SUPPORTED));
        assert!(!intersection.has(Capabilities::MULTI_STREAM_SUPPORTED));
    }

    #[test]
    fn test_close_during_handshake() {
        let config = initiator_config();
        let mut hlc = Hlc::new(1_000_000);

        // Start handshake
        let init_trans = initiate_handshake(&config, &mut hlc);

        // Receive CLOSE instead of HELLO_ACK
        let close = Song::close(
            Hlc::new(1_000_100),
            CloseFields {
                reason_code: ReasonCode::ProtocolError,
                reason_text: Some("Invalid HELLO".to_string()),
            },
        );

        let final_trans = apply(init_trans.new_state, &config, &close, &mut hlc).unwrap();

        // Should be in Closed state
        if let ConnState::Closed(reason, text) = final_trans.new_state {
            assert_eq!(reason, ReasonCode::ProtocolError);
            assert_eq!(text, Some("Invalid HELLO".to_string()));
        } else {
            panic!("Expected Closed state");
        }
    }

    #[test]
    fn test_initiate_close() {
        let mut hlc = Hlc::new(1_000_000);

        let transition = initiate_close(
            ReasonCode::Normal,
            Some("Shutting down".to_string()),
            &mut hlc,
        );

        // Should be in Closed state
        assert!(matches!(
            transition.new_state,
            ConnState::Closed(ReasonCode::Normal, _)
        ));

        // Should send CLOSE
        assert_eq!(transition.outgoing.len(), 1);
        let close = &transition.outgoing[0];
        assert_eq!(close.header.frame_type, FrameType::Close);

        let fields = close.parse_close().unwrap();
        assert_eq!(fields.reason_code, ReasonCode::Normal);
        assert_eq!(fields.reason_text, Some("Shutting down".to_string()));
    }

    #[test]
    fn test_invalid_version_rejected() {
        let config = acceptor_config();
        let mut hlc = Hlc::new(1_000_000);

        // Create HELLO with invalid version
        let mut hello = Song::hello(
            Hlc::new(1_000_000),
            HelloFields {
                node_id: vec![0x01; 16],
                capabilities: Capabilities::new(Capabilities::HLC_SUPPORTED),
                security_mode: SecurityMode::TrustedLan,
                pubkey: None,
            },
        );
        hello.header.ver = 99; // Invalid version

        let result = apply(ConnState::Connecting, &config, &hello, &mut hlc);

        assert!(matches!(
            result,
            Err(StateMachineError::VersionMismatch(99))
        ));
    }

    #[test]
    fn test_reserved_flags_validation() {
        let config = acceptor_config();
        let mut hlc = Hlc::new(1_000_000);

        // Create HELLO with reserved flags set
        let mut hello = Song::hello(
            Hlc::new(1_000_000),
            HelloFields {
                node_id: vec![0x01; 16],
                capabilities: Capabilities::new(Capabilities::HLC_SUPPORTED),
                security_mode: SecurityMode::TrustedLan,
                pubkey: None,
            },
        );
        hello.header.flags.0 = 0x08; // Set reserved bit 3

        let result = apply(ConnState::Connecting, &config, &hello, &mut hlc);

        assert!(matches!(result, Err(StateMachineError::InvalidFlags)));
    }

    #[test]
    fn test_hlc_advances_during_handshake() {
        let initiator_config = initiator_config();
        let acceptor_config = acceptor_config();

        let mut initiator_hlc = Hlc::new(1_000_000);
        let mut acceptor_hlc = Hlc::new(999_000); // Acceptor clock behind

        // Initiator sends HELLO
        let init_trans = initiate_handshake(&initiator_config, &mut initiator_hlc);
        let hello = &init_trans.outgoing[0];

        let initial_acceptor_logical = acceptor_hlc.logical;

        // Acceptor receives HELLO
        apply(
            ConnState::Connecting,
            &acceptor_config,
            hello,
            &mut acceptor_hlc,
        )
        .unwrap();

        // Acceptor's HLC should have advanced
        assert!(acceptor_hlc.physical_ms >= 1_000_000);
        assert!(acceptor_hlc.logical > initial_acceptor_logical);
    }
}
