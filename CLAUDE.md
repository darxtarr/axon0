# CLAUDE.md — Onboarding for AI Agents Working on AXON/0

This document is for Claude (or other AI agents) picking up work on AXON/0 in future sessions.

## What is AXON/0?

AXON/0 is the **lowest-layer transport protocol** for the CHORUS distributed system. Think of it as:

- **The obsidian glass substrate** — fast, binary, minimalist wire protocol
- **Layer 0** — below everything else (AXON/1+ and CHORUS services build on top)
- **Not HTTP/REST** — binary framing, not text-based, not human-curl-friendly
- **AI-native observability** — designed to be debugged by agents reading traces, not humans staring at logs

### Core Concepts

**Songs** — the wire unit (like "packets" or "frames"):
- Fixed 32-byte header + variable payload + optional trailer (checksum/signature)
- Every Song carries a Hybrid Logical Clock (HLC) for causal ordering
- Types: HELLO, HELLO_ACK, CLOSE, DATA, ACK, NACK, PING, PONG

**Bells** — introspection events (not yet implemented):
- Structured trace events for debugging
- Consumed by AI trace agents, not humans
- Stored in binary format, decoded on-demand

**Security modes**:
- TrustedLan: No crypto overhead
- Checksummed: BLAKE3-128 integrity check
- Signed: Ed25519 signatures for authenticity

## Flat File Structure

This repo uses a **flat, LLM-friendly file structure** with descriptive prefixes:

```
axon0_doc_spec_protocol.md       — Wire format spec (CANONICAL)
axon0_doc_spec_handshake.md      — Handshake spec (CANONICAL)
axon0_lib.rs                      — Main library entry
axon0_lib_frame.rs                — Header, FrameType, Flags
axon0_lib_hlc.rs                  — Hybrid Logical Clock
axon0_lib_tlv.rs                  — Type-Length-Value codec
axon0_lib_song.rs                 — Song structure with crypto
axon0_lib_handshake.rs            — Typed handshake helpers
axon0_lib_conn.rs                 — Pure connection state machine
axon0_lib_io.rs                   — Thin I/O wrapper (Read+Write)
axon0_bin_demo_accept.rs          — Demo: acceptor binary
axon0_bin_demo_init.rs            — Demo: initiator binary
```

**Naming convention:**
- `axon0_doc_*` — Documentation, specifications
- `axon0_lib_*` — Library modules
- `axon0_bin_*` — Executable binaries
- `axon0_test_*` — Test utilities (future)

This makes it easy to glob/grep for specific categories without navigating directories.

## Canonical Source of Truth

**IMPORTANT:** The markdown specs are **canonical**. Code implements the specs.

When you spot divergences:
- **Fix the code** to match the spec (default)
- Only change the spec if explicitly agreed with the user

The two spec files define:
- `axon0_doc_spec_protocol.md` — §2-6: wire format, frame types, flags, HLC
- `axon0_doc_spec_handshake.md` — Handshake state machine, HELLO/HELLO_ACK, security negotiation

## Current Implementation Status (2024-12-01)

### ✅ DONE — Fully Implemented and Tested

1. **Wire format codec** (`frame`, `tlv`, `song`):
   - 32-byte header encoding/decoding
   - TLV sequences for control frames
   - Song structure with checksum (BLAKE3) and signature (Ed25519)
   - All frame types: HELLO, HELLO_ACK, CLOSE, DATA, ACK, NACK, PING, PONG

2. **Hybrid Logical Clock** (`hlc`):
   - Local tick on send
   - Receive tick with remote HLC merge
   - Maintains causal ordering across nodes
   - Tested for monotonicity and clock skew handling

3. **Handshake layer** (`handshake`):
   - Typed field structs: `HelloFields`, `HelloAckFields`, `CloseFields`
   - Song constructors: `Song::hello()`, `Song::hello_ack()`, `Song::close()`, etc.
   - TLV type constants from spec §5
   - Security modes: TrustedLan, Checksummed, Signed
   - Capability negotiation (bitfield)
   - Result codes and reason codes

4. **Connection state machine** (`conn`):
   - Pure, deterministic state machine (no I/O)
   - States: Idle → Connecting → Handshaking → Active → Closed
   - `apply(state, config, incoming, hlc)` — single transition function
   - Security policy: `SecurityPolicy::permissive()` and `SecurityPolicy::strict()`
   - Automatic mode negotiation (prefer strongest, allow downgrade)
   - 12 comprehensive unit tests covering all handshake scenarios

5. **I/O layer** (`io`):
   - `AxonConn<T: Read + Write>` — thin wrapper over any byte stream
   - Frame reading: header → payload → trailer (checksum/signature)
   - `initiate_handshake()` — for initiator (client)
   - `accept_handshake()` — for acceptor (server)
   - `poll_once()` — event-driven message processing
   - `send_data()`, `send_ping()`, `send_pong()`, `close()`
   - Events: `HandshakeCompleted`, `DataReceived`, `PingReceived`, `Closed`

6. **Demo binaries** (`axon0-demo-accept`, `axon0-demo-init`):
   - **Proof of concept**: Full end-to-end TCP connection working!
   - Acceptor listens on port 52020
   - Initiator connects, handshakes, sends DATA, closes
   - Security mode correctly negotiated (Signed mode selected)
   - HLC synchronization working across processes

**Test coverage:**
- 25 unit tests passing
- End-to-end demo proven over real TCP sockets

### ❌ NOT YET IMPLEMENTED

1. **Discovery beacons** (`axon0_lib_discovery.rs` — planned):
   - UDP broadcast with magic "AX0D"
   - Beacon encoding/decoding
   - `BeaconBroadcaster` and `BeaconListener`
   - TLVs: NODE_ID, ENDPOINT, CAPABILITIES

2. **Bells / Trace events** (`axon0_lib_bell.rs` — planned):
   - Bell record format (binary trace events)
   - Bell types: ConnectionOpened, SongSent, SongReceived, etc.
   - `BellSink` trait for trace recording
   - Integration into `AxonConn` and discovery

3. **ACK/NACK retransmission**:
   - At-least-once delivery semantics
   - Sequence numbers for DATA frames
   - Retransmit on timeout or NACK

4. **Async I/O** (`axon0_lib_io_async.rs` — future):
   - Mirror of `AxonConn` over `AsyncRead + AsyncWrite`
   - Tokio/async-std integration

5. **Connection pooling / topology management**:
   - Multiple concurrent connections
   - Peer registry
   - Automatic reconnection

## How to Work on AXON/0

### Running Tests

```bash
cargo test              # All unit tests (25 passing)
cargo test --lib        # Library tests only
```

### Running Demo

Terminal 1 (acceptor):
```bash
cargo run --bin axon0-demo-accept
```

Terminal 2 (initiator):
```bash
cargo run --bin axon0-demo-init
```

You should see:
- Handshake complete
- Security mode negotiated (Signed)
- DATA frames transferred
- HLC values advancing
- Graceful CLOSE

### Architecture Layers

```
┌─────────────────────────────────────┐
│   Demo Binaries (TCP sockets)      │ ← axon0_bin_demo_*.rs
├─────────────────────────────────────┤
│   AxonConn<T> (I/O wrapper)         │ ← axon0_lib_io.rs
├─────────────────────────────────────┤
│   ConnState machine (pure)          │ ← axon0_lib_conn.rs
├─────────────────────────────────────┤
│   Handshake helpers (typed API)     │ ← axon0_lib_handshake.rs
├─────────────────────────────────────┤
│   Song / TLV / HLC (wire format)    │ ← axon0_lib_{song,tlv,hlc,frame}.rs
├─────────────────────────────────────┤
│   Specs (canonical source)          │ ← axon0_doc_spec_*.md
└─────────────────────────────────────┘
```

The design is **layered and modular**:
- Pure state machine (testable without I/O)
- Generic I/O wrapper (works over any `Read + Write`)
- Codec layer is spec-compliant and symmetric

### What to Build Next

**Recommended order** (per Veyr's advice, confirmed working):

1. **Discovery beacons** (next logical step):
   - Create `axon0_lib_discovery.rs`
   - UDP broadcast/multicast on well-known port
   - Beacon format: magic "AX0D" + ver + flags + TLVs
   - `BeaconBroadcaster::new(node_id, endpoint, caps) -> Self`
   - `BeaconListener::listen() -> Stream<DiscoveredNode>`
   - Demo binary that discovers peers and auto-connects

2. **Bells / Trace instrumentation**:
   - Create `axon0_lib_bell.rs`
   - Define Bell record format (binary)
   - Bell types: ConnectionOpened, HandshakeCompleted, SongSent, SongReceived, BeaconSent, BeaconReceived, Error, etc.
   - `BellSink` trait (write to file, memory buffer, network sink)
   - Instrument `AxonConn` to emit Bells at key points
   - Demo: record trace, dump as JSON for inspection

3. **ACK/NACK + retransmission**:
   - Sequence numbers for DATA frames
   - Sliding window or simple stop-and-wait
   - Timeout-based retransmit
   - NACK on gap detection

4. **Async I/O version**:
   - `axon0_lib_io_async.rs` mirroring `axon0_lib_io.rs`
   - Use Tokio or async-std
   - Keep same state machine (it's pure!)

### Common Patterns

**Adding a new frame type:**
1. Add to `FrameType` enum in `axon0_lib_frame.rs`
2. Update spec `axon0_doc_spec_protocol.md` §4
3. Add TLV types to `axon0_lib_handshake.rs::tlv_types`
4. Create field struct like `FooFields` with `from_tlvs()` / `to_tlvs()`
5. Add `Song::foo()` constructor
6. Handle in state machine `apply()` or `poll_once()`

**Adding a new security mode:**
1. Add variant to `SecurityMode` enum in `axon0_lib_handshake.rs`
2. Update spec `axon0_doc_spec_handshake.md` §3
3. Add to `SecurityPolicy::select_mode()` logic
4. Update `AxonConn::send_data()` to apply mode

**Adding a new capability:**
1. Add bit constant to `Capabilities` in `axon0_lib_handshake.rs`
2. Update spec `axon0_doc_spec_handshake.md` §7
3. Use in handshake negotiation

## Session History

### 2024-12-01: Initial I/O layer and end-to-end demo

**What was done:**
- Created `axon0_lib_io.rs` — thin I/O wrapper with `AxonConn<T>`
- Implemented frame reading (header + payload + trailer)
- Implemented `initiate_handshake()` and `accept_handshake()`
- Created `axon0-demo-accept` and `axon0-demo-init` binaries
- **Proved end-to-end**: Full TCP handshake, DATA transfer, and CLOSE working!

**Key achievements:**
- Security mode negotiation works (selected Signed mode)
- HLC synchronization across processes confirmed
- 25 unit tests passing + end-to-end demo working

**Context from earlier sessions:**
- Wire format, HLC, TLV, Song structure implemented
- Pure state machine with security policy engine
- Handshake helpers with typed field structs
- Comprehensive unit tests for state machine

### Previous Sessions (context from other PC)

- Spec written (`axon0_doc_spec_protocol.md`, `axon0_doc_spec_handshake.md`)
- Core codec layer (`frame`, `hlc`, `tlv`, `song`)
- Checksum (BLAKE3) and signature (Ed25519) support
- Pure connection state machine
- Handshake typed APIs

---

## Quick Reference

**Compile and test:**
```bash
cargo test              # Run all tests
cargo build --release   # Build optimized
cargo doc --open        # Generate docs
```

**Demo end-to-end:**
```bash
# Terminal 1
cargo run --bin axon0-demo-accept

# Terminal 2
cargo run --bin axon0-demo-init
```

**Key files to read first:**
1. `README.md` — High-level overview
2. `axon0_doc_spec_protocol.md` — Wire format
3. `axon0_doc_spec_handshake.md` — Handshake behavior
4. `axon0_lib_conn.rs` — State machine (core logic)
5. `axon0_lib_io.rs` — I/O wrapper (how it all connects)

**Dependencies:**
- `blake3` — Cryptographic hashing
- `ed25519-dalek` — Ed25519 signatures
- `rand` — Key generation (dev/test)

No framework dependencies. No async runtime (yet). Pure Rust, minimal, defensible.

---

## Tips for AI Agents

1. **Always read the spec first** — The markdown files are canonical
2. **Preserve the flat structure** — Don't create subdirectories
3. **Run tests before pushing** — `cargo test` must pass
4. **Update this file** — Document what you did in "Session History"
5. **Ask about spec changes** — Don't modify specs without user approval
6. **Keep layers pure** — State machine has no I/O, I/O layer has no logic
7. **Test end-to-end** — The demos must work after any changes

---

**Welcome to AXON/0. The glass is ready.**
