# AXON/0 Protocol Specification (v0)

Status: DRAFT / SPIKE A
Scope: On-the-wire format and connection semantics for AXON/0 "Songs" and discovery beacons.

This document defines the **binary protocol** spoken by AXON/0 nodes.

It intentionally omits:
- CRDT/state semantics,
- application-level message schemas,
- and detailed observability tooling design,

leaving those to AXON/1+ and Trace/Forensics agents.

---

## 1. Wire Model

AXON/0 assumes a **reliable, ordered byte stream** between peers (typically TCP, possibly QUIC in the future) and defines:

- A **frame format** called a **Song**.
- A **connection handshake** and basic keepalive.
- Optional **integrity/authentication trailers**.

Separately, AXON/0 uses **unreliable datagrams** (typically UDP) for **discovery beacons**.

All multi-byte integers are encoded in **network byte order (big-endian)** unless otherwise stated.

---

## 2. Songs: Frame Format

Every Song on an AXON/0 connection has the following layout:

```
+----------------------+------------------+----------------------+
|  Fixed Header (32B)  |  Payload (N B)   |   Trailer (0..M B)   |
+----------------------+------------------+----------------------+
```

### 2.1 Fixed Header (32 bytes)

```text
 0               8              16              24              32
+-------+-------+-------+-------+-------------------------------+
| ver   | type  | flags | rsvd0 |    payload_len (u32)          |
+-------+-------+-------+-------+-------------------------------+
|             hlc_physical_ms (u64)                             |
+---------------------------------------------------------------+
|        hlc_logical (u32)      |      stream_id (u32)          |
+---------------------------------------------------------------+
|                         rsvd1 (u32)                           |
+---------------------------------------------------------------+
```

Fields:

- **ver** (u8): Protocol version. For this spec: 0x00.

- **type** (u8): Frame type (see §4).

- **flags** (u8): Bitfield controlling security / trailer / semantics (see §3).

- **rsvd0** (u8): Reserved. Must be 0 in this version.

- **payload_len** (u32): Length in bytes of the payload that follows the header (excluding trailer).

- **hlc_physical_ms** (u64): Physical component of the Hybrid Logical Clock timestamp in milliseconds since Unix epoch.

- **hlc_logical** (u32): Logical HLC counter (incremented on ties and receive events).

- **stream_id** (u32): Connection-local stream or flow identifier.

- **rsvd1** (u32): Reserved for future use (e.g. trace IDs). Must be 0 in this version.

The header is always exactly 32 bytes and is aligned to 4 bytes.

### 2.2 Payload

The payload is `payload_len` bytes.

Interpretation depends on `type`:

- For **DATA** Songs, the payload is opaque bytes owned by higher layers.

- For **control** Songs (HELLO, ACK, etc.), the payload is a TLV sequence as defined in §5.

We use a classic Type–Length–Value (TLV) scheme: a sequence of fields where each field is:

```text
+----------+------------+-----------------+
|  t (u8)  | len (u16)  |  value (len B)  |
+----------+------------+-----------------+
```

Types and their semantics are defined per frame type; unknown TLV types MUST be skipped based on `len`.

### 2.3 Trailer (optional)

The trailer is present only if certain bits in `flags` are set (§3).

Layout (if all enabled):

```text
+-------------------------+---------------------------+
|    checksum (16 B)      |    signature (64 B)       |
+-------------------------+---------------------------+
```

Semantics:

- **checksum**: BLAKE3-128 over header + payload.

- **signature**: Ed25519 signature over header + payload + checksum.

The presence and order of these fields is fixed; if a flag is not set, the corresponding segment is omitted.

---

## 3. Flags and Security Modes

The `flags` byte in the header has the following bit assignments (LSB = bit 0):

- **Bit 0 (0x01)**: Checksum present
  If set, a 16-byte BLAKE3 checksum is appended in the trailer.

- **Bit 1 (0x02)**: Signature present
  If set, a 64-byte Ed25519 signature is appended after the checksum (if any).

- **Bit 2 (0x04)**: End-of-stream hint
  If set on a DATA frame, indicates end-of-stream for `stream_id`.

- **Bits 3–7**: Reserved (must be 0 in this version).

We define three security modes negotiated during handshake:

- **Trusted-LAN**: flags bits 0–1 are clear by default. Integrity may be disabled or selectively enabled per-flow.

- **Checksummed**: bit 0 set on all DATA and critical control frames.

- **Signed**: bits 0 and 1 set on all DATA and critical control frames; keys exchanged in HELLO.

Higher layers may choose stricter policies, but AXON/0's job is to provide the mechanism.

---

## 4. Frame Types

Frame types are 8-bit unsigned integers:

```text
0x00  RESERVED
0x01  HELLO
0x02  HELLO_ACK
0x03  CLOSE

0x10  DATA
0x11  ACK
0x12  NACK

0x20  PING
0x21  PONG
```

Unrecognized types MUST cause the connection to be closed with a protocol error.

### 4.1 HELLO (0x01)

Direction: both ways (typically client → server first).
Purpose: establish identity, capabilities, and security mode.

Payload: TLV-encoded:

- **0x01 NODE_ID** (len: 16 or more) – opaque node identifier (e.g. hash of public key).

- **0x02 CAPABILITIES** – bitfield or feature list.

- **0x03 SECURITY_MODE** – desired mode: Trusted-LAN / Checksummed / Signed.

- **0x04 PUBKEY** (optional) – Ed25519 public key (if Signed is offered).

### 4.2 HELLO_ACK (0x02)

Direction: both ways.
Purpose: confirm negotiated parameters.

Payload: TLV:

- **0x01 NODE_ID** – remote's view of its own ID.

- **0x02 CAPABILITIES** – intersected capabilities.

- **0x03 SECURITY_MODE** – chosen mode.

- **0x05 RESULT** – OK / ERROR code.

After HELLO/HELLO_ACK exchange completes successfully, the connection is considered active and may carry DATA.

### 4.3 CLOSE (0x03)

Direction: both ways.
Purpose: graceful shutdown.

Payload TLVs:

- **0x01 REASON_CODE** (u16)

- **0x02 REASON_TEXT** (UTF-8, optional, human-facing)

Implementations should prefer to use close codes; text is optional and for the simian.

### 4.4 DATA (0x10)

Direction: both ways.
Purpose: carry application or higher-layer semantics.

Payload:

- Raw bytes owned by AXON/1+/application. AXON/0 does not interpret.

Semantics:

- `stream_id` identifies the flow.

- At-least-once delivery is provided using ACK/NACK and retransmit logic.

### 4.5 ACK (0x11)

Direction: both ways.
Purpose: acknowledge receipt of DATA.

Payload TLVs:

- **0x01 STREAM_ID** (u32) – The stream_id acknowledged.

- **0x02 RANGE_START** (u32) – First sequence number acknowledged (DATA numbering is up to the sender; this spec simply reserves the field).

- **0x03 RANGE_END** (u32) – Last sequence number acknowledged (inclusive).

You can initially simplify to "ACK by last seen sequence number" and refine later.

### 4.6 NACK (0x12)

Same as ACK, but indicates a gap / failure that may trigger retransmission.

### 4.7 PING (0x20) / PONG (0x21)

Purpose: liveness / RTT measurement.

Payload TLVs:

- **0x01 NONCE** (opaque) – copied verbatim into PONG.

Optionally, traces or stats as experimental TLVs.

---

## 5. Control TLVs

We reserve the following TLV type codes for control payloads (HELLO, HELLO_ACK, ACK, etc.):

```text
0x01  NODE_ID
0x02  CAPABILITIES
0x03  SECURITY_MODE
0x04  PUBKEY
0x05  RESULT

0x10  STREAM_ID
0x11  RANGE_START
0x12  RANGE_END

0x20  NONCE
0x21  REASON_CODE
0x22  REASON_TEXT
```

Semantics:

- **NODE_ID** – Binary identifier; length between 8 and 64 bytes.

- **CAPABILITIES** – Bitfield or feature list; exact layout TBD.

- **SECURITY_MODE** – Single byte:
  - 0x00 = Trusted-LAN
  - 0x01 = Checksummed
  - 0x02 = Signed

- **RESULT** – Single byte:
  - 0x00 = OK
  - 0x01.. = error codes (TBD).

- **STREAM_ID, RANGE_START, RANGE_END** – big-endian u32.

- **NONCE** – arbitrary bytes; echoed back in PONG.

- **REASON_CODE** – big-endian u16.

- **REASON_TEXT** – UTF-8 string; optional.

Unknown TLV types MUST be ignored and skipped.

---

## 6. HLC Semantics

AXON/0 uses Hybrid Logical Clocks (HLC) to timestamp all Songs.

Each node maintains:

- **PT** – its physical clock in milliseconds.

- **L** – a 32-bit logical counter.

- **H** – current HLC = (PT', L).

Update rules (informal):

**On local event:**

```
PT := physical_now_ms()
PT' := max(PT, H.PT)
If PT' == H.PT, L := H.L + 1 else L := 0
```

**On receive(header.HLC):**

Let (PT_r, L_r) be the received HLC.

```
PT := physical_now_ms()
PT' := max(PT, H.PT, PT_r)

If PT' == H.PT == PT_r, L := max(H.L, L_r) + 1
Else if PT' == H.PT, L := H.L + 1
Else if PT' == PT_r, L := L_r + 1
Else L := 0
```

`hlc_physical_ms` and `hlc_logical` in the header always carry the sender's current HLC at send time.

AXON/0 nodes may use HLC to:

- Reconstruct partial causal order across nodes.
- Provide time-window queries in trace tooling.
- Implement consistency checks in higher layers.

---

## 7. Connection State Machine (High-Level)

Each AXON/0 connection follows this rough state machine:

**IDLE**
Underlying TCP/stream not yet connected.

**CONNECTING**
TCP/stream established.

**HANDSHAKING**

- Send HELLO.
- Await HELLO (and HELLO_ACK if using a 2-step handshake).
- Negotiate security mode and capabilities.

**ACTIVE**

- Exchange DATA, ACK, NACK, PING, PONG.
- Enforce security mode (checksums/signatures).
- Manage retransmissions and keepalive.

**CLOSING**

- Optionally send CLOSE.
- Flush pending DATA if possible.
- Tear down underlying transport.

**CLOSED**

Exact retransmit / congestion policies are left to the implementation; AXON/0 only specifies the existence of ACK/NACK and that at-least-once delivery is expected.

For inspiration on robust frame-and-ACK design, QUIC's framing + ACK mechanisms are a useful reference point, though AXON/0 intentionally remains much simpler.

---

## 8. Discovery Beacons

Discovery runs over unreliable datagrams (typically UDP) on a well-known port.

Beacon payload format:

```text
+----------------+--------------+----------------------+
| magic (4 B)    | ver (u8)     |  flags (u8)          |
+----------------+--------------+----------------------+
| rsvd (u16)     |  TLVs...                         ...
+----------------+-------------------------------------+
```

- **magic**: ASCII "AX0D" (0x41 0x58 0x30 0x44).

- **ver**: protocol version (0x00).

- **flags**:
  - Bit 0 = this node is accepting connections.
  - Other bits reserved.

- **rsvd**: reserved; must be 0.

TLVs:

- **0x01 NODE_ID** – same as in HELLO.

- **0x02 ENDPOINT** – e.g. `tcp4://192.168.1.10:52020` (opaque UTF-8).

- **0x03 CAPABILITIES** – as in HELLO.

Nodes may periodically send beacons; listeners may:

- Auto-connect to interesting peers.
- Or feed discovered endpoints into a topology planner.

---

## 9. Bells and Traces (Preview)

Bells are not sent on the AXON/0 Songs channel; they are an internal event stream recorded to a trace buffer/file.

A Bell record might look like:

```text
+---------------------------+
| header (HLC, node_id, …)  |
+---------------------------+
| bell_type (u16)           |
+---------------------------+
| payload_len (u16)         |
+---------------------------+
| payload (TLV...)          |
+---------------------------+
```

Where `bell_type` could be:

- CONNECTION_OPENED
- CONNECTION_CLOSED
- SONG_SENT
- SONG_RECEIVED
- RETRANSMIT
- ERROR

The exact Bell schema is left to the forthcoming `AXON0_TRACE.md`. The key invariant is that trace records are:

- Binary, compact, and self-describing (TLV).
- Designed to be consumed by trace agents, which then generate human-friendly views.

---

## 10. Compatibility and Evolution

Because the header is fixed-size and TLVs are self-describing:

- Older nodes can skip unknown TLVs and still parse messages.

New fields are added by:

- Defining new TLV types,
- Or repurposing reserved bits/fields in new `ver`.

The combination of:

- versioned header (`ver`),
- TLV-extensible payloads,
- and reserved fields

gives Axon/0 room to evolve without breaking the glass under Chorus.
