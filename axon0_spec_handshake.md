# AXON/0 Handshake and Connection Semantics

Status: DRAFT / SPIKE A
Scope: HELLO / HELLO_ACK messages, security mode negotiation, and basic connection lifecycle.

This document refines the protocol spec by defining **how two AXON/0 peers agree to talk** before any DATA Songs flow.

---

## 1. Roles and Connection Model

AXON/0 assumes a reliable, ordered byte stream (e.g. TCP) between peers.

For the purposes of the handshake, we distinguish:

- **Initiator** – the side that actively opens the underlying stream (typically "client").
- **Acceptor** – the side that passively accepts incoming streams (typically "server").

The handshake is intentionally asymmetric and kept to a single RTT:

1. Initiator opens stream.
2. Initiator sends **HELLO**.
3. Acceptor validates and responds with **HELLO_ACK**.
4. If HELLO_ACK is OK, both sides enter **ACTIVE** and may send DATA Songs.

If either side sends a protocol error or encounters invalid parameters, it must close the connection.

---

## 2. Recap: Frame Types and TLVs

From the main protocol spec:

- `HELLO` (type `0x01`)
- `HELLO_ACK` (type `0x02`)
- `CLOSE` (type `0x03`)

Control payloads (HELLO / HELLO_ACK / CLOSE) are TLV sequences where each field is:

```text
+----------+------------+-----------------+
|  t (u8)  | len (u16)  |  value (len B)  |
+----------+------------+-----------------+
```

Reserved TLV type codes for the handshake:

```text
0x01  NODE_ID
0x02  CAPABILITIES
0x03  SECURITY_MODE
0x04  PUBKEY
0x05  RESULT
0x21  REASON_CODE     (for CLOSE)
0x22  REASON_TEXT     (for CLOSE)
```

---

## 3. Security Modes

Security mode values:

```text
0x00  Trusted-LAN
0x01  Checksummed
0x02  Signed
```

Semantics:

- **Trusted-LAN** – no checksum or signature is required by default. Integrity may still be enabled per-flow if desired.

- **Checksummed** – BLAKE3-128 checksum trailers (16 bytes) are required on DATA and HELLO/HELLO_ACK.

- **Signed** – both checksum and Ed25519 signature trailers (16 + 64 bytes) are required on DATA and HELLO/HELLO_ACK.

Each implementation maintains a supported set of security modes (e.g. {Trusted-LAN, Checksummed} or {Trusted-LAN, Checksummed, Signed}), and a policy for choosing among them (e.g. "prefer highest security available").

---

## 4. HELLO Message

Sent by: Initiator immediately after establishing the underlying stream.

Frame:

- `type` = HELLO (0x01)
- `payload` = TLV sequence

**Required TLVs:**

- **NODE_ID (0x01)**
  - Opaque binary ID (8–64 bytes).
  - Recommended: hash of the node's long-term public key or other stable identifier.

- **CAPABILITIES (0x02)**
  - Bitfield or feature list encoded as bytes (see §7).

- **SECURITY_MODE (0x03)**
  - Single byte indicating the preferred security mode of the initiator:
    - 0x00 / 0x01 / 0x02 as above.

- **PUBKEY (0x04)** (required if SECURITY_MODE is Signed)
  - Ed25519 public key (32 bytes).

**Optional TLVs (for future use):**

- Additional capability hints.
- Application-specific tags understood by higher layers.

The HELLO header's `hlc_*` fields must carry the initiator's current HLC at send time.

---

## 5. HELLO_ACK Message

Sent by: Acceptor in response to a valid HELLO.

Frame:

- `type` = HELLO_ACK (0x02)
- `payload` = TLV sequence

**Required TLVs:**

- **NODE_ID (0x01)**
  - The acceptor's own node ID (same format as in HELLO).

- **CAPABILITIES (0x02)**
  - The intersection of supported capabilities between initiator and acceptor (or the acceptor's subset, per policy).

- **SECURITY_MODE (0x03)**
  - The selected security mode for this connection.

- **RESULT (0x05)**
  - Single byte result code (see below).

**Optional TLVs:**

- **PUBKEY (0x04)** if the selected SECURITY_MODE is Signed and the acceptor has a key.
- Additional capabilities or hints.

### 5.1 RESULT Codes

RESULT (0x05) value:

```text
0x00  OK
0x01  ERROR_UNSUPPORTED_VERSION
0x02  ERROR_UNSUPPORTED_SECURITY_MODE
0x03  ERROR_CAPABILITY_MISMATCH
0x04  ERROR_POLICY
0x05  ERROR_INTERNAL
```

Semantics:

- **OK** – Handshake succeeded; both peers may transition to ACTIVE.

- **ERROR_*** – Handshake failed; acceptor should send a CLOSE (optionally) and then tear down the connection.

---

## 6. Security Mode Negotiation

Each peer has:

- `supported_security_modes`: a non-empty set, e.g. {Trusted-LAN, Checksummed, Signed}.
- `policy`: a deterministic algorithm for selecting one mode from an intersection.

**Recommended default policy:**

1. Compute `intersection = initiator.supported ∩ acceptor.supported`.

2. If intersection is empty:
   - Send HELLO_ACK with:
     - SECURITY_MODE = 0x00 (placeholder)
     - RESULT = ERROR_UNSUPPORTED_SECURITY_MODE
   - Optionally send CLOSE with REASON_CODE SECURITY_ERROR, then close.

3. Otherwise:
   - Choose the most secure mode in intersection, preferring:
     - Signed over Checksummed over Trusted-LAN.
   - Return chosen mode in HELLO_ACK SECURITY_MODE.
   - Set RESULT = OK.

If the initiator requested a specific mode in HELLO SECURITY_MODE, the acceptor may choose to:

- Treat it as a strict requirement (if policy says "no downgrade"), or
- Treat it as a preference and still pick a stronger mode from intersection.

The selected mode governs:

- Which flags must be set on headers (CHECKSUM, SIGNATURE).
- Whether trailers (checksum, signature) must be present and validated.

---

## 7. Capabilities

CAPABILITIES (0x02) is a bitfield or feature list. For Spike A, a simple 32-bit bitfield is sufficient.

Example initial layout (big-endian u32):

```text
bit 0  HLC_SUPPORTED            (must be 1 for AXON/0)
bit 1  CHECKSUM_SUPPORTED       (BLAKE3)
bit 2  SIGNATURE_SUPPORTED      (Ed25519)
bit 3  COMPRESSION_SUPPORTED    (reserved for future use)
bit 4  MULTI_STREAM_SUPPORTED   (multiple logical streams per connection)
bit 5  RESERVED
...
bit 31 RESERVED
```

Rules:

- A peer must not advertise features it does not actually implement.

- The acceptor may:
  - Return the bitwise AND of capabilities, or
  - Return a curated subset (e.g. disabling features for policy reasons).

Future versions may expand this field or introduce additional TLVs for feature negotiation.

---

## 8. CLOSE Semantics

CLOSE (0x03) is used for graceful shutdown or error signaling.

Payload TLVs:

- **REASON_CODE (0x21)** – u16 code (network byte order).
- **REASON_TEXT (0x22)** – optional UTF-8 string for humans.

Example reason codes (handshake-related):

```text
0x0000  NORMAL
0x0001  PROTOCOL_ERROR
0x0002  SECURITY_ERROR
0x0003  CAPABILITY_ERROR
0x0004  VERSION_MISMATCH
0x0005  INTERNAL_ERROR
```

On receiving CLOSE, a peer should:

1. Stop sending new DATA frames.
2. Optionally flush pending outgoing Songs.
3. Tear down the underlying stream.

If CLOSE is not received (e.g. transport error), the peer should treat the connection as aborted with an implicit error.

---

## 9. Connection State Machine (Handshake Focus)

**From the perspective of the initiator:**

**Idle**
Underlying stream not yet established.

**Connecting**
TCP/stream connect in progress.

**Handshaking**

- Send HELLO.
- Start handshake timer.
- Await HELLO_ACK.
- On HELLO_ACK:
  - If RESULT = OK and SECURITY_MODE and capabilities are acceptable:
    - Configure security mode and capabilities.
    - Transition to Active.
  - Otherwise:
    - Optionally send CLOSE with a matching REASON_CODE.
    - Transition to Closed.

**From the perspective of the acceptor:**

**Listening**
Await new transport connections.

**Handshaking**

- On new stream, await HELLO within a timeout.
- Validate version, capabilities, and requested security mode.
- Choose security mode and capabilities per policy.
- Send HELLO_ACK with RESULT.
- On RESULT = OK, transition to Active; otherwise send CLOSE and transition to Closed.

Timeouts are implementation-defined but should be short enough to avoid resource exhaustion by half-open handshakes.

---

## 10. Example Handshakes

### 10.1 Trusted-LAN, no signatures

**Initiator:**

- Supports: {Trusted-LAN, Checksummed}
- Prefers: Trusted-LAN for this connection.

HELLO payload:

- NODE_ID = 0x01 02 03 04 ...
- CAPABILITIES = HLC_SUPPORTED | CHECKSUM_SUPPORTED
- SECURITY_MODE = 0x00 (Trusted-LAN)
- No PUBKEY.

**Acceptor:**

- Supports: {Trusted-LAN, Checksummed, Signed}
- Policy: "Choose highest security available, but allow explicit downgrade to Trusted-LAN on local network."

Intersection = {Trusted-LAN, Checksummed}
Policy chooses Trusted-LAN because the initiator explicitly requested it and local policy allows downgrade.

HELLO_ACK payload:

- NODE_ID = 0xAA BB CC DD ...
- CAPABILITIES = HLC_SUPPORTED | CHECKSUM_SUPPORTED
- SECURITY_MODE = 0x00
- RESULT = OK

Connection becomes Active; neither side is required to attach checksum/signature trailers, though checksum may still be used opportunistically.

### 10.2 Signed mode with mutual keys

**Initiator:**

- Supports: {Trusted-LAN, Checksummed, Signed}
- Prefers: Signed.

HELLO payload:

- NODE_ID = hash of initiator pubkey.
- CAPABILITIES = HLC_SUPPORTED | CHECKSUM_SUPPORTED | SIGNATURE_SUPPORTED
- SECURITY_MODE = 0x02 (Signed)
- PUBKEY = initiator Ed25519 public key.

**Acceptor:**

- Supports: {Checksummed, Signed}
- Policy: "Choose highest security; no downgrade."

Intersection = {Checksummed, Signed}
Policy chooses Signed.

HELLO_ACK payload:

- NODE_ID = hash of acceptor pubkey.
- CAPABILITIES = HLC_SUPPORTED | CHECKSUM_SUPPORTED | SIGNATURE_SUPPORTED
- SECURITY_MODE = 0x02
- RESULT = OK
- PUBKEY = acceptor Ed25519 public key.

From this point on:

- HELLO and HELLO_ACK themselves should carry checksum and signature trailers.
- All DATA frames must be checksummed and signed and validated on receipt.

---

This handshake spec is intentionally small and strict: a single HELLO / HELLO_ACK exchange, explicit security negotiation, and clear failure modes. Everything else in AXON/0 (streams, retransmit policy, tracing) builds on top of this agreement.
