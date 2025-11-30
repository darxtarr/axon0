# AXON/0 — Obsidian Transport Fabric for CHORUS

AXON/0 is the lowest layer of the CHORUS transport stack.

It is the **obsidian glass** under everything else: a fast, binary, structurally simple fabric that moves bytes and signals between nodes with minimal ceremony, while remaining fully understandable and re-implementable in-house.

Higher layers (AXON/1 and beyond) may speak in streams, conversations, CRDT ops or semantic messages. AXON/0 only cares about:

- who is talking to whom,
- which bytes are being moved,
- in what causal order,
- and with what integrity guarantees.

Everything else is built on top.

---

## Design Goals

AXON/0 exists to satisfy a small number of very specific goals:

- **Fast by default**
  The wire format is binary and compact. No JSON, no text envelopes, no accidental bloat. Latency, throughput, and predictable CPU profiles matter more than "curl friendliness."

- **Transparent, not opaque**
  Transparency here does *not* mean "human-readable on the wire."
  It means:
  - The protocol is small and fully specified.
  - We can re-implement it in any language without vendor magic.
  - AI agents and tools can learn the grammar and reason about traces.

- **AI-native observability**
  AXON/0 is designed to be debugged and inspected primarily by **agents**, not by humans staring at logs.
  - The substrate is binary.
  - "Bells" (introspection) are structured trace events that **TraceVeyr**-style mnematodes can decode, cluster, and explain.
  - Humans consume stories, diagrams, and summaries, not raw packets.

- **Causality-aware**
  Every message carries a **Hybrid Logical Clock (HLC)** stamp so the fabric can reconstruct causal order across nodes.

- **Boutique and minimal**
  The implementation depends only on a small, defensible set of crates (async runtime, crypto primitives, basic codecs). Everything is replaceable; there are no hidden frameworks.

---

## Non-Goals

AXON/0 is deliberately *not* responsible for:

- Semantic routing or topic-based messaging.
- Document or state replication (CRDTs, etc.).
- Application-level retries, idempotence rules, or business logic.
- Human-readable JSON logs as a first-class artifact.

Those belong to higher layers (AXON/1+, CHORUS services, or application code) and to dedicated observability agents.

---

## Core Concepts

### Songs

**Songs** are the primary on-the-wire units of AXON/0.

- They are **binary frames** with a small, fixed header and a typed payload.
- They carry:
  - Protocol version
  - Frame type
  - Length
  - Sender/receiver IDs (or flow ID)
  - HLC timestamp
  - Integrity/authentication fields (presence depends on mode)
- Payload encodings are simple and spec'd; a Song is always parseable without heuristics.

Songs are designed to be:

- Easy to parse with a straightforward state machine.
- Easy to learn for models (finite set of types, clear layout).
- Suitable for zero-copy or low-copy paths when possible.

### Bells

**Bells** are introspection events.

- They are **not** part of the hot data path.
- They are emitted by endpoints and routers to describe what happened:
  - Connection opened/closed
  - Retries and drops
  - Latency and queue statistics
  - Anomalies and errors

Bells are recorded to a **trace stream** (or file) that is meant to be consumed by:

- AI agents (TraceVeyr, Forensics mnematodes) that:
  - Decode the binary format.
  - Reconstruct timelines and causal graphs.
  - Generate human-readable reports on demand.

If a human needs JSON or text, it is produced *by these agents*, not by AXON/0 itself.

---

## Semantics

AXON/0 provides the following basic semantics between peers:

- **At-least-once delivery**
  Messages are delivered one or more times, never silently dropped.
  Duplicates are possible; higher layers handle idempotence.

- **Causal ordering with HLC**
  Each Song carries a Hybrid Logical Clock.
  This allows:
  - Partial causal order reconstruction across nodes.
  - Reasonable "what happened before what" debugging.
  - Time-window based queries over traces.

- **Integrity by default**
  AXON/0 can run in different security modes:
  - `Trusted-LAN`: integrity checks (e.g. BLAKE3) without per-frame signatures.
  - `Signed-LAN` / `Untrusted`: Ed25519 signatures per frame or per flow.

  The mode is explicit in the handshake; security is a capability, not accidental overhead.

- **Connection semantics**
  On top of the underlying transport (TCP, QUIC, or similar), AXON/0 defines:
  - A basic handshake (identity exchange, capabilities, security mode).
  - A framing layer for Songs.
  - Heartbeat / keepalive expectations.
  - Backpressure and basic flow control signals.

Exact details live in the protocol spec.

---

## Discovery

AXON/0 includes a minimal discovery mechanism for LAN-style deployments:

- Nodes emit **beacons** on a well-known port (e.g. UDP broadcast or multicast).
- Beacons announce:
  - Node identity
  - Listening endpoints
  - Capabilities/hints (security mode, supported transports, etc.)
- Listeners can:
  - Auto-connect to discovered peers.
  - Or feed the list into higher-level topology builders.

Discovery is a convenience layer; static config of peers remains supported and is appropriate in many deployments.

---

## Observability and Debugging

AXON/0's observability story is built around **agents**, not around line-oriented log files.

Key principles:

- Every significant event (connection, Song, error, retry) can emit a Bell.
- Bells are recorded in a compact, binary trace format that:
  - Is efficient to write.
  - Can be sliced by time and node.
  - Can be replayed by tools.

On top of that, we anticipate:

- **TraceVeyr**: an agent that reads AXON/0 traces and produces:
  - Timelines of events.
  - ASCII sequence diagrams.
  - Natural language summaries of incidents.
  - Suspicion scores for anomalies (e.g. unusual latencies).

- **Protocol Tutor** agents that:
  - Ingest the AXON/0 spec.
  - Check captures for spec violations.
  - Suggest improvements or warn about misconfigurations.

Humans interact mainly with these explanations, not with raw trace files.

---

## Relationship to Other Layers

AXON/0 is **layer 0** of the Axon family:

- **AXON/0**: ephemeral fabric
  - Frames, discovery, HLC, basic reliability & integrity.
- **AXON/1** (planned): persistent / semantic layer
  - Streams, sessions, semantic message types, state replication.
- **CHORUS services**: domain-specific protocols
  - Mnematodes, Spirit, Houndmaster, RenderLlama, etc.

The layers are deliberately decoupled so that AXON/0 can remain small and stable, while higher layers evolve.

---

## Status

AXON/0 is currently in the **specification and scaffolding** phase.

- [ ] Finalize frame format (header + payload types)
- [ ] Specify handshake and discovery messages
- [ ] Define trace (Bell) format and minimal TraceVeyr agent contract
- [ ] Implement reference Rust library for:
  - Framing
  - HLC
  - Basic discovery
  - Trusted-LAN integrity mode

Nothing in this repository should be treated as a long-term API guarantee yet.
The immediate goal is a solid, testable substrate that the rest of CHORUS can depend on.
