# MDNS — CONTEXT
Scope/role: the `MDNS` Tier-1 facade (browser / responder) plus its package-internal
NIO transport seam; built on the Embedded-clean `DNSWire` codec. Depended on by
peer-discovery callers (libp2p) that want service browse / advertise over mDNS.
Last reviewed: 2026-06-25

Invariants and design intent that the source does not state structurally. Read this
before changing the facade (`Sources/MDNS`) or the wire codec (`Sources/DNSWire`).
The currency is `[UInt8]` / `MDNSService` / `P2PCore.IPAddress`; this is an
Embedded-first package, so the codec (`DNSWire`) must stay Foundation-free and the
facade must keep `Data` / `ByteBuffer` / NIO types off its public surface. The
README is the structural reference (file tree, type tables, usage); this file is
the contract.

## Contracts (the load-bearing rules)

- **`DNSWire` is the codec; `MDNS` is the host facade — keep the split.** `import
  MDNS` does NOT pull in `DNSWire`; a caller building records by hand imports
  `DNSWire` deliberately. `DNSWire` carries no `swift-p2p-core` dependency, which
  keeps it off the macOS-26 `Span` floor and lets it compile under Embedded Swift.
  Do not introduce a `DNSWire -> P2PCore` (or `DNSWire -> NIO`) edge.
- **`MDNSTransport` is a `package` protocol, not public.** It is the injection seam
  used by tests and the `NIODNSTransport` adapter. `NIODNSTransport` is the single
  place where `[UInt8]` crosses to / from a NIO `ByteBuffer` (one bulk copy at the
  datagram edge in `encodeToByteBuffer` / `decode(fromBuffer:)`). Do not let NIO
  types leak past this seam into the browser / responder.
- **`browse(_:)` returns the named `MDNSDiscoveries`** — an `AsyncSequence` with
  `Element == MDNSService`, `Failure == MDNSError` (typed throws). It is NOT an
  opaque `some AsyncSequence` and NOT an `AsyncThrowingStream` (whose `Failure` is
  pinned to `any Error`). Calling `browse` again adds another service type to the
  same stream and returns it again; keep that single-stream behavior.
- **Discovery is upsert-only — there is no event enum.** There is no
  `.found` / `.updated` / `.removed` case. An updated or removed service is
  delivered as a fresh `MDNSService` value carrying the current state; consumers
  deduplicate on `MDNSService.id` (the full service name). Do not add a
  synthesized "unreachable" / removal sentinel: a goodbye (TTL == 0) re-emits the
  last-known state of the removed service, and that is the only removal signal.
- **TXT values are raw `[UInt8]`** on `MDNSService` (`txt: [String: [UInt8]]`),
  per the byte currency — there is no String-valued TXT API. On the wire they are
  rendered as `key=value` (or bare `key` for an empty value) and parsed back to
  bytes. Do not add a String-valued TXT path to the facade.

## Invariants (must hold; tests guard them)

- **The decoder rejects hostile input — it never traps and never silently
  substitutes a default.** Malformed input throws `DNSError`; unrecognized
  opcode / rcode / class / record-type values are preserved as `.unknown(...)`
  rather than defaulted.
- **DNS name decompression is bounded.** `DNSName.decode` caps compression-pointer
  jumps (`maxJumps = 128`) and requires every pointer to point strictly backward
  and within message bounds — a forward or self-referential pointer throws. This
  defeats compression-pointer loops and the "infinite name" expansion attack.
- **RFC 1035 total-name length (255 bytes) is enforced at decode time**,
  incrementally as labels are appended — not only in `init(String)`. Compression
  plus many short labels cannot build an over-long name past the cap.
- **`DNSMessage.decode` enforces a hard size ceiling BEFORE reading any
  attacker-controlled section count.** A datagram larger than `mdnsMaxMessageSize`
  throws `DNSError.messageTooLarge` up front, so a tiny datagram cannot claim huge
  section counts. Every speculative `reserveCapacity` is then capped to what the
  remaining bytes could actually hold (`min(count, remainingBytes / minEntrySize)`)
  — a DoS guard against forged 0xFFFF section counts. Do not reserve raw wire counts.
- **Inbound decode failures are dropped per RFC 6762, never fatal, and are
  observable.** A malformed multicast datagram is dropped without tearing down the
  receive loop; `NIODNSTransport` counts it (`droppedDecodeFailureCount`) and emits
  a throttled non-debug log at power-of-ten thresholds. Do not swallow the failure
  silently and do not let it kill the loop.
- **A facade-reaching `DNSWire` failure is wrapped as `MDNSError.codec(DNSError)`**
  so a caller has one exhaustive `catch`. Keep `MDNSError` the single public error.

## Embedded constraints (do not regress)

- **`DNSWire` is the Embedded-clean target: no Foundation, no NIO, no `any`.** Its
  `WriteBuffer` owns `ContiguousArray<UInt8>`; the decode workhorse uses
  random-access `[UInt8]` indexing (compression pointers jump backward) rather than
  a forward cursor, which stays Embedded-clean. The Embedded build is
  `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target DNSWire`.
- **The `MDNS` facade is host-only** — it links NIO (`NIOUDPTransport`) for I/O and
  `Mutex` for the transport's internal state. Keep all NIO / Foundation / `Mutex`
  use inside the facade and its transport adapter; never push them down into
  `DNSWire`.

## Dependencies & seams

- `MDNS` depends on `DNSWire` (codec), `NIOUDPTransport` (UDP + multicast join),
  `P2PCoreTransport` (supplies the facade currency `IPAddress`), and `Logging`.
- `NIODNSTransport` uses separate IPv4 / IPv6 `NIOUDPTransport` instances (each
  address family needs its own socket bound to `0.0.0.0` / `::`) and joins the mDNS
  multicast groups (224.0.0.251 / ff02::fb on port 5353).
- `IPAddressBridge` is the only place `DNSWire`'s `IPv4Address` / `IPv6Address`
  convert to / from `P2PCore.IPAddress`.

## Wire protocol notes

- mDNS: multicast 224.0.0.251 (IPv4) / ff02::fb (IPv6), UDP port 5353, message ID
  always 0. Cache-flush bit = high bit of the class field; QU bit = high bit of the
  question class (requests unicast); goodbye = TTL 0. (RFC 6762 / 6763 / 1035 / 2782.)

## Build

- Host: `swift build` (Swift tools 6.2, platform floor macOS 26 — the facade
  surfaces `P2PCore.IPAddress`).
- Embedded codec: `P2P_CORE_EMBEDDED=1 swiftly run +6.3.1 swift build --target DNSWire`.
